//! DataStore (115). SSBU makes these calls right after the secure login (61, 83, 95, 84, 60) and
//! drops the session with error 2306-0103 if one fails; layouts come from the game's serializers
//! and result extractors (docs/re/protocols.md). Objects posted with their metadata only (21) are
//! kept by `crate::objects`; uploads, replays and shared content are not served yet.
//!
//! shortcut: the results are empty or zero (no stored data, no flags set); replace each with real
//! data once the game's use of it is known

use super::{Ctx, Fail, NOT_IMPLEMENTED, Reply};
use crate::objects::{Object, Permission};
use oof_nex::rmc::errors;
use oof_nex::stream::{DateTime, Reader, Writer};

/// Persistence slot ID meaning "no slot" (`DataStorePersistenceInitParam`).
const NO_SLOT: u16 = 0xffff;

fn read_permission(r: &mut Reader) -> oof_nex::stream::Result<Permission> {
    let (_, mut p) = r.structure()?;
    Ok(Permission { kind: p.u8()?, recipients: p.list(|r| r.pid())? })
}

fn write_permission(w: &mut Writer, p: &Permission) {
    w.structure(0, |w| {
        w.u8(p.kind).list(&p.recipients, |w, &pid| {
            w.pid(pid);
        });
    });
}

/// `DataStoreMetaInfo`, field order checked against the game's reader at main+0x28a310.
fn write_meta(w: &mut Writer, id: u64, o: &Object) {
    let expires = DateTime::from_unix(DateTime(o.created).to_unix() + u64::from(o.period) * 86_400).0;
    w.structure(0, |w| {
        w.u64(id).pid(o.owner).u32(o.size).string(&o.name).u16(o.data_type).qbuffer(&o.meta_binary);
        write_permission(w, &o.permission);
        write_permission(w, &o.delete_permission);
        // created, updated, period, status, referred count, refer data ID, flag, referred, expires
        w.u64(o.created).u64(o.updated).u16(o.period).u8(0).u32(0).u32(o.refer_data_id).u32(o.flag);
        w.u64(o.created).u64(expires);
        w.list(&o.tags, |w, t| {
            w.string(t);
        });
        w.u32(0); // ratings
    });
}

pub fn handle(ctx: &mut Ctx, method: u32, r: &mut Reader) -> Reply {
    let pid = ctx.pid.expect("dispatch only routes secure connections here");
    let mut w = Writer::new();
    match method {
        // GetMeta(DataStoreGetMetaParam) -> DataStoreMetaInfo, or NotFound for an absent object.
        8 => {
            let (_, mut p) = r.structure()?;
            let data_id = p.u64()?;
            let (_, mut target) = p.structure()?;
            let owner = target.pid()?;
            let slot = target.u16()?;
            let options = p.u8()?;
            let _access_password = p.u64()?;
            let found = ctx.state.objects.lock().expect("objects lock").get(pid, data_id, owner, slot)?;
            let Some((id, object)) = found else {
                tracing::debug!(data_id, owner, slot, options, "DataStore GetMeta: object not found");
                return Err(Fail(errors::DATASTORE_NOT_FOUND));
            };
            write_meta(&mut w, id, &object);
        }
        // PostMetaBinary(DataStorePreparePostParam) -> u64 data ID. Request layout from the serializer of
        // method 21; the extractor main+0x28cd10 reads one u64. Both players post at match start (slot 0).
        21 => {
            let (_, mut p) = r.structure()?;
            let (size, name, data_type) = (p.u32()?, p.string()?, p.u16()?);
            let meta_binary = p.qbuffer()?.to_vec();
            let (permission, delete_permission) = (read_permission(&mut p)?, read_permission(&mut p)?);
            let (flag, period, refer_data_id) = (p.u32()?, p.u16()?, p.u32()?);
            let tags = p.list(|r| r.string())?;
            p.list(|r| r.structure().map(drop))?; // rating slots: no ratings yet
            let (_, mut persistence) = p.structure()?;
            let slot = persistence.u16()?;
            let delete_last = persistence.remaining() > 0 && persistence.bool()?;
            p.list(|r| r.string())?; // extra data
            tracing::debug!(
                name,
                data_type,
                size,
                meta = meta_binary.len(),
                period,
                slot,
                ?tags,
                "DataStore PostMetaBinary"
            );
            let object = Object {
                owner: pid,
                size,
                name,
                data_type,
                meta_binary,
                permission,
                delete_permission,
                created: DateTime::now().0,
                updated: DateTime::now().0,
                period,
                refer_data_id,
                flag,
                tags,
            };
            let slot = (slot != NO_SLOT).then_some((slot, delete_last));
            let id = ctx.state.objects.lock().expect("objects lock").post(&object, slot)?;
            tracing::debug!(id, "DataStore PostMetaBinary stored");
            w.u64(id);
        }
        // ChangeMeta(DataStoreChangeMetaParam) -> nothing (extractor main+0x28d7e0 is a bare ret). Both players
        // change their slot-0 object (see 21) after each Quickplay match. The modifies flag bits follow the
        // fields' order: name 0x1, permission 0x2, delete permission 0x4, period 0x8, meta binary 0x10, tags 0x20,
        // referred count 0x40, data type 0x80, status 0x100.
        38 => {
            let (_, mut p) = r.structure()?;
            let (data_id, flag, name) = (p.u64()?, p.u32()?, p.string()?);
            let (permission, delete_permission) = (read_permission(&mut p)?, read_permission(&mut p)?);
            let (period, meta_binary, tags) = (p.u16()?, p.qbuffer()?.to_vec(), p.list(|r| r.string())?);
            let (_update_password, _referred, data_type, _status) = (p.u64()?, p.u32()?, p.u16()?, p.u8()?);
            let (_, mut compare) = p.structure()?;
            let comparison = compare.u32()?;
            let (_, mut target) = p.structure()?;
            let (owner, slot) = (target.pid()?, target.u16()?);
            tracing::debug!(data_id, flag, comparison, owner, slot, meta = meta_binary.len(), "DataStore ChangeMeta");
            // shortcut: the compare param (change only if the stored values still match) is not checked; one console
            // owns each object, so nothing races it yet
            let set = |bit: u32| flag & bit != 0;
            let changed = ctx.state.objects.lock().expect("objects lock").change(pid, data_id, owner, slot, |o| {
                if set(0x1) {
                    o.name = name;
                }
                if set(0x2) {
                    o.permission = permission;
                }
                if set(0x4) {
                    o.delete_permission = delete_permission;
                }
                if set(0x8) {
                    o.period = period;
                }
                if set(0x10) {
                    o.meta_binary = meta_binary;
                }
                if set(0x20) {
                    o.tags = tags;
                }
                if set(0x80) {
                    o.data_type = data_type;
                }
                o.updated = DateTime::now().0;
            })?;
            if !changed {
                return Err(Fail(errors::DATASTORE_NOT_FOUND));
            }
        }
        // Struct{bool, bool} -> nothing; extractor main+0x28f380 returns immediately.
        94 => {
            let (_, mut p) = r.structure()?;
            p.bool()?;
            p.bool()?;
        }
        // ?() -> List<Struct>
        60 => {
            w.u32(0);
        }
        // ?() -> u32
        61 => {
            w.u32(0);
        }
        // ?(Struct{u8, Struct{String}, Struct{String x4}}) -> nothing. Seen from the game:
        // 3, "eu_es", then "US", "unknown", "2000-01-01", "eu_es" (console region/language data)
        83 => {
            let (_, mut p) = r.structure()?;
            let kind = p.u8()?;
            let first = p.structure()?.1.string()?;
            let (_, mut s) = p.structure()?;
            let rest = [s.string()?, s.string()?, s.string()?, s.string()?];
            tracing::debug!(kind, first, ?rest, "DataStore 83");
        }
        // ?(Struct{u8, u32, u32, u32, u64, u32}) -> nothing (extractor main+0x28ee70 is a bare
        // ret). Both players send it when a Quickplay match starts, right before 21.
        82 => {
            let (_, mut p) = r.structure()?;
            let fields = (p.u8()?, p.u32()?, p.u32()?, p.u32()?, p.u64()?, p.u32()?);
            tracing::debug!(?fields, "DataStore 82");
        }
        // ?() -> (Map or List, Struct{u32, u32, u32, u64})
        84 => {
            w.u32(0).structure(0, |w| {
                w.u32(0).u32(0).u32(0).u64(0);
            });
        }
        // ?() -> List<0x18-byte element> (extractor main+0x28ee00 → reader main+0x25be10). Opening "Espectador".
        // shortcut: always empty, so the mode lists nothing to watch; fill it once match broadcasts are stored.
        80 => {
            w.u32(0);
        }
        // ?(Struct{String, u16, u8, u8, Struct{u32, u32}, …}) -> List<0x238-byte element> (extractor
        // main+0x28e8d0 → reader main+0x286dd0). Sent three times right after 80 when "Espectador" opens.
        // shortcut: always empty, like 80.
        66 => {
            let (_, mut p) = r.structure()?;
            let key = p.string()?;
            tracing::debug!(key, rest = p.remaining(), "DataStore 66");
            w.u32(0);
        }
        // ?() -> Struct{bool}
        95 => {
            w.structure(0, |w| {
                w.bool(false);
            });
        }
        _ => return Err(NOT_IMPLEMENTED),
    }
    Ok(w.into_bytes())
}
