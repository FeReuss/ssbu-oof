//! DataStore (115). SSBU makes these calls right after the secure login (61, 83, 95, 84, 60) and
//! drops the session with error 2306-0103 if one fails; layouts come from the game's serializers
//! and result extractors (docs/re/protocols.md). Posted objects (21, and 24 with a payload uploaded over HTTP) are
//! kept by `crate::objects`.
//!
//! shortcut: the results are empty or zero (no stored data, no flags set); replace each with real
//! data once the game's use of it is known

use super::{Ctx, Fail, NOT_IMPLEMENTED, Reply};
use crate::objects::{Object, Permission};
use oof_nex::rmc::{RESULT_SUCCESS, errors};
use oof_nex::stream::{DateTime, Reader, Variant, Writer};

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
fn write_meta(w: &mut Writer, id: u64, o: &Object, likes: u32) {
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
        // ratings: Shared Content likes in slot 0 (DataStoreRatingInfoWithSlot{i8 slot, {i64 total, u32 count, i64
        // initial}})
        if likes == 0 {
            w.u32(0);
        } else {
            w.u32(1).structure(0, |w| {
                w.u8(0).structure(0, |w| {
                    w.i64(i64::from(likes)).u32(likes).i64(0);
                });
            });
        }
    });
}

/// `DataStorePreparePostParam` (methods 21 and 24): the object to store and its persistence slot (slot ID, delete the
/// object it held).
fn read_post_param(r: &mut Reader, pid: u64) -> Result<(Object, Option<(u16, bool)>), Fail> {
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
    tracing::debug!(name, data_type, size, meta = meta_binary.len(), period, slot, ?tags, "DataStore post param");
    let now = DateTime::now().0;
    let object = Object {
        owner: pid,
        size,
        name,
        data_type,
        meta_binary,
        permission,
        delete_permission,
        created: now,
        updated: now,
        period,
        refer_data_id,
        flag,
        tags,
    };
    Ok((object, (slot != NO_SLOT).then_some((slot, delete_last))))
}

/// `DataStoreReqGetInfo` (reader main+0x288ee0): String url, List<key/value> request headers, u32 size, Buffer root CA,
/// u64 data ID.
fn write_get_info(w: &mut Writer, ctx: &Ctx, id: u64, size: u32) {
    w.structure(0, |w| {
        w.string(&object_url(ctx, id, false)).u32(0).u32(size).buffer(&[]).u64(id);
    });
}

/// Shared Content ID of a data ID: 8 characters, digits and capitals without I and O.
fn share_code(id: u64) -> String {
    const DIGITS: &[u8] = b"0123456789ABCDEFGHJKLMNPQRSTUVWXYZ";
    let mut n = id;
    let mut out = [b'0'; 8];
    for c in out.iter_mut().rev() {
        *c = DIGITS[(n % DIGITS.len() as u64) as usize];
        n /= DIGITS.len() as u64;
    }
    String::from_utf8(out.to_vec()).expect("ASCII")
}

/// `C2ShareMetaInfo` (reader main+0x287cb0): DataStoreMetaInfo, u8 x3, Buffer, String, List<Struct{bool, u64, u32}>,
/// Struct{bool, u8, String, String, String}, filled from the share description 62 stored.
fn write_share(w: &mut Writer, shared: &crate::objects::Shared) {
    let (id, object) = (shared.id, &shared.object);
    let mut r = Reader::new(&shared.info);
    let mut field = || -> oof_nex::stream::Result<_> {
        let kinds = [r.u8()?, r.u8()?, r.u8()?];
        let names = [r.string()?, r.string()?, r.string()?];
        let fighters = r.buffer()?.to_vec();
        Ok((kinds, names, fighters, r.u8()?))
    };
    let (kinds, names, fighters, flag) = field().unwrap_or_default();
    w.structure(0, |w| {
        write_meta(w, id, object, shared.likes);
        w.u8(kinds[0]).u8(kinds[1]).u8(kinds[2]).buffer(&fighters).string(&share_code(id)).u32(0);
        w.structure(0, |w| {
            w.bool(false).u8(flag).string(&names[0]).string(&names[1]).string(&names[2]);
        });
    });
}

/// Where the game uploads (`put`) or downloads an object's payload: this server's `/v1/objects/<id>`, signed so only
/// the holder of the URL may use it. The scheme is https like the NEX connection; a port in plain-bytes mode (standard
/// section 6) sends it unencrypted.
fn object_url(ctx: &Ctx, id: u64, put: bool) -> String {
    let c = &ctx.state.config;
    format!(
        "https://{}:{}/v1/objects/{id}?k={}",
        c.public_host,
        c.public_port,
        crate::objects::url_key(&ctx.state.secret, id, put)
    )
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
            write_meta(&mut w, id, &object, 0);
        }
        // PostMetaBinary(DataStorePreparePostParam) -> u64 data ID. Request layout from the serializer of
        // method 21; the extractor main+0x28cd10 reads one u64. Both players post at match start (slot 0).
        21 => {
            let (object, slot) = read_post_param(r, pid)?;
            let id = ctx.state.objects.lock().expect("objects lock").post(&object, slot)?;
            tracing::debug!(id, "DataStore PostMetaBinary stored");
            w.u64(id);
        }
        // PreparePostObject(DataStorePreparePostParam) -> DataStoreReqPostInfo{u64 data ID, String url, List<key/value>
        // request headers, List<key/value> form fields, Buffer root CA} (reader main+0x2907b0). "Post" on a replay in the
        // Vault; the game then uploads the payload to the URL and calls 26.
        24 => {
            let (object, slot) = read_post_param(r, pid)?;
            let size = object.size;
            let id = ctx.state.objects.lock().expect("objects lock").post(&object, slot)?;
            tracing::debug!(id, size, "DataStore PreparePostObject");
            w.structure(0, |w| {
                w.u64(id).string(&object_url(ctx, id, true)).u32(0).u32(0).buffer(&[]);
            });
        }
        // PrepareGetObject(DataStorePrepareGetParam{u64 data ID, u32 lock ID, persistence target, u64 access
        // password, List<String> extra data}) -> DataStoreReqGetInfo{String url, List<key/value> request headers, u32
        // size, Buffer root CA, u64 data ID} (reader main+0x288ee0).
        25 => {
            let (_, mut p) = r.structure()?;
            let (data_id, _lock_id) = (p.u64()?, p.u32()?);
            let (_, mut target) = p.structure()?;
            let (owner, slot) = (target.pid()?, target.u16()?);
            let store = ctx.state.objects.lock().expect("objects lock");
            let Some((id, object)) = store.get(pid, data_id, owner, slot)? else {
                return Err(Fail(errors::DATASTORE_NOT_FOUND));
            };
            if store.payload(id)?.is_none() {
                return Err(Fail(errors::DATASTORE_NOT_FOUND));
            }
            tracing::debug!(id, "DataStore PrepareGetObject");
            write_get_info(&mut w, ctx, id, object.size);
        }
        // GetObjectInfos(List<u64> data IDs) -> (List<DataStoreReqGetInfo>, List<Result>) (extractor main+0x28db50).
        // Playing a replay from Shared Content.
        45 => {
            let ids = r.list(|r| r.u64())?;
            let store = ctx.state.objects.lock().expect("objects lock");
            let mut found = Vec::new();
            for &id in &ids {
                let object = store.get(pid, id, 0, 0)?.filter(|_| store.payload(id).ok().flatten().is_some());
                found.push(object.map(|(_, o)| o.size));
            }
            tracing::debug!(?ids, ?found, "DataStore GetObjectInfos");
            w.u32(ids.len() as u32);
            for (&id, size) in ids.iter().zip(&found) {
                write_get_info(&mut w, ctx, id, size.unwrap_or(0));
            }
            w.list(&found, |w, size| {
                w.result(if size.is_some() { RESULT_SUCCESS } else { errors::DATASTORE_NOT_FOUND });
            });
        }
        // CompletePostObject(DataStoreCompletePostParam{u64 data ID, bool success}) -> nothing.
        26 => {
            let (_, mut p) = r.structure()?;
            let id = p.u64()?;
            let success = p.bool()?;
            let done = ctx.state.objects.lock().expect("objects lock").complete(pid, id, success)?;
            tracing::debug!(id, success, done, "DataStore CompletePostObject");
            if !done {
                return Err(Fail(errors::DATASTORE_NOT_FOUND));
            }
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
        // Shared Content search: Struct{String language, u16 data type (0xFFFF on the "Hot!" tab), u8, u8, Struct{u32
        // offset, u32 size}, List<{u16 data type, u32 version}> the game can show}. Tabs: Mii fighters 0, spirit teams
        // 1, replays 2, stages 3, videos 4.
        // shortcut: newest first on every tab ("Hot!" included) and the version list is not checked; rank by likes once
        // the game reports them.
        66 => {
            let (_, mut p) = r.structure()?;
            let language = p.string()?;
            let (data_type, b, c) = (p.u16()?, p.u8()?, p.u8()?);
            let (_, mut range) = p.structure()?;
            let (offset, size) = (range.u32()?, range.u32()?);
            let rest: String = p.take(p.remaining())?.iter().map(|b| format!("{b:02x}")).collect();
            tracing::debug!(language, data_type, b, c, offset, size, rest, "DataStore 66 search");
            let data_type = (data_type != 0xffff).then_some(data_type);
            let shared = ctx.state.objects.lock().expect("objects lock").shared(data_type, offset, size.min(100))?;
            // A structure that extends another (reader main+0x286dd0): the base {List<C2ShareMetaInfo>} with its own
            // header, then the derived part {u16 total}.
            w.structure(0, |w| {
                w.list(&shared, write_share);
            });
            w.structure(0, |w| {
                w.u16(shared.len() as u16);
            });
        }
        // ?() -> Struct{bool}
        95 => {
            w.structure(0, |w| {
                w.bool(false);
            });
        }
        // (DataStorePreparePostParam, DataStoreCompletePostParam, share description) -> String content ID (extractor
        // main+0x28e5f0). "Post" on a replay: after 24 and the upload, this completes the object and lists it in Shared
        // Content. The description (written by main+0x283d80, structure version 1): u8 kind, u8, u8, String poster
        // nickname, String, String, Buffer fighters, u8, Map<String, Variant> search attributes (country, fighter_1,
        // stage, melee_rule, movie_time, ...), u32, u32.
        62 => {
            read_post_param(r, pid)?; // the same parameters 24 already stored
            let (_, mut complete) = r.structure()?;
            let (id, success) = (complete.u64()?, complete.bool()?);
            let (_, mut info) = r.structure()?;
            let info = info.take(info.remaining())?;
            let kind = Reader::new(info).u8()?;
            let mut store = ctx.state.objects.lock().expect("objects lock");
            if !store.complete(pid, id, success)? || !success || !store.share(pid, id, kind, info)? {
                return Err(Fail(errors::DATASTORE_NOT_FOUND));
            }
            tracing::debug!(id, kind, code = share_code(id), "DataStore shared");
            w.string(&share_code(id));
        }
        // Sent at login by profiles with play history (lists of named counters such as "play_count"); the extractors
        // (main+0x28f400, main+0x28f410) are bare rets. Accepted and logged.
        // List<Struct{u64 data ID, u8, u32}> -> List<Result> (extractor main+0x28ecf0); 74 takes one entry and returns
        // nothing. Sent when leaving Shared Content after playing a replay: entries (1, 3, 1) for data ID 1. Meaning
        // not established; accepted.
        74 | 75 => {
            let entry = |r: &mut Reader| -> oof_nex::stream::Result<_> {
                let (_, mut e) = r.structure()?;
                Ok((e.u64()?, e.u8()?, e.u32()?))
            };
            if method == 74 {
                tracing::debug!(entry = ?entry(r)?, "DataStore 74");
            } else {
                let entries = r.list(entry)?;
                tracing::debug!(?entries, "DataStore 75");
                w.list(&entries, |w, _| {
                    w.result(RESULT_SUCCESS);
                });
            }
        }
        97 => {
            tracing::debug!(len = r.remaining(), "DataStore play statistics");
        }
        // Shared Content actions, sent in batches: Struct{List<(Struct{Map<String, Variant>}, Struct{u64 data ID})>}.
        // Seen: action_type 0 listed, 1 opened, 3 liked, 4 like taken back, 6 played (with play_time); also alg,
        // list_page_type, thumbnail_size. Sent when leaving Shared Content and every few minutes.
        96 => {
            let (_, mut p) = r.structure()?;
            let actions = p.list(|r| {
                let (_, mut props) = r.structure()?;
                let mut action = None;
                for _ in 0..props.u32()? {
                    let key = props.string()?;
                    if let (Variant::I64(v), "action_type") = (props.variant()?, key.as_str()) {
                        action = Some(v);
                    }
                }
                Ok((action, r.structure()?.1.u64()?))
            })?;
            tracing::debug!(?actions, "DataStore Shared Content actions");
            let mut store = ctx.state.objects.lock().expect("objects lock");
            for (action, id) in actions {
                if let Some(on @ (3 | 4)) = action {
                    store.like(id, pid, on == 3)?;
                }
            }
        }
        _ => return Err(NOT_IMPLEMENTED),
    }
    Ok(w.into_bytes())
}
