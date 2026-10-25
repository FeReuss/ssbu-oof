//! Utility (110). Methods 9-11 are SSBU additions (docs/re/protocols.md); 11 lists the game's
//! timed events (online tourney schedule, spirit board events).

use super::{Ctx, NOT_IMPLEMENTED, Reply};
use oof_nex::stream::{Reader, Writer};

pub fn handle(ctx: &mut Ctx, method: u32, r: &mut Reader) -> Reply {
    let mut w = Writer::new();
    match method {
        // AcquireNexUniqueId -> u64 (ids for uploaded content and replays)
        1 => {
            w.u64(ctx.state.new_unique_id());
        }
        // GetIntegerSettings(u32 index) -> Map<u16, i32>: the operator's `integer_settings` for that index.
        7 => {
            let index = r.u32()?;
            let values = ctx.state.integer_settings.get(&index).map_or(&[][..], Vec::as_slice);
            tracing::debug!(index, ?values, "GetIntegerSettings");
            w.u32(values.len() as u32);
            for (key, value) in values {
                w.u16(*key).i32(*value);
            }
        }
        // GetStringSettings(u32 index) -> Map<u16, String>
        8 => {
            r.u32()?;
            w.u32(0);
        }
        // SSBU eligibility query: Struct{u32, u32, String} -> Struct{u32, u32, u32}.
        // shortcut: neutral eligibility data until the three fields' semantics are established
        9 => {
            let (_, mut p) = r.structure()?;
            p.u32()?;
            p.u32()?;
            p.string()?;
            w.structure(0, |w| {
                w.u32(0).u32(0).u32(0);
            });
        }
        // Struct{Struct{u32 x3}, i32} -> Struct{bool, u32}; false lets the game proceed.
        // shortcut: no server-side restriction policy yet; revisit when eligibility fields are mapped
        10 => {
            let (_, mut p) = r.structure()?;
            let (_, mut eligibility) = p.structure()?;
            eligibility.u32()?;
            eligibility.u32()?;
            eligibility.u32()?;
            p.i32()?;
            w.structure(0, |w| {
                w.bool(false).u32(0);
            });
        }
        // GetGameEvents(Struct{u32 kinds, String language}) -> List<GameEvent>: the operator's `[[events]]` sharing a
        // bit with the requested category mask (the online menu asks for 4, the tourney screen for 3).
        11 => {
            let (_, mut p) = r.structure()?;
            let (kinds, language) = (p.u32()?, p.string()?);
            let events: Vec<_> = ctx.state.config.events.iter().filter(|e| e.kinds & kinds != 0).cloned().collect();
            tracing::debug!(kinds, language, events = events.len(), "GetGameEvents");
            return Ok(crate::events::list(&events));
        }
        _ => return Err(NOT_IMPLEMENTED),
    }
    Ok(w.into_bytes())
}
