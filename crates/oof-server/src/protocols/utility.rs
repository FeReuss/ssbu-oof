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
        // GetIntegerSettings(u32 index) -> Map<u16, i32>; no server-side overrides
        7 => {
            r.u32()?;
            w.u32(0);
        }
        // GetStringSettings(u32 index) -> Map<u16, String>
        8 => {
            r.u32()?;
            w.u32(0);
        }
        // GetGameEvents(Struct{u32, String}) -> List<GameEvent>
        // shortcut: no events are scheduled yet; tourneys need the event model (docs/features.md)
        11 => {
            r.structure()?;
            w.u32(0);
        }
        _ => return Err(NOT_IMPLEMENTED),
    }
    Ok(w.into_bytes())
}
