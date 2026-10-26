//! Matchmake Referee (120): the per-player stats behind Smash power and Elite Smash. Layouts: docs/re/protocols.md,
//! "Matchmake Referee".

use super::{Ctx, NOT_IMPLEMENTED, Reply};
use oof_nex::stream::{Reader, Writer};

/// The `u32` counters after the PID in SSBU's MatchmakeRefereeStats (reader `main+0x25c130`): NEX's 13 (six recent,
/// six total, the rating) and one more.
const COUNTERS: usize = 14;
/// Where NEX keeps the rating among the counters.
const RATING: usize = 12;

/// MatchmakeRefereeStats{u64 unique ID, u32 category, u64 PID, u32 × COUNTERS} for a player with no rounds yet.
fn new_stats(w: &mut Writer, category: u32, pid: u64, rating: u32) {
    w.structure(0, |w| {
        w.u64(0).u32(category).pid(pid);
        for i in 0..COUNTERS {
            w.u32(if i == RATING { rating } else { 0 });
        }
    });
}

pub fn handle(ctx: &mut Ctx, method: u32, r: &mut Reader) -> Reply {
    let pid = ctx.pid.expect("dispatch only routes secure connections here");
    match method {
        // 12 GetOrCreateStats(MatchmakeRefereeStatsInitParam{u32 category, u32 initial rating}) -> MatchmakeRefereeStats.
        // Seen from the game (category 1, rating 1500) with the service switches 9010-9015 on, after a Quickplay match.
        // shortcut: nothing is stored yet: every player has the initial rating until rounds (1, 3) are kept.
        12 => {
            let (_, mut p) = r.structure()?;
            let (category, rating) = (p.u32()?, p.u32()?);
            tracing::debug!(pid, category, rating, "GetOrCreateStats");
            let mut w = Writer::new();
            new_stats(&mut w, category, pid, rating);
            Ok(w.into_bytes())
        }
        _ => Err(NOT_IMPLEMENTED),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_stats_carry_the_initial_rating() {
        let mut w = Writer::new();
        new_stats(&mut w, 1, 77, 1500);
        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes);
        let (_, mut s) = r.structure().unwrap();
        assert_eq!((s.u64().unwrap(), s.u32().unwrap(), s.pid().unwrap()), (0, 1, 77));
        let counters: Vec<u32> = (0..COUNTERS).map(|_| s.u32().unwrap()).collect();
        assert_eq!(counters[RATING], 1500);
        assert_eq!(counters.iter().sum::<u32>(), 1500);
        assert_eq!(s.remaining(), 0);
    }
}
