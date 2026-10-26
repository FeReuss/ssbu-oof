//! Tournament (201, SSBU-only): Online Tourney entry and brackets. Layouts: docs/re/protocols.md, "Online Tourney".
//!
//! The game learns which tourney it is in, and every change to it, only from notifications of type 201xxx (param1 the
//! tourney ID, param2 a phase that only grows; `main+0x171f9d0`). Each new phase makes it fetch the tourney again
//! (201/12). The first notification (phase 0) is sent when the entry closes: the game fixes the bracket layout from the
//! first TournamentInfo it reads (player count and players per match), so that one must already hold the matches.

use super::{Ctx, Fail, NOT_IMPLEMENTED, Reply};
use crate::state::State;
use oof_nex::rmc::errors;
use oof_nex::stream::{Reader, Writer};
use std::sync::Arc;

/// One player entered from a console (201/9 lists every local player), or an empty seat (`pid` 0).
#[derive(Debug, Clone)]
pub struct Entrant {
    pub pid: u64,
    pub fighter: u8,
    pub costume: u8,
    pub name: String,
    /// The entry structure as the game sent it (echoed back in 201/12).
    pub raw: Vec<u8>,
}

/// One match of a bracket: the entrants (indexes into `Bracket::entrants`) who play it. IDs count from the final (0)
/// down to the first round, and `next` is the match the winner goes to: the game finds a finished match's winner as
/// the player of both (`main+0x239acc0`, docs/re/protocols.md "Match fields").
#[derive(Debug, Clone)]
pub struct Match {
    pub id: u32,
    /// 0 for the first round.
    pub round: u8,
    pub next: u32,
    pub players: Vec<u32>,
}

/// A bracket of one event: entrants grouped as they enter until it starts.
#[derive(Debug, Default)]
pub struct Bracket {
    pub id: u32,
    pub event: u64,
    pub entrants: Vec<Entrant>,
    /// Grows with every change the players must fetch (notification param2).
    pub phase: u8,
    pub matches: Vec<Match>,
}

#[derive(Debug, Default)]
pub struct Tournaments {
    brackets: Vec<Bracket>,
    next_id: u32,
}

/// Players per match. The game picks the bracket layout from the largest player list among the matches.
/// shortcut: 1v1 brackets only; 4-player ones (8/16/32/64 players) once the event setting that selects them is known.
const PER_MATCH: usize = 2;
/// Bracket sizes the game has a 1v1 layout for (`main+0x239d810`; docs/re/protocols.md, "Online Tourney").
const SIZES: [usize; 3] = [8, 16, 32];
const BRACKET_SIZE: usize = SIZES[SIZES.len() - 1];
/// Seconds the entry stays open when the event does not set `tournament_entry_max_seconds` (the game's default).
const ENTRY_SECONDS: u64 = 60;
/// Notification type the game watches for tourney changes (category 201, the protocol).
const TOURNEY_CHANGED: u32 = 201_000;

impl Tournaments {
    /// Put a console's players in the open bracket of `event` (a new one when it is full or started) and return the
    /// bracket ID and whether the bracket is new.
    pub fn enter(&mut self, event: u64, players: Vec<Entrant>) -> (u32, bool) {
        let pid = players.first().map(|p| p.pid);
        for b in self.brackets.iter_mut().filter(|b| b.matches.is_empty()) {
            b.entrants.retain(|e| Some(e.pid) != pid);
        }
        let open = self
            .brackets
            .iter()
            .position(|b| b.event == event && b.matches.is_empty() && b.entrants.len() + players.len() <= BRACKET_SIZE);
        let new = open.is_none();
        let i = open.unwrap_or_else(|| {
            self.next_id = self.next_id.wrapping_add(1).max(1);
            self.brackets.push(Bracket { id: self.next_id, event, ..Default::default() });
            self.brackets.len() - 1
        });
        self.brackets[i].entrants.extend(players);
        (self.brackets[i].id, new)
    }

    pub fn get(&self, id: u32) -> Option<&Bracket> {
        self.brackets.iter().find(|b| b.id == id)
    }

    /// Close the entry of bracket `id`: fill it up to a size the game has a layout for with empty seats (every round-1
    /// match needs players, an empty one aborts the game's bracket screen) and pair seats in entry order, so entrants
    /// meet each other first. Returns the PIDs to tell.
    /// shortcut: round 1 only; later rounds and results once the game's result report is decoded.
    pub fn start(&mut self, id: u32) -> Option<Vec<u64>> {
        let b = self.brackets.iter_mut().find(|b| b.id == id && b.matches.is_empty() && !b.entrants.is_empty())?;
        let size = SIZES.into_iter().find(|&s| s >= b.entrants.len()).unwrap_or(BRACKET_SIZE);
        let mut pids: Vec<u64> = b.entrants.iter().map(|e| e.pid).collect();
        pids.dedup();
        b.entrants.resize_with(size, Entrant::empty_seat);
        b.matches = bracket_matches(size);
        Some(pids)
    }

    /// 201/11: leave tourney `id`. Before the start the seat is freed; afterwards it stays (the player is absent).
    pub fn leave(&mut self, id: u32, pid: u64) {
        if let Some(b) = self.brackets.iter_mut().find(|b| b.id == id && b.matches.is_empty()) {
            b.entrants.retain(|e| e.pid != pid);
        }
    }

    /// The other players of `pid`'s first-round match in its latest started bracket (Online Tourney matchmaking, game mode
    /// 12, pairs only them).
    pub fn opponents(&self, pid: u64) -> Option<Vec<u64>> {
        let b =
            self.brackets.iter().rev().find(|b| !b.matches.is_empty() && b.entrants.iter().any(|e| e.pid == pid))?;
        let seat = b.entrants.iter().position(|e| e.pid == pid)? as u32;
        let m = b.matches.iter().find(|m| m.round == 0 && m.players.contains(&seat))?;
        Some(m.players.iter().map(|&k| b.entrants[k as usize].pid).filter(|&p| p != pid && p != 0).collect())
    }
}

/// Every match of a bracket of `size` seats, in ID order (the final first): first-round matches hold the seats in
/// order, later ones wait for winners.
fn bracket_matches(size: usize) -> Vec<Match> {
    let mut per_round = vec![size / PER_MATCH];
    while *per_round.last().expect("not empty") > 1 {
        per_round.push(per_round.last().expect("not empty") / PER_MATCH);
    }
    // the ID of round r's first match: the matches of every later round come before it
    let first = |r: usize| per_round[r + 1..].iter().sum::<usize>() as u32;
    let mut matches = Vec::new();
    for r in (0..per_round.len()).rev() {
        for p in 0..per_round[r] {
            let next = if r + 1 < per_round.len() { first(r + 1) + (p / PER_MATCH) as u32 } else { 0 };
            let players =
                if r == 0 { ((p * PER_MATCH) as u32..((p + 1) * PER_MATCH) as u32).collect() } else { Vec::new() };
            matches.push(Match { id: first(r) + p as u32, round: r as u8, next, players });
        }
    }
    matches
}

impl Entrant {
    /// A seat nobody took: no player, an entry with fighter 0 and no name.
    fn empty_seat() -> Self {
        let mut w = Writer::new();
        w.u8(0).u8(0).u8(0).string("").qbuffer(&[]).qbuffer(&[]).qbuffer(&[]);
        Entrant { pid: 0, fighter: 0, costume: 0, name: String::new(), raw: w.into_bytes() }
    }
}

fn announce(state: &State, id: u32, phase: u8, pids: &[u64]) {
    for &pid in pids {
        let event = crate::matchmaking::Notification {
            source: pid,
            kind: TOURNEY_CHANGED,
            param1: u64::from(id),
            param2: u64::from(phase),
            text: String::new(),
            param3: 0,
        };
        state.notify(pid, &event);
    }
}

pub fn handle(ctx: &mut Ctx, method: u32, r: &mut Reader) -> Reply {
    let pid = ctx.pid.expect("dispatch only routes secure connections here");
    match method {
        // Struct{u64 event id, u32, u16, List<Struct{u8 fighter, u8 costume, u8, String name, qBuffer x3}>} -> u32
        9 => {
            let (_, mut p) = r.structure()?;
            let (event, a, b) = (p.u64()?, p.u32()?, p.u16()?);
            let players = p.list(|r| {
                let (_, mut e) = r.structure()?;
                let raw = e.clone().take(e.remaining())?.to_vec();
                let (fighter, costume, _flags, name) = (e.u8()?, e.u8()?, e.u8()?, e.string()?);
                for _ in 0..3 {
                    e.qbuffer()?;
                }
                Ok(Entrant { pid, fighter, costume, name, raw })
            })?;
            let Some(config) = ctx.state.config.events.iter().find(|e| u64::from(e.id) == event) else {
                return Err(Fail(errors::CORE_INVALID_ARGUMENT));
            };
            if players.is_empty() {
                return Err(Fail(errors::CORE_INVALID_ARGUMENT));
            }
            let entry_seconds = match config.params.get("tournament_entry_max_seconds") {
                Some(crate::events::Param::Int(s)) if *s > 0 => *s as u64,
                _ => ENTRY_SECONDS,
            };
            let count = players.len();
            let (bracket, new) = ctx.state.tournaments.lock().expect("tournaments lock").enter(event, players);
            tracing::info!(pid, event, a, b, players = count, bracket, "tourney entry");
            // the entry stays open as long as the game counts down (tournament_entry_max_seconds), then phase 0
            if new {
                let state = Arc::clone(ctx.state);
                tokio::spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_secs(entry_seconds)).await;
                    let started = state.tournaments.lock().expect("tournaments lock").start(bracket);
                    if let Some(pids) = started {
                        tracing::info!(bracket, players = pids.len(), "tourney started");
                        announce(&state, bracket, 0, &pids);
                    }
                });
            }
            let mut w = Writer::new();
            w.u32(bracket);
            Ok(w.into_bytes())
        }
        // Struct{u32 tourney ID} -> TournamentInfo{u32, u32, u8, u8, u32, Map<u32, TournamentMatchInfo{u32, u32, u8, u8,
        // u8, List<u32>, u8, u64}>, Map<u32, TournamentPlayerInfo{u32, u64 PID, u32, u16, u8, u8, u8, List<entry as in
        // 9>}>} (readers main+0x2b03a0, 0x2b0fb0, 0x2b1740). Asked after every tourney notification.
        // TournamentMatchInfo = {u32 ID, u32 next match, u8 round, u8 state (5 = finished), u8, List<u32> player keys, u8,
        // u64}; the game fills the first round's seats from the round-0 matches in order (docs/re/protocols.md).
        // shortcut: no results yet (every match state 0), and TournamentInfo's u32s other than ID and phase are guesses.
        12 => {
            let (_, mut p) = r.structure()?;
            let id = p.u32()?;
            let tournaments = ctx.state.tournaments.lock().expect("tournaments lock");
            let Some(bracket) = tournaments.get(id) else { return Err(Fail(errors::CORE_INVALID_ARGUMENT)) };
            tracing::debug!(id, entrants = bracket.entrants.len(), matches = bracket.matches.len(), "tourney info");
            let mut w = Writer::new();
            w.structure(0, |w| {
                // +0x14 is the phase: the game refetches only when a notification carries a higher one
                w.u32(bracket.id).u32(0).u8(bracket.phase).u8(0).u32(bracket.entrants.len() as u32);
                w.u32(bracket.matches.len() as u32);
                for m in &bracket.matches {
                    w.u32(m.id).structure(0, |w| {
                        w.u32(m.id).u32(m.next).u8(m.round).u8(0).u8(0);
                        w.list(&m.players, |w, k| {
                            w.u32(*k);
                        });
                        w.u8(0).u64(0);
                    });
                }
                w.u32(bracket.entrants.len() as u32);
                for (i, e) in bracket.entrants.iter().enumerate() {
                    w.u32(i as u32).structure(0, |w| {
                        w.u32(i as u32).pid(e.pid).u32(0).u16(0).u8(0).u8(0).u8(0);
                        w.u32(1).structure(0, |w| {
                            w.bytes(&e.raw);
                        });
                    });
                }
            });
            Ok(w.into_bytes())
        }
        // 11: leave the tourney, Struct{u32 tourney ID} -> u32 (kind 1 of the request switch main+0x1736cd0 sends 10, by
        // event, before the tourney ID is known). 13: Struct{u32 tourney ID, u32 (1 in round 1)} -> u32, sent ~10 s after
        // the match's mesh is complete: 1 starts the match, 0 makes both players leave (verified with the game).
        11 | 13 => {
            let (_, mut p) = r.structure()?;
            let id = p.u32()?;
            let arg = if method == 13 { Some(p.u32()?) } else { None };
            tracing::info!(pid, method, id, arg, "tourney call");
            if method == 11 {
                ctx.state.tournaments.lock().expect("tournaments lock").leave(id, pid);
            }
            let mut w = Writer::new();
            w.u32(u32::from(method == 13));
            Ok(w.into_bytes())
        }
        // 14: the match result, Struct{u32 tourney ID, u32 (0 in round 1), u32 (1 from both players of a 1v1 whose
        // seats were 0 and 1: likely the winner's key), u64 (the data ID of the replay the player posted just before as
        // DataStore type 18, else 0)} -> u32. Sent by each player when a match ends (verified with the game, run tw20).
        // shortcut: only logged; results drive the next round once the meaning of the u32s is confirmed.
        14 => {
            let (_, mut p) = r.structure()?;
            let (id, a, b, replay) = (p.u32()?, p.u32()?, p.u32()?, p.u64()?);
            tracing::info!(pid, id, a, b, replay, "tourney match result");
            let mut w = Writer::new();
            w.u32(1);
            Ok(w.into_bytes())
        }
        _ => Err(NOT_IMPLEMENTED),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn player(pid: u64) -> Vec<Entrant> {
        vec![Entrant { pid, fighter: 6, costume: 0, name: format!("p{pid}"), raw: Vec::new() }]
    }

    #[test]
    fn entrants_share_a_bracket_until_it_is_full() {
        let mut t = Tournaments::default();
        let (first, new) = t.enter(1, player(10));
        assert!(new);
        assert_eq!(t.enter(1, player(11)), (first, false));
        assert_ne!(t.enter(2, player(12)).0, first); // another event, another bracket
        assert_eq!(t.enter(1, player(10)).0, first); // entering again does not count twice
        assert_eq!(t.get(first).unwrap().entrants.len(), 2);
        for pid in 100..130 {
            assert_eq!(t.enter(1, player(pid)).0, first);
        }
        assert_ne!(t.enter(1, player(200)).0, first); // 32 entrants: the next one opens a new bracket
    }

    #[test]
    fn starting_fills_a_layout_size_and_pairs_entrants_first() {
        let mut t = Tournaments::default();
        let (id, _) = t.enter(1, player(10));
        t.enter(1, player(11));
        t.enter(1, player(12));
        assert_eq!(t.start(id).unwrap(), vec![10, 11, 12]);
        let b = t.get(id).unwrap();
        assert_eq!(b.entrants.len(), 8, "the smallest 1v1 layout has 8 players");
        let shape: Vec<_> = b.matches.iter().map(|m| (m.id, m.round, m.next, m.players.clone())).collect();
        assert_eq!(
            shape,
            vec![
                (0, 2, 0, vec![]),
                (1, 1, 0, vec![]),
                (2, 1, 0, vec![]),
                (3, 0, 1, vec![0, 1]),
                (4, 0, 1, vec![2, 3]),
                (5, 0, 2, vec![4, 5]),
                (6, 0, 2, vec![6, 7]),
            ],
            "final first, winners of 3 and 4 meet in 1"
        );
        assert_eq!(bracket_matches(32).len(), 31);
        assert_eq!(t.opponents(10), Some(vec![11]));
        assert_eq!(t.opponents(12), Some(vec![]), "an empty seat is nobody to wait for");
        assert!(t.start(id).is_none(), "started twice");
        assert_ne!(t.enter(1, player(13)).0, id, "entered a started bracket");
    }

    #[test]
    fn leaving_frees_the_seat_only_before_the_start() {
        let mut t = Tournaments::default();
        let (id, _) = t.enter(1, player(10));
        t.enter(1, player(11));
        t.leave(id, 11);
        assert_eq!(t.get(id).unwrap().entrants.len(), 1);
        t.enter(1, player(11));
        t.start(id);
        t.leave(id, 11);
        assert_eq!(t.opponents(10), Some(vec![11]), "a started bracket keeps the seat");
    }
}
