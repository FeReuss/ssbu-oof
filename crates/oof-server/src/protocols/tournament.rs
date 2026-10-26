//! Tournament (201, SSBU-only): Online Tourney entry and brackets. Layouts: docs/re/protocols.md, "Online Tourney".
//!
//! The game learns which tourney it is in, and every change to it, only from notifications of type 201xxx (param1 the
//! tourney ID, param2 a phase that only grows; `main+0x171f9d0`). Each new phase makes it fetch the tourney again
//! (201/12). The first notification must carry phase 0.

use super::{Ctx, Fail, NOT_IMPLEMENTED, Reply};
use crate::state::State;
use oof_nex::rmc::errors;
use oof_nex::stream::{Reader, Writer};
use std::sync::Arc;

/// One player entered from a console (201/9 lists every local player).
#[derive(Debug, Clone)]
pub struct Entrant {
    pub pid: u64,
    pub fighter: u8,
    pub costume: u8,
    pub name: String,
    /// The entry structure as the game sent it (echoed back in 201/12).
    pub raw: Vec<u8>,
}

/// One match of a bracket: the entrants (indexes into `Bracket::entrants`) who play it.
#[derive(Debug, Clone)]
pub struct Match {
    pub id: u32,
    pub round: u32,
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

/// Entrants per bracket ("a battle for victory among 64 players" on the tourney screen).
const BRACKET_SIZE: usize = 64;
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

    /// Close the entry of bracket `id`: pair its entrants in entry order for round 1 (an odd one out plays alone)
    /// and move to the next phase. Returns the new phase and the PIDs to tell.
    /// shortcut: one round; later rounds, results and byes come once the game's reports (201/13, 201/14) are decoded.
    pub fn start(&mut self, id: u32) -> Option<(u8, Vec<u64>)> {
        let b = self.brackets.iter_mut().find(|b| b.id == id && b.matches.is_empty())?;
        let keys: Vec<u32> = (0..b.entrants.len() as u32).collect();
        b.matches = keys.chunks(2).zip(0..).map(|(pair, id)| Match { id, round: 0, players: pair.to_vec() }).collect();
        b.phase += 1;
        let mut pids: Vec<u64> = b.entrants.iter().map(|e| e.pid).collect();
        pids.dedup();
        Some((b.phase, pids))
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
            announce(ctx.state, bracket, 0, &[pid]);
            // shortcut: brackets do not start yet: with matches in 201/12 the game's bracket screen aborts
            // (std::out_of_range, docs/PROGRESS.md "Next"); set OOF_TOURNEY_START=1 to reproduce it.
            if new && std::env::var_os("OOF_TOURNEY_START").is_some() {
                let state = Arc::clone(ctx.state);
                tokio::spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_secs(entry_seconds)).await;
                    let started = state.tournaments.lock().expect("tournaments lock").start(bracket);
                    if let Some((phase, pids)) = started {
                        tracing::info!(bracket, phase, players = pids.len(), "tourney started");
                        announce(&state, bracket, phase, &pids);
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
        // shortcut: the meaning of most fields is not known yet; matches carry their ID, round and players' keys.
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
                        w.u32(m.id).u32(m.round).u8(0).u8(0).u8(0);
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
        for pid in 100..162 {
            assert_eq!(t.enter(1, player(pid)).0, first);
        }
        assert_ne!(t.enter(1, player(200)).0, first); // 64 entrants: the next one opens a new bracket
    }

    #[test]
    fn starting_pairs_entrants_and_closes_the_entry() {
        let mut t = Tournaments::default();
        let (id, _) = t.enter(1, player(10));
        t.enter(1, player(11));
        t.enter(1, player(12));
        let (phase, pids) = t.start(id).unwrap();
        assert_eq!((phase, pids), (1, vec![10, 11, 12]));
        let players: Vec<_> = t.get(id).unwrap().matches.iter().map(|m| m.players.clone()).collect();
        assert_eq!(players, vec![vec![0, 1], vec![2]]);
        assert!(t.start(id).is_none(), "started twice");
        assert_ne!(t.enter(1, player(13)).0, id, "entered a started bracket");
    }
}
