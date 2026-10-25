//! Tournament (201, SSBU-only): Online Tourney entry and brackets. Layouts: docs/re/protocols.md, "Online Tourney".

use super::{Ctx, Fail, NOT_IMPLEMENTED, Reply};
use oof_nex::rmc::errors;
use oof_nex::stream::{Reader, Writer};

/// One player entered from a console (201/9 lists every local player).
#[derive(Debug, Clone)]
pub struct Entrant {
    pub pid: u64,
    pub fighter: u8,
    pub costume: u8,
    pub name: String,
}

/// A bracket of one event: entrants grouped as they enter.
#[derive(Debug, Default)]
pub struct Bracket {
    pub id: u32,
    pub event: u64,
    pub entrants: Vec<Entrant>,
}

#[derive(Debug, Default)]
pub struct Tournaments {
    brackets: Vec<Bracket>,
    next_id: u32,
}

/// Entrants per bracket ("a battle for victory among 64 players" on the tourney screen).
const BRACKET_SIZE: usize = 64;

impl Tournaments {
    /// Put a console's players in the open bracket of `event` (a new one when it is full) and return the bracket ID.
    pub fn enter(&mut self, event: u64, players: Vec<Entrant>) -> u32 {
        let pid = players.first().map(|p| p.pid);
        for b in &mut self.brackets {
            b.entrants.retain(|e| Some(e.pid) != pid);
        }
        let open =
            self.brackets.iter().position(|b| b.event == event && b.entrants.len() + players.len() <= BRACKET_SIZE);
        let i = open.unwrap_or_else(|| {
            self.next_id = self.next_id.wrapping_add(1).max(1);
            self.brackets.push(Bracket { id: self.next_id, event, entrants: Vec::new() });
            self.brackets.len() - 1
        });
        self.brackets[i].entrants.extend(players);
        self.brackets[i].id
    }

    pub fn get(&self, id: u32) -> Option<&Bracket> {
        self.brackets.iter().find(|b| b.id == id)
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
                let (fighter, costume, _flags, name) = (e.u8()?, e.u8()?, e.u8()?, e.string()?);
                for _ in 0..3 {
                    e.qbuffer()?;
                }
                Ok(Entrant { pid, fighter, costume, name })
            })?;
            if players.is_empty() || !ctx.state.config.events.iter().any(|e| u64::from(e.id) == event) {
                return Err(Fail(errors::CORE_INVALID_ARGUMENT));
            }
            let count = players.len();
            let bracket = ctx.state.tournaments.lock().expect("tournaments lock").enter(event, players);
            tracing::info!(pid, event, a, b, players = count, bracket, "tourney entry");
            let mut w = Writer::new();
            w.u32(bracket);
            Ok(w.into_bytes())
        }
        _ => Err(NOT_IMPLEMENTED),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn player(pid: u64) -> Vec<Entrant> {
        vec![Entrant { pid, fighter: 6, costume: 0, name: format!("p{pid}") }]
    }

    #[test]
    fn entrants_share_a_bracket_until_it_is_full() {
        let mut t = Tournaments::default();
        let first = t.enter(1, player(10));
        assert_eq!(t.enter(1, player(11)), first);
        assert_ne!(t.enter(2, player(12)), first); // another event, another bracket
        assert_eq!(t.enter(1, player(10)), first); // entering again does not count twice
        assert_eq!(t.get(first).unwrap().entrants.len(), 2);
        for pid in 100..162 {
            assert_eq!(t.enter(1, player(pid)), first);
        }
        assert_ne!(t.enter(1, player(200)), first); // 64 entrants: the next one opens a new bracket
    }
}
