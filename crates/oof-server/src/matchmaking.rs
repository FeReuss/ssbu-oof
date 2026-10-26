//! Gatherings (NEX matchmake sessions): the shared state behind Quickplay, Elite Smash, Battle Arenas
//! and background matchmaking. Pure logic; the protocol layer parses requests, calls in here under
//! one lock, and sends the returned notifications after releasing it.
//!
//! Wire layouts are NEX 4.x (verified against SSBU 13.0.5's serializer at `main+0x254b00`; see
//! docs/re/protocols.md).

use oof_nex::stream::{DateTime, Reader, Result, Variant, Writer};
use std::collections::BTreeMap;

pub const PARTICIPANT_JOINED: u32 = 3001;
pub const PARTICIPANT_LEFT: u32 = 3002;
pub const PARTICIPANT_DISCONNECTED: u32 = 3007;
pub const OWNERSHIP_CHANGED: u32 = 4000;
pub const GATHERING_UNREGISTERED: u32 = 109_000;
pub const HOST_CHANGED: u32 = 110_000;

/// `NotificationEvent` (Switch revision 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notification {
    pub source: u64,
    pub kind: u32,
    pub param1: u64,
    pub param2: u64,
    pub text: String,
    pub param3: u64,
}

impl Notification {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.structure(1, |w| {
            w.pid(self.source)
                .u32(self.kind)
                .u64(self.param1)
                .u64(self.param2)
                .string(&self.text)
                .u64(self.param3)
                .u32(0);
        });
        w.into_bytes()
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct MatchmakeSession {
    // Gathering
    pub id: u32,
    pub owner: u64,
    pub host: u64,
    pub min_participants: u16,
    pub max_participants: u16,
    pub participation_policy: u32,
    pub policy_argument: u32,
    pub flags: u32,
    pub state: u32,
    pub description: String,
    // MatchmakeSession
    pub game_mode: u32,
    pub attribs: Vec<u32>,
    pub open_participation: bool,
    pub matchmake_system: u32,
    pub application_buffer: Vec<u8>,
    pub participation_count: u32,
    pub progress_score: u8,
    pub session_key: Vec<u8>,
    pub option: u32,
    pub param: Vec<(String, Variant)>,
    pub started: DateTime,
    pub user_password: String,
    pub refer_gid: u32,
    pub user_password_enabled: bool,
    pub system_password_enabled: bool,
    pub codeword: String,
}

fn read_param(r: &mut Reader) -> Result<Vec<(String, Variant)>> {
    let (_, mut s) = r.structure()?;
    s.list(|r| Ok((r.string()?, r.variant()?)))
}

fn write_param(w: &mut Writer, param: &[(String, Variant)]) {
    w.structure(0, |w| {
        w.list(param, |w, (k, v)| {
            w.string(k).variant(v);
        });
    });
}

impl MatchmakeSession {
    /// Reads `Gathering` + `MatchmakeSession` structures (each with its own header).
    pub fn read(r: &mut Reader) -> Result<Self> {
        let (_, mut g) = r.structure()?;
        let mut s = MatchmakeSession {
            id: g.u32()?,
            owner: g.pid()?,
            host: g.pid()?,
            min_participants: g.u16()?,
            max_participants: g.u16()?,
            participation_policy: g.u32()?,
            policy_argument: g.u32()?,
            flags: g.u32()?,
            state: g.u32()?,
            description: g.string()?,
            ..Default::default()
        };
        let (_, mut m) = r.structure()?;
        s.game_mode = m.u32()?;
        s.attribs = m.list(|r| r.u32())?;
        s.open_participation = m.bool()?;
        s.matchmake_system = m.u32()?;
        s.application_buffer = m.buffer()?.to_vec();
        s.participation_count = m.u32()?;
        s.progress_score = m.u8()?;
        s.session_key = m.buffer()?.to_vec();
        s.option = m.u32()?;
        s.param = read_param(&mut m)?;
        s.started = DateTime(m.u64()?);
        s.user_password = m.string()?;
        s.refer_gid = m.u32()?;
        s.user_password_enabled = m.bool()?;
        s.system_password_enabled = m.bool()?;
        s.codeword = m.string()?;
        Ok(s)
    }

    pub fn write(&self, w: &mut Writer) {
        w.structure(0, |w| {
            w.u32(self.id)
                .pid(self.owner)
                .pid(self.host)
                .u16(self.min_participants)
                .u16(self.max_participants)
                .u32(self.participation_policy)
                .u32(self.policy_argument)
                .u32(self.flags)
                .u32(self.state)
                .string(&self.description);
        });
        w.structure(0, |w| {
            w.u32(self.game_mode)
                .list(&self.attribs, |w, a| {
                    w.u32(*a);
                })
                .bool(self.open_participation)
                .u32(self.matchmake_system)
                .buffer(&self.application_buffer)
                .u32(self.participation_count)
                .u8(self.progress_score)
                .buffer(&self.session_key)
                .u32(self.option);
            write_param(w, &self.param);
            w.u64(self.started.0)
                .string(&self.user_password)
                .u32(self.refer_gid)
                .bool(self.user_password_enabled)
                .bool(self.system_password_enabled)
                .string(&self.codeword);
        });
    }
}

/// `MatchmakeSessionSearchCriteria`: every field is a string filter ("" = any, "n" = exact,
/// "a,b" = inclusive range), matched against the session's attributes.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SearchCriteria {
    pub attribs: Vec<String>,
    pub game_mode: String,
    pub min_participants: String,
    pub max_participants: String,
    pub matchmake_system: String,
    pub vacant_only: bool,
    pub exclude_locked: bool,
    pub exclude_non_host_pid: bool,
    pub selection_method: u32,
    pub vacant_participants: u16,
    pub exclude_user_password: bool,
    pub exclude_system_password: bool,
    pub refer_gid: u32,
    pub codeword: String,
    pub offset: u32,
    pub size: u32,
}

impl SearchCriteria {
    pub fn read(r: &mut Reader) -> Result<Self> {
        let (_, mut s) = r.structure()?;
        let mut c = SearchCriteria {
            attribs: s.list(|r| r.string())?,
            game_mode: s.string()?,
            min_participants: s.string()?,
            max_participants: s.string()?,
            matchmake_system: s.string()?,
            vacant_only: s.bool()?,
            exclude_locked: s.bool()?,
            exclude_non_host_pid: s.bool()?,
            selection_method: s.u32()?,
            vacant_participants: s.u16()?,
            ..Default::default()
        };
        read_param(&mut s)?;
        c.exclude_user_password = s.bool()?;
        c.exclude_system_password = s.bool()?;
        c.refer_gid = s.u32()?;
        c.codeword = s.string()?;
        let (_, mut range) = s.structure()?;
        c.offset = range.u32()?;
        c.size = range.u32()?;
        Ok(c)
    }

    fn matches(&self, g: &Gathering, needed: u32) -> bool {
        let s = &g.session;
        let vacant = (s.max_participants as u32).saturating_sub(s.participation_count);
        filter(&self.game_mode, s.game_mode)
            && filter(&self.min_participants, s.min_participants as u32)
            && filter(&self.max_participants, s.max_participants as u32)
            && filter(&self.matchmake_system, s.matchmake_system)
            && self
                .attribs
                .iter()
                .enumerate()
                .all(|(i, f)| f.trim().is_empty() || s.attribs.get(i).is_some_and(|v| filter(f, *v)))
            && (!self.vacant_only || vacant >= needed.max(self.vacant_participants as u32).max(1))
            && (!self.exclude_locked || s.open_participation)
            && (!self.exclude_user_password || !s.user_password_enabled)
            && (!self.exclude_system_password || !s.system_password_enabled)
            && (self.codeword.is_empty() || self.codeword == s.codeword)
    }
}

fn filter(spec: &str, value: u32) -> bool {
    let spec = spec.trim();
    if spec.is_empty() {
        return true;
    }
    match spec.split_once(',') {
        Some((lo, hi)) => match (lo.trim().parse::<u32>(), hi.trim().parse::<u32>()) {
            (Ok(lo), Ok(hi)) => (lo..=hi).contains(&value),
            _ => false,
        },
        None => spec.parse::<u32>().is_ok_and(|v| v == value),
    }
}

#[derive(Debug, Clone)]
pub struct Gathering {
    pub session: MatchmakeSession,
    /// (pid, players on that console): online co-op brings two players on one PID.
    pub participants: Vec<(u64, u32)>,
    pub system_password: String,
    /// Arena ID players type to find this gathering (109/55, 109/56); empty until first asked for.
    pub code: String,
}

impl Gathering {
    fn recount(&mut self) {
        self.session.participation_count = self.participants.iter().map(|(_, n)| n).sum();
    }

    pub fn has(&self, pid: u64) -> bool {
        self.participants.iter().any(|(p, _)| *p == pid)
    }
}

#[derive(Debug)]
pub enum JoinError {
    NotFound,
    Full,
    Closed,
    WrongPassword,
}

pub type Notices = Vec<(u64, Notification)>;

/// 3001: param1 = gathering, param2 = participant (both read by Pia's handler, main+0xef5d0); Pia
/// also reads a leading digit 1-4 of the text as the participant's player count.
fn joined_note(gid: u32, pid: u64, message: &str, count: u32) -> Notification {
    Notification {
        source: pid,
        kind: PARTICIPANT_JOINED,
        param1: gid as u64,
        param2: pid,
        text: message.to_string(),
        param3: count as u64,
    }
}

#[derive(Debug, Default)]
pub struct Matchmaking {
    gatherings: BTreeMap<u32, Gathering>,
    next_id: u32,
}

impl Matchmaking {
    pub fn get(&self, gid: u32) -> Option<&Gathering> {
        self.gatherings.get(&gid)
    }

    pub fn get_mut(&mut self, gid: u32) -> Option<&mut Gathering> {
        self.gatherings.get_mut(&gid)
    }

    /// The Arena ID of `gid`, issued on first request from `fresh` and unique among live gatherings.
    pub fn code(&mut self, gid: u32, mut fresh: impl FnMut() -> String) -> Option<String> {
        if self.gatherings.get(&gid)?.code.is_empty() {
            let code = std::iter::repeat_with(&mut fresh).find(|c| self.by_code(c).is_none())?;
            self.gatherings.get_mut(&gid)?.code = code;
        }
        Some(self.gatherings[&gid].code.clone())
    }

    /// The gathering whose Arena ID is `code` (typed by a player, so case is ignored).
    pub fn by_code(&self, code: &str) -> Option<u32> {
        let code = code.trim();
        self.gatherings.values().find(|g| !g.code.is_empty() && g.code.eq_ignore_ascii_case(code)).map(|g| g.session.id)
    }

    pub fn len(&self) -> usize {
        self.gatherings.len()
    }

    /// Register a new session owned and hosted by `pid` (who joins it with `players` players). The
    /// creator is told about its own participation like any joiner (see `join`).
    pub fn create(
        &mut self,
        pid: u64,
        mut session: MatchmakeSession,
        players: u32,
        session_key: Vec<u8>,
        message: &str,
    ) -> (MatchmakeSession, Notices) {
        self.next_id = self.next_id.wrapping_add(1).max(1);
        while self.gatherings.contains_key(&self.next_id) {
            self.next_id = self.next_id.wrapping_add(1).max(1);
        }
        session.id = self.next_id;
        session.owner = pid;
        session.host = pid;
        session.session_key = session_key;
        // Pia's packet key (first 16 bytes): lets a developer decrypt a capture of a test match
        tracing::trace!(gid = session.id, key = %session.session_key.iter().map(|b| format!("{b:02x}")).collect::<String>(), "session key");
        session.started = DateTime::now();
        if session.max_participants == 0 {
            session.max_participants = 8;
        }
        let mut g = Gathering {
            session,
            participants: vec![(pid, players.max(1))],
            system_password: String::new(),
            code: String::new(),
        };
        g.recount();
        let out = g.session.clone();
        self.gatherings.insert(out.id, g);
        let note = joined_note(out.id, pid, message, out.participation_count);
        (out, vec![(pid, note)])
    }

    pub fn join(
        &mut self,
        gid: u32,
        pid: u64,
        players: u32,
        password: &str,
        message: &str,
    ) -> std::result::Result<(MatchmakeSession, Notices), JoinError> {
        let g = self.gatherings.get_mut(&gid).ok_or(JoinError::NotFound)?;
        if g.has(pid) {
            return Ok((g.session.clone(), Vec::new()));
        }
        if !g.session.open_participation {
            return Err(JoinError::Closed);
        }
        let password_ok = (!g.session.user_password_enabled || g.session.user_password == password)
            && (!g.session.system_password_enabled
                || g.system_password == password
                || g.session.user_password == password);
        if !password_ok {
            return Err(JoinError::WrongPassword);
        }
        let players = players.max(1);
        if g.session.participation_count + players > g.session.max_participants as u32 {
            return Err(JoinError::Full);
        }
        g.participants.push((pid, players));
        g.recount();
        // Everyone in the session hears about the newcomer, the newcomer included: Pia's
        // Nex{Create,Join}SessionJob::WaitNotification (main+0x1057a0) waits up to 10 s for a 3001
        // naming each local player in this gathering before it starts the P2P session.
        let note = joined_note(gid, pid, message, g.session.participation_count);
        let mut notices: Notices = g.participants.iter().map(|(p, _)| (*p, note.clone())).collect();
        // The newcomer also hears about everyone already there: Pia connects only to stations whose PID it saw in a
        // 3001 for this gathering (NexConnectStationJob vtable+0x40 = main+0xf1db0 -> registry main+0xee8d0), else
        // SendConnectionRequest fails right after the NAT traversal. Pia reads the count from the text's first digit.
        for &(p, n) in g.participants.iter().filter(|(p, _)| *p != pid) {
            let count = if (2..=4).contains(&n) { n.to_string() } else { String::new() };
            notices.push((pid, joined_note(gid, p, &count, g.session.participation_count)));
        }
        Ok((g.session.clone(), notices))
    }

    /// First session matching any criteria with room for `players`, oldest first; with `only`, one whose participants
    /// are all in that list.
    pub fn find_open(&self, criteria: &[SearchCriteria], pid: u64, players: u32, only: Option<&[u64]>) -> Option<u32> {
        self.gatherings
            .values()
            .filter(|g| g.session.open_participation && !g.has(pid))
            .filter(|g| !g.session.user_password_enabled && !g.session.system_password_enabled)
            .filter(|g| g.session.participation_count + players.max(1) <= g.session.max_participants as u32)
            .filter(|g| only.is_none_or(|o| g.participants.iter().all(|(p, _)| o.contains(p))))
            .find(|g| criteria.is_empty() || criteria.iter().any(|c| c.matches(g, players)))
            .map(|g| g.session.id)
    }

    pub fn browse(&self, criteria: &SearchCriteria) -> Vec<MatchmakeSession> {
        self.gatherings
            .values()
            .filter(|g| criteria.matches(g, 1))
            .skip(criteria.offset as usize)
            .take(if criteria.size == 0 { 100 } else { criteria.size.min(100) as usize })
            .map(|g| g.session.clone())
            .collect()
    }

    pub fn by_participant(&self, pid: u64) -> Vec<MatchmakeSession> {
        self.gatherings.values().filter(|g| g.has(pid)).map(|g| g.session.clone()).collect()
    }

    pub fn by_owner(&self, pid: u64) -> Vec<MatchmakeSession> {
        self.gatherings.values().filter(|g| g.session.owner == pid).map(|g| g.session.clone()).collect()
    }

    /// Remove `pid` from one gathering, migrating ownership or deleting it when empty.
    pub fn leave(&mut self, gid: u32, pid: u64, kind: u32, message: &str) -> Notices {
        let Some(g) = self.gatherings.get_mut(&gid) else { return Vec::new() };
        if !g.has(pid) {
            return Vec::new();
        }
        g.participants.retain(|(p, _)| *p != pid);
        g.recount();
        if g.participants.is_empty() {
            self.gatherings.remove(&gid);
            return Vec::new();
        }
        let mut notes = Vec::new();
        if g.session.owner == pid {
            let new_owner = g.participants[0].0;
            g.session.owner = new_owner;
            for (p, _) in &g.participants {
                notes.push((
                    *p,
                    Notification {
                        source: pid,
                        kind: OWNERSHIP_CHANGED,
                        param1: gid as u64,
                        param2: new_owner,
                        text: String::new(),
                        param3: 0,
                    },
                ));
            }
        }
        if g.session.host == pid {
            g.session.host = g.session.owner;
        }
        notes.push((
            g.session.owner,
            Notification { source: pid, kind, param1: gid as u64, param2: pid, text: message.to_string(), param3: 0 },
        ));
        notes
    }

    /// The owner tears a gathering down; every remaining participant is told.
    pub fn unregister(&mut self, gid: u32, pid: u64) -> Option<Notices> {
        let g = self.gatherings.get(&gid)?;
        if g.session.owner != pid {
            return None;
        }
        let g = self.gatherings.remove(&gid)?;
        Some(
            g.participants
                .iter()
                .filter(|(p, _)| *p != pid)
                .map(|(p, _)| {
                    (
                        *p,
                        Notification {
                            source: pid,
                            kind: GATHERING_UNREGISTERED,
                            param1: gid as u64,
                            param2: 0,
                            text: String::new(),
                            param3: 0,
                        },
                    )
                })
                .collect(),
        )
    }

    /// Connection lost: leave every gathering.
    pub fn disconnect(&mut self, pid: u64) -> Notices {
        let gids: Vec<u32> = self.gatherings.values().filter(|g| g.has(pid)).map(|g| g.session.id).collect();
        gids.into_iter().flat_map(|gid| self.leave(gid, pid, PARTICIPANT_DISCONNECTED, "")).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(game_mode: u32, max: u16) -> MatchmakeSession {
        MatchmakeSession {
            game_mode,
            max_participants: max,
            open_participation: true,
            attribs: vec![3, 7],
            ..Default::default()
        }
    }

    #[test]
    fn wire_round_trip() {
        let mut s = session(2, 4);
        s.param = vec![("rule".into(), Variant::I64(5))];
        s.codeword = "ABCDE".into();
        let mut w = Writer::new();
        s.write(&mut w);
        let bytes = w.into_bytes();
        assert_eq!(MatchmakeSession::read(&mut Reader::new(&bytes)).unwrap(), s);
    }

    #[test]
    fn quickplay_style_flow() {
        let mut mm = Matchmaking::default();
        let crit = SearchCriteria {
            game_mode: "2".into(),
            attribs: vec!["".into(), "5,9".into()],
            vacant_only: true,
            ..Default::default()
        };
        assert_eq!(mm.find_open(std::slice::from_ref(&crit), 10, 1, None), None);
        let (created, notes) = mm.create(10, session(2, 2), 1, vec![1; 32], "");
        assert_eq!((created.owner, created.participation_count), (10, 1));
        // the creator is told about itself (Pia waits for it before starting P2P)
        assert_eq!(
            notes.iter().map(|(to, n)| (*to, n.kind, n.param2)).collect::<Vec<_>>(),
            [(10, PARTICIPANT_JOINED, 10)]
        );
        // co-op pair (2 players) does not fit in a 2-player session that already has 1
        assert_eq!(mm.find_open(std::slice::from_ref(&crit), 20, 2, None), None);
        let gid = mm.find_open(std::slice::from_ref(&crit), 20, 1, None).unwrap();
        let (joined, notes) = mm.join(gid, 20, 1, "", "hi").unwrap();
        assert_eq!(joined.participation_count, 2);
        // owner and joiner both hear that 20 joined this gathering, and the joiner hears that 10 is in it
        let seen: Vec<_> = notes.iter().map(|(to, n)| (*to, n.kind, n.param1, n.param2)).collect();
        assert_eq!(
            seen,
            [
                (10, PARTICIPANT_JOINED, gid as u64, 20),
                (20, PARTICIPANT_JOINED, gid as u64, 20),
                (20, PARTICIPANT_JOINED, gid as u64, 10)
            ]
        );
        assert!(matches!(mm.join(gid, 30, 1, "", ""), Err(JoinError::Full)));
        // owner drops: ownership moves to 20, who is told twice (ownership + disconnect)
        let notes = mm.disconnect(10);
        assert_eq!(mm.get(gid).unwrap().session.owner, 20);
        assert!(notes.iter().any(|(p, n)| *p == 20 && n.kind == OWNERSHIP_CHANGED));
        mm.disconnect(20);
        assert_eq!(mm.len(), 0);
    }

    #[test]
    fn explicit_group_filter_does_not_match_a_missing_attribute() {
        let mut mm = Matchmaking::default();
        let mut s = session(1, 2);
        s.attribs.clear();
        mm.create(10, s, 1, vec![1; 32], "");
        let mut criteria = SearchCriteria { attribs: vec!["1".into()], ..Default::default() };
        assert!(mm.browse(&criteria).is_empty());
        criteria.attribs[0] = " ".into();
        assert_eq!(mm.browse(&criteria).len(), 1);
    }

    #[test]
    fn passwords_and_filters() {
        let mut mm = Matchmaking::default();
        let mut s = session(1, 8);
        s.user_password_enabled = true;
        s.user_password = "1234".into();
        let gid = mm.create(1, s, 1, Vec::new(), "").0.id;
        assert!(matches!(mm.join(gid, 2, 1, "0000", ""), Err(JoinError::WrongPassword)));
        assert!(mm.join(gid, 2, 1, "1234", "").is_ok());
        // Arena IDs: stable once issued, unique, found case-insensitively
        let mut next = ["AAAAA", "AAAAA", "BBBBB"].into_iter().map(String::from);
        assert_eq!(mm.code(gid, || next.next().unwrap()).as_deref(), Some("AAAAA"));
        assert_eq!(mm.code(gid, || unreachable!()).as_deref(), Some("AAAAA"));
        let other = mm.create(3, session(1, 8), 1, Vec::new(), "").0.id;
        assert_eq!(mm.code(other, || next.next().unwrap()).as_deref(), Some("BBBBB"));
        assert_eq!((mm.by_code(" aaaaa"), mm.by_code("BBBBB"), mm.by_code("CCCCC")), (Some(gid), Some(other), None));
        assert_eq!(mm.code(999, || unreachable!()), None);
        assert!(filter("", 9) && filter("4", 4) && !filter("4", 5) && filter("1,3", 2) && !filter("x", 1));
    }
}
