//! Match Making (21), Match Making Ext (50) and Matchmake Extension (109): gathering lifecycle.
//!
//! Method numbers are the ones the SSBU 13.0.5 client links (docs/re/protocols.md). Methods the game
//! links but this file lacks answer `Core::NotImplemented` and are logged by the dispatcher.

use super::{Ctx, Fail, MATCH_MAKING, MATCH_MAKING_EXT, NOT_IMPLEMENTED, Reply};
use crate::accounts;
use crate::matchmaking::{
    HOST_CHANGED, JoinError, MatchmakeSession, Matchmaking, Notices, Notification, PARTICIPANT_LEFT, SearchCriteria,
};
use oof_nex::rmc::errors;
use oof_nex::stream::{DateTime, Reader, Writer};

pub fn handle(ctx: &mut Ctx, protocol: u16, method: u32, r: &mut Reader) -> Reply {
    let pid = ctx.pid.expect("dispatch only routes secure connections here");
    match (protocol, method) {
        (MATCH_MAKING, 2) => unregister(ctx, pid, r),
        (MATCH_MAKING, 41) => session_urls(ctx, r),
        (MATCH_MAKING, 42) => update_host(ctx, pid, r),
        (MATCH_MAKING_EXT, 1) => end_participation(ctx, pid, r),
        (MATCH_MAKING, _) | (MATCH_MAKING_EXT, _) => Err(NOT_IMPLEMENTED),
        (_, 1) => set_open(ctx, pid, r, false),
        (_, 2) => set_open(ctx, pid, r, true),
        (_, 8) => modify_game_attribute(ctx, pid, r),
        (_, 11) => update_application_buffer(ctx, pid, r),
        (_, 12) => update_attributes(ctx, pid, r),
        (_, 34) => update_progress_score(ctx, pid, r),
        (_, 36) => system_password(ctx, pid, r, true),
        (_, 37) => system_password(ctx, pid, r, false),
        (_, 38) => create_with_param(ctx, pid, r),
        (_, 39) => join_with_param(ctx, pid, r),
        (_, 40) => auto_matchmake_with_param(ctx, pid, r),
        (_, 41) | (_, 49) => find_by_gid(ctx, r),
        (_, 44) => update_part(ctx, pid, r),
        (_, 48) => find_by_gids(ctx, r),
        (_, 50) => find_by_owner(ctx, r),
        (_, 51) => find_by_participant(ctx, r),
        (_, 52) => browse(ctx, r),
        (_, 55) => arena_code(ctx, r),
        (_, 56) => find_by_code(ctx, r),
        (_, 58) => matchmaking_group(pid, r),
        _ => Err(NOT_IMPLEMENTED),
    }
}

/// Resolve the queue mode to the group copied into session/search attribute 0 (docs/re/protocols.md).
fn matchmaking_group(pid: u64, r: &mut Reader) -> Reply {
    let mode = r.u32()?;
    // SSBU's call-site mask 0x20ae admits exactly these modes. Group IDs also index a 32-bit mask.
    if !matches!(mode, 1 | 2 | 3 | 5 | 7 | 13) || r.remaining() != 0 {
        return Err(Fail(errors::CORE_INVALID_ARGUMENT));
    }
    // OOF policy: one stable group per queue mode, including modes sharing the same NEX game_mode.
    let group = mode;
    tracing::debug!(pid, mode, group, "matchmaking group resolved");
    let mut w = Writer::new();
    w.u32(group);
    Ok(w.into_bytes())
}

/// Run `f` under the matchmaking lock, then deliver the notifications it produced.
fn with_mm<T>(ctx: &Ctx, f: impl FnOnce(&mut Matchmaking) -> (T, Notices)) -> T {
    let (out, notes) = f(&mut ctx.state.matchmaking.lock().expect("matchmaking lock"));
    for (to, note) in &notes {
        ctx.state.notify(*to, note);
    }
    out
}

fn join_error(e: JoinError) -> Fail {
    Fail(match e {
        JoinError::NotFound => errors::RENDEZVOUS_SESSION_VOID,
        JoinError::Full => errors::RENDEZVOUS_SESSION_FULL,
        JoinError::Closed => errors::RENDEZVOUS_SESSION_CLOSED,
        JoinError::WrongPassword => errors::RENDEZVOUS_INVALID_PASSWORD,
    })
}

fn session_bytes(s: &MatchmakeSession) -> Vec<u8> {
    let mut w = Writer::new();
    s.write(&mut w);
    w.into_bytes()
}

fn session_list(list: &[MatchmakeSession]) -> Vec<u8> {
    let mut w = Writer::new();
    w.list(list, |w, s| s.write(w));
    w.into_bytes()
}

/// Mutate a gathering the caller owns (or hosts).
fn owned(ctx: &Ctx, pid: u64, gid: u32, f: impl FnOnce(&mut crate::matchmaking::Gathering)) -> Reply {
    let mut mm = ctx.state.matchmaking.lock().expect("matchmaking lock");
    let g = mm.get_mut(gid).ok_or(Fail(errors::RENDEZVOUS_SESSION_VOID))?;
    if g.session.owner != pid && g.session.host != pid {
        return Err(Fail(errors::RENDEZVOUS_PERMISSION_DENIED));
    }
    f(g);
    Ok(Vec::new())
}

fn players(n: u16) -> u32 {
    n.max(1) as u32
}

fn create_with_param(ctx: &mut Ctx, pid: u64, r: &mut Reader) -> Reply {
    let (_, mut p) = r.structure()?;
    let session = MatchmakeSession::read(&mut p)?;
    let _additional = p.list(|r| r.pid())?;
    let _gid_check = p.u32()?;
    let _options = p.u32()?;
    let message = p.string()?;
    let count = p.u16()?;
    let created =
        with_mm(ctx, |mm| mm.create(pid, session, players(count), accounts::random_bytes::<32>().to_vec(), &message));
    tracing::info!(pid, gid = created.id, game_mode = created.game_mode, "session created");
    Ok(session_bytes(&created))
}

fn join_with_param(ctx: &mut Ctx, pid: u64, r: &mut Reader) -> Reply {
    let (_, mut p) = r.structure()?;
    let gid = p.u32()?;
    let _participants = p.list(|r| r.pid())?;
    let _gid_check = p.u32()?;
    let _options = p.u32()?;
    let _behavior = p.u8()?;
    let user_password = p.string()?;
    let system_password = p.string()?;
    let message = p.string()?;
    let count = p.u16()?;
    let password = if user_password.is_empty() { system_password } else { user_password };
    let joined = with_mm(ctx, |mm| match mm.join(gid, pid, players(count), &password, &message) {
        Ok((s, notes)) => (Ok(s), notes),
        Err(e) => (Err(e), Vec::new()),
    })
    .map_err(join_error)?;
    Ok(session_bytes(&joined))
}

/// Quickplay / Elite Smash / background matchmaking: join the first compatible session, or open one.
fn auto_matchmake_with_param(ctx: &mut Ctx, pid: u64, r: &mut Reader) -> Reply {
    let (_, mut p) = r.structure()?;
    let session = MatchmakeSession::read(&mut p)?;
    let _participants = p.list(|r| r.pid())?;
    let _gid_check = p.u32()?;
    let _options = p.u32()?;
    let message = p.string()?;
    let count = players(p.u16()?);
    let criteria = p.list(SearchCriteria::read)?;
    let _target_gids = p.list(|r| r.u32())?;
    let key = accounts::random_bytes::<32>().to_vec();
    let result = with_mm(ctx, |mm| {
        if let Some(gid) = mm.find_open(&criteria, pid, count, &[])
            && let Ok((s, notes)) = mm.join(gid, pid, count, "", &message)
        {
            return (s, notes);
        }
        mm.create(pid, session, count, key, &message)
    });
    tracing::info!(pid, gid = result.id, players = result.participation_count, "auto matchmake");
    Ok(session_bytes(&result))
}

fn browse(ctx: &mut Ctx, r: &mut Reader) -> Reply {
    let criteria = SearchCriteria::read(r)?;
    let found = ctx.state.matchmaking.lock().expect("matchmaking lock").browse(&criteria);
    Ok(session_list(&found))
}

fn find_by_gid(ctx: &mut Ctx, r: &mut Reader) -> Reply {
    let gid = r.u32()?;
    let mm = ctx.state.matchmaking.lock().expect("matchmaking lock");
    let g = mm.get(gid).ok_or(Fail(errors::RENDEZVOUS_SESSION_VOID))?;
    Ok(session_bytes(&g.session))
}

fn find_by_gids(ctx: &mut Ctx, r: &mut Reader) -> Reply {
    let gids = r.list(|r| r.u32())?;
    let mm = ctx.state.matchmaking.lock().expect("matchmaking lock");
    let found: Vec<_> = gids.iter().filter_map(|g| mm.get(*g).map(|g| g.session.clone())).collect();
    Ok(session_list(&found))
}

/// Arena ID alphabet: digits and capitals without the look-alikes 0/O, 1/I, 2/Z, 5/S, 8/B.
const CODE_CHARS: &[u8] = b"34679ACDEFGHJKLMNPQRTUVWXY";

fn fresh_code() -> String {
    accounts::random_bytes::<5>().iter().map(|b| CODE_CHARS[*b as usize % CODE_CHARS.len()] as char).collect()
}

/// 109/55: `u32` gathering ID → `Struct{String code, DateTime}`; the creator shows the code as the Arena ID.
fn arena_code(ctx: &mut Ctx, r: &mut Reader) -> Reply {
    let gid = r.u32()?;
    let mut mm = ctx.state.matchmaking.lock().expect("matchmaking lock");
    let code = mm.code(gid, fresh_code).ok_or(Fail(errors::RENDEZVOUS_SESSION_VOID))?;
    // shortcut: the DateTime's meaning is unknown (issue time or expiry); the creation time is sent.
    let started = mm.get(gid).map_or(DateTime::now(), |g| g.session.started);
    let mut w = Writer::new();
    w.structure(0, |w| {
        w.string(&code).u64(started.0);
    });
    Ok(w.into_bytes())
}

/// 109/56: `Struct{String code, DateTime}` (only the typed code is set) → `u32` gathering ID.
fn find_by_code(ctx: &mut Ctx, r: &mut Reader) -> Reply {
    let (_, mut p) = r.structure()?;
    let code = p.string()?;
    let gid = ctx.state.matchmaking.lock().expect("matchmaking lock").by_code(&code);
    let mut w = Writer::new();
    w.u32(gid.ok_or(Fail(errors::RENDEZVOUS_SESSION_VOID))?);
    Ok(w.into_bytes())
}

fn find_by_owner(ctx: &mut Ctx, r: &mut Reader) -> Reply {
    let owner = r.pid()?;
    let found = ctx.state.matchmaking.lock().expect("matchmaking lock").by_owner(owner);
    Ok(session_list(&found))
}

fn find_by_participant(ctx: &mut Ctx, r: &mut Reader) -> Reply {
    let (_, mut p) = r.structure()?;
    let pids = p.list(|r| r.pid())?;
    let mm = ctx.state.matchmaking.lock().expect("matchmaking lock");
    let mut w = Writer::new();
    let results: Vec<(u64, MatchmakeSession)> =
        pids.iter().flat_map(|pid| mm.by_participant(*pid).into_iter().map(|s| (*pid, s))).collect();
    w.list(&results, |w, (pid, s)| {
        w.structure(0, |w| {
            w.pid(*pid);
            s.write(w);
        });
    });
    Ok(w.into_bytes())
}

fn set_open(ctx: &mut Ctx, pid: u64, r: &mut Reader, open: bool) -> Reply {
    let gid = r.u32()?;
    owned(ctx, pid, gid, |g| g.session.open_participation = open)
}

fn modify_game_attribute(ctx: &mut Ctx, pid: u64, r: &mut Reader) -> Reply {
    let gid = r.u32()?;
    let index = r.u32()? as usize;
    let value = r.u32()?;
    if index >= 32 {
        return Err(Fail(errors::CORE_INVALID_ARGUMENT));
    }
    owned(ctx, pid, gid, |g| {
        if g.session.attribs.len() <= index {
            g.session.attribs.resize(index + 1, 0);
        }
        g.session.attribs[index] = value;
    })
}

fn update_application_buffer(ctx: &mut Ctx, pid: u64, r: &mut Reader) -> Reply {
    let gid = r.u32()?;
    let buffer = r.buffer()?.to_vec();
    owned(ctx, pid, gid, |g| g.session.application_buffer = buffer)
}

fn update_attributes(ctx: &mut Ctx, pid: u64, r: &mut Reader) -> Reply {
    let gid = r.u32()?;
    let attribs = r.list(|r| r.u32())?;
    owned(ctx, pid, gid, |g| g.session.attribs = attribs)
}

fn update_progress_score(ctx: &mut Ctx, pid: u64, r: &mut Reader) -> Reply {
    let gid = r.u32()?;
    let score = r.u8()?;
    owned(ctx, pid, gid, |g| g.session.progress_score = score)
}

/// Generate (or clear) the password friends use to join an arena without the code word.
fn system_password(ctx: &mut Ctx, pid: u64, r: &mut Reader, generate: bool) -> Reply {
    let gid = r.u32()?;
    let password = if generate {
        format!("{:08}", u32::from_le_bytes(accounts::random_bytes()) % 100_000_000)
    } else {
        String::new()
    };
    let stored = password.clone();
    owned(ctx, pid, gid, |g| {
        g.session.system_password_enabled = generate;
        g.system_password = stored;
    })?;
    if !generate {
        return Ok(Vec::new());
    }
    let mut w = Writer::new();
    w.string(&password);
    Ok(w.into_bytes())
}

/// `UpdateMatchmakeSessionPart`: overwrite the fields selected by `modification_flags`.
// shortcut: flag bits are assumed to follow field order (bit 0 = attributes ... bit 14 = code word);
// confirm against a capture or the server-side checks before relying on rarely used fields.
fn update_part(ctx: &mut Ctx, pid: u64, r: &mut Reader) -> Reply {
    let (_, mut p) = r.structure()?;
    let gid = p.u32()?;
    let flags = p.u32()?;
    let attribs = p.list(|r| r.u32())?;
    let open = p.bool()?;
    let app = p.buffer()?.to_vec();
    let progress = p.u8()?;
    let (_, mut param) = p.structure()?;
    let param = param.list(|r| Ok((r.string()?, r.variant()?)))?;
    let started = DateTime(p.u64()?);
    let user_password = p.string()?;
    let game_mode = p.u32()?;
    let description = p.string()?;
    let min = p.u16()?;
    let max = p.u16()?;
    let system = p.u32()?;
    let policy = p.u32()?;
    let policy_arg = p.u32()?;
    let codeword = p.string()?;
    owned(ctx, pid, gid, |g| {
        let s = &mut g.session;
        let on = |bit: u32| flags & (1 << bit) != 0;
        if on(0) {
            s.attribs = attribs;
        }
        if on(1) {
            s.open_participation = open;
        }
        if on(2) {
            s.application_buffer = app;
        }
        if on(3) {
            s.progress_score = progress;
        }
        if on(4) {
            s.param = param;
        }
        if on(5) {
            s.started = started;
        }
        if on(6) {
            s.user_password_enabled = !user_password.is_empty();
            s.user_password = user_password;
        }
        if on(7) {
            s.game_mode = game_mode;
        }
        if on(8) {
            s.description = description;
        }
        if on(9) {
            s.min_participants = min;
        }
        if on(10) {
            s.max_participants = max;
        }
        if on(11) {
            s.matchmake_system = system;
        }
        if on(12) {
            s.participation_policy = policy;
        }
        if on(13) {
            s.policy_argument = policy_arg;
        }
        if on(14) {
            s.codeword = codeword;
        }
    })
}

fn unregister(ctx: &mut Ctx, pid: u64, r: &mut Reader) -> Reply {
    let gid = r.u32()?;
    let ok = with_mm(ctx, |mm| match mm.unregister(gid, pid) {
        Some(notes) => (true, notes),
        None => (false, Vec::new()),
    });
    let mut w = Writer::new();
    w.bool(ok);
    Ok(w.into_bytes())
}

fn end_participation(ctx: &mut Ctx, pid: u64, r: &mut Reader) -> Reply {
    let gid = r.u32()?;
    let message = r.string()?;
    let notes_sent = with_mm(ctx, |mm| {
        let notes = mm.leave(gid, pid, PARTICIPANT_LEFT, &message);
        (true, notes)
    });
    let mut w = Writer::new();
    w.bool(notes_sent);
    Ok(w.into_bytes())
}

/// Station URLs of the session host, so a joining Pia peer can reach it.
/// The host's station is final once its NAT check replaced a station URL (`ReplaceURL` adds the Pia `CID`).
fn host_station_ready(state: &crate::state::State, gid: u32) -> bool {
    let Some(host) = state.matchmaking.lock().expect("matchmaking lock").get(gid).map(|g| g.session.host) else {
        return true;
    };
    let sessions = state.sessions.read().expect("sessions lock");
    sessions.get(&host).is_none_or(|s| {
        s.urls.iter().any(|u| super::secure::StationUrl::parse(u).is_some_and(|u| u.get("CID").is_some()))
    })
}

/// GetSessionURLs is answered once the host's station is final: a joiner asks right after matchmaking, often while
/// the host is still in its NAT check, and Pia gives up on URLs without the host's `CID` (seen from 13.0.5: the
/// joiner then fails `WaitGetStationConnection` without sending a datagram). Waits at most 10 s, then answers with
/// what there is. shortcut: polls every 50 ms and holds this connection's other messages meanwhile; use a per-host
/// notifier and a detached reply if that ever matters.
pub async fn wait_for_host_station(state: &crate::state::State, body: &[u8]) {
    let Ok(gid) = Reader::new(body).u32() else { return };
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    while !host_station_ready(state, gid) && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

fn session_urls(ctx: &mut Ctx, r: &mut Reader) -> Reply {
    let gid = r.u32()?;
    let host = ctx
        .state
        .matchmaking
        .lock()
        .expect("matchmaking lock")
        .get(gid)
        .map(|g| g.session.host)
        .ok_or(Fail(errors::RENDEZVOUS_SESSION_VOID))?;
    let urls = ctx.state.sessions.read().expect("sessions lock").get(&host).map(|s| super::secure::peer_urls(&s.urls));
    let urls = urls.unwrap_or_default();
    tracing::debug!(gid, host, ?urls, "GetSessionURLs");
    let mut w = Writer::new();
    w.list(&urls, |w, u| {
        w.string(u);
    });
    Ok(w.into_bytes())
}

/// Host migration: the caller becomes host (and owner when `migrate_owner`).
fn update_host(ctx: &mut Ctx, pid: u64, r: &mut Reader) -> Reply {
    let gid = r.u32()?;
    let migrate_owner = r.bool()?;
    with_mm(ctx, |mm| {
        let Some(g) = mm.get_mut(gid).filter(|g| g.has(pid)) else {
            return (Err(Fail(errors::RENDEZVOUS_NOT_PARTICIPATED)), Vec::new());
        };
        let old = g.session.host;
        g.session.host = pid;
        if migrate_owner {
            g.session.owner = pid;
        }
        let notes = g
            .participants
            .iter()
            .map(|(p, _)| {
                (
                    *p,
                    Notification {
                        source: old,
                        kind: HOST_CHANGED,
                        param1: gid as u64,
                        param2: pid,
                        text: String::new(),
                        param3: 0,
                    },
                )
            })
            .collect();
        (Ok(Vec::new()), notes)
    })
}
