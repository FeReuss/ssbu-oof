//! Ticket Granting (10), the only protocol of the authentication connection.
//!
//! Switch clients log in with method 6, `ValidateAndRequestTicketWithParam`, carrying the
//! network-service-account ID token in `AuthenticationInfo`. Here that token is an OOF ID token
//! (crate::accounts), which the player's port obtained from this server.

use super::{Ctx, Fail, NOT_IMPLEMENTED, Reply};
use crate::accounts;
use oof_nex::kerberos::{self, SESSION_KEY_SIZE, ServerTicket};
use oof_nex::rmc::{RESULT_SUCCESS, errors};
use oof_nex::stream::{DateTime, Reader, Writer};

/// PID of the secure server, the target of every ticket.
pub const SECURE_SERVER_PID: u64 = 2;
const BUILD_NAME: &str = concat!("ssbu-oof ", env!("CARGO_PKG_VERSION"));

pub fn handle(ctx: &mut Ctx, method: u32, r: &mut Reader) -> Reply {
    match method {
        6 => validate_and_request_ticket_with_param(ctx, r),
        3 => request_ticket(ctx, r),
        _ => Err(NOT_IMPLEMENTED),
    }
}

fn now_unix() -> u64 {
    DateTime::now().to_unix()
}

/// Seals a fresh session key twice: for the secure server (inside the server ticket) and for the
/// client (with a random `sourceKey` the client receives as hex).
fn ticket(ctx: &Ctx, pid: u64) -> (Vec<u8>, String) {
    let session_key: [u8; SESSION_KEY_SIZE] = accounts::random_bytes();
    let server = ServerTicket { issued: DateTime::now(), source_pid: pid, session_key }
        .encrypt(&ctx.state.kerberos_key, &accounts::random_bytes());
    let user_key: [u8; 16] = accounts::random_bytes();
    let sealed = kerberos::client_ticket(&user_key, &session_key, SECURE_SERVER_PID, &server);
    (sealed, user_key.iter().map(|b| format!("{b:02x}")).collect())
}

fn validate_and_request_ticket_with_param(ctx: &mut Ctx, r: &mut Reader) -> Reply {
    let (_, mut p) = r.structure()?;
    let _platform = p.u32()?;
    let username = p.string()?;
    let (class, mut info) = p.any_data()?;
    // Each class level has its own structure header: Data (empty), then AuthenticationInfo.
    let token = if class == "AuthenticationInfo" {
        info.structure()?;
        info.structure()?.1.string()?
    } else {
        String::new()
    };
    let pid = accounts::verify_token(&ctx.state.secret, &token, now_unix())
        .ok_or(Fail(errors::RENDEZVOUS_INVALID_PASSWORD))?;
    // The token proves the identity. The user name should be the decimal PID; where the game takes
    // it from on a port is not verified yet, so a mismatch is logged rather than refused.
    if username.parse::<u64>().ok() != Some(pid) {
        tracing::warn!(pid, username, "NEX user name differs from the token's PID");
    }
    let (sealed, source_key) = ticket(ctx, pid);
    ctx.auth_pid = Some(pid);
    tracing::info!(pid, "ticket granted");
    let mut w = Writer::new();
    w.structure(0, |w| {
        w.pid(pid)
            .buffer(&sealed)
            .string(&ctx.state.secure_url())
            .u64(DateTime::now().0)
            .string(BUILD_NAME)
            .string(&source_key);
    });
    Ok(w.into_bytes())
}

/// `RequestTicket(source pid, target pid)`: a new ticket for an already-authenticated client.
fn request_ticket(ctx: &mut Ctx, r: &mut Reader) -> Reply {
    let source = r.pid()?;
    let target = r.pid()?;
    // Only for the PID this connection already proved with method 6.
    let pid =
        ctx.auth_pid.filter(|p| *p == source && target == SECURE_SERVER_PID).ok_or(Fail(errors::CORE_ACCESS_DENIED))?;
    let (sealed, source_key) = ticket(ctx, pid);
    let mut w = Writer::new();
    w.result(RESULT_SUCCESS).buffer(&sealed).string(&source_key);
    Ok(w.into_bytes())
}
