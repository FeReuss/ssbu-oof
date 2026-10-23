//! RMC dispatch. Protocol IDs are the ones SSBU 13.0.5 constructs its clients with
//! (docs/re/protocols.md); method numbers per protocol live in each module. DataStore (115),
//! Matchmake Referee (120), Screening (124) and Tournament (201) are not served yet.

pub mod matchmake;
pub mod nat;
pub mod secure;
pub mod ticket_granting;
pub mod utility;

use crate::state::State;
use oof_nex::rmc::{self, Request, errors};
use oof_nex::stream::{Error, Reader};
use std::net::SocketAddr;
use std::sync::Arc;

pub const NAT_TRAVERSAL: u16 = 3;
pub const TICKET_GRANTING: u16 = 10;
pub const SECURE_CONNECTION: u16 = 11;
pub const NOTIFICATION: u16 = 14;
pub const MATCH_MAKING: u16 = 21;
pub const MATCH_MAKING_EXT: u16 = 50;
pub const MATCHMAKE_EXTENSION: u16 = 109;
pub const UTILITY: u16 = 110;

/// A NEX error code for a failed call. Stream read errors become `Core::InvalidArgument`, so
/// handlers can use `?` on every read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fail(pub u32);

impl From<Error> for Fail {
    fn from(_: Error) -> Self {
        Fail(errors::CORE_INVALID_ARGUMENT)
    }
}

pub const NOT_IMPLEMENTED: Fail = Fail(errors::CORE_NOT_IMPLEMENTED);

/// Handler result: response body or error code.
pub type Reply = Result<Vec<u8>, Fail>;

/// Who is on the other end of one PRUDP connection.
pub struct Ctx<'a> {
    pub state: &'a Arc<State>,
    pub peer: SocketAddr,
    /// Set once the secure-server CONNECT carried a valid ticket.
    pub pid: Option<u64>,
    pub cid: u32,
    /// PID proven on the authentication connection (by its ID token).
    pub auth_pid: Option<u64>,
}

pub fn dispatch(ctx: &mut Ctx, req: &Request) -> Vec<u8> {
    let mut body = Reader::new(&req.body);
    let r = &mut body;
    let reply = match (ctx.pid.is_some(), req.protocol) {
        (false, TICKET_GRANTING) => ticket_granting::handle(ctx, req.method, r),
        (true, SECURE_CONNECTION) => secure::handle(ctx, req.method, r),
        (true, UTILITY) => utility::handle(ctx, req.method, r),
        (true, NAT_TRAVERSAL) => nat::handle(ctx, req.method, r),
        (true, MATCH_MAKING | MATCH_MAKING_EXT | MATCHMAKE_EXTENSION) => {
            matchmake::handle(ctx, req.protocol, req.method, r)
        }
        _ => Err(NOT_IMPLEMENTED),
    };
    match reply {
        Ok(out) => rmc::encode_ok(req.protocol, req.call_id, req.method, &out),
        Err(Fail(code)) => {
            if code == errors::CORE_NOT_IMPLEMENTED {
                // The log of these is the to-do list: which calls the game made that we lack.
                tracing::warn!(
                    protocol = req.protocol,
                    method = req.method,
                    len = req.body.len(),
                    "unimplemented RMC method"
                );
            } else {
                tracing::debug!(protocol = req.protocol, method = req.method, code = format!("{code:#x}"), "RMC error");
            }
            rmc::encode_err(req.protocol, req.call_id, code)
        }
    }
}
