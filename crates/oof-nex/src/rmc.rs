//! RMC (remote method call) messages carried inside PRUDP DATA payloads.
//!
//! Request:  `u32 size | u8 protocol|0x80 [u16 protocol] | u32 call_id | u32 method | body`
//! Response: `u32 size | u8 protocol [u16] | u8 success | (u32 call_id | u32 method|0x8000 | body) or (u32 error | u32 call_id)`
//! Protocol IDs above 0x7E are written as `0x7F` followed by a `u16` (SSBU `main+0x22b480`).

use crate::stream::{Error, Reader, Result, Writer};

/// Success result code.
pub const RESULT_SUCCESS: u32 = 0x0001_0001;

/// Common NEX error codes (`ErrorCode` values carried in failed responses).
pub mod errors {
    pub const CORE_UNKNOWN: u32 = 0x8001_0001;
    pub const CORE_NOT_IMPLEMENTED: u32 = 0x8001_0002;
    pub const CORE_INVALID_ARGUMENT: u32 = 0x8001_000A;
    pub const CORE_ACCESS_DENIED: u32 = 0x8001_0006;
    pub const DATASTORE_NOT_FOUND: u32 = 0x8069_0004;
    pub const RENDEZVOUS_INVALID_USERNAME: u32 = 0x8003_0064;
    pub const RENDEZVOUS_INVALID_PASSWORD: u32 = 0x8003_006B;
    pub const RENDEZVOUS_SESSION_VOID: u32 = 0x8003_0065;
    pub const RENDEZVOUS_SESSION_FULL: u32 = 0x8003_006C;
    pub const RENDEZVOUS_SESSION_CLOSED: u32 = 0x8003_006E;
    pub const RENDEZVOUS_NOT_PARTICIPATED: u32 = 0x8003_006F;
    pub const RENDEZVOUS_PERMISSION_DENIED: u32 = 0x8003_0069;
    /// `RendezVous::AccountDisabled` in the public NEX error table (kinnay/NintendoClients); the code the game shows
    /// for it is not verified yet.
    pub const RENDEZVOUS_ACCOUNT_DISABLED: u32 = 0x8003_0067;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub protocol: u16,
    pub call_id: u32,
    pub method: u32,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    Ok { protocol: u16, call_id: u32, method: u32, body: Vec<u8> },
    Err { protocol: u16, call_id: u32, error: u32 },
}

/// A decoded message: requests come from clients; responses come back for server-initiated calls
/// (notifications, NAT probes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Request(Request),
    Response(Response),
}

fn write_protocol(w: &mut Writer, protocol: u16, request: bool) {
    let flag = if request { 0x80 } else { 0 };
    if protocol < 0x7F {
        w.u8(protocol as u8 | flag);
    } else {
        w.u8(0x7F | flag).u16(protocol);
    }
}

fn framed(content: impl FnOnce(&mut Writer)) -> Vec<u8> {
    let mut w = Writer::new();
    content(&mut w);
    let body = w.into_bytes();
    let mut out = Vec::with_capacity(body.len() + 4);
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(&body);
    out
}

pub fn encode_request(protocol: u16, call_id: u32, method: u32, body: &[u8]) -> Vec<u8> {
    framed(|w| {
        write_protocol(w, protocol, true);
        w.u32(call_id).u32(method).bytes(body);
    })
}

pub fn encode_ok(protocol: u16, call_id: u32, method: u32, body: &[u8]) -> Vec<u8> {
    framed(|w| {
        write_protocol(w, protocol, false);
        w.u8(1).u32(call_id).u32(method | 0x8000).bytes(body);
    })
}

pub fn encode_err(protocol: u16, call_id: u32, error: u32) -> Vec<u8> {
    framed(|w| {
        write_protocol(w, protocol, false);
        w.u8(0).u32(error).u32(call_id);
    })
}

pub fn decode(data: &[u8]) -> Result<Message> {
    let mut r = Reader::new(data);
    let size = r.u32()? as usize;
    if size != r.remaining() {
        return Err(Error::Invalid("RMC size"));
    }
    let first = r.u8()?;
    let request = first & 0x80 != 0;
    let protocol = match first & 0x7F {
        0x7F => r.u16()?,
        p => p as u16,
    };
    if request {
        let call_id = r.u32()?;
        let method = r.u32()?;
        return Ok(Message::Request(Request { protocol, call_id, method, body: r.take(r.remaining())?.to_vec() }));
    }
    Ok(Message::Response(if r.bool()? {
        let call_id = r.u32()?;
        let method = r.u32()? & !0x8000;
        Response::Ok { protocol, call_id, method, body: r.take(r.remaining())?.to_vec() }
    } else {
        let error = r.u32()?;
        Response::Err { protocol, call_id: r.u32()?, error }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_short_and_extended_protocol_ids() {
        for protocol in [10u16, 109, 201] {
            let req = encode_request(protocol, 7, 40, b"xy");
            assert_eq!(
                decode(&req).unwrap(),
                Message::Request(Request { protocol, call_id: 7, method: 40, body: b"xy".to_vec() })
            );
            assert_eq!(
                decode(&encode_ok(protocol, 7, 40, b"z")).unwrap(),
                Message::Response(Response::Ok { protocol, call_id: 7, method: 40, body: b"z".to_vec() })
            );
            assert_eq!(
                decode(&encode_err(protocol, 7, errors::CORE_NOT_IMPLEMENTED)).unwrap(),
                Message::Response(Response::Err { protocol, call_id: 7, error: errors::CORE_NOT_IMPLEMENTED })
            );
        }
        // Wire form of an extended ID request header.
        assert_eq!(&encode_request(201, 1, 2, &[])[4..7], &[0xFF, 201, 0]);
    }

    #[test]
    fn rejects_bad_size() {
        assert!(decode(&[9, 0, 0, 0, 0x8A]).is_err());
    }
}
