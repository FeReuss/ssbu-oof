//! Kerberos-style tickets NEX uses to hand a session key from the authentication server to the
//! secure server. Encryption is RC4 with an HMAC-MD5 trailer.
//!
//! Switch flow (NEX 4): `ValidateAndRequestTicketWithParam` returns a ticket encrypted with
//! `sourceKey` (sent as hex), so no password-based key derivation is involved.

use crate::stream::Error;
use crate::stream::{DateTime, Reader, Result, Writer};
use hmac::{Hmac, KeyInit, Mac};
use md5::{Digest, Md5};

/// Session key length in Switch tickets.
pub const SESSION_KEY_SIZE: usize = 32;

pub fn md5(data: &[u8]) -> [u8; 16] {
    Md5::digest(data).into()
}

pub fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut mac = Hmac::<Md5>::new_from_slice(key).expect("HMAC takes any key size");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// RC4 stream cipher (encryption and decryption are the same operation).
pub fn rc4(key: &[u8], data: &mut [u8]) {
    let mut s: [u8; 256] = std::array::from_fn(|i| i as u8);
    let mut j = 0u8;
    for i in 0..256 {
        j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
        s.swap(i, j as usize);
    }
    let (mut i, mut j) = (0u8, 0u8);
    for byte in data {
        i = i.wrapping_add(1);
        j = j.wrapping_add(s[i as usize]);
        s.swap(i as usize, j as usize);
        *byte ^= s[s[i as usize].wrapping_add(s[j as usize]) as usize];
    }
}

/// RC4-encrypt and append HMAC-MD5(key, ciphertext).
pub fn seal(key: &[u8], plain: &[u8]) -> Vec<u8> {
    let mut out = plain.to_vec();
    rc4(key, &mut out);
    let mac = hmac_md5(key, &out);
    out.extend_from_slice(&mac);
    out
}

/// Verify the HMAC-MD5 trailer and RC4-decrypt.
pub fn open(key: &[u8], sealed: &[u8]) -> Result<Vec<u8>> {
    let split = sealed.len().checked_sub(16).ok_or(Error::Eof)?;
    let (data, mac) = sealed.split_at(split);
    // Constant-time compare: this check authenticates the ticket.
    let expected = hmac_md5(key, data);
    if expected.iter().zip(mac).fold(0u8, |acc, (a, b)| acc | (a ^ b)) != 0 {
        return Err(Error::Invalid("Kerberos checksum"));
    }
    let mut out = data.to_vec();
    rc4(key, &mut out);
    Ok(out)
}

/// The part only the secure server can read: who the ticket is for and the session key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerTicket {
    pub issued: DateTime,
    pub source_pid: u64,
    pub session_key: [u8; SESSION_KEY_SIZE],
}

impl ServerTicket {
    /// Ticket version 1: `Buffer ticket_key | Buffer seal(md5(server_key + ticket_key), ...)`.
    pub fn encrypt(&self, server_key: &[u8], ticket_key: &[u8; 16]) -> Vec<u8> {
        let mut plain = Writer::new();
        plain.u64(self.issued.0).pid(self.source_pid).bytes(&self.session_key);
        let key = md5(&[server_key, ticket_key].concat());
        let mut w = Writer::new();
        w.buffer(ticket_key).buffer(&seal(&key, &plain.into_bytes()));
        w.into_bytes()
    }

    pub fn decrypt(data: &[u8], server_key: &[u8]) -> Result<Self> {
        let mut r = Reader::new(data);
        let ticket_key = r.buffer()?;
        let key = md5(&[server_key, ticket_key].concat());
        let plain = open(&key, r.buffer()?)?;
        let mut r = Reader::new(&plain);
        Ok(Self {
            issued: DateTime(r.u64()?),
            source_pid: r.pid()?,
            session_key: r.take(SESSION_KEY_SIZE)?.try_into().expect("exact length"),
        })
    }
}

/// What the client receives: the session key, the target server PID and the opaque server ticket.
pub fn client_ticket(
    user_key: &[u8],
    session_key: &[u8; SESSION_KEY_SIZE],
    target_pid: u64,
    server_ticket: &[u8],
) -> Vec<u8> {
    let mut w = Writer::new();
    w.bytes(session_key).pid(target_pid).buffer(server_ticket);
    seal(user_key, &w.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rc4_known_vector() {
        // RFC 6229 key "Key", plaintext "Plaintext"
        let mut data = *b"Plaintext";
        rc4(b"Key", &mut data);
        assert_eq!(data, [0xBB, 0xF3, 0x16, 0xE8, 0xD9, 0x40, 0xAF, 0x0A, 0xD3]);
    }

    #[test]
    fn hmac_md5_known_vector() {
        // RFC 2202 test case 2
        let mac = hmac_md5(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            mac,
            [0x75, 0x0c, 0x78, 0x3e, 0x6a, 0xb0, 0xb5, 0x03, 0xea, 0xa8, 0x6e, 0x31, 0x0a, 0x5d, 0xb7, 0x38]
        );
    }

    #[test]
    fn server_ticket_round_trip_and_tamper() {
        let t = ServerTicket {
            issued: DateTime::from_unix(1_700_000_000),
            source_pid: 0x1234_5678_9abc,
            session_key: [7; 32],
        };
        let sealed = t.encrypt(b"server", &[1; 16]);
        assert_eq!(ServerTicket::decrypt(&sealed, b"server").unwrap(), t);
        assert!(ServerTicket::decrypt(&sealed, b"other").is_err());
        let mut bad = sealed.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(ServerTicket::decrypt(&bad, b"server").is_err());
    }
}
