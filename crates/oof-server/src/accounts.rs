//! OOF accounts without a database: a principal ID (PID) is random, its password is
//! HMAC(secret, pid), and ID tokens are HMAC-signed `(pid, expiry)` pairs. Any node holding the
//! shared secret can verify them, which keeps the login path stateless and horizontally scalable.
//!
//! A port obtains a token over HTTP (`POST /v1/token`) and returns it to the game from its
//! `nn::account` network-service-account ID token functions (see docs/STANDARD.md).

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

const TOKEN_PREFIX: &str = "oof1.";

fn mac(secret: &[u8], label: &[u8], data: &[u8]) -> [u8; 32] {
    let mut m = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC takes any key size");
    m.update(label);
    m.update(data);
    m.finalize().into_bytes().into()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn equal(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    getrandom::fill(&mut out).expect("OS random number generator");
    out
}

/// New principal ID. Switch PIDs are 64-bit; values stay above 2^32 (clear of the reserved low PIDs:
/// 1 = auth server, 2 = secure server) and below 2^53 so JSON clients read them exactly.
// shortcut: random PIDs collide with probability ~n²/2^54 (~5e-5 at a million accounts); a
// database-backed allocator replaces this once accounts carry profile data.
pub fn new_pid() -> u64 {
    (u64::from_le_bytes(random_bytes()) & ((1 << 53) - 1)) | 0x1_0000_0000
}

pub fn password(secret: &[u8], pid: u64) -> String {
    hex(&mac(secret, b"password", &pid.to_le_bytes()))
}

pub fn check_password(secret: &[u8], pid: u64, candidate: &str) -> bool {
    equal(password(secret, pid).as_bytes(), candidate.as_bytes())
}

pub fn issue_token(secret: &[u8], pid: u64, expires_unix: u64) -> String {
    let mut payload = pid.to_le_bytes().to_vec();
    payload.extend_from_slice(&expires_unix.to_le_bytes());
    let body = B64.encode(&payload);
    let sig = B64.encode(mac(secret, b"token", body.as_bytes()));
    format!("{TOKEN_PREFIX}{body}.{sig}")
}

/// Returns the PID of a valid, unexpired token.
pub fn verify_token(secret: &[u8], token: &str, now_unix: u64) -> Option<u64> {
    let rest = token.strip_prefix(TOKEN_PREFIX)?;
    let (body, sig) = rest.split_once('.')?;
    if !equal(&B64.decode(sig).ok()?, &mac(secret, b"token", body.as_bytes())) {
        return None;
    }
    let payload = B64.decode(body).ok()?;
    let pid = u64::from_le_bytes(payload.get(..8)?.try_into().ok()?);
    let expires = u64::from_le_bytes(payload.get(8..16)?.try_into().ok()?);
    (now_unix < expires).then_some(pid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_and_passwords() {
        let secret = [3u8; 32];
        let pid = new_pid();
        assert!(pid > u32::MAX as u64 && pid < 1 << 53);
        assert!(check_password(&secret, pid, &password(&secret, pid)));
        assert!(!check_password(&secret, pid + 1, &password(&secret, pid)));

        let token = issue_token(&secret, pid, 100);
        assert_eq!(verify_token(&secret, &token, 99), Some(pid));
        assert_eq!(verify_token(&secret, &token, 100), None, "expired");
        assert_eq!(verify_token(&[4u8; 32], &token, 99), None, "other secret");
        let forged = token.replacen('A', "B", 1);
        assert!(forged == token || verify_token(&secret, &forged, 99).is_none());
    }
}
