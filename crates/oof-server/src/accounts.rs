//! OOF accounts: a player registers a user name and a password (no e-mail, no phone number) and gets a principal ID
//! (PID). Logging in on a device returns a **device key**, which the port keeps instead of the password and trades for
//! short-lived ID tokens (`POST /v1/token`); the game hands the token to the NEX login. So every connection maps to one
//! account, which can be banned (bans are checked when a token is issued, at the NEX login and on connected players)
//! and protected (a password change revokes every device key). The account is not tied to a save: any save can log in.
//!
//! Passwords are stored as Argon2id hashes, device keys as SHA-256 hashes, both in the server's SQLite database
//! (`database` in the config). ID tokens are HMAC-signed `(pid, expiry)` pairs that any node holding the shared secret
//! verifies without the database.
//!
//! A port obtains a token over HTTP and returns it to the game from its `nn::account` network-service-account ID token
//! functions (see docs/STANDARD.md).

use argon2::Argon2;
use argon2::password_hash::{PasswordHasher, PasswordVerifier};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use hmac::{Hmac, KeyInit, Mac};
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};

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
/// 1 = auth server, 2 = secure server) and below 2^53 so JSON clients read them exactly. The database refuses a
/// duplicate, and registration draws again.
fn new_pid() -> u64 {
    (u64::from_le_bytes(random_bytes()) & ((1 << 53) - 1)) | 0x1_0000_0000
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

/// 3–10 characters: letters, digits, `_`, `-`, `.`; unique without regard to case. It is also the player's nickname
/// in the game (the port returns it from `nn::account`), and a Switch nickname has at most 10 characters.
pub fn valid_username(name: &str) -> bool {
    (3..=10).contains(&name.len()) && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b))
}

/// 8–128 characters (any).
pub fn valid_password(password: &str) -> bool {
    (8..=128).contains(&password.chars().count())
}

/// Argon2id with the crate's default (OWASP) parameters and a random salt; slow on purpose, so callers run it on a
/// blocking thread.
pub fn hash_password(password: &str) -> String {
    Argon2::default().hash_password(password.as_bytes()).expect("argon2 with default parameters").to_string()
}

pub fn password_matches(password: &str, hash: &str) -> bool {
    Argon2::default().verify_password(password.as_bytes(), hash).is_ok()
}

fn key_hash(key: &str) -> Vec<u8> {
    Sha256::digest(key.as_bytes()).to_vec()
}

#[derive(Debug, Clone, PartialEq)]
pub struct Ban {
    /// Unix time the ban ends; None: permanent.
    pub until: Option<u64>,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Account {
    pub pid: u64,
    pub username: String,
    pub password_hash: String,
    pub created: u64,
    pub ban: Option<Ban>,
    pub last_login: Option<u64>,
    pub last_address: Option<String>,
    pub devices: usize,
}

pub struct AccountStore {
    db: Connection,
}

impl AccountStore {
    /// `path` = None: an in-memory database (tests, throwaway servers).
    pub fn open(path: Option<&str>) -> rusqlite::Result<Self> {
        let db = match path {
            Some(p) => Connection::open(p)?,
            None => Connection::open_in_memory()?,
        };
        db.busy_timeout(std::time::Duration::from_secs(5))?;
        db.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA foreign_keys = ON;
             CREATE TABLE IF NOT EXISTS accounts (pid INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                 password_hash TEXT NOT NULL, created INTEGER NOT NULL, banned_until INTEGER, ban_reason TEXT,
                 last_login INTEGER, last_address TEXT);
             CREATE TABLE IF NOT EXISTS devices (key_hash BLOB PRIMARY KEY,
                 pid INTEGER NOT NULL REFERENCES accounts (pid) ON DELETE CASCADE, name TEXT NOT NULL,
                 created INTEGER NOT NULL, last_used INTEGER NOT NULL);
             CREATE INDEX IF NOT EXISTS devices_pid ON devices (pid);
             CREATE TABLE IF NOT EXISTS friends (pid INTEGER NOT NULL REFERENCES accounts (pid) ON DELETE CASCADE,
                 friend INTEGER NOT NULL REFERENCES accounts (pid) ON DELETE CASCADE, since INTEGER NOT NULL,
                 PRIMARY KEY (pid, friend));
             CREATE TABLE IF NOT EXISTS friend_requests (sender INTEGER NOT NULL REFERENCES accounts (pid) ON DELETE CASCADE,
                 receiver INTEGER NOT NULL REFERENCES accounts (pid) ON DELETE CASCADE, created INTEGER NOT NULL,
                 PRIMARY KEY (sender, receiver));
             CREATE TABLE IF NOT EXISTS blocks (pid INTEGER NOT NULL REFERENCES accounts (pid) ON DELETE CASCADE,
                 blocked INTEGER NOT NULL REFERENCES accounts (pid) ON DELETE CASCADE, PRIMARY KEY (pid, blocked));",
        )?;
        Ok(AccountStore { db })
    }

    /// A new account; None when the user name is taken. `password_hash` comes from `hash_password`.
    pub fn create(&self, username: &str, password_hash: &str, now: u64) -> rusqlite::Result<Option<u64>> {
        loop {
            let pid = new_pid();
            match self.db.execute(
                "INSERT INTO accounts (pid, username, password_hash, created) VALUES (?1, ?2, ?3, ?4)",
                params![pid as i64, username, password_hash, now as i64],
            ) {
                Ok(_) => return Ok(Some(pid)),
                Err(rusqlite::Error::SqliteFailure(e, Some(m)))
                    if e.code == rusqlite::ErrorCode::ConstraintViolation =>
                {
                    if m.contains("username") {
                        return Ok(None);
                    } // else the PID collided: draw again
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// By user name (any case) or decimal PID.
    pub fn find(&self, who: &str) -> rusqlite::Result<Option<Account>> {
        let pid = who.parse::<i64>().unwrap_or(-1);
        self.db
            .query_row(
                "SELECT pid, username, password_hash, created, banned_until, ban_reason, last_login, last_address,
                     (SELECT COUNT(*) FROM devices d WHERE d.pid = a.pid) FROM accounts a WHERE username = ?1 OR pid = ?2",
                params![who, pid],
                |r| {
                    let banned_until: Option<i64> = r.get(4)?;
                    let reason: Option<String> = r.get(5)?;
                    Ok(Account {
                        pid: r.get::<_, i64>(0)? as u64,
                        username: r.get(1)?,
                        password_hash: r.get(2)?,
                        created: r.get::<_, i64>(3)? as u64,
                        // banned_until: NULL = not banned, 0 = permanent, else the end
                        ban: banned_until.map(|t| Ban { until: (t > 0).then_some(t as u64), reason: reason.unwrap_or_default() }),
                        last_login: r.get::<_, Option<i64>>(6)?.map(|t| t as u64),
                        last_address: r.get(7)?,
                        devices: r.get::<_, i64>(8)? as usize,
                    })
                },
            )
            .optional()
    }

    /// The ban in force on `pid` at `now` (an expired ban is none).
    pub fn ban_of(&self, pid: u64, now: u64) -> rusqlite::Result<Option<Ban>> {
        Ok(self.find(&pid.to_string())?.and_then(|a| a.ban).filter(|b| b.until.is_none_or(|t| t > now)))
    }

    /// `until`: Unix time, None = permanent.
    pub fn set_ban(&self, pid: u64, until: Option<u64>, reason: &str) -> rusqlite::Result<bool> {
        let until = until.map_or(0, |t| t.max(1) as i64);
        Ok(self.db.execute(
            "UPDATE accounts SET banned_until = ?2, ban_reason = ?3 WHERE pid = ?1",
            params![pid as i64, until, reason],
        )? == 1)
    }

    pub fn unban(&self, pid: u64) -> rusqlite::Result<bool> {
        Ok(self
            .db
            .execute("UPDATE accounts SET banned_until = NULL, ban_reason = NULL WHERE pid = ?1", [pid as i64])?
            == 1)
    }

    /// Players among `pids` banned at `now`.
    pub fn banned_among(&self, pids: &[u64], now: u64) -> rusqlite::Result<Vec<u64>> {
        let mut out = Vec::new();
        for &pid in pids {
            if self.ban_of(pid, now)?.is_some() {
                out.push(pid);
            }
        }
        Ok(out)
    }

    /// A new device key for `pid` (returned once; only its hash is stored).
    pub fn add_device(&self, pid: u64, name: &str, now: u64) -> rusqlite::Result<String> {
        let key = hex(&random_bytes::<32>());
        self.db.execute(
            "INSERT INTO devices (key_hash, pid, name, created, last_used) VALUES (?1, ?2, ?3, ?4, ?4)",
            params![key_hash(&key), pid as i64, name, now as i64],
        )?;
        Ok(key)
    }

    /// Whether `key` is a device key of `pid`; records its use.
    pub fn device_ok(&self, pid: u64, key: &str, now: u64) -> rusqlite::Result<bool> {
        Ok(self.db.execute(
            "UPDATE devices SET last_used = ?3 WHERE key_hash = ?1 AND pid = ?2",
            params![key_hash(key), pid as i64, now as i64],
        )? == 1)
    }

    /// Revokes one device key (log out on that device).
    pub fn remove_device(&self, pid: u64, key: &str) -> rusqlite::Result<bool> {
        Ok(self
            .db
            .execute("DELETE FROM devices WHERE key_hash = ?1 AND pid = ?2", params![key_hash(key), pid as i64])?
            == 1)
    }

    /// New password; every device key is revoked (protection after a leak).
    pub fn set_password(&self, pid: u64, password_hash: &str) -> rusqlite::Result<()> {
        self.db.execute("UPDATE accounts SET password_hash = ?2 WHERE pid = ?1", params![pid as i64, password_hash])?;
        self.db.execute("DELETE FROM devices WHERE pid = ?1", [pid as i64])?;
        Ok(())
    }

    pub fn record_login(&self, pid: u64, address: &str, now: u64) -> rusqlite::Result<()> {
        self.db.execute(
            "UPDATE accounts SET last_login = ?2, last_address = ?3 WHERE pid = ?1",
            params![pid as i64, now as i64, address],
        )?;
        Ok(())
    }
}

/// The Switch's friend list limit.
pub const MAX_FRIENDS: usize = 300;

/// Outcome of `add_friend`.
#[derive(Debug, PartialEq, Eq)]
pub enum FriendAdd {
    Requested,
    /// The other player had asked first: now friends.
    Friends,
    AlreadyFriends,
    UnknownUser,
    Yourself,
    /// One of the two blocked the other.
    Blocked,
    TooManyFriends,
}

/// A player's friends (pid, user name), requests both ways and blocked players.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct FriendList {
    pub friends: Vec<(u64, String)>,
    pub incoming: Vec<(u64, String)>,
    pub outgoing: Vec<(u64, String)>,
    pub blocked: Vec<(u64, String)>,
}

impl AccountStore {
    fn pairs(&self, sql: &str, pid: u64) -> rusqlite::Result<Vec<(u64, String)>> {
        let mut q = self.db.prepare(sql)?;
        let rows = q.query_map([pid as i64], |r| Ok((r.get::<_, i64>(0)? as u64, r.get(1)?)))?;
        rows.collect()
    }

    pub fn friend_list(&self, pid: u64) -> rusqlite::Result<FriendList> {
        Ok(FriendList {
            friends: self.pairs(
                "SELECT a.pid, a.username FROM friends f JOIN accounts a ON a.pid = f.friend WHERE f.pid = ?1 ORDER BY f.since",
                pid,
            )?,
            incoming: self.pairs(
                "SELECT a.pid, a.username FROM friend_requests r JOIN accounts a ON a.pid = r.sender WHERE r.receiver = ?1",
                pid,
            )?,
            outgoing: self.pairs(
                "SELECT a.pid, a.username FROM friend_requests r JOIN accounts a ON a.pid = r.receiver WHERE r.sender = ?1",
                pid,
            )?,
            blocked: self
                .pairs("SELECT a.pid, a.username FROM blocks b JOIN accounts a ON a.pid = b.blocked WHERE b.pid = ?1", pid)?,
        })
    }

    fn count(&self, sql: &str, a: u64, b: u64) -> rusqlite::Result<i64> {
        self.db.query_row(sql, params![a as i64, b as i64], |r| r.get(0))
    }

    /// Sends a friend request to `who` (user name or PID), or accepts theirs.
    pub fn add_friend(&self, pid: u64, who: &str, now: u64) -> rusqlite::Result<FriendAdd> {
        let Some(other) = self.find(who)?.map(|a| a.pid) else { return Ok(FriendAdd::UnknownUser) };
        if other == pid {
            return Ok(FriendAdd::Yourself);
        }
        let blocked = "SELECT COUNT(*) FROM blocks WHERE (pid = ?1 AND blocked = ?2) OR (pid = ?2 AND blocked = ?1)";
        if self.count(blocked, pid, other)? > 0 {
            return Ok(FriendAdd::Blocked);
        }
        if self.count("SELECT COUNT(*) FROM friends WHERE pid = ?1 AND friend = ?2", pid, other)? > 0 {
            return Ok(FriendAdd::AlreadyFriends);
        }
        let full = |p: u64| -> rusqlite::Result<bool> {
            let n: i64 = self.db.query_row("SELECT COUNT(*) FROM friends WHERE pid = ?1", [p as i64], |r| r.get(0))?;
            Ok(n as usize >= MAX_FRIENDS)
        };
        if full(pid)? {
            return Ok(FriendAdd::TooManyFriends);
        }
        let theirs = "DELETE FROM friend_requests WHERE sender = ?1 AND receiver = ?2";
        if self.db.execute(theirs, params![other as i64, pid as i64])? == 1 {
            if full(other)? {
                return Ok(FriendAdd::TooManyFriends);
            }
            self.db.execute(theirs, params![pid as i64, other as i64])?;
            for (a, b) in [(pid, other), (other, pid)] {
                self.db.execute(
                    "INSERT OR IGNORE INTO friends (pid, friend, since) VALUES (?1, ?2, ?3)",
                    params![a as i64, b as i64, now as i64],
                )?;
            }
            return Ok(FriendAdd::Friends);
        }
        self.db.execute(
            "INSERT OR IGNORE INTO friend_requests (sender, receiver, created) VALUES (?1, ?2, ?3)",
            params![pid as i64, other as i64, now as i64],
        )?;
        Ok(FriendAdd::Requested)
    }

    /// Ends a friendship, or withdraws / declines a request, either way. False: there was nothing between them.
    pub fn remove_friend(&self, pid: u64, other: u64) -> rusqlite::Result<bool> {
        let (a, b) = (pid as i64, other as i64);
        let n = self
            .db
            .execute("DELETE FROM friends WHERE (pid = ?1 AND friend = ?2) OR (pid = ?2 AND friend = ?1)", [a, b])?
            + self.db.execute(
                "DELETE FROM friend_requests WHERE (sender = ?1 AND receiver = ?2) OR (sender = ?2 AND receiver = ?1)",
                [a, b],
            )?;
        Ok(n > 0)
    }

    /// Blocking also ends any friendship or request between the two.
    pub fn block(&self, pid: u64, other: u64) -> rusqlite::Result<bool> {
        if pid == other || self.find(&other.to_string())?.is_none() {
            return Ok(false);
        }
        self.remove_friend(pid, other)?;
        self.db.execute("INSERT OR IGNORE INTO blocks (pid, blocked) VALUES (?1, ?2)", [pid as i64, other as i64])?;
        Ok(true)
    }

    pub fn unblock(&self, pid: u64, other: u64) -> rusqlite::Result<bool> {
        Ok(self.db.execute("DELETE FROM blocks WHERE pid = ?1 AND blocked = ?2", [pid as i64, other as i64])? == 1)
    }
}

/// Administration from the command line (`oof-server <config> account|ban|unban …`), on the server's database: the
/// running server sees a ban at the next login and disconnects a connected player within 30 s.
pub fn admin(store: &AccountStore, args: &[String], now: u64) -> Result<String, String> {
    let db = |e: rusqlite::Error| format!("database: {e}");
    let usage = "usage: account <user|pid> | ban <user|pid> <hours|permanent> <reason…> | unban <user|pid>";
    let (Some(command), Some(who)) = (args.first(), args.get(1)) else { return Err(usage.into()) };
    let account = store.find(who).map_err(db)?.ok_or_else(|| format!("no account {who}"))?;
    match command.as_str() {
        "account" => {
            let ban = match store.ban_of(account.pid, now).map_err(db)? {
                Some(Ban { until: Some(t), reason }) => format!("banned until {t} (Unix time): {reason}"),
                Some(Ban { until: None, reason }) => format!("banned permanently: {reason}"),
                None => "not banned".into(),
            };
            Ok(format!(
                "{} pid {} created {} last login {} from {} devices {} — {ban}",
                account.username,
                account.pid,
                account.created,
                account.last_login.map_or("never".into(), |t| t.to_string()),
                account.last_address.as_deref().unwrap_or("-"),
                account.devices
            ))
        }
        "ban" => {
            let until = match args.get(2).map(String::as_str) {
                Some("permanent") => None,
                Some(h) => Some(now + h.parse::<u64>().map_err(|_| usage.to_string())? * 3600),
                None => return Err(usage.into()),
            };
            let reason = args.get(3..).map(|r| r.join(" ")).filter(|r| !r.is_empty()).ok_or(usage)?;
            store.set_ban(account.pid, until, &reason).map_err(db)?;
            Ok(format!(
                "{} (pid {}) banned {}: {reason}",
                account.username,
                account.pid,
                until.map_or("permanently".into(), |t| format!("until {t}"))
            ))
        }
        "unban" => {
            store.unban(account.pid).map_err(db)?;
            Ok(format!("{} (pid {}) unbanned", account.username, account.pid))
        }
        _ => Err(usage.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_commands() {
        let store = AccountStore::open(None).unwrap();
        let pid = store.create("Ana", &hash_password("password1"), 1).unwrap().unwrap();
        let run = |args: &[&str]| admin(&store, &args.iter().map(|a| a.to_string()).collect::<Vec<_>>(), 1000);
        assert!(run(&["account", "ana"]).unwrap().contains("not banned"));
        assert!(run(&["ban", "ana", "2", "spam"]).unwrap().contains("until 8200"));
        assert_eq!(store.ban_of(pid, 8199).unwrap().unwrap().reason, "spam");
        assert!(run(&["ban", &pid.to_string(), "permanent", "cheating", "online"]).unwrap().contains("permanently"));
        assert!(run(&["account", "Ana"]).unwrap().contains("banned permanently: cheating online"));
        assert!(run(&["unban", "ana"]).is_ok() && store.ban_of(pid, 0).unwrap().is_none());
        assert!(
            run(&["ban", "ana", "2"]).is_err()
                && run(&["ban", "ana", "x", "r"]).is_err()
                && run(&["account", "bea"]).is_err()
        );
    }

    #[test]
    fn friends_requests_and_blocks() {
        let store = AccountStore::open(None).unwrap();
        let [ana, bea, cid] = ["ana", "bea", "cid"].map(|n| store.create(n, "h", 1).unwrap().unwrap());
        assert_eq!(store.add_friend(ana, "BEA", 5).unwrap(), FriendAdd::Requested);
        assert_eq!(store.add_friend(ana, "bea", 5).unwrap(), FriendAdd::Requested); // asking twice keeps one request
        assert_eq!(store.friend_list(bea).unwrap().incoming, [(ana, "ana".to_string())]);
        assert_eq!(store.add_friend(bea, &ana.to_string(), 6).unwrap(), FriendAdd::Friends); // accepting = asking back
        let list = store.friend_list(ana).unwrap();
        assert_eq!((list.friends, list.incoming.len(), list.outgoing.len()), (vec![(bea, "bea".into())], 0, 0));
        assert_eq!(store.add_friend(bea, "ana", 7).unwrap(), FriendAdd::AlreadyFriends);
        assert_eq!(store.add_friend(ana, "ana", 7).unwrap(), FriendAdd::Yourself);
        assert_eq!(store.add_friend(ana, "nobody", 7).unwrap(), FriendAdd::UnknownUser);
        // blocking ends the friendship and stops requests both ways
        assert!(store.block(bea, ana).unwrap());
        assert!(store.friend_list(ana).unwrap().friends.is_empty());
        assert_eq!(store.add_friend(ana, "bea", 8).unwrap(), FriendAdd::Blocked);
        assert_eq!(store.add_friend(bea, "ana", 8).unwrap(), FriendAdd::Blocked);
        assert!(store.unblock(bea, ana).unwrap() && !store.unblock(bea, ana).unwrap());
        // declining = removing the request
        assert_eq!(store.add_friend(cid, "ana", 9).unwrap(), FriendAdd::Requested);
        assert!(store.remove_friend(ana, cid).unwrap() && !store.remove_friend(ana, cid).unwrap());
        assert_eq!(store.friend_list(cid).unwrap(), FriendList::default());
    }

    #[test]
    fn tokens() {
        let secret = [3u8; 32];
        let pid = new_pid();
        assert!(pid > u32::MAX as u64 && pid < 1 << 53);
        let token = issue_token(&secret, pid, 100);
        assert_eq!(verify_token(&secret, &token, 99), Some(pid));
        assert_eq!(verify_token(&secret, &token, 100), None, "expired");
        assert_eq!(verify_token(&[4u8; 32], &token, 99), None, "other secret");
        let forged = token.replacen('A', "B", 1);
        assert!(forged == token || verify_token(&secret, &forged, 99).is_none());
    }

    #[test]
    fn accounts_devices_and_bans() {
        let store = AccountStore::open(None).unwrap();
        assert!(
            valid_username("Ana_1")
                && !valid_username("ab")
                && !valid_username("a b c")
                && !valid_username(&"x".repeat(11))
        );
        assert!(valid_password("12345678") && !valid_password("1234567"));
        let hash = hash_password("correct horse");
        assert!(
            hash.starts_with("$argon2id$")
                && password_matches("correct horse", &hash)
                && !password_matches("wrong", &hash)
        );
        let pid = store.create("Ana_1", &hash, 10).unwrap().unwrap();
        assert_eq!(store.create("ana_1", &hash, 10).unwrap(), None, "user names are unique without regard to case");
        assert_eq!(store.find("ANA_1").unwrap().unwrap().pid, pid);
        assert_eq!(store.find(&pid.to_string()).unwrap().unwrap().username, "Ana_1");

        let key = store.add_device(pid, "Mac", 11).unwrap();
        assert!(store.device_ok(pid, &key, 12).unwrap());
        assert!(!store.device_ok(pid + 1, &key, 12).unwrap() && !store.device_ok(pid, "00", 12).unwrap());
        let second = store.add_device(pid, "other Mac", 13).unwrap();
        assert!(store.remove_device(pid, &second).unwrap() && !store.device_ok(pid, &second, 14).unwrap());
        store.set_password(pid, &hash_password("new password")).unwrap();
        assert!(!store.device_ok(pid, &key, 15).unwrap(), "a password change keeps old device keys");

        assert_eq!(store.ban_of(pid, 20).unwrap(), None);
        store.set_ban(pid, Some(100), "cheating").unwrap();
        assert_eq!(store.ban_of(pid, 99).unwrap(), Some(Ban { until: Some(100), reason: "cheating".into() }));
        assert_eq!(store.ban_of(pid, 100).unwrap(), None, "expired ban");
        store.set_ban(pid, None, "permanent").unwrap();
        assert_eq!(store.banned_among(&[pid, 7], u64::MAX).unwrap(), vec![pid]);
        store.unban(pid).unwrap();
        assert!(store.banned_among(&[pid], 0).unwrap().is_empty());
        store.record_login(pid, "203.0.113.9:5000", 30).unwrap();
        let a = store.find("ana_1").unwrap().unwrap();
        assert_eq!((a.last_login, a.last_address.as_deref(), a.devices), (Some(30), Some("203.0.113.9:5000"), 0));
    }
}
