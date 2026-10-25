use crate::config::Config;
use crate::matchmaking::Matchmaking;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Mutex, RwLock};
use tokio::sync::mpsc;

/// `Call::protocol` that tells a player's connection to close (a ban), instead of carrying a call.
pub const KICK: u16 = 0;

/// A server-to-client RMC call (notification, NAT probe) queued for a connected player.
#[derive(Debug, Clone)]
pub struct Call {
    pub protocol: u16,
    pub method: u32,
    pub body: Vec<u8>,
}

/// A player logged in to the secure server.
#[derive(Debug, Clone)]
pub struct Session {
    pub cid: u32,
    pub tx: mpsc::UnboundedSender<Call>,
    /// Station URLs the client registered (public one first), used for P2P setup.
    pub urls: Vec<String>,
}

pub struct State {
    pub config: Config,
    /// `config.integer_settings` parsed: index -> (key, value) pairs for Utility 110/7.
    pub integer_settings: std::collections::BTreeMap<u32, Vec<(u16, i32)>>,
    pub secret: Vec<u8>,
    /// Key that seals server tickets; derived from `secret` so every node agrees.
    pub kerberos_key: [u8; 16],
    pub sessions: RwLock<HashMap<u64, Session>>,
    pub matchmaking: Mutex<Matchmaking>,
    pub tournaments: Mutex<crate::protocols::tournament::Tournaments>,
    pub objects: Mutex<crate::objects::ObjectStore>,
    pub accounts: Mutex<crate::accounts::AccountStore>,
    next_cid: AtomicU32,
    next_unique_id: AtomicU64,
}

impl State {
    pub fn new(config: Config) -> Result<Self, String> {
        let secret = config.secret_bytes()?;
        config.events.iter().try_for_each(|e| e.validate())?;
        let integer_settings = config.integer_settings()?;
        if let Some(nat) = &config.nat_check
            && (nat.primary == nat.secondary || nat.primary.is_unspecified() || nat.secondary.is_unspecified())
        {
            return Err("nat_check: primary and secondary must be two different addresses of this host".into());
        }
        let kerberos_key = oof_nex::kerberos::md5(&[b"oof-kerberos".as_slice(), &secret].concat());
        let seed = u64::from_le_bytes(crate::accounts::random_bytes()) >> 16;
        let objects =
            crate::objects::ObjectStore::open(config.database.as_deref()).map_err(|e| format!("database: {e}"))?;
        let accounts =
            crate::accounts::AccountStore::open(config.database.as_deref()).map_err(|e| format!("database: {e}"))?;
        Ok(Self {
            config,
            integer_settings,
            secret,
            kerberos_key,
            sessions: RwLock::default(),
            matchmaking: Mutex::default(),
            tournaments: Mutex::default(),
            objects: Mutex::new(objects),
            accounts: Mutex::new(accounts),
            next_cid: AtomicU32::new(1),
            next_unique_id: AtomicU64::new(seed),
        })
    }

    pub fn new_cid(&self) -> u32 {
        self.next_cid.fetch_add(1, Ordering::Relaxed)
    }

    pub fn new_unique_id(&self) -> u64 {
        self.next_unique_id.fetch_add(1, Ordering::Relaxed)
    }

    pub fn secure_url(&self) -> String {
        format!(
            "prudps:/address={};port={};CID=1;PID=2;sid=1;stream=10;type=2",
            self.config.public_host, self.config.public_port
        )
    }

    /// Queue a call to a connected player; returns false when they are offline.
    pub fn call(&self, pid: u64, protocol: u16, method: u32, body: Vec<u8>) -> bool {
        let sessions = self.sessions.read().expect("sessions lock");
        sessions.get(&pid).is_some_and(|s| s.tx.send(Call { protocol, method, body }).is_ok())
    }

    pub fn notify(&self, pid: u64, event: &crate::matchmaking::Notification) {
        self.call(pid, crate::protocols::NOTIFICATION, 1, event.encode());
    }
}

/// Closes the connections of players banned since they logged in (bans are also checked at every login).
pub fn kick_banned(state: &State) -> usize {
    let online: Vec<u64> = state.sessions.read().expect("sessions lock").keys().copied().collect();
    let now = oof_nex::stream::DateTime::now().to_unix();
    let banned = match state.accounts.lock().expect("accounts lock").banned_among(&online, now) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(%e, "account database");
            return 0;
        }
    };
    for &pid in &banned {
        tracing::info!(pid, "disconnecting a banned player");
        state.call(pid, KICK, 0, Vec::new());
    }
    banned.len()
}

pub async fn kick_banned_every(state: std::sync::Arc<State>, period: std::time::Duration) {
    loop {
        tokio::time::sleep(period).await;
        kick_banned(&state);
    }
}
