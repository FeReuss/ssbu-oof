use serde::Deserialize;
use std::net::SocketAddr;

/// Server configuration (`oof.toml`; see `oof.example.toml`).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Address the HTTP + WebSocket listener binds to.
    pub listen: SocketAddr,
    /// Host name or IP that clients use to reach this server (goes into station URLs).
    pub public_host: String,
    /// Port clients use (differs from `listen` behind a TLS terminator / load balancer).
    pub public_port: u16,
    /// 32+ random bytes as hex. Signs account passwords, ID tokens and Kerberos tickets, so every
    /// node of one deployment must share it. Rotating it logs everybody out.
    pub secret: String,
    /// Lifetime of ID tokens handed to ports, in seconds.
    #[serde(default = "default_token_ttl")]
    pub token_ttl_secs: u64,
    /// UDP NAT check server for Pia (`nncs1`/`nncs2`); omit to run it elsewhere.
    pub nat_check: Option<NatCheck>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NatCheck {
    /// Usually port 10025.
    pub primary: SocketAddr,
    /// Usually port 10125 on the same host.
    pub secondary: SocketAddr,
}

fn default_token_ttl() -> u64 {
    3600
}

impl Config {
    pub fn secret_bytes(&self) -> Result<Vec<u8>, String> {
        let s = self.secret.trim();
        if s.len() < 64 || !s.len().is_multiple_of(2) {
            return Err("secret must be at least 32 bytes of hex (64 hex characters)".into());
        }
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| "secret is not hex".to_string()))
            .collect()
    }
}
