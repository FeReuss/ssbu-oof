use serde::Deserialize;
use std::net::{Ipv4Addr, SocketAddr};

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
    /// UDP NAT check server for Pia (`nncs1`/`nncs2`), announced in `GET /v1/status`; omit to run
    /// without online battles (Pia refuses to start a NAT check without it).
    pub nat_check: Option<NatCheck>,
    /// Development only: take each client's public address from the station URLs it registers instead of the address
    /// its connections come from, so several game instances on one machine can look like separate hosts (the port's
    /// `OOF_VIRTUAL_INDEX`). Never enable it on a public server: clients could claim any address.
    #[serde(default)]
    pub trust_client_address: bool,
    /// SQLite file for what must survive a restart (players' DataStore records, which carry their disconnect and
    /// conduct state). Omitted: kept in memory only, forgotten on restart.
    pub database: Option<String>,
    /// Timed events (online tourneys and similar) served by Utility 110/11; none when omitted.
    #[serde(default)]
    pub events: Vec<crate::events::GameEvent>,
    /// Utility 110/7 `GetIntegerSettings`: per requested index, the `Map<u16, i32>` returned (TOML keys are the
    /// numbers as strings, e.g. `[integer_settings.0]` with `"3" = 1`); an index without an entry gets an empty map.
    #[serde(default)]
    pub integer_settings: std::collections::BTreeMap<String, std::collections::BTreeMap<String, i32>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NatCheck {
    /// `nncs1`: an IPv4 address of this host, serving UDP 10025 and 10125.
    pub primary: Ipv4Addr,
    /// `nncs2`: another IPv4 address of this host, serving the same ports. Pia picks its second
    /// NAT check server as the first address with the same port and a different IP than the
    /// first one (`main+0xc6590`), and fails the NAT check (0x10c08) when there is none.
    /// shortcut: the bound addresses are the announced ones; add public overrides when a node sits
    /// behind 1:1 NAT (cloud elastic IPs).
    pub secondary: Ipv4Addr,
}

fn default_token_ttl() -> u64 {
    3600
}

impl Config {
    /// `integer_settings` with numeric keys; an invalid key is a config error.
    pub fn integer_settings(&self) -> Result<std::collections::BTreeMap<u32, Vec<(u16, i32)>>, String> {
        let bad = |k: &str| format!("integer_settings: {k:?} is not a number");
        let mut out = std::collections::BTreeMap::new();
        for (index, map) in &self.integer_settings {
            let mut values = Vec::new();
            for (key, value) in map {
                values.push((key.parse().map_err(|_| bad(key))?, *value));
            }
            out.insert(index.parse().map_err(|_| bad(index))?, values);
        }
        Ok(out)
    }

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

#[cfg(test)]
mod tests {
    #[test]
    fn the_example_config_parses() {
        let c: super::Config = toml::from_str(include_str!("../../../oof.example.toml")).unwrap();
        assert_eq!(c.database.as_deref(), Some("oof.db"));
        assert!(c.nat_check.is_some() && !c.trust_client_address);
    }
}
