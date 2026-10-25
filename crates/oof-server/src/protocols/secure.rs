//! Secure Connection (11): registers the client's station URLs (where peers reach it for P2P).

use super::{Ctx, NOT_IMPLEMENTED, Reply};
use oof_nex::rmc::RESULT_SUCCESS;
use oof_nex::stream::{Reader, Writer};

/// `scheme:/k=v;k=v` with keys kept in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StationUrl {
    pub scheme: String,
    pub params: Vec<(String, String)>,
}

impl StationUrl {
    pub fn parse(s: &str) -> Option<Self> {
        let (scheme, rest) = s.split_once(":/")?;
        let params = rest
            .split(';')
            .filter(|p| !p.is_empty())
            .map(|p| p.split_once('=').map(|(k, v)| (k.to_string(), v.to_string())))
            .collect::<Option<Vec<_>>>()?;
        Some(Self { scheme: scheme.to_string(), params })
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.params.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }

    pub fn set(&mut self, key: &str, value: impl ToString) {
        match self.params.iter_mut().find(|(k, _)| k == key) {
            Some((_, v)) => *v = value.to_string(),
            None => self.params.push((key.to_string(), value.to_string())),
        }
    }
}

impl std::fmt::Display for StationUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:/", self.scheme)?;
        for (i, (k, v)) in self.params.iter().enumerate() {
            write!(f, "{}{k}={v}", if i == 0 { "" } else { ";" })?;
        }
        Ok(())
    }
}

pub fn handle(ctx: &mut Ctx, method: u32, r: &mut Reader) -> Reply {
    match method {
        1 => register(ctx, r),
        4 => register(ctx, r), // RegisterEx: same list, then login data we do not need
        3 => request_urls(ctx, r),
        6 => {
            let urls = r.list(|r| r.string())?;
            store(ctx, urls);
            Ok(Vec::new())
        }
        7 => replace_url(ctx, r),
        8 => Ok(Vec::new()), // SendReport: client diagnostics
        _ => Err(NOT_IMPLEMENTED),
    }
}

/// The client's public address as this server sees it, using the client's own port and flags.
fn public_url(ctx: &Ctx, local: &str) -> String {
    let mut url = StationUrl::parse(local).unwrap_or(StationUrl { scheme: "prudp".into(), params: Vec::new() });
    if !ctx.state.config.trust_client_address || url.get("address").is_none() {
        url.set("address", ctx.peer.ip());
    }
    url.set("type", 3); // public
    url.set("PID", ctx.pid.unwrap_or(0));
    url.set("RVCID", ctx.cid);
    url.to_string()
}

/// A station URL as peers must see it: owned by this connection's PID and RVCID.
fn stamp(u: &str, pid: u64, cid: u32) -> String {
    let Some(mut url) = StationUrl::parse(u) else { return u.to_string() };
    url.set("PID", pid);
    url.set("RVCID", cid);
    url.to_string()
}

/// The station URLs a peer gets (GetSessionURLs, RequestURLs). Pia takes one or two and, with two, exactly one
/// public (`type` bit 2) and one private, else its URL parser fails with 0x10c07 (`main+0xc2460`); peers with the
/// same public address use the private one. 13.0.5 registers two placeholder URLs (`port=1`, `port=2`); behind a NAT
/// it replaces one after its NAT check with its real local address (the private URL with the Pia `CID`). Not behind a
/// NAT it replaces nothing and its private address is its public one: peers then get a private copy of the public URL.
pub fn peer_urls(urls: &[String]) -> Vec<String> {
    let is_public = |u: &StationUrl| u.get("type").and_then(|t| t.parse::<u32>().ok()).is_some_and(|t| t & 2 != 0);
    let parsed: Vec<StationUrl> = urls.iter().filter_map(|u| StationUrl::parse(u)).collect();
    let Some(public) = parsed.iter().find(|u| is_public(u)) else { return urls.to_vec() };
    let private = parsed.iter().find(|u| !is_public(u) && u.get("CID").is_some()).map(StationUrl::to_string);
    let private = private.unwrap_or_else(|| {
        let mut copy = StationUrl { scheme: public.scheme.clone(), params: public.params.clone() };
        copy.params.retain(|(k, _)| k != "type");
        copy.to_string()
    });
    vec![public.to_string(), private]
}

fn store(ctx: &Ctx, urls: Vec<String>) {
    let Some(pid) = ctx.pid else { return };
    let urls = urls.iter().map(|u| stamp(u, pid, ctx.cid)).collect();
    if let Some(s) = ctx.state.sessions.write().expect("sessions lock").get_mut(&pid) {
        s.urls = urls;
    }
}

/// The client with this RVCID as the NAT check service on nncs1:33335 sees it (its Pia dummy): its public station
/// URL (`type=3`) gets the dummy's source address and port, which peers receive from GetSessionURLs (before that
/// it only carries the WebSocket peer address), and the dummy's Pia `CID`. A client that is not behind a NAT never
/// sends ReplaceURL, so this is where a peer learns its CID; Pia ignores probes from a station whose CID it does not
/// expect (seen from 13.0.5: a joiner given `CID=0` received the host's probe requests and never answered).
pub fn observe_public_address(state: &crate::state::State, rvcid: u32, cid: u32, from: std::net::SocketAddr) {
    let mut sessions = state.sessions.write().expect("sessions lock");
    let Some(s) = sessions.values_mut().find(|s| s.cid == rvcid) else { return };
    for u in &mut s.urls {
        let Some(mut url) = StationUrl::parse(u) else { continue };
        if url.get("type") != Some("3") {
            continue;
        }
        let before = url.to_string();
        if !state.config.trust_client_address {
            url.set("address", from.ip());
        }
        url.set("port", from.port());
        if cid != 0 {
            url.set("CID", cid);
        }
        if url.to_string() != before {
            tracing::debug!(rvcid, cid, %from, "public station address");
            *u = url.to_string();
        }
    }
}

/// ReplaceURL(old, new): after Pia's NAT check the game swaps one of its station URLs for one that
/// carries its NAT properties (seen from 13.0.5 right before GetSessionURLs). The stored URL with the
/// same scheme, address and port as `old` is replaced; without one, `new` is added so peers still
/// get it.
fn replace_url(ctx: &mut Ctx, r: &mut Reader) -> Reply {
    let old = r.string()?;
    let new = r.string()?;
    tracing::debug!(%old, %new, "ReplaceURL");
    let Some(pid) = ctx.pid else { return Ok(Vec::new()) };
    let key = |u: &str| {
        StationUrl::parse(u)
            .map(|u| (u.scheme.clone(), u.get("address").map(str::to_owned), u.get("port").map(str::to_owned)))
    };
    let new = stamp(&new, pid, ctx.cid);
    let nat = StationUrl::parse(&new).map(|u| (u.get("natm").map(str::to_owned), u.get("natf").map(str::to_owned)));
    if let Some(s) = ctx.state.sessions.write().expect("sessions lock").get_mut(&pid) {
        match s.urls.iter_mut().find(|u| key(u).is_some() && key(u) == key(&old)) {
            Some(u) => *u = new,
            None => s.urls.push(new),
        }
        // the public URL describes the same station: it carries the NAT properties the check found
        for u in &mut s.urls {
            if let (Some(mut url), Some((Some(m), Some(f)))) = (StationUrl::parse(u), nat.clone())
                && url.get("type") == Some("3")
            {
                url.set("natm", m);
                url.set("natf", f);
                *u = url.to_string();
            }
        }
    }
    Ok(Vec::new())
}

fn register(ctx: &mut Ctx, r: &mut Reader) -> Reply {
    let local = r.list(|r| r.string())?;
    tracing::debug!(?local, "Register");
    let public = public_url(ctx, local.first().map(String::as_str).unwrap_or("prudp:/"));
    let mut all = vec![public.clone()];
    all.extend(local);
    store(ctx, all);
    let mut w = Writer::new();
    w.result(RESULT_SUCCESS).u32(ctx.cid).string(&public);
    Ok(w.into_bytes())
}

fn request_urls(ctx: &mut Ctx, r: &mut Reader) -> Reply {
    let _cid = r.u32()?;
    let pid = r.pid()?;
    let urls = ctx.state.sessions.read().expect("sessions lock").get(&pid).map(|s| peer_urls(&s.urls));
    let mut w = Writer::new();
    w.bool(urls.is_some()).list(&urls.unwrap_or_default(), |w, u| {
        w.string(u);
    });
    Ok(w.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::StationUrl;

    #[test]
    fn pia_dummy_source_becomes_the_public_station_address() {
        let config = crate::config::Config {
            listen: "127.0.0.1:1".parse().unwrap(),
            public_host: "127.0.0.1".into(),
            public_port: 1,
            secret: "11".repeat(32),
            token_ttl_secs: 60,
            nat_check: None,
            trust_client_address: false,
            database: None,
            events: Vec::new(),
            integer_settings: Default::default(),
        };
        let state = crate::state::State::new(config).unwrap();
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let urls = vec![
            "prudp:/address=127.0.0.1;port=2;natf=0;natm=0;type=3;PID=9;RVCID=7".to_string(),
            "prudp:/address=192.168.1.7;port=50380;natf=17;natm=1;PID=9;RVCID=7".to_string(),
        ];
        state.sessions.write().unwrap().insert(9, crate::state::Session { cid: 7, tx, urls });
        super::observe_public_address(&state, 8, 5, "203.0.113.5:61000".parse().unwrap()); // another client: no change
        assert!(state.sessions.read().unwrap()[&9].urls[0].contains("address=127.0.0.1;port=2"));
        super::observe_public_address(&state, 7, 5, "203.0.113.5:61000".parse().unwrap());
        let urls = state.sessions.read().unwrap()[&9].urls.clone();
        assert_eq!(urls[0], "prudp:/address=203.0.113.5;port=61000;natf=0;natm=0;type=3;PID=9;RVCID=7;CID=5");
        assert_eq!(
            urls[1], "prudp:/address=192.168.1.7;port=50380;natf=17;natm=1;PID=9;RVCID=7",
            "local URL untouched"
        );
        // never replaced (not behind a NAT): the private URL peers get is the public one
        assert_eq!(
            super::peer_urls(&urls),
            [
                "prudp:/address=203.0.113.5;port=61000;natf=0;natm=0;type=3;PID=9;RVCID=7;CID=5",
                "prudp:/address=203.0.113.5;port=61000;natf=0;natm=0;PID=9;RVCID=7;CID=5"
            ]
        );
    }

    #[test]
    fn trusted_client_address_survives_the_dummy() {
        let config = crate::config::Config {
            listen: "127.0.0.1:1".parse().unwrap(),
            public_host: "127.0.0.1".into(),
            public_port: 1,
            secret: "11".repeat(32),
            token_ttl_secs: 60,
            nat_check: None,
            trust_client_address: true,
            database: None,
            events: Vec::new(),
            integer_settings: Default::default(),
        };
        let state = crate::state::State::new(config).unwrap();
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let urls = vec!["prudp:/address=198.51.100.2;port=1;type=3;PID=9;RVCID=7".to_string()];
        state.sessions.write().unwrap().insert(9, crate::state::Session { cid: 7, tx, urls });
        super::observe_public_address(&state, 7, 5, "127.0.0.1:51000".parse().unwrap());
        assert_eq!(
            state.sessions.read().unwrap()[&9].urls[0],
            "prudp:/address=198.51.100.2;port=51000;type=3;PID=9;RVCID=7;CID=5"
        );
    }

    #[test]
    fn station_url_round_trip_and_edit() {
        let mut u = StationUrl::parse("prudp:/address=192.168.1.2;port=59000;natf=0;natm=0;type=2").unwrap();
        assert_eq!(u.get("port"), Some("59000"));
        u.set("address", "203.0.113.9");
        u.set("RVCID", 7);
        assert_eq!(u.to_string(), "prudp:/address=203.0.113.9;port=59000;natf=0;natm=0;type=2;RVCID=7");
        assert!(StationUrl::parse("no-scheme").is_none());
    }
}
