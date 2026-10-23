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
        8 => Ok(Vec::new()), // SendReport: client diagnostics
        _ => Err(NOT_IMPLEMENTED),
    }
}

/// The client's public address as this server sees it, using the client's own port and flags.
fn public_url(ctx: &Ctx, local: &str) -> String {
    let mut url = StationUrl::parse(local).unwrap_or(StationUrl { scheme: "prudp".into(), params: Vec::new() });
    url.set("address", ctx.peer.ip());
    url.set("type", 3); // public
    url.set("PID", ctx.pid.unwrap_or(0));
    url.set("RVCID", ctx.cid);
    url.to_string()
}

fn store(ctx: &Ctx, mut urls: Vec<String>) {
    let Some(pid) = ctx.pid else { return };
    for u in &mut urls {
        if let Some(mut url) = StationUrl::parse(u) {
            url.set("PID", pid);
            url.set("RVCID", ctx.cid);
            *u = url.to_string();
        }
    }
    if let Some(s) = ctx.state.sessions.write().expect("sessions lock").get_mut(&pid) {
        s.urls = urls;
    }
}

fn register(ctx: &mut Ctx, r: &mut Reader) -> Reply {
    let local = r.list(|r| r.string())?;
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
    let urls = ctx.state.sessions.read().expect("sessions lock").get(&pid).map(|s| s.urls.clone());
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
    fn station_url_round_trip_and_edit() {
        let mut u = StationUrl::parse("prudp:/address=192.168.1.2;port=59000;natf=0;natm=0;type=2").unwrap();
        assert_eq!(u.get("port"), Some("59000"));
        u.set("address", "203.0.113.9");
        u.set("RVCID", 7);
        assert_eq!(u.to_string(), "prudp:/address=203.0.113.9;port=59000;natf=0;natm=0;type=2;RVCID=7");
        assert!(StationUrl::parse("no-scheme").is_none());
    }
}
