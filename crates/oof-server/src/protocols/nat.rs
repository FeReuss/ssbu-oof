//! NAT Traversal (3): Pia peers ask the server to tell each other to start UDP probes at the same
//! time, which opens both NATs. The server only relays the request; the probes are P2P.

use super::secure::StationUrl;
use super::{Ctx, NAT_TRAVERSAL, NOT_IMPLEMENTED, Reply};
use oof_nex::stream::{DateTime, Reader, Writer};

const INITIATE_PROBE: u32 = 2;

pub fn handle(ctx: &mut Ctx, method: u32, r: &mut Reader) -> Reply {
    match method {
        // RequestProbeInitiation(List<StationURL> targets): probe the caller's public URL
        1 => {
            let targets = r.list(|r| r.string())?;
            let me = ctx.pid.and_then(|pid| {
                ctx.state.sessions.read().expect("sessions lock").get(&pid).and_then(|s| s.urls.first().cloned())
            });
            relay(ctx, &targets, &me.unwrap_or_default());
            Ok(Vec::new())
        }
        // RequestProbeInitiationExt(List<StationURL> targets, StationURL station_to_probe)
        3 => {
            let targets = r.list(|r| r.string())?;
            let station = r.string()?;
            tracing::debug!(?targets, %station, "RequestProbeInitiationExt");
            relay(ctx, &targets, &station);
            Ok(Vec::new())
        }
        // ReportNATTraversalResult / ReportNATProperties / ReportNATTraversalResultDetail: telemetry
        4 | 5 | 7 => Ok(Vec::new()),
        // GetRelaySignatureKey -> (i32 mode, DateTime, String address, u16 port, i32 type, u32 game server id)
        // Mode 0 = no relay server. SSBU 13.0.5 never calls this: its Pia relay is compiled in but switched off
        // (docs/re/protocols.md, "Relay").
        6 => {
            let mut w = Writer::new();
            w.i32(0).u64(DateTime::now().0).string("").u16(0).i32(0).u32(0);
            Ok(w.into_bytes())
        }
        _ => Err(NOT_IMPLEMENTED),
    }
}

fn relay(ctx: &Ctx, targets: &[String], station: &str) {
    let mut body = Writer::new();
    body.string(station);
    let body = body.into_bytes();
    for target in targets {
        let pid = StationUrl::parse(target).and_then(|u| u.get("PID").and_then(|p| p.parse::<u64>().ok()));
        if let Some(pid) = pid.filter(|p| Some(*p) != ctx.pid) {
            tracing::debug!(from = ?ctx.pid, to = pid, "InitiateProbe");
            ctx.state.call(pid, NAT_TRAVERSAL, INITIATE_PROBE, body.clone());
        }
    }
}
