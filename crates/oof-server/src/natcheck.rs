//! NAT check server (`nncs1`/`nncs2`): Pia's NatDetectionJob sends 16-byte big-endian UDP probes and
//! learns its public address and NAT behaviour from where and how the answers come back.
//!
//! Message: `u32 type | u32 external port | u32 external IPv4 | u32 address`. The server fills in
//! the sender's address. Types 2, 3 and 102 must be answered from a different port (type 2 ideally
//! from a different IP too, which needs a second node; see docs/features.md).

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;

/// Answer for one probe: which socket replies (`true` = the other one) and the reply bytes.
pub fn answer(probe: &[u8], from: SocketAddr, server_ip: Option<std::net::Ipv4Addr>) -> Option<(bool, [u8; 16])> {
    let kind = u32::from_be_bytes(probe.get(..4)?.try_into().ok()?);
    if probe.len() != 16 || !matches!(kind, 1..=5 | 101..=103) {
        return None;
    }
    let IpAddr::V4(ip) = from.ip() else { return None };
    let mut out = [0u8; 16];
    out[..4].copy_from_slice(&kind.to_be_bytes());
    out[4..8].copy_from_slice(&(from.port() as u32).to_be_bytes());
    out[8..12].copy_from_slice(&ip.octets());
    out[12..].copy_from_slice(&server_ip.map(|i| i.octets()).unwrap_or_default());
    Some((matches!(kind, 2 | 3 | 102), out))
}

pub async fn run(primary: UdpSocket, secondary: UdpSocket, server_ip: Option<std::net::Ipv4Addr>) {
    let (primary, secondary) = (Arc::new(primary), Arc::new(secondary));
    let serve = |me: Arc<UdpSocket>, other: Arc<UdpSocket>| async move {
        let mut buf = [0u8; 64];
        loop {
            let Ok((n, from)) = me.recv_from(&mut buf).await else { continue };
            if let Some((swap, reply)) = answer(&buf[..n], from, server_ip) {
                let sock = if swap { &other } else { &me };
                let _ = sock.send_to(&reply, from).await;
            }
        }
    };
    tokio::join!(serve(primary.clone(), secondary.clone()), serve(secondary, primary));
}

#[cfg(test)]
mod tests {
    use super::answer;

    #[test]
    fn fills_external_address_and_picks_port() {
        let from = "203.0.113.7:50000".parse().unwrap();
        let mut probe = [0u8; 16];
        probe[3] = 1;
        let (swap, reply) = answer(&probe, from, Some("198.51.100.1".parse().unwrap())).unwrap();
        assert!(!swap);
        assert_eq!(reply, [0, 0, 0, 1, 0, 0, 0xC3, 0x50, 203, 0, 113, 7, 198, 51, 100, 1]);
        probe[3] = 3;
        assert!(answer(&probe, from, None).unwrap().0);
        probe[3] = 9;
        assert!(answer(&probe, from, None).is_none());
        assert!(answer(&probe[..8], from, None).is_none());
    }
}
