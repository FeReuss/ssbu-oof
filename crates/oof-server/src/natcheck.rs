//! NAT check server (`nncs1`/`nncs2`): Pia's NatDetectionJob sends 16-byte big-endian UDP probes and
//! learns its public address and NAT behaviour from where and how the answers come back.
//!
//! Message: `u32 type | u32 external port | u32 external IPv4 | u32 address`. The server fills in
//! the sender's address. Types 3 and 102 are answered from the other port, type 2 from the other
//! address and port. The two addresses are `nncs1` and `nncs2` (config `nat_check`), each serving
//! both ports.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;

/// The ports of both NAT check servers; Pia sets 10025 itself (`main+0xc4fc0`).
pub const PORTS: [u16; 2] = [10025, 10125];
/// On the first NAT check address Pia also sends 16 zero bytes to 33334 during the check and, from its game
/// socket, NAT Protocol dummies to 33335 (`main+0xcafac`, `main+0xcc2c0`). Neither expects an answer.
pub const PIA_PORTS: [u16; 2] = [33334, 33335];

/// The station in a Pia NAT Protocol dummy (seen from 13.0.5, docs/re/protocols.md "Pia NAT check"): unencrypted
/// header version 4 (`32 AB 98 64`, byte 4 = 4, connection id 0; 32-byte header), a 24-byte message header with
/// protocol type 0x34 at 0x24, payload `NatProbeData` at 0x38: `u32 service variable id` (the client's RVCID),
/// `u8` probe type 0xFF, padding, `u64` timestamp, `u32 variable id` at 0x48 (the client's Pia CID), big-endian.
/// Returns (RVCID, CID).
pub fn pia_dummy_station(packet: &[u8]) -> Option<(u32, u32)> {
    if packet.len() < 0x4c || packet[..4] != [0x32, 0xAB, 0x98, 0x64] || packet[4] != 4 || packet[5] != 0 {
        return None;
    }
    if packet[0x24] != 0x34 || packet[0x3c] != 0xFF {
        return None;
    }
    let be = |at: usize| u32::from_be_bytes(packet[at..at + 4].try_into().expect("4 bytes"));
    Some((be(0x38), be(0x48)))
}

/// Which socket answers a probe, relative to the one that received it.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ReplyFrom {
    Same,
    OtherPort,
    OtherAddressAndPort,
}

/// Answer for one probe: which socket replies and the reply bytes.
pub fn answer(probe: &[u8], from: SocketAddr, server_ip: Option<std::net::Ipv4Addr>) -> Option<(ReplyFrom, [u8; 16])> {
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
    let reply = match kind {
        2 => ReplyFrom::OtherAddressAndPort,
        3 | 102 => ReplyFrom::OtherPort,
        _ => ReplyFrom::Same,
    };
    Some((reply, out))
}

/// Serves `sockets[address][port]` (addresses `nncs1`, `nncs2`; ports as in [`PORTS`]) and `pia` (nncs1 at
/// [`PIA_PORTS`]): a dummy's source address is the client's public UDP address, which becomes its public station
/// URL for peers (`GetSessionURLs`).
pub async fn run(
    sockets: [[UdpSocket; 2]; 2],
    pia: [UdpSocket; 2],
    server_ip: Option<std::net::Ipv4Addr>,
    state: Arc<crate::state::State>,
) {
    let listen = |sock: UdpSocket| {
        let state = state.clone();
        async move {
            let mut buf = [0u8; 1500];
            loop {
                let Ok((n, from)) = sock.recv_from(&mut buf).await else { continue };
                let station = pia_dummy_station(&buf[..n]);
                tracing::debug!(%from, len = n, ?station, "Pia NAT service datagram");
                if let Some((rvcid, cid)) = station {
                    crate::protocols::secure::observe_public_address(&state, rvcid, cid, from);
                }
            }
        }
    };
    let [p0, p1] = pia;
    tokio::spawn(listen(p0));
    tokio::spawn(listen(p1));
    let sockets = Arc::new(sockets);
    let serve = |a: usize, p: usize| {
        let sockets = sockets.clone();
        async move {
            let mut buf = [0u8; 64];
            loop {
                let Ok((n, from)) = sockets[a][p].recv_from(&mut buf).await else { continue };
                if let Some((by, reply)) = answer(&buf[..n], from, server_ip) {
                    let sock = match by {
                        ReplyFrom::Same => &sockets[a][p],
                        ReplyFrom::OtherPort => &sockets[a][1 - p],
                        ReplyFrom::OtherAddressAndPort => &sockets[1 - a][1 - p],
                    };
                    let _ = sock.send_to(&reply, from).await;
                }
            }
        }
    };
    tokio::join!(serve(0, 0), serve(0, 1), serve(1, 0), serve(1, 1));
}

#[cfg(test)]
mod tests {
    use super::{ReplyFrom, answer};

    #[test]
    fn fills_external_address_and_picks_port() {
        let from = "203.0.113.7:50000".parse().unwrap();
        let mut probe = [0u8; 16];
        probe[3] = 1;
        let (by, reply) = answer(&probe, from, Some("198.51.100.1".parse().unwrap())).unwrap();
        assert_eq!(by, ReplyFrom::Same);
        assert_eq!(reply, [0, 0, 0, 1, 0, 0, 0xC3, 0x50, 203, 0, 113, 7, 198, 51, 100, 1]);
        probe[3] = 3;
        assert_eq!(answer(&probe, from, None).unwrap().0, ReplyFrom::OtherPort);
        probe[3] = 2;
        assert_eq!(answer(&probe, from, None).unwrap().0, ReplyFrom::OtherAddressAndPort);
        probe[3] = 9;
        assert!(answer(&probe, from, None).is_none());
        assert!(answer(&probe[..8], from, None).is_none());
    }

    #[test]
    fn reads_the_station_of_a_pia_dummy() {
        // 76-byte dummy as the game sends it, RVCID 2 (only the fields the parser reads are non-zero here)
        let mut p = [0u8; 76];
        p[..5].copy_from_slice(&[0x32, 0xAB, 0x98, 0x64, 4]);
        p[0x20..0x25].copy_from_slice(&[0x7F, 0x09, 0x00, 0x14, 0x34]);
        p[0x3b] = 2;
        p[0x3c] = 0xFF;
        p[0x48..0x4c].copy_from_slice(&0xb4f0_14b3u32.to_be_bytes()); // CID
        assert_eq!(super::pia_dummy_station(&p), Some((2, 0xb4f0_14b3)));
        let mut encrypted = p;
        encrypted[4] = 0x84;
        assert_eq!(super::pia_dummy_station(&encrypted), None);
        let mut probe = p;
        probe[0x3c] = 0; // a probe request, not a dummy
        assert_eq!(super::pia_dummy_station(&probe), None);
        assert_eq!(super::pia_dummy_station(&p[..0x48]), None);
    }
}
