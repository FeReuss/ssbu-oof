//! NAT check server (`nncs1`/`nncs2`): Pia's NatDetectionJob sends 16-byte big-endian UDP probes and
//! learns its public address and NAT behaviour from the answers.
//!
//! Message: `u32 type | u32 external port | u32 external IPv4 | u32 address`. The server fills in
//! the sender's address. Pia 5.19 sends only types 101 and 102 to nncs1 and 103 to nncs2, all to port
//! 10025; 102 is answered from the other port, the rest from the same socket. No answer comes from the
//! other address, so each address serves its two ports on its own and nncs2 may be another host
//! (config `nat_check.remote_secondary`, `oof-server nat-check`).

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
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

/// Answer for one probe: whether it comes from the other port of the receiving address, and the reply bytes.
/// Pia accepts only answers of type 101..=103 (`main+0xc86b4`) and stores the message, not where it came from; it
/// never reads the last field (the answering address here).
pub fn answer(probe: &[u8], from: SocketAddr, address: Ipv4Addr) -> Option<(bool, [u8; 16])> {
    let kind = u32::from_be_bytes(probe.get(..4)?.try_into().ok()?);
    if probe.len() != 16 || !(101..=103).contains(&kind) {
        return None;
    }
    let IpAddr::V4(ip) = from.ip() else { return None };
    let mut out = [0u8; 16];
    out[..4].copy_from_slice(&kind.to_be_bytes());
    out[4..8].copy_from_slice(&(from.port() as u32).to_be_bytes());
    out[8..12].copy_from_slice(&ip.octets());
    out[12..].copy_from_slice(&address.octets());
    Some((kind == 102, out))
}

/// Binds `ip` at both `ports`; a NAT check that cannot listen is a startup error.
pub async fn bind(ip: Ipv4Addr, ports: [u16; 2]) -> [UdpSocket; 2] {
    let bind = |port| async move {
        let a = SocketAddr::from((ip, port));
        UdpSocket::bind(a).await.unwrap_or_else(|e| panic!("binding {a}: {e}"))
    };
    [bind(ports[0]).await, bind(ports[1]).await]
}

/// Serves one NAT check address announced as `address`: `sockets` are bound at its [`PORTS`].
pub async fn serve(sockets: [UdpSocket; 2], address: Ipv4Addr) {
    let sockets = Arc::new(sockets);
    let port = |p: usize| {
        let sockets = sockets.clone();
        async move {
            let mut buf = [0u8; 64];
            loop {
                let Ok((n, from)) = sockets[p].recv_from(&mut buf).await else { continue };
                if let Some((other_port, reply)) = answer(&buf[..n], from, address) {
                    let _ = sockets[if other_port { 1 - p } else { p }].send_to(&reply, from).await;
                }
            }
        }
    };
    tokio::join!(port(0), port(1));
}

/// Listens on nncs1's [`PIA_PORTS`]: a dummy's source address is the client's public UDP address, which becomes its
/// public station URL for peers (`GetSessionURLs`).
pub async fn listen_pia(sockets: [UdpSocket; 2], state: Arc<crate::state::State>) {
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
    let [p0, p1] = sockets;
    tokio::join!(listen(p0), listen(p1));
}

#[cfg(test)]
mod tests {
    use super::answer;

    #[test]
    fn fills_external_address_and_picks_port() {
        let from = "203.0.113.7:50000".parse().unwrap();
        let server = "198.51.100.1".parse().unwrap();
        let mut probe = [0u8; 16];
        probe[3] = 101;
        let (other_port, reply) = answer(&probe, from, server).unwrap();
        assert!(!other_port);
        assert_eq!(reply, [0, 0, 0, 101, 0, 0, 0xC3, 0x50, 203, 0, 113, 7, 198, 51, 100, 1]);
        probe[3] = 102;
        assert!(answer(&probe, from, server).unwrap().0);
        probe[3] = 103;
        assert!(!answer(&probe, from, server).unwrap().0);
        for kind in [0, 2, 104] {
            probe[3] = kind;
            assert!(answer(&probe, from, server).is_none(), "{kind}");
        }
        assert!(answer(&probe[..8], from, server).is_none());
    }

    /// A NAT check address served alone (as `oof-server nat-check` does for a remote nncs2): 103 comes back from the
    /// socket it was sent to, 102 from the other port.
    #[tokio::test]
    async fn serves_one_address_on_its_own() {
        let ip = std::net::Ipv4Addr::LOCALHOST;
        let sockets =
            [tokio::net::UdpSocket::bind((ip, 0)).await.unwrap(), tokio::net::UdpSocket::bind((ip, 0)).await.unwrap()];
        let ports = sockets.each_ref().map(|s| s.local_addr().unwrap());
        tokio::spawn(super::serve(sockets, ip));
        let client = tokio::net::UdpSocket::bind((ip, 0)).await.unwrap();
        let mut buf = [0u8; 64];
        for (kind, answered_by) in [(103u32, ports[0]), (102, ports[1])] {
            client.send_to(&[kind.to_be_bytes(), [0; 4], [0; 4], [0; 4]].concat(), ports[0]).await.unwrap();
            let (n, from) = client.recv_from(&mut buf).await.unwrap();
            assert_eq!((n, from), (16, answered_by), "{kind}");
            assert_eq!(buf[4..8], (client.local_addr().unwrap().port() as u32).to_be_bytes());
        }
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
