//! PRUDP "Lite": the packet format Switch NEX clients send over a WebSocket (subprotocol `NEX`).
//!
//! The WebSocket already gives reliable ordered delivery and TLS, so Lite has no checksums, no
//! payload encryption and no resends; PRUDP still provides virtual connections (one per
//! `source type/port` pair), sequence numbers, ACKs and fragmentation.
//!
//! Header (12 bytes, little endian): `0x80 | option size | payload size u16 | src type<<4 | dst type |
//! src port | dst port | fragment id | type | flags<<4 (u16) | sequence id u16`, then options, payload.

use crate::stream::{Error, Reader, Result, Writer};
use std::collections::{BTreeMap, HashMap};

pub const TYPE_SYN: u8 = 0;
pub const TYPE_CONNECT: u8 = 1;
pub const TYPE_DATA: u8 = 2;
pub const TYPE_DISCONNECT: u8 = 3;
pub const TYPE_PING: u8 = 4;

pub const FLAG_ACK: u16 = 0x001;
pub const FLAG_RELIABLE: u16 = 0x002;
pub const FLAG_NEED_ACK: u16 = 0x004;
pub const FLAG_HAS_SIZE: u16 = 0x008;
pub const FLAG_MULTI_ACK: u16 = 0x200;

pub const OPT_SUPPORT: u8 = 0;
pub const OPT_CONNECTION_SIG: u8 = 1;
pub const OPT_CONNECTION_SIG_LITE: u8 = 0x80;

/// Highest PRUDP minor version this server negotiates (Switch clients use 5 or lower).
pub const MINOR_VERSION: u32 = 5;
/// Payload bytes per fragment for server-originated DATA.
pub const FRAGMENT_SIZE: usize = 1300;
/// Largest reassembled message accepted from a client (RMC requests are small).
pub const MAX_MESSAGE: usize = 1 << 20;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Packet {
    pub source_type: u8,
    pub source_port: u8,
    pub dest_type: u8,
    pub dest_port: u8,
    pub fragment_id: u8,
    pub kind: u8,
    pub flags: u16,
    pub seq: u16,
    pub options: Vec<(u8, Vec<u8>)>,
    pub payload: Vec<u8>,
}

impl Packet {
    pub fn option(&self, id: u8) -> Option<&[u8]> {
        self.options.iter().find(|(k, _)| *k == id).map(|(_, v)| v.as_slice())
    }

    pub fn support(&self) -> Option<u32> {
        self.option(OPT_SUPPORT).and_then(|v| v.try_into().ok()).map(u32::from_le_bytes)
    }

    /// A reply addressed back to the sender of `self`.
    fn reply(&self, kind: u8, flags: u16) -> Packet {
        Packet {
            source_type: self.dest_type,
            source_port: self.dest_port,
            dest_type: self.source_type,
            dest_port: self.source_port,
            kind,
            flags,
            ..Default::default()
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut opts = Writer::new();
        for (id, value) in &self.options {
            opts.u8(*id).u8(value.len() as u8).bytes(value);
        }
        let opts = opts.into_bytes();
        let mut w = Writer::new();
        w.u8(0x80)
            .u8(opts.len() as u8)
            .u16(self.payload.len() as u16)
            .u8(self.source_type << 4 | self.dest_type)
            .u8(self.source_port)
            .u8(self.dest_port)
            .u8(self.fragment_id)
            .u16(self.kind as u16 | self.flags << 4)
            .u16(self.seq)
            .bytes(&opts)
            .bytes(&self.payload);
        w.into_bytes()
    }
}

/// Decode every packet in one WebSocket message.
pub fn decode_all(data: &[u8]) -> Result<Vec<Packet>> {
    let mut r = Reader::new(data);
    let mut out = Vec::new();
    while r.remaining() > 0 {
        if r.u8()? != 0x80 {
            return Err(Error::Invalid("PRUDP Lite magic"));
        }
        let option_size = r.u8()? as usize;
        let payload_size = r.u16()? as usize;
        let types = r.u8()?;
        let (source_port, dest_port, fragment_id) = (r.u8()?, r.u8()?, r.u8()?);
        let type_flags = r.u16()?;
        let seq = r.u16()?;
        let mut opts = Reader::new(r.take(option_size)?);
        let mut options = Vec::new();
        while opts.remaining() > 0 {
            let id = opts.u8()?;
            let len = opts.u8()? as usize;
            options.push((id, opts.take(len)?.to_vec()));
        }
        out.push(Packet {
            source_type: types >> 4,
            dest_type: types & 0xF,
            source_port,
            dest_port,
            fragment_id,
            kind: (type_flags & 0xF) as u8,
            flags: type_flags >> 4,
            seq,
            options,
            payload: r.take(payload_size)?.to_vec(),
        });
    }
    Ok(out)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ConnKey {
    pub kind: u8,
    pub port: u8,
}

/// What the endpoint asks its owner to do.
#[derive(Debug, PartialEq, Eq)]
pub enum Output {
    Send(Packet),
    /// A CONNECT arrived; call [`Endpoint::accept`] (or drop the connection) with the login result.
    Connect {
        conn: ConnKey,
        payload: Vec<u8>,
    },
    /// A complete (reassembled) message from the client.
    Message {
        conn: ConnKey,
        data: Vec<u8>,
    },
    Closed(ConnKey),
}

#[derive(Debug)]
struct Connection {
    local_type: u8,
    local_port: u8,
    connected: bool,
    support: u32,
    next_in: u16,
    early: BTreeMap<u16, Packet>,
    fragments: Vec<u8>,
    next_out: u16,
}

/// The server side of all PRUDP virtual connections multiplexed on one WebSocket.
#[derive(Debug, Default)]
pub struct Endpoint {
    conns: HashMap<ConnKey, Connection>,
}

impl Endpoint {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_connected(&self, conn: ConnKey) -> bool {
        self.conns.get(&conn).is_some_and(|c| c.connected)
    }

    /// Feed one packet from the client. `signature` is the 16-byte connection signature to hand out
    /// on SYN (any unpredictable value works over a WebSocket).
    pub fn handle(&mut self, p: Packet, signature: [u8; 16], out: &mut Vec<Output>) -> Result<()> {
        let key = ConnKey { kind: p.source_type, port: p.source_port };
        if p.flags & (FLAG_ACK | FLAG_MULTI_ACK) != 0 {
            return Ok(()); // acknowledgements of our packets: TCP already guarantees delivery
        }
        match p.kind {
            TYPE_SYN => {
                let client = p.support().ok_or(Error::Invalid("SYN without support option"))?;
                let support = (client & 0xFF).min(MINOR_VERSION); // no optional functions
                let mut ack = p.reply(TYPE_SYN, FLAG_ACK);
                ack.options =
                    vec![(OPT_SUPPORT, support.to_le_bytes().to_vec()), (OPT_CONNECTION_SIG, signature.to_vec())];
                self.conns.insert(
                    key,
                    Connection {
                        local_type: p.dest_type,
                        local_port: p.dest_port,
                        connected: false,
                        support,
                        next_in: 2, // the CONNECT consumes reliable sequence id 1
                        early: BTreeMap::new(),
                        fragments: Vec::new(),
                        next_out: 1,
                    },
                );
                out.push(Output::Send(ack));
            }
            TYPE_CONNECT => {
                let conn = self.conns.get(&key).ok_or(Error::Invalid("CONNECT before SYN"))?;
                if conn.connected || p.seq != 1 {
                    return Err(Error::Invalid("unexpected CONNECT"));
                }
                out.push(Output::Connect { conn: key, payload: p.payload });
            }
            _ => {
                let Some(conn) = self.conns.get_mut(&key) else {
                    return Err(Error::Invalid("packet for unknown connection"));
                };
                if !conn.connected {
                    return Err(Error::Invalid("packet before CONNECT"));
                }
                if p.flags & FLAG_NEED_ACK != 0 {
                    let mut ack = p.reply(p.kind, FLAG_ACK);
                    ack.seq = p.seq;
                    ack.fragment_id = p.fragment_id;
                    out.push(Output::Send(ack));
                }
                if p.flags & FLAG_RELIABLE == 0 {
                    if p.kind == TYPE_DATA {
                        out.push(Output::Message { conn: key, data: p.payload });
                    } else if p.kind == TYPE_DISCONNECT {
                        self.close(key, out);
                    }
                    return Ok(());
                }
                // Reliable packets (DATA, PING, DISCONNECT) share one ordered sequence space.
                if seq_before(p.seq, conn.next_in) {
                    return Ok(()); // duplicate
                }
                conn.early.insert(p.seq, p);
                while let Some(p) = conn.early.remove(&conn.next_in) {
                    conn.next_in = conn.next_in.wrapping_add(1);
                    match p.kind {
                        TYPE_DATA => {
                            if conn.fragments.len() + p.payload.len() > MAX_MESSAGE {
                                return Err(Error::Invalid("message too large"));
                            }
                            conn.fragments.extend_from_slice(&p.payload);
                            if p.fragment_id == 0 {
                                out.push(Output::Message { conn: key, data: std::mem::take(&mut conn.fragments) });
                            }
                        }
                        TYPE_DISCONNECT => {
                            self.close(key, out);
                            return Ok(());
                        }
                        _ => {} // PING: the ACK above is the whole answer
                    }
                }
                if conn.early.len() > 256 {
                    return Err(Error::Invalid("reliable window overflow"));
                }
            }
        }
        Ok(())
    }

    /// Complete a CONNECT: `response` is the payload of the CONNECT/ACK (empty on the
    /// authentication server, the ticket check value on the secure server).
    pub fn accept(&mut self, conn: ConnKey, response: Vec<u8>) -> Option<Packet> {
        let c = self.conns.get_mut(&conn)?;
        c.connected = true;
        Some(Packet {
            source_type: c.local_type,
            source_port: c.local_port,
            dest_type: conn.kind,
            dest_port: conn.port,
            kind: TYPE_CONNECT,
            flags: FLAG_ACK | FLAG_HAS_SIZE,
            seq: 1,
            options: vec![(OPT_SUPPORT, c.support.to_le_bytes().to_vec())],
            payload: response,
            ..Default::default()
        })
    }

    /// Split a message into reliable DATA fragments.
    pub fn send(&mut self, conn: ConnKey, data: &[u8]) -> Vec<Packet> {
        let Some(c) = self.conns.get_mut(&conn) else { return Vec::new() };
        let chunks: Vec<&[u8]> = if data.is_empty() { vec![data] } else { data.chunks(FRAGMENT_SIZE).collect() };
        let last = chunks.len() - 1;
        chunks
            .into_iter()
            .enumerate()
            .map(|(i, chunk)| {
                let seq = c.next_out;
                c.next_out = c.next_out.wrapping_add(1);
                Packet {
                    source_type: c.local_type,
                    source_port: c.local_port,
                    dest_type: conn.kind,
                    dest_port: conn.port,
                    // fragment ids count up from 1; the last fragment is 0
                    fragment_id: if i == last { 0 } else { (i + 1) as u8 },
                    kind: TYPE_DATA,
                    flags: FLAG_RELIABLE | FLAG_NEED_ACK | FLAG_HAS_SIZE,
                    seq,
                    options: Vec::new(),
                    payload: chunk.to_vec(),
                }
            })
            .collect()
    }

    fn close(&mut self, key: ConnKey, out: &mut Vec<Output>) {
        if let Some(c) = self.conns.remove(&key) {
            // The protocol acknowledges a DISCONNECT three times.
            for _ in 0..3 {
                out.push(Output::Send(Packet {
                    source_type: c.local_type,
                    source_port: c.local_port,
                    dest_type: key.kind,
                    dest_port: key.port,
                    kind: TYPE_DISCONNECT,
                    flags: FLAG_ACK,
                    ..Default::default()
                }));
            }
            out.push(Output::Closed(key));
        }
    }
}

/// Sequence comparison with 16-bit wrap-around.
fn seq_before(a: u16, b: u16) -> bool {
    (a.wrapping_sub(b) as i16) < 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client(kind: u8, flags: u16, seq: u16, payload: &[u8]) -> Packet {
        Packet {
            source_type: 0xA,
            source_port: 0xF,
            dest_type: 0xA,
            dest_port: 1,
            kind,
            flags,
            seq,
            payload: payload.to_vec(),
            ..Default::default()
        }
    }

    #[test]
    fn header_round_trip() {
        let mut p = client(TYPE_SYN, FLAG_NEED_ACK, 0, b"");
        p.options.push((OPT_SUPPORT, 4u32.to_le_bytes().to_vec()));
        let bytes = p.encode();
        assert_eq!(bytes[..4], [0x80, 6, 0, 0]);
        assert_eq!(bytes[4], 0xAA);
        assert_eq!(decode_all(&[bytes.clone(), bytes].concat()).unwrap(), vec![p.clone(), p]);
    }

    #[test]
    fn handshake_data_fragments_and_disconnect() {
        let mut ep = Endpoint::new();
        let mut out = Vec::new();
        let mut syn = client(TYPE_SYN, FLAG_NEED_ACK, 0, b"");
        syn.options.push((OPT_SUPPORT, 7u32.to_le_bytes().to_vec()));
        ep.handle(syn, [9; 16], &mut out).unwrap();
        let Output::Send(ack) = &out[0] else { panic!() };
        assert_eq!((ack.kind, ack.flags, ack.support()), (TYPE_SYN, FLAG_ACK, Some(5)));
        assert_eq!((ack.dest_port, ack.source_port), (0xF, 1));

        out.clear();
        ep.handle(client(TYPE_CONNECT, FLAG_RELIABLE | FLAG_NEED_ACK, 1, b"hello"), [0; 16], &mut out).unwrap();
        let key = ConnKey { kind: 0xA, port: 0xF };
        assert_eq!(out, vec![Output::Connect { conn: key, payload: b"hello".to_vec() }]);
        let ack = ep.accept(key, vec![1, 2]).unwrap();
        assert_eq!((ack.kind, ack.seq, ack.payload.as_slice()), (TYPE_CONNECT, 1, &[1u8, 2][..]));

        // seq 3 arrives before seq 2: delivered in order once 2 shows up; fragments 1,0 join.
        out.clear();
        let r = FLAG_RELIABLE | FLAG_NEED_ACK;
        ep.handle(client(TYPE_DATA, r, 3, b"B"), [0; 16], &mut out).unwrap();
        let mut first = client(TYPE_DATA, r, 2, b"A");
        first.fragment_id = 1;
        ep.handle(first, [0; 16], &mut out).unwrap();
        ep.handle(client(TYPE_DATA, r, 3, b"B"), [0; 16], &mut out).unwrap(); // duplicate
        let messages: Vec<_> = out
            .iter()
            .filter_map(|o| if let Output::Message { data, .. } = o { Some(data.clone()) } else { None })
            .collect();
        assert_eq!(messages, vec![b"AB".to_vec()]);

        let sent = ep.send(key, &vec![0u8; FRAGMENT_SIZE + 1]);
        assert_eq!(sent.iter().map(|p| (p.seq, p.fragment_id)).collect::<Vec<_>>(), vec![(1, 1), (2, 0)]);

        out.clear();
        ep.handle(client(TYPE_DISCONNECT, r, 4, b""), [0; 16], &mut out).unwrap();
        assert_eq!(out.last(), Some(&Output::Closed(key)));
        assert!(!ep.is_connected(key));
    }

    #[test]
    fn rejects_data_before_connect() {
        let mut ep = Endpoint::new();
        assert!(ep.handle(client(TYPE_DATA, FLAG_RELIABLE, 2, b""), [0; 16], &mut Vec::new()).is_err());
    }
}
