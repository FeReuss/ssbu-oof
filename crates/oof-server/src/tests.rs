//! End-to-end test: a minimal NEX Lite client logs in like the game does (HTTP token, auth server,
//! ticket, secure server) and two players meet through AutoMatchmakeWithParam_Postpone.

use crate::{config::Config, router, state::State};
use futures_util::{SinkExt, StreamExt};
use oof_nex::kerberos;
use oof_nex::prudp::{self, FLAG_ACK, FLAG_HAS_SIZE, FLAG_NEED_ACK, FLAG_RELIABLE, OPT_SUPPORT, Packet};
use oof_nex::rmc::{self, Message, Response};
use oof_nex::stream::{Reader, Writer};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite::{self, client::IntoClientRequest};

type Ws = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn start() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let config = Config {
        listen: addr,
        public_host: "127.0.0.1".into(),
        public_port: addr.port(),
        secret: "11".repeat(32),
        token_ttl_secs: 60,
        nat_check: None,
    };
    let state = Arc::new(State::new(config).unwrap());
    tokio::spawn(async move {
        axum::serve(listener, router(state).into_make_service_with_connect_info::<SocketAddr>()).await.unwrap();
    });
    addr
}

async fn http_post(addr: SocketAddr, path: &str, body: &str) -> serde_json::Value {
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    s.write_all(req.as_bytes()).await.unwrap();
    let mut text = String::new();
    s.read_to_string(&mut text).await.unwrap();
    let (head, json) = text.split_once("\r\n\r\n").unwrap();
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    serde_json::from_str(json).unwrap()
}

struct Client {
    ws: Ws,
    seq: u16,
    call_id: u32,
    notifications: Vec<rmc::Request>,
}

fn packet(kind: u8, flags: u16, seq: u16, payload: Vec<u8>) -> Packet {
    Packet {
        source_type: 0xA,
        source_port: 0xF,
        dest_type: 0xA,
        dest_port: 1,
        kind,
        flags,
        seq,
        payload,
        ..Default::default()
    }
}

impl Client {
    async fn connect(addr: SocketAddr, payload: Vec<u8>) -> (Client, Vec<u8>) {
        let mut req = format!("ws://{addr}/").into_client_request().unwrap();
        req.headers_mut().insert("Sec-WebSocket-Protocol", "NEX".parse().unwrap());
        let (ws, resp) = tokio_tungstenite::connect_async(req).await.unwrap();
        assert_eq!(resp.headers()["sec-websocket-protocol"], "NEX");
        let mut c = Client { ws, seq: 1, call_id: 0, notifications: Vec::new() };
        let mut syn = packet(prudp::TYPE_SYN, FLAG_NEED_ACK, 0, Vec::new());
        syn.options.push((OPT_SUPPORT, 5u32.to_le_bytes().to_vec()));
        c.send(syn).await;
        let ack = c.recv().await;
        assert_eq!((ack.kind, ack.flags), (prudp::TYPE_SYN, FLAG_ACK));
        let mut connect = packet(prudp::TYPE_CONNECT, FLAG_RELIABLE | FLAG_NEED_ACK | FLAG_HAS_SIZE, 1, payload);
        connect.options.push((OPT_SUPPORT, ack.support().unwrap().to_le_bytes().to_vec()));
        c.send(connect).await;
        let ack = c.recv().await;
        assert_eq!((ack.kind, ack.seq), (prudp::TYPE_CONNECT, 1));
        (c, ack.payload)
    }

    async fn send(&mut self, p: Packet) {
        self.ws.send(tungstenite::Message::Binary(p.encode().into())).await.unwrap();
    }

    async fn recv(&mut self) -> Packet {
        loop {
            match self.ws.next().await.unwrap().unwrap() {
                tungstenite::Message::Binary(data) => return prudp::decode_all(&data).unwrap().remove(0),
                _ => continue,
            }
        }
    }

    /// Next complete RMC message from the server, acknowledging DATA as a client must.
    async fn message(&mut self) -> Message {
        let mut buf = Vec::new();
        loop {
            let p = self.recv().await;
            if p.flags & FLAG_ACK != 0 {
                continue;
            }
            let mut ack = packet(p.kind, FLAG_ACK, p.seq, Vec::new());
            ack.fragment_id = p.fragment_id;
            self.send(ack).await;
            buf.extend_from_slice(&p.payload);
            if p.fragment_id == 0 {
                return rmc::decode(&buf).unwrap();
            }
        }
    }

    async fn call(&mut self, protocol: u16, method: u32, body: Vec<u8>) -> Result<Vec<u8>, u32> {
        self.call_id += 1;
        self.seq += 1;
        let msg = rmc::encode_request(protocol, self.call_id, method, &body);
        self.send(packet(prudp::TYPE_DATA, FLAG_RELIABLE | FLAG_NEED_ACK | FLAG_HAS_SIZE, self.seq, msg)).await;
        loop {
            match self.message().await {
                Message::Response(Response::Ok { call_id, method: m, body, .. }) if call_id == self.call_id => {
                    assert_eq!(m, method);
                    return Ok(body);
                }
                Message::Response(Response::Err { call_id, error, .. }) if call_id == self.call_id => {
                    return Err(error);
                }
                Message::Request(n) => self.notifications.push(n),
                other => panic!("unexpected {other:?}"),
            }
        }
    }

    async fn notification(&mut self) -> rmc::Request {
        if !self.notifications.is_empty() {
            return self.notifications.remove(0);
        }
        match self.message().await {
            Message::Request(n) => n,
            other => panic!("expected a notification, got {other:?}"),
        }
    }
}

/// HTTP account + token, auth server ticket, secure server login and Register; returns the client.
async fn login(addr: SocketAddr) -> (Client, u64) {
    let account = http_post(addr, "/v1/accounts", "").await;
    let pid = account["pid"].as_u64().unwrap();
    let token = http_post(
        addr,
        "/v1/token",
        &format!(r#"{{"pid":{pid},"password":"{}"}}"#, account["password"].as_str().unwrap()),
    )
    .await;
    let token = token["id_token"].as_str().unwrap().to_string();

    let (mut auth, _) = Client::connect(addr, Vec::new()).await;
    let mut p = Writer::new();
    p.structure(0, |w| {
        w.u32(3).string(&pid.to_string()).any_data("AuthenticationInfo", |w| {
            w.structure(0, |_| {}).structure(0, |w| {
                w.string(&token).u32(4).u8(2).u32(0);
            });
        });
        w.bool(false).u32(40613).u32(0);
    });
    let result = auth.call(10, 6, p.into_bytes()).await.unwrap();
    let (_, mut r) = Reader::new(&result).structure().unwrap();
    assert_eq!(r.pid().unwrap(), pid);
    let sealed = r.buffer().unwrap().to_vec();
    assert!(r.string().unwrap().starts_with("prudps:/address=127.0.0.1;port="));
    r.u64().unwrap();
    r.string().unwrap();
    let source_key = r.string().unwrap();
    let key: Vec<u8> =
        (0..source_key.len()).step_by(2).map(|i| u8::from_str_radix(&source_key[i..i + 2], 16).unwrap()).collect();

    // What the client does with the ticket (it never sees the server key).
    let plain = kerberos::open(&key, &sealed).unwrap();
    let mut t = Reader::new(&plain);
    let session_key = t.take(32).unwrap().to_vec();
    assert_eq!(t.pid().unwrap(), 2);
    let server_ticket = t.buffer().unwrap().to_vec();
    let mut req = Writer::new();
    req.pid(pid).u32(1).u32(0x1234_5678);
    let mut connect = Writer::new();
    connect.buffer(&server_ticket).buffer(&kerberos::seal(&session_key, &req.into_bytes()));
    let (mut secure, response) = Client::connect(addr, connect.into_bytes()).await;
    let mut r = Reader::new(&response);
    assert_eq!(r.buffer().unwrap(), 0x1234_5679u32.to_le_bytes());

    let mut urls = Writer::new();
    urls.list(&["prudp:/address=192.168.0.2;port=12345;natf=0;natm=0;pmp=0;sid=15;type=2;upnp=0"], |w, u| {
        w.string(u);
    });
    let reg = secure.call(11, 1, urls.into_bytes()).await.unwrap();
    let mut r = Reader::new(&reg);
    assert_eq!(r.u32().unwrap(), rmc::RESULT_SUCCESS);
    r.u32().unwrap();
    let public = r.string().unwrap();
    assert!(public.contains("address=127.0.0.1;port=12345") && public.contains(&format!("PID={pid}")), "{public}");
    (secure, pid)
}

fn auto_matchmake_param() -> Vec<u8> {
    let session = crate::matchmaking::MatchmakeSession {
        game_mode: 21,
        max_participants: 2,
        open_participation: true,
        attribs: vec![0, 4],
        ..Default::default()
    };
    let mut w = Writer::new();
    w.structure(0, |w| {
        session.write(w);
        w.list(&[0u64; 0], |_, _| {}).u32(0).u32(0).string("").u16(1);
        w.list(&[()], |w, _| {
            w.structure(0, |w| {
                w.list(&["", "4"], |w, s| {
                    w.string(s);
                })
                .string("21")
                .string("")
                .string("")
                .string("")
                .bool(true)
                .bool(true)
                .bool(false)
                .u32(0)
                .u16(0);
                w.structure(0, |w| {
                    w.u32(0);
                });
                w.bool(true).bool(true).u32(0).string("");
                w.structure(0, |w| {
                    w.u32(0).u32(10);
                });
            });
        });
        w.list(&[0u32; 0], |_, _| {}).structure(0, |w| {
            w.u32(0);
        });
    });
    w.into_bytes()
}

#[tokio::test]
async fn two_players_meet_in_quickplay() {
    let addr = start().await;
    let (mut a, pid_a) = login(addr).await;
    let (mut b, pid_b) = login(addr).await;

    let first = a.call(109, 40, auto_matchmake_param()).await.unwrap();
    let s1 = crate::matchmaking::MatchmakeSession::read(&mut Reader::new(&first)).unwrap();
    assert_eq!((s1.owner, s1.participation_count, s1.session_key.len()), (pid_a, 1, 32));

    let second = b.call(109, 40, auto_matchmake_param()).await.unwrap();
    let s2 = crate::matchmaking::MatchmakeSession::read(&mut Reader::new(&second)).unwrap();
    assert_eq!((s2.id, s2.participation_count, &s2.session_key), (s1.id, 2, &s1.session_key));

    // The owner hears about the new participant (NotificationEvent 3001).
    let n = a.notification().await;
    assert_eq!((n.protocol, n.method), (14, 1));
    let (_, mut ev) = Reader::new(&n.body).structure().unwrap();
    assert_eq!((ev.pid().unwrap(), ev.u32().unwrap(), ev.u64().unwrap()), (pid_b, 3001, s1.id as u64));

    // The joiner fetches the host's station URLs for the P2P connection.
    let mut gid = Writer::new();
    gid.u32(s1.id);
    let urls = b.call(21, 41, gid.into_bytes()).await.unwrap();
    let urls = Reader::new(&urls).list(|r| r.string()).unwrap();
    assert!(urls[0].contains(&format!("PID={pid_a}")), "{urls:?}");

    // A third method the server lacks answers NotImplemented instead of hanging the client.
    assert_eq!(b.call(201, 9, Vec::new()).await, Err(rmc::errors::CORE_NOT_IMPLEMENTED));

    // Owner leaves: B becomes owner and is told.
    drop(a);
    let n = b.notification().await;
    let (_, mut ev) = Reader::new(&n.body).structure().unwrap();
    assert_eq!((ev.pid().unwrap(), ev.u32().unwrap()), (pid_a, crate::matchmaking::OWNERSHIP_CHANGED));
}

#[tokio::test]
async fn bad_token_is_refused() {
    let addr = start().await;
    let (mut auth, _) = Client::connect(addr, Vec::new()).await;
    let mut p = Writer::new();
    p.structure(0, |w| {
        w.u32(3).string("4294967297").any_data("AuthenticationInfo", |w| {
            w.structure(0, |_| {}).structure(0, |w| {
                w.string("oof1.forged.token").u32(4).u8(2).u32(0);
            });
        });
        w.bool(false).u32(40613).u32(0);
    });
    assert_eq!(auth.call(10, 6, p.into_bytes()).await, Err(rmc::errors::RENDEZVOUS_INVALID_PASSWORD));
}
