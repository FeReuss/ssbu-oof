//! End-to-end test: a minimal NEX Lite client logs in like the game does (HTTP token, auth server,
//! ticket, secure server) and two players meet through AutoMatchmakeWithParam_Postpone.

use crate::{config::Config, router, state::State};
use futures_util::{SinkExt, StreamExt};
use oof_nex::kerberos;
use oof_nex::prudp::{self, FLAG_ACK, FLAG_HAS_SIZE, FLAG_NEED_ACK, FLAG_RELIABLE, OPT_SUPPORT, Packet};
use oof_nex::rmc::{self, Message, Response};
use oof_nex::stream::{DateTime, Reader, Writer};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite::{self, client::IntoClientRequest};

type Ws = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

fn test_config(addr: SocketAddr) -> Config {
    Config {
        listen: addr,
        public_host: "127.0.0.1".into(),
        public_port: addr.port(),
        secret: "11".repeat(32),
        token_ttl_secs: 60,
        nat_check: None,
        trust_client_address: false,
        database: None,
        events: Vec::new(),
        integer_settings: Default::default(),
    }
}

async fn start() -> SocketAddr {
    start_with(|_| {}).await
}

async fn start_with(edit: impl FnOnce(&mut Config)) -> SocketAddr {
    start_state(edit).await.0
}

async fn start_state(edit: impl FnOnce(&mut Config)) -> (SocketAddr, Arc<State>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mut config = test_config(addr);
    edit(&mut config);
    let state = Arc::new(State::new(config).unwrap());
    let served = state.clone();
    tokio::spawn(async move {
        axum::serve(listener, router(served).into_make_service_with_connect_info::<SocketAddr>()).await.unwrap();
    });
    (addr, state)
}

async fn http_post(addr: SocketAddr, path: &str, body: &str) -> serde_json::Value {
    http(addr, "POST", path, body).await
}

async fn http(addr: SocketAddr, method: &str, path: &str, body: &str) -> serde_json::Value {
    let (code, json) = http_status(addr, method, path, body).await;
    assert!((200..300).contains(&code), "{code} {json}");
    json
}

async fn http_status(addr: SocketAddr, method: &str, path: &str, body: &str) -> (u16, serde_json::Value) {
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    s.write_all(req.as_bytes()).await.unwrap();
    let mut text = String::new();
    s.read_to_string(&mut text).await.unwrap();
    let (head, json) = text.split_once("\r\n\r\n").unwrap();
    let code = head[9..12].parse().unwrap();
    (code, if json.is_empty() { serde_json::Value::Null } else { serde_json::from_str(json).unwrap() })
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

/// A registered account logged in on one device: (pid, user name, device key).
async fn new_account(addr: SocketAddr) -> (u64, String, String) {
    let name = format!("p{:08x}", u32::from_le_bytes(crate::accounts::random_bytes()));
    let credentials = format!(r#"{{"username":"{name}","password":"password1","device":"test"}}"#);
    let pid = http_post(addr, "/v1/accounts", &credentials).await["pid"].as_u64().unwrap();
    let login = http_post(addr, "/v1/login", &credentials).await;
    assert_eq!((login["pid"].as_u64(), login["username"].as_str()), (Some(pid), Some(name.as_str())));
    (pid, name, login["device_key"].as_str().unwrap().to_string())
}

async fn id_token(addr: SocketAddr, pid: u64, device_key: &str) -> String {
    let token = http_post(addr, "/v1/token", &format!(r#"{{"pid":{pid},"device_key":"{device_key}"}}"#)).await;
    token["id_token"].as_str().unwrap().to_string()
}

/// NEX Ticket Granting 6 (ValidateAndRequestTicketWithParam) with an ID token.
fn ticket_request(pid: u64, token: &str) -> Vec<u8> {
    let mut p = Writer::new();
    p.structure(0, |w| {
        w.u32(3).string(&pid.to_string()).any_data("AuthenticationInfo", |w| {
            w.structure(0, |_| {}).structure(0, |w| {
                w.string(token).u32(4).u8(2).u32(0);
            });
        });
        w.bool(false).u32(40613).u32(0);
    });
    p.into_bytes()
}

/// HTTP account + token, auth server ticket, secure server login and Register; returns the client.
async fn login(addr: SocketAddr) -> (Client, u64) {
    let (pid, _, key) = new_account(addr).await;
    let token = id_token(addr, pid, &key).await;
    nex_login(addr, pid, &token).await
}

async fn nex_login(addr: SocketAddr, pid: u64, token: &str) -> (Client, u64) {
    let (mut auth, _) = Client::connect(addr, Vec::new()).await;
    let result = auth.call(10, 6, ticket_request(pid, token)).await.unwrap();
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
    // 13.0.5 registers two placeholder URLs (ports 1 and 2) and no `type`
    let placeholders = [
        "prudp:/address=192.168.0.2;port=1;Pl=3;Tpt=2;natf=0;natm=0;pmp=0;sid=30;upnp=0",
        "prudp:/address=192.168.0.2;port=2;Pl=3;Tpt=2;natf=0;natm=0;pmp=0;sid=30;upnp=0",
    ];
    urls.list(&placeholders, |w, u| {
        w.string(u);
    });
    let reg = secure.call(11, 1, urls.into_bytes()).await.unwrap();
    let mut r = Reader::new(&reg);
    assert_eq!(r.u32().unwrap(), rmc::RESULT_SUCCESS);
    r.u32().unwrap();
    let public = r.string().unwrap();
    assert!(
        public.contains("address=127.0.0.1;port=1;")
            && public.contains("type=3")
            && public.contains(&format!("PID={pid}")),
        "{public}"
    );
    (secure, pid)
}

fn auto_matchmake_param(group: u32) -> Vec<u8> {
    let session = crate::matchmaking::MatchmakeSession {
        game_mode: 1,
        max_participants: 2,
        open_participation: true,
        attribs: vec![group, 4],
        ..Default::default()
    };
    let mut w = Writer::new();
    w.structure(0, |w| {
        session.write(w);
        w.list(&[0u64; 0], |_, _| {}).u32(0).u32(0).string("").u16(1);
        w.list(&[()], |w, _| {
            w.structure(0, |w| {
                w.list(&[group.to_string(), "4".into()], |w, s| {
                    w.string(s);
                })
                .string("1")
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

    // The game calls method 58 before creating a gathering; it must not require one.
    for mode in [1u32, 2, 3, 5, 7, 13] {
        assert_eq!(a.call(109, 58, mode.to_le_bytes().to_vec()).await.unwrap(), mode.to_le_bytes());
    }
    for mode in [0u32, 4, 6, 8, 12, 14, 32, u32::MAX] {
        assert_eq!(a.call(109, 58, mode.to_le_bytes().to_vec()).await, Err(rmc::errors::CORE_INVALID_ARGUMENT));
    }
    assert_eq!(a.call(109, 58, vec![1, 0, 0, 0, 0]).await, Err(rmc::errors::CORE_INVALID_ARGUMENT));
    for size in 0..4 {
        assert_eq!(a.call(109, 58, vec![0; size]).await, Err(rmc::errors::CORE_INVALID_ARGUMENT));
    }

    let first = a.call(109, 40, auto_matchmake_param(1)).await.unwrap();
    let s1 = crate::matchmaking::MatchmakeSession::read(&mut Reader::new(&first)).unwrap();
    assert_eq!((s1.owner, s1.participation_count, s1.session_key.len()), (pid_a, 1, 32));

    let second = b.call(109, 40, auto_matchmake_param(1)).await.unwrap();
    let s2 = crate::matchmaking::MatchmakeSession::read(&mut Reader::new(&second)).unwrap();
    assert_eq!((s2.id, s2.participation_count, &s2.session_key), (s1.id, 2, &s1.session_key));

    // NotificationEvent 3001 {gathering, participant}: the owner hears about itself, then the new
    // participant; the joiner hears about itself (Pia waits for its own before going P2P).
    let joined = |n: rmc::Request| {
        assert_eq!((n.protocol, n.method), (14, 1));
        let (_, mut ev) = Reader::new(&n.body).structure().unwrap();
        (ev.pid().unwrap(), ev.u32().unwrap(), ev.u64().unwrap(), ev.u64().unwrap())
    };
    assert_eq!(joined(a.notification().await), (pid_a, 3001, s1.id as u64, pid_a));
    assert_eq!(joined(a.notification().await), (pid_b, 3001, s1.id as u64, pid_b));
    assert_eq!(joined(b.notification().await), (pid_b, 3001, s1.id as u64, pid_b));
    // ...and about the participants already there (Pia connects only to stations it saw join)
    assert_eq!(joined(b.notification().await), (pid_a, 3001, s1.id as u64, pid_a));

    // The joiner fetches the host's station URLs for the P2P connection while the host is still in its NAT
    // check: the answer waits for the host's ReplaceURL (the URL with the Pia CID), well before the 10 s limit.
    let mut gid = Writer::new();
    gid.u32(s1.id);
    let mut replace = Writer::new();
    replace
        .string("prudp:/address=192.168.0.2;port=2;Pl=3;Tpt=2;natf=0;natm=0;pmp=0;sid=30;upnp=0")
        .string("prudp:/address=192.168.0.2;port=50000;CID=77;Pl=3;Tpt=2;natf=17;natm=1;pmp=0;sid=30;upnp=0");
    let (urls, replaced) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        tokio::join!(b.call(21, 41, gid.into_bytes()), async {
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            a.call(11, 7, replace.into_bytes()).await
        })
    })
    .await
    .expect("GetSessionURLs answered once the host's station is final");
    assert!(replaced.unwrap().is_empty());
    let urls = Reader::new(&urls.unwrap()).list(|r| r.string()).unwrap();
    assert!(urls[0].contains(&format!("PID={pid_a}")), "{urls:?}");
    // Pia's parser takes at most two URLs, one public (main+0xc2460): the public one and the replaced one
    assert_eq!(urls.len(), 2, "{urls:?}");
    assert!(urls[0].contains("type=3") && urls[1].contains("CID=77") && !urls[1].contains("type="), "{urls:?}");

    // A third method the server lacks answers NotImplemented instead of hanging the client.
    assert_eq!(b.call(120, 1, Vec::new()).await, Err(rmc::errors::CORE_NOT_IMPLEMENTED));

    // Owner leaves: B becomes owner and is told.
    drop(a);
    let n = b.notification().await;
    let (_, mut ev) = Reader::new(&n.body).structure().unwrap();
    assert_eq!((ev.pid().unwrap(), ev.u32().unwrap()), (pid_a, crate::matchmaking::OWNERSHIP_CHANGED));
}

#[tokio::test]
async fn matchmaking_groups_separate_queues_with_the_same_game_mode() {
    let addr = start().await;
    let (mut a, _) = login(addr).await;
    let (mut b, _) = login(addr).await;
    let (mut c, _) = login(addr).await;
    let group_a = a.call(109, 58, 1u32.to_le_bytes().to_vec()).await.unwrap();
    let group_b = b.call(109, 58, 3u32.to_le_bytes().to_vec()).await.unwrap();
    let group_c = c.call(109, 58, 1u32.to_le_bytes().to_vec()).await.unwrap();
    let group_a = Reader::new(&group_a).u32().unwrap();
    let group_b = Reader::new(&group_b).u32().unwrap();
    let group_c = Reader::new(&group_c).u32().unwrap();
    assert_ne!(group_a, group_b);
    assert_eq!(group_a, group_c);
    let first = a.call(109, 40, auto_matchmake_param(group_a)).await.unwrap();
    let second = b.call(109, 40, auto_matchmake_param(group_b)).await.unwrap();
    let third = c.call(109, 40, auto_matchmake_param(group_c)).await.unwrap();
    let first = crate::matchmaking::MatchmakeSession::read(&mut Reader::new(&first)).unwrap();
    let second = crate::matchmaking::MatchmakeSession::read(&mut Reader::new(&second)).unwrap();
    let third = crate::matchmaking::MatchmakeSession::read(&mut Reader::new(&third)).unwrap();
    assert_eq!(first.game_mode, second.game_mode);
    assert_ne!(first.id, second.id);
    assert_eq!(first.id, third.id);
    assert_eq!((second.participation_count, third.participation_count), (1, 2));
}

#[tokio::test]
async fn login_datastore_calls_succeed() {
    let addr = start().await;
    let (mut c, _) = login(addr).await;
    assert_eq!(c.call(115, 61, Vec::new()).await.unwrap(), 0u32.to_le_bytes());
    assert_eq!(c.call(115, 60, Vec::new()).await.unwrap(), 0u32.to_le_bytes());
    let r84 = c.call(115, 84, Vec::new()).await.unwrap();
    let mut r = Reader::new(&r84);
    assert_eq!(r.u32().unwrap(), 0);
    let (_, mut s) = r.structure().unwrap();
    assert_eq!((s.u32().unwrap(), s.u32().unwrap(), s.u32().unwrap(), s.u64().unwrap()), (0, 0, 0, 0));
    let r95 = c.call(115, 95, Vec::new()).await.unwrap();
    assert!(!Reader::new(&r95).structure().unwrap().1.bool().unwrap());

    // Same shape and size (60 bytes) as the game's call; the strings are placeholders.
    let mut p = Writer::new();
    p.structure(0, |w| {
        w.u8(1).structure(0, |w| {
            w.string("aaaaaaaaaa");
        });
        w.structure(0, |w| {
            w.string("bbbbbbb").string("cccc").string("dddd").string("eeee");
        });
    });
    let body = p.into_bytes();
    assert_eq!(body.len(), 60);
    assert_eq!(c.call(115, 83, body).await.unwrap(), Vec::<u8>::new());
    assert_eq!(c.call(115, 83, vec![0]).await, Err(rmc::errors::CORE_INVALID_ARGUMENT));

    // 82: same size as the game's call (30 bytes), empty result.
    let mut p = Writer::new();
    p.structure(0, |w| {
        w.u8(1).u32(2).u32(3).u32(4).u64(5).u32(6);
    });
    let body = p.into_bytes();
    assert_eq!(body.len(), 30);
    assert!(c.call(115, 82, body.clone()).await.unwrap().is_empty());
    assert_eq!(c.call(115, 82, body[..29].to_vec()).await, Err(rmc::errors::CORE_INVALID_ARGUMENT));
}

#[tokio::test]
async fn quickplay_eligibility_calls_succeed_and_reject_truncated_fields() {
    let addr = start().await;
    let (mut c, _) = login(addr).await;
    // Exact bytes reported by the port for DataStore 94.
    let flags = vec![0, 2, 0, 0, 0, 1, 1];
    assert!(c.call(115, 94, flags).await.unwrap().is_empty());

    let mut query = Writer::new();
    query.structure(0, |w| {
        w.u32(6).u32(3).string("US");
    });
    let query = query.into_bytes();
    assert_eq!(query.len(), 18);
    let eligibility = c.call(110, 9, query).await.unwrap();
    let mut reply = Reader::new(&eligibility);
    let (version, mut data) = reply.structure().unwrap();
    assert_eq!(version, 0);
    assert_eq!((data.u32().unwrap(), data.u32().unwrap(), data.u32().unwrap()), (0, 0, 0));
    assert_eq!((data.remaining(), reply.remaining()), (0, 0));

    let mut query = Writer::new();
    query.structure(0, |w| {
        w.bytes(&eligibility).i32(-1);
    });
    let restriction = c.call(110, 10, query.into_bytes()).await.unwrap();
    let mut reply = Reader::new(&restriction);
    let (version, mut data) = reply.structure().unwrap();
    assert_eq!(version, 0);
    assert!(!data.bool().unwrap());
    assert_eq!(data.u32().unwrap(), 0);
    assert_eq!((data.remaining(), reply.remaining()), (0, 0));

    // Valid outer headers with missing required fields must fail too.
    for (protocol, method) in [(115, 94), (110, 9), (110, 10)] {
        let mut empty = Writer::new();
        empty.structure(0, |_| {});
        assert_eq!(c.call(protocol, method, empty.into_bytes()).await, Err(rmc::errors::CORE_INVALID_ARGUMENT));
        assert_eq!(c.call(protocol, method, vec![0]).await, Err(rmc::errors::CORE_INVALID_ARGUMENT));
    }
    let mut missing_sentinel = Writer::new();
    missing_sentinel.structure(0, |w| {
        w.bytes(&eligibility);
    });
    assert_eq!(c.call(110, 10, missing_sentinel.into_bytes()).await, Err(rmc::errors::CORE_INVALID_ARGUMENT));
}

#[tokio::test]
async fn datastore_get_meta_reports_absent_objects_and_rejects_truncation() {
    let addr = start().await;
    let (mut c, pid) = login(addr).await;
    // Persistent slot lookup seen before Quickplay (37 bytes); also cover a direct object lookup.
    for (data_id, owner, slot) in [(0, pid, 10), (1234, 0, 0)] {
        let mut query = Writer::new();
        query.structure(0, |w| {
            w.u64(data_id).structure(0, |w| {
                w.pid(owner).u16(slot);
            });
            w.u8(4).u64(0);
        });
        let query = query.into_bytes();
        assert_eq!(query.len(), 37);
        assert_eq!(c.call(115, 8, query.clone()).await, Err(rmc::errors::DATASTORE_NOT_FOUND));
        // Every truncated prefix must be rejected, even when outer lengths are adjusted.
        for end in 0..query.len() {
            let mut truncated = query[..end].to_vec();
            if end >= 5 {
                truncated[1..5].copy_from_slice(&((end - 5) as u32).to_le_bytes());
            }
            assert_eq!(c.call(115, 8, truncated).await, Err(rmc::errors::CORE_INVALID_ARGUMENT));
        }
    }
    // A valid failure leaves the session usable.
    assert_eq!(c.call(115, 61, Vec::new()).await.unwrap(), 0u32.to_le_bytes());
}

fn get_meta(data_id: u64, owner: u64, slot: u16) -> Vec<u8> {
    let mut query = Writer::new();
    query.structure(0, |w| {
        w.u64(data_id).structure(0, |w| {
            w.pid(owner).u16(slot);
        });
        w.u8(4).u64(0);
    });
    query.into_bytes()
}

#[tokio::test]
async fn datastore_post_meta_binary_is_read_back_by_id_and_slot() {
    let addr = start().await;
    let (mut a, pid_a) = login(addr).await;
    let (mut b, _) = login(addr).await;
    // DataStorePreparePostParam in the order of the game's method-21 serializer.
    let post = |permission: u8, slot: u16| {
        let mut p = Writer::new();
        p.structure(0, |w| {
            w.u32(0).string("match").u16(7).qbuffer(&[1, 2, 3, 4]);
            w.structure(0, |w| {
                w.u8(permission).u32(0);
            });
            w.structure(0, |w| {
                w.u8(3).u32(0);
            });
            w.u32(0).u16(90).u32(0).list(&["t"], |w, t| {
                w.string(t);
            });
            w.u32(0).structure(0, |w| {
                w.u16(slot).bool(true);
            });
            w.u32(0);
        });
        p.into_bytes()
    };
    let public = post(0, 3);
    let id = u64::from_le_bytes(a.call(115, 21, public.clone()).await.unwrap().try_into().unwrap());
    assert_ne!(id, 0);
    for meta in
        [b.call(115, 8, get_meta(id, 0, 0)).await.unwrap(), b.call(115, 8, get_meta(0, pid_a, 3)).await.unwrap()]
    {
        let (_, mut m) = Reader::new(&meta).structure().unwrap();
        assert_eq!((m.u64().unwrap(), m.pid().unwrap(), m.u32().unwrap()), (id, pid_a, 0));
        assert_eq!(
            (m.string().unwrap(), m.u16().unwrap(), m.qbuffer().unwrap()),
            ("match".into(), 7, &[1u8, 2, 3, 4][..])
        );
        assert_eq!(m.structure().unwrap().1.u8().unwrap(), 0);
        assert_eq!(m.structure().unwrap().1.u8().unwrap(), 3);
        let created = m.u64().unwrap();
        assert_eq!(m.u64().unwrap(), created);
        assert_eq!(m.u16().unwrap(), 90);
        let (_status, _referred, _refer, _flag, _referred_time) = (m.u8(), m.u32(), m.u32(), m.u32(), m.u64());
        assert_eq!(DateTime(m.u64().unwrap()).to_unix() - DateTime(created).to_unix(), 90 * 86_400);
        assert_eq!(m.list(|r| r.string()).unwrap(), vec!["t".to_string()]);
        assert_eq!(m.u32().unwrap(), 0);
        assert_eq!(m.remaining(), 0);
    }
    // A private object is visible to its owner only; truncated posts are refused and store nothing.
    let private = u64::from_le_bytes(a.call(115, 21, post(3, 0xffff)).await.unwrap().try_into().unwrap());
    assert!(a.call(115, 8, get_meta(private, 0, 0)).await.is_ok());
    assert_eq!(b.call(115, 8, get_meta(private, 0, 0)).await, Err(rmc::errors::DATASTORE_NOT_FOUND));
    let mut truncated = public[..public.len() - 4].to_vec();
    let inner = (truncated.len() - 5) as u32;
    truncated[1..5].copy_from_slice(&inner.to_le_bytes());
    assert_eq!(a.call(115, 21, truncated).await, Err(rmc::errors::CORE_INVALID_ARGUMENT));
    assert!(b.call(115, 8, get_meta(0, pid_a, 3)).await.is_ok(), "a refused post replaced the slot");

    // ChangeMeta (38), in the order of the game's serializer: by data ID, then by persistence target (data ID 0).
    let change = |data_id: u64, flag: u32, meta: &[u8], owner: u64, slot: u16| {
        let mut p = Writer::new();
        p.structure(0, |w| {
            w.u64(data_id).u32(flag).string("ignored");
            for kind in [0u8, 3] {
                w.structure(0, |w| {
                    w.u8(kind).u32(0);
                });
            }
            w.u16(30).qbuffer(meta).u32(0).u64(0).u32(0).u16(99).u8(0);
            w.structure(0, |w| {
                w.u32(0).string("").structure(0, |w| {
                    w.u8(0).u32(0);
                });
                w.structure(0, |w| {
                    w.u8(0).u32(0);
                });
                w.u16(0).qbuffer(&[]).u32(0).u32(0).u16(0).u8(0);
            });
            w.structure(0, |w| {
                w.pid(owner).u16(slot);
            });
        });
        p.into_bytes()
    };
    let read_meta = |meta: Vec<u8>| {
        let (_, mut m) = Reader::new(&meta).structure().unwrap();
        let (_, _, _, name, data_type) = (m.u64(), m.pid(), m.u32(), m.string().unwrap(), m.u16().unwrap());
        (name, data_type, m.qbuffer().unwrap().to_vec())
    };
    assert!(a.call(115, 38, change(id, 0x10, &[5, 6], 0, 0)).await.unwrap().is_empty());
    assert_eq!(read_meta(b.call(115, 8, get_meta(id, 0, 0)).await.unwrap()), ("match".into(), 7, vec![5, 6]));
    assert!(a.call(115, 38, change(0, 0x10 | 0x80, &[7], pid_a, 3)).await.unwrap().is_empty());
    assert_eq!(read_meta(b.call(115, 8, get_meta(0, pid_a, 3)).await.unwrap()), ("match".into(), 99, vec![7]));
    assert_eq!(b.call(115, 38, change(id, 0x10, &[0], 0, 0)).await, Err(rmc::errors::DATASTORE_NOT_FOUND));
    let full = change(id, 0x10, &[8], 0, 0);
    let mut truncated = full[..full.len() - 2].to_vec();
    let inner = (truncated.len() - 5) as u32;
    truncated[1..5].copy_from_slice(&inner.to_le_bytes());
    assert_eq!(a.call(115, 38, truncated).await, Err(rmc::errors::CORE_INVALID_ARGUMENT));
    assert_eq!(read_meta(b.call(115, 8, get_meta(id, 0, 0)).await.unwrap()).2, vec![7], "refused changes applied");
}

#[tokio::test]
async fn accounts_identify_players_and_bans_hold() {
    let (addr, state) = start_state(|_| {}).await;
    let post = |path: &'static str, body: String| async move { http_status(addr, "POST", path, &body).await };
    // Registration: valid user names only, unique without regard to case, passwords of 8+ characters.
    assert_eq!(post("/v1/accounts", r#"{"username":"Ana.1","password":"secret-pw"}"#.into()).await.0, 201);
    assert_eq!(post("/v1/accounts", r#"{"username":"ana.1","password":"secret-pw"}"#.into()).await.0, 409);
    for bad in [
        r#"{"username":"ab","password":"secret-pw"}"#,
        r#"{"username":"elevenchars","password":"secret-pw"}"#,
        r#"{"username":"a b","password":"secret-pw"}"#,
        r#"{"username":"Bea","password":"short"}"#,
    ] {
        assert_eq!(post("/v1/accounts", bad.into()).await.0, 400, "{bad}");
    }
    // Login: wrong password refused; the device key (not the password) buys ID tokens that name the account.
    assert_eq!(post("/v1/login", r#"{"username":"ANA.1","password":"wrong-pw!"}"#.into()).await.0, 401);
    assert_eq!(post("/v1/login", r#"{"username":"nobody","password":"secret-pw"}"#.into()).await.0, 401);
    let (code, login) = post("/v1/login", r#"{"username":"ana.1","password":"secret-pw","device":"Mac"}"#.into()).await;
    assert_eq!((code, login["username"].as_str()), (200, Some("Ana.1")));
    let (pid, key) = (login["pid"].as_u64().unwrap(), login["device_key"].as_str().unwrap().to_string());
    let device = format!(r#"{{"pid":{pid},"device_key":"{key}"}}"#);
    let (code, token) = post("/v1/token", device.clone()).await;
    assert_eq!(
        (code, token["username"].as_str(), token["nex_username"].as_str()),
        (200, Some("Ana.1"), Some(&*pid.to_string()))
    );
    assert_eq!(post("/v1/token", format!(r#"{{"pid":{pid},"device_key":"00"}}"#)).await.0, 401);
    assert!(
        state.accounts.lock().unwrap().find("ana.1").unwrap().unwrap().last_address.is_some(),
        "login not recorded"
    );

    // A connected player who gets banned is disconnected, gets no token, and an earlier token no longer logs in.
    let earlier = token["id_token"].as_str().unwrap().to_string();
    let (mut secure, _) = nex_login(addr, pid, &earlier).await;
    state.accounts.lock().unwrap().set_ban(pid, None, "cheating").unwrap();
    assert_eq!(crate::state::kick_banned(&state), 1);
    let closed =
        tokio::time::timeout(std::time::Duration::from_secs(5), secure.ws.next()).await.expect("still connected");
    assert!(!matches!(closed, Some(Ok(tungstenite::Message::Binary(_)))), "{closed:?}");
    let (code, refused) = post("/v1/token", device.clone()).await;
    assert_eq!((code, refused["error"].as_str(), refused["reason"].as_str()), (403, Some("banned"), Some("cheating")));
    assert_eq!(post("/v1/login", r#"{"username":"Ana.1","password":"secret-pw"}"#.into()).await.0, 403);
    let (mut auth, _) = Client::connect(addr, Vec::new()).await;
    assert_eq!(auth.call(10, 6, ticket_request(pid, &earlier)).await, Err(rmc::errors::RENDEZVOUS_ACCOUNT_DISABLED));
    state.accounts.lock().unwrap().unban(pid).unwrap();
    assert_eq!(post("/v1/token", device.clone()).await.0, 200);

    // Protection: a password change logs every device out; logout forgets one device.
    let change = r#"{"username":"Ana.1","password":"secret-pw","new_password":"another-pw"}"#;
    assert_eq!(post("/v1/password", change.into()).await.0, 204);
    assert_eq!(post("/v1/token", device).await.0, 401);
    let (code, again) = post("/v1/login", r#"{"username":"Ana.1","password":"another-pw"}"#.into()).await;
    assert_eq!(code, 200);
    let fresh = format!(r#"{{"pid":{pid},"device_key":"{}"}}"#, again["device_key"].as_str().unwrap());
    assert_eq!(post("/v1/logout", fresh.clone()).await.0, 204);
    assert_eq!(post("/v1/token", fresh).await.0, 401);
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

/// Pia needs nncs1 and nncs2 on different addresses (`main+0xc6590`); the port learns them here.
#[tokio::test]
async fn status_announces_nat_check_addresses() {
    let addr = start().await;
    assert!(http(addr, "GET", "/v1/status", "").await["nat_check"].is_null());
    let addr = start_with(|c| {
        c.nat_check = Some(crate::config::NatCheck {
            primary: "203.0.113.1".parse().unwrap(),
            secondary: "203.0.113.2".parse().unwrap(),
        })
    })
    .await;
    let status = http(addr, "GET", "/v1/status", "").await;
    assert_eq!(status["nat_check"], serde_json::json!({ "primary": "203.0.113.1", "secondary": "203.0.113.2" }));
}

#[test]
fn nat_check_needs_two_addresses() {
    let mut config = test_config("127.0.0.1:1".parse().unwrap());
    for (a, b) in [("127.0.0.1", "127.0.0.1"), ("0.0.0.0", "127.0.0.1")] {
        config.nat_check = Some(crate::config::NatCheck { primary: a.parse().unwrap(), secondary: b.parse().unwrap() });
        assert!(State::new(config.clone()).is_err(), "{a} {b}");
    }
}

/// After its NAT check Pia replaces its local station URL with one carrying the NAT properties
/// (Secure Connection 7); peers must then get the new one.
#[tokio::test]
async fn replace_url_updates_the_registered_station() {
    let addr = start().await;
    let (mut secure, pid) = login(addr).await;
    let mut w = Writer::new();
    w.string("prudp:/address=192.168.0.2;port=2;Pl=3;Tpt=2;natf=0;natm=0;pmp=0;sid=30;upnp=0")
        .string("prudp:/address=192.168.0.2;port=50000;CID=77;Pl=3;Tpt=2;natf=1;natm=1;pmp=0;sid=30;upnp=0");
    assert!(secure.call(11, 7, w.into_bytes()).await.unwrap().is_empty());
    let mut w = Writer::new();
    w.u32(0).pid(pid);
    let reply = secure.call(11, 3, w.into_bytes()).await.unwrap();
    let mut r = Reader::new(&reply);
    assert!(r.bool().unwrap());
    let urls = r.list(|r| r.string()).unwrap();
    assert_eq!(urls.len(), 2, "{urls:?}"); // public + replaced local, not the port=1 placeholder
    assert!(urls[1].contains("natf=1;natm=1") && urls[1].contains(&format!("PID={pid}")), "{urls:?}");
    assert!(!urls.iter().any(|u| u.contains("192.168.0.2;port=1;") || u.contains("192.168.0.2;port=2;")), "{urls:?}");
    assert!(
        urls[0].contains("type=3") && urls[0].contains("natf=1") && urls[0].contains("natm=1"),
        "public URL keeps the NAT properties: {urls:?}"
    );
}
