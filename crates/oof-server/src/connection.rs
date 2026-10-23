//! One client WebSocket: PRUDP Lite virtual connections, login, RMC dispatch and the calls other
//! players' actions queue for this client. Each socket is one task; shared state lives in `State`.

use crate::protocols::{self, Ctx};
use crate::state::{Call, Session, State};
use axum::extract::ws::{Message, WebSocket};
use oof_nex::kerberos::{self, ServerTicket};
use oof_nex::prudp::{self, ConnKey, Endpoint, Output};
use oof_nex::rmc;
use oof_nex::stream::{DateTime, Reader, Writer};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

/// Tickets older than this are refused at the secure-server CONNECT.
const TICKET_MAX_AGE_SECS: u64 = 300;
/// A client that sends nothing (not even a PING) for this long is dropped.
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

struct Conn {
    pid: Option<u64>,
    cid: u32,
    auth_pid: Option<u64>,
}

pub async fn serve(mut socket: WebSocket, peer: SocketAddr, state: Arc<State>) {
    let (tx, mut rx) = mpsc::unbounded_channel::<Call>();
    let mut endpoint = Endpoint::new();
    let mut conns: HashMap<ConnKey, Conn> = HashMap::new();
    let mut call_id: u32 = 0;
    loop {
        let mut out = Vec::new();
        tokio::select! {
            msg = tokio::time::timeout(IDLE_TIMEOUT, socket.recv()) => {
                let data = match msg {
                    Ok(Some(Ok(Message::Binary(data)))) => data,
                    Ok(Some(Ok(Message::Ping(_) | Message::Pong(_)))) => continue,
                    Ok(Some(Ok(Message::Text(_)))) => { tracing::debug!(%peer, "text frame ignored"); continue }
                    _ => break, // closed, error or idle
                };
                let packets = match prudp::decode_all(&data) {
                    Ok(p) => p,
                    Err(e) => { tracing::debug!(%peer, %e, "bad PRUDP packet"); break }
                };
                for p in packets {
                    if let Err(e) = endpoint.handle(p, crate::accounts::random_bytes(), &mut out) {
                        tracing::debug!(%peer, %e, "PRUDP protocol error");
                    }
                }
            }
            Some(call) = rx.recv() => {
                // Server-initiated call: goes to this socket's secure connection.
                if let Some((key, _)) = conns.iter().find(|(_, c)| c.pid.is_some()) {
                    call_id = call_id.wrapping_add(1);
                    let msg = rmc::encode_request(call.protocol, call_id, call.method, &call.body);
                    out.extend(endpoint.send(*key, &msg).into_iter().map(Output::Send));
                }
            }
        }
        // Outputs can produce more outputs (a CONNECT turns into an ACK), so drain in a loop.
        let mut i = 0;
        while i < out.len() {
            match std::mem::replace(&mut out[i], Output::Closed(ConnKey { kind: 0, port: 0 })) {
                Output::Send(p) => {
                    if socket.send(Message::Binary(p.encode().into())).await.is_err() {
                        return finish(&state, &conns);
                    }
                }
                Output::Connect { conn, payload } => match login(&state, &payload, &tx) {
                    Ok((c, response)) => {
                        if let Some(old) = conns.insert(conn, c) {
                            drop_session(&state, &old);
                        }
                        if let Some(ack) = endpoint.accept(conn, response) {
                            out.push(Output::Send(ack));
                        }
                    }
                    Err(e) => tracing::info!(%peer, e, "secure login refused"),
                },
                Output::Message { conn, data } => {
                    let Some(c) = conns.get_mut(&conn) else { continue };
                    match rmc::decode(&data) {
                        Ok(rmc::Message::Request(req)) => {
                            let mut ctx = Ctx { state: &state, peer, pid: c.pid, cid: c.cid, auth_pid: c.auth_pid };
                            let reply = protocols::dispatch(&mut ctx, &req);
                            c.auth_pid = ctx.auth_pid;
                            out.extend(endpoint.send(conn, &reply).into_iter().map(Output::Send));
                        }
                        Ok(rmc::Message::Response(_)) => {} // acknowledgement of a notification
                        Err(e) => tracing::debug!(%peer, %e, "bad RMC message"),
                    }
                }
                Output::Closed(conn) => {
                    if let Some(c) = conns.remove(&conn) {
                        drop_session(&state, &c);
                    }
                }
            }
            i += 1;
        }
    }
    finish(&state, &conns);
}

/// CONNECT payload: empty on the authentication server; `Buffer ticket | Buffer sealed(pid, cid,
/// check)` on the secure server, answered with `Buffer(u32 check + 1)`.
fn login(
    state: &Arc<State>,
    payload: &[u8],
    tx: &mpsc::UnboundedSender<Call>,
) -> Result<(Conn, Vec<u8>), &'static str> {
    if payload.is_empty() {
        return Ok((Conn { pid: None, cid: 0, auth_pid: None }, Vec::new()));
    }
    let mut r = Reader::new(payload);
    let ticket = r.buffer().map_err(|_| "malformed CONNECT")?;
    let sealed = r.buffer().map_err(|_| "malformed CONNECT")?;
    let ticket = ServerTicket::decrypt(ticket, &state.kerberos_key).map_err(|_| "ticket does not verify")?;
    let age = DateTime::now().to_unix().saturating_sub(ticket.issued.to_unix());
    if age > TICKET_MAX_AGE_SECS {
        return Err("ticket expired");
    }
    let plain = kerberos::open(&ticket.session_key, sealed).map_err(|_| "request does not verify")?;
    let mut r = Reader::new(&plain);
    let (pid, _client_cid, check) = (r.pid(), r.u32(), r.u32());
    let (Ok(pid), Ok(check)) = (pid, check) else { return Err("short request") };
    if pid != ticket.source_pid {
        return Err("ticket belongs to another PID");
    }
    let cid = state.new_cid();
    let previous =
        state.sessions.write().expect("sessions lock").insert(pid, Session { cid, tx: tx.clone(), urls: Vec::new() });
    if previous.is_some() {
        tracing::info!(pid, "replaced an older session of the same player");
    }
    tracing::info!(pid, cid, "secure connection");
    let mut w = Writer::new();
    w.buffer(&check.wrapping_add(1).to_le_bytes());
    Ok((Conn { pid: Some(pid), cid, auth_pid: None }, w.into_bytes()))
}

fn drop_session(state: &Arc<State>, c: &Conn) {
    let Some(pid) = c.pid else { return };
    {
        let mut sessions = state.sessions.write().expect("sessions lock");
        // Only remove our own entry; a newer login of the same player may have replaced it.
        if sessions.get(&pid).is_some_and(|s| s.cid == c.cid) {
            sessions.remove(&pid);
        } else {
            return;
        }
    }
    let notes = state.matchmaking.lock().expect("matchmaking lock").disconnect(pid);
    for (to, note) in &notes {
        state.notify(*to, note);
    }
    tracing::info!(pid, "secure connection closed");
}

fn finish(state: &Arc<State>, conns: &HashMap<ConnKey, Conn>) {
    for c in conns.values() {
        drop_session(state, c);
    }
}
