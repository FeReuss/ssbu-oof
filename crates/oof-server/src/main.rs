//! ssbu-oof server: one listener serves the NEX WebSocket (`GET /`, subprotocol `NEX`) and the
//! small HTTP API ports use to obtain accounts and ID tokens (`/v1/...`).

mod accounts;
mod config;
mod connection;
mod events;
mod matchmaking;
mod natcheck;
mod objects;
mod protocols;
mod state;
#[cfg(test)]
mod tests;

use axum::extract::{ConnectInfo, State as AxState, WebSocketUpgrade};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;
use state::State;
use std::net::SocketAddr;
use std::sync::Arc;

type App = AxState<Arc<State>>;

async fn nex(
    ws: WebSocketUpgrade,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    AxState(state): App,
) -> impl IntoResponse {
    ws.protocols(["NEX"])
        .max_message_size(prudp_limit())
        .on_upgrade(move |socket| connection::serve(socket, peer, state))
}

fn prudp_limit() -> usize {
    // A WebSocket message carries PRUDP packets of at most 64 KiB payload each.
    256 * 1024
}

fn now_unix() -> u64 {
    oof_nex::stream::DateTime::now().to_unix()
}

fn reply(code: StatusCode, body: serde_json::Value) -> axum::response::Response {
    (code, Json(body)).into_response()
}

fn database_error(e: rusqlite::Error) -> axum::response::Response {
    tracing::error!(%e, "account database");
    reply(StatusCode::INTERNAL_SERVER_ERROR, json!({ "error": "server error" }))
}

fn banned(ban: &accounts::Ban) -> axum::response::Response {
    reply(StatusCode::FORBIDDEN, json!({ "error": "banned", "reason": ban.reason, "until": ban.until }))
}

#[derive(Deserialize)]
struct Credentials {
    username: String,
    password: String,
    /// `/v1/login`: a name for the device ("Ana's MacBook"), shown to the account's owner and to admins.
    #[serde(default)]
    device: String,
    /// `/v1/password`: the new password.
    #[serde(default)]
    new_password: String,
}

/// The account behind a user name and password, checked on a blocking thread (Argon2 is slow on purpose).
async fn authenticate(state: &Arc<State>, c: &Credentials) -> Result<accounts::Account, Box<axum::response::Response>> {
    let found =
        state.accounts.lock().expect("accounts lock").find(&c.username).map_err(|e| Box::new(database_error(e)))?;
    let refused = || reply(StatusCode::UNAUTHORIZED, json!({ "error": "wrong user name or password" }));
    let Some(account) = found.filter(|a| a.username.eq_ignore_ascii_case(&c.username)) else {
        return Err(Box::new(refused()));
    };
    let (password, hash) = (c.password.clone(), account.password_hash.clone());
    let ok = tokio::task::spawn_blocking(move || accounts::password_matches(&password, &hash)).await.unwrap_or(false);
    if ok { Ok(account) } else { Err(Box::new(refused())) }
}

/// `POST /v1/accounts` `{username, password}` → `{pid, username}`: registration. No e-mail or phone number; the user
/// name is also the player's in-game nickname.
async fn create_account(AxState(state): App, Json(c): Json<Credentials>) -> axum::response::Response {
    if !accounts::valid_username(&c.username) {
        return reply(StatusCode::BAD_REQUEST, json!({ "error": "user name: 3 to 10 letters, digits, _ - or ." }));
    }
    if !accounts::valid_password(&c.password) {
        return reply(StatusCode::BAD_REQUEST, json!({ "error": "password: 8 to 128 characters" }));
    }
    let password = c.password.clone();
    let hash = tokio::task::spawn_blocking(move || accounts::hash_password(&password)).await.expect("hashing");
    match state.accounts.lock().expect("accounts lock").create(&c.username, &hash, now_unix()) {
        Ok(Some(pid)) => {
            tracing::info!(pid, username = c.username, "account created");
            reply(StatusCode::CREATED, json!({ "pid": pid, "username": c.username }))
        }
        Ok(None) => reply(StatusCode::CONFLICT, json!({ "error": "that user name is taken" })),
        Err(e) => database_error(e),
    }
}

/// `POST /v1/login` `{username, password, device?}` → `{pid, username, device_key}`. The port keeps the device key
/// (never the password) and trades it for ID tokens.
async fn login(
    AxState(state): App,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(c): Json<Credentials>,
) -> axum::response::Response {
    let account = match authenticate(&state, &c).await {
        Ok(a) => a,
        Err(r) => {
            tracing::info!(%peer, username = c.username, "login refused");
            return *r;
        }
    };
    let store = state.accounts.lock().expect("accounts lock");
    match store.ban_of(account.pid, now_unix()) {
        Ok(Some(ban)) => return banned(&ban),
        Err(e) => return database_error(e),
        Ok(None) => {}
    }
    let device = if c.device.trim().is_empty() { "device" } else { c.device.trim() };
    match store.add_device(account.pid, &device.chars().take(64).collect::<String>(), now_unix()) {
        Ok(key) => {
            tracing::info!(pid = account.pid, username = account.username, %peer, device, "device logged in");
            reply(StatusCode::OK, json!({ "pid": account.pid, "username": account.username, "device_key": key }))
        }
        Err(e) => database_error(e),
    }
}

#[derive(Deserialize)]
struct DeviceRequest {
    pid: u64,
    device_key: String,
}

/// `POST /v1/token` `{pid, device_key}` → `{id_token, expires_in, nex_username, username}`; 403 with the reason while
/// the account is banned. Every token issued is logged with the account and address.
async fn token(
    AxState(state): App,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(req): Json<DeviceRequest>,
) -> axum::response::Response {
    let now = now_unix();
    let store = state.accounts.lock().expect("accounts lock");
    let account = match store
        .device_ok(req.pid, &req.device_key, now)
        .and_then(|ok| if ok { store.find(&req.pid.to_string()) } else { Ok(None) })
    {
        Ok(Some(a)) => a,
        Ok(None) => return reply(StatusCode::UNAUTHORIZED, json!({ "error": "unknown device: log in again" })),
        Err(e) => return database_error(e),
    };
    if let Some(ban) = account.ban.as_ref().filter(|b| b.until.is_none_or(|t| t > now)) {
        tracing::info!(pid = account.pid, username = account.username, %peer, "token refused: account banned");
        return banned(ban);
    }
    if let Err(e) = store.record_login(account.pid, &peer.to_string(), now) {
        return database_error(e);
    }
    drop(store);
    let ttl = state.config.token_ttl_secs;
    let token = accounts::issue_token(&state.secret, account.pid, now + ttl);
    tracing::info!(pid = account.pid, username = account.username, %peer, "token issued");
    reply(
        StatusCode::OK,
        json!({ "id_token": token, "expires_in": ttl, "nex_username": account.pid.to_string(), "username": account.username }),
    )
}

/// Friends API (standard section 7): `{pid, device_key}` identifies the caller; `user` is a user name or a PID.
#[derive(Deserialize)]
struct FriendRequest {
    pid: u64,
    device_key: String,
    #[serde(default)]
    user: String,
}

/// The caller's account after checking its device key, or the response refusing it.
fn friend_caller<'a>(
    state: &'a State,
    req: &FriendRequest,
) -> Result<std::sync::MutexGuard<'a, accounts::AccountStore>, Box<axum::response::Response>> {
    let store = state.accounts.lock().expect("accounts lock");
    match store.device_ok(req.pid, &req.device_key, now_unix()) {
        Ok(true) => Ok(store),
        Ok(false) => Err(Box::new(reply(StatusCode::UNAUTHORIZED, json!({ "error": "unknown device: log in again" })))),
        Err(e) => Err(Box::new(database_error(e))),
    }
}

/// `POST /v1/friends` → `{friends: [{pid, username, online}], incoming, outgoing, blocked: [{pid, username}], max}`;
/// online = connected to this server.
async fn friends(AxState(state): App, Json(req): Json<FriendRequest>) -> axum::response::Response {
    let list = match friend_caller(&state, &req).map(|s| s.friend_list(req.pid)) {
        Ok(Ok(list)) => list,
        Ok(Err(e)) => return database_error(e),
        Err(refused) => return *refused,
    };
    let sessions = state.sessions.read().expect("sessions lock");
    let people =
        |v: &[(u64, String)]| v.iter().map(|(pid, name)| json!({ "pid": pid, "username": name })).collect::<Vec<_>>();
    let friends: Vec<_> = list
        .friends
        .iter()
        .map(|(pid, name)| json!({ "pid": pid, "username": name, "online": sessions.contains_key(pid) }))
        .collect();
    reply(
        StatusCode::OK,
        json!({ "friends": friends, "incoming": people(&list.incoming), "outgoing": people(&list.outgoing),
                "blocked": people(&list.blocked), "max": accounts::MAX_FRIENDS }),
    )
}

/// `POST /v1/friends/add` `{…, user}` → `{state: "requested" | "friends"}`: asks `user`, or accepts their request.
async fn friends_add(AxState(state): App, Json(req): Json<FriendRequest>) -> axum::response::Response {
    use accounts::FriendAdd::*;
    let result = match friend_caller(&state, &req).map(|s| s.add_friend(req.pid, &req.user, now_unix())) {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => return database_error(e),
        Err(refused) => return *refused,
    };
    let (code, body) = match result {
        Requested => (StatusCode::OK, json!({ "state": "requested" })),
        Friends => (StatusCode::OK, json!({ "state": "friends" })),
        AlreadyFriends => (StatusCode::OK, json!({ "state": "friends" })),
        UnknownUser => (StatusCode::NOT_FOUND, json!({ "error": "no such user" })),
        Yourself => (StatusCode::BAD_REQUEST, json!({ "error": "that is you" })),
        Blocked => (StatusCode::FORBIDDEN, json!({ "error": "blocked" })),
        TooManyFriends => (StatusCode::CONFLICT, json!({ "error": "friend list full", "max": accounts::MAX_FRIENDS })),
    };
    tracing::info!(pid = req.pid, user = req.user, ?result, "friend request");
    reply(code, body)
}

/// `POST /v1/friends/remove|block|unblock` `{…, user}`: ends a friendship or request (either way), blocks (also ending
/// it) or unblocks. 204, or 404 when there was nothing to change.
async fn friends_change(state: Arc<State>, req: FriendRequest, action: &'static str) -> axum::response::Response {
    let store = match friend_caller(&state, &req) {
        Ok(s) => s,
        Err(refused) => return *refused,
    };
    let other = match store.find(&req.user) {
        Ok(Some(a)) => a.pid,
        Ok(None) => return reply(StatusCode::NOT_FOUND, json!({ "error": "no such user" })),
        Err(e) => return database_error(e),
    };
    let done = match action {
        "remove" => store.remove_friend(req.pid, other),
        "block" => store.block(req.pid, other),
        _ => store.unblock(req.pid, other),
    };
    match done {
        Ok(true) => {
            tracing::info!(pid = req.pid, other, action, "friends");
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => reply(StatusCode::NOT_FOUND, json!({ "error": "nothing to change" })),
        Err(e) => database_error(e),
    }
}

/// `POST /v1/logout` `{pid, device_key}`: forgets that device key.
async fn logout(AxState(state): App, Json(req): Json<DeviceRequest>) -> axum::response::Response {
    match state.accounts.lock().expect("accounts lock").remove_device(req.pid, &req.device_key) {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => reply(StatusCode::UNAUTHORIZED, json!({ "error": "unknown device" })),
        Err(e) => database_error(e),
    }
}

/// `POST /v1/password` `{username, password, new_password}`: changes the password and logs every device out.
async fn change_password(AxState(state): App, Json(c): Json<Credentials>) -> axum::response::Response {
    if !accounts::valid_password(&c.new_password) {
        return reply(StatusCode::BAD_REQUEST, json!({ "error": "password: 8 to 128 characters" }));
    }
    let account = match authenticate(&state, &c).await {
        Ok(a) => a,
        Err(r) => return *r,
    };
    let password = c.new_password.clone();
    let hash = tokio::task::spawn_blocking(move || accounts::hash_password(&password)).await.expect("hashing");
    match state.accounts.lock().expect("accounts lock").set_password(account.pid, &hash) {
        Ok(()) => {
            tracing::info!(pid = account.pid, username = account.username, "password changed; devices logged out");
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => database_error(e),
    }
}

#[derive(Deserialize)]
struct ObjectKey {
    k: String,
}

/// Upload of a DataStore object's payload to the URL 115/24 handed out (PUT, or POST with a multipart form).
async fn put_object(
    AxState(state): App,
    axum::extract::Path(id): axum::extract::Path<u64>,
    axum::extract::Query(key): axum::extract::Query<ObjectKey>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> axum::response::Response {
    if key.k != objects::url_key(&state.secret, id, true) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let kind = headers.get(axum::http::header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("");
    let Some(data) = objects::upload_body(kind, &body) else { return StatusCode::BAD_REQUEST.into_response() };
    match state.objects.lock().expect("objects lock").upload(id, data) {
        Ok(true) => {
            tracing::debug!(id, len = data.len(), "object payload uploaded");
            StatusCode::OK.into_response()
        }
        Ok(false) => StatusCode::BAD_REQUEST.into_response(),
        Err(e) => database_error(e),
    }
}

/// Download of a completed object's payload from the URL 115/25 handed out.
async fn get_object(
    AxState(state): App,
    axum::extract::Path(id): axum::extract::Path<u64>,
    axum::extract::Query(key): axum::extract::Query<ObjectKey>,
) -> axum::response::Response {
    if key.k != objects::url_key(&state.secret, id, false) {
        return StatusCode::FORBIDDEN.into_response();
    }
    match state.objects.lock().expect("objects lock").payload(id) {
        Ok(Some(data)) => ([(axum::http::header::CONTENT_TYPE, "application/octet-stream")], data).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => database_error(e),
    }
}

async fn status(AxState(state): App) -> impl IntoResponse {
    let online = state.sessions.read().expect("sessions lock").len();
    let sessions = state.matchmaking.lock().expect("matchmaking lock").len();
    Json(
        json!({ "server": "ssbu-oof", "version": env!("CARGO_PKG_VERSION"), "players_online": online, "matchmake_sessions": sessions,
                "nat_check": state.config.nat_check.as_ref().map(|n| json!({ "primary": n.primary, "secondary": n.secondary })) }),
    )
}

pub fn router(state: Arc<State>) -> Router {
    Router::new()
        .route("/", get(nex))
        .route("/v1/accounts", post(create_account))
        .route("/v1/login", post(login))
        .route("/v1/token", post(token))
        .route("/v1/logout", post(logout))
        .route("/v1/password", post(change_password))
        .route("/v1/status", get(status))
        .route(
            "/v1/objects/{id}",
            get(get_object)
                .put(put_object)
                .post(put_object)
                .layer(axum::extract::DefaultBodyLimit::max(objects::MAX_PAYLOAD + (1 << 16))),
        )
        .route("/v1/friends", post(friends))
        .route("/v1/friends/add", post(friends_add))
        .route(
            "/v1/friends/remove",
            post(|AxState(s): App, Json(r): Json<FriendRequest>| friends_change(s, r, "remove")),
        )
        .route("/v1/friends/block", post(|AxState(s): App, Json(r): Json<FriendRequest>| friends_change(s, r, "block")))
        .route(
            "/v1/friends/unblock",
            post(|AxState(s): App, Json(r): Json<FriendRequest>| friends_change(s, r, "unblock")),
        )
        .with_state(state)
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("nat-check") {
        // `oof-server nat-check <address> [<bind address>]`: only the NAT check address `nncs2` on a host of its own
        // (`nat_check.remote_secondary` on the main server); needs no config.
        let ip = |i: usize| args.get(i).map(|s| s.parse().unwrap_or_else(|e| panic!("{s}: {e}")));
        let Some(address) = ip(1) else { panic!("usage: oof-server nat-check <address> [<bind address>]") };
        let sockets = natcheck::bind(ip(2).unwrap_or(address), natcheck::PORTS).await;
        tracing::info!(%address, "NAT check listening on UDP 10025/10125");
        natcheck::serve(sockets, address).await;
        return;
    }
    let path = args.first().cloned().unwrap_or_else(|| "oof.toml".into());
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {path}: {e}"));
    let config: config::Config = toml::from_str(&text).unwrap_or_else(|e| panic!("parsing {path}: {e}"));
    if args.len() > 1 {
        // `oof-server <config> account|ban|unban …`: administration on the configured database, then exit.
        let Some(db) = config.database.as_deref() else { panic!("{path}: account administration needs `database`") };
        let store = accounts::AccountStore::open(Some(db)).unwrap_or_else(|e| panic!("{db}: {e}"));
        match accounts::admin(&store, &args[1..], now_unix()) {
            Ok(out) => println!("{out}"),
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(2);
            }
        }
        return;
    }
    let listen = config.listen;
    let state = Arc::new(State::new(config).unwrap_or_else(|e| panic!("{path}: {e}")));
    if let Some(nat) = &state.config.nat_check {
        let primary = nat.primary_bind.unwrap_or(nat.primary);
        tokio::spawn(natcheck::serve(natcheck::bind(primary, natcheck::PORTS).await, nat.primary));
        tokio::spawn(natcheck::listen_pia(natcheck::bind(primary, natcheck::PIA_PORTS).await, state.clone()));
        if !nat.remote_secondary {
            let secondary = nat.secondary_bind.unwrap_or(nat.secondary);
            tokio::spawn(natcheck::serve(natcheck::bind(secondary, natcheck::PORTS).await, nat.secondary));
        }
        tracing::info!(primary = %nat.primary, secondary = %nat.secondary, remote_secondary = nat.remote_secondary,
            "NAT check listening on UDP 10025/10125 (+33334/33335 on primary)");
    }
    tokio::spawn(state::kick_banned_every(state.clone(), std::time::Duration::from_secs(30)));
    let listener = tokio::net::TcpListener::bind(listen).await.unwrap_or_else(|e| panic!("binding {listen}: {e}"));
    tracing::info!(%listen, "ssbu-oof listening");
    axum::serve(listener, router(state).into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .expect("server");
}
