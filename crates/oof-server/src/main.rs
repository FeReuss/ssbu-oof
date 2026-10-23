//! ssbu-oof server: one listener serves the NEX WebSocket (`GET /`, subprotocol `NEX`) and the
//! small HTTP API ports use to obtain accounts and ID tokens (`/v1/...`).

mod accounts;
mod config;
mod connection;
mod matchmaking;
mod natcheck;
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

/// `POST /v1/accounts` → `{pid, password}`: a new player identity for a port to store.
async fn create_account(AxState(state): App) -> impl IntoResponse {
    let pid = accounts::new_pid();
    tracing::info!(pid, "account created");
    Json(json!({ "pid": pid, "password": accounts::password(&state.secret, pid) }))
}

#[derive(Deserialize)]
struct TokenRequest {
    pid: u64,
    password: String,
}

/// `POST /v1/token` `{pid, password}` → `{id_token, expires_in}`.
async fn token(AxState(state): App, Json(req): Json<TokenRequest>) -> impl IntoResponse {
    if !accounts::check_password(&state.secret, req.pid, &req.password) {
        return (StatusCode::UNAUTHORIZED, Json(json!({ "error": "invalid pid or password" })));
    }
    let ttl = state.config.token_ttl_secs;
    let expires = oof_nex::stream::DateTime::now().to_unix() + ttl;
    let token = accounts::issue_token(&state.secret, req.pid, expires);
    (StatusCode::OK, Json(json!({ "id_token": token, "expires_in": ttl, "nex_username": req.pid.to_string() })))
}

async fn status(AxState(state): App) -> impl IntoResponse {
    let online = state.sessions.read().expect("sessions lock").len();
    let sessions = state.matchmaking.lock().expect("matchmaking lock").len();
    Json(
        json!({ "server": "ssbu-oof", "version": env!("CARGO_PKG_VERSION"), "players_online": online, "matchmake_sessions": sessions }),
    )
}

pub fn router(state: Arc<State>) -> Router {
    Router::new()
        .route("/", get(nex))
        .route("/v1/accounts", post(create_account))
        .route("/v1/token", post(token))
        .route("/v1/status", get(status))
        .with_state(state)
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    let path = std::env::args().nth(1).unwrap_or_else(|| "oof.toml".into());
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {path}: {e}"));
    let config: config::Config = toml::from_str(&text).unwrap_or_else(|e| panic!("parsing {path}: {e}"));
    let listen = config.listen;
    if let Some(nat) = &config.nat_check {
        let bind =
            |a| async move { tokio::net::UdpSocket::bind(a).await.unwrap_or_else(|e| panic!("binding {a}: {e}")) };
        let (primary, secondary) = (bind(nat.primary).await, bind(nat.secondary).await);
        let ip = config.public_host.parse().ok();
        tokio::spawn(natcheck::run(primary, secondary, ip));
        tracing::info!(primary = %nat.primary, secondary = %nat.secondary, "NAT check listening");
    }
    let state = Arc::new(State::new(config).unwrap_or_else(|e| panic!("{path}: {e}")));
    let listener = tokio::net::TcpListener::bind(listen).await.unwrap_or_else(|e| panic!("binding {listen}: {e}"));
    tracing::info!(%listen, "ssbu-oof listening");
    axum::serve(listener, router(state).into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .expect("server");
}
