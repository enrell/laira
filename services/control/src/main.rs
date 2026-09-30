//! laira control service: the community's admin authority over HTTP.
//!
//! Holds the `Authority` (admission, revocation, epoch keying), issues
//! short-lived session tokens for the SFU, and hosts an opaque TTL mailbox
//! (PLAN §10 dead-drop, single operator for now). Admin routes need the
//! bearer token in `<dir>/admin.token`; everything else is authenticated by
//! the signed objects themselves.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use axum::{
    body::Bytes,
    extract::{Path as UrlPath, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post, put},
    Json, Router,
};
use clap::{Parser, Subcommand};
use laira_identity::{
    Authority, AuthoritySnapshot, EpochBundle, Genesis, Identity, InviteBundle, JoinRequest,
    MembershipCert, PublicKey, Revocation, Role, SessionToken, TokenRequest,
};
use serde::{Deserialize, Serialize};

const MAILBOX_MAX_RECORD: usize = 16 * 1024;
const MAILBOX_MAX_PER_TOPIC: usize = 64;
const MAILBOX_MAX_TOPICS: usize = 4096;
const MAILBOX_MAX_TTL: u64 = 3600;

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create admin identity, genesis and empty state in DIR.
    Init {
        #[arg(long)]
        dir: PathBuf,
    },
    /// Serve the control API.
    Serve {
        #[arg(long)]
        dir: PathBuf,
        #[arg(long, default_value = "127.0.0.1:4500")]
        bind: String,
    },
    /// Ask a running server for an invite (uses <dir>/admin.token).
    Invite {
        #[arg(long)]
        dir: PathBuf,
        #[arg(long, default_value = "http://127.0.0.1:4500")]
        url: String,
        #[arg(long, default_value_t = 86400)]
        ttl: u64,
        #[arg(long, default_value_t = 1)]
        uses: u32,
        /// Print a browser invite link for this web app URL instead of JSON.
        #[arg(long)]
        web: Option<String>,
    },
    /// Revoke a member (hex public key) and rotate the epoch.
    Revoke {
        #[arg(long)]
        dir: PathBuf,
        #[arg(long, default_value = "http://127.0.0.1:4500")]
        url: String,
        member: String,
    },
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

struct Inner {
    auth: Authority,
    dir: PathBuf,
    mailbox: HashMap<String, Vec<(u64, Vec<u8>)>>,
    admin_token: String,
}

type Shared = Arc<Mutex<Inner>>;

impl Inner {
    fn persist(&self) -> Result<()> {
        let tmp = self.dir.join("state.json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(&self.auth.snapshot())?)?;
        std::fs::rename(tmp, self.dir.join("state.json"))?;
        Ok(())
    }
}

fn write_secret(path: &Path, data: &str) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path)?;
    f.write_all(data.as_bytes())?;
    Ok(())
}

#[derive(Serialize, Deserialize)]
struct AdminFile {
    seed: String,
}

fn load_identity(dir: &Path) -> Result<Identity> {
    let f: AdminFile = serde_json::from_slice(&std::fs::read(dir.join("admin.json")).context("admin.json")?)?;
    let seed: [u8; 32] = hex::decode(f.seed)?.try_into().map_err(|_| anyhow::anyhow!("bad seed"))?;
    Ok(Identity::from_seed(seed))
}

fn init(dir: &Path) -> Result<()> {
    anyhow::ensure!(!dir.join("admin.json").exists(), "already initialized");
    std::fs::create_dir_all(dir)?;
    let id = Identity::generate();
    write_secret(&dir.join("admin.json"), &serde_json::to_string(&AdminFile { seed: hex::encode(id.seed()) })?)?;
    write_secret(&dir.join("admin.token"), &hex::encode(rand::random::<[u8; 24]>()))?;
    let genesis = Genesis::create(&id, vec![], 0, now());
    let mut auth = Authority::new(id, genesis.clone())?;
    auth.new_epoch()?; // epoch 1: admin only
    let inner = Inner { auth, dir: dir.to_path_buf(), mailbox: HashMap::new(), admin_token: String::new() };
    inner.persist()?;
    println!("community_id = {}", hex::encode(genesis.community_id()));
    println!("admin_key    = {}", hex::encode(genesis.admin.0));
    println!("note: no recovery guardians configured (PLAN §11) — losing admin.json loses the community");
    Ok(())
}

type ApiErr = (StatusCode, String);

fn err<E: std::fmt::Display>(code: StatusCode) -> impl Fn(E) -> ApiErr {
    move |e| (code, e.to_string())
}

fn check_admin(h: &HeaderMap, st: &Inner) -> Result<(), ApiErr> {
    let ok = h.get("authorization").and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .is_some_and(|t| t == st.admin_token);
    ok.then_some(()).ok_or((StatusCode::UNAUTHORIZED, "admin token required".into()))
}

fn lock(s: &Shared) -> std::sync::MutexGuard<'_, Inner> {
    s.lock().unwrap_or_else(|p| p.into_inner())
}

async fn genesis(State(s): State<Shared>) -> Json<Genesis> {
    Json(lock(&s).auth.genesis().clone())
}

#[derive(Serialize)]
struct JoinReply {
    cert: MembershipCert,
    epoch: EpochBundle,
}

async fn join(State(s): State<Shared>, Json(req): Json<JoinRequest>) -> Result<Json<JoinReply>, ApiErr> {
    let mut st = lock(&s);
    let cert = st.auth.admit(&req, now()).map_err(err(StatusCode::FORBIDDEN))?;
    // Rekey on every new member so the epoch secret they hold is fresh; an
    // idempotent re-admit returns the current epoch without rotating.
    let epoch = match st.auth.latest_epoch() {
        Some(e) if e.kid_of(&req.member).is_some() => e.clone(),
        _ => st.auth.new_epoch().map_err(err(StatusCode::CONFLICT))?,
    };
    st.persist().map_err(err(StatusCode::INTERNAL_SERVER_ERROR))?;
    Ok(Json(JoinReply { cert, epoch }))
}

async fn latest_epoch(State(s): State<Shared>) -> Result<Json<EpochBundle>, ApiErr> {
    lock(&s).auth.latest_epoch().cloned().map(Json).ok_or((StatusCode::NOT_FOUND, "no epoch".into()))
}

async fn token(State(s): State<Shared>, Json(req): Json<TokenRequest>) -> Result<Json<SessionToken>, ApiErr> {
    lock(&s).auth.issue_token(&req, now()).map(Json).map_err(err(StatusCode::FORBIDDEN))
}

#[derive(Deserialize)]
struct InviteReq {
    ttl_secs: u64,
    max_uses: u32,
    #[serde(default)]
    moderator: bool,
}

async fn admin_invite(State(s): State<Shared>, h: HeaderMap, Json(r): Json<InviteReq>) -> Result<Json<InviteBundle>, ApiErr> {
    let mut st = lock(&s);
    check_admin(&h, &st)?;
    let role = if r.moderator { Role::Moderator } else { Role::Member };
    let b = st.auth.create_invite(now(), r.ttl_secs, r.max_uses, role);
    st.persist().map_err(err(StatusCode::INTERNAL_SERVER_ERROR))?;
    Ok(Json(b))
}

#[derive(Deserialize)]
struct RevokeReq {
    member: PublicKey,
}

#[derive(Serialize)]
struct RevokeReply {
    revocation: Revocation,
    epoch: EpochBundle,
}

async fn admin_revoke(State(s): State<Shared>, h: HeaderMap, Json(r): Json<RevokeReq>) -> Result<Json<RevokeReply>, ApiErr> {
    let mut st = lock(&s);
    check_admin(&h, &st)?;
    let revocation = st.auth.revoke(r.member);
    let epoch = st.auth.new_epoch().map_err(err(StatusCode::CONFLICT))?;
    st.persist().map_err(err(StatusCode::INTERNAL_SERVER_ERROR))?;
    Ok(Json(RevokeReply { revocation, epoch }))
}

fn valid_topic(t: &str) -> bool {
    t.len() == 64 && t.bytes().all(|b| b.is_ascii_hexdigit())
}

async fn mailbox_put(State(s): State<Shared>, UrlPath(topic): UrlPath<String>, h: HeaderMap, body: Bytes) -> Result<StatusCode, ApiErr> {
    if !valid_topic(&topic) || body.is_empty() || body.len() > MAILBOX_MAX_RECORD {
        return Err((StatusCode::BAD_REQUEST, "bad topic or record size".into()));
    }
    let ttl = h.get("x-ttl").and_then(|v| v.to_str().ok()).and_then(|v| v.parse().ok())
        .unwrap_or(600u64).min(MAILBOX_MAX_TTL);
    let t = now();
    let mut st = lock(&s);
    st.mailbox.retain(|_, v| { v.retain(|(exp, _)| *exp > t); !v.is_empty() });
    if !st.mailbox.contains_key(&topic) && st.mailbox.len() >= MAILBOX_MAX_TOPICS {
        return Err((StatusCode::INSUFFICIENT_STORAGE, "mailbox full".into()));
    }
    let q = st.mailbox.entry(topic).or_default();
    if q.len() >= MAILBOX_MAX_PER_TOPIC {
        return Err((StatusCode::TOO_MANY_REQUESTS, "topic full".into()));
    }
    q.push((t + ttl, body.to_vec()));
    Ok(StatusCode::NO_CONTENT)
}

async fn mailbox_get(State(s): State<Shared>, UrlPath(topic): UrlPath<String>) -> Result<Json<Vec<String>>, ApiErr> {
    if !valid_topic(&topic) {
        return Err((StatusCode::BAD_REQUEST, "bad topic".into()));
    }
    let t = now();
    let st = lock(&s);
    Ok(Json(st.mailbox.get(&topic).map(|v| {
        v.iter().filter(|(exp, _)| *exp > t).map(|(_, r)| hex::encode(r)).collect()
    }).unwrap_or_default()))
}

fn router(shared: Shared) -> Router {
    Router::new()
        .route("/v1/genesis", get(genesis))
        .route("/v1/join", post(join))
        .route("/v1/epoch/latest", get(latest_epoch))
        .route("/v1/token", post(token))
        .route("/v1/admin/invite", post(admin_invite))
        .route("/v1/admin/revoke", post(admin_revoke))
        .route("/v1/mailbox/{topic}", put(mailbox_put).get(mailbox_get))
        .layer(
            // Browsers join from another origin; every route is authenticated
            // by signed objects or the admin bearer token, not by origin.
            tower_http::cors::CorsLayer::new()
                .allow_origin(tower_http::cors::Any)
                .allow_methods(tower_http::cors::Any)
                .allow_headers(tower_http::cors::Any),
        )
        .with_state(shared)
}

async fn admin_call(dir: &Path, url: &str, path: &str, body: serde_json::Value) -> Result<serde_json::Value> {
    let tok = std::fs::read_to_string(dir.join("admin.token"))?;
    let r = reqwest::Client::new().post(format!("{url}{path}")).bearer_auth(tok.trim()).json(&body).send().await?;
    let status = r.status();
    let text = r.text().await?;
    anyhow::ensure!(status.is_success(), "{status}: {text}");
    Ok(serde_json::from_str(&text)?)
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter(
        tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into())).init();
    match Cli::parse().cmd {
        Cmd::Init { dir } => init(&dir),
        Cmd::Serve { dir, bind } => {
            let snap: AuthoritySnapshot = serde_json::from_slice(&std::fs::read(dir.join("state.json")).context("run init first")?)?;
            let auth = Authority::restore(load_identity(&dir)?, snap)?;
            let admin_token = std::fs::read_to_string(dir.join("admin.token"))?.trim().to_string();
            let shared = Arc::new(Mutex::new(Inner { auth, dir, mailbox: HashMap::new(), admin_token }));
            let l = tokio::net::TcpListener::bind(&bind).await?;
            tracing::info!(%bind, "control listening");
            axum::serve(l, router(shared)).await?;
            Ok(())
        }
        Cmd::Invite { dir, url, ttl, uses, web } => {
            let v = admin_call(&dir, &url, "/v1/admin/invite", serde_json::json!({"ttl_secs": ttl, "max_uses": uses})).await?;
            match web {
                // The secret rides in the URL fragment: never sent to a server.
                Some(w) => println!("{}/#c={}&i={}", w.trim_end_matches('/'), url, hex::encode(v.to_string())),
                None => println!("{v}"),
            }
            Ok(())
        }
        Cmd::Revoke { dir, url, member } => {
            let v = admin_call(&dir, &url, "/v1/admin/revoke", serde_json::json!({"member": member})).await?;
            println!("revoked; epoch {}", v["epoch"]["epoch"]);
            Ok(())
        }
    }
}
