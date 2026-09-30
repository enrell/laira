//! laira-desktop M0: native capture + SFU streaming + return voice.
//! OBS stack: PipeWire capture -> FFmpeg encode -> RTP -> mediasoup.
//!
//!   laira-desktop list-audio        # pick --audio-target
//!   laira-desktop list-mics         # pick --mic
//!   laira-desktop stream            # portal picker -> stream to SFU

mod portal;
mod profile;
mod signaling;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use laira_media as media;
use laira_media::capture::{self, FrameMsg};
use laira_media::RtpDest;
use laira_protocol::{methods, ConsumePlainResult, JoinResult, PlainRecvResult, PlainSendResult, ProducerInfo, ProduceResult};
use serde_json::json;
use signaling::Signaling;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::process::Child;
use std::sync::mpsc as std_mpsc;

const VIDEO_PT: u8 = 101;
const GAME_PT: u8 = 111;
const MIC_PT: u8 = 112;

#[derive(Parser)]
#[command(name = "laira-desktop", about = "laira native client (M0 vertical proof)")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// List PipeWire playback streams (candidates for --audio-target).
    ListAudio,
    /// List PipeWire capture sources (candidates for --mic).
    ListMics,
    /// Join a community: consume an invite (JSON file, or `-` for stdin).
    Join {
        #[arg(long)]
        control: String,
        invite: String,
    },
    /// Use the admin identity from a `laira-control init` dir as this profile.
    AdoptAdmin {
        #[arg(long)]
        control: String,
        #[arg(long)]
        dir: std::path::PathBuf,
    },
    /// Show this profile's identity, roster slot and current epoch.
    Whoami,
    /// End-to-end encrypted text chat (channels are created by moderators/admin).
    #[command(subcommand)]
    Chat(ChatCmd),
    /// Capture screen + game audio + mic and stream through the SFU.
    Stream(StreamArgs),
    /// E2E check of the Rust RTP path: testsrc2 -> Annex-B -> our packetizer
    /// -> SFU producer stats. No portal needed.
    TestVideo {
        #[arg(long, default_value = "ws://127.0.0.1:4443")]
        sfu: String,
        #[arg(long, default_value_t = 6)]
        seconds: u64,
        #[arg(long)]
        e2ee: bool,
    },
    /// Send a synthetic 440 Hz tone as an audio producer (no PipeWire needed).
    TestAudio {
        #[arg(long, default_value = "ws://127.0.0.1:4443")]
        sfu: String,
        #[arg(long, default_value_t = 8)]
        seconds: u64,
        #[arg(long)]
        e2ee: bool,
    },
    /// Watch a video producer natively: PlainTransport receive -> depacketize
    /// -> optional SFrame decrypt -> Annex-B -> ffplay window. No browser.
    Watch {
        #[arg(long, default_value = "ws://127.0.0.1:4443")]
        sfu: String,
        #[arg(long)]
        e2ee: bool,
        /// Producer id to watch; defaults to the first video producer.
        #[arg(long)]
        producer: Option<String>,
        /// Write the decoded Annex-B stream to a file instead of ffplay.
        #[arg(long)]
        dump: Option<String>,
    },
}

#[derive(Subcommand)]
enum ChatCmd {
    /// List channels.
    Channels,
    /// Create a channel (moderator/admin only).
    Create { name: String },
    /// Send a message.
    Send { channel: String, text: Vec<String> },
    /// Encrypt and share a file (up to 64 MiB) in a channel.
    SendFile { channel: String, path: std::path::PathBuf },
    /// Download and decrypt the file attached to message SEQ.
    SaveFile { channel: String, seq: u64, #[arg(long, default_value = ".")] out_dir: std::path::PathBuf },
    /// Read messages; with --follow keep polling.
    Read {
        channel: String,
        #[arg(long, default_value_t = 0)]
        after: u64,
        #[arg(long)]
        follow: bool,
    },
}

#[derive(Parser)]
struct StreamArgs {
    /// Signaling URL of services/sfu.
    #[arg(long, default_value = "ws://127.0.0.1:4443")]
    sfu: String,
    /// PipeWire object.serial of the app's playback stream (see list-audio).
    /// If omitted and exactly one app stream exists, it is used.
    #[arg(long)]
    audio_target: Option<u64>,
    /// PipeWire object.serial of the mic source; default source if unset.
    #[arg(long)]
    mic: Option<u64>,
    #[arg(long)]
    no_game_audio: bool,
    #[arg(long)]
    no_mic: bool,
    #[arg(long, value_enum, default_value = "h264")]
    codec: Codec,
    #[arg(long, default_value_t = 3_000_000)]
    bitrate: u32,
    /// SFrame-encrypt video frames with the M1 test key (viewers must enable
    /// the decrypt transform — the M1 interop vector).
    #[arg(long)]
    e2ee: bool,
}

#[derive(Clone, Copy, ValueEnum)]
enum Codec {
    H264,
    Vp8,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::ListAudio => list_audio(),
        Cmd::ListMics => list_mics(),
        Cmd::Join { control, invite } => {
            let raw = if invite == "-" { std::io::read_to_string(std::io::stdin())? } else { std::fs::read_to_string(&invite)? };
            let p = profile::Profile::join(&control, serde_json::from_str(&raw)?).await?;
            println!("joined; member key {}", hex::encode(p.public()?.0));
            Ok(())
        }
        Cmd::AdoptAdmin { control, dir } => {
            let p = profile::Profile::adopt_admin(&control, &dir).await?;
            println!("adopted admin {}", hex::encode(p.public()?.0));
            Ok(())
        }
        Cmd::Whoami => whoami().await,
        Cmd::Chat(c) => chat(c).await,
        Cmd::Stream(args) => { if args.e2ee { init_e2ee().await?; } stream(args).await }
        Cmd::TestVideo { sfu, seconds, e2ee } => { if e2ee { init_e2ee().await?; } test_video(sfu, seconds, e2ee).await }
        Cmd::TestAudio { sfu, seconds, e2ee } => { if e2ee { init_e2ee().await?; } test_audio(sfu, seconds, e2ee).await }
        Cmd::Watch { sfu, e2ee, producer, dump } => { if e2ee { init_e2ee().await?; } watch(sfu, e2ee, producer, dump).await }
    }
}

/// Live SFrame state for this process (set once by `init_e2ee`). The encryptor
/// and decryptor are shared handles: the epoch poller rekeys them in place.
struct E2eeKeys {
    enc: media::sframe::SframeEncryptor,
    dec: media::sframe::SframeDecryptor,
}

static E2EE: std::sync::OnceLock<E2eeKeys> = std::sync::OnceLock::new();

const EPOCH_POLL: std::time::Duration = std::time::Duration::from_secs(3);
const EPOCH_GRACE: std::time::Duration = std::time::Duration::from_secs(15);

/// Resolve keys: a joined profile (epoch fetched from the control service,
/// KID bound by the admin-signed roster; kept fresh by a poller that rekeys
/// live and exits if we are removed) wins; otherwise `LAIRA_EPOCH_SECRET` /
/// `LAIRA_EPOCH` / `LAIRA_KID` / `LAIRA_ACCEPT_KIDS`; otherwise the PUBLIC M1
/// test key, loudly.
async fn init_e2ee() -> Result<()> {
    let keys = if let Some(p) = profile::Profile::load()? {
        let me = p.public()?;
        let (secret, bundle) = p.latest_epoch().await?;
        let kid = bundle.kid_of(&me).context("not in epoch roster")?;
        tracing::info!(epoch = secret.epoch(), kid, "sframe: keys from community epoch");
        let senders = |s: &laira_identity::EpochSecret, b: &laira_identity::EpochBundle|
            b.roster.iter().map(|(k, _)| (*k, s.sframe_base_key(*k))).collect::<Vec<_>>();
        let keys = E2eeKeys {
            enc: media::sframe::SframeEncryptor::with_kid(&secret.sframe_base_key(kid), kid),
            dec: media::sframe::SframeDecryptor::with_senders(senders(&secret, &bundle)),
        };
        let (enc, dec, mut epoch) = (keys.enc.share(), keys.dec.clone(), secret.epoch());
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(EPOCH_POLL).await;
                match p.latest_epoch().await {
                    Ok((s, b)) if s.epoch() > epoch => {
                        if b.kid_of(&me) != Some(kid) {
                            tracing::error!("roster slot changed; stopping");
                            std::process::exit(3);
                        }
                        enc.rekey(&s.sframe_base_key(kid));
                        dec.rotate(senders(&s, &b));
                        epoch = s.epoch();
                        tracing::info!(epoch, "sframe: rekeyed to new epoch");
                        let d = dec.clone();
                        tokio::spawn(async move { tokio::time::sleep(EPOCH_GRACE).await; d.forget_previous(); });
                    }
                    Ok(_) => {}
                    Err(e) if format!("{e:#}").contains("cannot open") => {
                        tracing::error!(%e, "removed from the community; stopping");
                        std::process::exit(3);
                    }
                    Err(e) => tracing::warn!(%e, "epoch poll failed (keeping current keys)"),
                }
            }
        });
        keys
    } else if let Ok(hexs) = std::env::var("LAIRA_EPOCH_SECRET") {
        let bytes: [u8; 32] = hex::decode(hexs.trim())?.try_into()
            .map_err(|_| anyhow::anyhow!("LAIRA_EPOCH_SECRET must be 64 hex chars"))?;
        let epoch = std::env::var("LAIRA_EPOCH").ok().and_then(|v| v.parse().ok()).unwrap_or(0);
        let e = laira_identity::EpochSecret::new(bytes, epoch);
        let kid: u8 = std::env::var("LAIRA_KID").ok().and_then(|v| v.parse().ok()).unwrap_or(0);
        anyhow::ensure!(kid <= 7, "LAIRA_KID must be 0..=7");
        let kids: Vec<u8> = std::env::var("LAIRA_ACCEPT_KIDS").unwrap_or_else(|_| "0".into())
            .split(',').filter_map(|k| k.trim().parse().ok()).filter(|k| *k <= 7).collect();
        E2eeKeys {
            enc: media::sframe::SframeEncryptor::with_kid(&e.sframe_base_key(kid), kid),
            dec: media::sframe::SframeDecryptor::with_senders(kids.iter().map(|k| (*k, e.sframe_base_key(*k)))),
        }
    } else {
        tracing::warn!("no profile or LAIRA_EPOCH_SECRET: using the PUBLIC M1 test key (not confidential)");
        E2eeKeys {
            enc: media::sframe::SframeEncryptor::new(&media::sframe::TEST_BASE_KEY),
            dec: media::sframe::SframeDecryptor::new(&media::sframe::TEST_BASE_KEY),
        }
    };
    E2EE.set(keys).map_err(|_| anyhow::anyhow!("e2ee already initialised"))
}

fn e2ee_encryptor() -> media::sframe::SframeEncryptor {
    E2EE.get().expect("init_e2ee not called").enc.share()
}

fn e2ee_decryptor() -> media::sframe::SframeDecryptor {
    E2EE.get().expect("init_e2ee not called").dec.clone()
}

async fn chat(cmd: ChatCmd) -> Result<()> {
    let p = profile::Profile::load()?.context("no profile; run `join` or `adopt-admin`")?;
    match cmd {
        ChatCmd::Channels => {
            for c in p.channels().await? {
                println!("{}\t{}", c.id, c.name);
            }
        }
        ChatCmd::Create { name } => {
            let c = p.create_channel(&name).await?;
            println!("created #{}", c.id);
        }
        ChatCmd::Send { channel, text } => {
            let seq = p.send_chat(&channel, &text.join(" ")).await?;
            println!("sent #{channel} seq {seq}");
        }
        ChatCmd::SendFile { channel, path } => {
            let a = p.send_file(&channel, &path).await?;
            println!("shared {} ({} bytes, {} chunk(s))", a.name, a.size, a.chunks);
        }
        ChatCmd::SaveFile { channel, seq, out_dir } => {
            println!("saved {}", p.save_file(&channel, seq, &out_dir).await?.display());
        }
        ChatCmd::Read { channel, mut after, follow } => loop {
            for m in p.read_chat(&channel, after).await? {
                after = after.max(m.seq);
                let shown = match laira_identity::Attachment::from_message(&m.text) {
                    Some(a) => format!("[file] {} ({} bytes) - save with: chat save-file {channel} {}", a.name, a.size, m.seq),
                    None => m.text.clone(),
                };
                println!("[{}] {}: {}", m.seq, &hex::encode(m.sender.0)[..8], shown);
            }
            if !follow { break }
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        },
    }
    Ok(())
}

async fn whoami() -> Result<()> {
    let p = profile::Profile::load()?.context("no profile; run `join` or `adopt-admin`")?;
    let (secret, bundle) = p.latest_epoch().await?;
    println!("member   {}", hex::encode(p.public()?.0));
    println!("community {}", hex::encode(p.genesis.community_id()));
    println!("kid      {}", bundle.kid_of(&p.public()?).unwrap_or(255));
    println!("epoch    {}", secret.epoch());
    println!("roster   {} member(s)", bundle.roster.len());
    // Fingerprint (not the key) of slot 0's SFrame key, for cross-implementation checks.
    use sha2::Digest;
    println!("key0-fp  {}", hex::encode(&sha2::Sha256::digest(secret.sframe_base_key(0))[..6]));
    Ok(())
}

/// SFU URLs to try, most preferred first: the community's admin-signed route
/// when one is published, otherwise the `--sfu` value.
async fn sfu_candidates(fallback: &str) -> Vec<String> {
    if let Ok(Some(p)) = profile::Profile::load() {
        match p.route().await {
            Ok(Some(r)) => return r.sfus,
            Ok(None) => {}
            Err(e) => tracing::warn!(%e, "could not fetch the SFU route; using --sfu"),
        }
    }
    vec![fallback.to_string()]
}

/// Connect to the first reachable candidate, trying `start` first and wrapping.
async fn connect_any(cands: &[String], start: usize) -> Result<(Signaling, tokio::sync::mpsc::Receiver<(String, serde_json::Value)>, usize)> {
    for k in 0..cands.len() {
        let i = (start + k) % cands.len();
        match tokio::time::timeout(std::time::Duration::from_secs(3), Signaling::connect(&cands[i])).await {
            Ok(Ok((sig, ev))) => return Ok((sig, ev, i)),
            Ok(Err(e)) => tracing::warn!(url = %cands[i], %e, "sfu unreachable"),
            Err(_) => tracing::warn!(url = %cands[i], "sfu connect timed out"),
        }
    }
    bail!("no SFU reachable among {} candidate(s)", cands.len())
}

/// `Write` handle shared across receive threads so the output (file/ffplay)
/// survives a failover that replaces the receiver.
#[derive(Clone)]
struct SharedOut(std::sync::Arc<std::sync::Mutex<Box<dyn std::io::Write + Send>>>);

impl std::io::Write for SharedOut {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().write(b)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.lock().unwrap().flush()
    }
}

/// Join the SFU. With a community profile this presents a session token and
/// keeps it fresh so the SFU only serves current members.
async fn join_sfu(sig: &signaling::Signaling) -> Result<JoinResult> {
    let Some(p) = profile::Profile::load()? else {
        return sig.call(methods::JOIN, json!({})).await;
    };
    let token = p.session_token().await?;
    let joined: JoinResult = sig.call(methods::JOIN, json!({ "token": token })).await?;
    let sig = sig.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(120)).await;
            let r = match p.session_token().await {
                Ok(t) => sig.call_unit("refreshToken", json!({ "token": t })).await,
                Err(e) => Err(e),
            };
            if let Err(e) = r {
                // Only an explicit refusal (revoked) ends the session; a
                // control-service outage keeps the stream until the token lapses.
                if format!("{e:#}").contains("token refused") {
                    tracing::error!(%e, "session token refused; leaving");
                    std::process::exit(3);
                }
                tracing::warn!(%e, "session token refresh failed; will retry");
            }
        }
    });
    Ok(joined)
}

/// Native video receive path: consume a producer on a PlainTransport, depacketize
/// + SFrame-decrypt in Rust, decode+display via ffplay on stdin.
async fn watch(sfu: String, e2ee: bool, producer: Option<String>, dump: Option<String>) -> Result<()> {
    let cands = sfu_candidates(&sfu).await;
    let dec = e2ee.then(e2ee_decryptor);
    let mut ffplay = None;
    let out: Box<dyn std::io::Write + Send> = if let Some(path) = &dump {
        Box::new(std::fs::File::create(path)?)
    } else {
        let mut c = std::process::Command::new("ffplay")
            .args(["-loglevel", "warning", "-fflags", "nobuffer", "-flags", "low_delay", "-f", "h264", "-i", "-"])
            .stdin(std::process::Stdio::piped())
            .spawn()?;
        let stdin = c.stdin.take().unwrap();
        ffplay = Some(c);
        Box::new(stdin)
    };
    let out = SharedOut(std::sync::Arc::new(std::sync::Mutex::new(out)));
    let mut idx = 0usize;
    let mut lost_at: Option<std::time::Instant> = None;
    let session = async {
        loop {
            // (re)connect and consume the video producer; after a failover the
            // sender may take a moment to re-publish, so wait for it.
            let (sig, _events, used) = connect_any(&cands, idx).await?;
            idx = used;
            let join: JoinResult = join_sfu(&sig).await?;
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
            let mut producers = join.producers;
            let video = loop {
                if let Some(p) = producers.iter().find(|p| producer.as_deref().map_or(true, |id| p.producer_id == id) && p.kind == "video") {
                    break p.clone();
                }
                if std::time::Instant::now() > deadline { bail!("no video producer on sfu"); }
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                #[derive(serde::Deserialize, Default)]
                struct Listed { #[serde(default)] producers: Vec<ProducerInfo> }
                producers = sig.call::<Listed>(methods::LIST_PRODUCERS, json!({})).await.unwrap_or_default().producers;
            };
            tracing::info!(producer = %video.producer_id, sfu = %cands[used], "watching");
            let sock = std::net::UdpSocket::bind("127.0.0.1:0")?;
            let port = sock.local_addr()?.port();
            let tr: PlainRecvResult = sig.call(methods::CREATE_PLAIN_RECV, json!({})).await?;
            sig.call::<serde_json::Value>(methods::CONNECT_PLAIN, json!({
                "transportId": tr.transport_id, "ip": "127.0.0.1", "port": port,
            })).await?;
            let c: serde_json::Value = sig.call(methods::CONSUME_PLAIN, json!({
                "transportId": tr.transport_id, "producerId": video.producer_id,
            })).await?;
            let ssrc = c["rtpParameters"]["encodings"][0]["ssrc"].as_u64()
                .ok_or_else(|| anyhow::anyhow!("no consumer ssrc"))? as u32;
            if let Some(t) = lost_at.take() {
                tracing::info!(ms = t.elapsed().as_millis() as u64, sfu = %cands[used], "viewer failover complete");
            }
            let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let _recv = media::rtp_recv::h264_recv_loop_stoppable(sock, ssrc, dec.clone(), out.clone(), stop.clone());
            sig.wait_closed().await;
            stop.store(true, std::sync::atomic::Ordering::Relaxed);
            lost_at = Some(std::time::Instant::now());
            tracing::warn!(sfu = %cands[used], "sfu connection lost; failing over");
            idx = (used + 1) % cands.len();
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    };
    match ffplay.as_mut() {
        Some(c) => {
            tokio::select! {
                r = session => r?,
                _ = tokio::task::spawn_blocking({ let mut c = ffplay.take().unwrap(); move || c.wait() }) => {}
            }
            Ok(())
        }
        None => { tracing::info!("dumping; ctrl-c to stop"); session.await }
    }
}

async fn test_audio(sfu: String, seconds: u64, e2ee: bool) -> Result<()> {
    let (sig, _events) = Signaling::connect(&sfu).await?;
    let _join: JoinResult = join_sfu(&sig).await?;
    let mut children = Vec::new();
    let (level_tx, _level_rx) = std_mpsc::channel();
    let dest = RtpDest { ip: String::new(), port: 0, payload_type: MIC_PT, ssrc: 0x2b2b02, name: "tone".into() };
    let track = start_audio_source(&sig, dest, e2ee, &mut children, level_tx, "test-audio").await?;
    tokio::time::sleep(std::time::Duration::from_secs(seconds)).await;
    let bytes = producer_bytes(&sig, &track.producer_id).await;
    for mut c in children { let _ = c.kill(); }
    println!("audio sfu_bytes={bytes}");
    if bytes > 5_000 { println!("RUST AUDIO PATH OK"); Ok(()) } else { bail!("sfu counted no audio bytes") }
}

async fn produce_test_video(sig: &Signaling, ssrc: u32) -> Result<(PlainSendResult, ProduceResult)> {
    let t: PlainSendResult = sig.call(methods::CREATE_PLAIN_SEND, json!({})).await?;
    let produced: ProduceResult = sig.call(methods::PRODUCE_PLAIN, json!({
        "transportId": t.transport_id, "kind": "video",
        "rtpParameters": media::rtp::video_h264(
            &RtpDest { ip: t.ip.clone(), port: t.port, payload_type: VIDEO_PT, ssrc, name: "t".into() }, "0"),
        "appData": { "stream": "test-video" },
    })).await?;
    Ok((t, produced))
}

fn spawn_rtcp_logger(sender: &std::sync::Arc<std::sync::Mutex<media::rtp_send::RtpSender>>) -> Result<()> {
    let rtcp_sock = sender.lock().unwrap().try_clone_socket()?;
    let (rtcp_tx, rtcp_rx) = std_mpsc::channel();
    std::thread::spawn(move || media::rtp_send::RtpSender::rtcp_loop(rtcp_sock, rtcp_tx));
    std::thread::spawn(move || while let Ok(ev) = rtcp_rx.recv() { tracing::info!(?ev, "rtcp"); });
    Ok(())
}

async fn test_video(sfu: String, seconds: u64, e2ee: bool) -> Result<()> {
    let cands = sfu_candidates(&sfu).await;
    let (sig, _events, idx) = connect_any(&cands, 0).await?;
    let _join: JoinResult = join_sfu(&sig).await?;
    let ssrc: u32 = 0x1a1a01;
    let (t, produced) = produce_test_video(&sig, ssrc).await?;
    let before = producer_bytes(&sig, &produced.producer_id).await;
    let current = std::sync::Arc::new(std::sync::Mutex::new((sig.clone(), produced.producer_id.clone(), before)));

    let (mut enc, mut stdin, stdout) = media::ffmpeg::h264_annexb_encoder("bgra", 640, 360, 30, 1_500_000)?;
    let sender = std::sync::Arc::new(std::sync::Mutex::new(
        media::rtp_send::RtpSender::connect(&t.ip, t.port, VIDEO_PT, ssrc)?));
    spawn_rtcp_logger(&sender)?;
    let e2ee_enc = e2ee.then(e2ee_encryptor);
    let _pump = media::rtp_send::h264_rtp_pump(stdout, sender.clone(),
        e2ee_enc.as_ref().map(|e| e.share()));

    // Failover: when the SFU connection drops, publish on the next SFU of the
    // route and point the running RTP stream at its transport. The encoder and
    // packetizer keep running; viewers wait for the next keyframe (<= 2 s GOP).
    {
        let (cands, sender, current) = (cands.clone(), sender.clone(), current.clone());
        tokio::spawn(async move {
            let mut idx = idx;
            loop {
                let sig = current.lock().unwrap().0.clone();
                sig.wait_closed().await;
                let t0 = std::time::Instant::now();
                tracing::warn!("sfu connection lost; failing over");
                loop {
                    idx = (idx + 1) % cands.len();
                    let attempt = async {
                        let (sig, _ev, used) = connect_any(&cands, idx).await?;
                        join_sfu(&sig).await?;
                        let (t, produced) = produce_test_video(&sig, ssrc).await?;
                        Ok::<_, anyhow::Error>((sig, used, t, produced))
                    };
                    match attempt.await {
                        Ok((sig, used, t, produced)) => {
                            idx = used;
                            if let Err(e) = sender.lock().unwrap().retarget(&t.ip, t.port) { tracing::error!(%e, "retarget"); continue }
                            let _ = spawn_rtcp_logger(&sender);
                            let base = producer_bytes(&sig, &produced.producer_id).await;
                            *current.lock().unwrap() = (sig, produced.producer_id, base);
                            tracing::info!(ms = t0.elapsed().as_millis() as u64, sfu = %cands[used], "sender failover complete");
                            break;
                        }
                        Err(e) => { tracing::warn!(%e, "failover attempt failed"); tokio::time::sleep(std::time::Duration::from_millis(500)).await; }
                    }
                }
            }
        });
    }

    // feed testsrc2 frames into the encoder stdin
    let mut src = std::process::Command::new("ffmpeg")
        .args(["-hide_banner", "-loglevel", "error", "-f", "lavfi",
               "-i", "testsrc2=size=640x360:rate=30", "-f", "rawvideo",
               "-pix_fmt", "bgra", "-"])
        .stdout(std::process::Stdio::piped())
        .spawn()?;
    let mut src_out = src.stdout.take().unwrap();
    let t_end = std::time::Instant::now() + std::time::Duration::from_secs(seconds);
    let mut frame = vec![0u8; 640 * 360 * 4];
    let mut n = 0u64;
    while std::time::Instant::now() < t_end {
        // blocking read on a dedicated thread would be cleaner; frames arrive at
        // 30 fps so this stays short and lets the runtime run the failover task
        let r = tokio::task::block_in_place(|| src_out.read_exact(&mut frame));
        if r.is_err() { break }
        if stdin.write_all(&frame).is_err() { break }
        n += 1;
    }
    drop(stdin); // EOF -> encoder flushes
    let _ = enc.wait();
    let _ = src.kill();
    tokio::time::sleep(std::time::Duration::from_millis(800)).await;
    let (sig, pid, base) = current.lock().unwrap().clone();
    let after = producer_bytes(&sig, &pid).await;
    println!("frames_in={n} sfu_bytes {} -> {} (delta {})", base, after, after.saturating_sub(base));
    if after > base + 10_000 { println!("RUST RTP PATH OK"); Ok(()) }
    else { bail!("sfu counted no video bytes — packetizer broken") }
}

async fn producer_bytes(sig: &Signaling, id: &str) -> u64 {
    #[derive(serde::Deserialize)]
    struct Stats { stats: Vec<serde_json::Value> }
    let s: Stats = sig.call(methods::PRODUCER_STATS, json!({ "producerId": id })).await.unwrap_or(Stats { stats: vec![] });
    s.stats.iter().map(|x| x["byteCount"].as_u64().unwrap_or(0)).sum()
}

fn list_audio() -> Result<()> {
    let streams = media::pw::list_output_streams()?;
    if streams.is_empty() {
        println!("no playback streams right now — start the game/app first");
    }
    for s in streams {
        println!("serial={:<8} node={:<5} app={}  ({})", s.serial, s.node_id, s.app_name, s.media_name);
    }
    Ok(())
}

fn list_mics() -> Result<()> {
    for s in media::pw::list_sources()? {
        println!("serial={:<8} node={:<5} {}  ({})", s.serial, s.node_id, s.name, s.description);
    }
    Ok(())
}

struct SendTrack {
    /// Producer registered on the SFU (for pause/mute later).
    #[allow(dead_code)]
    producer_id: String,
}

/// PCM tap: read pw-record stdout, compute RMS, forward to ffmpeg stdin.
/// Killing two birds: metering is "exactly what gets transmitted".
fn pump_pcm(mut src: impl Read + Send + 'static, mut dst: impl Write + Send + 'static, level: std_mpsc::Sender<(String, f64)>, name: &'static str) {
    std::thread::spawn(move || {
        let mut buf = vec![0u8; 960 * 4]; // 10ms stereo s16
        loop {
            match src.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let chunk = &buf[..n];
                    let mut peak: i32 = 0;
                    for b in chunk.chunks_exact(2) {
                        peak = peak.max((b[0] as i16 | (b[1] as i16) << 8).unsigned_abs() as i32);
                    }
                    let db = if peak == 0 { -120.0 } else { 20.0 * (peak as f64 / 32768.0).log10() };
                    let _ = level.send((name.to_string(), db));
                    if dst.write_all(chunk).is_err() { break }
                }
            }
        }
    });
}

/// PipeWire frames -> ffmpeg rawvideo stdin. Respawns encoder on Format
/// changes (e.g. window resize switches dimensions).
/// Holds the encoder child + whichever stdin writes frames into it.
enum VideoStdin {
    /// ffmpeg muxes RTP itself (VP8 path — transitional).
    Muxed(media::ffmpeg::EncoderProc),
    /// ffmpeg emits Annex-B on stdout; Rust packetizes RTP (H.264 path).
    AnnexB { stdin: std::process::ChildStdin, child: Child },
}

impl VideoStdin {
    /// Kill a replaced encoder — dropping a Child detaches it and the orphaned
    /// ffmpeg would block forever writing to a pipe nobody reads.
    fn kill(&mut self) {
        match self {
            Self::Muxed(p) => { let _ = p.child.kill(); }
            Self::AnnexB { child, .. } => { let _ = child.kill(); }
        }
    }
}

impl Write for VideoStdin {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Muxed(p) => p.stdin.write(buf),
            Self::AnnexB { stdin, .. } => stdin.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Muxed(p) => p.stdin.flush(),
            Self::AnnexB { stdin, .. } => stdin.flush(),
        }
    }
}

fn pump_video(
    rx: std_mpsc::Receiver<FrameMsg>,
    dest: RtpDest,
    codec: media::VideoCodec,
    bitrate: u32,
    e2ee: bool,
    level: std_mpsc::Sender<(String, f64)>,
) {
    std::thread::spawn(move || {
        let _ = level; // video has no RMS meter; fps logged below
        // One RTP socket per transport, shared across encoder restarts:
        // mediasoup's comedia locks to the first-learned source tuple, so a
        // re-negotiation that created a new socket would silently blackhole
        // the stream (this exact bug froze video after a Paused->Streaming
        // flip while the orphaned rtcp thread kept logging RRs).
        let sender = match media::rtp_send::RtpSender::connect(
            &dest.ip, dest.port, dest.payload_type, dest.ssrc,
        ) {
            Ok(s) => std::sync::Arc::new(std::sync::Mutex::new(s)),
            Err(e) => { tracing::error!(%e, "rtp sender"); return }
        };
        if let Ok(rtcp_sock) = sender.lock().unwrap().try_clone_socket() {
            let (rtcp_tx, rtcp_rx) = std_mpsc::channel();
            std::thread::spawn(move || media::rtp_send::RtpSender::rtcp_loop(rtcp_sock, rtcp_tx));
            std::thread::spawn(move || {
                while let Ok(ev) = rtcp_rx.recv() { tracing::info!(?ev, "rtcp"); }
            });
        }
        let e2ee_enc = e2ee.then(e2ee_encryptor);
        let mut enc: Option<VideoStdin> = None;
        let mut n = 0u64;
        let mut t0 = std::time::Instant::now();
        while let Ok(msg) = rx.recv() {
            match msg {
                FrameMsg::Format(info) => {
                    tracing::info!(?info, "encoder input format");
                    if let Some(old) = enc.as_mut() { old.kill(); }
                    enc = match codec {
                        media::VideoCodec::H264 => {
                            match media::ffmpeg::h264_annexb_encoder(
                                &info.pix_fmt, info.width, info.height, info.fps, bitrate,
                            ) {
                                Ok((child, stdin, stdout)) => {
                                    media::rtp_send::h264_rtp_pump(
                                        stdout, sender.clone(),
                                        e2ee_enc.as_ref().map(|e| e.share()),
                                    );
                                    Some(VideoStdin::AnnexB { stdin, child })
                                }
                                Err(e) => { tracing::error!(%e, "spawn video encoder"); None }
                            }
                        }
                        media::VideoCodec::Vp8 => {
                            match media::ffmpeg::video_encoder(
                                &dest, &info.pix_fmt, info.width, info.height, info.fps, bitrate, codec,
                            ) {
                                Ok(e) => Some(VideoStdin::Muxed(e)),
                                Err(e) => { tracing::error!(%e, "spawn video encoder"); None }
                            }
                        }
                    };
                }
                FrameMsg::Frame(data) => {
                    if let Some(w) = enc.as_mut() {
                        if w.write_all(&data).is_err() {
                            tracing::error!("encoder stdin closed");
                            enc = None;
                        }
                        n += 1;
                        let dt = t0.elapsed().as_secs_f32();
                        if dt >= 5.0 {
                            tracing::info!(fps = n as f32 / dt, "capture rate");
                            n = 0; t0 = std::time::Instant::now();
                        }
                    }
                }
                FrameMsg::Drained => { tracing::warn!("capture drained"); enc = None; }
            }
        }
    });
}

async fn stream(args: StreamArgs) -> Result<()> {
    let (sig, mut events) = Signaling::connect(&args.sfu).await?;
    let join: JoinResult = join_sfu(&sig).await?;
    tracing::info!(peer = %join.peer_id, "joined sfu");

    let base: u32 = (std::process::id() & 0xFFFF) << 8;
    let mut sends: Vec<SendTrack> = Vec::new();
    let mut children: Vec<Child> = Vec::new();
    // Remote audio players keyed by producer id so we can kill them the moment
    // the producer closes instead of waiting for ffmpeg's input timeout.
    let mut players: HashMap<String, Child> = HashMap::new();
    let (level_tx, level_rx) = std_mpsc::channel::<(String, f64)>();
    let (async_tx, mut async_rx) = tokio::sync::mpsc::unbounded_channel();
    std::thread::spawn(move || while let Ok(v) = level_rx.recv() { let _ = async_tx.send(v); });

    // --- video: portal picker -> pipewire capture -> ffmpeg -> rtp ---
    let session = portal::pick_screen().await?;
    let t: PlainSendResult = sig.call(methods::CREATE_PLAIN_SEND, json!({})).await?;
    let dest = RtpDest { ip: t.ip, port: t.port, payload_type: VIDEO_PT, ssrc: base | 1, name: "video".into() };
    let produced: ProduceResult = sig.call(methods::PRODUCE_PLAIN, json!({
        "transportId": t.transport_id, "kind": "video",
        "rtpParameters": match args.codec {
            Codec::Vp8 => media::rtp::video_vp8(&dest, "0"),
            Codec::H264 => media::rtp::video_h264(&dest, "0"),
        },
        "appData": { "stream": "screen" },
    })).await?;
    sends.push(SendTrack { producer_id: produced.producer_id });
    let (_capture, frame_rx) = capture::start(session.node_id)?;
    pump_video(frame_rx, dest, match args.codec {
        Codec::Vp8 => media::VideoCodec::Vp8,
        Codec::H264 => media::VideoCodec::H264,
    }, args.bitrate, args.e2ee, level_tx.clone());

    // --- audio sends: pw-record -> rms meter -> ffmpeg opus -> rtp ---
    if !args.no_game_audio {
        if let Some(target) = resolve_audio_target(args.audio_target)? {
            let dest = RtpDest { ip: String::new(), port: 0, payload_type: GAME_PT, ssrc: base | 2, name: "game".into() };
            sends.push(start_audio(&sig, dest, args.e2ee, Some(target), 128_000, "game-audio", &mut children, level_tx.clone()).await?);
        }
    }
    if !args.no_mic {
        let dest = RtpDest { ip: String::new(), port: 0, payload_type: MIC_PT, ssrc: base | 3, name: "mic".into() };
        sends.push(start_audio(&sig, dest, args.e2ee, args.mic, 64_000, "mic", &mut children, level_tx.clone()).await?);
    }

    // --- consume remote audio ---
    for p in join.producers.iter().filter(|p| p.peer_id != join.peer_id) {
        if let Err(e) = handle_remote(&sig, p.clone(), &mut players, args.e2ee).await {
            tracing::warn!(%e, producer = %p.producer_id, "consume failed");
        }
    }

    println!("streaming — ctrl-c to stop");
    let mut levels: HashMap<String, f64> = HashMap::new();
    let mut meter_tick = tokio::time::interval(std::time::Duration::from_millis(1500));
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            ev = events.recv() => {
                let Some((event, data)) = ev else { break };
                match event.as_str() {
                    "newProducer" => {
                        if let Ok(p) = serde_json::from_value::<ProducerInfo>(data) {
                            if p.peer_id != join.peer_id {
                                if let Err(e) = handle_remote(&sig, p, &mut players, args.e2ee).await {
                                    tracing::warn!(%e, "consume failed");
                                }
                            }
                        }
                    }
                    "producerClosed" => {
                        tracing::info!(?data, "remote producer closed");
                        if let Some(id) = data.get("producerId").and_then(|v| v.as_str()) {
                            if let Some(mut c) = players.remove(id) {
                                let _ = c.kill();
                            }
                        }
                    }
                    _ => {}
                }
            }
            _ = meter_tick.tick() => {
                while let Ok((name, db)) = async_rx.try_recv() { levels.insert(name, db); }
                if !levels.is_empty() {
                    let parts: Vec<String> = levels.iter()
                        .map(|(k, v)| format!("{k}: {:.0} dB", v)).collect();
                    eprint!("\rlevel  {}\x1b[K", parts.join("  "));
                }
            }
        }
    }

    println!("\nstopping");
    for mut c in children { let _ = c.kill(); }
    for (_, mut c) in players { let _ = c.kill(); }
    drop(session);
    Ok(())
}

/// pw-record -> pump (with RMS meter) -> ffmpeg opus -> RTP. `target` is the
/// PipeWire serial of the app stream; None = default source (mic).
async fn start_audio_source(
    sig: &Signaling,
    dest: RtpDest,
    e2ee: bool,
    children: &mut Vec<Child>,
    level: std_mpsc::Sender<(String, f64)>,
    label: &'static str,
) -> Result<SendTrack> {
    start_audio_impl(sig, dest, e2ee, None, 64_000, label, children, level, true).await
}

async fn start_audio(
    sig: &Signaling,
    dest: RtpDest,
    e2ee: bool,
    target: Option<u64>,
    bitrate: u32,
    label: &'static str,
    children: &mut Vec<Child>,
    level: std_mpsc::Sender<(String, f64)>,
) -> Result<SendTrack> {
    start_audio_impl(sig, dest, e2ee, target, bitrate, label, children, level, false).await
}

async fn start_audio_impl(
    sig: &Signaling,
    mut dest: RtpDest,
    e2ee: bool,
    target: Option<u64>,
    bitrate: u32,
    label: &'static str,
    children: &mut Vec<Child>,
    level: std_mpsc::Sender<(String, f64)>,
    tone: bool,
) -> Result<SendTrack> {
    let t: PlainSendResult = sig.call(methods::CREATE_PLAIN_SEND, json!({})).await?;
    dest.ip = t.ip; dest.port = t.port;
    let produced: ProduceResult = sig.call(methods::PRODUCE_PLAIN, json!({
        "transportId": t.transport_id, "kind": "audio",
        "rtpParameters": media::rtp::audio_opus(&dest, "1"),
        "appData": { "stream": label },
    })).await?;
    let mut rec = match tone {
        true => media::ffmpeg::audio_tone()?,
        false => media::ffmpeg::audio_capture(target)?,
    };
    // With E2EE, ffmpeg targets a local relay that SFrame-protects each Opus
    // payload and forwards to the SFU from one persistent socket.
    let mut ff_dest = dest.clone();
    if e2ee {
        let listen = std::net::UdpSocket::bind("127.0.0.1:0")?;
        ff_dest.ip = "127.0.0.1".into();
        ff_dest.port = listen.local_addr()?.port();
        let sfu: std::net::SocketAddr = format!("{}:{}", dest.ip, dest.port).parse()
            .context("sfu rtp address")?;
        media::rtp_relay::encrypt_relay(listen, std::net::UdpSocket::bind("0.0.0.0:0")?, sfu, e2ee_encryptor());
    }
    let enc = media::ffmpeg::audio_encoder(&ff_dest, bitrate)?;
    let stdout = rec.stdout.take().context("pw-record stdout")?;
    pump_pcm(stdout, enc.stdin, level, label);
    children.push(rec);
    children.push(enc.child);
    tracing::info!(%label, producer = %produced.producer_id, port = dest.port, "producing");
    Ok(SendTrack { producer_id: produced.producer_id })
}

/// Consume a remote audio producer into local playback (ffmpeg -f pulse).
async fn handle_remote(
    sig: &Signaling,
    p: ProducerInfo,
    players: &mut HashMap<String, Child>,
    e2ee: bool,
) -> Result<()> {
    if p.kind != "audio" {
        tracing::info!(producer = %p.producer_id, "skipping remote video (M0)");
        return Ok(());
    }
    let t: PlainRecvResult = sig.call(methods::CREATE_PLAIN_RECV, json!({})).await?;
    let tmp = std::net::UdpSocket::bind("127.0.0.1:0")?;
    let port = tmp.local_addr()?.port(); // where the local ffmpeg player listens
    // With E2EE the SFU sends to a relay socket that decrypts and forwards to
    // the player; otherwise it sends straight to the player's port.
    let relay_in = if e2ee { Some(std::net::UdpSocket::bind("127.0.0.1:0")?) } else { None };
    let sfu_port = relay_in.as_ref().map_or(Ok(port), |s| s.local_addr().map(|a| a.port()))?;
    drop(tmp);
    if let Some(l) = relay_in {
        media::rtp_relay::decrypt_relay(l, std::net::SocketAddr::from(([127, 0, 0, 1], port)), e2ee_decryptor());
    }
    sig.call_unit(methods::CONNECT_PLAIN, json!({
        "transportId": t.transport_id, "ip": "127.0.0.1", "port": sfu_port,
    })).await?;
    let c: ConsumePlainResult = sig.call(methods::CONSUME_PLAIN, json!({
        "transportId": t.transport_id, "producerId": p.producer_id,
    })).await?;
    let pt = c.rtp_parameters["codecs"][0]["payloadType"].as_u64()
        .context("consumer rtpParameters missing payloadType")? as u8;
    let ssrc = c.rtp_parameters["encodings"][0]["ssrc"].as_u64()
        .context("consumer rtpParameters missing ssrc")? as u32;
    let label = format!("laira-{}", &p.peer_id[..8.min(p.peer_id.len())]);
    players.insert(p.producer_id.clone(), media::ffmpeg::audio_player(port, pt, ssrc, &label)?);
    tracing::info!(producer = %p.producer_id, %port, "consuming remote audio");
    Ok(())
}

fn resolve_audio_target(arg: Option<u64>) -> Result<Option<u64>> {
    if let Some(s) = arg {
        return Ok(Some(s));
    }
    let streams = media::pw::list_output_streams()?;
    match streams.len() {
        0 => {
            tracing::warn!("no app playback streams found — game audio disabled");
            Ok(None)
        }
        1 => {
            tracing::info!(app = %streams[0].app_name, serial = streams[0].serial,
                "auto-selected audio target");
            Ok(Some(streams[0].serial))
        }
        _ => {
            eprintln!("multiple playback streams — pick one with --audio-target:");
            for s in &streams {
                eprintln!("  serial={:<8} app={}  ({})", s.serial, s.app_name, s.media_name);
            }
            bail!("ambiguous audio target");
        }
    }
}
