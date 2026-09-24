//! laira-desktop M0: native capture + SFU streaming + return voice.
//! OBS stack: PipeWire capture -> FFmpeg encode -> RTP -> mediasoup.
//!
//!   laira-desktop list-audio        # pick --audio-target
//!   laira-desktop list-mics         # pick --mic
//!   laira-desktop stream            # portal picker -> stream to SFU

mod portal;
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
        Cmd::Stream(args) => stream(args).await,
        Cmd::TestVideo { sfu, seconds, e2ee } => test_video(sfu, seconds, e2ee).await,
        Cmd::Watch { sfu, e2ee, producer, dump } => watch(sfu, e2ee, producer, dump).await,
    }
}

/// Native video receive path: consume a producer on a PlainTransport, depacketize
/// + SFrame-decrypt in Rust, decode+display via ffplay on stdin.
async fn watch(sfu: String, e2ee: bool, producer: Option<String>, dump: Option<String>) -> Result<()> {
    let (sig, _events) = Signaling::connect(&sfu).await?;
    let join: JoinResult = sig.call(methods::JOIN, json!({})).await?;
    let video = join.producers.iter()
        .find(|p| producer.as_deref().map_or(true, |id| p.producer_id == id) && p.kind == "video")
        .ok_or_else(|| anyhow::anyhow!("no video producer on sfu"))?
        .clone();
    tracing::info!(producer = %video.producer_id, "watching");

    let sock = std::net::UdpSocket::bind("127.0.0.1:0")?;
    let port = sock.local_addr()?.port();
    let tr: PlainRecvResult = sig.call(methods::CREATE_PLAIN_RECV, json!({})).await?;
    sig.call::<serde_json::Value>(methods::CONNECT_PLAIN, json!({
        "transportId": tr.transport_id, "ip": "127.0.0.1", "port": port,
    })).await?;
    let c: serde_json::Value = sig.call(methods::CONSUME_PLAIN, json!({
        "transportId": tr.transport_id, "producerId": video.producer_id,
    })).await?;
    let ssrc = c["rtpParameters"]["encodings"][0]["ssrc"]
        .as_u64().ok_or_else(|| anyhow::anyhow!("no consumer ssrc"))? as u32;
    tracing::info!(consumer = %c["consumerId"], %ssrc, "consuming");

    let dec = e2ee.then(|| media::sframe::SframeDecryptor::new(&media::sframe::TEST_BASE_KEY));
    if let Some(path) = dump {
        let f = std::fs::File::create(&path)?;
        let _recv = media::rtp_recv::h264_recv_loop(sock, ssrc, dec, f);
        tracing::info!(%path, "dumping; ctrl-c to stop");
        loop { tokio::time::sleep(std::time::Duration::from_secs(1)).await; }
    }
    let mut ffplay = std::process::Command::new("ffplay")
        .args(["-loglevel", "warning", "-fflags", "nobuffer", "-flags", "low_delay",
               "-f", "h264", "-i", "-"])
        .stdin(std::process::Stdio::piped())
        .spawn()?;
    let _recv = media::rtp_recv::h264_recv_loop(sock, ssrc, dec, ffplay.stdin.take().unwrap());
    ffplay.wait()?;
    Ok(())
}

/// Pushes synthetic frames through the real H.264 Annex-B -> Rust RTP path
/// and verifies the SFU counts bytes on the producer.
async fn test_video(sfu: String, seconds: u64, e2ee: bool) -> Result<()> {
    let (sig, _events) = Signaling::connect(&sfu).await?;
    let _join: JoinResult = sig.call(methods::JOIN, json!({})).await?;
    let t: PlainSendResult = sig.call(methods::CREATE_PLAIN_SEND, json!({})).await?;
    let ssrc: u32 = 0x1a1a01;
    let produced: ProduceResult = sig.call(methods::PRODUCE_PLAIN, json!({
        "transportId": t.transport_id, "kind": "video",
        "rtpParameters": media::rtp::video_h264(
            &RtpDest { ip: t.ip.clone(), port: t.port, payload_type: VIDEO_PT, ssrc, name: "t".into() }, "0"),
        "appData": { "stream": "test-video" },
    })).await?;
    let before = producer_bytes(&sig, &produced.producer_id).await;

    let (mut enc, mut stdin, stdout) = media::ffmpeg::h264_annexb_encoder("bgra", 640, 360, 30, 1_500_000)?;
    let sender = std::sync::Arc::new(std::sync::Mutex::new(
        media::rtp_send::RtpSender::connect(&t.ip, t.port, VIDEO_PT, ssrc)?));
    let rtcp_sock = sender.lock().unwrap().try_clone_socket()?;
    let (rtcp_tx, rtcp_rx) = std_mpsc::channel();
    std::thread::spawn(move || media::rtp_send::RtpSender::rtcp_loop(rtcp_sock, rtcp_tx));
    std::thread::spawn(move || while let Ok(ev) = rtcp_rx.recv() { tracing::info!(?ev, "rtcp"); });
    let _pump = media::rtp_send::h264_rtp_pump(stdout, sender,
        e2ee.then(|| media::sframe::SframeEncryptor::new(&media::sframe::TEST_BASE_KEY)));

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
        if src_out.read_exact(&mut frame).is_err() { break }
        if stdin.write_all(&frame).is_err() { break }
        n += 1;
    }
    drop(stdin); // EOF -> encoder flushes
    let _ = enc.wait();
    let _ = src.kill();
    tokio::time::sleep(std::time::Duration::from_millis(800)).await;
    let after = producer_bytes(&sig, &produced.producer_id).await;
    println!("frames_in={n} sfu_bytes {} -> {} (delta {})", before, after, after.saturating_sub(before));
    if after > before + 10_000 { println!("RUST RTP PATH OK"); Ok(()) }
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
                                        e2ee.then(|| media::sframe::SframeEncryptor::new(&media::sframe::TEST_BASE_KEY)),
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
    let join: JoinResult = sig.call(methods::JOIN, json!({})).await?;
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
            sends.push(start_audio(&sig, dest, Some(target), 128_000, "game-audio", &mut children, level_tx.clone()).await?);
        }
    }
    if !args.no_mic {
        let dest = RtpDest { ip: String::new(), port: 0, payload_type: MIC_PT, ssrc: base | 3, name: "mic".into() };
        sends.push(start_audio(&sig, dest, args.mic, 64_000, "mic", &mut children, level_tx.clone()).await?);
    }

    // --- consume remote audio ---
    for p in join.producers.iter().filter(|p| p.peer_id != join.peer_id) {
        if let Err(e) = handle_remote(&sig, p.clone(), &mut players).await {
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
                                if let Err(e) = handle_remote(&sig, p, &mut players).await {
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
async fn start_audio(
    sig: &Signaling,
    mut dest: RtpDest,
    target: Option<u64>,
    bitrate: u32,
    label: &'static str,
    children: &mut Vec<Child>,
    level: std_mpsc::Sender<(String, f64)>,
) -> Result<SendTrack> {
    let t: PlainSendResult = sig.call(methods::CREATE_PLAIN_SEND, json!({})).await?;
    dest.ip = t.ip; dest.port = t.port;
    let produced: ProduceResult = sig.call(methods::PRODUCE_PLAIN, json!({
        "transportId": t.transport_id, "kind": "audio",
        "rtpParameters": media::rtp::audio_opus(&dest, "1"),
        "appData": { "stream": label },
    })).await?;
    let mut rec = media::ffmpeg::audio_capture(target)?;
    let enc = media::ffmpeg::audio_encoder(&dest, bitrate)?;
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
) -> Result<()> {
    if p.kind != "audio" {
        tracing::info!(producer = %p.producer_id, "skipping remote video (M0)");
        return Ok(());
    }
    let t: PlainRecvResult = sig.call(methods::CREATE_PLAIN_RECV, json!({})).await?;
    let tmp = std::net::UdpSocket::bind("127.0.0.1:0")?;
    let port = tmp.local_addr()?.port();
    drop(tmp);
    sig.call_unit(methods::CONNECT_PLAIN, json!({
        "transportId": t.transport_id, "ip": "127.0.0.1", "port": port,
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
