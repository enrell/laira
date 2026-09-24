//! PipeWire screen capture via the portal stream (the OBS `linux-pipewire`
//! model): connect a Video/Input stream to the granted node, negotiate a raw
//! format we can hand straight to ffmpeg's rawvideo demuxer.
//!
//! Runs a PipeWire MainLoop on its own thread; frames come back through a
//! bounded channel (full = drop, we never queue latency).

use anyhow::{Context, Result};
use pipewire as pw;
use pw::spa;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::SyncSender;
use std::sync::Arc;

pub struct Capture {
    quit: Arc<AtomicBool>,
}

impl Capture {
    /// Signal the capture loop to stop dequeuing. The PipeWire mainloop has no
    /// Send-safe quit handle in this crate version; the thread detaches and
    /// dies with the process — acceptable for M0's stream-until-exit model.
    pub fn stop(&self) {
        self.quit.store(true, Ordering::Relaxed);
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        self.stop();
    }
}

#[derive(Debug, Clone)]
pub struct VideoInfo {
    /// ffmpeg `-pixel_format` name.
    pub pix_fmt: String,
    pub width: u32,
    pub height: u32,
    pub fps: u32,
}

#[derive(Debug)]
pub enum FrameMsg {
    /// Negotiated — spawn/restart the encoder for this format.
    Format(VideoInfo),
    /// Tightly-packed pixel data (stride already removed).
    Frame(Vec<u8>),
    /// Producer stopped sending (window closed, capture revoked).
    Drained,
}

struct State {
    tx: SyncSender<FrameMsg>,
    format: spa::param::video::VideoInfoRaw,
    quit: Arc<AtomicBool>,
    announced: bool,
    frames: u64,
}

fn spa_to_ffmpeg(fmt: spa::param::video::VideoFormat) -> Option<&'static str> {
    use spa::param::video::VideoFormat as F;
    Some(match fmt {
        F::BGRA => "bgra",
        F::BGRx => "bgr0",
        F::RGBA => "rgba",
        F::RGBx => "rgb0",
        F::YUY2 => "yuyv422",
        F::I420 => "yuv420p",
        F::NV12 => "nv12",
        _ => return None,
    })
}

/// Start capturing `node_id` (from the portal) on a dedicated thread.
/// Frames arrive on the returned receiver until `stop()` / drop.
pub fn start(node_id: u32) -> Result<(Capture, std::sync::mpsc::Receiver<FrameMsg>)> {
    pw::init();
    let (tx, rx) = std::sync::mpsc::sync_channel::<FrameMsg>(3);
    let quit = Arc::new(AtomicBool::new(false));
    let quit_t = quit.clone();
    let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel::<Result<(), String>>(0);
    std::thread::spawn(move || {
        if let Err(e) = run_loop(node_id, tx, quit_t, ready_tx.clone()) {
            tracing::error!(%e, "pipewire capture loop failed");
            let _ = ready_tx.send(Err(e.to_string()));
        }
    });
    ready_rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .context("pipewire capture init")?
        .map_err(|e| anyhow::anyhow!(e))?;
    Ok((Capture { quit }, rx))
}

fn run_loop(
    node_id: u32,
    tx: SyncSender<FrameMsg>,
    quit: Arc<AtomicBool>,
    ready: std::sync::mpsc::SyncSender<Result<(), String>>,
) -> Result<()> {
    let mainloop = pw::main_loop::MainLoopRc::new(None)?;
    let context = pw::context::ContextRc::new(&mainloop, None)?;
    let core = context.connect_rc(None)?;

    let stream = pw::stream::StreamBox::new(
        &core,
        "laira-capture",
        pw::properties::properties! {
            *pw::keys::MEDIA_TYPE => "Video",
            *pw::keys::MEDIA_CATEGORY => "Capture",
            *pw::keys::MEDIA_ROLE => "Screen",
        },
    )?;

    let state = State { tx, format: Default::default(), quit, announced: false, frames: 0 };
    let _listener = stream
        .add_local_listener_with_user_data(state)
        .state_changed(|_, s, old, new| {
            tracing::info!(?old, ?new, "pw stream state");
            if matches!(new, pw::stream::StreamState::Error(_)) {
                s.quit.store(true, Ordering::Relaxed);
            }
        })
        .param_changed(|_, s, id, param| {
            let Some(param) = param else { return };
            if id != spa::param::ParamType::Format.as_raw() { return }
            let Ok((mt, ms)) = spa::param::format_utils::parse_format(param) else { return };
            if mt != spa::param::format::MediaType::Video
                || ms != spa::param::format::MediaSubtype::Raw { return }
            if s.format.parse(param).is_err() { return }
            let info = VideoInfo {
                pix_fmt: spa_to_ffmpeg(s.format.format()).unwrap_or("bgra").to_string(),
                width: s.format.size().width,
                height: s.format.size().height,
                fps: s.format.framerate().num.max(1),
            };
            tracing::info!(?info, "negotiated format");
            s.announced = true;
            let _ = s.tx.try_send(FrameMsg::Format(info));
        })
        .process(|stream, s| {
            if s.quit.load(Ordering::Relaxed) { return }
            let Some(mut buffer) = stream.dequeue_buffer() else { return };
            let datas = buffer.datas_mut();
            if datas.is_empty() { return }
            let d = &mut datas[0];
            let (offset, size, stride) = {
                let c = d.chunk();
                (c.offset() as usize, c.size() as usize, c.stride() as usize)
            };
            let Some(mem) = d.data() else {
                if s.frames == 0 { tracing::warn!("buffer not mapped (no MAP_BUFFERS?)"); }
                return;
            };
            if size == 0 || offset + size > mem.len() { return }

            let w = s.format.size().width as usize;
            let h = s.format.size().height as usize;
            let bpp = match s.format.format() {
                spa::param::video::VideoFormat::I420 | spa::param::video::VideoFormat::NV12 => 1,
                spa::param::video::VideoFormat::YUY2 => 2,
                _ => 4,
            };
            let row = w * bpp;
            let payload = &mem[offset..offset + size];
            let packed = if stride > 0 && stride != row {
                let mut out = Vec::with_capacity(row * h);
                for y in 0..h.min(size / stride) {
                    out.extend_from_slice(&payload[y * stride..y * stride + row]);
                }
                out
            } else {
                payload[..size.min(row * h)].to_vec()
            };
            s.frames += 1;
            let _ = s.tx.try_send(FrameMsg::Frame(packed));
        })
        .drained(|_, s| { let _ = s.tx.try_send(FrameMsg::Drained); })
        .register()?;

    // Offer packed RGB formats first — zero conversion for ffmpeg rawvideo.
    let obj = spa::pod::object!(
        spa::utils::SpaTypes::ObjectParamFormat,
        spa::param::ParamType::EnumFormat,
        spa::pod::property!(spa::param::format::FormatProperties::MediaType, Id,
            spa::param::format::MediaType::Video),
        spa::pod::property!(spa::param::format::FormatProperties::MediaSubtype, Id,
            spa::param::format::MediaSubtype::Raw),
        spa::pod::property!(spa::param::format::FormatProperties::VideoFormat,
            Choice, Enum, Id,
            spa::param::video::VideoFormat::BGRA,
            spa::param::video::VideoFormat::BGRA,
            spa::param::video::VideoFormat::BGRx,
            spa::param::video::VideoFormat::RGBA,
            spa::param::video::VideoFormat::RGBx),
        spa::pod::property!(spa::param::format::FormatProperties::VideoSize,
            Choice, Range, Rectangle,
            spa::utils::Rectangle { width: 1920, height: 1080 },
            spa::utils::Rectangle { width: 1, height: 1 },
            spa::utils::Rectangle { width: 4096, height: 4096 }),
        spa::pod::property!(spa::param::format::FormatProperties::VideoFramerate,
            Choice, Range, Fraction,
            spa::utils::Fraction { num: 30, denom: 1 },
            spa::utils::Fraction { num: 0, denom: 1 },
            spa::utils::Fraction { num: 1000, denom: 1 }),
    );
    let values: Vec<u8> = spa::pod::serialize::PodSerializer::serialize(
        std::io::Cursor::new(Vec::new()),
        &spa::pod::Value::Object(obj),
    ).context("serialize enumformat")?.0.into_inner();
    let mut params = [spa::pod::Pod::from_bytes(&values).context("pod")?];

    stream.connect(
        spa::utils::Direction::Input,
        Some(node_id),
        pw::stream::StreamFlags::AUTOCONNECT | pw::stream::StreamFlags::MAP_BUFFERS,
        &mut params,
    )?;

    let _ = ready.send(Ok(()));
    mainloop.run();
    Ok(())
}
