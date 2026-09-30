//! ffmpeg subprocess wrappers (the OBS model: capture ourselves, encode via
//! ffmpeg, RTP out of ffmpeg's own muxer). No GStreamer anywhere.

use crate::RtpDest;
use anyhow::{Context, Result};
use std::io::Write;
use std::process::{Child, ChildStdin, Command, Stdio};

pub struct EncoderProc {
    pub child: Child,
    pub stdin: ChildStdin,
}

fn base(cmd: &mut Command) -> &mut Command {
    cmd.arg("-hide_banner").arg("-loglevel").arg("warning")
}

/// rawvideo on stdin -> encoded -> RTP to the SFU's PlainTransport tuple.
pub fn video_encoder(
    dest: &RtpDest,
    pix_fmt: &str,
    width: u32,
    height: u32,
    fps: u32,
    bitrate: u32,
    codec: crate::VideoCodec,
) -> Result<EncoderProc> {
    // Portal screencast is variable-rate: PipeWire may negotiate a meaningless
    // framerate (0/1, 1/1). Clamp to a sane declaration and stamp frames by
    // arrival time so RTP timestamps stay correct when capture pauses.
    let fps = fps.clamp(15, 120);
    let mut cmd = Command::new("ffmpeg");
    base(&mut cmd)
        .args([
            "-f", "rawvideo",
            "-pixel_format", pix_fmt,
            "-video_size", &format!("{width}x{height}"),
            "-framerate", &fps.to_string(),
            "-use_wallclock_as_timestamps", "1",
            "-i", "pipe:0",
            "-an",
        ]);
    match codec {
        crate::VideoCodec::H264 => cmd.args([
            "-c:v", "libx264",
            "-preset", "veryfast",
            "-tune", "zerolatency",
            "-g", &(fps * 2).to_string(),
            "-bf", "0",
            "-pix_fmt", "yuv420p",
            "-b:v", &bitrate.to_string(),
            "-maxrate", &bitrate.to_string(),
            "-bufsize", &bitrate.to_string(),
        ]),
        crate::VideoCodec::Vp8 => cmd.args([
            "-c:v", "libvpx",
            "-deadline", "realtime",
            "-cpu-used", "8",
            "-g", &(fps * 2).to_string(),
            "-pix_fmt", "yuv420p",
            "-b:v", &bitrate.to_string(),
        ]),
    };
    cmd.args([
        "-f", "rtp",
        "-payload_type", &dest.payload_type.to_string(),
        "-ssrc", &dest.ssrc.to_string(),
        &format!("rtp://{}:{}", dest.ip, dest.port),
    ])
    .stdin(Stdio::piped())
    .stdout(Stdio::null())
    .stderr(Stdio::inherit());
    let mut child = cmd.spawn().context("spawn ffmpeg video")?;
    let stdin = child.stdin.take().context("ffmpeg stdin")?;
    Ok(EncoderProc { child, stdin })
}

/// rawvideo on stdin -> H.264 **Annex-B elementary stream** on stdout.
/// The Rust side packetizes RTP itself (see rtp_send.rs) so it owns the socket,
/// can read RTCP, and gets an insertion point for SFrame. `aud=1` makes x264
/// delimit every access unit with an AUD NAL — that's how the packetizer finds
/// frame boundaries.
pub fn h264_annexb_encoder(
    pix_fmt: &str,
    width: u32,
    height: u32,
    fps: u32,
    bitrate: u32,
) -> Result<(Child, ChildStdin, std::process::ChildStdout)> {
    let fps = fps.clamp(15, 120);
    let mut child = base(&mut Command::new("ffmpeg"))
        .args([
            "-f", "rawvideo",
            "-pixel_format", pix_fmt,
            "-video_size", &format!("{width}x{height}"),
            "-framerate", &fps.to_string(),
            "-use_wallclock_as_timestamps", "1",
            "-i", "pipe:0",
            "-an",
            "-c:v", "libx264",
            "-preset", "veryfast",
            "-tune", "zerolatency",
            "-g", &(fps * 2).to_string(),
            "-bf", "0",
            "-pix_fmt", "yuv420p",
            "-b:v", &bitrate.to_string(),
            "-maxrate", &bitrate.to_string(),
            "-bufsize", &bitrate.to_string(),
            "-x264-params", "aud=1",
            "-f", "h264",
            "pipe:1",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .context("spawn ffmpeg h264 es")?;
    let stdin = child.stdin.take().context("ffmpeg stdin")?;
    let stdout = child.stdout.take().context("ffmpeg stdout")?;
    Ok((child, stdin, stdout))
}

/// s16le/48k/stereo on stdin -> libopus -> RTP.
pub fn audio_encoder(dest: &RtpDest, bitrate: u32) -> Result<EncoderProc> {
    let mut child = base(&mut Command::new("ffmpeg"))
        .args([
            "-f", "s16le",
            "-ar", "48000",
            "-ch_layout", "stereo",
            "-i", "pipe:0",
            "-vn",
            "-c:a", "libopus",
            "-b:a", &bitrate.to_string(),
            "-frame_duration", "20",
            "-f", "rtp",
            "-payload_type", &dest.payload_type.to_string(),
            "-ssrc", &dest.ssrc.to_string(),
            &format!("rtp://{}:{}", dest.ip, dest.port),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .context("spawn ffmpeg audio")?;
    let stdin = child.stdin.take().context("ffmpeg stdin")?;
    Ok(EncoderProc { child, stdin })
}

/// pw-record capturing a PipeWire node (app playback stream via object.serial,
/// or the default source when None) -> raw s16le/48k/stereo on stdout.
pub fn audio_capture(target_serial: Option<u64>) -> Result<Child> {
    let mut cmd = Command::new("pw-record");
    if let Some(s) = target_serial {
        cmd.arg("--target").arg(s.to_string());
    }
    let child = cmd
        .args([
            "--format", "s16",
            "--rate", "48000",
            "--channels", "2",
            "--raw", "-",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("spawn pw-record")?;
    Ok(child)
}

/// Synthetic 440 Hz stereo tone as raw s16le/48k on stdout (test source that
/// stands in for pw-record; returned as a Child so callers treat it the same).
pub fn audio_tone() -> Result<Child> {
    base(&mut Command::new("ffmpeg"))
        .args([
            "-re", "-f", "lavfi", "-i", "sine=frequency=440:sample_rate=48000",
            "-ac", "2", "-f", "s16le", "-",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .context("spawn ffmpeg tone")
}

/// Play one remote Opus RTP stream through the local default output.
/// The SDP hands ffmpeg the payload-type mapping for the dynamic PT.
pub fn audio_player(listen_port: u16, payload_type: u8, ssrc: u32, label: &str) -> Result<Child> {
    let sdp = format!(
        "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=laira\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
         m=audio {listen_port} RTP/AVP {payload_type}\r\na=rtpmap:{payload_type} opus/48000/2\r\n\
         a=ssrc:{ssrc}\r\n"
    );
    let mut child = base(&mut Command::new("ffmpeg"))
        .args([
            "-protocol_whitelist", "file,pipe,udp,rtp",
            "-f", "sdp",
            "-i", "pipe:0",
            "-f", "pulse",
            label,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .context("spawn ffmpeg player")?;
    child
        .stdin
        .as_mut()
        .context("player stdin")?
        .write_all(sdp.as_bytes())?;
    // SDP read is one-shot; closing stdin tells ffmpeg to proceed.
    drop(child.stdin.take());
    Ok(child)
}
