//! Media pipeline for the M0 vertical proof — OBS stack: PipeWire capture +
//! FFmpeg encode/mux. No GStreamer anywhere; the only runtime dependencies
//! are `ffmpeg`, `pw-record` and libpipewire, all stock on a desktop Linux.
//!
//! Send: portal PipeWire stream -> raw frames -> ffmpeg -> RTP -> SFU
//!       pw-record (app stream or mic) -> ffmpeg opus -> RTP -> SFU
//! Recv: remote RTP -> ffmpeg (SDP input) -> pulse -> PipeWire playback.
//!       Call audio is its own playback stream and never wired back into the
//!       captured app node — the "no call return in the game feed" guarantee
//!       comes from tapping the app stream itself, not the sink monitor.

pub mod capture;
pub mod ffmpeg;
pub mod pw;
pub mod rtp;
pub mod rtp_recv;
pub mod rtp_send;
pub mod sframe;

/// Where an RTP stream goes on the SFU, plus the wire identity we fix
/// (payload type + SSRC) so mediasoup `produce` matches bit-for-bit.
#[derive(Debug, Clone)]
pub struct RtpDest {
    pub ip: String,
    pub port: u16,
    pub payload_type: u8,
    pub ssrc: u32,
    pub name: String,
}

#[derive(Debug, Clone, Copy)]
pub enum VideoCodec {
    H264,
    Vp8,
}
