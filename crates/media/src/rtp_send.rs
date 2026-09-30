//! Rust-owned RTP sender: packetizes encoded access units onto a UDP socket
//! we control, so RTCP from the SFU (RR/PLI/FIR) is actually readable and an
//! SFrame encryptor can sit between encode and packetization later.
//!
//! Video path: ffmpeg emits H.264 Annex-B on stdout -> split into NALs ->
//! group into access units (x264 `aud=1` delimits them) -> RTP packetize
//! (single NAL or FU-A at MTU) -> send.

use anyhow::{Context, Result};
use std::io::Read;
use std::net::UdpSocket;
use std::time::Instant;

const MTU: usize = 1200;
const CLOCK: u32 = 90_000;

/// H.264 NAL unit types we care about.
const NAL_AUD: u8 = 9; // access unit delimiter — emitted by x264 aud=1

pub struct RtpSender {
    sock: UdpSocket,
    pt: u8,
    ssrc: u32,
    seq: u16,
    t0: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RtcpEvent {
    ReceiverReport { fraction_lost: u8, jitter: u32 },
    Pli,
    Fir,
    Other(u8),
}

impl RtpSender {
    /// Connected UDP socket: RTP goes to `ip:port`, RTCP comes back on the
    /// same socket (mediasoup PlainTransport uses rtcpMux + comedia).
    pub fn connect(ip: &str, port: u16, payload_type: u8, ssrc: u32) -> Result<Self> {
        let sock = UdpSocket::bind("0.0.0.0:0").context("bind rtp socket")?;
        sock.connect(format!("{ip}:{port}")).context("connect rtp socket")?;
        Ok(Self { sock, pt: payload_type, ssrc, seq: 1, t0: Instant::now() })
    }

    fn now_ts(&self) -> u32 {
        (self.t0.elapsed().as_secs_f64() * CLOCK as f64) as u32
    }

    fn send_packet(&mut self, marker: bool, ts: u32, payload: &[u8]) -> Result<()> {
        let mut pkt = Vec::with_capacity(12 + payload.len());
        pkt.push(0x80); // V=2
        pkt.push(if marker { 0x80 | self.pt } else { self.pt });
        pkt.extend_from_slice(&self.seq.to_be_bytes());
        self.seq = self.seq.wrapping_add(1);
        pkt.extend_from_slice(&ts.to_be_bytes());
        pkt.extend_from_slice(&self.ssrc.to_be_bytes());
        pkt.extend_from_slice(payload);
        self.sock.send(&pkt).context("rtp send")?;
        Ok(())
    }

    /// Packetize one access unit: every packet shares `ts`; marker set on the
    /// last packet of the unit.
    pub fn send_access_unit(&mut self, nals: &[&[u8]], ts: u32) -> Result<()> {
        // count packets to know which one is last; FU-A carries MTU-2 payload
        // bytes per packet (FU indicator + FU header)
        let mut total = 0usize;
        for nal in nals {
            if nal.is_empty() { continue }
            total += if nal.len() <= MTU { 1 } else { (nal.len() - 1).div_ceil(MTU - 2) };
        }
        let mut left = total;
        for nal in nals {
            if nal.is_empty() { continue }
            if nal.len() <= MTU {
                left -= 1;
                self.send_packet(left == 0, ts, nal)?;
            } else {
                // FU-A: indicator = F|NRI|28, header = S|E|orig type
                let fu_ind = (nal[0] & 0xE0) | 28;
                let nal_type = nal[0] & 0x1F;
                let mut off = 1;
                while off < nal.len() {
                    let end = (off + MTU - 2).min(nal.len());
                    left -= 1;
                    let mut p = Vec::with_capacity(2 + (end - off));
                    p.push(fu_ind);
                    p.push(nal_type | if off == 1 { 0x80 } else { 0 } | if end == nal.len() { 0x40 } else { 0 });
                    p.extend_from_slice(&nal[off..end]);
                    self.send_packet(left == 0, ts, &p)?;
                    off = end;
                }
            }
        }
        Ok(())
    }

    /// Blocking RTCP read loop on the same socket. Sends parsed events to `tx`;
    /// returns when the socket errors or `stop` is set.
    pub fn rtcp_loop(sock: UdpSocket, tx: std::sync::mpsc::Sender<RtcpEvent>) {
        let mut buf = [0u8; 2048];
        loop {
            match sock.recv(&mut buf) {
                Ok(n) => {
                    for ev in parse_rtcp(&buf[..n]) {
                        if tx.send(ev).is_err() { return }
                    }
                }
                Err(_) => return,
            }
        }
    }

    pub fn try_clone_socket(&self) -> Result<UdpSocket> {
        Ok(self.sock.try_clone()?)
    }
}

/// Minimal RTCP compound-packet parser — enough for RR stats and PLI/FIR.
fn parse_rtcp(buf: &[u8]) -> Vec<RtcpEvent> {
    let mut out = Vec::new();
    let mut off = 0;
    while off + 4 <= buf.len() {
        let rc = buf[off] & 0x1F;
        let pt = buf[off + 1];
        let len = ((buf[off + 2] as usize) << 8 | buf[off + 3] as usize) * 4 + 4;
        let body = &buf[off + 4..(off + len).min(buf.len())];
        match pt {
            201 if body.len() >= 4 + 24 => {
                // RR: reporter SSRC(4) then report block: ssrc(4) frac(1)
                // cumul-lost(3) ext-seq(4) jitter(4) lsr(4) dlsr(4)
                let frac = body[8];
                let jitter = u32::from_be_bytes([body[16], body[17], body[18], body[19]]);
                out.push(RtcpEvent::ReceiverReport { fraction_lost: frac, jitter });
            }
            206 if rc == 1 => out.push(RtcpEvent::Pli),
            206 if rc == 4 => out.push(RtcpEvent::Fir),
            _ => out.push(RtcpEvent::Other(pt)),
        }
        off += len.max(4);
    }
    out
}

/// Split an Annex-B stream chunk into complete NAL units. `pending` carries
/// bytes not yet terminated by a following start code; the last NAL stays
/// pending until the next chunk or `flush`.
pub struct AnnexbSplitter {
    pending: Vec<u8>,
}

impl AnnexbSplitter {
    pub fn new() -> Self { Self { pending: Vec::new() } }

    /// Feed raw bytes; returns complete NALs (start code stripped).
    pub fn feed(&mut self, mut data: &[u8]) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        loop {
            match find_start_code(data) {
                Some((pos, sc_len)) => {
                    let head = &data[..pos];
                    if !head.is_empty() {
                        if self.pending.is_empty() && out.is_empty() {
                            // leading zeros before first start code — skip
                        } else {
                            self.pending.extend_from_slice(head);
                        }
                    }
                    if !self.pending.is_empty() {
                        out.push(std::mem::take(&mut self.pending));
                    }
                    data = &data[pos + sc_len..];
                    // everything until the next start code belongs to a NAL;
                    // loop continues to detect the next boundary
                    match find_start_code(data) {
                        Some(_) => continue,
                        None => { self.pending.extend_from_slice(data); break }
                    }
                }
                None => { self.pending.extend_from_slice(data); break }
            }
        }
        // pending now holds a complete-or-partial NAL; emit only complete ones:
        // a NAL is complete only when followed by a start code — which the loop
        // above already handles by pushing on boundary. So `out` is right.
        out
    }

    /// Flush whatever remains (EOF).
    pub fn flush(&mut self) -> Option<Vec<u8>> {
        if self.pending.is_empty() { None } else { Some(std::mem::take(&mut self.pending)) }
    }
}

/// Find the next Annex-B start code (0x000001 or 0x00000001).
fn find_start_code(buf: &[u8]) -> Option<(usize, usize)> {
    let mut i = 0;
    while i + 3 <= buf.len() {
        if buf[i] == 0 && buf[i + 1] == 0 && buf[i + 2] == 1 {
            return Some((i, 3));
        }
        if i + 4 <= buf.len() && buf[i] == 0 && buf[i + 1] == 0 && buf[i + 2] == 0 && buf[i + 3] == 1 {
            return Some((i, 4));
        }
        i += 1;
    }
    None
}

/// Reader thread: Annex-B bytes from `src` -> access units -> RTP.
/// When `enc` is Some, each AU is SFrame-encrypted into a single ciphertext
/// blob before packetization (the FU-A path just fragments it — browsers
/// reassemble and the insertable-streams transform decrypts).
///
/// The socket is shared via `sender`: encoder restarts (PipeWire format
/// renegotiation) MUST keep the same UDP source port, or mediasoup's comedia
/// mode keeps forwarding to the first-learned tuple and silently drops the
/// new sender's packets. Caller starts `RtpSender::rtcp_loop` once.
static TAP: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();

pub fn h264_rtp_pump(
    mut src: impl Read + Send + 'static,
    sender: std::sync::Arc<std::sync::Mutex<RtpSender>>,
    mut enc: Option<crate::sframe::SframeEncryptor>,
) -> std::thread::JoinHandle<()>
{
    // Encrypted wire format: see crate::wire (real SPS/PPS + a slice-typed
    // blob NAL, escaped so ciphertext can't form start codes).
    fn flush_au(
        sender: &std::sync::Arc<std::sync::Mutex<RtpSender>>,
        au: &mut Vec<Vec<u8>>,
        ts: u32,
        enc: &mut Option<crate::sframe::SframeEncryptor>,
        last_cfg: &mut (Option<Vec<u8>>, Option<Vec<u8>>),
    ) {
        if au.is_empty() { return }
        for nal in au.iter() {
            match nal[0] & 0x1F {
                7 => last_cfg.0 = Some(nal.clone()),
                8 => last_cfg.1 = Some(nal.clone()),
                _ => {}
            }
        }
        // debug tap: record the plaintext Annex-B we are about to packetize
        if let Some(Some(path)) = TAP.get() {
            use std::io::Write;
            if let Ok(mut f) = std::fs::OpenOptions::new().append(true).create(true).open(path) {
                for nal in au.iter() { let _ = f.write_all(&[0,0,0,1]); let _ = f.write_all(nal); }
            }
        }
        let mut sender = sender.lock().unwrap();
        if let Some(e) = enc.as_mut() {
            let mut frame = Vec::with_capacity(au.iter().map(|n| n.len() + 4).sum());
            for nal in au.iter() {
                frame.extend_from_slice(&[0, 0, 0, 1]);
                frame.extend_from_slice(nal);
            }
            match e.encrypt(&frame) {
                Ok(ct) => {
                    let key = crate::wire::au_is_key(au);
                    let blob = crate::wire::blob_nal(key, &ct);
                    let mut parts: Vec<&[u8]> = Vec::with_capacity(3);
                    if key {
                        // Real parameter sets ahead of the IDR-typed blob: mediasoup
                        // gates on SPS and browsers need SPS+PPS+IDR for a keyframe.
                        if let (Some(sps), Some(pps)) = (last_cfg.0.as_deref(), last_cfg.1.as_deref()) {
                            parts.push(sps);
                            parts.push(pps);
                        }
                    }
                    parts.push(&blob);
                    if let Err(err) = sender.send_access_unit(&parts, ts) {
                        tracing::warn!(%err, "rtp send failed");
                    }
                }
                Err(err) => tracing::warn!(%err, "sframe encrypt failed"),
            }
        } else {
            let refs: Vec<&[u8]> = au.iter().map(|v| v.as_slice()).collect();
            if let Err(e) = sender.send_access_unit(&refs, ts) {
                tracing::warn!(%e, "rtp send failed");
            }
        }
        au.clear();
    }

    std::thread::spawn(move || {
        TAP.get_or_init(|| std::env::var("LAIRA_TAP_SEND").ok());
        let mut splitter = AnnexbSplitter::new();
        let mut au: Vec<Vec<u8>> = Vec::new();
        let mut au_ts = sender.lock().unwrap().now_ts();
        let mut last_cfg: (Option<Vec<u8>>, Option<Vec<u8>>) = (None, None);
        let mut buf = [0u8; 256 * 1024];
        loop {
            match src.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    for nal in splitter.feed(&buf[..n]) {
                        if nal.is_empty() { continue }
                        if nal[0] & 0x1F == NAL_AUD {
                            // AUD opens a new access unit — flush the previous.
                            flush_au(&sender, &mut au, au_ts, &mut enc, &mut last_cfg);
                            au_ts = sender.lock().unwrap().now_ts();
                        }
                        au.push(nal);
                    }
                }
                Err(_) => break,
            }
        }
        flush_au(&sender, &mut au, au_ts, &mut enc, &mut last_cfg);
        tracing::info!("h264 rtp pump: encoder stdout closed");
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nal(t: u8, fill: u8, len: usize) -> Vec<u8> {
        let mut v = vec![t]; // header byte: F|NRI|type
        v.extend(std::iter::repeat(fill).take(len - 1));
        v
    }

    #[test]
    fn annexb_split_basic_and_chunked() {
        let mut s = AnnexbSplitter::new();
        let stream = [
            vec![0, 0, 1], nal(0x67, 0xA1, 10),           // SPS
            vec![0, 0, 0, 1], nal(0x68, 0xB2, 8),        // PPS (4-byte sc)
            vec![0, 0, 1], nal(0x65, 0xC3, 3000),        // IDR
        ].concat();
        // feed in odd-size chunks to exercise carry-over
        let mut out = Vec::new();
        for chunk in stream.chunks(7) {
            out.extend(s.feed(chunk));
        }
        if let Some(last) = s.flush() { out.push(last) }
        assert_eq!(out.len(), 3);
        assert_eq!(out[0][0], 0x67);
        assert_eq!(out[2].len(), 3000);
        assert!(out[2].iter().skip(1).all(|&b| b == 0xC3));
    }

    #[test]
    fn annexb_skips_leading_zeros() {
        let mut s = AnnexbSplitter::new();
        let out = s.feed(&[0, 0, 0, 0, 0, 1, 0x41, 0x9A]);
        assert!(out.is_empty());
        let out = s.feed(&[0, 0, 1, 0x42, 0x11]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0], vec![0x41, 0x9A]);
    }

    /// Capture packets by pointing a sender at a local UDP sink.
    fn capture_au(nals: &[&[u8]]) -> Vec<Vec<u8>> {
        let sink = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = sink.local_addr().unwrap().port();
        let mut s = RtpSender::connect("127.0.0.1", port, 96, 0xdead).unwrap();
        s.send_access_unit(nals, 12345).unwrap();
        sink.set_read_timeout(Some(std::time::Duration::from_millis(300))).unwrap();
        let mut got = Vec::new();
        let mut buf = [0u8; 4096];
        while let Ok(n) = sink.recv(&mut buf) {
            got.push(buf[..n].to_vec());
        }
        got
    }

    #[test]
    fn packetize_small_nal_marker_set() {
        let n = nal(0x65, 0x77, 500);
        let pkts = capture_au(&[&n]);
        assert_eq!(pkts.len(), 1);
        assert_eq!(pkts[0][1] & 0x80, 0x80, "marker must be set");
        assert_eq!(pkts[0][1] & 0x7F, 96);
        assert_eq!(&pkts[0][4..8], &12345u32.to_be_bytes());
        assert_eq!(&pkts[0][8..12], &0xdeadu32.to_be_bytes());
        assert_eq!(&pkts[0][12..], n.as_slice());
    }

    #[test]
    fn packetize_fu_a_fragments_and_marker_on_last() {
        let n = nal(0x65, 0xAB, 3000); // > MTU -> FU-A
        let pkts = capture_au(&[&n]);
        let expect = (3000 - 1 + (MTU - 3)) / (MTU - 2); // ceil((L-1)/(MTU-2))
        assert_eq!(pkts.len(), expect);
        for (i, p) in pkts.iter().enumerate() {
            let fu_ind = p[12];
            let fu_hdr = p[13];
            assert_eq!(fu_ind & 0x1F, 28, "FU-A indicator");
            assert_eq!(fu_ind & 0xE0, 0x65 & 0xE0, "NRI preserved");
            assert_eq!(fu_hdr & 0x1F, 0x65 & 0x1F, "orig nal type");
            assert_eq!(fu_hdr & 0x80 != 0, i == 0, "S bit on first only");
            assert_eq!(fu_hdr & 0x40 != 0, i == pkts.len() - 1, "E bit on last only");
            assert_eq!(p[1] & 0x80 != 0, i == pkts.len() - 1, "marker on last only");
            assert_eq!(p.len(), if i == pkts.len() - 1 { p.len() } else { 12 + MTU });
        }
        // reassemble
        let mut reasm = vec![(pkts[0][12] & 0xE0) | (pkts[0][13] & 0x1F)];
        for p in &pkts { reasm.extend_from_slice(&p[14..]); }
        assert_eq!(reasm, n);
    }

    #[test]
    fn rtcp_parse_pli_and_rr() {
        // PLI: V=2 RC=1 PT=206 len=2 + ssrc sender + ssrc media
        let pli = [0x81, 206, 0, 2, 0, 0, 0, 1, 0, 0, 0, 2];
        let evs = parse_rtcp(&pli);
        assert!(matches!(evs[0], RtcpEvent::Pli));
        // RR: V=2 RC=1 PT=201 len=7 + reporter ssrc + report block(24)
        let mut rr = vec![0x81, 201, 0, 7, 0, 0, 0, 9];
        rr.resize(4 + 4 + 24, 0);
        rr[12] = 0x55; // fraction_lost: body[8] = rr[4+8]
        rr[20] = 0x12; rr[21] = 0x34; rr[22] = 0x56; rr[23] = 0x78; // jitter
        let evs = parse_rtcp(&rr);
        assert!(matches!(evs[0], RtcpEvent::ReceiverReport { fraction_lost: 0x55, jitter: 0x12345678 }));
    }
}
