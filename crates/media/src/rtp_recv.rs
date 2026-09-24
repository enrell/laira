//! Rust-owned RTP receiver for the native watch path: UDP -> RTP parse ->
//! depacketize (single NAL + FU-A) -> optional SFrame decrypt -> Annex-B
//! H.264 bytes on `out` (e.g. ffplay/ffmpeg stdin).
//!
//! Wire format for encrypted frames (see rtp_send::flush_au): each access
//! unit is two logical NALs at one timestamp — a real SPS (mediasoup keyframe
//! gate) and a SEI-typed blob unit `0x66 || sframe`. Decrypted plaintext is
//! already Annex-B; everything else passes through as Annex-B too.

use std::collections::BTreeMap;
use std::io::Write;
use std::net::UdpSocket;
use std::os::fd::AsRawFd;

/// Raise the kernel receive buffer — a single keyframe AU can exceed the
/// ~208KB default and PlainTransport has no retransmission, so a dropped
/// fragment corrupts the whole frame.
fn big_rcvbuf(sock: &UdpSocket) {
    let sz: libc::c_int = 4 << 20;
    unsafe {
        libc::setsockopt(sock.as_raw_fd(), libc::SOL_SOCKET, libc::SO_RCVBUF,
            &sz as *const _ as *const libc::c_void, std::mem::size_of_val(&sz) as _);
    }
}

const NAL_SPS: u8 = 7;
const NAL_SEI_BLOB: u8 = 6; // type 6 (SEI) used as the opaque SFrame carrier
const NAL_FU_A: u8 = 28;
const NAL_FU_B: u8 = 29;
const START: &[u8] = &[0, 0, 0, 1];

struct Frame {
    /// seq -> rtp payload bytes
    pkts: BTreeMap<u16, Vec<u8>>,
    complete: bool,
}

/// Depacketize one RTP payload into (maybe) a complete NAL unit.
/// `fu` accumulates an in-progress FU-A: (reconstructed header byte, bytes).
fn depacketize(pay: &[u8], fu: &mut Option<(u8, Vec<u8>)>, nals: &mut Vec<Vec<u8>>) {
    if pay.len() < 2 { return }
    let t = pay[0] & 0x1F;
    if t == NAL_FU_A || t == NAL_FU_B {
        let fuh = pay[1];
        if fuh & 0x80 != 0 {
            *fu = Some(((pay[0] & 0xE0) | (fuh & 0x1F), pay[2..].to_vec()));
        } else if let Some((_, ref mut body)) = fu {
            body.extend_from_slice(&pay[2..]);
        }
        if fuh & 0x40 != 0 {
            if let Some((hdr, body)) = fu.take() {
                let mut nal = Vec::with_capacity(body.len() + 1);
                nal.push(hdr);
                nal.extend_from_slice(&body);
                nals.push(nal);
            }
        }
    } else {
        nals.push(pay.to_vec());
    }
}

/// Blocking receive loop: reads RTP from `sock`, emits Annex-B to `out`.
/// If `dec` is set, 0x66-marked blob units are SFrame-decrypted; a blob that
/// fails to decrypt is dropped (wrong key / corrupt) — passthrough NALs are
/// emitted regardless, so a plaintext producer works with `dec` set too.
/// `want_ssrc`: the consumer's SSRC from consumePlain rtpParameters — foreign
/// packets (e.g. stray producer-SSRC packets landing on the port) must not
/// touch seq-gap tracking or they'd trigger spurious AU drops.
pub fn h264_recv_loop(
    sock: UdpSocket,
    want_ssrc: u32,
    mut dec: Option<crate::sframe::SframeDecryptor>,
    mut out: impl Write + Send + 'static,
) -> std::thread::JoinHandle<()> {
    big_rcvbuf(&sock);
    std::thread::spawn(move || {
        let mut frames: BTreeMap<u32, Frame> = BTreeMap::new();
        let mut fu: Option<(u8, Vec<u8>)> = None;
        let mut last_seq: Option<u16> = None;
        let mut buf = [0u8; 4096];
        loop {
            let n = match sock.recv(&mut buf) {
                Ok(n) => n,
                Err(_) => return,
            };
            let pkt = &buf[..n];
            if pkt.len() < 13 || pkt[0] >> 6 != 2 { continue }
            let pt = pkt[1] & 0x7F;
            if (72..=76).contains(&pt) { continue } // RTCP on a muxed socket
            let ssrc = u32::from_be_bytes([pkt[8], pkt[9], pkt[10], pkt[11]]);
            if ssrc != want_ssrc { continue }
            let marker = pkt[1] & 0x80 != 0;
            let seq = u16::from_be_bytes([pkt[2], pkt[3]]);
            let ts = u32::from_be_bytes([pkt[4], pkt[5], pkt[6], pkt[7]]);
            // gap in the seq space: every in-progress AU is damaged — drop it
            // (decoder conceals a missing AU far better than a corrupt one)
            if last_seq.is_some_and(|s| seq != s.wrapping_add(1)) {
                fu = None;
                frames.clear();
                tracing::warn!(got = seq, "rtp gap — dropping in-flight AUs");
            }
            last_seq = Some(seq);
            let mut off = 12 + (pkt[0] & 0x0F) as usize * 4;
            if pkt[0] & 0x10 != 0 && pkt.len() >= off + 4 {
                off += 4 + u16::from_be_bytes([pkt[off + 2], pkt[off + 3]]) as usize * 4;
            }
            if off >= pkt.len() { continue }
            let f = frames.entry(ts).or_insert_with(|| Frame { pkts: BTreeMap::new(), complete: false });
            f.pkts.insert(seq, pkt[off..].to_vec());
            if marker { f.complete = true }
            // drain every ts that is complete (and anything before the newest
            // complete ts, to not stall on a lost marker)
            let upto = frames.iter().find(|(_, f)| f.complete).map(|(t, _)| *t);
            let Some(upto) = upto else { continue };
            let done: Vec<u32> = frames.range(..=upto).map(|(t, _)| *t).collect();
            for t in done {
                let Some(fr) = frames.remove(&t) else { continue };
                let mut nals = Vec::new();
                for (_, pay) in fr.pkts { depacketize(&pay, &mut fu, &mut nals); }
                for nal in nals {
                    let is_blob = nal.len() > 6 && nal[0] == 0x66 && nal[1] == 0x03;
                    if is_blob {
                        if let Some(d) = dec.as_mut() {
                            match d.decrypt(&nal[1..]) {
                                // plaintext is Annex-B already — write as-is
                                Ok(pt) => { let _ = out.write_all(&pt); }
                                Err(e) => tracing::warn!(%e, "sframe decrypt failed"),
                            }
                        }
                        continue;
                    }
                    let _ = out.write_all(START);
                    let _ = out.write_all(&nal);
                    if nal[0] & 0x1F == NAL_SPS {
                        tracing::debug!("sps passthrough");
                    }
                }
                let _ = out.flush();
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtp_send::RtpSender;
    use std::io::Write as _;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    struct Sink(Arc<Mutex<Vec<u8>>>);
    impl Write for Sink {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
    }

    fn au_nals() -> Vec<Vec<u8>> {
        let mut idr = vec![0x65];
        idr.extend(std::iter::repeat(0xAB).take(5000)); // forces FU-A
        vec![
            vec![0x09, 0x10],            // AUD
            vec![0x67, 0x42, 0xE0, 0x1F], // SPS
            vec![0x68, 0xCE, 0x06],       // PPS
            idr,
        ]
    }

    fn expected_annexb(nals: &[Vec<u8>]) -> Vec<u8> {
        let mut v = Vec::new();
        for n in nals { v.extend_from_slice(START); v.extend_from_slice(n); }
        v
    }

    #[test]
    fn recv_roundtrip_plaintext() {
        let recv = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = recv.local_addr().unwrap().port();
        let got = Arc::new(Mutex::new(Vec::new()));
        let _h = h264_recv_loop(recv, 0x1234, None, Sink(got.clone()));

        let mut sender = RtpSender::connect("127.0.0.1", port, 96, 0x1234).unwrap();
        let nals = au_nals();
        let refs: Vec<&[u8]> = nals.iter().map(|v| v.as_slice()).collect();
        for i in 0..3 { sender.send_access_unit(&refs, i * 3000).unwrap(); }

        std::thread::sleep(Duration::from_millis(300));
        let got = got.lock().unwrap();
        let want: Vec<u8> = (0..3).flat_map(|_| expected_annexb(&nals)).collect();
        assert_eq!(*got, want);
    }
}
