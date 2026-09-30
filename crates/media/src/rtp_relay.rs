//! Local RTP relays that add/remove SFrame on audio payloads.
//!
//! ffmpeg muxes Opus into RTP itself; rather than replace its packetizer we
//! sit between it and the network. Opus RTP is one frame per packet (no
//! fragmentation), so protecting audio is: keep the RTP header, replace the
//! payload with the SFrame buffer. Headers (seq/ts/ssrc/PT) stay in the clear,
//! as the SFU needs them; the codec payload is what is confidential.

use std::net::{SocketAddr, UdpSocket};

use crate::sframe::{SframeDecryptor, SframeEncryptor};

/// Length of the RTP header (fixed + CSRCs + extension) or None if malformed.
fn header_len(pkt: &[u8]) -> Option<usize> {
    if pkt.len() < 12 || pkt[0] >> 6 != 2 {
        return None;
    }
    let mut off = 12 + (pkt[0] & 0x0F) as usize * 4;
    if pkt[0] & 0x10 != 0 {
        if pkt.len() < off + 4 {
            return None;
        }
        off += 4 + u16::from_be_bytes([pkt[off + 2], pkt[off + 3]]) as usize * 4;
    }
    (off < pkt.len()).then_some(off)
}

/// Padding (P bit) would also need trimming; ffmpeg's RTP muxer never sets it.
fn is_rtcp(pkt: &[u8]) -> bool {
    pkt.len() >= 2 && (72..=76).contains(&(pkt[1] & 0x7F))
}

/// Rewrite one packet's payload through `f`; `None` drops the packet.
fn rewrite(pkt: &[u8], f: impl FnOnce(&[u8]) -> Option<Vec<u8>>) -> Option<Vec<u8>> {
    let off = header_len(pkt)?;
    let payload = f(&pkt[off..])?;
    let mut out = Vec::with_capacity(off + payload.len());
    out.extend_from_slice(&pkt[..off]);
    out.extend_from_slice(&payload);
    Some(out)
}

/// ffmpeg -> (encrypt) -> SFU. `out` is a persistent socket so mediasoup's
/// comedia keeps a single source tuple for the whole session.
pub fn encrypt_relay(
    listen: UdpSocket,
    out: UdpSocket,
    dest: SocketAddr,
    mut enc: SframeEncryptor,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut buf = [0u8; 2048];
        while let Ok(n) = listen.recv(&mut buf) {
            let pkt = &buf[..n];
            if is_rtcp(pkt) {
                continue; // ffmpeg's SR would carry plaintext-clock info; the SFU has its own
            }
            let Some(wire) = rewrite(pkt, |p| enc.encrypt(p).ok()) else { continue };
            let _ = out.send_to(&wire, dest);
        }
    })
}

/// SFU -> (decrypt) -> local ffmpeg player. Undecryptable packets (wrong or
/// not-yet-installed epoch key) are dropped, never played as noise.
pub fn decrypt_relay(
    listen: UdpSocket,
    forward: SocketAddr,
    dec: SframeDecryptor,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let out = match UdpSocket::bind("127.0.0.1:0") {
            Ok(s) => s,
            Err(_) => return,
        };
        let mut buf = [0u8; 2048];
        let mut dropped = 0u64;
        while let Ok(n) = listen.recv(&mut buf) {
            let pkt = &buf[..n];
            if is_rtcp(pkt) {
                continue;
            }
            match rewrite(pkt, |p| dec.decrypt(p).ok()) {
                Some(wire) => { let _ = out.send_to(&wire, forward); }
                None => {
                    dropped += 1;
                    if dropped == 1 || dropped % 500 == 0 {
                        tracing::warn!(dropped, "audio sframe decrypt failed");
                    }
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn rtp(seq: u16, payload: &[u8]) -> Vec<u8> {
        let mut p = vec![0x80, 111];
        p.extend_from_slice(&seq.to_be_bytes());
        p.extend_from_slice(&1000u32.to_be_bytes());
        p.extend_from_slice(&0xABCDu32.to_be_bytes());
        p.extend_from_slice(payload);
        p
    }

    #[test]
    fn audio_relay_roundtrip_and_wrong_key() {
        let key = [7u8; 16];
        // ffmpeg -> enc relay -> (wire) -> dec relay -> player
        let player = UdpSocket::bind("127.0.0.1:0").unwrap();
        player.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
        let dec_in = UdpSocket::bind("127.0.0.1:0").unwrap();
        let enc_in = UdpSocket::bind("127.0.0.1:0").unwrap();
        let (enc_addr, dec_addr) = (enc_in.local_addr().unwrap(), dec_in.local_addr().unwrap());
        encrypt_relay(enc_in, UdpSocket::bind("127.0.0.1:0").unwrap(), dec_addr, SframeEncryptor::with_kid(&key, 2));
        decrypt_relay(dec_in, player.local_addr().unwrap(), SframeDecryptor::with_senders([(2, key)]));

        let ffmpeg = UdpSocket::bind("127.0.0.1:0").unwrap();
        let opus = [0xFC, 0xFF, 0xFE, 1, 2, 3, 4, 5];
        ffmpeg.send_to(&rtp(9, &opus), enc_addr).unwrap();
        let mut buf = [0u8; 256];
        let n = player.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], &rtp(9, &opus)[..]); // header and payload restored exactly

        // a receiver with a different key plays nothing
        let player2 = UdpSocket::bind("127.0.0.1:0").unwrap();
        player2.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
        let dec2_in = UdpSocket::bind("127.0.0.1:0").unwrap();
        let dec2_addr = dec2_in.local_addr().unwrap();
        decrypt_relay(dec2_in, player2.local_addr().unwrap(), SframeDecryptor::with_senders([(2, [8u8; 16])]));
        let enc2_in = UdpSocket::bind("127.0.0.1:0").unwrap();
        let enc2_addr = enc2_in.local_addr().unwrap();
        encrypt_relay(enc2_in, UdpSocket::bind("127.0.0.1:0").unwrap(), dec2_addr, SframeEncryptor::with_kid(&key, 2));
        ffmpeg.send_to(&rtp(10, &opus), enc2_addr).unwrap();
        assert!(player2.recv(&mut buf).is_err());
    }
}
