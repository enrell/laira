//! Encrypted-video wire format (v2), shared by the native sender/receiver and
//! mirrored in apps/web/src/sframe-worker.ts.
//!
//! An SFrame-protected access unit is sent as:
//!   keyframe AU: [real SPS][real PPS][blob NAL, type 5 (IDR slice)]
//!   delta AU:    [blob NAL, type 1 (non-IDR slice)]
//! Browsers only assemble and hand frames to an encoded transform when their
//! depacketizer sees a keyframe made of SPS+PPS+IDR (and slice NALs after it),
//! and mediasoup gates forwarding on a real SPS. The blob NAL is
//! `header || escape(PREFIX || sframe)`:
//!  - PREFIX begins with bytes that parse as a valid slice header
//!    (first_mb_in_slice=0, slice_type=7, pps_id=0) because libwebrtc reads
//!    the PPS id out of every slice NAL, then a magic tag.
//!  - `escape` is H.264 emulation prevention, so ciphertext can never contain
//!    an Annex-B start code (`00 00 01`) that would split the NAL; a 0x80 stop
//!    byte follows the SFrame buffer so the NAL never ends in 0x00.

pub const NAL_SLICE: u8 = 1;
pub const NAL_IDR: u8 = 5;
/// `1 0001000 1` = ue(0) ue(7) ue(0) padded, then the magic "L2".
pub const BLOB_PREFIX: [u8; 4] = [0x88, 0x80, b'L', b'2'];

/// Insert 0x03 after any `00 00` that is followed by a byte <= 3 (or ends the
/// payload), so the result never contains `00 00 00/01/02`. Callers must not
/// end the payload in a lone `00` (the blob adds an RBSP stop byte).
pub fn escape(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + data.len() / 128 + 1);
    let mut zeros = 0;
    for &b in data {
        if zeros >= 2 && b <= 3 {
            out.push(3);
            zeros = 0;
        }
        out.push(b);
        zeros = if b == 0 { zeros + 1 } else { 0 };
    }
    // A payload ending in `00 00` needs a trailing 03 (removed by `unescape`).
    if zeros >= 2 {
        out.push(3);
    }
    out
}

pub fn unescape(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut zeros = 0;
    for &b in data {
        if zeros >= 2 && b == 3 {
            zeros = 0;
            continue;
        }
        out.push(b);
        zeros = if b == 0 { zeros + 1 } else { 0 };
    }
    out
}

/// Build the blob NAL (without start code) carrying an SFrame buffer.
pub fn blob_nal(is_key: bool, sframe: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(BLOB_PREFIX.len() + sframe.len());
    body.extend_from_slice(&BLOB_PREFIX);
    body.extend_from_slice(sframe);
    body.push(0x80); // RBSP stop byte: a NAL must not end in 0x00
    let mut nal = Vec::with_capacity(body.len() + body.len() / 128 + 2);
    nal.push(if is_key { 0x60 | NAL_IDR } else { 0x40 | NAL_SLICE });
    nal.extend_from_slice(&escape(&body));
    nal
}

/// If `nal` (no start code) is a blob NAL, return the inner SFrame buffer.
pub fn parse_blob(nal: &[u8]) -> Option<Vec<u8>> {
    let t = *nal.first()? & 0x1F;
    if t != NAL_SLICE && t != NAL_IDR {
        return None;
    }
    let body = unescape(&nal[1..]);
    let inner = body.strip_prefix(&BLOB_PREFIX[..])?;
    inner.strip_suffix(&[0x80]).map(|s| s.to_vec())
}

/// True if the access unit's NALs contain an IDR slice.
pub fn au_is_key(nals: &[Vec<u8>]) -> bool {
    nals.iter().any(|n| n.first().is_some_and(|h| h & 0x1F == NAL_IDR))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_roundtrip_and_no_start_codes() {
        let mut data = vec![0u8, 0, 1, 0, 0, 0, 0, 2, 0, 0, 3, 0, 0];
        data.extend((0..20_000u32).map(|i| if i % 7 == 0 { 0 } else { (i % 4) as u8 }));
        data.extend([0, 0]);
        let esc = escape(&data);
        assert_eq!(unescape(&esc), data);
        for w in esc.windows(3) {
            assert!(!(w[0] == 0 && w[1] == 0 && w[2] <= 2), "start-code pattern leaked");
        }
    }

    #[test]
    fn blob_roundtrip() {
        let sf = vec![0x03, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0xFF, 0];
        for key in [true, false] {
            let nal = blob_nal(key, &sf);
            assert_eq!(nal[0] & 0x1F, if key { NAL_IDR } else { NAL_SLICE });
            assert_eq!(parse_blob(&nal).unwrap(), sf);
        }
        // a real plaintext slice is not mistaken for a blob
        assert!(parse_blob(&[0x65, 0x88, 0x84, 0x00, 0x33]).is_none());
        assert!(parse_blob(&[0x67, 0x42]).is_none());
    }
}
