//! SFrame frame encryption (RFC 9605), cipher suite AES_128_GCM_SHA256_128.
//!
//! Wire format on the RTP payload:
//!   header || ciphertext || gcm-tag(16)
//!   header = cfg(1) || ctr(4, BE)          — kid=0, 4-byte counter
//!   cfg    = X(1b)|K(3b)|C(4b) = 0x03      — X=0, K=KID=0, C=ctr_len-1
//!
//! Key derivation (HKDF-SHA256, mirrors the WebCrypto path in apps/web):
//!   secret = HKDF-Extract(salt="SFrame 1.0", ikm=base_key)
//!   key    = HKDF-Expand(secret, "key", 16)
//!   salt   = HKDF-Expand(secret, "salt", 12)
//!   nonce  = salt XOR ctr (12-byte BE)
//!
//! M1 test vector uses a fixed base key; real key management is OpenMLS (M2).

use aes_gcm::{aead::{Aead, KeyInit, Payload}, Aes128Gcm};
use anyhow::Result;
use hkdf::Hkdf;
use sha2::Sha256;

const CTR_LEN: usize = 4;
const TAG_LEN: usize = 16;

/// M1 test vector — the same bytes are hardcoded in apps/web. NOT a secret;
/// proves interop only. M2 replaces this with MLS-derived per-sender keys.
pub const TEST_BASE_KEY: [u8; 16] = *b"laira-m0-sframe!";

pub struct SframeEncryptor {
    key: [u8; 16],
    salt: [u8; 12],
    ctr: u64,
    kid: u8,
}

impl SframeEncryptor {
    pub fn new(base_key: &[u8; 16]) -> Self {
        Self::with_kid(base_key, 0)
    }

    pub fn with_kid(base_key: &[u8; 16], kid: u8) -> Self {
        let hk = Hkdf::<Sha256>::new(Some(b"SFrame 1.0"), base_key);
        let mut key = [0u8; 16];
        let mut salt = [0u8; 12];
        hk.expand(b"key", &mut key).expect("hkdf key");
        hk.expand(b"salt", &mut salt).expect("hkdf salt");
        Self { key, salt, ctr: 0, kid }
    }

    fn nonce(&self, ctr: u64) -> [u8; 12] {
        let mut n = self.salt;
        let be = ctr.to_be_bytes();
        for i in 0..8 {
            n[4 + i] ^= be[i];
        }
        n
    }

    /// Encrypt one access unit; returns header||ct||tag.
    pub fn encrypt(&mut self, frame: &[u8]) -> Result<Vec<u8>> {
        let ctr = self.ctr;
        self.ctr += 1;
        // cfg: X=0, K=kid (<=7), C=CTR_LEN-1
        let mut out = Vec::with_capacity(1 + CTR_LEN + frame.len() + TAG_LEN);
        out.push((self.kid << 4) | (CTR_LEN as u8 - 1));
        out.extend_from_slice(&(ctr as u32).to_be_bytes());
        let nonce = self.nonce(ctr);
        let cipher = Aes128Gcm::new_from_slice(&self.key).expect("key len");
        let ct = cipher
            .encrypt(&nonce.into(), Payload { msg: frame, aad: &out })
            .map_err(|_| anyhow::anyhow!("sframe encrypt failed"))?;
        out.extend_from_slice(&ct);
        Ok(out)
    }
}

/// Reusable decryptor — derives key+salt once (the native watch path).
pub struct SframeDecryptor {
    key: [u8; 16],
    salt: [u8; 12],
}

impl SframeDecryptor {
    pub fn new(base_key: &[u8; 16]) -> Self {
        let hk = Hkdf::<Sha256>::new(Some(b"SFrame 1.0"), base_key);
        let mut key = [0u8; 16];
        let mut salt = [0u8; 12];
        hk.expand(b"key", &mut key).unwrap();
        hk.expand(b"salt", &mut salt).unwrap();
        Self { key, salt }
    }

    pub fn decrypt(&self, buf: &[u8]) -> Result<Vec<u8>> {
        let cfg = *buf.first().ok_or_else(|| anyhow::anyhow!("empty sframe"))?;
        let ctr_len = (cfg & 0x0F) as usize + 1;
        anyhow::ensure!(buf.len() > 1 + ctr_len + TAG_LEN, "short sframe");
        let mut ctr: u64 = 0;
        for b in &buf[1..1 + ctr_len] { ctr = (ctr << 8) | *b as u64 }
        let mut nonce = self.salt;
        for i in 0..8 { nonce[4 + i] ^= ctr.to_be_bytes()[i]; }
        let cipher = Aes128Gcm::new_from_slice(&self.key).unwrap();
        let pt = cipher
            .decrypt(&nonce.into(), Payload { msg: &buf[1 + ctr_len..], aad: &buf[..1 + ctr_len] })
            .map_err(|_| anyhow::anyhow!("sframe decrypt failed"))?;
        Ok(pt)
    }
}

/// Decrypt a header||ct||tag buffer — used by tests; the browser does its own.
#[allow(dead_code)]
pub fn decrypt(base_key: &[u8; 16], kid: u8, buf: &[u8]) -> Result<Vec<u8>> {
    let hk = Hkdf::<Sha256>::new(Some(b"SFrame 1.0"), base_key);
    let mut key = [0u8; 16];
    let mut salt = [0u8; 12];
    hk.expand(b"key", &mut key).unwrap();
    hk.expand(b"salt", &mut salt).unwrap();
    let cfg = buf[0];
    let ctr_len = (cfg & 0x0F) as usize + 1;
    anyhow::ensure!(buf.len() > 1 + ctr_len + TAG_LEN, "short sframe");
    let mut ctr: u64 = 0;
    for b in &buf[1..1 + ctr_len] { ctr = (ctr << 8) | *b as u64 }
    let mut nonce = salt;
    for i in 0..8 { nonce[4 + i] ^= ctr.to_be_bytes()[i]; }
    let cipher = Aes128Gcm::new_from_slice(&key).unwrap();
    let pt = cipher
        .decrypt(&nonce.into(), Payload { msg: &buf[1 + ctr_len..], aad: &buf[..1 + ctr_len] })
        .map_err(|_| anyhow::anyhow!("sframe decrypt failed (kid={kid})"))?;
    Ok(pt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let mut enc = SframeEncryptor::new(&TEST_BASE_KEY);
        let a = enc.encrypt(b"hello frame one").unwrap();
        let b = enc.encrypt(b"frame two").unwrap();
        assert_ne!(&a[..5], &b[..5]); // ctr differs
        assert_eq!(decrypt(&TEST_BASE_KEY, 0, &a).unwrap(), b"hello frame one");
        assert_eq!(decrypt(&TEST_BASE_KEY, 0, &b).unwrap(), b"frame two");
    }

    #[test]
    fn header_format() {
        let mut enc = SframeEncryptor::new(&TEST_BASE_KEY);
        let out = enc.encrypt(b"x").unwrap();
        assert_eq!(out[0], 0x03); // X=0 KID=0 CTR len=4
        assert_eq!(&out[1..5], &0u32.to_be_bytes());
    }

    #[test]
    fn wrong_key_fails() {
        let mut enc = SframeEncryptor::new(&TEST_BASE_KEY);
        let a = enc.encrypt(b"data").unwrap();
        assert!(decrypt(b"other-key-16byte", 0, &a).is_err());
    }

    /// Writes a fixed interop vector to /tmp/sframe-vector.json so
    /// tests/m1/sframe-interop.mjs can verify the WebCrypto side decrypts the
    /// exact bytes this implementation produces (same HKDF, nonce, aad, tag).
    #[test]
    fn write_interop_vector() {
        let mut enc = SframeEncryptor::new(&TEST_BASE_KEY);
        // a fake AU: AUD + fake IDR — shape doesn't matter, only the bytes.
        let pt: Vec<u8> = vec![0x09, 0x10, 0x65, 0x88, 0x84, 0xde, 0xad, 0xbe, 0xef];
        let ct = enc.encrypt(&pt).unwrap();
        // wire format: frame.data equivalent = Annex-B start code + SEI-typed
        // blob unit (0x66 || sframe), see rtp_send::flush_au + sframe-worker.ts
        let mut wire = vec![0, 0, 0, 1, 0x66];
        wire.extend_from_slice(&ct);
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        let json = format!(
            "{{\"baseKey\":\"{}\",\"plaintext\":\"{}\",\"ciphertext\":\"{}\"}}\n",
            hex(&TEST_BASE_KEY), hex(&pt), hex(&wire));
        std::fs::write("/tmp/sframe-vector.json", &json).unwrap();
    }
}
