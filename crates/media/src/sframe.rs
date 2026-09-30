//! SFrame frame encryption (RFC 9605), cipher suite AES_128_GCM_SHA256_128.
//!
//! Wire format on the RTP payload:
//!   header || ciphertext || gcm-tag(16)
//!   header = cfg(1) || ctr(8, BE)          — 8-byte counter
//!   cfg    = X(1b)|K(3b)|C(4b)             — X=0, K=KID, C=ctr_len-1 = 7
//!
//! Key derivation (HKDF-SHA256, mirrors the WebCrypto path in apps/web):
//!   secret = HKDF-Extract(salt="SFrame 1.0", ikm=base_key)
//!   key    = HKDF-Expand(secret, "key", 16)
//!   salt   = HKDF-Expand(secret, "salt", 12)
//!   nonce  = salt XOR ctr (12-byte BE)
//!
//! Per-sender base keys come from `laira-identity`'s epoch key schedule
//! (M2); `TEST_BASE_KEY` remains only as the M1 interop vector.

use aes_gcm::{aead::{Aead, KeyInit, Payload}, Aes128Gcm};
use anyhow::Result;
use hkdf::Hkdf;
use sha2::Sha256;

/// 8-byte counter: a random 32-bit per-encryptor prefix in the high half and a
/// 32-bit frame counter in the low half. Two processes (or tabs, or devices)
/// of the same member share a KID and key, so their nonce spaces must not
/// overlap; the random prefix makes collisions negligible.
const CTR_LEN: usize = 8;

fn fresh_ctr() -> u64 {
    (rand::random::<u32>() as u64) << 32
}
const TAG_LEN: usize = 16;

/// M1 test vector — the same bytes are hardcoded in apps/web. NOT a secret;
/// proves interop only. M2 replaces this with MLS-derived per-sender keys.
pub const TEST_BASE_KEY: [u8; 16] = *b"laira-m0-sframe!";

struct EncState {
    key: [u8; 16],
    salt: [u8; 12],
    ctr: u64,
}

/// Cloneable handle: all clones share one key + counter, so encoder restarts
/// continue the counter (no nonce reuse) and `rekey` reaches every clone.
pub struct SframeEncryptor {
    state: std::sync::Arc<std::sync::Mutex<EncState>>,
    kid: u8,
}

impl SframeEncryptor {
    pub fn new(base_key: &[u8; 16]) -> Self {
        Self::with_kid(base_key, 0)
    }

    pub fn with_kid(base_key: &[u8; 16], kid: u8) -> Self {
        let (key, salt) = derive(base_key);
        Self { state: std::sync::Arc::new(std::sync::Mutex::new(EncState { key, salt, ctr: fresh_ctr() })), kid }
    }

    /// Second handle on the same key and counter (for encoder restarts).
    pub fn share(&self) -> Self {
        Self { state: self.state.clone(), kid: self.kid }
    }

    /// Switch to a new epoch's key; the counter restarts under the new key.
    pub fn rekey(&self, base_key: &[u8; 16]) {
        let (key, salt) = derive(base_key);
        *self.state.lock().unwrap() = EncState { key, salt, ctr: fresh_ctr() };
    }

    /// Encrypt one access unit; returns header||ct||tag.
    pub fn encrypt(&mut self, frame: &[u8]) -> Result<Vec<u8>> {
        let mut st = self.state.lock().unwrap();
        let ctr = st.ctr;
        anyhow::ensure!((ctr & 0xFFFF_FFFF) < u32::MAX as u64, "sframe counter exhausted; rekey required");
        st.ctr += 1;
        let mut nonce = st.salt;
        let be = ctr.to_be_bytes();
        for i in 0..8 {
            nonce[4 + i] ^= be[i];
        }
        // cfg: X=0, K=kid (<=7), C=CTR_LEN-1
        let mut out = Vec::with_capacity(1 + CTR_LEN + frame.len() + TAG_LEN);
        out.push((self.kid << 4) | (CTR_LEN as u8 - 1));
        out.extend_from_slice(&ctr.to_be_bytes());
        let cipher = Aes128Gcm::new_from_slice(&st.key).expect("key len");
        let ct = cipher
            .encrypt(&nonce.into(), Payload { msg: frame, aad: &out })
            .map_err(|_| anyhow::anyhow!("sframe encrypt failed"))?;
        out.extend_from_slice(&ct);
        Ok(out)
    }
}

type KeyMap = std::collections::HashMap<u8, ([u8; 16], [u8; 12])>;

fn derive(base_key: &[u8; 16]) -> ([u8; 16], [u8; 12]) {
    let hk = Hkdf::<Sha256>::new(Some(b"SFrame 1.0"), base_key);
    let mut key = [0u8; 16];
    let mut salt = [0u8; 12];
    hk.expand(b"key", &mut key).expect("hkdf key");
    hk.expand(b"salt", &mut salt).expect("hkdf salt");
    (key, salt)
}

fn open(map: &KeyMap, buf: &[u8]) -> Result<Vec<u8>> {
    let cfg = *buf.first().ok_or_else(|| anyhow::anyhow!("empty sframe"))?;
    anyhow::ensure!(cfg & 0x80 == 0, "extended sframe KID unsupported");
    let kid = (cfg >> 4) & 0x07;
    let (key, salt) = map.get(&kid).ok_or_else(|| anyhow::anyhow!("unknown sframe kid {kid}"))?;
    let ctr_len = (cfg & 0x0F) as usize + 1;
    anyhow::ensure!(buf.len() > 1 + ctr_len + TAG_LEN, "short sframe");
    let mut ctr: u64 = 0;
    for b in &buf[1..1 + ctr_len] { ctr = (ctr << 8) | *b as u64 }
    let mut nonce = *salt;
    for i in 0..8 { nonce[4 + i] ^= ctr.to_be_bytes()[i]; }
    Aes128Gcm::new_from_slice(key).unwrap()
        .decrypt(&nonce.into(), Payload { msg: &buf[1 + ctr_len..], aad: &buf[..1 + ctr_len] })
        .map_err(|_| anyhow::anyhow!("sframe decrypt failed (kid={kid})"))
}

struct DecState {
    current: KeyMap,
    /// Previous epoch, kept until the next rotation so in-flight frames
    /// encrypted just before a rekey still decode.
    previous: KeyMap,
}

/// Cloneable decryptor holding one derived key per sender KID. The KID is read
/// from the SFrame header (K field, 3 bits; X=1 extended KIDs unsupported).
#[derive(Clone)]
pub struct SframeDecryptor {
    state: std::sync::Arc<std::sync::RwLock<DecState>>,
}

fn keymap(senders: impl IntoIterator<Item = (u8, [u8; 16])>) -> KeyMap {
    senders.into_iter().map(|(k, b)| (k, derive(&b))).collect()
}

impl SframeDecryptor {
    /// Single sender with KID 0 (the M1 test-vector shape).
    pub fn new(base_key: &[u8; 16]) -> Self {
        Self::with_senders([(0, *base_key)])
    }

    pub fn with_senders(senders: impl IntoIterator<Item = (u8, [u8; 16])>) -> Self {
        Self { state: std::sync::Arc::new(std::sync::RwLock::new(DecState { current: keymap(senders), previous: KeyMap::new() })) }
    }

    /// Install a new epoch's keys; the outgoing set becomes `previous`.
    pub fn rotate(&self, senders: impl IntoIterator<Item = (u8, [u8; 16])>) {
        let mut st = self.state.write().unwrap();
        st.previous = std::mem::replace(&mut st.current, keymap(senders));
    }

    /// Drop the previous epoch's keys (call after a grace period).
    pub fn forget_previous(&self) {
        self.state.write().unwrap().previous.clear();
    }

    pub fn decrypt(&self, buf: &[u8]) -> Result<Vec<u8>> {
        let st = self.state.read().unwrap();
        open(&st.current, buf).or_else(|e| if st.previous.is_empty() { Err(e) } else { open(&st.previous, buf).map_err(|_| e) })
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
        assert_ne!(&a[..9], &b[..9]); // ctr differs
        assert_eq!(decrypt(&TEST_BASE_KEY, 0, &a).unwrap(), b"hello frame one");
        assert_eq!(decrypt(&TEST_BASE_KEY, 0, &b).unwrap(), b"frame two");
    }

    #[test]
    fn header_format() {
        let mut enc = SframeEncryptor::new(&TEST_BASE_KEY);
        let out = enc.encrypt(b"x").unwrap();
        assert_eq!(out[0], 0x07); // X=0 KID=0 CTR len=8
        // low half is the frame counter: first frame is 0
        assert_eq!(&out[5..9], &0u32.to_be_bytes());
    }

    #[test]
    fn independent_encryptors_do_not_share_nonce_space() {
        // Two processes of one member (same key and KID) must not collide.
        let prefixes: std::collections::HashSet<[u8; 4]> = (0..64)
            .map(|_| {
                let out = SframeEncryptor::new(&TEST_BASE_KEY).encrypt(b"x").unwrap();
                out[1..5].try_into().unwrap()
            })
            .collect();
        assert!(prefixes.len() > 60, "counter prefixes are not random");
    }

    #[test]
    fn shared_counter_survives_restart() {
        let mut a = SframeEncryptor::new(&TEST_BASE_KEY);
        let mut b = a.share();
        let x = a.encrypt(b"1").unwrap();
        let y = b.encrypt(b"2").unwrap();
        assert_ne!(&x[1..9], &y[1..9]);
    }

    #[test]
    fn rekey_and_rotate() {
        let (k1, k2) = ([1u8; 16], [2u8; 16]);
        let mut e = SframeEncryptor::with_kid(&k1, 1);
        let dec = SframeDecryptor::with_senders([(1, k1)]);
        let old = e.encrypt(b"old").unwrap();
        e.share().rekey(&k2); // any handle rekeys them all
        let new = e.encrypt(b"new").unwrap();
        assert!(dec.decrypt(&new).is_err()); // viewer hasn't rotated yet
        dec.rotate([(1, k2)]);
        assert_eq!(dec.decrypt(&new).unwrap(), b"new");
        assert_eq!(dec.decrypt(&old).unwrap(), b"old"); // grace: previous epoch
        dec.forget_previous();
        assert!(dec.decrypt(&old).is_err());
        // a member removed from the next epoch never learns k3
        let mut e3 = SframeEncryptor::with_kid(&[3u8; 16], 1);
        assert!(dec.decrypt(&e3.encrypt(b"secret").unwrap()).is_err());
    }

    #[test]
    fn per_sender_kids() {
        let (ka, kb) = ([1u8; 16], [2u8; 16]);
        let mut ea = SframeEncryptor::with_kid(&ka, 1);
        let mut eb = SframeEncryptor::with_kid(&kb, 2);
        let dec = SframeDecryptor::with_senders([(1, ka), (2, kb)]);
        assert_eq!(dec.decrypt(&ea.encrypt(b"from a").unwrap()).unwrap(), b"from a");
        assert_eq!(dec.decrypt(&eb.encrypt(b"from b").unwrap()).unwrap(), b"from b");
        // unknown sender and cross-keyed KID are both rejected
        let only_a = SframeDecryptor::with_senders([(1, ka)]);
        assert!(only_a.decrypt(&eb.encrypt(b"x").unwrap()).is_err());
        let mut mislabeled = SframeEncryptor::with_kid(&kb, 1);
        assert!(dec.decrypt(&mislabeled.encrypt(b"x").unwrap()).is_err());
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
        // wire format: frame.data equivalent = Annex-B start code + blob NAL
        // (crate::wire, keyframe form), see rtp_send::flush_au + sframe-worker.ts
        let mut wire = vec![0, 0, 0, 1];
        wire.extend_from_slice(&crate::wire::blob_nal(true, &ct));
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        let json = format!(
            "{{\"baseKey\":\"{}\",\"plaintext\":\"{}\",\"ciphertext\":\"{}\"}}\n",
            hex(&TEST_BASE_KEY), hex(&pt), hex(&wire));
        std::fs::write("/tmp/sframe-vector.json", &json).unwrap();
    }
}
