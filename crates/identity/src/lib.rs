//! laira identity, genesis, invites and membership (M2, first slice).
//!
//! Everything signed here is hashed over a canonical, length-prefixed,
//! domain-separated encoding (never JSON) so signatures cannot be replayed
//! across message kinds. Time is always passed in explicitly (unix seconds).
//!
//! Scope of this slice: a single serializing admin authority per PLAN §11.
//! Recovery (2-of-3) is recorded in the genesis but not yet executed; OpenMLS
//! group keys (PLAN §12) build on `MembershipView` in a later step.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// serde helpers: fixed arrays and byte vectors as lowercase hex strings.
mod hexser {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer, const N: usize>(v: &[u8; N], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(d: D) -> Result<[u8; N], D::Error> {
        let h = String::deserialize(d)?;
        hex::decode(&h).map_err(serde::de::Error::custom)?
            .try_into().map_err(|_| serde::de::Error::custom("wrong length"))
    }
}

mod hexvec {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        hex::decode(String::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}


#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("invalid signature")]
    BadSignature,
    #[error("wrong community")]
    WrongCommunity,
    #[error("unknown invite")]
    UnknownInvite,
    #[error("invite expired")]
    InviteExpired,
    #[error("invite exhausted")]
    InviteExhausted,
    #[error("invite proof invalid")]
    BadInviteProof,
    #[error("member revoked")]
    Revoked,
    #[error("malformed key")]
    BadKey,
    #[error("not in the epoch roster")]
    NotInRoster,
    #[error("too many members for one SFrame domain (max 8)")]
    RosterFull,
    #[error("not the admin authority")]
    NotAdmin,
}

pub type Result<T> = std::result::Result<T, Error>;

/// Ed25519 public key; the durable identity of a user (or device).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PublicKey(#[serde(with = "hexser")] pub [u8; 32]);

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PublicKey({})", hex::encode(&self.0[..6]))
    }
}

impl PublicKey {
    fn verify(&self, msg: &[u8], sig: &[u8; 64]) -> Result<()> {
        let vk = VerifyingKey::from_bytes(&self.0).map_err(|_| Error::BadKey)?;
        vk.verify(msg, &Signature::from_bytes(sig))
            .map_err(|_| Error::BadSignature)
    }
}

/// Secret signing identity.
pub struct Identity {
    sk: SigningKey,
}

impl Identity {
    pub fn generate() -> Self {
        Self::from_seed(rand::random())
    }

    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self { sk: SigningKey::from_bytes(&seed) }
    }

    pub fn public(&self) -> PublicKey {
        PublicKey(self.sk.verifying_key().to_bytes())
    }

    /// Raw seed for on-disk storage; protect the file (mode 0600).
    pub fn seed(&self) -> [u8; 32] {
        self.sk.to_bytes()
    }

    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.sk.sign(msg).to_bytes()
    }
}

/// Canonical encoding: `len(domain) domain (len(field) field)*`, u32 BE lengths.
struct Canon(Vec<u8>);

impl Canon {
    fn new(domain: &str) -> Self {
        Self(Vec::new()).field(domain.as_bytes())
    }
    fn field(mut self, bytes: &[u8]) -> Self {
        self.0.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        self.0.extend_from_slice(bytes);
        self
    }
    fn u64(self, v: u64) -> Self {
        self.field(&v.to_be_bytes())
    }
    fn done(self) -> Vec<u8> {
        self.0
    }
}

pub type CommunityId = [u8; 32];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum Role {
    Member = 0,
    Moderator = 1,
}

// ---------------------------------------------------------------- genesis

/// Signed root of a community: fixes the admin and the recovery policy.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Genesis {
    pub admin: PublicKey,
    pub recovery: Vec<PublicKey>,
    pub recovery_threshold: u8,
    pub created_at: u64,
    #[serde(with = "hexser")]
    pub signature: [u8; 64],
}

impl Genesis {
    pub fn create(admin: &Identity, recovery: Vec<PublicKey>, threshold: u8, now: u64) -> Self {
        let mut g = Genesis {
            admin: admin.public(),
            recovery,
            recovery_threshold: threshold,
            created_at: now,
            signature: [0; 64],
        };
        g.signature = admin.sign(&g.body());
        g
    }

    fn body(&self) -> Vec<u8> {
        let mut c = Canon::new("laira/genesis/v1")
            .field(&self.admin.0)
            .u64(self.created_at)
            .field(&[self.recovery_threshold]);
        for r in &self.recovery {
            c = c.field(&r.0);
        }
        c.done()
    }

    /// Community id commits to the whole unsigned genesis body.
    pub fn community_id(&self) -> CommunityId {
        Sha256::digest(self.body()).into()
    }

    pub fn verify(&self) -> Result<()> {
        self.admin.verify(&self.body(), &self.signature)
    }
}

// ----------------------------------------------------------------- invite

pub type InviteId = [u8; 16];

/// Admin-signed invite. Commits to `secret` without revealing it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Invite {
    #[serde(with = "hexser")]
    pub community_id: CommunityId,
    #[serde(with = "hexser")]
    pub invite_id: InviteId,
    pub expires_at: u64,
    pub max_uses: u32,
    pub role: Role,
    #[serde(with = "hexser")]
    pub secret_commit: [u8; 32],
    #[serde(with = "hexser")]
    pub signature: [u8; 64],
}

impl Invite {
    fn body(&self) -> Vec<u8> {
        Canon::new("laira/invite/v1")
            .field(&self.community_id)
            .field(&self.invite_id)
            .u64(self.expires_at)
            .u64(self.max_uses as u64)
            .field(&[self.role as u8])
            .field(&self.secret_commit)
            .done()
    }

    pub fn verify(&self, genesis: &Genesis) -> Result<()> {
        if self.community_id != genesis.community_id() {
            return Err(Error::WrongCommunity);
        }
        genesis.admin.verify(&self.body(), &self.signature)
    }
}

/// What an invited person receives out of band: the invite plus its secret.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InviteBundle {
    pub invite: Invite,
    #[serde(with = "hexser")]
    pub secret: [u8; 32],
}

/// A prospective member's request to consume an invite.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JoinRequest {
    #[serde(with = "hexser")]
    pub community_id: CommunityId,
    #[serde(with = "hexser")]
    pub invite_id: InviteId,
    pub member: PublicKey,
    #[serde(with = "hexser")]
    pub nonce: [u8; 16],
    #[serde(with = "hexser")]
    pub proof: [u8; 32],
    #[serde(with = "hexser")]
    pub signature: [u8; 64],
}

fn invite_proof(secret: &[u8; 32], member: &PublicKey, nonce: &[u8; 16]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(secret).expect("hmac accepts any key length");
    mac.update(&Canon::new("laira/join-proof/v1").field(&member.0).field(nonce).done());
    mac.finalize().into_bytes().into()
}

impl JoinRequest {
    pub fn new(member: &Identity, bundle: &InviteBundle) -> Self {
        let pk = member.public();
        let nonce: [u8; 16] = rand::random();
        let mut req = JoinRequest {
            community_id: bundle.invite.community_id,
            invite_id: bundle.invite.invite_id,
            member: pk,
            nonce,
            proof: invite_proof(&bundle.secret, &pk, &nonce),
            signature: [0; 64],
        };
        req.signature = member.sign(&req.body());
        req
    }

    fn body(&self) -> Vec<u8> {
        Canon::new("laira/join/v1")
            .field(&self.community_id)
            .field(&self.invite_id)
            .field(&self.member.0)
            .field(&self.nonce)
            .field(&self.proof)
            .done()
    }
}

// ------------------------------------------------- certificates & revocation

/// Admin-signed statement that `member` belongs to the community.
/// `seq` is the admin's global, strictly increasing sequence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipCert {
    #[serde(with = "hexser")]
    pub community_id: CommunityId,
    pub member: PublicKey,
    pub role: Role,
    pub seq: u64,
    pub issued_at: u64,
    #[serde(with = "hexser")]
    pub signature: [u8; 64],
}

impl MembershipCert {
    fn body(&self) -> Vec<u8> {
        Canon::new("laira/member-cert/v1")
            .field(&self.community_id)
            .field(&self.member.0)
            .field(&[self.role as u8])
            .u64(self.seq)
            .u64(self.issued_at)
            .done()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Revocation {
    #[serde(with = "hexser")]
    pub community_id: CommunityId,
    pub member: PublicKey,
    pub seq: u64,
    #[serde(with = "hexser")]
    pub signature: [u8; 64],
}

impl Revocation {
    fn body(&self) -> Vec<u8> {
        Canon::new("laira/revocation/v1")
            .field(&self.community_id)
            .field(&self.member.0)
            .u64(self.seq)
            .done()
    }
}

// --------------------------------------------------------------- authority

struct InviteState {
    invite: Invite,
    secret: [u8; 32],
    uses: u32,
}

/// The admin's side: issues invites, admits members, revokes.
pub struct Authority {
    id: Identity,
    genesis: Genesis,
    seq: u64,
    invites: HashMap<InviteId, InviteState>,
    members: HashMap<PublicKey, MembershipCert>,
    revoked: HashSet<PublicKey>,
    epoch: u64,
    kids: HashMap<PublicKey, u8>,
    latest_epoch: Option<EpochBundle>,
}

/// Serializable authority state (the admin's identity seed is stored
/// separately by the caller).
#[derive(Serialize, Deserialize)]
struct InviteRecord {
    invite: Invite,
    #[serde(with = "hexser")]
    secret: [u8; 32],
    uses: u32,
}

#[derive(Serialize, Deserialize)]
pub struct AuthoritySnapshot {
    genesis: Genesis,
    seq: u64,
    epoch: u64,
    invites: Vec<InviteRecord>,
    members: Vec<MembershipCert>,
    revoked: Vec<PublicKey>,
    kids: Vec<(PublicKey, u8)>,
    latest_epoch: Option<EpochBundle>,
}

impl Authority {
    pub fn snapshot(&self) -> AuthoritySnapshot {
        AuthoritySnapshot {
            genesis: self.genesis.clone(),
            seq: self.seq,
            epoch: self.epoch,
            invites: self.invites.values()
                .map(|i| InviteRecord { invite: i.invite.clone(), secret: i.secret, uses: i.uses }).collect(),
            members: self.members.values().cloned().collect(),
            revoked: self.revoked.iter().copied().collect(),
            kids: self.kids.iter().map(|(k, v)| (*k, *v)).collect(),
            latest_epoch: self.latest_epoch.clone(),
        }
    }

    pub fn restore(id: Identity, snap: AuthoritySnapshot) -> Result<Self> {
        let mut a = Self::new(id, snap.genesis)?;
        a.seq = snap.seq;
        a.epoch = snap.epoch;
        a.invites = snap.invites.into_iter()
            .map(|r| (r.invite.invite_id, InviteState { invite: r.invite, secret: r.secret, uses: r.uses }))
            .collect();
        a.members = snap.members.into_iter().map(|c| (c.member, c)).collect();
        a.revoked = snap.revoked.into_iter().collect();
        a.kids = snap.kids.into_iter().collect();
        a.latest_epoch = snap.latest_epoch;
        Ok(a)
    }

    pub fn latest_epoch(&self) -> Option<&EpochBundle> {
        self.latest_epoch.as_ref()
    }

    /// Issue a session token to a current member who proves key possession.
    pub fn issue_token(&self, req: &TokenRequest, now: u64) -> Result<SessionToken> {
        if req.community_id != self.genesis.community_id() {
            return Err(Error::WrongCommunity);
        }
        req.member.verify(&req.body(), &req.signature)?;
        if now.abs_diff(req.ts) > TOKEN_SKEW_SECS {
            return Err(Error::InviteExpired);
        }
        if !self.is_member(&req.member) {
            return Err(if self.revoked.contains(&req.member) { Error::Revoked } else { Error::NotInRoster });
        }
        let mut t = SessionToken { community_id: req.community_id, member: req.member, expires_at: now + TOKEN_TTL_SECS, signature: [0; 64] };
        t.signature = self.id.sign(&t.body());
        Ok(t)
    }

    pub fn is_member(&self, m: &PublicKey) -> bool {
        *m == self.genesis.admin || self.members.contains_key(m)
    }

    pub fn new(id: Identity, genesis: Genesis) -> Result<Self> {
        genesis.verify()?;
        if genesis.admin != id.public() {
            return Err(Error::NotAdmin);
        }
        Ok(Self {
            id,
            genesis,
            seq: 0,
            invites: HashMap::new(),
            members: HashMap::new(),
            revoked: HashSet::new(),
            epoch: 0,
            kids: HashMap::new(),
            latest_epoch: None,
        })
    }

    pub fn genesis(&self) -> &Genesis {
        &self.genesis
    }

    pub fn create_invite(&mut self, now: u64, ttl_secs: u64, max_uses: u32, role: Role) -> InviteBundle {
        let secret: [u8; 32] = rand::random();
        let mut invite = Invite {
            community_id: self.genesis.community_id(),
            invite_id: rand::random(),
            expires_at: now + ttl_secs,
            max_uses,
            role,
            secret_commit: Sha256::digest(secret).into(),
            signature: [0; 64],
        };
        invite.signature = self.id.sign(&invite.body());
        self.invites.insert(
            invite.invite_id,
            InviteState { invite: invite.clone(), secret, uses: 0 },
        );
        InviteBundle { invite, secret }
    }

    /// Validate a join request and issue a membership certificate.
    /// Re-admitting an existing member is idempotent and consumes no use.
    pub fn admit(&mut self, req: &JoinRequest, now: u64) -> Result<MembershipCert> {
        if req.community_id != self.genesis.community_id() {
            return Err(Error::WrongCommunity);
        }
        req.member.verify(&req.body(), &req.signature)?;
        if self.revoked.contains(&req.member) {
            return Err(Error::Revoked);
        }
        let st = self.invites.get_mut(&req.invite_id).ok_or(Error::UnknownInvite)?;
        // Constant-time enough: compare through the MAC output equality of
        // equal-length arrays after recomputation.
        let expect = invite_proof(&st.secret, &req.member, &req.nonce);
        if !ct_eq(&expect, &req.proof) {
            return Err(Error::BadInviteProof);
        }
        if let Some(existing) = self.members.get(&req.member) {
            return Ok(existing.clone());
        }
        if now >= st.invite.expires_at {
            return Err(Error::InviteExpired);
        }
        if st.uses >= st.invite.max_uses {
            return Err(Error::InviteExhausted);
        }
        st.uses += 1;
        let role = st.invite.role;
        self.seq += 1;
        let mut cert = MembershipCert {
            community_id: self.genesis.community_id(),
            member: req.member,
            role,
            seq: self.seq,
            issued_at: now,
            signature: [0; 64],
        };
        cert.signature = self.id.sign(&cert.body());
        self.members.insert(req.member, cert.clone());
        Ok(cert)
    }

    /// Start a new epoch for the admin plus all current members. Call after
    /// every membership change so revoked members can't open the new secret.
    /// KID slots are sticky within a community lifetime and never reused
    /// while the member is present; freed slots are recycled.
    pub fn new_epoch(&mut self) -> Result<EpochBundle> {
        let cid = self.genesis.community_id();
        let mut who: Vec<PublicKey> = vec![self.genesis.admin];
        let mut members: Vec<&MembershipCert> = self.members.values().collect();
        members.sort_by_key(|c| c.seq);
        who.extend(members.iter().map(|c| c.member));
        self.kids.retain(|k, _| who.contains(k));
        for pk in &who {
            if !self.kids.contains_key(pk) {
                let used: HashSet<u8> = self.kids.values().copied().collect();
                let kid = (0..MAX_KIDS as u8).find(|k| !used.contains(k)).ok_or(Error::RosterFull)?;
                self.kids.insert(*pk, kid);
            }
        }
        self.epoch += 1;
        let secret: [u8; 32] = rand::random();
        let aad = EpochBundle::aad(&cid, self.epoch);
        let mut roster: Vec<(u8, PublicKey)> = who.iter().map(|p| (self.kids[p], *p)).collect();
        roster.sort();
        let sealed = who.iter().map(|p| Ok((*p, seal(&secret, p, &aad)?))).collect::<Result<Vec<_>>>()?;
        let mut b = EpochBundle { community_id: cid, epoch: self.epoch, roster, sealed, signature: [0; 64] };
        b.signature = self.id.sign(&b.body());
        self.latest_epoch = Some(b.clone());
        Ok(b)
    }

    pub fn revoke(&mut self, member: PublicKey) -> Revocation {
        self.seq += 1;
        self.members.remove(&member);
        self.revoked.insert(member);
        let mut r = Revocation {
            community_id: self.genesis.community_id(),
            member,
            seq: self.seq,
            signature: [0; 64],
        };
        r.signature = self.id.sign(&r.body());
        r
    }
}

fn ct_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

// -------------------------------------------------------------------- view

/// Any peer's verified view of who is a member, built only from
/// admin-signed certificates and revocations. Highest `seq` per member wins,
/// so delivery order and duplicates don't matter.
pub struct MembershipView {
    genesis: Genesis,
    // member -> (seq, Some(role) if member, None if revoked)
    state: HashMap<PublicKey, (u64, Option<Role>)>,
}

impl MembershipView {
    pub fn new(genesis: Genesis) -> Result<Self> {
        genesis.verify()?;
        Ok(Self { genesis, state: HashMap::new() })
    }

    pub fn apply_cert(&mut self, c: &MembershipCert) -> Result<()> {
        self.check(c.community_id, &c.body(), &c.signature)?;
        self.put(c.member, c.seq, Some(c.role));
        Ok(())
    }

    pub fn apply_revocation(&mut self, r: &Revocation) -> Result<()> {
        self.check(r.community_id, &r.body(), &r.signature)?;
        self.put(r.member, r.seq, None);
        Ok(())
    }

    fn check(&self, cid: CommunityId, body: &[u8], sig: &[u8; 64]) -> Result<()> {
        if cid != self.genesis.community_id() {
            return Err(Error::WrongCommunity);
        }
        self.genesis.admin.verify(body, sig)
    }

    fn put(&mut self, m: PublicKey, seq: u64, role: Option<Role>) {
        match self.state.get(&m) {
            Some((s, _)) if *s >= seq => {}
            _ => {
                self.state.insert(m, (seq, role));
            }
        }
    }

    pub fn role_of(&self, m: &PublicKey) -> Option<Role> {
        self.state.get(m).and_then(|(_, r)| *r)
    }

    pub fn is_member(&self, m: &PublicKey) -> bool {
        self.role_of(m).is_some()
    }
}

// ------------------------------------------------------------- key schedule

/// Per-epoch group secret with an MLS-exporter-shaped interface
/// (`export(label, context, len)`), so an OpenMLS group's exporter secret can
/// replace the source of `secret` without touching callers. The secret must
/// already be bound to the community/domain by whoever produces it.
pub struct EpochSecret {
    secret: [u8; 32],
    epoch: u64,
}

impl EpochSecret {
    pub fn new(secret: [u8; 32], epoch: u64) -> Self {
        Self { secret, epoch }
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// HKDF-Expand over `canonical(label, epoch, context)`; output is
    /// independent per label, context and epoch.
    pub fn export(&self, label: &str, context: &[u8], out: &mut [u8]) {
        let hk = hkdf::Hkdf::<Sha256>::from_prk(&self.secret).expect("32-byte prk");
        let info = Canon::new("laira/export/v1")
            .field(label.as_bytes())
            .u64(self.epoch)
            .field(context)
            .done();
        hk.expand(&info, out).expect("output length within hkdf limit");
    }

    /// SFrame base key for the sender occupying roster slot `kid` (0..=7).
    pub fn sframe_base_key(&self, kid: u8) -> [u8; 16] {
        let mut k = [0u8; 16];
        self.export("sframe-base-key", &[kid], &mut k);
        k
    }
}

// ---------------------------------------------------------- session tokens

/// Member's proof-of-possession request for a session token.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenRequest {
    #[serde(with = "hexser")]
    pub community_id: CommunityId,
    pub member: PublicKey,
    pub ts: u64,
    #[serde(with = "hexser")]
    pub signature: [u8; 64],
}

impl TokenRequest {
    pub fn new(me: &Identity, community_id: CommunityId, now: u64) -> Self {
        let mut r = TokenRequest { community_id, member: me.public(), ts: now, signature: [0; 64] };
        r.signature = me.sign(&r.body());
        r
    }
    fn body(&self) -> Vec<u8> {
        Canon::new("laira/token-request/v1").field(&self.community_id).field(&self.member.0).u64(self.ts).done()
    }
}

/// Short-lived admin-signed pass that services (SFU, mailbox) verify offline
/// with only the genesis admin key. Wire canonical form is mirrored in
/// services/sfu/server.mjs (`tokenBody`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionToken {
    #[serde(with = "hexser")]
    pub community_id: CommunityId,
    pub member: PublicKey,
    pub expires_at: u64,
    #[serde(with = "hexser")]
    pub signature: [u8; 64],
}

pub const TOKEN_SKEW_SECS: u64 = 60;
pub const TOKEN_TTL_SECS: u64 = 300;

impl SessionToken {
    fn body(&self) -> Vec<u8> {
        Canon::new("laira/session-token/v1")
            .field(&self.community_id).field(&self.member.0).u64(self.expires_at).done()
    }

    pub fn verify(&self, genesis: &Genesis, now: u64) -> Result<()> {
        if self.community_id != genesis.community_id() {
            return Err(Error::WrongCommunity);
        }
        if now >= self.expires_at {
            return Err(Error::InviteExpired);
        }
        genesis.admin.verify(&self.body(), &self.signature)
    }
}

// ------------------------------------------------------ epoch distribution

use aes_gcm::{aead::{Aead, Payload}, Aes256Gcm};

/// Sealed-box style encryption of a 32-byte secret to an Ed25519 identity
/// (converted to X25519): ephemeral DH -> HKDF -> AES-256-GCM.
fn x25519_secret(id: &Identity) -> x25519_dalek::StaticSecret {
    x25519_dalek::StaticSecret::from(id.sk.to_scalar_bytes())
}

fn x25519_public(pk: &PublicKey) -> Result<x25519_dalek::PublicKey> {
    let vk = VerifyingKey::from_bytes(&pk.0).map_err(|_| Error::BadKey)?;
    Ok(x25519_dalek::PublicKey::from(vk.to_montgomery().to_bytes()))
}

fn seal_key(shared: &[u8; 32], eph: &[u8; 32], recipient: &PublicKey) -> ([u8; 32], [u8; 12]) {
    let hk = hkdf::Hkdf::<Sha256>::new(Some(b"laira/seal/v1"), shared);
    let info = Canon::new("laira/seal-info/v1").field(eph).field(&recipient.0).done();
    let mut okm = [0u8; 44];
    hk.expand(&info, &mut okm).expect("hkdf");
    (okm[..32].try_into().unwrap(), okm[32..].try_into().unwrap())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sealed {
    #[serde(with = "hexser")]
    pub ephemeral: [u8; 32],
    #[serde(with = "hexvec")]
    pub ciphertext: Vec<u8>,
}

fn seal(secret: &[u8; 32], to: &PublicKey, aad: &[u8]) -> Result<Sealed> {
    let eph = x25519_dalek::StaticSecret::from(rand::random::<[u8; 32]>());
    let eph_pub = x25519_dalek::PublicKey::from(&eph).to_bytes();
    let shared = eph.diffie_hellman(&x25519_public(to)?);
    let (key, nonce) = seal_key(shared.as_bytes(), &eph_pub, to);
    let ct = Aes256Gcm::new_from_slice(&key).expect("len")
        .encrypt(&nonce.into(), Payload { msg: secret, aad })
        .map_err(|_| Error::BadSignature)?;
    Ok(Sealed { ephemeral: eph_pub, ciphertext: ct })
}

fn unseal(s: &Sealed, me: &Identity, aad: &[u8]) -> Result<[u8; 32]> {
    let shared = x25519_secret(me).diffie_hellman(&x25519_dalek::PublicKey::from(s.ephemeral));
    let (key, nonce) = seal_key(shared.as_bytes(), &s.ephemeral, &me.public());
    let pt = Aes256Gcm::new_from_slice(&key).expect("len")
        .decrypt(&nonce.into(), Payload { msg: &s.ciphertext, aad })
        .map_err(|_| Error::NotInRoster)?;
    pt.try_into().map_err(|_| Error::NotInRoster)
}

/// One epoch of group keying, produced by the domain's controller (the admin
/// in v1, PLAN §12: durable membership changes are serialized by one
/// controller). The roster binds SFrame KID slots to identities and is
/// covered by the admin signature, so a KID can't be claimed by another key.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EpochBundle {
    #[serde(with = "hexser")]
    pub community_id: CommunityId,
    pub epoch: u64,
    /// (kid, member) — kid is stable for a member within the bundle, <= 7.
    pub roster: Vec<(u8, PublicKey)>,
    pub sealed: Vec<(PublicKey, Sealed)>,
    #[serde(with = "hexser")]
    pub signature: [u8; 64],
}

pub const MAX_KIDS: usize = 8;

impl EpochBundle {
    fn body(&self) -> Vec<u8> {
        let mut c = Canon::new("laira/epoch-bundle/v1").field(&self.community_id).u64(self.epoch);
        for (kid, pk) in &self.roster {
            c = c.field(&[*kid]).field(&pk.0);
        }
        for (pk, s) in &self.sealed {
            c = c.field(&pk.0).field(&s.ephemeral).field(&s.ciphertext);
        }
        c.done()
    }

    fn aad(community_id: &CommunityId, epoch: u64) -> Vec<u8> {
        Canon::new("laira/epoch-seal-aad/v1").field(community_id).u64(epoch).done()
    }

    /// Verify against the genesis and open our copy of the epoch secret.
    /// Returns the secret plus the roster (kid -> member).
    pub fn open(&self, genesis: &Genesis, me: &Identity) -> Result<(EpochSecret, Vec<(u8, PublicKey)>)> {
        if self.community_id != genesis.community_id() {
            return Err(Error::WrongCommunity);
        }
        genesis.admin.verify(&self.body(), &self.signature)?;
        let mine = self.sealed.iter().find(|(pk, _)| *pk == me.public()).ok_or(Error::NotInRoster)?;
        let secret = unseal(&mine.1, me, &Self::aad(&self.community_id, self.epoch))?;
        Ok((EpochSecret::new(secret, self.epoch), self.roster.clone()))
    }

    pub fn kid_of(&self, m: &PublicKey) -> Option<u8> {
        self.roster.iter().find(|(_, p)| p == m).map(|(k, _)| *k)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (Authority, Genesis) {
        let admin = Identity::from_seed([1; 32]);
        let rec = vec![Identity::from_seed([2; 32]).public(), Identity::from_seed([3; 32]).public()];
        let g = Genesis::create(&admin, rec, 2, 1000);
        (Authority::new(admin, g.clone()).unwrap(), g)
    }

    #[test]
    fn session_tokens() {
        let (mut auth, g) = setup();
        let b = auth.create_invite(1000, 600, 2, Role::Member);
        let a = Identity::generate();
        auth.admit(&JoinRequest::new(&a, &b), 1001).unwrap();
        let cid = g.community_id();
        let t = auth.issue_token(&TokenRequest::new(&a, cid, 1002), 1002).unwrap();
        t.verify(&g, 1003).unwrap();
        assert_eq!(t.verify(&g, 1002 + TOKEN_TTL_SECS), Err(Error::InviteExpired));
        // outsider and stale request are refused; revoked member loses access
        let m = Identity::generate();
        assert_eq!(auth.issue_token(&TokenRequest::new(&m, cid, 1002), 1002).err(), Some(Error::NotInRoster));
        assert!(auth.issue_token(&TokenRequest::new(&a, cid, 500), 1002).is_err());
        auth.revoke(a.public());
        assert_eq!(auth.issue_token(&TokenRequest::new(&a, cid, 1005), 1005).err(), Some(Error::Revoked));
        let mut forged = t.clone();
        forged.member = m.public();
        assert!(forged.verify(&g, 1003).is_err());
    }

    #[test]
    fn snapshot_roundtrip_json() {
        let (mut auth, g) = setup();
        let b = auth.create_invite(1000, 600, 2, Role::Member);
        let a = Identity::generate();
        auth.admit(&JoinRequest::new(&a, &b), 1001).unwrap();
        let e = auth.new_epoch().unwrap();
        let json = serde_json::to_string(&auth.snapshot()).unwrap();
        let mut back = Authority::restore(Identity::from_seed([1; 32]), serde_json::from_str(&json).unwrap()).unwrap();
        assert!(back.is_member(&a.public()));
        assert_eq!(back.latest_epoch().unwrap().epoch, e.epoch);
        // invite use count survived: one use left, then exhausted
        back.admit(&JoinRequest::new(&Identity::generate(), &b), 1002).unwrap();
        assert_eq!(back.admit(&JoinRequest::new(&Identity::generate(), &b), 1003), Err(Error::InviteExhausted));
        // wire types roundtrip and still verify
        let eb: EpochBundle = serde_json::from_str(&serde_json::to_string(&e).unwrap()).unwrap();
        eb.open(&g, &a).unwrap();
    }

    #[test]
    fn epoch_keys_are_separated() {
        let e1 = EpochSecret::new([5; 32], 1);
        let e2 = EpochSecret::new([5; 32], 2);
        let other = EpochSecret::new([6; 32], 1);
        assert_eq!(e1.sframe_base_key(0), EpochSecret::new([5; 32], 1).sframe_base_key(0));
        assert_ne!(e1.sframe_base_key(0), e1.sframe_base_key(1));
        assert_ne!(e1.sframe_base_key(0), e2.sframe_base_key(0));
        assert_ne!(e1.sframe_base_key(0), other.sframe_base_key(0));
    }

    #[test]
    fn epoch_distribution_and_revocation() {
        let (mut auth, g) = setup();
        let admin = Identity::from_seed([1; 32]);
        let b = auth.create_invite(1000, 600, 3, Role::Member);
        let (alice, bob) = (Identity::generate(), Identity::generate());
        auth.admit(&JoinRequest::new(&alice, &b), 1001).unwrap();
        auth.admit(&JoinRequest::new(&bob, &b), 1001).unwrap();
        let e1 = auth.new_epoch().unwrap();
        let (sa, ra) = e1.open(&g, &alice).unwrap();
        let (sb, _) = e1.open(&g, &bob).unwrap();
        let (sad, _) = e1.open(&g, &admin).unwrap();
        let kid_a = e1.kid_of(&alice.public()).unwrap();
        assert_eq!(sa.sframe_base_key(kid_a), sb.sframe_base_key(kid_a));
        assert_eq!(sa.sframe_base_key(0), sad.sframe_base_key(0));
        assert_eq!(ra.len(), 3);
        let kids: HashSet<u8> = e1.roster.iter().map(|(k, _)| *k).collect();
        assert_eq!(kids.len(), 3);
        // outsider can't open; tampered roster breaks the signature
        assert_eq!(e1.open(&g, &Identity::generate()).err(), Some(Error::NotInRoster));
        let mut forged = e1.clone();
        forged.roster[0].0 = 7;
        assert_eq!(forged.open(&g, &alice).err(), Some(Error::BadSignature));
        // revoke bob -> next epoch excludes him; alice keeps her KID
        auth.revoke(bob.public());
        let e2 = auth.new_epoch().unwrap();
        assert_eq!(e2.open(&g, &bob).err(), Some(Error::NotInRoster));
        let (sa2, _) = e2.open(&g, &alice).unwrap();
        assert_eq!(e2.kid_of(&alice.public()), Some(kid_a));
        assert_ne!(sa.sframe_base_key(kid_a), sa2.sframe_base_key(kid_a));
        // old bundle replayed against a different community fails
        let og = Genesis::create(&Identity::from_seed([8; 32]), vec![], 0, 1);
        assert_eq!(e1.open(&og, &alice).err(), Some(Error::WrongCommunity));
    }

    #[test]
    fn genesis_tamper_detected() {
        let (_, mut g) = setup();
        g.verify().unwrap();
        g.recovery_threshold = 1;
        assert_eq!(g.verify(), Err(Error::BadSignature));
    }

    #[test]
    fn member_joins_with_invite() {
        let (mut auth, g) = setup();
        let bundle = auth.create_invite(1000, 600, 1, Role::Member);
        bundle.invite.verify(&g).unwrap();
        let alice = Identity::generate();
        let cert = auth.admit(&JoinRequest::new(&alice, &bundle), 1001).unwrap();
        let mut view = MembershipView::new(g).unwrap();
        view.apply_cert(&cert).unwrap();
        assert!(view.is_member(&alice.public()));
    }

    #[test]
    fn non_member_rejected() {
        let (mut auth, g) = setup();
        let bundle = auth.create_invite(1000, 600, 5, Role::Member);
        // Knows the invite id but not the secret.
        let mallory = Identity::generate();
        let mut forged = bundle.clone();
        forged.secret = [9; 32];
        assert_eq!(
            auth.admit(&JoinRequest::new(&mallory, &forged), 1001),
            Err(Error::BadInviteProof)
        );
        // Request signed by someone else than the claimed member.
        let mut req = JoinRequest::new(&mallory, &bundle);
        req.member = Identity::generate().public();
        assert_eq!(auth.admit(&req, 1001), Err(Error::BadSignature));
        // Never issued: not a member in any view.
        let view = MembershipView::new(g).unwrap();
        assert!(!view.is_member(&mallory.public()));
    }

    #[test]
    fn invite_limits() {
        let (mut auth, _) = setup();
        let one = auth.create_invite(1000, 600, 1, Role::Member);
        auth.admit(&JoinRequest::new(&Identity::generate(), &one), 1001).unwrap();
        assert_eq!(
            auth.admit(&JoinRequest::new(&Identity::generate(), &one), 1002),
            Err(Error::InviteExhausted)
        );
        let short = auth.create_invite(1000, 10, 5, Role::Member);
        assert_eq!(
            auth.admit(&JoinRequest::new(&Identity::generate(), &short), 1010),
            Err(Error::InviteExpired)
        );
    }

    #[test]
    fn readmit_is_idempotent() {
        let (mut auth, _) = setup();
        let b = auth.create_invite(1000, 600, 1, Role::Member);
        let a = Identity::generate();
        let c1 = auth.admit(&JoinRequest::new(&a, &b), 1001).unwrap();
        let c2 = auth.admit(&JoinRequest::new(&a, &b), 1002).unwrap();
        assert_eq!(c1.seq, c2.seq);
    }

    #[test]
    fn revocation_wins_regardless_of_order() {
        let (mut auth, g) = setup();
        let b = auth.create_invite(1000, 600, 2, Role::Member);
        let a = Identity::generate();
        let cert = auth.admit(&JoinRequest::new(&a, &b), 1001).unwrap();
        let rev = auth.revoke(a.public());

        let mut v1 = MembershipView::new(g.clone()).unwrap();
        v1.apply_cert(&cert).unwrap();
        v1.apply_revocation(&rev).unwrap();
        let mut v2 = MembershipView::new(g).unwrap();
        v2.apply_revocation(&rev).unwrap();
        v2.apply_cert(&cert).unwrap(); // stale cert arrives late
        assert!(!v1.is_member(&a.public()));
        assert!(!v2.is_member(&a.public()));
        // And a revoked key can't rejoin with the same invite.
        assert_eq!(auth.admit(&JoinRequest::new(&a, &b), 1003), Err(Error::Revoked));
    }

    #[test]
    fn foreign_community_and_forged_certs_rejected() {
        let (mut auth, g) = setup();
        let other_admin = Identity::from_seed([7; 32]);
        let og = Genesis::create(&other_admin, vec![], 0, 5);
        let mut other = Authority::new(other_admin, og.clone()).unwrap();
        let b = other.create_invite(1000, 600, 1, Role::Member);
        let a = Identity::generate();
        assert_eq!(auth.admit(&JoinRequest::new(&a, &b), 1001), Err(Error::WrongCommunity));
        let cert = other.admit(&JoinRequest::new(&a, &b), 1001).unwrap();
        let mut view = MembershipView::new(g).unwrap();
        assert_eq!(view.apply_cert(&cert), Err(Error::WrongCommunity));
    }
}
