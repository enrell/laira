//! Local member profile: identity seed, control URL, genesis and membership
//! cert, stored under `$LAIRA_HOME` (default `~/.local/share/laira`) with the
//! secret file at mode 0600. Also resolves the current epoch's SFrame keys
//! from the control service.

use std::path::PathBuf;

use anyhow::{Context, Result};
use laira_identity::{
    Route, Attachment, FILE_CHUNK, Channel, ChatEnvelope, AdminRecovery, RecoveryChain, Trust, EpochBundle, EpochSecret, Genesis, Identity, InviteBundle, JoinRequest, MembershipCert,
    PublicKey, SessionToken, TokenRequest,
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct Profile {
    seed: String,
    pub control: String,
    pub genesis: Genesis,
    /// None for the admin, who is not admitted through an invite.
    pub cert: Option<MembershipCert>,
}

pub fn home() -> PathBuf {
    std::env::var_os("LAIRA_HOME").map(PathBuf::from).unwrap_or_else(|| {
        PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".local/share/laira")
    })
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

impl Profile {
    fn path() -> PathBuf {
        home().join("profile.json")
    }

    pub fn load() -> Result<Option<Profile>> {
        match std::fs::read(Self::path()) {
            Ok(b) => Ok(Some(serde_json::from_slice(&b).context("corrupt profile.json")?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn save(&self) -> Result<()> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::create_dir_all(home())?;
        let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true)
            .mode(0o600).open(Self::path())?;
        f.write_all(&serde_json::to_vec_pretty(self)?)?;
        Ok(())
    }

    pub fn identity(&self) -> Result<Identity> {
        let seed: [u8; 32] = hex::decode(&self.seed)?.try_into().map_err(|_| anyhow::anyhow!("bad seed"))?;
        Ok(Identity::from_seed(seed))
    }

    /// Join a community with an invite; verifies the genesis binding and the
    /// returned epoch before writing anything to disk.
    pub async fn join(control: &str, invite: InviteBundle) -> Result<Profile> {
        anyhow::ensure!(Self::load()?.is_none(), "profile already exists in {}", home().display());
        let http = reqwest::Client::new();
        let genesis: Genesis = get_json(&http, &format!("{control}/v1/genesis")).await?;
        genesis.verify()?;
        invite.invite.verify(&genesis).context("invite does not match this community")?;
        let me = Identity::generate();
        let req = JoinRequest::new(&me, &invite);
        let r = http.post(format!("{control}/v1/join")).json(&req).send().await?;
        let status = r.status();
        let text = r.text().await?;
        anyhow::ensure!(status.is_success(), "join refused: {status} {text}");
        #[derive(Deserialize)]
        struct Reply { cert: MembershipCert, epoch: EpochBundle }
        let reply: Reply = serde_json::from_str(&text)?;
        let trust = trust_from(&http, control, &genesis).await?;
        reply.epoch.open(&trust, &me).context("epoch bundle did not open")?;
        let p = Profile { seed: hex::encode(me.seed()), control: control.into(), genesis, cert: Some(reply.cert) };
        p.save()?;
        Ok(p)
    }

    /// Use the admin identity created by `laira-control init` as this
    /// machine's member profile (the admin sits in the roster too).
    pub async fn adopt_admin(control: &str, dir: &std::path::Path) -> Result<Profile> {
        anyhow::ensure!(Self::load()?.is_none(), "profile already exists in {}", home().display());
        #[derive(Deserialize)]
        struct A { seed: String }
        let a: A = serde_json::from_slice(&std::fs::read(dir.join("admin.json"))?)?;
        let http = reqwest::Client::new();
        let genesis: Genesis = get_json(&http, &format!("{control}/v1/genesis")).await?;
        genesis.verify()?;
        let p = Profile { seed: a.seed, control: control.into(), genesis, cert: None };
        anyhow::ensure!(p.identity()?.public() == p.trust().await?.admin, "admin.json is not the community's current admin");
        p.save()?;
        Ok(p)
    }

    /// The current admin per the guardian-signed recovery chain (verified
    /// against the genesis, never taken on the control service's word).
    pub async fn trust(&self) -> Result<Trust> {
        trust_from(&reqwest::Client::new(), &self.control, &self.genesis).await
    }

    pub async fn latest_epoch(&self) -> Result<(EpochSecret, EpochBundle)> {
        let http = reqwest::Client::new();
        let b: EpochBundle = get_json(&http, &format!("{}/v1/epoch/latest", self.control)).await?;
        let trust = self.trust().await?;
        let (secret, _) = b.open(&trust, &self.identity()?)
            .context("cannot open current epoch (revoked or not in roster?)")?;
        Ok((secret, b))
    }

    pub async fn session_token(&self) -> Result<SessionToken> {
        let me = self.identity()?;
        let req = TokenRequest::new(&me, self.genesis.community_id(), now());
        let r = reqwest::Client::new().post(format!("{}/v1/token", self.control)).json(&req).send().await?;
        let status = r.status();
        let text = r.text().await?;
        anyhow::ensure!(status.is_success(), "token refused: {status} {text}");
        Ok(serde_json::from_str(&text)?)
    }

    async fn token_header(&self) -> Result<String> {
        Ok(hex::encode(serde_json::to_vec(&self.session_token().await?)?))
    }

    async fn authed(&self, req: reqwest::RequestBuilder) -> Result<reqwest::Response> {
        let r = req.header("x-laira-token", self.token_header().await?).send().await?;
        let status = r.status();
        if !status.is_success() {
            anyhow::bail!("{status}: {}", r.text().await.unwrap_or_default());
        }
        Ok(r)
    }

    pub async fn channels(&self) -> Result<Vec<Channel>> {
        let http = reqwest::Client::new();
        Ok(self.authed(http.get(format!("{}/v1/channels", self.control))).await?.json().await?)
    }

    pub async fn create_channel(&self, name: &str) -> Result<Channel> {
        let http = reqwest::Client::new();
        let c: Channel = self.authed(http.post(format!("{}/v1/channels", self.control))
            .json(&serde_json::json!({ "name": name }))).await?.json().await?;
        c.verify(&self.trust().await?).context("channel signature")?;
        Ok(c)
    }

    pub async fn send_chat(&self, channel: &str, text: &str) -> Result<u64> {
        let (secret, _) = self.latest_epoch().await?;
        let env = ChatEnvelope::seal(&self.identity()?, &secret, self.genesis.community_id(), channel, text, now())?;
        let http = reqwest::Client::new();
        Ok(self.authed(http.post(format!("{}/v1/chat/{channel}", self.control)).json(&env)).await?.json().await?)
    }

    /// Fetch messages after `after`; each is verified and decrypted with the
    /// secret of the epoch it was sent in (fetched and cached on demand).
    pub async fn read_chat(&self, channel: &str, after: u64) -> Result<Vec<ChatLine>> {
        #[derive(Deserialize)]
        struct Stored { seq: u64, envelope: ChatEnvelope }
        let http = reqwest::Client::new();
        let msgs: Vec<Stored> = self.authed(http.get(format!("{}/v1/chat/{channel}?after={after}", self.control)))
            .await?.json().await?;
        let trust = self.trust().await?;
        let me = self.identity()?;
        let mut secrets: std::collections::HashMap<u64, Option<EpochSecret>> = Default::default();
        let mut out = Vec::new();
        for m in msgs {
            let e = m.envelope;
            if !secrets.contains_key(&e.epoch) {
                let s = match get_json::<EpochBundle>(&http, &format!("{}/v1/epoch/{}", self.control, e.epoch)).await {
                    Ok(b) => b.open(&trust, &me).ok().map(|(s, _)| s),
                    Err(_) => None,
                };
                secrets.insert(e.epoch, s);
            }
            let text = match secrets[&e.epoch].as_ref() {
                Some(s) => e.open(s).map_err(|err| format!("[invalid message: {err}]")),
                None => Err(format!("[unreadable: you were not a member during epoch {}]", e.epoch)),
            };
            out.push(ChatLine { seq: m.seq, sender: e.sender, ts: e.ts, text: text.unwrap_or_else(|t| t) });
        }
        Ok(out)
    }

    /// SFU signaling URLs from the admin-signed route (verified against the
    /// current trust anchor), or None if no route is published.
    pub async fn route(&self) -> Result<Option<Route>> {
        let http = reqwest::Client::new();
        let r = http.get(format!("{}/v1/route", self.control)).send().await?;
        if r.status() == reqwest::StatusCode::NOT_FOUND { return Ok(None); }
        anyhow::ensure!(r.status().is_success(), "route: {}", r.status());
        let route: Route = r.json().await?;
        route.verify(&self.trust().await?).context("route signature")?;
        Ok(Some(route))
    }

    /// Encrypt `path` chunk by chunk, upload the ciphertext to the relay, then
    /// announce it in the channel; the file key travels only inside the E2EE
    /// chat message.
    pub async fn send_file(&self, channel: &str, path: &std::path::Path) -> Result<Attachment> {
        let data = std::fs::read(path).with_context(|| path.display().to_string())?;
        let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "file".into());
        let (att, chunks) = Attachment::encrypt(&name, &data)?;
        let http = reqwest::Client::new();
        let token = self.token_header().await?;
        for (i, c) in chunks.iter().enumerate() {
            let r = http.put(format!("{}/v1/blob/{}/{i}", self.control, att.id))
                .header("x-laira-token", &token).body(c.clone()).send().await?;
            anyhow::ensure!(r.status().is_success(), "upload chunk {i}: {} {}", r.status(), r.text().await.unwrap_or_default());
        }
        self.send_chat(channel, &att.to_message()).await?;
        Ok(att)
    }

    /// Download and decrypt the attachment of message `seq` into `out_dir`.
    pub async fn save_file(&self, channel: &str, seq: u64, out_dir: &std::path::Path) -> Result<std::path::PathBuf> {
        let line = self.read_chat(channel, seq.saturating_sub(1)).await?.into_iter().find(|l| l.seq == seq)
            .context("no such message")?;
        let att = Attachment::from_message(&line.text).context("message has no attachment (or it was unreadable)")?;
        let http = reqwest::Client::new();
        let token = self.token_header().await?;
        let mut data = Vec::with_capacity(att.size as usize);
        for i in 0..att.chunks {
            let r = http.get(format!("{}/v1/blob/{}/{i}", self.control, att.id)).header("x-laira-token", &token).send().await?;
            anyhow::ensure!(r.status().is_success(), "download chunk {i}: {}", r.status());
            data.extend(att.decrypt_chunk(i, &r.bytes().await?).context("chunk failed authentication")?);
        }
        anyhow::ensure!(data.len() as u64 == att.size, "size mismatch");
        // The name came from another member: keep only a safe basename.
        let safe: String = att.name.rsplit(['/', '\\']).next().unwrap_or("file").trim_start_matches('.').chars()
            .filter(|c| !c.is_control()).collect();
        let out = out_dir.join(if safe.is_empty() { "file" } else { &safe });
        anyhow::ensure!(!out.exists(), "{} already exists", out.display());
        std::fs::write(&out, data)?;
        let _ = FILE_CHUNK;
        Ok(out)
    }

    pub fn public(&self) -> Result<PublicKey> {
        Ok(self.identity()?.public())
    }
}

pub struct ChatLine {
    pub seq: u64,
    pub sender: PublicKey,
    pub ts: u64,
    pub text: String,
}

async fn trust_from(http: &reqwest::Client, control: &str, genesis: &Genesis) -> Result<Trust> {
    let recs: Vec<AdminRecovery> = get_json(http, &format!("{control}/v1/recoveries")).await?;
    let mut chain = RecoveryChain::new(genesis.clone())?;
    for r in &recs {
        chain.apply(r).context("control service returned an invalid recovery chain")?;
    }
    Ok(Trust::from(&chain))
}

async fn get_json<T: serde::de::DeserializeOwned>(http: &reqwest::Client, url: &str) -> Result<T> {
    let r = http.get(url).send().await?;
    let status = r.status();
    anyhow::ensure!(status.is_success(), "GET {url}: {status}");
    Ok(r.json().await?)
}
