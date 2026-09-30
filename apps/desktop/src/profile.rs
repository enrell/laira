//! Local member profile: identity seed, control URL, genesis and membership
//! cert, stored under `$LAIRA_HOME` (default `~/.local/share/laira`) with the
//! secret file at mode 0600. Also resolves the current epoch's SFrame keys
//! from the control service.

use std::path::PathBuf;

use anyhow::{Context, Result};
use laira_identity::{
    EpochBundle, EpochSecret, Genesis, Identity, InviteBundle, JoinRequest, MembershipCert,
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
        reply.epoch.open(&genesis, &me).context("epoch bundle did not open")?;
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
        anyhow::ensure!(p.identity()?.public() == p.genesis.admin, "admin.json does not match community");
        p.save()?;
        Ok(p)
    }

    pub async fn latest_epoch(&self) -> Result<(EpochSecret, EpochBundle)> {
        let http = reqwest::Client::new();
        let b: EpochBundle = get_json(&http, &format!("{}/v1/epoch/latest", self.control)).await?;
        let (secret, _) = b.open(&self.genesis, &self.identity()?)
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

    pub fn public(&self) -> Result<PublicKey> {
        Ok(self.identity()?.public())
    }
}

async fn get_json<T: serde::de::DeserializeOwned>(http: &reqwest::Client, url: &str) -> Result<T> {
    let r = http.get(url).send().await?;
    let status = r.status();
    anyhow::ensure!(status.is_success(), "GET {url}: {status}");
    Ok(r.json().await?)
}
