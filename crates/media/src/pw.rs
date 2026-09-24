//! PipeWire discovery helpers: list playback streams (for game-audio pick)
//! and sources (for mic pick). M0 shells out to `pw-dump` — a native PipeWire
//! backend can replace this later without touching callers.

use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct PwNode {
    pub id: u32,
    #[serde(rename = "type")]
    pub kind: String,
    pub info: Option<PwInfo>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PwInfo {
    pub props: Option<serde_json::Value>,
}

#[derive(Debug, Clone)]
pub struct AudioStream {
    /// `object.serial` — this is what pipewiresrc `target-object` wants.
    pub serial: u64,
    pub node_id: u32,
    pub app_name: String,
    pub media_name: String,
}

#[derive(Debug, Clone)]
pub struct AudioSource {
    pub serial: u64,
    pub node_id: u32,
    pub name: String,
    pub description: String,
}

fn prop<'a>(props: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    props.get(key).and_then(|v| v.as_str())
}

fn dump() -> Result<Vec<PwNode>> {
    let out = std::process::Command::new("pw-dump")
        .output()
        .context("pw-dump failed")?;
    serde_json::from_slice(&out.stdout).context("pw-dump json parse")
}

/// Streams of class Stream/Output/Audio — apps currently playing audio.
/// These are the valid `--audio-target` values for game capture.
pub fn list_output_streams() -> Result<Vec<AudioStream>> {
    let mut out = Vec::new();
    for node in dump()? {
        if node.kind != "PipeWire:Interface:Node" {
            continue;
        }
        let Some(props) = node.info.and_then(|i| i.props) else { continue };
        if prop(&props, "media.class") != Some("Stream/Output/Audio") {
            continue;
        }
        let serial = props.get("object.serial")
            .and_then(|v| v.as_str().and_then(|s| s.parse().ok()).or_else(|| v.as_u64()));
        let Some(serial) = serial else { continue };
        out.push(AudioStream {
            serial,
            node_id: node.id,
            app_name: prop(&props, "application.name")
                .or_else(|| prop(&props, "application.process.binary"))
                .unwrap_or("?")
                .to_string(),
            media_name: prop(&props, "media.name").unwrap_or("").to_string(),
        });
    }
    Ok(out)
}

/// Real capture devices (Audio/Source) — mic candidates.
pub fn list_sources() -> Result<Vec<AudioSource>> {
    let mut out = Vec::new();
    for node in dump()? {
        if node.kind != "PipeWire:Interface:Node" {
            continue;
        }
        let Some(props) = node.info.and_then(|i| i.props) else { continue };
        let class = prop(&props, "media.class").unwrap_or("");
        if class != "Audio/Source" {
            continue;
        }
        let serial = props.get("object.serial")
            .and_then(|v| v.as_str().and_then(|s| s.parse().ok()).or_else(|| v.as_u64()));
        let Some(serial) = serial else { continue };
        out.push(AudioSource {
            serial,
            node_id: node.id,
            name: prop(&props, "node.name").unwrap_or("?").to_string(),
            description: prop(&props, "node.description").unwrap_or("").to_string(),
        });
    }
    Ok(out)
}
