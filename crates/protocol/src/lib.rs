//! laira signaling protocol (M0): JSON messages over a WebSocket.
//!
//! Keep in sync with services/sfu/server.mjs (`handlers` map) and
//! apps/web/src/main.ts. Envelope is request/response by `id`; the server
//! also pushes unsolicited `event` messages.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Request sent by a client.
#[derive(Debug, Clone, Serialize)]
pub struct Request {
    pub id: u64,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

/// Any message the server can send.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum ServerMessage {
    /// Reply to a request: `{id, ok, data|error}`.
    Reply {
        id: u64,
        ok: bool,
        #[serde(default)]
        data: Option<Value>,
        #[serde(default)]
        error: Option<String>,
    },
    /// Server-pushed event: `{type: "event", event, data}`.
    Event { event: String, data: Value },
}

/// Methods a client may call (subset typed; params stay as JSON).
pub mod methods {
    pub const JOIN: &str = "join";
    pub const CREATE_SEND_TRANSPORT: &str = "createSendTransport";
    pub const CREATE_RECV_TRANSPORT: &str = "createRecvTransport";
    pub const CONNECT: &str = "connect";
    pub const PRODUCE: &str = "produce";
    pub const CONSUME: &str = "consume";
    pub const RESUME_CONSUMER: &str = "resumeConsumer";
    pub const PAUSE_PRODUCER: &str = "pauseProducer";
    pub const RESUME_PRODUCER: &str = "resumeProducer";
    pub const CREATE_PLAIN_SEND: &str = "createPlainSend";
    pub const PRODUCE_PLAIN: &str = "producePlain";
    pub const CREATE_PLAIN_RECV: &str = "createPlainRecv";
    pub const CONNECT_PLAIN: &str = "connectPlain";
    pub const CONSUME_PLAIN: &str = "consumePlain";
    pub const PRODUCER_STATS: &str = "producerStats";
    pub const LIST_PRODUCERS: &str = "listProducers";
}

/// `join` reply.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JoinResult {
    pub peer_id: String,
    pub rtp_capabilities: Value,
    #[serde(default)]
    pub producers: Vec<ProducerInfo>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProducerInfo {
    pub producer_id: String,
    pub kind: String,
    #[serde(default)]
    pub app_data: Value,
    #[serde(default)]
    pub peer_id: String,
}

/// `createPlainSend` reply.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlainSendResult {
    pub transport_id: String,
    pub ip: String,
    pub port: u16,
}

/// `createPlainRecv` reply.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlainRecvResult {
    pub transport_id: String,
}

/// `consumePlain` reply.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsumePlainResult {
    pub consumer_id: String,
    pub producer_id: String,
    pub kind: String,
    pub rtp_parameters: Value,
}

/// `produce`/`producePlain` reply.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProduceResult {
    pub producer_id: String,
}
