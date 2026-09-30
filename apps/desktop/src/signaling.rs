//! Minimal WS signaling client matching services/sfu/server.mjs.

use anyhow::{bail, Context, Result};
use futures_util::{SinkExt, StreamExt};
use laira_protocol::{Request, ServerMessage};
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio_tungstenite::tungstenite::Message;

#[derive(Clone)]
pub struct Signaling {
    write: Arc<Mutex<futures_util::stream::SplitSink<
        tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
        Message,
    >>>,
    pending: Arc<Mutex<HashMap<u64, oneshot::Sender<Result<Value, String>>>>>,
    next_id: Arc<AtomicU64>,
}

impl Signaling {
    /// Returns the client plus the receiver for server-pushed events.
    pub async fn connect(url: &str) -> Result<(Self, mpsc::Receiver<(String, Value)>)> {
        let (ws, _) = tokio_tungstenite::connect_async(url)
            .await
            .with_context(|| format!("ws connect {url}"))?;
        let (write, mut read) = ws.split();
        let pending: Arc<Mutex<HashMap<u64, oneshot::Sender<Result<Value, String>>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let (event_tx, events) = mpsc::channel(64);
        let pending_task = pending.clone();
        tokio::spawn(async move {
            while let Some(Ok(Message::Text(text))) = read.next().await {
                let Ok(msg) = serde_json::from_str::<ServerMessage>(&text) else { continue };
                match msg {
                    ServerMessage::Reply { id, ok, data, error } => {
                        let tx = pending_task.lock().await.remove(&id);
                        if let Some(tx) = tx {
                            let _ = tx.send(if ok {
                                Ok(data.unwrap_or(Value::Null))
                            } else {
                                Err(error.unwrap_or_else(|| "unknown error".into()))
                            });
                        }
                    }
                    ServerMessage::Event { event, data } => {
                        let _ = event_tx.send((event, data)).await;
                    }
                }
            }
        });
        Ok((
            Self {
                write: Arc::new(Mutex::new(write)),
                pending,
                next_id: Arc::new(AtomicU64::new(1)),
            },
            events,
        ))
    }

    pub async fn call<T: DeserializeOwned>(&self, method: &str, params: Value) -> Result<T> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.pending.lock().await.insert(id, tx);
        let msg = serde_json::to_string(&Request {
            id,
            method: method.into(),
            params,
        })?;
        self.write.lock().await.send(Message::Text(msg.into())).await?;
        match rx.await.context("signaling reply dropped")? {
            Ok(data) => Ok(serde_json::from_value(data).with_context(|| {
                format!("decoding {method} reply")
            })?),
            Err(e) => bail!("{method}: {e}"),
        }
    }

    pub async fn call_unit(&self, method: &str, params: Value) -> Result<()> {
        self.call::<Value>(method, params).await.map(|_| ())
    }

}
