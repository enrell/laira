//! XDG ScreenCast portal session: user picks a monitor or window and we get
//! back a PipeWire fd + stream node id for pipewiresrc.
//!
//! The returned `PortalSession` owns the ashpd session + proxy; dropping it
//! ends the capture permission, so keep it alive for the stream's lifetime.

use anyhow::{Context, Result};
use ashpd::desktop::screencast::{CursorMode, Screencast, SourceType};
use ashpd::desktop::{PersistMode, Session};
use std::os::fd::IntoRawFd;

pub struct PortalSession {
    // Kept alive for Drop semantics; underscore silences dead_code on purpose.
    _proxy: Screencast<'static>,
    _session: Session<'static, Screencast<'static>>,
    /// Portal PipeWire fd. Unused on the OBS stack — we connect to the user's
    /// session daemon directly (the fd is only mandatory for sandboxed apps),
    /// but keeping it open is what the permission is anchored to.
    #[allow(dead_code)]
    pub fd: i32,
    pub node_id: u32,
}

pub async fn pick_screen() -> Result<PortalSession> {
    let proxy = Screencast::new().await.context("screencast proxy")?;
    let session = proxy.create_session().await.context("portal session")?;
    proxy
        .select_sources(
            &session,
            CursorMode::Embedded,
            SourceType::Monitor | SourceType::Window,
            false,
            None,
            PersistMode::DoNot,
        )
        .await
        .context("select_sources")?;
    let response = proxy
        .start(&session, None)
        .await
        .context("start request")?
        .response()
        .context("start response (user cancelled?)")?;
    let stream = response
        .streams()
        .first()
        .context("portal returned no streams")?;
    let node_id = stream.pipe_wire_node_id();
    let fd = proxy
        .open_pipe_wire_remote(&session)
        .await
        .context("open_pipe_wire_remote")?;
    tracing::info!(node_id, "portal granted stream");
    Ok(PortalSession {
        _proxy: proxy,
        _session: session,
        fd: fd.into_raw_fd(),
        node_id,
    })
}
