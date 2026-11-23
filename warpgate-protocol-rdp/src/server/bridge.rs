//! Target-side bridging: once auth succeeds, dial the target, pump its framebuffer to the
//! viewer-facing RDP server, and record the session.

use std::sync::Arc;

use anyhow::Result;
use tokio::sync::mpsc::Sender;
use tracing::{Instrument as _, info, warn};
use warpgate_common::TargetRdpOptions;
use warpgate_core::rdp_account::TargetCredentials;
use warpgate_core::recordings::DesktopRecorder;
use warpgate_core::{
    AdmittedTarget, DesktopClientHandles, DesktopConnectionError, DesktopEvent, DesktopState,
    Services,
};

use super::BackendBridge;
use super::protocol::{Input as ServerInput, Refusal};

/// Bridge target-side desktop events to the viewer-facing RDP server. Every framebuffer
/// update is a delta rectangle, so none may be dropped — a lost tile leaves that region
/// stale until it next changes. `server_in` is bounded, so a slow viewer applies
/// backpressure here, which reaches the target client: it keeps reading the target and
/// sends the viewer the desktop as it is once there is room, rather than every state the
/// target went through.
///
/// Recording runs on its own task so its (serialising) `write_event` never gates live frame
/// delivery — `DesktopEvent` clones are cheap (`RawImage` holds ref-counted `Bytes`). The
/// recorder is also shared with `control_loop` (viewer input); the recording finalises once
/// every handle drops.
async fn frame_bridge(
    mut event_rx: tokio::sync::mpsc::Receiver<DesktopEvent>,
    server_in: Sender<ServerInput>,
    recorder: Option<Arc<DesktopRecorder>>,
) {
    let record_tx = recorder.map(|recorder| {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<DesktopEvent>(256);
        tokio::spawn(
            async move {
                while let Some(event) = rx.recv().await {
                    if let Err(error) = recorder.write_event(&event).await {
                        warn!(%error, "Failed to record RDP desktop event");
                    }
                }
            }
            .in_current_span(),
        );
        tx
    });

    if server_in.send(ServerInput::TargetConnected).await.is_err() {
        return;
    }
    while let Some(event) = event_rx.recv().await {
        if let Some(record_tx) = &record_tx {
            // Best-effort: recording must never stall the live path, so drop under overload.
            let _ = record_tx.try_send(event.clone());
        }

        let message = match event {
            DesktopEvent::Resize { width, height } => ServerInput::Resize { width, height },
            DesktopEvent::RawImage { rect, data } => ServerInput::Frame {
                x: rect.x,
                y: rect.y,
                width: rect.width,
                height: rect.height,
                // `data` is ref-counted `Bytes` — moved into the frame, no framebuffer copy.
                data,
            },
            DesktopEvent::Cursor { rect, data } => ServerInput::Cursor {
                // As in RFB, the rect's origin is the hotspot.
                hotspot_x: rect.x,
                hotspot_y: rect.y,
                width: rect.width,
                height: rect.height,
                data,
            },
            DesktopEvent::CursorDefault => ServerInput::CursorDefault,
            DesktopEvent::CursorHidden => ServerInput::CursorHidden,
            DesktopEvent::Clipboard(text) => ServerInput::Clipboard(text),
            DesktopEvent::State(DesktopState::Disconnected) => {
                let _ = server_in.send(ServerInput::Shutdown).await;
                return;
            }
            DesktopEvent::Error(error) => {
                warn!(%error, "RDP target reported an error");
                // A logon as an account the viewer may not use: the viewer is told it was
                // refused, not left to take it for a dropped connection.
                if matches!(*error, DesktopConnectionError::LogonAccountRefused { .. }) {
                    let _ = server_in
                        .send(ServerInput::Disconnect(Refusal::Denied))
                        .await;
                    return;
                }
                continue;
            }
            DesktopEvent::State(state @ (DesktopState::Connecting | DesktopState::Connected)) => {
                info!(?state, "RDP target");
                continue;
            }
            // The client never emits the remaining framebuffer variants
            _ => continue,
        };

        if server_in.send(message).await.is_err() {
            return;
        }
    }
}

/// Connect to the target and start bridging its framebuffer, once auth is complete.
/// `keyboard_layout` is the viewer's (a Windows KLID), or `0` for the target's default.
/// `credentials` signs in to a target that uses an account the viewer typed the password of
/// (their own domain account, or one assigned to them), and is consumed (and wiped) once the
/// connection is configured.
pub(super) async fn connect_backend(
    services: &Services,
    server_in_tx: &Sender<ServerInput>,
    admitted: AdmittedTarget<TargetRdpOptions>,
    screen: warpgate_desktop_ui::Screen,
    keyboard_layout: u32,
    credentials: Option<TargetCredentials>,
) -> Result<BackendBridge> {
    info!(
        target = %admitted.target().name,
        keyboard_layout = %format!("{keyboard_layout:#010x}"),
        "Authorized"
    );

    let recorder = warpgate_desktop_auth::start_recording(services, &admitted.id(), "rdp")
        .await
        .map(Arc::new);

    let DesktopClientHandles {
        event_rx,
        input_tx,
        abort_tx,
        logon_state,
    } = crate::connect_with_keyboard_layout(
        admitted,
        (screen.width, screen.height),
        services.secret_backends.clone(),
        keyboard_layout,
        credentials,
    )?;
    if let Some(recorder) = &recorder {
        recorder.track_logon_state(logon_state);
    }
    let frame_bridge = tokio::spawn(
        frame_bridge(event_rx, server_in_tx.clone(), recorder.clone()).in_current_span(),
    );
    Ok(BackendBridge {
        input_tx,
        abort_tx,
        frame_bridge,
        recorder,
        dialed_at: Some(screen),
    })
}
