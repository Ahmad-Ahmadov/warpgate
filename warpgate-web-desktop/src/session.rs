use std::sync::{Arc, OnceLock};

use bytes::Bytes;
use tokio::sync::Mutex;
use tokio::sync::mpsc::{Receiver, Sender, channel};
use tokio_util::sync::CancellationToken;
use tracing::warn;
use uuid::Uuid;
use warpgate_common::UserSessionId;
use warpgate_core::recordings::DesktopRecorder;
use warpgate_core::{DesktopEvent, DesktopInput, DesktopRect, Framebuffer, Rect};
use warpgate_web_clients_common::{ManagedSession, Sheddable, WebSession};

use crate::protocol::{ServerMessage, SignInPassword, SignInRequest, WsRect};

/// Initial output-buffer allocation. Not a hard cap: incremental frames are bounded by
/// [`MAX_BUFFERED_INCREMENTAL`] and structural messages are rare, so the buffer stays small.
const OUTPUT_BUFFER_CAPACITY: usize = 128;

/// How many incremental (droppable) framebuffer frames to keep buffered for a slow or
/// briefly-disconnected client. Small on purpose: a client that falls behind should get
/// the recent live edge, not a huge stale backlog to grind through (which is what froze
/// the browser on high-frequency updates). Structural messages are never counted or dropped.
const MAX_BUFFERED_INCREMENTAL: usize = 64;

impl Sheddable for ServerMessage {
    fn is_droppable(&self) -> bool {
        self.is_incremental()
    }
}

pub struct DesktopBackend {
    pub input_tx: Sender<DesktopInput>,
    pub recorder: Option<Arc<DesktopRecorder>>,
}

/// The browser's answer to a [`SignInRequest`]: the account it chose (only ever looked up
/// among the ones the request offered) and the password typed for it.
pub struct SignInSubmission {
    pub account: Option<String>,
    pub password: SignInPassword,
}

/// The sign-in a session may be waiting for, between its approval and dialing the target.
struct SignIn {
    tx: Sender<SignInSubmission>,
    rx: std::sync::Mutex<Option<Receiver<SignInSubmission>>>,
    /// The request the browser has to answer, asked again of a browser that attaches (a
    /// reload, say) while it is open. `None` when no answer is wanted, so one sent then is
    /// dropped.
    open: std::sync::Mutex<Option<SignInRequest>>,
}

pub struct WebDesktopSession {
    core: WebSession<ServerMessage>,
    backend: OnceLock<DesktopBackend>,
    /// Composited surface, kept so a viewer attaching mid-session gets a base image.
    /// Separate from the recorder's: that one must only see events it actually wrote.
    /// Holds the refinement scratch too, so encoding one region needs a single lock.
    framebuffer: Mutex<(Framebuffer, RefineScratch)>,
    sign_in: SignIn,
}

/// Buffers reused across refinement encodes. A settling screen refines many regions back to
/// back, and `rgba` is a full copy of each region's pixels — a fresh allocation per region
/// would churn megabytes for a once-per-settle job.
#[derive(Default)]
struct RefineScratch {
    rgba: Vec<u8>,
    png: Vec<u8>,
}

impl WebDesktopSession {
    pub fn new(
        id: UserSessionId,
        user_id: Uuid,
        target_name: String,
        target_kind: warpgate_db_entities::Target::TargetKind,
        server_handle: Arc<tokio::sync::Mutex<warpgate_core::WarpgateServerHandle>>,
        cancel: CancellationToken,
    ) -> Self {
        Self {
            core: WebSession::new(
                id,
                user_id,
                target_name,
                target_kind,
                server_handle,
                cancel,
                OUTPUT_BUFFER_CAPACITY,
                MAX_BUFFERED_INCREMENTAL,
            ),
            backend: OnceLock::new(),
            framebuffer: Mutex::new((Framebuffer::default(), RefineScratch::default())),
            sign_in: {
                // One answer at a time: the request is answered, checked, then asked again.
                let (tx, rx) = channel(1);
                SignIn {
                    tx,
                    rx: std::sync::Mutex::new(Some(rx)),
                    open: std::sync::Mutex::new(None),
                }
            },
        }
    }

    /// Where the browser's answers to sign-in requests arrive. Taken once, by the task that
    /// connects the session.
    pub fn take_sign_in_answers(&self) -> Option<Receiver<SignInSubmission>> {
        self.sign_in
            .rx
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
    }

    /// Ask the browser for the password of the account to sign in to the target as.
    pub async fn ask_sign_in(&self, request: SignInRequest) {
        *self
            .sign_in
            .open
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(request.clone());
        self.push(ServerMessage::SignIn(request)).await;
    }

    /// Stop taking answers: one came, or none is wanted any more.
    pub fn close_sign_in(&self) {
        *self
            .sign_in
            .open
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    }

    /// Ask a browser that just attached the request still open, if one is.
    pub async fn replay_sign_in(&self) {
        let open = self
            .sign_in
            .open
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        if let Some(request) = open {
            self.push(ServerMessage::SignIn(request)).await;
        }
    }

    /// The browser's answer to the open sign-in request. Dropped when none is open, or one
    /// answer is already waiting to be checked.
    pub fn answer_sign_in(&self, submission: SignInSubmission) {
        let open = self
            .sign_in
            .open
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
            .is_some();
        if open {
            let _ = self.sign_in.tx.try_send(submission);
        }
    }

    pub fn bind_backend(&self, backend: DesktopBackend) {
        let _ = self.backend.set(backend);
    }

    /// Composite an event into the session's surface. Driven from the manager's event loop
    /// on the *pre-JPEG* stream, so this stays a plain blit with no decode round-trip.
    pub async fn composite(&self, event: &DesktopEvent) {
        self.framebuffer.lock().await.0.apply(event);
    }

    /// A full-canvas snapshot for a viewer that just attached. `None` until the backend has
    /// painted something, so a viewer is never handed a black surface to reveal.
    ///
    /// Encodes under the lock: it runs once per attach, and copying the surface out to
    /// offload it would cost more than the encode saves.
    pub async fn keyframe(&self) -> Option<ServerMessage> {
        let (width, height, data) = self.framebuffer.lock().await.0.snapshot_png()?;
        Some(ServerMessage::Keyframe {
            rect: WsRect {
                x: 0,
                y: 0,
                width,
                height,
            },
            data: data.into(),
        })
    }

    /// The current pixels of a region, as a lossless PNG event. Used to refine a region
    /// that was sent lossily and has since gone quiet; `None` once it falls outside the
    /// surface (a resize since it was marked dirty).
    pub async fn refinement(&self, rect: DesktopRect) -> Option<DesktopEvent> {
        let mut guard = self.framebuffer.lock().await;
        let (framebuffer, scratch) = &mut *guard;
        let clipped = framebuffer.region_png(
            Rect {
                x: u32::from(rect.x),
                y: u32::from(rect.y),
                width: u32::from(rect.width),
                height: u32::from(rect.height),
            },
            &mut scratch.rgba,
            &mut scratch.png,
        )?;
        Some(DesktopEvent::PngImage {
            rect: DesktopRect {
                x: u16::try_from(clipped.x).ok()?,
                y: u16::try_from(clipped.y).ok()?,
                width: u16::try_from(clipped.width).ok()?,
                height: u16::try_from(clipped.height).ok()?,
            },
            // Copied out so the scratch keeps its capacity for the next region.
            data: Bytes::copy_from_slice(&scratch.png),
        })
    }

    pub async fn send_input(&self, input: DesktopInput) {
        let Some(backend) = self.backend.get() else {
            return;
        };
        // Record the viewer's input for audit before forwarding (like native RDP/VNC).
        if let Some(recorder) = &backend.recorder
            && let Err(error) = recorder.write_input(&input).await
        {
            warn!(%error, "Failed to record web-desktop viewer input");
        }
        // let inputs drop under backpressure
        let _ = backend.input_tx.try_send(input);
    }
}

impl std::ops::Deref for WebDesktopSession {
    type Target = WebSession<ServerMessage>;
    fn deref(&self) -> &Self::Target {
        &self.core
    }
}

impl ManagedSession for WebDesktopSession {
    fn id(&self) -> UserSessionId {
        self.core.id()
    }

    fn user_id(&self) -> Uuid {
        self.core.user_id()
    }

    fn on_removed(&self) {
        self.core.abort();
    }
}
