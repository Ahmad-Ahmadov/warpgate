//! Viewer-facing RDP server: runs IronRDP's server state machine (including TLS) over
//! the accepted viewer socket, and bridges everything else to the owning Warpgate session
//! over [`Input`]/[`Event`] channels.
//!
//! Warpgate owns the listening socket, the session, authentication and recording; this
//! module owns only the RDP server protocol and its TLS.

use std::io;
use std::net::SocketAddr;
use std::num::{NonZeroU16, NonZeroUsize};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::Duration;

use anyhow::{Context, Result};
use bytes::Bytes;
use ironrdp_displaycontrol::pdu::{DisplayControlMonitorLayout, MonitorLayoutEntry};
use ironrdp_pdu::gcc::KeyboardType;
use ironrdp_pdu::input::fast_path::SynchronizeFlags;
use ironrdp_pdu::rdp::server_error_info::{ErrorInfo, ProtocolIndependentCode};
use ironrdp_server::{
    BitmapUpdate, ConnectionHandler, ConnectionInfo, CredentialDecision, CredentialValidationError,
    CredentialValidator, Credentials, DesktopSize, DisplayContext, DisplayUpdate,
    ErrorInfoDisconnectHandle, KeyboardEvent, LargePointer, MouseButton, MouseEvent, PixelFormat,
    RGBAPointer, RdpServer, RdpServerDisplay, RdpServerDisplayUpdates, RdpServerInputHandler,
    ServerResult,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig as TlsServerConfig;
use tracing::{Instrument as _, Span, debug, info, warn};
use warpgate_core::{DesktopInput, Scancode};
#[cfg(test)]
use warpgate_desktop_ui::DEFAULT_SIZE;

use super::clipboard::ViewerClipboard;
use super::protocol::{AuthVerdict, Event, Input, Refusal};
use crate::desktop_size::{MAX_DESKTOP_DIM, bound_desktop_size};
#[cfg(test)]
use crate::desktop_size::{MAX_FRAME_BYTES, MIN_DESKTOP_DIM};

/// Depth of the queue between Warpgate's frames and IronRDP's encoder. One update waiting
/// while another is encoded keeps the encoder busy; anything deeper only makes the viewer
/// see the desktop later, since the target client merges what does not fit (see
/// `client::damage`).
const DISPLAY_QUEUE_CAPACITY: usize = 2;

/// How long the viewer must have asked for no output (mstsc does when minimised) before
/// updates are held back. IronRDP's `DisplayContext::display_suppressed` documents why:
/// mstsc also sends that request while its connection is still being set up, and some
/// clients flap it under load.
const SUPPRESS_SETTLE: Duration = Duration::from_secs(1);

/// How often held-back updates check whether the viewer wants output again.
const SUPPRESS_POLL: Duration = Duration::from_millis(100);

/// Run the RDP server on a dedicated thread, resolving to its result.
///
/// `RdpServer::run_connection` holds `Rc`s across await points, so its future is not
/// `Send` and cannot join the multi-threaded runtime. It gets a current-thread runtime of
/// its own instead; everything it exchanges with the session (the duplex transport and the
/// two channels) is `Send`, so only the state machine itself stays pinned here.
///
/// `keyboard_layout` receives the keyboard layout the viewer announces, once its session is
/// activated, for the target connection.
pub fn run_on_thread<S>(
    stream: S,
    cert_pem: String,
    key_pem: String,
    size: (u16, u16),
    out_tx: mpsc::UnboundedSender<Event>,
    in_rx: mpsc::Receiver<Input>,
    keyboard_layout: Arc<AtomicU32>,
) -> oneshot::Receiver<Result<()>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
{
    let (done_tx, done_rx) = oneshot::channel();
    // The session span is thread-local, so it has to be carried over by hand: without it
    // nothing this server logs is attributed to the session.
    let span = Span::current();
    std::thread::spawn(move || {
        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(error) => {
                let _ = done_tx.send(Err(anyhow::Error::new(error).context("RDP server runtime")));
                return;
            }
        };
        let result = runtime.block_on(
            run(
                stream,
                cert_pem,
                key_pem,
                size,
                out_tx,
                in_rx,
                keyboard_layout,
            )
            .instrument(span),
        );
        let _ = done_tx.send(result);
    });
    done_rx
}

/// Run the RDP server state machine against an accepted viewer connection.
async fn run<S>(
    stream: S,
    cert_pem: String,
    key_pem: String,
    size: (u16, u16),
    out_tx: mpsc::UnboundedSender<Event>,
    in_rx: mpsc::Receiver<Input>,
    keyboard_layout: Arc<AtomicU32>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
{
    // `ironrdp-server` pulls in tokio-rustls with the aws-lc-rs provider (its default);
    // install it as the process default so `ServerConfig::builder()` works.
    let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();

    let tls = build_tls_acceptor(&cert_pem, &key_pem)?;

    let (frame_tx, frame_rx) = mpsc::channel::<DisplayUpdate>(DISPLAY_QUEUE_CAPACITY);
    let size = Arc::new(Mutex::new(DesktopSize {
        width: size.0,
        height: size.1,
    }));

    let clipboard = ViewerClipboard::new(out_tx.clone());
    let progress = Arc::new(Progress::default());
    let target_connected = Arc::new(AtomicBool::new(false));

    let display = DisplayHandler {
        size: Arc::clone(&size),
        initial_size_negotiated: false,
        updates: Arc::new(Mutex::new(frame_rx)),
        target_connected: Arc::clone(&target_connected),
        out: out_tx.clone(),
    };
    let input = InputHandler {
        out: out_tx.clone(),
        x: 0,
        y: 0,
        buttons: 0,
    };
    let validator: Arc<dyn CredentialValidator> = Arc::new(Validator {
        out: out_tx.clone(),
        progress: Arc::clone(&progress),
    });

    let mut server = RdpServer::builder()
        // `addr` is only used by `RdpServer::run()` (which binds a listener); we drive
        // `run_connection()` directly with the accepted stream, so it's a harmless
        // placeholder here.
        .with_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
        .with_tls(tls)
        .with_input_handler(input)
        .with_display_handler(display)
        // Opt in to calling `request_initial_size`; without it the acceptor ignores the
        // viewer's requested resolution and pins the session to `size()`'s seed.
        .with_honor_client_desktop_size(Some(DesktopSize {
            width: MAX_DESKTOP_DIM,
            height: MAX_DESKTOP_DIM,
        }))
        .with_credential_validator(Some(validator))
        .with_cliprdr_factory(Some(Box::new(clipboard.clone())))
        .with_connection_handler(Some(Box::new(ViewerConnection { keyboard_layout })))
        .build();

    let router = tokio::spawn(
        route_input(
            in_rx,
            frame_tx,
            DisplayRouteState {
                size,
                target_connected,
                out: out_tx.clone(),
            },
            clipboard,
            server.error_info_disconnect_handle(),
        )
        .in_current_span(),
    );

    let result = server.run_connection(stream).await;
    router.abort();

    // However the session ends, it is not a failure of the gateway: report it and shut
    // down cleanly. What is worth a warning is a session that failed, rather than one the
    // viewer closed or Warpgate refused.
    match result {
        Ok(()) => debug!("Viewer connection closed"),
        // The control loop has logged why it refused the credentials.
        Err(error) if progress.refused.load(Ordering::Relaxed) => debug!(
            error = %format!("{error:#}"),
            "Viewer connection closed after its credentials were refused"
        ),
        // Before its logon info, as when mstsc's user declines its certificate warning
        // or the client gives up on the negotiation.
        Err(error) if is_hang_up(&error) && !progress.logon_info.load(Ordering::Relaxed) => {
            info!(
                error = %format!("{error:#}"),
                "Viewer disconnected during the connection handshake, before sending its logon info"
            );
        }
        // How every session ends that the viewer closes: mstsc, for one, closes the
        // connection without a TLS close_notify.
        Err(error) if is_hang_up(&error) => {
            info!(error = %format!("{error:#}"), "Viewer disconnected");
        }
        Err(error) => warn!(error = %format!("{error:#}"), "RDP session ended with error"),
    }
    Ok(())
}

/// How far the viewer's connection got, for telling why it ended.
#[derive(Default)]
struct Progress {
    /// The viewer completed the handshake and sent its Client Info PDU.
    logon_info: AtomicBool,
    /// Warpgate refused its credentials.
    refused: AtomicBool,
}

/// Whether `error` is the viewer's connection going away, rather than anything failing.
fn is_hang_up(error: &(dyn std::error::Error + 'static)) -> bool {
    std::iter::successors(Some(error), |error| error.source()).any(|error| {
        error.downcast_ref::<io::Error>().is_some_and(|error| {
            matches!(
                error.kind(),
                io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::BrokenPipe
            )
        })
    })
}

/// The Set Error Info code (MS-RDPBCGR 2.2.5.1.1) a refusal reaches the viewer as.
const fn refusal_error_info(refusal: Refusal) -> ErrorInfo {
    ErrorInfo::ProtocolIndependentCode(match refusal {
        // As the RDP server refuses credentials from the Client Info PDU.
        Refusal::Denied => ProtocolIndependentCode::ServerInsufficientPrivileges,
        Refusal::NotApproved => ProtocolIndependentCode::ServerDeniedConnection,
        Refusal::TimedOut => ProtocolIndependentCode::LogonTimeout,
    })
}

/// Logs what the viewer announced once its session is activated, and keeps its keyboard
/// layout for the target connection.
struct ViewerConnection {
    keyboard_layout: Arc<AtomicU32>,
}

impl ConnectionHandler for ViewerConnection {
    fn on_connection_info(&mut self, info: &ConnectionInfo) {
        info!(
            keyboard_layout = %format!("{:#010x}", info.keyboard_layout),
            keyboard_type = info.keyboard_type.0,
            monitors = info.client_monitors.len(),
            "Viewer session activated"
        );
        // The target is told the viewer's layout, as a direct connection would tell it, so
        // that keystrokes, which reach it as scancodes, type what the viewer's keycaps say.
        // Only for the standard keyboard type the target connection declares: a Japanese or
        // Korean layout needs its own keyboard type and subtype to go with it.
        if info.keyboard_type == KeyboardType::IBM_ENHANCED {
            self.keyboard_layout
                .store(info.keyboard_layout, Ordering::Relaxed);
        }
    }
}

/// Build a rustls `TlsAcceptor` from PEM cert + key.
fn build_tls_acceptor(cert_pem: &str, key_pem: &str) -> Result<TlsAcceptor> {
    let mut cert_reader = cert_pem.as_bytes();
    let certs = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .context("parsing TLS certificate PEM")?;
    if certs.is_empty() {
        anyhow::bail!("no certificate found in TLS certificate PEM");
    }

    let mut key_reader = key_pem.as_bytes();
    let key = rustls_pemfile::private_key(&mut key_reader)
        .context("parsing TLS private key PEM")?
        .context("no private key found in TLS private key PEM")?;

    let config = TlsServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("building rustls server config")?;

    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// Shared display state used while routing Warpgate framebuffer messages.
struct DisplayRouteState {
    size: Arc<Mutex<DesktopSize>>,
    /// Set on [`Input::TargetConnected`]; see [`DisplayHandler::target_connected`].
    target_connected: Arc<AtomicBool>,
    out: mpsc::UnboundedSender<Event>,
}

/// Route Warpgate's messages to the display backend (framebuffer updates), the viewer's
/// clipboard, and the server itself (ending the session).
async fn route_input(
    mut rx: mpsc::Receiver<Input>,
    frame_tx: mpsc::Sender<DisplayUpdate>,
    display: DisplayRouteState,
    clipboard: ViewerClipboard,
    disconnect: ErrorInfoDisconnectHandle,
) {
    while let Some(msg) = rx.recv().await {
        match msg {
            Input::Frame {
                x,
                y,
                width,
                height,
                data,
            } => {
                if let Some(update) = frame_to_update(x, y, width, height, data)
                    && frame_tx.send(update).await.is_err()
                {
                    break;
                }
            }
            Input::Resize { width, height } => {
                let new = DesktopSize { width, height };
                // A resize costs a deactivation-reactivation: the server tears the session
                // down to the acceptor and renegotiates capabilities with the viewer. Skip
                // it when the size is unchanged so an already-correct session is never
                // disturbed.
                let previous = core::mem::replace(&mut *display.size.lock().await, new);
                if previous == new {
                    continue;
                }
                debug!(?previous, ?new, "viewer surface resized");
                if frame_tx.send(DisplayUpdate::Resize(new)).await.is_err() {
                    break;
                }
                let _ = display.out.send(Event::Size {
                    width: new.width,
                    height: new.height,
                });
            }
            Input::Cursor {
                hotspot_x,
                hotspot_y,
                width,
                height,
                data,
            } => {
                let update = cursor_to_update(hotspot_x, hotspot_y, width, height, &data);
                if frame_tx.send(update).await.is_err() {
                    break;
                }
            }
            Input::CursorDefault => {
                if frame_tx.send(DisplayUpdate::DefaultPointer).await.is_err() {
                    break;
                }
            }
            Input::CursorHidden => {
                if frame_tx.send(DisplayUpdate::HidePointer).await.is_err() {
                    break;
                }
            }
            Input::Clipboard(text) => clipboard.offer(text),
            Input::TargetConnected => display.target_connected.store(true, Ordering::Relaxed),
            Input::Shutdown => break,
            Input::Disconnect(refusal) => {
                debug!(?refusal, "Ending the viewer's session");
                if disconnect.disconnect(refusal_error_info(refusal)).is_ok() {
                    // Closing the display feed, as returning would, ends the session too,
                    // and that would race the event carrying the reason: half the time the
                    // viewer would not hear it. So the feed stays open, and whatever still
                    // arrives is dropped, until the server has sent the reason and ended
                    // the session, which aborts this task.
                    while rx.recv().await.is_some() {}
                    std::future::pending::<()>().await;
                }
                break;
            }
        }
    }
}

/// Convert a BGRA framebuffer rectangle into an IronRDP bitmap update. Returns `None` for
/// degenerate or short buffers rather than panicking downstream.
fn frame_to_update(x: u16, y: u16, width: u16, height: u16, data: Bytes) -> Option<DisplayUpdate> {
    let nz_width = NonZeroU16::new(width)?;
    let nz_height = NonZeroU16::new(height)?;
    let stride = NonZeroUsize::new(usize::from(width) * 4)?;
    if data.len() < usize::from(width) * usize::from(height) * 4 {
        warn!(width, height, len = data.len(), "ignoring undersized frame");
        return None;
    }
    Some(DisplayUpdate::Bitmap(BitmapUpdate {
        x,
        y,
        width: nz_width,
        height: nz_height,
        // The client emits bytes in B,G,R,A memory order (see its raw-image encoder),
        // which is exactly `PixelFormat::BgrA32`.
        format: PixelFormat::BgrA32,
        data,
        stride,
    }))
}

/// Largest cursor, in pixels per side, that RDP carries at all: the Large Pointer Update's
/// limit (MS-RDPBCGR 2.2.9.1.2.1.11). How large a cursor a viewer takes depends on the
/// large-pointer sizes it negotiated with the server; the server's encoder sends each cursor
/// in an update the viewer takes at that size, or as the viewer's default pointer.
const MAX_CURSOR_DIM: u16 = 384;

/// Largest cursor, per side, sent as an [`RGBAPointer`] (a New Pointer Update, at most 96x96);
/// a larger one goes as a [`LargePointer`].
const MAX_NEW_POINTER_DIM: u16 = 96;

/// Convert a BGRA cursor image (top row first) into an IronRDP pointer update. A cursor that
/// is malformed, or larger than RDP carries, becomes the viewer's default pointer, so the
/// viewer never keeps showing a shape the target has already left.
fn cursor_to_update(
    hotspot_x: u16,
    hotspot_y: u16,
    width: u16,
    height: u16,
    data: &[u8],
) -> DisplayUpdate {
    let row_len = usize::from(width) * 4;
    if width == 0
        || height == 0
        || width > MAX_CURSOR_DIM
        || height > MAX_CURSOR_DIM
        || data.len() != row_len * usize::from(height)
    {
        warn!(
            width,
            height,
            len = data.len(),
            "unusable cursor, using the default"
        );
        return DisplayUpdate::DefaultPointer;
    }
    // The pointer PDU's 32bpp XOR mask is a bottom-up DIB, hence the reversed rows.
    // `RGBAPointer` is named for its channels, but the mask goes on the wire as given, and
    // the wire order is BGRA.
    let data = data
        .chunks_exact(row_len)
        .rev()
        .flatten()
        .copied()
        .collect();
    // Every update replaces the one slot; the target's own cache isn't mirrored.
    let cache_index = 0;
    if width <= MAX_NEW_POINTER_DIM && height <= MAX_NEW_POINTER_DIM {
        DisplayUpdate::RGBAPointer(RGBAPointer {
            cache_index,
            width,
            height,
            hot_x: hotspot_x,
            hot_y: hotspot_y,
            data,
        })
    } else {
        DisplayUpdate::LargePointer(LargePointer {
            cache_index,
            width,
            height,
            hot_x: hotspot_x,
            hot_y: hotspot_y,
            data,
        })
    }
}

/// Bound a viewer-supplied desktop size with [`bound_desktop_size`]. On this path it arrives
/// during the capability exchange, before the credential validator has run.
fn clamp_desktop_size(requested: DesktopSize) -> DesktopSize {
    let (width, height) = bound_desktop_size(requested.width, requested.height);
    DesktopSize { width, height }
}

fn primary_monitor_size(layout: &DisplayControlMonitorLayout) -> Option<DesktopSize> {
    let monitor = layout
        .monitors()
        .iter()
        .find(|monitor| monitor.is_primary())?;
    let (width, height) = monitor.dimensions();
    let (width, height) = MonitorLayoutEntry::adjust_display_size(width, height);
    Some(clamp_desktop_size(DesktopSize {
        width: u16::try_from(width).ok()?,
        height: u16::try_from(height).ok()?,
    }))
}

/// Display backend: hands the IronRDP server a receiver of framebuffer updates fed by
/// Warpgate.
struct DisplayHandler {
    /// `size()` is re-queried on every deactivation-reactivation to build the new
    /// `UpdateEncoder`, so this has to track the size last renegotiated with the client,
    /// not the one the session started at.
    size: Arc<Mutex<DesktopSize>>,
    /// Whether the initial viewer-driven size has been adopted. Gates
    /// [`Self::request_initial_size`] so reactivations keep the committed size instead of
    /// re-adopting a stale one the viewer echoes.
    initial_size_negotiated: bool,
    // Shared, not `take()`n: ironrdp-server calls `updates()` again after every
    // deactivation-reactivation (e.g. an mstsc / MS Remote Desktop resize), so a
    // one-shot receiver would fail the second connection with "already taken".
    updates: Arc<Mutex<mpsc::Receiver<DisplayUpdate>>>,
    /// Whether the frames are the target's desktop yet, rather than Warpgate's sign-in,
    /// second-factor or approval screens. Only the target's are held back for a minimised
    /// viewer: those screens' painter waits on every frame it sends, and the sign-in they
    /// drive has to carry on while the viewer is minimised.
    target_connected: Arc<AtomicBool>,
    out: mpsc::UnboundedSender<Event>,
}

#[async_trait::async_trait]
impl RdpServerDisplay for DisplayHandler {
    async fn size(&mut self) -> DesktopSize {
        *self.size.lock().await
    }

    /// Whatever this returns is what the session runs at; RDP lets the server dictate, and
    /// the viewer resizes to match.
    ///
    /// ironrdp-server also calls this on every deactivation-reactivation, passing the size
    /// the viewer echoes in its Confirm Active. That echo can lag the resolution Warpgate
    /// just negotiated — mstsc, growing the window, still reports the smaller previous size —
    /// and adopting it would rebuild the encoder below the frames Warpgate is about to send,
    /// so every larger tile hits the "bitmap exceeds desktop size" drop (a grow paints black,
    /// while a shrink still fits and looks fine). So the viewer's size is honoured only for
    /// the initial negotiation; from then on the committed size — driven by the target after
    /// a Display Control resize — is authoritative and the viewer conforms to it.
    async fn request_initial_size(&mut self, client_size: DesktopSize) -> DesktopSize {
        if self.initial_size_negotiated {
            let committed = *self.size.lock().await;
            debug!(
                ?client_size,
                ?committed,
                "reactivation: keeping committed size, viewer echo ignored"
            );
            return committed;
        }
        self.initial_size_negotiated = true;
        let size = clamp_desktop_size(client_size);
        debug!(?client_size, adopted = ?size, "initial viewer size negotiated");
        *self.size.lock().await = size;
        let _ = self.out.send(Event::Size {
            width: size.width,
            height: size.height,
        });
        size
    }

    async fn updates(
        &mut self,
        ctx: DisplayContext,
    ) -> ServerResult<Box<dyn RdpServerDisplayUpdates>> {
        // Hand out a fresh view over the shared receiver. Only one is active at a time
        // (the previous is dropped when its client loop ends before reactivation).
        Ok(Box::new(DisplayUpdatesReceiver::new(
            self.updates.clone(),
            ctx.display_suppressed,
            self.target_connected.clone(),
        )))
    }

    fn request_layout(&mut self, layout: DisplayControlMonitorLayout) {
        let Some(size) = primary_monitor_size(&layout) else {
            return;
        };
        // ironrdp-server calls this from `spawn_blocking`, never on the runtime thread, which
        // is what makes blocking on the lock legal here.
        if *self.size.blocking_lock() == size {
            return;
        }
        debug!(requested = ?size, "viewer requested a dynamic resize");
        let _ = self.out.send(Event::ResizeRequest {
            width: size.width,
            height: size.height,
        });
    }
}

struct DisplayUpdatesReceiver {
    rx: Arc<Mutex<mpsc::Receiver<DisplayUpdate>>>,
    /// Set while the viewer has asked for no output, as mstsc does when minimised.
    suppressed: Arc<AtomicBool>,
    /// Since when `suppressed` has been set without a break.
    suppressed_since: Option<tokio::time::Instant>,
    /// Whether this activation has delivered a frame yet. Until it has, a request for no
    /// output is ignored: mstsc sends one before its surface is ready, and holding the first
    /// frame back would leave it frozen.
    delivered: bool,
    /// See [`DisplayHandler::target_connected`].
    target_connected: Arc<AtomicBool>,
}

impl DisplayUpdatesReceiver {
    const fn new(
        rx: Arc<Mutex<mpsc::Receiver<DisplayUpdate>>>,
        suppressed: Arc<AtomicBool>,
        target_connected: Arc<AtomicBool>,
    ) -> Self {
        Self {
            rx,
            suppressed,
            suppressed_since: None,
            delivered: false,
            target_connected,
        }
    }

    /// Wait while the viewer has steadily asked for no output. Nothing is encoded or sent
    /// meanwhile; the target client keeps the desktop current and sends what changed once
    /// the viewer is back.
    async fn hold_while_suppressed(&mut self) {
        loop {
            if !self.delivered
                || !self.target_connected.load(Ordering::Relaxed)
                || !self.suppressed.load(Ordering::Relaxed)
            {
                self.suppressed_since = None;
                return;
            }
            let since = *self
                .suppressed_since
                .get_or_insert_with(tokio::time::Instant::now);
            if since.elapsed() < SUPPRESS_SETTLE {
                return;
            }
            tokio::time::sleep(SUPPRESS_POLL).await;
        }
    }
}

#[async_trait::async_trait]
impl RdpServerDisplayUpdates for DisplayUpdatesReceiver {
    async fn next_update(&mut self) -> ServerResult<Option<DisplayUpdate>> {
        // Waiting out a suppression consumes nothing, and `mpsc::Receiver::recv` is
        // cancellation-safe, so this stays cancellation-safe as the trait requires; the
        // guard is released on cancel and no message is lost. `Resize` and the frames that
        // follow it share this one ordered channel, so the encoder is always resized before
        // it is handed a frame at the new size.
        self.hold_while_suppressed().await;
        let update = self.rx.lock().await.recv().await;
        if matches!(update, Some(DisplayUpdate::Bitmap(_))) {
            self.delivered = true;
        }
        Ok(update)
    }
}

/// Credential validator: forwards the viewer's credentials to Warpgate and awaits its
/// verdict on a per-request reply channel.
struct Validator {
    out: mpsc::UnboundedSender<Event>,
    progress: Arc<Progress>,
}

#[async_trait::async_trait]
impl CredentialValidator for Validator {
    async fn validate(
        &self,
        credentials: &Credentials,
    ) -> Result<CredentialDecision, CredentialValidationError> {
        self.progress.logon_info.store(true, Ordering::Relaxed);
        // The handshake is through: the X.224 negotiation (TLS, the only security this
        // listener offers), the TLS handshake, the MCS connection and the Client Info PDU.
        // Whether a password came with it decides between signing the viewer in with it and
        // asking for it on the sign-in screen. The credentials themselves are never logged.
        info!(
            password_supplied = !credentials.password.is_empty(),
            domain_supplied = credentials
                .domain
                .as_deref()
                .is_some_and(|domain| !domain.is_empty()),
            "Viewer completed the TLS handshake and sent its logon info"
        );

        let (reply, verdict) = oneshot::channel();
        if self
            .out
            .send(Event::AuthRequest {
                username: credentials.username.clone(),
                password: credentials.password.clone(),
                reply,
            })
            .is_err()
        {
            // Warpgate hung up before we could ask.
            self.progress.refused.store(true, Ordering::Relaxed);
            return Ok(CredentialDecision::Reject);
        }
        match verdict.await {
            Ok(AuthVerdict::StartSession) => Ok(CredentialDecision::Accept),
            // Explicit denial, or the control loop dropped the reply without answering.
            Ok(AuthVerdict::Deny) | Err(_) => {
                self.progress.refused.store(true, Ordering::Relaxed);
                Ok(CredentialDecision::Reject)
            }
        }
    }
}

/// Input handler: normalises IronRDP keyboard/mouse events onto the shared
/// `DesktopInput` stream.
struct InputHandler {
    out: mpsc::UnboundedSender<Event>,
    x: u16,
    y: u16,
    buttons: u8,
}

impl InputHandler {
    fn emit_pointer(&self) {
        let _ = self.out.send(Event::Input(DesktopInput::Pointer {
            x: self.x,
            y: self.y,
            buttons: self.buttons,
        }));
    }

    fn send_key(&self, keysym: Option<u32>, scancode: Option<Scancode>, down: bool) {
        let _ = self.out.send(Event::Input(DesktopInput::Key {
            keysym,
            scancode,
            down,
        }));
    }

    fn set_button(&mut self, bit: u8, down: bool) {
        if down {
            self.buttons |= 1 << bit;
        } else {
            self.buttons &= !(1 << bit);
        }
        self.emit_pointer();
    }
}

impl RdpServerInputHandler for InputHandler {
    fn keyboard(&mut self, event: KeyboardEvent) {
        match event {
            KeyboardEvent::Pressed { code, extended } => {
                self.send_key(None, Some(Scancode { code, extended }), true);
            }
            KeyboardEvent::Released { code, extended } => {
                self.send_key(None, Some(Scancode { code, extended }), false);
            }
            KeyboardEvent::UnicodePressed(unit) => {
                self.send_key(Some(u32::from(unit)), None, true);
            }
            KeyboardEvent::UnicodeReleased(unit) => {
                self.send_key(Some(u32::from(unit)), None, false);
            }
            // Lock-key state. Not propagated to the target, which keeps its own; the
            // sign-in screen reads it, to type what the keycaps say.
            KeyboardEvent::Synchronize(flags) => {
                let _ = self.out.send(Event::KeyboardSync {
                    caps_lock: flags.contains(SynchronizeFlags::CAPS_LOCK),
                    num_lock: flags.contains(SynchronizeFlags::NUM_LOCK),
                });
            }
        }
    }

    fn mouse(&mut self, event: MouseEvent) {
        match event {
            MouseEvent::Move { x, y } => {
                self.x = x;
                self.y = y;
                self.emit_pointer();
            }
            MouseEvent::Button {
                x,
                y,
                button,
                pressed,
            } => {
                self.x = x;
                self.y = y;
                self.set_button(button_bit(button), pressed);
            }
            MouseEvent::ButtonRel {
                x,
                y,
                button,
                pressed,
            } => {
                self.x = self.x.saturating_add_signed(clamp_to_i16(x));
                self.y = self.y.saturating_add_signed(clamp_to_i16(y));
                self.set_button(button_bit(button), pressed);
            }
            MouseEvent::VerticalScroll { value } => {
                let _ = self.out.send(Event::Input(DesktopInput::Wheel {
                    x: self.x,
                    y: self.y,
                    vertical: true,
                    delta: wheel_notches(value),
                }));
            }
            MouseEvent::Scroll { x, y } => {
                // High-resolution (ainput) 2D scroll: prefer the vertical axis.
                let (vertical, magnitude) = if y != 0 { (true, y) } else { (false, x) };
                if magnitude != 0 {
                    let _ = self.out.send(Event::Input(DesktopInput::Wheel {
                        x: self.x,
                        y: self.y,
                        vertical,
                        delta: i16::try_from(magnitude.signum()).unwrap_or(0),
                    }));
                }
            }
            MouseEvent::RelMove { x, y } => {
                self.x = self.x.saturating_add_signed(clamp_to_i16(x));
                self.y = self.y.saturating_add_signed(clamp_to_i16(y));
                self.emit_pointer();
            }
            // `MouseEvent` is non-exhaustive; input kinds added upstream have no viewer mapping.
            _ => {}
        }
    }
}

/// RDP carries wheel rotation in units of 120 per detent; Warpgate's shared `Wheel` input
/// is a notch count (re-multiplied by 120 downstream), so divide, preserving sign for
/// sub-detent high-resolution wheels.
const fn wheel_notches(value: i16) -> i16 {
    let notches = value / 120;
    if notches == 0 {
        value.signum()
    } else {
        notches
    }
}

/// Bit index of `button` in the viewer-side button mask (matches the browser's
/// `MouseEvent.buttons` order).
fn button_bit(button: MouseButton) -> u8 {
    match button {
        MouseButton::Left => 0,
        MouseButton::Middle => 1,
        MouseButton::Right => 2,
        MouseButton::X1 => 3,
        MouseButton::X2 => 4,
        _ => 5,
    }
}

fn clamp_to_i16(value: i32) -> i16 {
    value.clamp(i32::from(i16::MIN), i32::from(i16::MAX)) as i16
}

#[cfg(test)]
mod desktop_size_tests {
    use std::sync::Arc;

    use ironrdp_displaycontrol::pdu::{DisplayControlMonitorLayout, MonitorLayoutEntry};
    use tokio::sync::{Mutex, mpsc};

    use super::{
        DEFAULT_SIZE, DesktopSize, DisplayHandler, MAX_DESKTOP_DIM, MAX_FRAME_BYTES,
        MIN_DESKTOP_DIM, RdpServerDisplay, clamp_desktop_size, primary_monitor_size,
    };
    use crate::server::protocol::Event;

    fn size(width: u16, height: u16) -> DesktopSize {
        DesktopSize { width, height }
    }

    fn single_primary_layout(width: u32, height: u32) -> DisplayControlMonitorLayout {
        DisplayControlMonitorLayout::new(&[MonitorLayoutEntry::new_primary(width, height).unwrap()])
            .unwrap()
    }

    #[test]
    fn honours_a_reasonable_request() {
        assert_eq!(clamp_desktop_size(size(2560, 1440)), size(2560, 1440));
    }

    #[test]
    fn clamps_degenerate_and_oversized_dimensions() {
        assert_eq!(
            clamp_desktop_size(size(0, 0)),
            size(MIN_DESKTOP_DIM, MIN_DESKTOP_DIM)
        );
        // Clamped per dimension, and the resulting area still has to fit one frame.
        let clamped = clamp_desktop_size(size(u16::MAX, 240));
        assert_eq!(clamped, size(MAX_DESKTOP_DIM, 240));
    }

    #[test]
    fn falls_back_when_a_full_frame_would_not_fit() {
        // 8192x8192 BGRA is 256 MB, past MAX_FRAME_BYTES, so neither dimension is trusted.
        let fallback = clamp_desktop_size(size(MAX_DESKTOP_DIM, MAX_DESKTOP_DIM));
        assert_eq!(fallback, size(DEFAULT_SIZE.0, DEFAULT_SIZE.1));
        let frame_len = usize::from(fallback.width) * usize::from(fallback.height) * 4;
        assert!(frame_len <= MAX_FRAME_BYTES);
    }

    #[test]
    fn uses_primary_monitor_for_dynamic_layout() {
        let layout = DisplayControlMonitorLayout::new(&[
            MonitorLayoutEntry::new_primary(1920, 1080).unwrap(),
            MonitorLayoutEntry::new_secondary(1280, 720)
                .unwrap()
                .with_position(1920, 0)
                .unwrap(),
        ])
        .unwrap();

        assert_eq!(primary_monitor_size(&layout), Some(size(1920, 1080)));
    }

    #[test]
    fn normalizes_dynamic_layout_size() {
        let layout = single_primary_layout(1921, 1080);

        assert_eq!(primary_monitor_size(&layout), Some(size(1920, 1080)));
    }

    fn display_handler(
        committed: DesktopSize,
        initial_size_negotiated: bool,
    ) -> (DisplayHandler, mpsc::UnboundedReceiver<Event>) {
        let (_tx, rx) = mpsc::channel(1);
        let (out, events) = mpsc::unbounded_channel();
        let display = DisplayHandler {
            size: Arc::new(Mutex::new(committed)),
            initial_size_negotiated,
            updates: Arc::new(Mutex::new(rx)),
            target_connected: Arc::default(),
            out,
        };
        (display, events)
    }

    /// A layout at the committed size is noise; a different one is a request for the target.
    #[test]
    fn dynamic_layout_request_is_forwarded_to_the_target() {
        let (mut display, mut events) = display_handler(size(800, 600), true);

        display.request_layout(single_primary_layout(800, 600));
        assert!(events.try_recv().is_err());

        display.request_layout(single_primary_layout(1024, 768));
        assert!(matches!(
            events.try_recv(),
            Ok(Event::ResizeRequest {
                width: 1024,
                height: 768,
            })
        ));
    }

    #[tokio::test]
    async fn initial_size_adopts_the_viewer_request() {
        let (mut display, mut events) =
            display_handler(size(DEFAULT_SIZE.0, DEFAULT_SIZE.1), false);

        assert_eq!(
            display.request_initial_size(size(1024, 768)).await,
            size(1024, 768)
        );
        assert_eq!(display.size().await, size(1024, 768));
        assert!(matches!(
            events.try_recv(),
            Ok(Event::Size {
                width: 1024,
                height: 768,
            })
        ));
    }

    /// On reactivation the viewer can echo a size that lags the freshly negotiated one; the
    /// committed (target-driven) size must win, or a grow would rebuild the encoder too small
    /// and drop every oversized tile.
    #[tokio::test]
    async fn reactivation_keeps_the_committed_size() {
        let (mut display, mut events) = display_handler(size(1920, 1080), true);

        assert_eq!(
            display.request_initial_size(size(1024, 768)).await,
            size(1920, 1080)
        );
        assert_eq!(display.size().await, size(1920, 1080));
        assert!(events.try_recv().is_err());
    }
}

#[cfg(test)]
mod cursor_tests {
    use ironrdp_graphics::pointer::{DecodedPointer, PointerBitmapTarget};
    use ironrdp_pdu::pointer::{ColorPointerAttribute, Point16, PointerAttribute};
    use ironrdp_server::DisplayUpdate;

    use super::{MAX_CURSOR_DIM, MAX_NEW_POINTER_DIM, cursor_to_update};

    /// What a viewer decodes from the update: the target's RGBA pixels come back out.
    #[test]
    fn viewer_decodes_the_cursor_the_target_sent() {
        // 2x2, BGRA, top row first: red, green / blue, translucent white.
        let bgra = [
            [0, 0, 255, 255],
            [0, 255, 0, 255],
            [255, 0, 0, 255],
            [255, 255, 255, 128],
        ]
        .concat();
        let DisplayUpdate::RGBAPointer(pointer) = cursor_to_update(1, 0, 2, 2, &bgra) else {
            panic!("expected a pointer update");
        };
        assert_eq!((pointer.hot_x, pointer.hot_y), (1, 0));

        let decoded = DecodedPointer::decode_pointer_attribute(
            &PointerAttribute {
                xor_bpp: 32,
                color_pointer: ColorPointerAttribute {
                    cache_index: pointer.cache_index,
                    hot_spot: Point16 {
                        x: pointer.hot_x,
                        y: pointer.hot_y,
                    },
                    width: pointer.width,
                    height: pointer.height,
                    xor_mask: &pointer.data,
                    and_mask: &[],
                },
            },
            PointerBitmapTarget::Accelerated,
        )
        .unwrap();
        let rgba = [
            [255, 0, 0, 255],
            [0, 255, 0, 255],
            [0, 0, 255, 255],
            [255, 255, 255, 128],
        ]
        .concat();
        assert_eq!(decoded.bitmap_data, rgba);
    }

    #[test]
    fn unusable_cursors_fall_back_to_the_default() {
        let pixels =
            |width: u16, height: u16| vec![0; usize::from(width) * usize::from(height) * 4];

        assert!(matches!(
            cursor_to_update(0, 0, 0, 0, &[]),
            DisplayUpdate::DefaultPointer
        ));
        assert!(matches!(
            cursor_to_update(0, 0, 2, 2, &pixels(2, 1)),
            DisplayUpdate::DefaultPointer
        ));
        let too_big = MAX_CURSOR_DIM + 1;
        assert!(matches!(
            cursor_to_update(0, 0, too_big, 1, &pixels(too_big, 1)),
            DisplayUpdate::DefaultPointer
        ));
    }

    /// A target whose cursors are larger than 32x32 (a scaled display, or a larger pointer
    /// size in its accessibility settings) has them shown, not replaced by the default.
    /// Which update a viewer can take at that size is the server's encoder's choice.
    #[test]
    fn large_cursors_are_sent_whole() {
        let pixels =
            |width: u16, height: u16| vec![7; usize::from(width) * usize::from(height) * 4];

        for size in [32, 48, MAX_NEW_POINTER_DIM] {
            let DisplayUpdate::RGBAPointer(pointer) =
                cursor_to_update(3, 4, size, size, &pixels(size, size))
            else {
                panic!("expected a {size}x{size} cursor to go as an RGBAPointer");
            };
            assert_eq!((pointer.width, pointer.height), (size, size));
            assert_eq!((pointer.hot_x, pointer.hot_y), (3, 4));
            assert_eq!(pointer.data, pixels(size, size));
        }

        for (width, height) in [
            (MAX_NEW_POINTER_DIM + 1, 32),
            (32, MAX_NEW_POINTER_DIM + 1),
            (MAX_CURSOR_DIM, MAX_CURSOR_DIM),
        ] {
            let DisplayUpdate::LargePointer(pointer) =
                cursor_to_update(3, 4, width, height, &pixels(width, height))
            else {
                panic!("expected a {width}x{height} cursor to go as a LargePointer");
            };
            assert_eq!((pointer.width, pointer.height), (width, height));
            assert_eq!((pointer.hot_x, pointer.hot_y), (3, 4));
            assert_eq!(pointer.data, pixels(width, height));
        }
    }
}

#[cfg(test)]
mod outcome_tests {
    use std::io;

    use ironrdp_pdu::rdp::server_error_info::{ErrorInfo, ProtocolIndependentCode};
    use ironrdp_server::{ServerError, ServerErrorExt as _};

    use super::{Refusal, is_hang_up, refusal_error_info};

    /// The error mstsc's ordinary disconnect produces is told from a session that failed,
    /// however deep in the error chain the I/O error sits.
    #[test]
    fn a_viewer_hanging_up_is_not_a_failure() {
        let no_close_notify = ServerError::io(
            "read frame",
            io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "peer closed connection without sending TLS close_notify",
            ),
        );
        assert!(is_hang_up(&no_close_notify));
        assert!(is_hang_up(&ServerError::io(
            "write",
            io::ErrorKind::ConnectionReset.into()
        )));

        assert!(!is_hang_up(&ServerError::reason("decode", "invalid PDU")));
        assert!(!is_hang_up(&ServerError::io(
            "tls",
            io::Error::new(io::ErrorKind::InvalidData, "bad certificate")
        )));
    }

    #[test]
    fn each_refusal_tells_the_viewer_why() {
        let code = |refusal| match refusal_error_info(refusal) {
            ErrorInfo::ProtocolIndependentCode(code) => code,
            other => panic!("unexpected error info {other:?}"),
        };
        assert_eq!(
            code(Refusal::Denied),
            ProtocolIndependentCode::ServerInsufficientPrivileges
        );
        assert_eq!(
            code(Refusal::NotApproved),
            ProtocolIndependentCode::ServerDeniedConnection
        );
        assert_eq!(
            code(Refusal::TimedOut),
            ProtocolIndependentCode::LogonTimeout
        );
    }
}

#[cfg(test)]
mod suppress_tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use bytes::Bytes;
    use ironrdp_server::{DisplayUpdate, RdpServerDisplayUpdates as _};
    use tokio::sync::{Mutex, mpsc};

    use super::{DisplayUpdatesReceiver, SUPPRESS_SETTLE, frame_to_update};

    fn frame() -> DisplayUpdate {
        frame_to_update(0, 0, 1, 1, Bytes::from_static(&[0, 0, 0, 255])).unwrap()
    }

    /// A receiver whose frames are the target's desktop.
    fn receiver() -> (
        mpsc::Sender<DisplayUpdate>,
        Arc<AtomicBool>,
        DisplayUpdatesReceiver,
    ) {
        let (tx, rx) = mpsc::channel(4);
        let suppressed = Arc::new(AtomicBool::new(false));
        let updates = DisplayUpdatesReceiver::new(
            Arc::new(Mutex::new(rx)),
            suppressed.clone(),
            Arc::new(AtomicBool::new(true)),
        );
        (tx, suppressed, updates)
    }

    /// Warpgate's own screens go out to a minimised viewer: the sign-in and its second
    /// factor carry on meanwhile, and their painter waits on every frame it sends.
    #[tokio::test(start_paused = true)]
    async fn warpgates_own_screens_are_never_held_back() {
        let (tx, rx) = mpsc::channel(4);
        let suppressed = Arc::new(AtomicBool::new(false));
        let mut updates = DisplayUpdatesReceiver::new(
            Arc::new(Mutex::new(rx)),
            suppressed.clone(),
            Arc::new(AtomicBool::new(false)),
        );
        tx.send(frame()).await.unwrap();
        updates.next_update().await.unwrap();

        suppressed.store(true, Ordering::Relaxed);
        tokio::time::sleep(SUPPRESS_SETTLE * 2).await;
        for _ in 0..3 {
            tx.send(frame()).await.unwrap();
            assert!(matches!(updates.next_update().await, Ok(Some(_))));
            tokio::time::sleep(SUPPRESS_SETTLE).await;
        }
    }

    /// mstsc asks for no output while it is still connecting; its first frame goes out
    /// regardless, or it would stay frozen.
    #[tokio::test(start_paused = true)]
    async fn the_first_frame_is_never_held_back() {
        let (tx, suppressed, mut updates) = receiver();
        suppressed.store(true, Ordering::Relaxed);
        tokio::time::sleep(SUPPRESS_SETTLE * 2).await;

        tx.send(frame()).await.unwrap();
        assert!(matches!(
            updates.next_update().await,
            Ok(Some(DisplayUpdate::Bitmap(_)))
        ));
    }

    /// A viewer minimised for a while is sent nothing until it is back, and then gets what
    /// waited.
    #[tokio::test(start_paused = true)]
    async fn a_minimised_viewer_is_sent_nothing_until_it_is_back() {
        let (tx, suppressed, mut updates) = receiver();
        tx.send(frame()).await.unwrap();
        updates.next_update().await.unwrap();

        suppressed.store(true, Ordering::Relaxed);
        // Not yet: the request could be a flap.
        tx.send(frame()).await.unwrap();
        assert!(matches!(updates.next_update().await, Ok(Some(_))));

        tokio::time::sleep(SUPPRESS_SETTLE).await;
        tx.send(frame()).await.unwrap();
        let held = tokio::time::timeout(Duration::from_secs(10), updates.next_update()).await;
        assert!(held.is_err(), "an update went out to a minimised viewer");

        suppressed.store(false, Ordering::Relaxed);
        assert!(matches!(
            updates.next_update().await,
            Ok(Some(DisplayUpdate::Bitmap(_)))
        ));
    }

    /// A request for no output that is withdrawn within the settling time holds nothing.
    #[tokio::test(start_paused = true)]
    async fn a_flapping_request_holds_nothing_back() {
        let (tx, suppressed, mut updates) = receiver();
        tx.send(frame()).await.unwrap();
        updates.next_update().await.unwrap();

        for _ in 0..5 {
            suppressed.store(true, Ordering::Relaxed);
            tx.send(frame()).await.unwrap();
            assert!(matches!(updates.next_update().await, Ok(Some(_))));
            suppressed.store(false, Ordering::Relaxed);
            tx.send(frame()).await.unwrap();
            assert!(matches!(updates.next_update().await, Ok(Some(_))));
            tokio::time::sleep(SUPPRESS_SETTLE / 2).await;
        }
    }
}

#[cfg(test)]
mod framed_tests {
    use std::time::Duration;

    use ironrdp_pdu::X224_HINT;
    use ironrdp_tokio::TokioFramed;
    use tokio::io::AsyncWriteExt as _;

    /// A fast-path header whose length field is zero is a frame `X224_HINT` neither
    /// matches nor can skip past. The reader has to fail it; looping on it would pin a
    /// core for as long as the process lives, long after the sender has gone away.
    #[tokio::test]
    async fn zero_length_unmatched_frame_fails_instead_of_spinning() {
        let (server_side, mut client_side) = tokio::io::duplex(64);
        client_side.write_all(&[0x00, 0x00]).await.unwrap();
        let mut framed = TokioFramed::new(server_side);
        let result = tokio::time::timeout(Duration::from_secs(5), framed.read_by_hint(&X224_HINT))
            .await
            .expect("read_by_hint spun instead of returning");
        assert!(result.is_err());
    }
}
