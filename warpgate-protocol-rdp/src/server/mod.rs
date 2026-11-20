//! Native RDP server endpoint.
//!
//! Warpgate accepts a raw TCP connection from a standard RDP client (mstsc/FreeRDP) and
//! brokers between two halves:
//!
//! * the viewer-facing [`rdp`] server runs the RDP server state machine and terminates
//!   TLS, and
//! * the target-facing [`crate::client`] (via [`crate::connect`]) drives the RDP client
//!   toward the configured target.
//!
//! Warpgate keeps ownership of the listener, the session/audit lifecycle, and
//! authentication. Credentials the viewer submits arrive as [`ServerEvent::AuthRequest`];
//! Warpgate authenticates them with the same [`AuthSelector`] flow used by the native VNC
//! server, connects to the resolved target, and bridges target framebuffer events back to
//! the viewer while recording them — so native RDP records exactly like the in-browser
//! path. A viewer that sends no password, as mstsc does without a saved credential, signs
//! in on Warpgate's own sign-in screen instead (the `sign_in` module).

use std::io;
use std::net::SocketAddr;
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use futures::FutureExt;
use futures::future::BoxFuture;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt as _, DuplexStream};
use tokio::sync::mpsc::{Sender, UnboundedReceiver, UnboundedSender, channel, unbounded_channel};
use tokio::sync::oneshot;
use tokio::time::{Instant, timeout, timeout_at};
use tracing::{Instrument, debug, error, info, info_span, warn};
use warpgate_common::helpers::net::accept_loop;
use warpgate_common::{ListenEndpoint, TargetRdpOptions, WarpgateError};
use warpgate_core::recordings::DesktopRecorder;
use warpgate_core::{
    DesktopInput, Services, State, TargetAuthorization, UserSessionStateInit, WarpgateServerHandle,
};
use warpgate_db_entities::Parameters;
use warpgate_desktop_ui::{DEFAULT_SCREEN_H, DEFAULT_SCREEN_W};

use crate::PROTOCOL_NAME;
use crate::session_handle::RdpSessionHandle;

mod bridge;
mod clipboard;
mod hold_screen;
mod protocol;
mod rdp;
mod sign_in;

use bridge::connect_backend;
use hold_screen::{hold_while, run_banner_screen, run_hold_screen};
use protocol::{AuthVerdict, Event as ServerEvent, Input as ServerInput, Refusal};
use sign_in::{SignInScreen, SignInStep, Submission, needs_sign_in};
use warpgate_desktop_auth::{
    AdmissionHold, DesktopAuthOutcome, InteractiveAuth, admit_desktop_session, authenticate,
    finalize_user_auth,
};

/// Depth of the feed into the viewer-facing RDP server. Bounded so a slow viewer
/// backpressures `frame_bridge`, and through it the target client, which then folds the
/// updates the viewer has no room for into later ones. Kept small: every frame queued here
/// is one the viewer sees late, and can be a whole-desktop image.
const SERVER_INPUT_CAPACITY: usize = 4;

/// Size of each direction of the in-memory duplex carrying raw RDP bytes between the
/// viewer socket and the RDP server.
const RELAY_BUFFER_BYTES: usize = 64 * 1024;

/// The most the relay passes from the RDP server to the viewer's socket in one write. With
/// `tokio::io::copy`'s 8 KB, a busy desktop cost the relay a system call for every 8 KB.
const RELAY_WRITE_BYTES: usize = 64 * 1024;

/// How much the viewer's socket may hold that it has not sent yet. The kernel otherwise lets it
/// take megabytes on a slow link, all of it frames the viewer sees late, one after another,
/// seconds behind the target. Bounded, the relay waits sooner, so does the RDP server behind it,
/// and the target client folds what changes meanwhile into its next update. The data in flight
/// is not limited by this, so neither is the link's throughput.
#[cfg(any(target_os = "linux", target_os = "android"))]
const VIEWER_UNSENT_BYTES: u32 = 256 * 1024;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(120);

/// How long the viewer's connection stays open once the session has ended, for the RDP
/// server's last PDUs to reach the viewer and the viewer to hang up. Generous: a viewer
/// that has them disconnects within a round trip.
const RELAY_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// Handles to the connected target-side RDP client, kept once authentication succeeds.
struct BackendBridge {
    input_tx: Sender<DesktopInput>,
    abort_tx: UnboundedSender<()>,
    frame_bridge: tokio::task::JoinHandle<()>,
    /// Shared with `frame_bridge`; used to record viewer input alongside the
    /// framebuffer. `None` when recording is disabled.
    recorder: Option<Arc<DesktopRecorder>>,
    /// The size the target was dialed at, until the viewer's own negotiated size has been
    /// reconciled against it; `None` once that has happened. A viewer whose buffered input
    /// dials the target before the capability exchange reports its resolution is dialed at
    /// the advertised default, and this is what lets the resolution that follows still reach
    /// the target. Only the viewer's *first* size is its own — every later one echoes a
    /// resize the target itself drove, and re-sending that would fight the target.
    dialed_at: Option<warpgate_desktop_ui::Screen>,
}

impl BackendBridge {
    /// Stop the target client and its frame bridge.
    fn shutdown(self) {
        let _ = self.abort_tx.send(());
        self.frame_bridge.abort();
    }
}

pub async fn bind_server(
    services: Services,
    address: ListenEndpoint,
    proxy_protocol: bool,
    cert_pem: String,
    key_pem: String,
) -> Result<BoxFuture<'static, Result<()>>> {
    let listener = address.tcp_accept_stream().await?;

    Ok(async move {
        accept_loop(
            "RDP connection",
            listener,
            proxy_protocol,
            move |stream, remote_address| {
                limit_unsent_bytes(&stream);
                let services = services.clone();
                let cert_pem = cert_pem.clone();
                let key_pem = key_pem.clone();
                async move {
                    let (session_handle, mut abort_rx) = RdpSessionHandle::new();

                    let (server_handle, viewer_stream) = State::register_user_session_with_stream(
                        &services.state,
                        PROTOCOL_NAME,
                        UserSessionStateInit {
                            remote_address: Some(remote_address),
                            handle: Box::new(session_handle),
                        },
                        stream,
                    )
                    .await
                    .context("registering session")?;

                    let span =
                        info_span!("RDP", session=%server_handle.lock().await.user_session_id());

                    // The outcome logs run in the span too: anything logged outside it is
                    // not attributed to the session. They are synchronous, so they enter the
                    // span directly rather than nesting another future in this one.
                    tokio::select! {
                        result = handle_connection(
                            services,
                            server_handle.clone(),
                            viewer_stream,
                            remote_address,
                            cert_pem,
                            key_pem,
                        ).instrument(span.clone()) => span.in_scope(|| match result {
                            Ok(()) => info!("Session ended"),
                            Err(error) => error!(%error, "Session failed"),
                        }),
                        _ = abort_rx.recv() => span.in_scope(|| {
                            warn!("Session aborted by admin");
                        }),
                    }
                    Ok(())
                }
            },
        )
        .await;

        Ok(())
    }
    .boxed())
}

/// Bound what the viewer's socket keeps unsent; see [`VIEWER_UNSENT_BYTES`]. A socket that
/// refuses keeps the kernel's default, as before.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn limit_unsent_bytes(stream: &tokio::net::TcpStream) {
    if let Err(error) = socket2::SockRef::from(stream).set_tcp_notsent_lowat(VIEWER_UNSENT_BYTES) {
        debug!(%error, "Could not bound the viewer socket's unsent bytes");
    }
}

/// Only Linux has `TCP_NOTSENT_LOWAT`; elsewhere the socket keeps the kernel's default.
#[cfg(not(any(target_os = "linux", target_os = "android")))]
const fn limit_unsent_bytes(_: &tokio::net::TcpStream) {}

async fn handle_connection(
    services: Services,
    server_handle: Arc<tokio::sync::Mutex<WarpgateServerHandle>>,
    viewer: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
    remote_address: SocketAddr,
    cert_pem: String,
    key_pem: String,
) -> Result<()> {
    // Warpgate owns the viewer socket and the session; `rdp` runs the RDP server state
    // machine over it and terminates TLS toward the viewer.
    let (server_out_tx, server_out_rx) = unbounded_channel::<ServerEvent>();
    // Bounded so a slow viewer backpressures the target losslessly; `frame_bridge` frames
    // and control_loop's occasional auth verdicts share this one ordered feed.
    let (server_in_tx, server_in_rx) = channel::<ServerInput>(SERVER_INPUT_CAPACITY);

    // `ironrdp-server` requires a `Sync` transport, which the session-wrapped viewer
    // stream is not, so the server runs against an in-memory duplex and we relay the raw
    // (TLS) RDP bytes across.
    let (server_side, relay_side) = tokio::io::duplex(RELAY_BUFFER_BYTES);
    // The viewer's keyboard layout, set once its session is activated, which is before the
    // capability exchange reports the size the target is dialed at.
    let keyboard_layout = Arc::new(AtomicU32::new(0));
    let rdp_done = rdp::run_on_thread(
        server_side,
        cert_pem,
        key_pem,
        (DEFAULT_SCREEN_W, DEFAULT_SCREEN_H),
        server_out_tx,
        server_in_rx,
        Arc::clone(&keyboard_layout),
    );

    drive_session(
        control_loop(
            services,
            server_handle,
            remote_address,
            server_out_rx,
            server_in_tx,
            keyboard_layout,
        ),
        rdp_done,
        relay(viewer, relay_side),
    )
    .await
}

/// Run the control loop, the RDP server and the byte relay concurrently; whichever ends
/// first ends the session.
///
/// The relay outlives the other two by up to [`RELAY_DRAIN_TIMEOUT`]. When the RDP server
/// ends the session itself — refusing a viewer whose credentials were rejected, say — its
/// last PDUs are still in the duplex when the control loop and the server's own result
/// report it gone, and dropping the relay then discarded them: the viewer saw the
/// connection vanish (mstsc: a protocol or network error) instead of the reason.
async fn drive_session(
    control: impl Future<Output = Result<()>>,
    mut rdp_done: oneshot::Receiver<Result<()>>,
    relay: impl Future<Output = ()>,
) -> Result<()> {
    let mut relay = pin!(relay);
    let mut relay_finished = false;

    let result = tokio::select! {
        result = control => result,
        result = &mut rdp_done => {
            match result {
                Ok(Ok(())) => {}
                Ok(Err(error)) => warn!(%error, "RDP server failed"),
                Err(_) => debug!("RDP server ended"),
            }
            Ok(())
        }
        () = &mut relay => {
            relay_finished = true;
            Ok(())
        }
    };

    if !relay_finished && timeout(RELAY_DRAIN_TIMEOUT, &mut relay).await.is_err() {
        debug!("Viewer still connected after the RDP session ended; closing");
    }

    result
}

/// Relay raw RDP bytes between the viewer's connection and the RDP server's duplex until
/// both are done: the server has ended and everything it wrote has reached the viewer,
/// and the viewer has hung up.
///
/// Unlike `copy_bidirectional`, the server ending first is not an error that cuts the
/// viewer off. A server that ends has usually just written its last PDUs, and input the
/// viewer sends meanwhile can no longer be delivered; failing on that would drop the
/// connection with those PDUs undelivered. So the input is discarded instead, and the
/// viewer gets everything the server wrote, then a FIN. It is then read until it hangs up
/// (the ultimatum the server ends with tells it to), because closing a socket that still
/// holds unread input makes the kernel reset the connection, and a reset can destroy the
/// server's last PDUs before the viewer has read them.
async fn relay<V>(viewer: V, server: DuplexStream)
where
    V: AsyncRead + AsyncWrite,
{
    let (mut viewer_rx, mut viewer_tx) = tokio::io::split(viewer);
    let (mut server_rx, mut server_tx) = tokio::io::split(server);

    let to_viewer = async {
        let mut server_rx = tokio::io::BufReader::with_capacity(RELAY_WRITE_BYTES, &mut server_rx);
        tokio::io::copy_buf(&mut server_rx, &mut viewer_tx).await?;
        viewer_tx.shutdown().await
    };
    let from_viewer = async {
        match tokio::io::copy(&mut viewer_rx, &mut server_tx).await {
            // The duplex is closed: the server has ended.
            Err(error) if error.kind() == io::ErrorKind::BrokenPipe => {
                tokio::io::copy(&mut viewer_rx, &mut tokio::io::sink()).await?;
            }
            result => {
                // Pass the viewer's hang-up on, so that the server ends too.
                let _ = server_tx.shutdown().await;
                result?;
            }
        }
        Ok::<_, io::Error>(())
    };

    if let Err(error) = tokio::try_join!(to_viewer, from_viewer) {
        debug!(%error, "RDP byte relay error");
    }
}

/// Read the RDP server's event stream: authenticate the viewer, connect to the target on
/// success, and forward viewer input to the target client.
async fn control_loop(
    services: Services,
    server_handle: Arc<tokio::sync::Mutex<WarpgateServerHandle>>,
    remote_address: SocketAddr,
    mut events: UnboundedReceiver<ServerEvent>,
    server_in_tx: Sender<ServerInput>,
    keyboard_layout: Arc<AtomicU32>,
) -> Result<()> {
    let viewer = Viewer {
        services: &services,
        server_handle: &server_handle,
        server_in_tx: &server_in_tx,
        remote_address,
        keyboard_layout: &keyboard_layout,
    };
    let mut backend: Option<BackendBridge> = None;
    // Authorized target awaiting the first `Size` event before we dial it. The RDP
    // sequence delivers the viewer's credentials (Client Info PDU) *before* its desktop
    // size (capability exchange), so we hold the authorized target here and dial once the
    // negotiated resolution arrives — otherwise the target would be dialed at the
    // pre-negotiation default and the whole session would run at that size.
    let mut pending_dial: Option<PendingDial> = None;
    // What the RDP server settled on with the viewer, which is what we ask the target for.
    // Seeded with the size we advertised, used only if the viewer never negotiates one.
    let mut screen = warpgate_desktop_ui::Screen {
        width: DEFAULT_SCREEN_W,
        height: DEFAULT_SCREEN_H,
    };

    let handshake_deadline = Instant::now() + HANDSHAKE_TIMEOUT;

    loop {
        // Bound the wait only until the target is dialed; once `backend` is set the
        // established proxy session runs without a time limit.
        let event = if backend.is_some() {
            events.recv().await
        } else {
            timeout_at(handshake_deadline, events.recv())
                .await
                .map_err(|_| anyhow!("RDP pre-authorization handshake timed out"))?
        };
        let Some(event) = event else {
            break;
        };
        let input = match event {
            ServerEvent::AuthRequest {
                username,
                password,
                reply,
            } => {
                if backend.is_some() || pending_dial.is_some() {
                    // Already authenticated (dialed, or awaiting the size to dial); reject a
                    // duplicate request by dropping its reply rather than answering twice.
                    continue;
                }
                match admit(
                    &viewer,
                    &username,
                    password,
                    reply,
                    &mut events,
                    &mut screen,
                )
                .await?
                {
                    // The RDP server refuses the connection, which ends this loop.
                    Admission::Refused => continue,
                    Admission::Ended => break,
                    Admission::DialOnSize(authorization) => {
                        pending_dial = Some(authorization);
                        continue;
                    }
                    Admission::DialNow {
                        authorization,
                        clipboard,
                    } => {
                        pending_dial = Some(authorization);
                        if !dial_if_pending(
                            &mut backend,
                            &mut pending_dial,
                            &viewer,
                            &mut events,
                            &mut screen,
                        )
                        .await?
                        {
                            break;
                        }
                        // The viewer's clipboard text, which a screen took on its way to the
                        // target: recorded and forwarded below like any other input.
                        match clipboard {
                            Some(text) => DesktopInput::Clipboard(text),
                            None => continue,
                        }
                    }
                }
            }
            ServerEvent::Size { width, height } => {
                screen = warpgate_desktop_ui::Screen { width, height };
                if !dial_if_pending(
                    &mut backend,
                    &mut pending_dial,
                    &viewer,
                    &mut events,
                    &mut screen,
                )
                .await?
                {
                    break;
                }
                // A target dialed before this arrived is running at the advertised default,
                // so bring it to the resolution the viewer actually negotiated. `take` spends
                // the reconciliation whether or not it resizes anything, so the `Size` a
                // target-driven resize echoes back here is never bounced at the target.
                if let Some(backend) = &mut backend
                    && let Some(dialed_at) = backend.dialed_at.take()
                    && dialed_at != screen
                    && backend
                        .input_tx
                        .send(DesktopInput::Resize { width, height })
                        .await
                        .is_err()
                {
                    break;
                }
                continue;
            }
            ServerEvent::ResizeRequest { width, height } => {
                if let Some(backend) = &mut backend {
                    // The viewer is driving the size itself now; reconciling the dial size
                    // afterwards could only replay a stale one.
                    backend.dialed_at = None;
                    if backend
                        .input_tx
                        .send(DesktopInput::Resize { width, height })
                        .await
                        .is_err()
                    {
                        break;
                    }
                } else if server_in_tx
                    .send(ServerInput::Resize { width, height })
                    .await
                    .is_err()
                {
                    break;
                }
                continue;
            }
            // Lock-key state matters to the sign-in screen only.
            ServerEvent::KeyboardSync { .. } => continue,
            // Viewer input: record it for audit (like native VNC) then forward to the
            // target. `break` once the target client is gone (send fails).
            ServerEvent::Input(input) => input,
        };

        // A viewer that never negotiates a size won't emit `Size`; dial the pending target on
        // its first input so the session still connects (at the advertised default). Input the
        // viewer sent during the handshake is delivered ahead of the negotiated size, so this
        // also fires for viewers that do negotiate one — the `Size` arm resizes the target once
        // that size arrives.
        if !dial_if_pending(
            &mut backend,
            &mut pending_dial,
            &viewer,
            &mut events,
            &mut screen,
        )
        .await?
        {
            break;
        }

        // Reached only for viewer input.
        let Some(backend) = &backend else {
            continue;
        };
        if let Some(recorder) = &backend.recorder
            && let Err(error) = recorder.write_input(&input).await
        {
            warn!(%error, "Failed to record RDP viewer input");
        }
        if backend.input_tx.send(input).await.is_err() {
            break;
        }
    }

    if let Some(backend) = backend {
        backend.shutdown();
    }
    Ok(())
}

/// What dialing the target and refusing the viewer take, fixed for the connection.
struct Viewer<'a> {
    services: &'a Services,
    server_handle: &'a Arc<tokio::sync::Mutex<WarpgateServerHandle>>,
    server_in_tx: &'a Sender<ServerInput>,
    remote_address: SocketAddr,
    /// The keyboard layout the viewer announced, for the target. `0`, the target's own
    /// default, until the viewer's session is activated.
    keyboard_layout: &'a AtomicU32,
}

impl Viewer<'_> {
    /// End the viewer's session, telling it why.
    async fn refuse(&self, refusal: Refusal) {
        let _ = self
            .server_in_tx
            .send(ServerInput::Disconnect(refusal))
            .await;
    }
}

/// How the viewer's credentials were settled.
enum Admission {
    /// Its Client Info credentials were refused, so the RDP server refuses the connection.
    Refused,
    /// The session is over: the viewer left, or was refused (and told why) after its
    /// session had started.
    Ended,
    /// Authorized during the handshake, before the capability exchange has reported the
    /// viewer's size: the target is dialed at that size once it arrives.
    DialOnSize(PendingDial),
    /// Authorized after a screen, which took the viewer's size meanwhile: dial now.
    DialNow {
        authorization: PendingDial,
        /// The viewer's clipboard text, if the sign-in screen took it, for the target.
        clipboard: Option<String>,
    },
}

/// Settle the viewer's credentials: check the ones its Client Info PDU carried or, without
/// a password, ask for them on the sign-in screen; then collect any second factor and show
/// the login banner.
async fn admit(
    viewer: &Viewer<'_>,
    username: &str,
    password: String,
    reply: oneshot::Sender<AuthVerdict>,
    events: &mut UnboundedReceiver<ServerEvent>,
    screen: &mut warpgate_desktop_ui::Screen,
) -> Result<Admission> {
    // Every screen takes the viewer's `Size` event while it waits, so after one the target
    // is dialed right away rather than on a `Size` that has come and gone.
    let signing_in = needs_sign_in(username, &password);
    let mut screen_shown = signing_in;

    let (outcome, clipboard) = if signing_in {
        // mstsc connects like this whenever it holds no saved credential: over TLS-only
        // security it asks for nothing and expects the server to sign the user in on
        // screen. Let the connection sequence finish, so there is a screen to do that on.
        info!("The viewer sent no password; asking for one on the sign-in screen");
        if reply.send(AuthVerdict::StartSession).is_err() {
            return Ok(Admission::Ended);
        }
        let Some(signed_in) = sign_in(viewer, username, events, screen).await? else {
            return Ok(Admission::Ended);
        };
        signed_in
    } else {
        match authenticate::<TargetRdpOptions>(
            viewer.services,
            viewer.server_handle,
            username,
            password,
            viewer.remote_address,
        )
        .await
        {
            Ok(DesktopAuthOutcome::Failed) => {
                warn!("Authentication failed");
                let _ = reply.send(AuthVerdict::Deny);
                return Ok(Admission::Refused);
            }
            Err(error) => {
                warn!(%error, "Authentication error");
                let _ = reply.send(AuthVerdict::Deny);
                return Ok(Admission::Refused);
            }
            Ok(outcome) => {
                // Accept the credentials so the connection sequence finishes; a second
                // factor and the target's approval are collected over the session.
                if reply.send(AuthVerdict::StartSession).is_err() {
                    return Ok(Admission::Ended);
                }
                (outcome, None)
            }
        }
    };

    let authorization = match outcome {
        DesktopAuthOutcome::Authorized { authorization } => authorization,
        DesktopAuthOutcome::NeedsInteractive(interactive) => {
            screen_shown = true;
            let Some(authorization) = second_factor(viewer, &interactive, events, screen).await
            else {
                return Ok(Admission::Ended);
            };
            authorization
        }
        // Refused above for credentials from the Client Info PDU, and `sign_in` returns
        // only a successful outcome.
        DesktopAuthOutcome::Failed => {
            viewer.refuse(Refusal::Denied).await;
            return Ok(Admission::Ended);
        }
    };

    Ok(
        match acknowledge_banner(viewer.services, events, viewer.server_in_tx, screen).await? {
            BannerOutcome::Disconnected => Admission::Ended,
            BannerOutcome::NotShown if !screen_shown => Admission::DialOnSize(authorization),
            BannerOutcome::NotShown | BannerOutcome::Acknowledged => Admission::DialNow {
                authorization,
                clipboard,
            },
        },
    )
}

/// Show the sign-in screen until the viewer signs in. Each submission is checked exactly as
/// a password from the Client Info PDU is, lockout and failed-attempt accounting included.
///
/// `None` once the session is over: the viewer left, or was refused (and told why) after
/// [`sign_in::MAX_SIGN_IN_ATTEMPTS`] refused attempts or [`sign_in::SIGN_IN_TIMEOUT`]. With
/// the outcome comes the viewer's clipboard text, if it sent any, for the target.
async fn sign_in(
    viewer: &Viewer<'_>,
    username: &str,
    events: &mut UnboundedReceiver<ServerEvent>,
    screen: &mut warpgate_desktop_ui::Screen,
) -> Result<Option<(DesktopAuthOutcome<TargetRdpOptions>, Option<String>)>> {
    let mut form = SignInScreen::new(username, *screen);
    loop {
        let Submission { username, password } = match form
            .next_submission(events, viewer.server_in_tx, screen)
            .await?
        {
            SignInStep::Submitted(submission) => submission,
            SignInStep::Disconnected => return Ok(None),
            SignInStep::TimedOut => {
                warn!("The viewer did not sign in in time");
                viewer.refuse(Refusal::TimedOut).await;
                return Ok(None);
            }
        };
        form.show_checking(viewer.server_in_tx).await?;
        match authenticate::<TargetRdpOptions>(
            viewer.services,
            viewer.server_handle,
            &username,
            password,
            viewer.remote_address,
        )
        .await
        {
            Ok(DesktopAuthOutcome::Failed) => warn!("Authentication failed"),
            Ok(outcome) => return Ok(Some((outcome, form.into_clipboard()))),
            // A wrong target, or the check itself failing. The viewer is told the same as
            // for a wrong password, see `sign_in::REFUSED`.
            Err(error) => warn!(%error, "Authentication error"),
        }
        if !form.refused() {
            warn!("Too many failed sign-in attempts");
            viewer.refuse(Refusal::Denied).await;
            return Ok(None);
        }
    }
}

/// Collect the second factor (TOTP / web approval) on a Warpgate-rendered holding screen,
/// then authorize the target. `None` once the session is over: the viewer left, or was
/// refused (and told why).
async fn second_factor(
    viewer: &Viewer<'_>,
    interactive: &InteractiveAuth,
    events: &mut UnboundedReceiver<ServerEvent>,
    screen: &mut warpgate_desktop_ui::Screen,
) -> Option<PendingDial> {
    // `screen` is kept up to date by `run_hold_screen` as the viewer negotiates its size
    // during the prompt.
    match run_hold_screen(
        viewer.services,
        interactive,
        events,
        viewer.server_in_tx,
        screen,
    )
    .await
    {
        Ok(Some(identity)) => {
            match finalize_user_auth::<TargetRdpOptions>(
                viewer.services,
                &identity,
                &interactive.target_name,
            )
            .await
            {
                Ok(authorization) => return Some(authorization),
                Err(error) => warn!(%error, "Authorization failed after second factor"),
            }
        }
        Ok(None) => warn!("Interactive authentication failed"),
        Err(error) => warn!(%error, "Holding-screen error"),
    }
    viewer.refuse(Refusal::Denied).await;
    None
}

/// An authorized target held until the viewer's negotiated size is known.
type PendingDial = TargetAuthorization<TargetRdpOptions>;

enum BannerOutcome {
    /// No banner is configured, so nothing was rendered and no events were consumed.
    NotShown,
    /// The viewer acknowledged the banner; its negotiated size is now in `screen`.
    Acknowledged,
    Disconnected,
}

/// Show the login banner, if one is configured, and wait for the viewer to acknowledge it.
async fn acknowledge_banner(
    services: &Services,
    events: &mut UnboundedReceiver<ServerEvent>,
    server_in_tx: &Sender<ServerInput>,
    screen: &mut warpgate_desktop_ui::Screen,
) -> Result<BannerOutcome> {
    let Some(banner) = Parameters::Entity::get(&services.db)
        .await?
        .banner_text()
        .map(str::to_owned)
    else {
        return Ok(BannerOutcome::NotShown);
    };
    Ok(
        if run_banner_screen(&banner, events, server_in_tx, screen).await? {
            BannerOutcome::Acknowledged
        } else {
            BannerOutcome::Disconnected
        },
    )
}

/// Connect to target (idempotent) and wait for approval if needed
///
/// Returns `false` if an approval is denied
async fn dial_if_pending(
    backend: &mut Option<BackendBridge>,
    pending: &mut Option<PendingDial>,
    viewer: &Viewer<'_>,
    events: &mut UnboundedReceiver<ServerEvent>,
    screen: &mut warpgate_desktop_ui::Screen,
) -> Result<bool> {
    if backend.is_none()
        && let Some(authorization) = pending.take()
    {
        let hold = AdmissionHold::default();
        let admitting = admit_desktop_session(
            viewer.services,
            viewer.server_handle,
            authorization,
            Some(viewer.remote_address.ip()),
            &hold,
        );
        let Some(admitted) = hold_while(admitting, events, viewer.server_in_tx, screen, || {
            hold.frame()
        })
        .await?
        else {
            // The viewer went away mid-hold. Dropping the hold released what it
            // was holding: the request row is closed and any ticket use
            // refunded.
            return Ok(false);
        };

        let admitted = match admitted {
            Ok(admitted) => admitted,
            Err(WarpgateError::SessionNotApproved) => {
                warn!("Session was not approved by an administrator");
                viewer.refuse(Refusal::NotApproved).await;
                return Ok(false);
            }
            Err(error) => return Err(error.into()),
        };
        *backend = Some(
            connect_backend(
                viewer.services,
                viewer.server_in_tx,
                admitted,
                *screen,
                viewer.keyboard_layout.load(Ordering::Relaxed),
            )
            .await?,
        );
    }
    Ok(true)
}

#[cfg(test)]
mod relay_tests {
    use std::time::Duration;

    use anyhow::anyhow;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, duplex};
    use tokio::sync::oneshot;
    use tokio::time::timeout;

    use super::{RELAY_DRAIN_TIMEOUT, drive_session, relay};

    const DEADLINE: Duration = Duration::from_secs(5);

    /// An RDP server result that has already arrived, as when the server ended the session.
    fn rdp_ended() -> oneshot::Receiver<anyhow::Result<()>> {
        let (done_tx, rdp_done) = oneshot::channel();
        done_tx.send(Ok(())).unwrap();
        rdp_done
    }

    #[tokio::test]
    async fn relays_both_ways_while_the_session_runs() {
        let (viewer_socket, mut viewer) = duplex(64);
        let (mut server, relay_side) = duplex(64);
        let relaying = tokio::spawn(relay(viewer_socket, relay_side));

        let mut buf = [0; 4];
        viewer.write_all(b"ping").await.unwrap();
        server.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        server.write_all(b"pong").await.unwrap();
        viewer.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");

        drop((viewer, server));
        timeout(DEADLINE, relaying).await.unwrap().unwrap();
    }

    /// A viewer that hangs up ends the server's side too, so the RDP server ends with it.
    #[tokio::test]
    async fn viewer_hang_up_reaches_the_server() {
        let (viewer_socket, viewer) = duplex(64);
        let (mut server, relay_side) = duplex(64);
        let relaying = tokio::spawn(relay(viewer_socket, relay_side));

        drop(viewer);
        let mut rest = Vec::new();
        timeout(DEADLINE, server.read_to_end(&mut rest))
            .await
            .unwrap()
            .unwrap();
        assert!(rest.is_empty());

        drop(server);
        timeout(DEADLINE, relaying).await.unwrap().unwrap();
    }

    /// The viewer is still sending input when the server ends — mstsc does, right after the
    /// connection is established, which is when a rejected sign-in ends it. That input can
    /// no longer be delivered, and `copy_bidirectional` failed on it before delivering what
    /// the server had written last.
    #[tokio::test]
    async fn server_output_reaches_a_viewer_that_keeps_sending() {
        let (viewer_socket, mut viewer) = duplex(64);
        let (mut server, relay_side) = duplex(64);
        let relaying = tokio::spawn(relay(viewer_socket, relay_side));

        server.write_all(b"denial").await.unwrap();
        drop(server);
        viewer.write_all(b"input").await.unwrap();

        let mut received = Vec::new();
        timeout(DEADLINE, viewer.read_to_end(&mut received))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received, b"denial");

        drop(viewer);
        timeout(DEADLINE, relaying).await.unwrap().unwrap();
    }

    /// On a rejected sign-in the control loop and the RDP server's result both report the
    /// session over at once, while the server's last PDUs are still in the duplex. Ending
    /// the session must not take those PDUs with it.
    #[tokio::test]
    async fn session_end_does_not_cut_off_the_server() {
        // A one-byte pipe to the viewer, so that the relay cannot have delivered the
        // server's output before the session ends, whichever branch ends it.
        let (viewer_socket, mut viewer) = duplex(1);
        let (mut server, relay_side) = duplex(64);
        server.write_all(b"denial").await.unwrap();
        drop(server);

        let session = tokio::spawn(drive_session(
            async { Ok(()) },
            rdp_ended(),
            relay(viewer_socket, relay_side),
        ));

        let mut received = Vec::new();
        timeout(DEADLINE, viewer.read_to_end(&mut received))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received, b"denial");

        drop(viewer);
        timeout(DEADLINE, session).await.unwrap().unwrap().unwrap();
    }

    /// The wait for the viewer to hang up is bounded, and the connection closed after it.
    #[tokio::test(start_paused = true)]
    async fn session_end_closes_a_viewer_that_never_hangs_up() {
        let (viewer_socket, mut viewer) = duplex(64);
        let (server, relay_side) = duplex(64);
        drop(server);

        let session = drive_session(
            async { Ok(()) },
            rdp_ended(),
            relay(viewer_socket, relay_side),
        );
        timeout(RELAY_DRAIN_TIMEOUT * 2, session)
            .await
            .unwrap()
            .unwrap();

        let mut rest = Vec::new();
        viewer.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn control_loop_error_is_returned() {
        let (viewer_socket, _viewer) = duplex(64);
        let (_server, relay_side) = duplex(64);
        let (_done_tx, rdp_done) = oneshot::channel();

        let result = drive_session(
            async { Err(anyhow!("control loop failed")) },
            rdp_done,
            relay(viewer_socket, relay_side),
        )
        .await;
        assert!(result.is_err());
    }
}

/// A rejected sign-in, end to end through the real server state machine and a real RDP
/// client: the client must receive a refusal it can parse. Warpgate used to send one that
/// no client could read, which mstsc reported as "protocol error" 0xd06. The refusal now
/// comes from IronRDP's acceptor, which has no test of its own for it, so this pins it.
#[cfg(test)]
mod rejection_tests {
    use std::io;
    use std::pin::Pin;
    use std::sync::atomic::AtomicU32;
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll};
    use std::time::Duration;

    use ironrdp_connector as connector;
    use ironrdp_pdu::mcs::decode_send_data_indication;
    use ironrdp_pdu::rdp::headers::{IoChannelPdu, ShareDataPdu, decode_io_channel};
    use ironrdp_pdu::rdp::server_error_info::{
        ErrorInfo, ProtocolIndependentCode, ServerSetErrorInfoPdu,
    };
    use ironrdp_tokio::TokioFramed;
    use ironrdp_tokio::reqwest::ReqwestNetworkClient;
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::mpsc;
    use tokio::time::timeout;
    use warpgate_common::RdpTlsSecurity;

    use super::protocol::{AuthVerdict, Event, Input, Refusal};
    use super::rdp::run_on_thread;
    use crate::client::{test_connector_config, upgrade_tls};

    const DEADLINE: Duration = Duration::from_secs(30);

    /// A stream that keeps a copy of everything read from it.
    struct Recorder<S> {
        inner: S,
        seen: Arc<Mutex<Vec<u8>>>,
    }

    impl<S: AsyncRead + Unpin> AsyncRead for Recorder<S> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let before = buf.filled().len();
            let poll = Pin::new(&mut self.inner).poll_read(cx, buf);
            if let Poll::Ready(Ok(())) = poll {
                self.seen
                    .lock()
                    .unwrap()
                    .extend_from_slice(&buf.filled()[before..]);
            }
            poll
        }
    }

    impl<S: AsyncWrite + Unpin> AsyncWrite for Recorder<S> {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.inner).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    /// The RDP frames at the start of `bytes`, slow-path (TPKT) and fast-path alike, up to
    /// the first that is incomplete or unreadable.
    fn rdp_frames(mut bytes: &[u8]) -> Vec<&[u8]> {
        let mut frames = Vec::new();
        while let Ok(Some(info)) = ironrdp_pdu::find_size(bytes) {
            if info.length == 0 || info.length > bytes.len() {
                break;
            }
            let (frame, rest) = bytes.split_at(info.length);
            frames.push(frame);
            bytes = rest;
        }
        frames
    }

    /// Every Set Error Info PDU in `bytes` that a client's I/O-channel parser accepts.
    fn error_infos(bytes: &[u8]) -> Vec<ErrorInfo> {
        rdp_frames(bytes)
            .into_iter()
            .filter_map(|frame| {
                let indication = decode_send_data_indication(frame).ok()?;
                match decode_io_channel(indication).ok()? {
                    IoChannelPdu::Data(data) => match data.pdu {
                        ShareDataPdu::ServerSetErrorInfo(ServerSetErrorInfoPdu(info)) => Some(info),
                        _ => None,
                    },
                    _ => None,
                }
            })
            .collect()
    }

    /// The detector itself: it finds a framed refusal and ignores the bare four bytes
    /// Warpgate used to send, so the test below fails if those ever come back.
    #[test]
    fn error_infos_tells_a_framed_refusal_from_a_bare_one() {
        use ironrdp_core::encode_vec;
        use ironrdp_pdu::mcs::SendDataIndication;
        use ironrdp_pdu::rdp::client_info::CompressionType;
        use ironrdp_pdu::rdp::headers::{
            CompressionFlags, ShareControlHeader, ShareControlPdu, ShareDataHeader, StreamPriority,
        };
        use ironrdp_pdu::x224::X224;

        let refusal = ServerSetErrorInfoPdu(ErrorInfo::ProtocolIndependentCode(
            ProtocolIndependentCode::ServerInsufficientPrivileges,
        ));
        let frame = |user_data: Vec<u8>| {
            encode_vec(&X224(SendDataIndication {
                initiator_id: 1007,
                channel_id: 1003,
                user_data: user_data.into(),
            }))
            .unwrap()
        };

        let bare = frame(encode_vec(&refusal).unwrap());
        let framed = frame(
            encode_vec(&ShareControlHeader {
                share_control_pdu: ShareControlPdu::Data(ShareDataHeader {
                    share_data_pdu: ShareDataPdu::ServerSetErrorInfo(refusal.clone()),
                    stream_priority: StreamPriority::Undefined,
                    compression_flags: CompressionFlags::empty(),
                    compression_type: CompressionType::K8,
                }),
                pdu_source: 0,
                share_id: 0,
            })
            .unwrap(),
        );

        assert!(error_infos(&bare).is_empty());
        assert_eq!(error_infos(&framed), [refusal.0]);
    }

    #[tokio::test]
    async fn rejected_sign_in_reaches_the_client_as_a_readable_refusal() {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.signing_key.serialize_pem();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client_tcp = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (server_tcp, _) = listener.accept().await.unwrap();

        // Warpgate's side: the real server state machine, and a control loop that turns
        // every credential down, as it does a wrong password.
        let (out_tx, mut out_rx) = mpsc::unbounded_channel();
        let (_in_tx, in_rx) = mpsc::channel(16);
        let server_done = run_on_thread(
            server_tcp,
            cert_pem,
            key_pem,
            (1024, 768),
            out_tx,
            in_rx,
            Arc::new(AtomicU32::new(0)),
        );
        let control = tokio::spawn(async move {
            let mut asked = 0;
            while let Some(event) = out_rx.recv().await {
                if let Event::AuthRequest { reply, .. } = event {
                    asked += 1;
                    let _ = reply.send(AuthVerdict::Deny);
                }
            }
            asked
        });

        // The viewer's side: Warpgate's own IronRDP client configuration, over TLS only,
        // which is how mstsc reaches this listener. It advertises error-info support, as
        // mstsc does; without that the server would send no refusal at all.
        let client_addr = client_tcp.local_addr().unwrap();
        let mut framed = TokioFramed::new(client_tcp);
        let mut connector = connector::ClientConnector::new(
            test_connector_config("alice:target", "wrong password"),
            client_addr,
        );
        let should_upgrade = ironrdp_tokio::connect_begin(&mut framed, &mut connector)
            .await
            .unwrap();
        let (tls, server_public_key) = upgrade_tls(
            framed.into_inner_no_leftover(),
            "localhost".to_owned(),
            false,
            RdpTlsSecurity::Tls12,
        )
        .await
        .unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let mut framed = TokioFramed::new(Recorder {
            inner: tls,
            seen: Arc::clone(&seen),
        });
        let upgraded = ironrdp_tokio::mark_as_upgraded(should_upgrade, &mut connector);
        let outcome = timeout(
            DEADLINE,
            ironrdp_tokio::connect_finalize(
                upgraded,
                connector,
                &mut framed,
                &mut ReqwestNetworkClient::new(),
                "localhost".into(),
                server_public_key,
                None,
            ),
        )
        .await
        .expect("the handshake hung instead of ending");
        assert!(
            outcome
                .and_then(connector::ConnectionOutcome::into_connected)
                .is_err(),
            "a rejected sign-in must not connect"
        );
        drop(framed);

        let asked = timeout(DEADLINE, control).await.unwrap().unwrap();
        assert_eq!(
            asked, 1,
            "the server asks Warpgate about the credentials once"
        );
        let _ = timeout(DEADLINE, server_done).await;

        let seen = seen.lock().unwrap().clone();
        let refusals = error_infos(&seen);
        assert!(
            matches!(
                refusals.as_slice(),
                [ErrorInfo::ProtocolIndependentCode(
                    ProtocolIndependentCode::ServerInsufficientPrivileges
                        | ProtocolIndependentCode::ServerDeniedConnection
                )]
            ),
            "expected one readable refusal from the server, found {refusals:?} in {} bytes",
            seen.len()
        );
    }

    /// mstsc without a saved credential sends no password. The connection must not be
    /// refused for that during the handshake: the viewer gets a session, where Warpgate's
    /// sign-in screen asks for the password. And a refusal that comes over that session, as
    /// after the last wrong attempt, reaches the viewer as a reason it can read, not as a
    /// dropped connection (which mstsc reports as a network error).
    #[tokio::test]
    async fn a_viewer_without_a_password_gets_a_session_and_hears_why_it_ends() {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.signing_key.serialize_pem();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client_tcp = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (server_tcp, _) = listener.accept().await.unwrap();

        // Warpgate's side: the real server state machine, and a control loop that does what
        // the real one does with an empty password, starting the session for the sign-in
        // screen, and then refuses the viewer, as after its last wrong attempt.
        let (out_tx, mut out_rx) = mpsc::unbounded_channel();
        let (in_tx, in_rx) = mpsc::channel(16);
        let server_done = run_on_thread(
            server_tcp,
            cert_pem,
            key_pem,
            (1024, 768),
            out_tx,
            in_rx,
            Arc::new(AtomicU32::new(0)),
        );
        let control = tokio::spawn(async move {
            let mut passwords = Vec::new();
            while let Some(event) = out_rx.recv().await {
                if let Event::AuthRequest {
                    password, reply, ..
                } = event
                {
                    passwords.push(password);
                    let _ = reply.send(AuthVerdict::StartSession);
                    let _ = in_tx.send(Input::Disconnect(Refusal::Denied)).await;
                }
            }
            passwords
        });

        // The viewer's side, over TLS only as mstsc reaches this listener, with an empty
        // password as mstsc sends when it holds no saved credential.
        let client_addr = client_tcp.local_addr().unwrap();
        let mut framed = TokioFramed::new(client_tcp);
        let mut connector =
            connector::ClientConnector::new(test_connector_config("alice:target", ""), client_addr);
        let should_upgrade = ironrdp_tokio::connect_begin(&mut framed, &mut connector)
            .await
            .unwrap();
        let (tls, server_public_key) = upgrade_tls(
            framed.into_inner_no_leftover(),
            "localhost".to_owned(),
            false,
            RdpTlsSecurity::Tls12,
        )
        .await
        .unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let mut framed = TokioFramed::new(Recorder {
            inner: tls,
            seen: Arc::clone(&seen),
        });
        let upgraded = ironrdp_tokio::mark_as_upgraded(should_upgrade, &mut connector);
        let outcome = timeout(
            DEADLINE,
            ironrdp_tokio::connect_finalize(
                upgraded,
                connector,
                &mut framed,
                &mut ReqwestNetworkClient::new(),
                "localhost".into(),
                server_public_key,
                None,
            ),
        )
        .await
        .expect("the handshake hung instead of ending");
        assert!(
            outcome
                .and_then(connector::ConnectionOutcome::into_connected)
                .is_ok(),
            "a viewer without a password must get a session, for the sign-in screen"
        );

        // Then read what the server sends until it closes the connection.
        let _ = timeout(DEADLINE, async { while framed.read_pdu().await.is_ok() {} }).await;
        drop(framed);

        let passwords = timeout(DEADLINE, control).await.unwrap().unwrap();
        assert_eq!(
            passwords,
            [String::new()],
            "the server asks Warpgate about the credentials once"
        );
        let _ = timeout(DEADLINE, server_done).await;

        let seen = seen.lock().unwrap().clone();
        let refusals = error_infos(&seen);
        assert_eq!(
            refusals,
            [ErrorInfo::ProtocolIndependentCode(
                ProtocolIndependentCode::ServerInsufficientPrivileges
            )],
            "expected the refusal's reason, found {refusals:?} in {} bytes",
            seen.len()
        );
    }
}
