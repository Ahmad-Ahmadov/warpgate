//! Messages exchanged between the viewer-facing RDP server task and the Warpgate
//! session that owns authentication, recording and the target connection.

use bytes::Bytes;
use tokio::sync::oneshot;
use warpgate_core::DesktopInput;

/// Warpgate's verdict on a viewer's credentials, returned through the
/// [`Event::AuthRequest`] reply channel.
pub enum AuthVerdict {
    /// Let the RDP session start: the password check passed, or the viewer sent no password
    /// and is to sign in on Warpgate's sign-in screen. Any second factor and the target's
    /// authorization — and, without a password, the sign-in itself — are still to come over
    /// the session; this only lets the connection sequence finish, and must not be read as
    /// "authorized".
    StartSession,
    /// Reject the credential; the session does not start.
    Deny,
}

/// Warpgate → RDP server: framebuffer updates (raw BGRA) and resize / shutdown control.
pub enum Input {
    Frame {
        x: u16,
        y: u16,
        width: u16,
        height: u16,
        data: Bytes,
    },
    Resize {
        width: u16,
        height: u16,
    },
    /// The target's cursor shape: BGRA pixels, top row first, with the hotspot inside them.
    Cursor {
        hotspot_x: u16,
        hotspot_y: u16,
        width: u16,
        height: u16,
        data: Bytes,
    },
    CursorDefault,
    CursorHidden,
    Clipboard(String),
    /// The target is connected: the frames that follow are its desktop rather than
    /// Warpgate's own screens, and may wait while the viewer is minimised. Warpgate's
    /// screens never do, since the sign-in and its second factor must go on meanwhile.
    TargetConnected,
    Shutdown,
    /// End the session and tell the viewer why. For a refusal after the viewer's session
    /// has started — on the sign-in screen, at a second factor, at an administrator's
    /// approval — where a plain close would reach it as a dropped connection (mstsc: a
    /// network error) rather than as a refusal.
    Disconnect(Refusal),
}

/// Why Warpgate ends a viewer's session itself. The viewer is sent the matching Set Error
/// Info PDU (MS-RDPBCGR 2.2.5.1.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// Sign-in or the second factor failed, or the user may not use the target.
    Denied,
    /// An administrator did not approve the session.
    NotApproved,
    /// The viewer did not sign in in time.
    TimedOut,
}

/// RDP server → Warpgate: viewer credentials and input. The viewer's domain is discarded —
/// Warpgate resolves the target's domain from the auth selector.
///
/// The session ends by this channel closing; the server's own outcome comes back as the
/// result of [`super::rdp::run_on_thread`].
pub enum Event {
    AuthRequest {
        username: String,
        password: String,
        /// The credential validator awaits its verdict here. Carrying the reply channel in
        /// the request keeps request and response correlated by construction; dropping this
        /// sender — the control loop ending, or declining to answer a duplicate — resolves as
        /// a rejection rather than hanging the server on a reply that never comes.
        reply: oneshot::Sender<AuthVerdict>,
    },
    /// The desktop size settled with the viewer. Sent once the capability exchange
    /// completes, and again after every renegotiation, so Warpgate can paint and dial
    /// the target at the size the viewer is actually showing.
    Size {
        width: u16,
        height: u16,
    },
    /// The viewer requested a dynamic desktop resize over the Display Control channel.
    /// This is distinct from [`Self::Size`]: it is a request to resize the target, not a
    /// signal that Warpgate should start painting at the new size.
    ResizeRequest {
        width: u16,
        height: u16,
    },
    Input(DesktopInput),
    /// The viewer's lock keys, from its Synchronize event: mstsc sends one when the session
    /// starts and whenever its window regains focus. Only the sign-in screen reads it, to
    /// type what the keycaps say; the target keeps its own lock state.
    KeyboardSync {
        caps_lock: bool,
        num_lock: bool,
    },
}
