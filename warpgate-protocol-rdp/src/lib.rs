#![feature(once_cell_try)]
//! In-workspace RDP integration for Warpgate.
//!
//! [`client`] drives IronRDP against a target host; [`server`] runs IronRDP's server state
//! machine for native RDP viewers (mstsc/FreeRDP) connecting to Warpgate's RDP port. Both
//! speak the shared [`DesktopEvent`]/[`DesktopInput`] streams, so the web-desktop manager
//! and browser canvas renderer work against either front end unchanged.

mod client;
mod clipboard;
mod desktop_size;
mod server;
mod session_handle;

use std::sync::Arc;

use anyhow::Context;
use futures::future::BoxFuture;
pub use server::bind_server;
use tokio::sync::mpsc::{channel, unbounded_channel};
use tracing::{Instrument, error, info, info_span, warn};
use warpgate_common::{ListenEndpoint, Protocol, SecretResolver, TargetRdpOptions, WarpgateError};
use warpgate_core::rdp_account::{AuthorizedSignIn, managed_logon_identity};
use warpgate_core::{
    AdmittedTarget, DESKTOP_INPUT_CHANNEL_CAPACITY, DesktopClientHandles, DesktopEvent,
    DesktopInput, DesktopState, LogonState, ProtocolServer, Services,
};
use warpgate_tls::TlsCertificateAndPrivateKey;

use crate::client::LogonWatcher;

pub const PROTOCOL_NAME: Protocol = Protocol::Rdp;

pub use warpgate_desktop_ui::DEFAULT_SIZE;

/// Depth of the target client's event channel. Small, because a slot is the client's only
/// signal that the viewer side wants more: while the channel is full, the client keeps
/// reading the target and merges what changes into what it sends next (see
/// `client::damage`), so a deeper queue would only hold older pixels, and more memory —
/// each event can be a whole-desktop image.
const EVENT_CHANNEL_CAPACITY: usize = 2;

/// The native RDP server endpoint. Standard RDP clients (mstsc/FreeRDP) connect
/// directly to Warpgate's RDP port; per connection it brokers between the viewer-facing
/// RDP server and a target-facing client (see [`server`]).
pub struct RdpProtocolServer {
    services: Services,
}

impl RdpProtocolServer {
    pub fn new(services: &Services) -> Self {
        Self {
            services: services.clone(),
        }
    }
}

impl ProtocolServer for RdpProtocolServer {
    async fn bind(
        self,
        address: ListenEndpoint,
        proxy_protocol: bool,
        tls: Vec<TlsCertificateAndPrivateKey>,
    ) -> anyhow::Result<BoxFuture<'static, anyhow::Result<()>>> {
        let certificate_and_key = tls
            .into_iter()
            .next()
            .context("RDP requires a TLS certificate and key")?;
        let cert_pem = String::from_utf8(certificate_and_key.certificate.bytes().to_vec())
            .context("RDP TLS certificate is not valid UTF-8 PEM")?;
        let key_pem = String::from_utf8(certificate_and_key.private_key.bytes().to_vec())
            .context("RDP TLS private key is not valid UTF-8 PEM")?;
        bind_server(self.services, address, proxy_protocol, cert_pem, key_pem).await
    }

    fn name(&self) -> &'static str {
        "RDP"
    }
}

impl std::fmt::Debug for RdpProtocolServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RdpProtocolServer").finish()
    }
}

/// Start an RDP client for a target and bridge it to normalised desktop streams.
///
/// `sign_in` is what the target is signed in to with, decided for the admitted user by
/// [`warpgate_core::rdp_account`]: the target's stored credential, or an account the user may
/// use (their own directory account, or one assigned to them) with the password they typed.
pub fn connect(
    admitted: AdmittedTarget<TargetRdpOptions>,
    size: (u16, u16),
    secrets: Arc<dyn SecretResolver>,
    sign_in: AuthorizedSignIn,
) -> Result<DesktopClientHandles, WarpgateError> {
    connect_with_keyboard_layout(admitted, size, secrets, 0, sign_in)
}

/// [`connect`], telling the target the viewer's keyboard layout: a Windows KLID such as
/// `0x0000_0409`, or `0` for the target's own default. A native RDP viewer sends keys as
/// scancodes, which the target turns into characters with this layout, so a viewer whose
/// layout the target is told types what its keycaps say, as over a direct connection.
pub fn connect_with_keyboard_layout(
    admitted: AdmittedTarget<TargetRdpOptions>,
    size: (u16, u16),
    secrets: Arc<dyn SecretResolver>,
    keyboard_layout: u32,
    sign_in: AuthorizedSignIn,
) -> Result<DesktopClientHandles, WarpgateError> {
    let target_session_id = admitted.id();
    let (user_info, target) = admitted.into_approved().into_parts();
    let (target, options) = target.into_parts();

    // The sign-in was decided for this user and this target: checked here, where both the
    // browser and the native client connect, so neither can hand the client one decided for
    // someone else, or for another target.
    if sign_in.user_id() != user_info.id || sign_in.target_id() != target.id {
        warn!(
            user = %user_info.username,
            target = %target.name,
            "Refused a sign-in decided for another user or target"
        );
        return Err(WarpgateError::InvalidRequest(
            "The account is not yours to sign in to this target with".into(),
        ));
    }
    let typed_password = sign_in.credentials().is_some();
    // The account the session must log on as: the one Warpgate signs in with.
    let allowed = match sign_in.credentials() {
        Some(credentials) => Some(credentials.identity().clone()),
        None => managed_logon_identity(&options),
    };
    // Who the target is signed in to as, next to who is signing in, for the audit log.
    info!(
        user = %user_info.username,
        target = %target.name,
        sign_in = sign_in.kind().as_str(),
        target_account = %sign_in.account(),
        binding_id = ?sign_in.binding_id(),
        "Connecting to the RDP target"
    );
    let credentials = sign_in.into_credentials();
    let (event_tx, event_rx) = channel::<DesktopEvent>(EVENT_CHANNEL_CAPACITY);
    let (input_tx, input_rx) = channel::<DesktopInput>(DESKTOP_INPUT_CHANNEL_CAPACITY);
    let (abort_tx, abort_rx) = unbounded_channel::<()>();

    // Autologon passes the credentials over CredSSP, so the session is logged on by the
    // time it is active; only an interactive-logon target starts at its sign-in screen. So
    // does one signed in with a password the user typed: should the target show its own
    // sign-in screen anyway, what is typed there is the user's password, which the
    // recording must not keep, until the target reports the logon.
    let sign_in = if options.interactive_logon || typed_password {
        LogonState::at_logon_screen()
    } else {
        LogonState::logged_on()
    };
    let logon = LogonWatcher {
        target_session_id,
        target_id: target.id,
        target_name: target.name,
        user_id: user_info.id,
        username: user_info.username,
        sign_in: sign_in.clone(),
        allowed,
    };

    let span = info_span!("RDP-client", host = %options.host, port = options.port);
    tokio::spawn(
        async move {
            if let Err(error) = client::run(
                options,
                size,
                keyboard_layout,
                event_tx.clone(),
                input_rx,
                abort_rx,
                logon,
                secrets,
                credentials,
            )
            .await
            {
                let error = Arc::new(error);
                let _ = event_tx.send(DesktopEvent::Error(error.clone())).await;
                error!("RDP client failed: {:#}", anyhow::Error::from(error));
            }
            let _ = event_tx
                .send(DesktopEvent::State(DesktopState::Disconnected))
                .await;
        }
        .instrument(span),
    );

    Ok(DesktopClientHandles {
        event_rx,
        input_tx,
        abort_tx,
        logon_state: sign_in,
    })
}
