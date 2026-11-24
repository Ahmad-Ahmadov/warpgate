use std::sync::Arc;

use poem::Request;
use poem::session::Session;
use poem::web::{Data, RemoteAddr};
use poem_openapi::param::Path;
use poem_openapi::payload::Json;
use poem_openapi::{Object, OpenApi};
use tracing::warn;
use uuid::Uuid;
use warpgate_common::{TargetOptions, UserSessionId, WarpgateError};
use warpgate_core::access_control::ConnectingUser;
use warpgate_core::rdp_account::plan_sign_in;
use warpgate_web_desktop::WebDesktopClientManager;

use crate::api::auth_scheme::AuthedSession;
use crate::api::web_clients::{
    CreateWebClientSessionResponse, DeleteWebClientSessionResponse, GetWebClientSessionResponse,
    create_web_client_session, delete_web_client_session, get_web_client_session,
};

pub struct Api;

#[derive(Object)]
struct CreateWebDesktopSessionBody {
    target_id: Uuid,
    /// Initial desktop resolution to request from the target, measured by the browser.
    /// Both must be present to take effect; otherwise a default is used.
    width: Option<u16>,
    height: Option<u16>,
}

#[OpenApi]
impl Api {
    #[oai(
        path = "/web-desktop/sessions",
        method = "post",
        operation_id = "create_web_desktop_session"
    )]
    async fn api_create_web_desktop_session(
        &self,
        remote_addr: &RemoteAddr,
        session: &Session,
        ctx: AuthedSession,
        body: Json<CreateWebDesktopSessionBody>,
        manager: Data<&Arc<WebDesktopClientManager>>,
    ) -> poem::Result<CreateWebClientSessionResponse> {
        let Json(CreateWebDesktopSessionBody {
            target_id,
            width,
            height,
        }) = body;
        let services = ctx.services();
        let manager = manager.0;
        let remote_addr = remote_addr.0.as_socket_addr().copied();
        create_web_client_session(&ctx, session, target_id, move |authorization| async move {
            // Who the user signs in to an RDP target as, settled for the authorized user
            // before an approval is asked for: one with no account Access Control lets them
            // use there is told so now. A password, where the account takes one, is asked
            // for over the session's stream once it is approved.
            let sign_in = match authorization.options() {
                TargetOptions::Rdp(_) => {
                    let user_info = authorization.user_info();
                    let target = authorization.target();
                    let user = ConnectingUser {
                        id: user_info.id,
                        username: &user_info.username,
                    };
                    Some(
                        plan_sign_in(
                            &services.db,
                            user,
                            target.id,
                            &target.name,
                            authorization.ticket_id().is_some(),
                        )
                        .await
                            .map_err(|error| {
                                warn!(user_id = %user.id, %error, "No account to sign in to the target with");
                                WarpgateError::InvalidRequest(error.user_message().into())
                            })?,
                    )
                }
                _ => None,
            };
            manager
                .create_session(
                    services,
                    authorization,
                    remote_addr,
                    width.zip(height),
                    sign_in,
                )
                .await
        })
        .await
    }

    #[oai(
        path = "/web-desktop/sessions/:session_id",
        method = "get",
        operation_id = "get_web_desktop_session"
    )]
    async fn api_get_web_desktop_session(
        &self,
        ctx: AuthedSession,
        req: &Request,
        Path(session_id): Path<UserSessionId>,
        manager: Data<&Arc<WebDesktopClientManager>>,
    ) -> poem::Result<GetWebClientSessionResponse> {
        get_web_client_session(&ctx, req, session_id, &manager).await
    }

    #[oai(
        path = "/web-desktop/sessions/:session_id",
        method = "delete",
        operation_id = "delete_web_desktop_session"
    )]
    async fn api_delete_web_desktop_session(
        &self,
        ctx: AuthedSession,
        req: &Request,
        Path(session_id): Path<UserSessionId>,
        manager: Data<&Arc<WebDesktopClientManager>>,
    ) -> poem::Result<DeleteWebClientSessionResponse> {
        delete_web_client_session(&ctx, req, session_id, &manager).await
    }
}
