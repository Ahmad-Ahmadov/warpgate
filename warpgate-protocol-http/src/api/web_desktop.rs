use std::sync::Arc;

use poem::Request;
use poem::session::Session;
use poem::web::{Data, RemoteAddr};
use poem_openapi::param::Path;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use tracing::warn;
use uuid::Uuid;
use warpgate_common::{Secret, TargetOptions, TargetRdpOptions, UserSessionId, WarpgateError};
use warpgate_core::domain_account::{
    DomainCredentials, MAX_DOMAIN_PASSWORD_CHARS, Zeroizing, find_domain_account,
    uses_domain_account, verify_domain_password,
};
use warpgate_core::{Services, TargetAuthorization};
use warpgate_web_desktop::WebDesktopClientManager;

use crate::api::auth_scheme::AuthedSession;
use crate::api::common::{WebClientTargetAccess, authorize_web_client_target};
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
    /// The user's own domain password, for a target that signs in with the user's domain
    /// account (see `get_web_desktop_target_account`). Checked with the directory, used for
    /// this one connection and never stored. Ignored for any other target.
    domain_password: Option<Secret<String>>,
}

/// How the user signs in to a desktop target, asked before connecting to it.
#[derive(Object)]
struct WebDesktopTargetAccount {
    /// The target signs in with the user's own domain account, so connecting to it takes
    /// the user's domain password.
    domain_account: bool,
    /// The account the target is signed in to, as `DOMAIN\user` or `user@domain`, when
    /// `domain_account` is set and the directory has one for the user.
    username: Option<String>,
    /// Why the user cannot sign in to the target with a domain account, when they cannot.
    problem: Option<String>,
}

#[derive(ApiResponse)]
enum GetWebDesktopTargetAccountResponse {
    #[oai(status = 200)]
    Ok(Json<WebDesktopTargetAccount>),
    #[oai(status = 401)]
    ReauthRequired,
    #[oai(status = 403)]
    Forbidden,
    #[oai(status = 404)]
    NotFound,
}

/// The RDP options of a target that signs in with the user's own domain account.
fn domain_account_options(authorization: &TargetAuthorization) -> Option<&TargetRdpOptions> {
    match authorization.options() {
        TargetOptions::Rdp(options) if uses_domain_account(options) => Some(options),
        _ => None,
    }
}

/// Check the domain password the user sent for a target that signs in with their own domain
/// account. The account is the one the authenticated user is linked to in the directory,
/// never one the request names. A refusal is a 400 with the directory's reason, which is the
/// user's own business (their password, their account).
async fn check_domain_password(
    services: &Services,
    authorization: &TargetAuthorization,
    options: &TargetRdpOptions,
    password: Option<Secret<String>>,
) -> Result<DomainCredentials, WarpgateError> {
    let password = Zeroizing::new(
        password
            .map(Secret::into_secret)
            .filter(|password| !password.is_empty())
            .ok_or_else(|| {
                WarpgateError::InvalidRequest(
                    "Enter your domain password to connect to this target".into(),
                )
            })?,
    );
    if password.chars().count() > MAX_DOMAIN_PASSWORD_CHARS {
        return Err(WarpgateError::InvalidRequest(
            "The domain password is too long".into(),
        ));
    }
    verify_domain_password(
        &services.db,
        authorization.user_info().id,
        options,
        password,
    )
    .await
    .map_err(|error| WarpgateError::InvalidRequest(error.user_message().into()))
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
            domain_password,
        }) = body;
        let services = ctx.services();
        let manager = manager.0;
        let remote_addr = remote_addr.0.as_socket_addr().copied();
        // The password is checked only once the user is authorized for the target, and
        // dropped unread for a target that does not sign in with it.
        create_web_client_session(&ctx, session, target_id, move |authorization| async move {
            let domain_credentials = match domain_account_options(&authorization) {
                Some(options) => Some(
                    check_domain_password(services, &authorization, options, domain_password)
                        .await?,
                ),
                None => None,
            };
            manager
                .create_session(
                    services,
                    authorization,
                    remote_addr,
                    width.zip(height),
                    domain_credentials,
                )
                .await
        })
        .await
    }

    /// Whether connecting to a desktop target takes the user's own domain password, and
    /// which account it signs in as: for the browser to ask for the password, with the
    /// account filled in, before it starts the session. Authorized as starting one is.
    #[oai(
        path = "/web-desktop/targets/:target_id/account",
        method = "get",
        operation_id = "get_web_desktop_target_account"
    )]
    async fn api_get_web_desktop_target_account(
        &self,
        session: &Session,
        ctx: AuthedSession,
        Path(target_id): Path<Uuid>,
    ) -> poem::Result<GetWebDesktopTargetAccountResponse> {
        let authorization = match authorize_web_client_target(&ctx, session, target_id).await? {
            WebClientTargetAccess::Authorized(authorization) => authorization,
            WebClientTargetAccess::ReauthRequired => {
                return Ok(GetWebDesktopTargetAccountResponse::ReauthRequired);
            }
            WebClientTargetAccess::Forbidden => {
                return Ok(GetWebDesktopTargetAccountResponse::Forbidden);
            }
            WebClientTargetAccess::NotFound => {
                return Ok(GetWebDesktopTargetAccountResponse::NotFound);
            }
        };
        let Some(options) = domain_account_options(&authorization) else {
            return Ok(GetWebDesktopTargetAccountResponse::Ok(Json(
                WebDesktopTargetAccount {
                    domain_account: false,
                    username: None,
                    problem: None,
                },
            )));
        };
        let user_id = authorization.user_info().id;
        let account = match find_domain_account(&ctx.services().db, user_id, options).await {
            Ok(account) => WebDesktopTargetAccount {
                domain_account: true,
                username: Some(account.display_name()),
                problem: None,
            },
            Err(error) => {
                warn!(%user_id, %error, "No domain account to sign in to the target with");
                WebDesktopTargetAccount {
                    domain_account: true,
                    username: None,
                    problem: Some(error.user_message().into()),
                }
            }
        };
        Ok(GetWebDesktopTargetAccountResponse::Ok(Json(account)))
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
