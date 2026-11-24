use std::sync::Arc;

use poem::Request;
use poem::session::Session;
use poem::web::{Data, RemoteAddr};
use poem_openapi::param::Path;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use tracing::warn;
use uuid::Uuid;
use warpgate_common::{TargetOptions, UserSessionId};
use warpgate_core::account_binding::{BindingChoice, BoundUser, TargetAccountKind, ssh_accounts};
use warpgate_core::rdp_account::{SignInKind, plan_sign_in};
use warpgate_web_ssh::WebSshClientManager;

use crate::api::auth_scheme::AuthedSession;
use crate::api::common::{WebClientTargetAccess, authorize_web_client_target};
use crate::api::web_clients::{
    CreateWebClientSessionResponse, DeleteWebClientSessionResponse, GetWebClientSessionResponse,
    create_web_client_session, delete_web_client_session, get_web_client_session,
};

pub struct Api;

#[derive(Object)]
struct CreateWebSshSessionBody {
    target_id: Uuid,
    /// The account to sign in as, among those assigned to the user on the target (see
    /// `get_target_accounts`): only ever one of their own. Without it, the only one, or the
    /// first of several.
    account_binding_id: Option<Uuid>,
}

/// An account the signed-in user may connect to a target as.
#[derive(Object)]
struct TargetAccount {
    /// The assignment it comes from (Access Control); absent for the target's own setup.
    binding_id: Option<Uuid>,
    /// The account, as the target is signed in to with it.
    account: String,
    kind: TargetAccountKind,
}

#[derive(ApiResponse)]
enum GetTargetAccountsResponse {
    /// The accounts, in the order they were assigned. Empty for an SSH target the user signs
    /// in to as it is set up.
    #[oai(status = 200)]
    Ok(Json<Vec<TargetAccount>>),
    /// The user has no account to use on the target, and why.
    #[oai(status = 400)]
    NoAccount(Json<String>),
    #[oai(status = 401)]
    ReauthRequired,
    #[oai(status = 403)]
    Forbidden,
    #[oai(status = 404)]
    NotFound,
}

const fn account_kind(kind: SignInKind) -> TargetAccountKind {
    match kind {
        SignInKind::Managed => TargetAccountKind::Managed,
        SignInKind::DomainAccount => TargetAccountKind::Directory,
        SignInKind::LocalAccount => TargetAccountKind::Local,
    }
}

#[OpenApi]
impl Api {
    /// The accounts the signed-in user may connect to a target as: their own assignments
    /// there, or the target's own setup. Authorized as starting a session is, and only ever
    /// about the user's own accounts.
    #[oai(
        path = "/targets/:target_id/accounts",
        method = "get",
        operation_id = "get_target_accounts"
    )]
    async fn api_get_target_accounts(
        &self,
        session: &Session,
        ctx: AuthedSession,
        Path(target_id): Path<Uuid>,
    ) -> poem::Result<GetTargetAccountsResponse> {
        let authorization = match authorize_web_client_target(&ctx, session, target_id).await? {
            WebClientTargetAccess::Authorized(authorization) => authorization,
            WebClientTargetAccess::ReauthRequired => {
                return Ok(GetTargetAccountsResponse::ReauthRequired);
            }
            WebClientTargetAccess::Forbidden => return Ok(GetTargetAccountsResponse::Forbidden),
            WebClientTargetAccess::NotFound => return Ok(GetTargetAccountsResponse::NotFound),
        };
        let db = &ctx.services().db;
        let user_info = authorization.user_info();
        let target = authorization.target();
        let user = BoundUser {
            id: user_info.id,
            username: &user_info.username,
        };
        let accounts = match authorization.options() {
            TargetOptions::Ssh(options) => ssh_accounts(db, user, target.id, &target.name, options)
                .await
                .map(|accounts| {
                    accounts
                        .into_iter()
                        .map(|account| TargetAccount {
                            binding_id: Some(account.binding_id),
                            account: account.username,
                            kind: account.kind,
                        })
                        .collect()
                })
                .map_err(|error| error.user_message()),
            TargetOptions::Rdp(options) => plan_sign_in(db, user, target.id, &target.name, options)
                .await
                .map(|plan| {
                    plan.choices()
                        .iter()
                        .map(|choice| TargetAccount {
                            binding_id: choice.binding_id,
                            account: choice.label(),
                            kind: account_kind(choice.kind),
                        })
                        .collect()
                })
                .map_err(|error| error.user_message()),
            _ => Ok(vec![]),
        };
        Ok(match accounts {
            Ok(accounts) => GetTargetAccountsResponse::Ok(Json(accounts)),
            Err(message) => {
                warn!(user = %user.username, target = %target.name, message, "No account to connect to the target with");
                GetTargetAccountsResponse::NoAccount(Json(message.to_owned()))
            }
        })
    }

    #[oai(
        path = "/web-ssh/sessions",
        method = "post",
        operation_id = "create_web_ssh_session"
    )]
    async fn api_create_web_ssh_session(
        &self,
        remote_addr: &RemoteAddr,
        session: &Session,
        ctx: AuthedSession,
        body: Json<CreateWebSshSessionBody>,
        manager: Data<&Arc<WebSshClientManager>>,
    ) -> poem::Result<CreateWebClientSessionResponse> {
        let account = body
            .account_binding_id
            .map_or(BindingChoice::First, BindingChoice::Id);
        create_web_client_session(&ctx, session, body.target_id, |authorization| {
            manager.create_session(
                ctx.services(),
                authorization,
                remote_addr.0.as_socket_addr().copied(),
                account,
            )
        })
        .await
    }

    #[oai(
        path = "/web-ssh/sessions/:session_id",
        method = "get",
        operation_id = "get_web_ssh_session"
    )]
    async fn api_get_web_ssh_session(
        &self,
        ctx: AuthedSession,
        req: &Request,
        Path(session_id): Path<UserSessionId>,
        manager: Data<&Arc<WebSshClientManager>>,
    ) -> poem::Result<GetWebClientSessionResponse> {
        get_web_client_session(&ctx, req, session_id, &manager).await
    }

    #[oai(
        path = "/web-ssh/sessions/:session_id",
        method = "delete",
        operation_id = "delete_web_ssh_session"
    )]
    async fn api_delete_web_ssh_session(
        &self,
        ctx: AuthedSession,
        req: &Request,
        Path(session_id): Path<UserSessionId>,
        manager: Data<&Arc<WebSshClientManager>>,
    ) -> poem::Result<DeleteWebClientSessionResponse> {
        delete_web_client_session(&ctx, req, session_id, &manager).await
    }
}
