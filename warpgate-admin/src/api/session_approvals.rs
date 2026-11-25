use poem::web::Data;
use poem::web::websocket::WebSocket;
use poem::{IntoResponse, handler};
use poem_openapi::param::Path;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder};
use time::OffsetDateTime;
use warpgate_common::auth::ApprovalKind;
use warpgate_common::{AdminPermission, RuleApproval, UserSessionId, WarpgateError};
use warpgate_common_http::AuthenticatedRequestContext;
use warpgate_core::access_policy::approver_allowed;
use warpgate_core::approvals::{ApprovalDecision, ApprovalScope};
use warpgate_core::cluster::{ClusterNotification, refresh_notification_stream};
use warpgate_db_entities::{AccessApprovalContext, Parameters, Role, SessionApprovalRequest, User};

use super::AdminContext;
use crate::api::common::require_admin_permission;
use crate::approvals::{Approver, find_pending_approval, resolve_pending_approval};

pub struct Api;

#[derive(Object)]
struct SessionApprovalItem {
    id: String,
    protocol: String,
    address: Option<String>,
    username: String,
    target: String,
    started: OffsetDateTime,
    caching_grace_seconds: Option<i64>,
    /// The access policy that asked for this approval, when one did.
    policy_name: Option<String>,
    /// Why approval is required.
    reason: Option<String>,
    /// The account the approval is for.
    account: Option<String>,
    /// When the request lapses unanswered; an approver cannot approve it after.
    expires_at: Option<OffsetDateTime>,
    /// How long an approval can start a connection once it is given.
    valid_for_seconds: Option<i64>,
    /// Who may approve it, when the policy names approvers.
    approvers: Option<String>,
    /// Whether the administrator asking may approve it.
    can_approve: bool,
}

/// The approvers a policy names, in words.
async fn describe_approvers(
    db: &DatabaseConnection,
    constraints: &[RuleApproval],
) -> Result<Option<String>, WarpgateError> {
    let mut parts: Vec<String> = vec![];
    for constraint in constraints {
        let mut names: Vec<String> = vec![];
        for id in &constraint.approver_user_ids {
            if let Some(user) = User::Entity::find_by_id(*id).one(db).await? {
                names.push(user.username);
            }
        }
        for id in &constraint.approver_role_ids {
            if let Some(role) = Role::Entity::find_by_id(*id).one(db).await? {
                names.push(format!("group {}", role.name));
            }
        }
        if !names.is_empty() {
            parts.push(names.join(", "));
        }
    }
    Ok((!parts.is_empty()).then(|| parts.join(" and ")))
}

#[derive(ApiResponse)]
enum ListResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<SessionApprovalItem>>),
}

#[derive(ApiResponse)]
enum ActionResponse {
    #[oai(status = 200)]
    Ok,
    #[oai(status = 404)]
    NotFound,
}

#[derive(Object)]
struct ApproveSessionRequest {
    scope: ApprovalScope,
    target: String,
}

#[derive(Object)]
struct RejectSessionRequest {
    target: String,
}

async fn resolve_inner(
    ctx: &AuthenticatedRequestContext,
    session_id: UserSessionId,
    target: &str, // target seen by the approval to ensure no TOCTOU
    decision: ApprovalDecision,
) -> poem::Result<ActionResponse> {
    let Some(pending) = find_pending_approval(ctx, session_id, ApprovalKind::Admin, target).await?
    else {
        return Ok(ActionResponse::NotFound);
    };

    if resolve_pending_approval(ctx, Approver::Administrator, pending, decision).await? {
        Ok(ActionResponse::Ok)
    } else {
        Ok(ActionResponse::NotFound)
    }
}

#[OpenApi]
impl Api {
    #[oai(
        path = "/session-approvals",
        method = "get",
        operation_id = "get_session_approvals"
    )]
    async fn api_list(&self, admin: AdminContext) -> poem::Result<ListResponse> {
        admin.require(AdminPermission::ApproveSessions)?;

        use SessionApprovalRequest as SAR;

        let requests = SAR::Entity::find()
            .filter(SAR::Column::Kind.eq(ApprovalKind::Admin))
            .filter(SAR::Column::Status.eq(SAR::ApprovalRequestStatus::Pending))
            .order_by_asc(SAR::Column::Started)
            .all(&admin.services().db)
            .await
            .map_err(WarpgateError::from)?;

        let caching_grace_seconds = Parameters::Entity::get(&admin.services().db)
            .await
            .map_err(WarpgateError::from)?
            .admin_approval_grace_period_seconds;

        let db = &admin.services().db;
        let now = OffsetDateTime::now_utc();
        let asking = admin.auth.user_id();
        let mut items = Vec::with_capacity(requests.len());
        for r in requests {
            let context =
                AccessApprovalContext::find(db, r.session_id, ApprovalKind::Admin, &r.target)
                    .await
                    .map_err(WarpgateError::from)?;
            // A request that has gone unanswered past its expiry can no longer be approved;
            // it is closed when its connection next looks, but is not offered meanwhile.
            if context
                .as_ref()
                .is_some_and(|context| context.expires_at <= now)
            {
                continue;
            }
            let (
                policy_name,
                reason,
                account,
                expires_at,
                valid_for_seconds,
                approvers,
                can_approve,
            ) = match &context {
                Some(context) => {
                    let constraints = context.approver_constraints();
                    let allowed = r.user_id != asking
                        && approver_allowed(db, &constraints, asking)
                            .await
                            .map_err(WarpgateError::from)?;
                    (
                        Some(context.policy_name.clone()),
                        Some(context.reason.clone()),
                        context.account_name.clone(),
                        Some(context.expires_at),
                        Some(context.valid_for_seconds),
                        describe_approvers(db, &constraints).await?,
                        allowed,
                    )
                }
                None => (None, None, None, None, None, None, true),
            };
            items.push(SessionApprovalItem {
                id: r.session_id.to_string(),
                protocol: r.protocol,
                address: r.remote_address,
                username: r.username,
                target: r.target,
                started: r.started,
                caching_grace_seconds,
                policy_name,
                reason,
                account,
                expires_at,
                valid_for_seconds,
                approvers,
                can_approve,
            });
        }
        Ok(ListResponse::Ok(Json(items)))
    }

    #[oai(
        path = "/session-approvals/:id/approve",
        method = "post",
        operation_id = "approve_session"
    )]
    async fn api_approve(
        &self,
        admin: AdminContext,
        Path(id): Path<UserSessionId>,
        body: Json<ApproveSessionRequest>,
    ) -> poem::Result<ActionResponse> {
        admin.require(AdminPermission::ApproveSessions)?;
        resolve_inner(
            &admin,
            id,
            &body.target,
            ApprovalDecision::Approved(body.scope),
        )
        .await
    }

    #[oai(
        path = "/session-approvals/:id/reject",
        method = "post",
        operation_id = "reject_session"
    )]
    async fn api_reject(
        &self,
        admin: AdminContext,
        Path(id): Path<UserSessionId>,
        body: Json<RejectSessionRequest>,
    ) -> poem::Result<ActionResponse> {
        admin.require(AdminPermission::ApproveSessions)?;
        resolve_inner(&admin, id, &body.target, ApprovalDecision::Rejected).await
    }
}

#[handler]
pub async fn api_get_session_approvals_stream(
    ctx: Data<&AuthenticatedRequestContext>,
    ws: WebSocket,
) -> Result<impl IntoResponse, WarpgateError> {
    require_admin_permission(&ctx, Some(AdminPermission::ApproveSessions)).await?;
    Ok(refresh_notification_stream(
        ws,
        ctx.services().cluster.subscribe(),
        |msg| matches!(msg, ClusterNotification::SessionApprovalsChanged).then(String::new),
    ))
}
