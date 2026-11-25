//! Access policies: schedules and approval rules for connections, and the history of the
//! approvals they asked for.
//!
//! * **Policies** (`/access-policies`, needs `AccessRolesAssign`): who may connect when. A
//!   policy covers a user, an access group, a target, or a pair of them, and only ever
//!   restricts: it never grants access (that is an assignment's job). How several combine is
//!   documented in `warpgate_core::access_policy`. A direct assignment's own schedule is a
//!   policy too, but it is edited with the assignment, not here.
//! * **Approvals** (`/access-approvals`, needs `ApproveSessions`): the approval requests that
//!   policies asked for, with what became of each: pending, approved, rejected, expired or used.
//!   They are the same requests as `/session-approvals`, decided in the same place.
//!
//! The server evaluates and enforces everything; nothing here trusts a time, a status or a
//! decision the browser sends. Every change is audited.

use std::collections::HashMap;

use poem_openapi::param::Path;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use sea_orm::{DatabaseConnection, EntityTrait, QueryOrder, QuerySelect};
use time::OffsetDateTime;
use uuid::Uuid;
use warpgate_common::audit::AuditEvent;
use warpgate_common::auth::ApprovalKind;
use warpgate_common::{AccessRules, AdminPermission, RuleAction, WarpgateError};
use warpgate_core::access_policy::{
    self, AccessApprovalStatus, PolicyData, PolicyError, PolicyScope, approval_status,
};
use warpgate_db_entities::{
    AccessApprovalContext, AccessPolicy, Role, SessionApprovalRequest, Target, TargetAccount, User,
};

use super::AdminContext;

// ---------------------------------------------------------------------------------------
// Presentation
// ---------------------------------------------------------------------------------------

/// An access policy, with the names of what it covers.
#[derive(Object)]
#[oai(rename = "AccessPolicy")]
struct AccessPolicyView {
    id: Uuid,
    name: String,
    description: String,
    enabled: bool,
    user_id: Option<Uuid>,
    user_name: Option<String>,
    /// An access group.
    role_id: Option<Uuid>,
    role_name: Option<String>,
    target_id: Option<Uuid>,
    target_name: Option<String>,
    target_account_id: Option<Uuid>,
    account: Option<String>,
    rules: AccessRules,
    /// The rules in words, as the audit log and approvers read them.
    summary: String,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

#[derive(Object)]
#[oai(rename = "AccessPolicyDataRequest")]
struct AccessPolicyDataRequest {
    name: String,
    #[oai(default)]
    description: String,
    #[oai(default = "default_true")]
    enabled: bool,
    /// Cover one user.
    user_id: Option<Uuid>,
    /// Cover the members of an access group.
    role_id: Option<Uuid>,
    /// Cover one target.
    target_id: Option<Uuid>,
    /// Cover one account on the target (needs `target_id`).
    target_account_id: Option<Uuid>,
    rules: AccessRules,
}

const fn default_true() -> bool {
    true
}

#[derive(ApiResponse)]
enum ListAccessPoliciesResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<AccessPolicyView>>),
}

#[derive(ApiResponse)]
enum SaveAccessPolicyResponse {
    #[oai(status = 200)]
    Ok(Json<AccessPolicyView>),
    #[oai(status = 400)]
    BadRequest(Json<String>),
    #[oai(status = 404)]
    NotFound(Json<String>),
    #[oai(status = 409)]
    Conflict(Json<String>),
}

#[derive(ApiResponse)]
enum DeleteAccessPolicyResponse {
    #[oai(status = 204)]
    Deleted,
    #[oai(status = 400)]
    BadRequest(Json<String>),
    #[oai(status = 404)]
    NotFound,
}

/// What became of an approval request, as a person reads it.
#[derive(Object)]
#[oai(rename = "AccessApproval")]
struct AccessApprovalView {
    /// With `target`, the key of the request: the same one `/session-approvals` uses.
    id: String,
    target: String,
    username: String,
    /// The account the approval is for; none on a protocol without remote accounts.
    account: Option<String>,
    policy_name: String,
    /// Why approval was required.
    reason: String,
    status: AccessApprovalStatus,
    requested_at: OffsetDateTime,
    /// When the request lapses unanswered.
    expires_at: OffsetDateTime,
    /// The last moment an approval can start a connection; set once approved.
    valid_until: Option<OffsetDateTime>,
    used_at: Option<OffsetDateTime>,
    resolved_by: Option<String>,
    resolved_at: Option<OffsetDateTime>,
}

#[derive(ApiResponse)]
enum ListAccessApprovalsResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<AccessApprovalView>>),
}

struct Names {
    users: HashMap<Uuid, String>,
    roles: HashMap<Uuid, String>,
    targets: HashMap<Uuid, String>,
    accounts: HashMap<Uuid, String>,
}

impl Names {
    async fn load(db: &DatabaseConnection) -> Result<Self, WarpgateError> {
        Ok(Self {
            users: User::Entity::find()
                .all(db)
                .await?
                .into_iter()
                .map(|user| (user.id, user.username))
                .collect(),
            roles: Role::Entity::find()
                .all(db)
                .await?
                .into_iter()
                .map(|role| (role.id, role.name))
                .collect(),
            targets: Target::Entity::find()
                .all(db)
                .await?
                .into_iter()
                .map(|target| (target.id, target.name))
                .collect(),
            accounts: TargetAccount::Entity::find()
                .all(db)
                .await?
                .into_iter()
                .map(|account| (account.id, account.display_name()))
                .collect(),
        })
    }
}

fn present(names: &Names, policy: &AccessPolicy::Model) -> AccessPolicyView {
    // Rules that cannot be read are shown as what they are enforced as: a denial.
    let rules = policy
        .rules()
        .unwrap_or_else(|_| AccessRules::new("UTC", RuleAction::Deny));
    AccessPolicyView {
        id: policy.id,
        name: policy.name.clone(),
        description: policy.description.clone(),
        enabled: policy.enabled,
        user_id: policy.user_id,
        user_name: policy
            .user_id
            .map(|id| names.users.get(&id).cloned().unwrap_or_default()),
        role_id: policy.role_id,
        role_name: policy
            .role_id
            .map(|id| names.roles.get(&id).cloned().unwrap_or_default()),
        target_id: policy.target_id,
        target_name: policy
            .target_id
            .map(|id| names.targets.get(&id).cloned().unwrap_or_default()),
        target_account_id: policy.target_account_id,
        account: policy
            .target_account_id
            .map(|id| names.accounts.get(&id).cloned().unwrap_or_default()),
        summary: rules.describe(),
        rules,
        created_at: policy.created_at,
        updated_at: policy.updated_at,
    }
}

/// Audit a policy change; never carries anything but the rules in words.
pub(super) async fn audit_changed(
    db: &DatabaseConnection,
    action: &str,
    policy: &AccessPolicy::Model,
    actor: Option<Uuid>,
) {
    AuditEvent::AccessPolicyChanged {
        action: action.to_owned(),
        policy_id: policy.id,
        policy_name: policy.name.clone(),
        scope: access_policy::describe_scope(db, access_policy::scope_of(policy)).await,
        enabled: policy.enabled,
        rules: policy
            .rules()
            .map_or_else(|_| "unreadable".to_owned(), |rules| rules.describe()),
        actor_user_id: actor,
    }
    .emit();
}

fn failure(error: PolicyError) -> Result<SaveAccessPolicyResponse, WarpgateError> {
    match error {
        PolicyError::Invalid(message) => Ok(SaveAccessPolicyResponse::BadRequest(Json(message))),
        PolicyError::NotFound => Ok(SaveAccessPolicyResponse::NotFound(Json(
            "Policy not found".into(),
        ))),
        PolicyError::Conflict(message) => Ok(SaveAccessPolicyResponse::Conflict(Json(message))),
        PolicyError::Database(error) => Err(error.into()),
    }
}

fn data_of(body: AccessPolicyDataRequest) -> PolicyData {
    PolicyData {
        name: body.name,
        description: body.description,
        enabled: body.enabled,
        scope: PolicyScope {
            user_id: body.user_id,
            role_id: body.role_id,
            target_id: body.target_id,
            target_account_id: body.target_account_id,
        },
        rules: body.rules,
    }
}

// ---------------------------------------------------------------------------------------
// The API
// ---------------------------------------------------------------------------------------

pub struct AccessPoliciesApi;

#[OpenApi]
impl AccessPoliciesApi {
    /// Every standing access policy. A direct assignment's own schedule is shown with the
    /// assignment, not here.
    #[oai(
        path = "/access-policies",
        method = "get",
        operation_id = "list_access_policies"
    )]
    async fn api_list(
        &self,
        admin: AdminContext,
    ) -> Result<ListAccessPoliciesResponse, WarpgateError> {
        admin.require(AdminPermission::AccessRolesAssign)?;
        let db = &admin.services().db;
        let names = Names::load(db).await?;
        let policies = access_policy::list_policies(db).await?;
        Ok(ListAccessPoliciesResponse::Ok(Json(
            policies
                .iter()
                .map(|policy| present(&names, policy))
                .collect(),
        )))
    }

    /// Create a policy. It takes effect for connections started from now on; sessions that
    /// are already open are not ended by a schedule.
    #[oai(
        path = "/access-policies",
        method = "post",
        operation_id = "create_access_policy"
    )]
    async fn api_create(
        &self,
        admin: AdminContext,
        body: Json<AccessPolicyDataRequest>,
    ) -> Result<SaveAccessPolicyResponse, WarpgateError> {
        admin.require(AdminPermission::AccessRolesAssign)?;
        let db = &admin.services().db;
        let created =
            match access_policy::create_policy(db, data_of(body.0), Some(admin.auth.user_id()))
                .await
            {
                Ok(created) => created,
                Err(error) => return failure(error),
            };
        audit_changed(db, "created", &created, Some(admin.auth.user_id())).await;
        let names = Names::load(db).await?;
        Ok(SaveAccessPolicyResponse::Ok(Json(present(
            &names, &created,
        ))))
    }

    /// Change a policy.
    #[oai(
        path = "/access-policies/:id",
        method = "put",
        operation_id = "update_access_policy"
    )]
    async fn api_update(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
        body: Json<AccessPolicyDataRequest>,
    ) -> Result<SaveAccessPolicyResponse, WarpgateError> {
        admin.require(AdminPermission::AccessRolesAssign)?;
        let db = &admin.services().db;
        let updated = match access_policy::update_policy(
            db,
            id.0,
            data_of(body.0),
            Some(admin.auth.user_id()),
        )
        .await
        {
            Ok(updated) => updated,
            Err(error) => return failure(error),
        };
        audit_changed(db, "updated", &updated, Some(admin.auth.user_id())).await;
        let names = Names::load(db).await?;
        Ok(SaveAccessPolicyResponse::Ok(Json(present(
            &names, &updated,
        ))))
    }

    /// Delete a policy.
    #[oai(
        path = "/access-policies/:id",
        method = "delete",
        operation_id = "delete_access_policy"
    )]
    async fn api_delete(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
    ) -> Result<DeleteAccessPolicyResponse, WarpgateError> {
        admin.require(AdminPermission::AccessRolesAssign)?;
        let db = &admin.services().db;
        match access_policy::delete_policy(db, id.0).await {
            Ok(deleted) => {
                audit_changed(db, "deleted", &deleted, Some(admin.auth.user_id())).await;
                Ok(DeleteAccessPolicyResponse::Deleted)
            }
            Err(PolicyError::NotFound) => Ok(DeleteAccessPolicyResponse::NotFound),
            Err(PolicyError::Invalid(message) | PolicyError::Conflict(message)) => {
                Ok(DeleteAccessPolicyResponse::BadRequest(Json(message)))
            }
            Err(PolicyError::Database(error)) => Err(error.into()),
        }
    }

    /// The approval requests that access policies asked for, newest first, with what became of
    /// each. To decide a pending one, use `/session-approvals`.
    #[oai(
        path = "/access-approvals",
        method = "get",
        operation_id = "list_access_approvals"
    )]
    async fn api_list_approvals(
        &self,
        admin: AdminContext,
    ) -> Result<ListAccessApprovalsResponse, WarpgateError> {
        admin.require(AdminPermission::ApproveSessions)?;
        let db = &admin.services().db;
        let contexts = AccessApprovalContext::Entity::find()
            .order_by_desc(AccessApprovalContext::Column::CreatedAt)
            .limit(200)
            .all(db)
            .await?;
        let now = OffsetDateTime::now_utc();
        let mut views = Vec::with_capacity(contexts.len());
        for context in contexts {
            let Some(request) = SessionApprovalRequest::Entity::find_by_id((
                context.session_id,
                ApprovalKind::Admin,
                context.target.clone(),
            ))
            .one(db)
            .await?
            else {
                continue;
            };
            views.push(AccessApprovalView {
                id: request.session_id.to_string(),
                target: request.target.clone(),
                username: request.username.clone(),
                account: context.account_name.clone(),
                policy_name: context.policy_name.clone(),
                reason: context.reason.clone(),
                status: approval_status(request.status, &context, now),
                requested_at: request.started,
                expires_at: context.expires_at,
                valid_until: context.valid_until,
                used_at: context.used_at,
                resolved_by: request.resolved_by_username.clone(),
                resolved_at: request.resolved_at,
            });
        }
        Ok(ListAccessApprovalsResponse::Ok(Json(views)))
    }
}
