//! Access Control: the one place administrators grant, change, review and revoke access.
//!
//! * **Target accounts** (`/targets/:id/accounts`, needs `TargetsEdit`): the remote accounts
//!   of a target. An account grants nobody anything.
//! * **Assignments** (`/access-assignments`, needs `AccessRolesAssign`): user, target and
//!   account. Listing shows every effective assignment, direct and group-derived, with
//!   where it comes from and whether it can be used now.
//! * **Access groups** (`/access-groups`, needs `AccessRolesAssign`): what a group (a role)
//!   grants its members. Group membership stays on the roles and users APIs.
//! * **Migration review** (`/access-migration/reviews`, needs `AccessRolesAssign`): the
//!   permissions m00098 could not map safely, waiting for a decision.
//!
//! Every change is audited, with the administrator, the user, the target, the account and
//! the state before and after; no credential is ever returned or logged. A change that can
//! take access away ends the affected users' live sessions on the target at once.

use std::collections::{HashMap, HashSet};

use poem_openapi::param::{Path, Query};
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Enum, Object, OpenApi};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder, Set,
};
use time::OffsetDateTime;
use tracing::warn;
use uuid::Uuid;
use warpgate_common::audit::AuditEvent;
use warpgate_common::{AdminPermission, Protocol, TargetAccountCredential, WarpgateError};
use warpgate_core::Services;
use warpgate_core::access_control::{
    AssignmentFilter, AssignmentOrigin, AssignmentSource, DirectoryUsernameFormat,
    EffectiveAssignment, TargetAccountAuthMethod, TargetAccountKind, check_account,
    close_sessions_on_target, effective_assignments, protocol_of, uses_accounts,
};
use warpgate_core::rdp_account::directory_account_names;
use warpgate_core::resources::target_accounts::{
    self, TargetAccountDataRequest, redacted_credential,
};
use warpgate_core::resources::{ResourceError, access_groups};
use warpgate_db_entities::AccessMigrationReview::{MigrationCategory, MigrationStatus};
use warpgate_db_entities::{
    AccessAssignment, AccessGroupGrant, AccessMigrationReview, Role, Target, TargetAccount, User,
    UserRoleAssignment,
};

use super::AdminContext;

// ---------------------------------------------------------------------------------------
// Presentation
// ---------------------------------------------------------------------------------------

/// An account in a target's inventory. Its credential is never returned: a password shows
/// blank, a secret reference shows as the reference.
#[derive(Object)]
#[oai(rename = "TargetAccount")]
struct TargetAccountView {
    id: Uuid,
    target_id: Uuid,
    kind: TargetAccountKind,
    /// As configured; empty for a linked directory account.
    name: String,
    /// As people read it: `WIN-SRV-01\support`, "Linked directory account (each user's own)".
    display_name: String,
    domain: Option<String>,
    auth_method: TargetAccountAuthMethod,
    credential: Option<TargetAccountCredential>,
    /// Where the credential comes from, in words: "Encrypted password", "Secret reference",
    /// "Warpgate SSH keys", ..., "Typed by the user when connecting".
    credential_source: String,
    username_format: Option<DirectoryUsernameFormat>,
    enabled: bool,
    is_primary: bool,
    description: String,
    /// Direct assignments of it, and access-group grants of it.
    assignment_count: u32,
    group_grant_count: u32,
    /// Why it cannot sign in to its target as configured, if it cannot.
    problem: Option<String>,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

/// Whether an effective assignment can be used now.
#[derive(Enum, Clone, Copy, PartialEq, Eq)]
#[oai(rename = "AccessAssignmentStatus")]
enum AssignmentStatus {
    #[oai(rename = "active")]
    Active,
    #[oai(rename = "disabled")]
    Disabled,
    #[oai(rename = "expired")]
    Expired,
    /// Group-derived, and the user was excluded from it.
    #[oai(rename = "excluded")]
    Excluded,
    /// It cannot be used as it is (the account is disabled, gone, or cannot sign in; the
    /// user's directory link changed; ...): see `problem`.
    #[oai(rename = "invalid")]
    Invalid,
}

/// Where an assignment comes from.
#[derive(Enum, Clone, Copy, PartialEq, Eq)]
#[oai(rename = "AccessAssignmentSource")]
enum SourceKind {
    #[oai(rename = "direct")]
    Direct,
    #[oai(rename = "group")]
    Group,
}

/// One effective assignment: a user's access to a target as an account.
#[derive(Object)]
#[oai(rename = "AccessAssignment")]
struct AssignmentView {
    /// The direct assignment; `None` for a group-derived one.
    id: Option<Uuid>,
    user_id: Uuid,
    /// Empty if the user has been deleted.
    username: String,
    target_id: Uuid,
    target_name: String,
    /// `rdp`, `ssh`, `mysql`, `postgres`, `http`, `kubernetes` or `vnc`.
    protocol: String,
    account_id: Option<Uuid>,
    /// The account as people read it; `None` where the protocol has none.
    account: Option<String>,
    account_kind: Option<TargetAccountKind>,
    auth_method: Option<TargetAccountAuthMethod>,
    credential_source: Option<String>,
    source: SourceKind,
    origin: Option<AssignmentOrigin>,
    group_id: Option<Uuid>,
    group_name: Option<String>,
    grant_id: Option<Uuid>,
    exclusion_id: Option<Uuid>,
    enabled: bool,
    expires_at: Option<OffsetDateTime>,
    status: AssignmentStatus,
    problem: Option<String>,
    note: String,
    created_at: Option<OffsetDateTime>,
    updated_at: Option<OffsetDateTime>,
}

/// Names for presenting assignments.
struct Lookup {
    users: HashMap<Uuid, String>,
    targets: HashMap<Uuid, (String, Protocol)>,
    direct: HashMap<Uuid, AccessAssignment::Model>,
}

impl Lookup {
    async fn load(db: &DatabaseConnection) -> Result<Self, WarpgateError> {
        Ok(Self {
            users: User::Entity::find()
                .all(db)
                .await?
                .into_iter()
                .map(|user| (user.id, user.username))
                .collect(),
            targets: Target::Entity::find()
                .all(db)
                .await?
                .into_iter()
                .map(|target| (target.id, (target.name, protocol_of(target.kind))))
                .collect(),
            direct: AccessAssignment::Entity::find()
                .all(db)
                .await?
                .into_iter()
                .map(|assignment| (assignment.id, assignment))
                .collect(),
        })
    }

    fn present(&self, assignment: &EffectiveAssignment) -> AssignmentView {
        let (target_name, protocol) = self
            .targets
            .get(&assignment.target_id)
            .map(|(name, protocol)| (name.clone(), protocol.name().to_owned()))
            .unwrap_or_default();
        let (id, origin, direct) = match &assignment.source {
            AssignmentSource::Direct {
                assignment_id,
                origin,
            } => (
                Some(*assignment_id),
                Some(*origin),
                self.direct.get(assignment_id),
            ),
            AssignmentSource::Group { .. } => (None, None, None),
        };
        let (group_id, group_name, grant_id) = match &assignment.source {
            AssignmentSource::Group {
                group_id,
                group_name,
                grant_id,
            } => (Some(*group_id), Some(group_name.clone()), Some(*grant_id)),
            AssignmentSource::Direct { .. } => (None, None, None),
        };
        let status = match assignment.problem {
            None => AssignmentStatus::Active,
            Some(_) if assignment.exclusion_id.is_some() => AssignmentStatus::Excluded,
            Some("disabled") => AssignmentStatus::Disabled,
            Some("expired") => AssignmentStatus::Expired,
            Some(_) => AssignmentStatus::Invalid,
        };
        AssignmentView {
            id,
            user_id: assignment.user_id,
            username: self
                .users
                .get(&assignment.user_id)
                .cloned()
                .unwrap_or_default(),
            target_id: assignment.target_id,
            target_name,
            protocol,
            account_id: assignment.account_id,
            account: assignment.account.as_ref().map(account_label),
            account_kind: assignment.account.as_ref().map(|account| account.kind),
            auth_method: assignment
                .account
                .as_ref()
                .map(|account| account.auth_method),
            credential_source: assignment.account.as_ref().map(credential_source),
            source: match assignment.source {
                AssignmentSource::Direct { .. } => SourceKind::Direct,
                AssignmentSource::Group { .. } => SourceKind::Group,
            },
            origin,
            group_id,
            group_name,
            grant_id,
            exclusion_id: assignment.exclusion_id,
            enabled: assignment.enabled,
            expires_at: assignment.expires_at,
            status,
            problem: assignment.problem.map(str::to_owned),
            note: direct.map(|d| d.note.clone()).unwrap_or_default(),
            created_at: direct.map(|d| d.created_at),
            updated_at: direct.map(|d| d.updated_at),
        }
    }
}

/// An account as people read it.
fn account_label(account: &TargetAccount::Model) -> String {
    match account
        .domain
        .as_deref()
        .map(str::trim)
        .filter(|d| !d.is_empty())
    {
        Some(domain)
            if account.kind != TargetAccountKind::Directory
                && !account.name.is_empty()
                && !account.name.contains('\\')
                && !account.name.contains('@') =>
        {
            format!("{domain}\\{}", account.name)
        }
        _ => account.display_name(),
    }
}

/// Where an account's credential comes from, in words; never the credential.
fn credential_source(account: &TargetAccount::Model) -> String {
    match account.auth_method {
        TargetAccountAuthMethod::TypedPassword => "Typed by the user when connecting",
        TargetAccountAuthMethod::DirectoryPassword => "The user's own directory password",
        TargetAccountAuthMethod::StoredCredential => match account.credential().ok().flatten() {
            Some(TargetAccountCredential::Password(credential)) => {
                if credential.password.as_reference().is_some() {
                    "Secret reference (Vault / OpenBao)"
                } else {
                    "Encrypted password"
                }
            }
            Some(TargetAccountCredential::PublicKey(_)) => "Warpgate SSH keys",
            Some(TargetAccountCredential::Certificate(_)) => "Vault-signed SSH certificate",
            Some(TargetAccountCredential::IamRole(_)) => "AWS IAM role",
            None => "Missing",
        },
    }
    .to_owned()
}

async fn present_account(
    db: &DatabaseConnection,
    account: &TargetAccount::Model,
) -> Result<TargetAccountView, WarpgateError> {
    let protocol = Target::Entity::find_by_id(account.target_id)
        .one(db)
        .await?
        .map(|target| protocol_of(target.kind));
    let assignment_count = AccessAssignment::Entity::find()
        .filter(AccessAssignment::Column::TargetAccountId.eq(account.id))
        .all(db)
        .await?
        .len();
    let group_grant_count = AccessGroupGrant::Entity::find()
        .filter(AccessGroupGrant::Column::TargetAccountId.eq(account.id))
        .all(db)
        .await?
        .len();
    Ok(TargetAccountView {
        id: account.id,
        target_id: account.target_id,
        kind: account.kind,
        name: account.name.clone(),
        display_name: account_label(account),
        domain: account.domain.clone(),
        auth_method: account.auth_method,
        credential: redacted_credential(account),
        credential_source: credential_source(account),
        username_format: account.username_format,
        enabled: account.enabled,
        is_primary: account.is_primary,
        description: account.description.clone(),
        assignment_count: u32::try_from(assignment_count).unwrap_or(u32::MAX),
        group_grant_count: u32::try_from(group_grant_count).unwrap_or(u32::MAX),
        problem: protocol
            .and_then(|protocol| check_account(protocol, account).err())
            .map(str::to_owned),
        created_at: account.created_at,
        updated_at: account.updated_at,
    })
}

fn describe_state(enabled: bool, expires_at: Option<OffsetDateTime>, account: &str) -> String {
    format!(
        "{}, {}, account {}",
        if enabled { "enabled" } else { "disabled" },
        expires_at.map_or_else(|| "never expires".to_owned(), |at| format!("expires {at}")),
        if account.is_empty() {
            "(none)"
        } else {
            account
        }
    )
}

fn resource_message(error: &ResourceError) -> Option<String> {
    match error {
        ResourceError::Invalid(message) => Some((*message).to_owned()),
        ResourceError::AccountTaken => Some("The target already has this account.".to_owned()),
        ResourceError::RoleAlreadyAssigned => {
            Some("The group already grants this account on this target.".to_owned())
        }
        ResourceError::NoPrimaryAccount => Some(error.to_string()),
        _ => None,
    }
}

/// End `user_ids`' live sessions on the target: access they may be using has gone or
/// changed. The periodic sweep would catch any that are left, within its interval.
async fn end_sessions(
    services: &Services,
    user_ids: impl IntoIterator<Item = Uuid>,
    target_id: Uuid,
) {
    for user_id in user_ids.into_iter().collect::<HashSet<_>>() {
        if let Err(error) = close_sessions_on_target(services, user_id, target_id).await {
            warn!(%error, %user_id, %target_id, "Could not end the user's sessions after their access changed");
        }
    }
}

// ---------------------------------------------------------------------------------------
// Target accounts
// ---------------------------------------------------------------------------------------

#[derive(ApiResponse)]
enum ListTargetAccountsResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<TargetAccountView>>),
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum SaveTargetAccountResponse {
    #[oai(status = 200)]
    Ok(Json<TargetAccountView>),
    #[oai(status = 400)]
    BadRequest(Json<String>),
    #[oai(status = 404)]
    NotFound,
    #[oai(status = 409)]
    Conflict(Json<String>),
}

#[derive(ApiResponse)]
enum DeleteTargetAccountResponse {
    #[oai(status = 204)]
    Deleted,
    #[oai(status = 404)]
    NotFound,
}

fn save_error(error: ResourceError) -> Result<SaveTargetAccountResponse, WarpgateError> {
    match error {
        ResourceError::NotFound => Ok(SaveTargetAccountResponse::NotFound),
        ResourceError::AccountTaken => Ok(SaveTargetAccountResponse::Conflict(Json(
            "The target already has this account.".into(),
        ))),
        ResourceError::Invalid(message) => {
            Ok(SaveTargetAccountResponse::BadRequest(Json(message.into())))
        }
        error => Err(error.into()),
    }
}

fn audit_account(action: &str, target_name: &str, account: &TargetAccount::Model, actor: Uuid) {
    AuditEvent::TargetAccountChanged {
        action: action.to_owned(),
        target_id: account.target_id,
        target_name: target_name.to_owned(),
        account_id: account.id,
        account: account_label(account),
        kind: account.kind.as_str().to_owned(),
        auth_method: account.auth_method.as_str().to_owned(),
        credential: account
            .credential()
            .ok()
            .flatten()
            .map_or("none", |credential| credential.kind_name())
            .to_owned(),
        enabled: account.enabled,
        actor_user_id: actor,
    }
    .emit();
}

/// The users whose access goes through `account_id`, for ending their sessions.
async fn users_of_account(
    db: &DatabaseConnection,
    target_id: Uuid,
    account_id: Uuid,
) -> Result<Vec<Uuid>, WarpgateError> {
    Ok(effective_assignments(
        db,
        AssignmentFilter {
            target_id: Some(target_id),
            ..Default::default()
        },
        OffsetDateTime::now_utc(),
    )
    .await?
    .into_iter()
    .filter(|assignment| assignment.account_id == Some(account_id))
    .map(|assignment| assignment.user_id)
    .collect())
}

pub struct TargetAccountsApi;

#[OpenApi]
impl TargetAccountsApi {
    /// A target's accounts. Credentials are never returned.
    #[oai(
        path = "/targets/:id/accounts",
        method = "get",
        operation_id = "list_target_accounts"
    )]
    async fn api_list(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
    ) -> Result<ListTargetAccountsResponse, WarpgateError> {
        // Who assigns accounts needs to see them, too.
        if !admin.has_permission(AdminPermission::AccessRolesAssign) {
            admin.require(AdminPermission::TargetsEdit)?;
        }
        let db = &admin.services().db;
        if Target::Entity::find_by_id(id.0).one(db).await?.is_none() {
            return Ok(ListTargetAccountsResponse::NotFound);
        }
        let mut accounts = vec![];
        for account in target_accounts::list(db, id.0).await? {
            accounts.push(present_account(db, &account).await?);
        }
        Ok(ListTargetAccountsResponse::Ok(Json(accounts)))
    }

    /// Add an account to a target. It grants nobody anything until assigned.
    #[oai(
        path = "/targets/:id/accounts",
        method = "post",
        operation_id = "create_target_account"
    )]
    async fn api_create(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
        body: Json<TargetAccountDataRequest>,
    ) -> Result<SaveTargetAccountResponse, WarpgateError> {
        admin.require(AdminPermission::TargetsEdit)?;
        let db = &admin.services().db;
        let actor = admin.auth.user_id();
        let account = match target_accounts::create(db, id.0, &body.0, Some(actor)).await {
            Ok(account) => account,
            Err(error) => return save_error(error),
        };
        let target_name = Target::Entity::find_by_id(id.0)
            .one(db)
            .await?
            .map(|target| target.name)
            .unwrap_or_default();
        audit_account("created", &target_name, &account, actor);
        Ok(SaveTargetAccountResponse::Ok(Json(
            present_account(db, &account).await?,
        )))
    }

    /// Change an account: its name, credential (a blank password keeps the stored one),
    /// whether it is enabled, ... Users connected as it are disconnected.
    #[oai(
        path = "/targets/:id/accounts/:account_id",
        method = "put",
        operation_id = "update_target_account"
    )]
    async fn api_update(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
        account_id: Path<Uuid>,
        body: Json<TargetAccountDataRequest>,
    ) -> Result<SaveTargetAccountResponse, WarpgateError> {
        admin.require(AdminPermission::TargetsEdit)?;
        let services = admin.services();
        let db = &services.db;
        let affected = users_of_account(db, id.0, account_id.0).await?;
        let (before, after) = match target_accounts::update(db, id.0, account_id.0, &body.0).await {
            Ok(result) => result,
            Err(error) => return save_error(error),
        };
        let target_name = Target::Entity::find_by_id(id.0)
            .one(db)
            .await?
            .map(|target| target.name)
            .unwrap_or_default();
        audit_account("updated", &target_name, &after, admin.auth.user_id());
        // A session signed in under the account's old terms must not outlive them.
        if before != after {
            end_sessions(services, affected, id.0).await;
        }
        Ok(SaveTargetAccountResponse::Ok(Json(
            present_account(db, &after).await?,
        )))
    }

    /// Delete an account, revoking every assignment and group grant of it.
    #[oai(
        path = "/targets/:id/accounts/:account_id",
        method = "delete",
        operation_id = "delete_target_account"
    )]
    async fn api_delete(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
        account_id: Path<Uuid>,
    ) -> Result<DeleteTargetAccountResponse, WarpgateError> {
        admin.require(AdminPermission::TargetsEdit)?;
        let services = admin.services();
        let db = &services.db;
        let affected = users_of_account(db, id.0, account_id.0).await?;
        let deleted = match target_accounts::delete(db, id.0, account_id.0).await {
            Ok(deleted) => deleted,
            Err(ResourceError::NotFound) => return Ok(DeleteTargetAccountResponse::NotFound),
            Err(error) => return Err(error.into()),
        };
        let actor = admin.auth.user_id();
        let lookup = Lookup::load(db).await?;
        let target_name = lookup
            .targets
            .get(&id.0)
            .map(|(name, _)| name.clone())
            .unwrap_or_default();
        audit_account("deleted", &target_name, &deleted.account, actor);
        let account = account_label(&deleted.account);
        for assignment in &deleted.assignments {
            AuditEvent::AccessAssignmentChanged {
                action: "revoked".into(),
                assignment_id: Some(assignment.id),
                user_id: assignment.user_id,
                username: lookup
                    .users
                    .get(&assignment.user_id)
                    .cloned()
                    .unwrap_or_default(),
                target_id: assignment.target_id,
                target_name: target_name.clone(),
                account: account.clone(),
                account_id: Some(deleted.account.id),
                source: "direct; the account was deleted".into(),
                previous_state: describe_state(assignment.enabled, assignment.expires_at, &account),
                new_state: "revoked".into(),
                actor_user_id: Some(actor),
            }
            .emit();
        }
        for grant in &deleted.grants {
            let group_name = Role::Entity::find_by_id(grant.role_id)
                .one(db)
                .await?
                .map(|role| role.name)
                .unwrap_or_default();
            AuditEvent::AccessGroupGrantChanged {
                action: "removed".into(),
                group_id: grant.role_id,
                group_name,
                target_id: grant.target_id,
                target_name: target_name.clone(),
                account: account.clone(),
                account_id: Some(deleted.account.id),
                affected_users: "the account was deleted".into(),
                actor_user_id: actor,
            }
            .emit();
        }
        end_sessions(services, affected, id.0).await;
        Ok(DeleteTargetAccountResponse::Deleted)
    }
}

// ---------------------------------------------------------------------------------------
// Assignments
// ---------------------------------------------------------------------------------------

#[derive(Object)]
struct CreateAccessAssignmentRequest {
    user_id: Uuid,
    target_id: Uuid,
    /// The target's account; required on RDP, SSH, MySQL and PostgreSQL, absent elsewhere.
    account_id: Option<Uuid>,
    #[oai(default = "default_true")]
    enabled: bool,
    expires_at: Option<OffsetDateTime>,
    #[oai(default)]
    note: String,
}

const fn default_true() -> bool {
    true
}

#[derive(Object)]
struct UpdateAccessAssignmentRequest {
    account_id: Option<Uuid>,
    enabled: bool,
    expires_at: Option<OffsetDateTime>,
    #[oai(default)]
    note: String,
}

#[derive(Enum, Clone, Copy, PartialEq, Eq)]
#[oai(rename = "AccessAssignmentBulkAction")]
enum BulkAction {
    #[oai(rename = "enable")]
    Enable,
    #[oai(rename = "disable")]
    Disable,
    #[oai(rename = "revoke")]
    Revoke,
}

#[derive(Object)]
struct BulkAccessAssignmentRequest {
    /// Direct assignments only; a group-derived one is changed through its group.
    ids: Vec<Uuid>,
    action: BulkAction,
    /// Only say what would change.
    #[oai(default)]
    dry_run: bool,
}

#[derive(Object)]
struct BulkAccessAssignmentResult {
    /// The assignments it changes (or would), as they are before the change.
    affected: Vec<AssignmentView>,
    summary: String,
    applied: bool,
}

/// An account that can be assigned to a user on a target.
#[derive(Object)]
struct AssignableAccount {
    id: Uuid,
    account: String,
    kind: TargetAccountKind,
    auth_method: TargetAccountAuthMethod,
    credential_source: String,
    enabled: bool,
    /// For a linked directory account: the name it signs this user in as, read from the
    /// directory now.
    signs_in_as: Option<String>,
    /// Why it cannot be assigned to this user now, if it cannot.
    problem: Option<String>,
}

#[derive(Object)]
struct AccessAssignmentOptions {
    protocol: String,
    /// Whether assignments on this target name an account.
    uses_accounts: bool,
    directory_linked: bool,
    accounts: Vec<AssignableAccount>,
    /// The user's access to the target as it is now.
    current: Vec<AssignmentView>,
}

#[derive(ApiResponse)]
enum ListAccessAssignmentsResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<AssignmentView>>),
}

#[derive(ApiResponse)]
enum SaveAccessAssignmentResponse {
    #[oai(status = 200)]
    Ok(Json<AssignmentView>),
    #[oai(status = 400)]
    BadRequest(Json<String>),
    #[oai(status = 404)]
    NotFound(Json<String>),
    #[oai(status = 409)]
    Conflict(Json<String>),
}

#[derive(ApiResponse)]
enum DeleteAccessAssignmentResponse {
    #[oai(status = 204)]
    Deleted,
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum BulkAccessAssignmentResponse {
    #[oai(status = 200)]
    Ok(Json<BulkAccessAssignmentResult>),
}

#[derive(ApiResponse)]
enum GetAccessAssignmentOptionsResponse {
    #[oai(status = 200)]
    Ok(Json<AccessAssignmentOptions>),
    #[oai(status = 404)]
    NotFound(Json<String>),
}

/// What an assignment of `account_id` to `user` on `target` would hold, checked: the
/// account must be the target's and able to sign in there, and a directory account needs
/// the user's link, which the assignment records.
async fn checked_account(
    db: &DatabaseConnection,
    user: &User::Model,
    target: &Target::Model,
    account_id: Option<Uuid>,
) -> Result<(Option<TargetAccount::Model>, Option<(Uuid, Uuid)>), String> {
    let protocol = protocol_of(target.kind);
    match (uses_accounts(protocol), account_id) {
        (true, None) => Err("Choose the account to assign on this target.".into()),
        (false, Some(_)) => Err("This target's protocol has no remote accounts.".into()),
        (false, None) => Ok((None, None)),
        (true, Some(account_id)) => {
            let account = TargetAccount::Entity::find_by_id(account_id)
                .one(db)
                .await
                .map_err(|error| error.to_string())?
                .filter(|account| account.target_id == target.id)
                .ok_or_else(|| "The account is not one of the target's.".to_owned())?;
            check_account(protocol, &account).map_err(str::to_owned)?;
            let link = if account.kind == TargetAccountKind::Directory {
                match (user.ldap_server_id, user.ldap_object_uuid) {
                    (Some(server), Some(entry)) => Some((server, entry)),
                    _ => {
                        return Err(
                            "The user is not linked to a directory account, so a linked directory account cannot be assigned to them.".into(),
                        );
                    }
                }
            } else {
                None
            };
            Ok((Some(account), link))
        }
    }
}

/// The effective assignment for a direct one, presented.
async fn present_direct(
    db: &DatabaseConnection,
    assignment: &AccessAssignment::Model,
) -> Result<AssignmentView, WarpgateError> {
    let lookup = Lookup::load(db).await?;
    let effective = effective_assignments(
        db,
        AssignmentFilter {
            user_id: Some(assignment.user_id),
            target_id: Some(assignment.target_id),
            direct_only: true,
            ..Default::default()
        },
        OffsetDateTime::now_utc(),
    )
    .await?;
    effective
        .iter()
        .find(|e| {
            matches!(e.source, AssignmentSource::Direct { assignment_id, .. } if assignment_id == assignment.id)
        })
        .map(|e| lookup.present(e))
        .ok_or_else(|| WarpgateError::InconsistentState("the assignment was not found".into()))
}

async fn account_name(db: &DatabaseConnection, account_id: Option<Uuid>) -> String {
    match account_id {
        Some(id) => TargetAccount::Entity::find_by_id(id)
            .one(db)
            .await
            .ok()
            .flatten()
            .map(|account| account_label(&account))
            .unwrap_or_default(),
        None => String::new(),
    }
}

pub struct AssignmentsApi;

#[OpenApi]
impl AssignmentsApi {
    /// Every effective assignment, direct and group-derived (excluded ones included), with
    /// where it comes from and whether it can be used now. Filter by user, target or group;
    /// `source` is `direct` or `group`.
    #[oai(
        path = "/access-assignments",
        method = "get",
        operation_id = "list_access_assignments"
    )]
    async fn api_list(
        &self,
        admin: AdminContext,
        user_id: Query<Option<Uuid>>,
        target_id: Query<Option<Uuid>>,
        group_id: Query<Option<Uuid>>,
        source: Query<Option<String>>,
    ) -> Result<ListAccessAssignmentsResponse, WarpgateError> {
        admin.require(AdminPermission::AccessRolesAssign)?;
        let db = &admin.services().db;
        let source = source.0.unwrap_or_default();
        let assignments = effective_assignments(
            db,
            AssignmentFilter {
                user_id: user_id.0,
                target_id: target_id.0,
                group_id: group_id.0,
                direct_only: source == "direct",
            },
            OffsetDateTime::now_utc(),
        )
        .await?;
        let lookup = Lookup::load(db).await?;
        let mut presented: Vec<AssignmentView> = assignments
            .iter()
            .filter(|a| source != "group" || matches!(a.source, AssignmentSource::Group { .. }))
            .map(|a| lookup.present(a))
            .collect();
        presented.sort_by(|a, b| {
            (a.username.to_lowercase(), a.target_name.to_lowercase())
                .cmp(&(b.username.to_lowercase(), b.target_name.to_lowercase()))
        });
        Ok(ListAccessAssignmentsResponse::Ok(Json(presented)))
    }

    /// What can be assigned to a user on a target: its accounts (a linked directory account
    /// with the name it would sign this user in as), and the user's access there now.
    #[oai(
        path = "/access-assignments/options",
        method = "get",
        operation_id = "get_access_assignment_options"
    )]
    async fn api_options(
        &self,
        admin: AdminContext,
        user_id: Query<Uuid>,
        target_id: Query<Uuid>,
    ) -> Result<GetAccessAssignmentOptionsResponse, WarpgateError> {
        admin.require(AdminPermission::AccessRolesAssign)?;
        let db = &admin.services().db;
        let Some(user) = User::Entity::find_by_id(user_id.0).one(db).await? else {
            return Ok(GetAccessAssignmentOptionsResponse::NotFound(Json(
                "User not found".into(),
            )));
        };
        let Some(target) = Target::Entity::find_by_id(target_id.0).one(db).await? else {
            return Ok(GetAccessAssignmentOptionsResponse::NotFound(Json(
                "Target not found".into(),
            )));
        };
        let protocol = protocol_of(target.kind);
        let directory_linked = user.ldap_server_id.is_some() && user.ldap_object_uuid.is_some();
        let directory_names: Vec<(DirectoryUsernameFormat, String)> = if directory_linked {
            directory_account_names(db, user.id)
                .await
                .unwrap_or_default()
        } else {
            vec![]
        };
        let mut accounts = vec![];
        for account in target_accounts::list(db, target.id).await? {
            let mut problem = check_account(protocol, &account).err().map(str::to_owned);
            let mut signs_in_as = None;
            if account.kind == TargetAccountKind::Directory {
                if directory_linked {
                    let format = account
                        .username_format
                        .unwrap_or(DirectoryUsernameFormat::Upn);
                    signs_in_as = directory_names
                        .iter()
                        .find(|(f, _)| *f == format)
                        .map(|(_, name)| name.clone());
                    if signs_in_as.is_none() && problem.is_none() {
                        problem = Some("The user's directory account could not be read now".into());
                    }
                } else if problem.is_none() {
                    problem = Some("The user is not linked to a directory account".into());
                }
            }
            if !account.enabled && problem.is_none() {
                problem = Some("The account is disabled".into());
            }
            accounts.push(AssignableAccount {
                id: account.id,
                account: account_label(&account),
                kind: account.kind,
                auth_method: account.auth_method,
                credential_source: credential_source(&account),
                enabled: account.enabled,
                signs_in_as,
                problem,
            });
        }
        let lookup = Lookup::load(db).await?;
        let current = effective_assignments(
            db,
            AssignmentFilter {
                user_id: Some(user.id),
                target_id: Some(target.id),
                ..Default::default()
            },
            OffsetDateTime::now_utc(),
        )
        .await?
        .iter()
        .map(|a| lookup.present(a))
        .collect();
        Ok(GetAccessAssignmentOptionsResponse::Ok(Json(
            AccessAssignmentOptions {
                protocol: protocol.name().to_owned(),
                uses_accounts: uses_accounts(protocol),
                directory_linked,
                accounts,
                current,
            },
        )))
    }

    /// Assign a user an account on a target: permission both to connect to the target and to
    /// sign in there as that account. Nothing else is needed.
    #[oai(
        path = "/access-assignments",
        method = "post",
        operation_id = "create_access_assignment"
    )]
    async fn api_create(
        &self,
        admin: AdminContext,
        body: Json<CreateAccessAssignmentRequest>,
    ) -> Result<SaveAccessAssignmentResponse, WarpgateError> {
        admin.require(AdminPermission::AccessRolesAssign)?;
        let db = &admin.services().db;
        let body = body.0;
        let actor = admin.auth.user_id();
        match create_direct(
            db,
            body.user_id,
            body.target_id,
            body.account_id,
            body.enabled,
            body.expires_at,
            body.note.trim(),
            AssignmentOrigin::Direct,
            actor,
        )
        .await?
        {
            Ok(assignment) => Ok(SaveAccessAssignmentResponse::Ok(Json(
                present_direct(db, &assignment).await?,
            ))),
            Err(refusal) => Ok(refusal),
        }
    }

    /// Change a direct assignment: its account, whether it is enabled, its expiry. The
    /// user's live sessions on the target end.
    #[oai(
        path = "/access-assignments/:id",
        method = "put",
        operation_id = "update_access_assignment"
    )]
    async fn api_update(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
        body: Json<UpdateAccessAssignmentRequest>,
    ) -> Result<SaveAccessAssignmentResponse, WarpgateError> {
        admin.require(AdminPermission::AccessRolesAssign)?;
        let services = admin.services();
        let db = &services.db;
        let body = body.0;
        let Some(existing) = AccessAssignment::Entity::find_by_id(id.0).one(db).await? else {
            return Ok(SaveAccessAssignmentResponse::NotFound(Json(
                "Assignment not found".into(),
            )));
        };
        let (Some(user), Some(target)) = (
            User::Entity::find_by_id(existing.user_id).one(db).await?,
            Target::Entity::find_by_id(existing.target_id)
                .one(db)
                .await?,
        ) else {
            return Ok(SaveAccessAssignmentResponse::NotFound(Json(
                "The user or target no longer exists".into(),
            )));
        };
        let mut model: AccessAssignment::ActiveModel = existing.clone().into();
        if body.account_id != existing.target_account_id {
            let (account, link) = match checked_account(db, &user, &target, body.account_id).await {
                Ok(checked) => checked,
                Err(message) => {
                    return Ok(SaveAccessAssignmentResponse::BadRequest(Json(message)));
                }
            };
            let key = AccessAssignment::account_key(account.as_ref().map(|a| a.id));
            if AccessAssignment::Entity::find()
                .filter(AccessAssignment::Column::UserId.eq(existing.user_id))
                .filter(AccessAssignment::Column::TargetId.eq(existing.target_id))
                .filter(AccessAssignment::Column::AccountKey.eq(key.clone()))
                .one(db)
                .await?
                .is_some()
            {
                return Ok(SaveAccessAssignmentResponse::Conflict(Json(
                    "This account is already assigned to the user on this target".into(),
                )));
            }
            model.target_account_id = Set(account.as_ref().map(|a| a.id));
            model.account_key = Set(key);
            model.ldap_server_id = Set(link.map(|(server, _)| server));
            model.ldap_object_uuid = Set(link.map(|(_, entry)| entry));
        }
        model.enabled = Set(body.enabled);
        model.expires_at = Set(body.expires_at);
        model.note = Set(body.note.trim().to_owned());
        model.updated_by = Set(Some(admin.auth.user_id()));
        model.updated_at = Set(OffsetDateTime::now_utc());
        let updated = model.update(db).await?;

        let before_account = account_name(db, existing.target_account_id).await;
        let after_account = account_name(db, updated.target_account_id).await;
        AuditEvent::AccessAssignmentChanged {
            action: if existing.enabled != updated.enabled {
                if updated.enabled {
                    "enabled"
                } else {
                    "disabled"
                }
            } else {
                "updated"
            }
            .into(),
            assignment_id: Some(updated.id),
            user_id: updated.user_id,
            username: user.username.clone(),
            target_id: updated.target_id,
            target_name: target.name.clone(),
            account: after_account.clone(),
            account_id: updated.target_account_id,
            source: "direct".into(),
            previous_state: describe_state(existing.enabled, existing.expires_at, &before_account),
            new_state: describe_state(updated.enabled, updated.expires_at, &after_account),
            actor_user_id: Some(admin.auth.user_id()),
        }
        .emit();
        // A session that signed in under the old terms ends: it must not outlive them.
        end_sessions(services, [updated.user_id], updated.target_id).await;
        Ok(SaveAccessAssignmentResponse::Ok(Json(
            present_direct(db, &updated).await?,
        )))
    }

    /// Revoke a direct assignment. The user's live sessions on the target end. A group's
    /// assignments are not touched: exclude the user from the group's grant for that.
    #[oai(
        path = "/access-assignments/:id",
        method = "delete",
        operation_id = "delete_access_assignment"
    )]
    async fn api_delete(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
    ) -> Result<DeleteAccessAssignmentResponse, WarpgateError> {
        admin.require(AdminPermission::AccessRolesAssign)?;
        let services = admin.services();
        let db = &services.db;
        let Some(assignment) = AccessAssignment::Entity::find_by_id(id.0).one(db).await? else {
            return Ok(DeleteAccessAssignmentResponse::NotFound);
        };
        revoke_direct(services, &assignment, admin.auth.user_id(), "direct").await?;
        Ok(DeleteAccessAssignmentResponse::Deleted)
    }

    /// Enable, disable or revoke several direct assignments at once; with `dry_run`, only
    /// say which would change.
    #[oai(
        path = "/access-assignments/bulk",
        method = "post",
        operation_id = "bulk_update_access_assignments"
    )]
    async fn api_bulk(
        &self,
        admin: AdminContext,
        body: Json<BulkAccessAssignmentRequest>,
    ) -> Result<BulkAccessAssignmentResponse, WarpgateError> {
        admin.require(AdminPermission::AccessRolesAssign)?;
        let services = admin.services();
        let db = &services.db;
        let body = body.0;
        let lookup = Lookup::load(db).await?;
        let wanted: HashSet<Uuid> = body.ids.iter().copied().collect();
        let all = effective_assignments(
            db,
            AssignmentFilter {
                direct_only: true,
                ..Default::default()
            },
            OffsetDateTime::now_utc(),
        )
        .await?;
        let affected: Vec<&EffectiveAssignment> = all
            .iter()
            .filter(|a| {
                let AssignmentSource::Direct { assignment_id, .. } = a.source else {
                    return false;
                };
                wanted.contains(&assignment_id)
                    && match body.action {
                        BulkAction::Enable => !a.enabled,
                        BulkAction::Disable => a.enabled,
                        BulkAction::Revoke => true,
                    }
            })
            .collect();
        let users: HashSet<Uuid> = affected.iter().map(|a| a.user_id).collect();
        let targets: HashSet<Uuid> = affected.iter().map(|a| a.target_id).collect();
        let (verb, done) = match body.action {
            BulkAction::Enable => ("enable", "Enabled"),
            BulkAction::Disable => ("disable", "Disabled"),
            BulkAction::Revoke => ("revoke", "Revoked"),
        };
        let counts = format!(
            "{} assignment(s) of {} user(s) on {} target(s)",
            affected.len(),
            users.len(),
            targets.len(),
        );
        // Enabling ends no sessions; disabling and revoking do (below).
        let summary = if body.dry_run {
            format!("Would {verb} {counts}.")
        } else if body.action == BulkAction::Enable {
            format!("{done} {counts}.")
        } else {
            format!("{done} {counts}; their sessions on those targets ended.")
        };
        let presented: Vec<AssignmentView> = affected.iter().map(|a| lookup.present(a)).collect();
        if !body.dry_run {
            let actor = admin.auth.user_id();
            for assignment in &affected {
                let AssignmentSource::Direct { assignment_id, .. } = assignment.source else {
                    continue;
                };
                let Some(model) = AccessAssignment::Entity::find_by_id(assignment_id)
                    .one(db)
                    .await?
                else {
                    continue;
                };
                if body.action == BulkAction::Revoke {
                    revoke_direct(services, &model, actor, "direct; bulk revoke").await?;
                    continue;
                }
                let enabled = body.action == BulkAction::Enable;
                let mut active: AccessAssignment::ActiveModel = model.clone().into();
                active.enabled = Set(enabled);
                active.updated_by = Set(Some(actor));
                active.updated_at = Set(OffsetDateTime::now_utc());
                active.update(db).await?;
                let account = account_name(db, model.target_account_id).await;
                AuditEvent::AccessAssignmentChanged {
                    action: verb.to_owned() + "d",
                    assignment_id: Some(model.id),
                    user_id: model.user_id,
                    username: lookup
                        .users
                        .get(&model.user_id)
                        .cloned()
                        .unwrap_or_default(),
                    target_id: model.target_id,
                    target_name: lookup
                        .targets
                        .get(&model.target_id)
                        .map(|(name, _)| name.clone())
                        .unwrap_or_default(),
                    account: account.clone(),
                    account_id: model.target_account_id,
                    source: "direct; bulk change".into(),
                    previous_state: describe_state(model.enabled, model.expires_at, &account),
                    new_state: describe_state(enabled, model.expires_at, &account),
                    actor_user_id: Some(actor),
                }
                .emit();
                if !enabled {
                    end_sessions(services, [model.user_id], model.target_id).await;
                }
            }
        }
        Ok(BulkAccessAssignmentResponse::Ok(Json(
            BulkAccessAssignmentResult {
                affected: presented,
                summary,
                applied: !body.dry_run,
            },
        )))
    }
}

/// Make a direct assignment, checked and audited; `Ok(Err(response))` is a refusal.
#[allow(clippy::too_many_arguments)]
async fn create_direct(
    db: &DatabaseConnection,
    user_id: Uuid,
    target_id: Uuid,
    account_id: Option<Uuid>,
    enabled: bool,
    expires_at: Option<OffsetDateTime>,
    note: &str,
    origin: AssignmentOrigin,
    actor: Uuid,
) -> Result<Result<AccessAssignment::Model, SaveAccessAssignmentResponse>, WarpgateError> {
    let Some(user) = User::Entity::find_by_id(user_id).one(db).await? else {
        return Ok(Err(SaveAccessAssignmentResponse::NotFound(Json(
            "User not found".into(),
        ))));
    };
    let Some(target) = Target::Entity::find_by_id(target_id).one(db).await? else {
        return Ok(Err(SaveAccessAssignmentResponse::NotFound(Json(
            "Target not found".into(),
        ))));
    };
    let (account, link) = match checked_account(db, &user, &target, account_id).await {
        Ok(checked) => checked,
        Err(message) => return Ok(Err(SaveAccessAssignmentResponse::BadRequest(Json(message)))),
    };
    let key = AccessAssignment::account_key(account.as_ref().map(|a| a.id));
    if AccessAssignment::Entity::find()
        .filter(AccessAssignment::Column::UserId.eq(user.id))
        .filter(AccessAssignment::Column::TargetId.eq(target.id))
        .filter(AccessAssignment::Column::AccountKey.eq(key.clone()))
        .one(db)
        .await?
        .is_some()
    {
        return Ok(Err(SaveAccessAssignmentResponse::Conflict(Json(
            "This account is already assigned to the user on this target".into(),
        ))));
    }
    let now = OffsetDateTime::now_utc();
    let assignment = AccessAssignment::ActiveModel {
        id: Set(Uuid::new_v4()),
        user_id: Set(user.id),
        target_id: Set(target.id),
        target_account_id: Set(account.as_ref().map(|a| a.id)),
        account_key: Set(key),
        ldap_server_id: Set(link.map(|(server, _)| server)),
        ldap_object_uuid: Set(link.map(|(_, entry)| entry)),
        enabled: Set(enabled),
        expires_at: Set(expires_at),
        origin: Set(origin),
        note: Set(note.to_owned()),
        created_by: Set(Some(actor)),
        updated_by: Set(Some(actor)),
        created_at: Set(now),
        updated_at: Set(now),
    }
    .insert(db)
    .await?;
    let account = account.as_ref().map(account_label).unwrap_or_default();
    AuditEvent::AccessAssignmentChanged {
        action: "created".into(),
        assignment_id: Some(assignment.id),
        user_id: user.id,
        username: user.username.clone(),
        target_id: target.id,
        target_name: target.name.clone(),
        account: account.clone(),
        account_id: assignment.target_account_id,
        source: origin.as_str().to_owned(),
        previous_state: "none".into(),
        new_state: describe_state(enabled, expires_at, &account),
        actor_user_id: Some(actor),
    }
    .emit();
    Ok(Ok(assignment))
}

/// Revoke a direct assignment, audited; ends the user's sessions on the target.
async fn revoke_direct(
    services: &Services,
    assignment: &AccessAssignment::Model,
    actor: Uuid,
    source: &str,
) -> Result<(), WarpgateError> {
    let db = &services.db;
    AccessAssignment::Entity::delete_by_id(assignment.id)
        .exec(db)
        .await?;
    let username = User::Entity::find_by_id(assignment.user_id)
        .one(db)
        .await?
        .map(|user| user.username)
        .unwrap_or_default();
    let target_name = Target::Entity::find_by_id(assignment.target_id)
        .one(db)
        .await?
        .map(|target| target.name)
        .unwrap_or_default();
    let account = account_name(db, assignment.target_account_id).await;
    AuditEvent::AccessAssignmentChanged {
        action: "revoked".into(),
        assignment_id: Some(assignment.id),
        user_id: assignment.user_id,
        username,
        target_id: assignment.target_id,
        target_name,
        account: account.clone(),
        account_id: assignment.target_account_id,
        source: source.to_owned(),
        previous_state: describe_state(assignment.enabled, assignment.expires_at, &account),
        new_state: "revoked".into(),
        actor_user_id: Some(actor),
    }
    .emit();
    end_sessions(services, [assignment.user_id], assignment.target_id).await;
    Ok(())
}

// ---------------------------------------------------------------------------------------
// Access groups
// ---------------------------------------------------------------------------------------

/// An access group: a role, as Access Control uses it.
#[derive(Object)]
struct AccessGroupView {
    id: Uuid,
    name: String,
    description: String,
    /// New users join it.
    is_default: bool,
    /// Active members.
    member_count: u32,
    grant_count: u32,
    /// An SSO provider's role mappings name it, so its membership is managed at sign-in.
    sso_managed: bool,
}

/// What a group grants: a target, as an account (or the target itself where the protocol has
/// no accounts).
#[derive(Object)]
struct AccessGroupGrantView {
    id: Uuid,
    group_id: Uuid,
    target_id: Uuid,
    target_name: String,
    protocol: String,
    account_id: Option<Uuid>,
    account: Option<String>,
    /// Members excluded from it.
    excluded_count: u32,
    created_at: OffsetDateTime,
}

#[derive(Object)]
struct CreateAccessGroupGrantRequest {
    target_id: Uuid,
    account_id: Option<Uuid>,
    /// Only say who would gain access.
    #[oai(default)]
    dry_run: bool,
}

/// What a change to a group's grants does (or would do).
#[derive(Object)]
struct AccessGroupGrantChange {
    grant: Option<AccessGroupGrantView>,
    /// The members whose access changes: who gains it, or who loses it.
    affected_users: Vec<String>,
    summary: String,
    applied: bool,
}

#[derive(Object)]
struct ExcludeFromGrantRequest {
    user_id: Uuid,
    #[oai(default)]
    note: String,
}

#[derive(ApiResponse)]
enum ListAccessGroupsResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<AccessGroupView>>),
}

#[derive(ApiResponse)]
enum ListAccessGroupGrantsResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<AccessGroupGrantView>>),
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum ChangeAccessGroupGrantResponse {
    #[oai(status = 200)]
    Ok(Json<AccessGroupGrantChange>),
    #[oai(status = 400)]
    BadRequest(Json<String>),
    #[oai(status = 404)]
    NotFound,
    #[oai(status = 409)]
    Conflict(Json<String>),
}

#[derive(ApiResponse)]
enum ExclusionResponse {
    #[oai(status = 200)]
    Ok(Json<AssignmentView>),
    #[oai(status = 204)]
    Removed,
    #[oai(status = 400)]
    BadRequest(Json<String>),
    #[oai(status = 404)]
    NotFound,
    #[oai(status = 409)]
    Conflict(Json<String>),
}

async fn present_grant(
    db: &DatabaseConnection,
    grant: &AccessGroupGrant::Model,
) -> Result<AccessGroupGrantView, WarpgateError> {
    let target = Target::Entity::find_by_id(grant.target_id).one(db).await?;
    let excluded = warpgate_db_entities::AccessGroupExclusion::Entity::find()
        .filter(warpgate_db_entities::AccessGroupExclusion::Column::RoleId.eq(grant.role_id))
        .filter(warpgate_db_entities::AccessGroupExclusion::Column::TargetId.eq(grant.target_id))
        .filter(
            warpgate_db_entities::AccessGroupExclusion::Column::AccountKey
                .eq(grant.account_key.clone()),
        )
        .all(db)
        .await?
        .len();
    Ok(AccessGroupGrantView {
        id: grant.id,
        group_id: grant.role_id,
        target_id: grant.target_id,
        target_name: target.as_ref().map(|t| t.name.clone()).unwrap_or_default(),
        protocol: target
            .as_ref()
            .map(|t| protocol_of(t.kind).name().to_owned())
            .unwrap_or_default(),
        account_id: grant.target_account_id,
        account: match grant.target_account_id {
            Some(_) => Some(account_name(db, grant.target_account_id).await),
            None => None,
        },
        excluded_count: u32::try_from(excluded).unwrap_or(u32::MAX),
        created_at: grant.created_at,
    })
}

/// The active members of a group, by id and name.
async fn members_of(
    db: &DatabaseConnection,
    group_id: Uuid,
) -> Result<Vec<(Uuid, String)>, WarpgateError> {
    let member_ids: Vec<Uuid> = UserRoleAssignment::Entity::find_active()
        .filter(UserRoleAssignment::Column::RoleId.eq(group_id))
        .all(db)
        .await?
        .into_iter()
        .map(|membership| membership.user_id)
        .collect();
    Ok(User::Entity::find()
        .filter(User::Column::Id.is_in(member_ids))
        .order_by_asc(User::Column::Username)
        .all(db)
        .await?
        .into_iter()
        .map(|user| (user.id, user.username))
        .collect())
}

/// Members of `group_id` who can use `account_id` on the target now, other than through
/// `except_grant`.
async fn members_with_access(
    db: &DatabaseConnection,
    target_id: Uuid,
    account_id: Option<Uuid>,
    except_grant: Option<Uuid>,
) -> Result<HashSet<Uuid>, WarpgateError> {
    Ok(effective_assignments(
        db,
        AssignmentFilter {
            target_id: Some(target_id),
            ..Default::default()
        },
        OffsetDateTime::now_utc(),
    )
    .await?
    .into_iter()
    .filter(|a| a.usable() && a.account_id == account_id)
    .filter(|a| match (&a.source, except_grant) {
        (AssignmentSource::Group { grant_id, .. }, Some(except)) => *grant_id != except,
        _ => true,
    })
    .map(|a| a.user_id)
    .collect())
}

fn sso_managed_roles(config: &warpgate_common::WarpgateConfig) -> HashSet<String> {
    config
        .store
        .sso_providers
        .iter()
        .filter_map(|provider| provider.provider.role_mappings())
        .flat_map(|mappings| mappings.into_values().flat_map(|mapping| mapping.roles()))
        .collect()
}

pub struct AccessGroupsApi;

#[OpenApi]
impl AccessGroupsApi {
    /// The access groups (roles), with how many members and grants each has.
    #[oai(
        path = "/access-groups",
        method = "get",
        operation_id = "list_access_groups"
    )]
    async fn api_list(
        &self,
        admin: AdminContext,
    ) -> Result<ListAccessGroupsResponse, WarpgateError> {
        admin.require(AdminPermission::AccessRolesAssign)?;
        let services = admin.services();
        let db = &services.db;
        let sso = sso_managed_roles(&*services.config.lock().await);
        let memberships = UserRoleAssignment::Entity::find_active().all(db).await?;
        let grants = AccessGroupGrant::Entity::find().all(db).await?;
        let groups = Role::Entity::find()
            .order_by_asc(Role::Column::Name)
            .all(db)
            .await?
            .into_iter()
            .map(|role| AccessGroupView {
                member_count: u32::try_from(
                    memberships.iter().filter(|m| m.role_id == role.id).count(),
                )
                .unwrap_or(u32::MAX),
                grant_count: u32::try_from(grants.iter().filter(|g| g.role_id == role.id).count())
                    .unwrap_or(u32::MAX),
                sso_managed: sso.contains(&role.name),
                id: role.id,
                name: role.name,
                description: role.description,
                is_default: role.is_default,
            })
            .collect();
        Ok(ListAccessGroupsResponse::Ok(Json(groups)))
    }

    /// What a group grants.
    #[oai(
        path = "/access-groups/:id/grants",
        method = "get",
        operation_id = "list_access_group_grants"
    )]
    async fn api_grants(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
    ) -> Result<ListAccessGroupGrantsResponse, WarpgateError> {
        admin.require(AdminPermission::AccessRolesAssign)?;
        let db = &admin.services().db;
        if Role::Entity::find_by_id(id.0).one(db).await?.is_none() {
            return Ok(ListAccessGroupGrantsResponse::NotFound);
        }
        let mut grants = vec![];
        for grant in AccessGroupGrant::Entity::find()
            .filter(AccessGroupGrant::Column::RoleId.eq(id.0))
            .order_by_asc(AccessGroupGrant::Column::CreatedAt)
            .all(db)
            .await?
        {
            grants.push(present_grant(db, &grant).await?);
        }
        Ok(ListAccessGroupGrantsResponse::Ok(Json(grants)))
    }

    /// Let a group's members connect to a target as an account. With `dry_run`, only say
    /// who would gain access.
    #[oai(
        path = "/access-groups/:id/grants",
        method = "post",
        operation_id = "create_access_group_grant"
    )]
    async fn api_add_grant(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
        body: Json<CreateAccessGroupGrantRequest>,
    ) -> Result<ChangeAccessGroupGrantResponse, WarpgateError> {
        admin.require(AdminPermission::AccessRolesAssign)?;
        let db = &admin.services().db;
        let body = body.0;
        let Some(group) = Role::Entity::find_by_id(id.0).one(db).await? else {
            return Ok(ChangeAccessGroupGrantResponse::NotFound);
        };
        let with_access = members_with_access(db, body.target_id, body.account_id, None).await?;
        let gaining: Vec<String> = members_of(db, group.id)
            .await?
            .into_iter()
            .filter(|(user_id, _)| !with_access.contains(user_id))
            .map(|(_, username)| username)
            .collect();
        let target_name = Target::Entity::find_by_id(body.target_id)
            .one(db)
            .await?
            .map(|target| target.name)
            .unwrap_or_default();
        let account = account_name(db, body.account_id).await;
        let summary = format!(
            "{} {} member(s) of {} access to {}{}",
            if body.dry_run { "Would give" } else { "Gave" },
            gaining.len(),
            group.name,
            target_name,
            if account.is_empty() {
                String::new()
            } else {
                format!(" as {account}")
            }
        );
        if body.dry_run {
            return Ok(ChangeAccessGroupGrantResponse::Ok(Json(
                AccessGroupGrantChange {
                    grant: None,
                    affected_users: gaining,
                    summary,
                    applied: false,
                },
            )));
        }
        let grant = match access_groups::add_grant(
            db,
            group.id,
            body.target_id,
            body.account_id,
            Some(admin.auth.user_id()),
        )
        .await
        {
            Ok(grant) => grant,
            Err(ResourceError::NotFound) => return Ok(ChangeAccessGroupGrantResponse::NotFound),
            Err(ResourceError::RoleAlreadyAssigned) => {
                return Ok(ChangeAccessGroupGrantResponse::Conflict(Json(
                    "The group already grants this account on this target.".into(),
                )));
            }
            Err(error) => match resource_message(&error) {
                Some(message) => {
                    return Ok(ChangeAccessGroupGrantResponse::BadRequest(Json(message)));
                }
                None => return Err(error.into()),
            },
        };
        AuditEvent::AccessGroupGrantChanged {
            action: "added".into(),
            group_id: group.id,
            group_name: group.name.clone(),
            target_id: grant.target_id,
            target_name,
            account,
            account_id: grant.target_account_id,
            affected_users: gaining.join(", "),
            actor_user_id: admin.auth.user_id(),
        }
        .emit();
        Ok(ChangeAccessGroupGrantResponse::Ok(Json(
            AccessGroupGrantChange {
                grant: Some(present_grant(db, &grant).await?),
                affected_users: gaining,
                summary,
                applied: true,
            },
        )))
    }

    /// Stop a group granting a target and account. Members who had it through nothing else
    /// lose it, and their sessions on the target end. With `dry_run`, only say who.
    #[oai(
        path = "/access-groups/:id/grants/:grant_id",
        method = "delete",
        operation_id = "delete_access_group_grant"
    )]
    async fn api_remove_grant(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
        grant_id: Path<Uuid>,
        dry_run: Query<Option<bool>>,
    ) -> Result<ChangeAccessGroupGrantResponse, WarpgateError> {
        admin.require(AdminPermission::AccessRolesAssign)?;
        let services = admin.services();
        let db = &services.db;
        let dry_run = dry_run.0.unwrap_or(false);
        let Some(group) = Role::Entity::find_by_id(id.0).one(db).await? else {
            return Ok(ChangeAccessGroupGrantResponse::NotFound);
        };
        let Some(grant) = AccessGroupGrant::Entity::find_by_id(grant_id.0)
            .one(db)
            .await?
            .filter(|grant| grant.role_id == group.id)
        else {
            return Ok(ChangeAccessGroupGrantResponse::NotFound);
        };
        let kept =
            members_with_access(db, grant.target_id, grant.target_account_id, Some(grant.id))
                .await?;
        let through_grant: HashSet<Uuid> =
            members_with_access(db, grant.target_id, grant.target_account_id, None)
                .await?
                .into_iter()
                .filter(|user_id| !kept.contains(user_id))
                .collect();
        let losing: Vec<(Uuid, String)> = members_of(db, group.id)
            .await?
            .into_iter()
            .filter(|(user_id, _)| through_grant.contains(user_id))
            .collect();
        let view = present_grant(db, &grant).await?;
        let summary = format!(
            "{} {} member(s) of {} access to {}{}",
            if dry_run {
                "Would take away"
            } else {
                "Took away"
            },
            losing.len(),
            group.name,
            view.target_name,
            view.account
                .as_ref()
                .map(|account| format!(" as {account}"))
                .unwrap_or_default()
        );
        let affected_users: Vec<String> = losing.iter().map(|(_, name)| name.clone()).collect();
        if !dry_run {
            access_groups::remove_grant(db, grant.id).await?;
            AuditEvent::AccessGroupGrantChanged {
                action: "removed".into(),
                group_id: group.id,
                group_name: group.name.clone(),
                target_id: grant.target_id,
                target_name: view.target_name.clone(),
                account: view.account.clone().unwrap_or_default(),
                account_id: grant.target_account_id,
                affected_users: affected_users.join(", "),
                actor_user_id: admin.auth.user_id(),
            }
            .emit();
            end_sessions(services, losing.iter().map(|(id, _)| *id), grant.target_id).await;
        }
        Ok(ChangeAccessGroupGrantResponse::Ok(Json(
            AccessGroupGrantChange {
                grant: Some(view),
                affected_users,
                summary,
                applied: !dry_run,
            },
        )))
    }

    /// Revoke a group-derived assignment for one member: exclude them from the grant. Their
    /// direct assignments and the group's other members are untouched.
    #[oai(
        path = "/access-group-grants/:grant_id/exclusions",
        method = "post",
        operation_id = "exclude_from_access_group_grant"
    )]
    async fn api_exclude(
        &self,
        admin: AdminContext,
        grant_id: Path<Uuid>,
        body: Json<ExcludeFromGrantRequest>,
    ) -> Result<ExclusionResponse, WarpgateError> {
        admin.require(AdminPermission::AccessRolesAssign)?;
        let services = admin.services();
        let db = &services.db;
        let Some(grant) = AccessGroupGrant::Entity::find_by_id(grant_id.0)
            .one(db)
            .await?
        else {
            return Ok(ExclusionResponse::NotFound);
        };
        let Some(user) = User::Entity::find_by_id(body.user_id).one(db).await? else {
            return Ok(ExclusionResponse::NotFound);
        };
        let actor = admin.auth.user_id();
        if let Err(error) =
            access_groups::exclude_member(db, &grant, user.id, body.note.trim(), Some(actor)).await
        {
            return match error {
                ResourceError::RoleAlreadyAssigned => Ok(ExclusionResponse::Conflict(Json(
                    "The user is already excluded from this grant.".into(),
                ))),
                error => Err(error.into()),
            };
        }
        let group_name = Role::Entity::find_by_id(grant.role_id)
            .one(db)
            .await?
            .map(|role| role.name)
            .unwrap_or_default();
        let view = present_grant(db, &grant).await?;
        let account = view.account.clone().unwrap_or_default();
        AuditEvent::AccessAssignmentChanged {
            action: "excluded".into(),
            assignment_id: None,
            user_id: user.id,
            username: user.username.clone(),
            target_id: grant.target_id,
            target_name: view.target_name.clone(),
            account: account.clone(),
            account_id: grant.target_account_id,
            source: format!("group {group_name}"),
            previous_state: "granted by the group".into(),
            new_state: "excluded for this user".into(),
            actor_user_id: Some(actor),
        }
        .emit();
        end_sessions(services, [user.id], grant.target_id).await;
        let lookup = Lookup::load(db).await?;
        let effective = effective_assignments(
            db,
            AssignmentFilter {
                user_id: Some(user.id),
                target_id: Some(grant.target_id),
                group_id: Some(grant.role_id),
                ..Default::default()
            },
            OffsetDateTime::now_utc(),
        )
        .await?;
        match effective.iter().find(|a| {
            matches!(&a.source, AssignmentSource::Group { grant_id, .. } if *grant_id == grant.id)
        }) {
            Some(assignment) => Ok(ExclusionResponse::Ok(Json(lookup.present(assignment)))),
            // Not a member (any more): the exclusion stands, for if they become one.
            None => Ok(ExclusionResponse::Removed),
        }
    }

    /// Put an excluded member back into a group's grant.
    #[oai(
        path = "/access-group-exclusions/:id",
        method = "delete",
        operation_id = "delete_access_group_exclusion"
    )]
    async fn api_include(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
    ) -> Result<ExclusionResponse, WarpgateError> {
        admin.require(AdminPermission::AccessRolesAssign)?;
        let db = &admin.services().db;
        let exclusion = match access_groups::include_member(db, id.0).await {
            Ok(exclusion) => exclusion,
            Err(ResourceError::NotFound) => return Ok(ExclusionResponse::NotFound),
            Err(error) => return Err(error.into()),
        };
        let lookup = Lookup::load(db).await?;
        let group_name = Role::Entity::find_by_id(exclusion.role_id)
            .one(db)
            .await?
            .map(|role| role.name)
            .unwrap_or_default();
        AuditEvent::AccessAssignmentChanged {
            action: "restored".into(),
            assignment_id: None,
            user_id: exclusion.user_id,
            username: lookup
                .users
                .get(&exclusion.user_id)
                .cloned()
                .unwrap_or_default(),
            target_id: exclusion.target_id,
            target_name: lookup
                .targets
                .get(&exclusion.target_id)
                .map(|(name, _)| name.clone())
                .unwrap_or_default(),
            account: account_name(db, exclusion.target_account_id).await,
            account_id: exclusion.target_account_id,
            source: format!("group {group_name}"),
            previous_state: "excluded for this user".into(),
            new_state: "granted by the group".into(),
            actor_user_id: Some(admin.auth.user_id()),
        }
        .emit();
        Ok(ExclusionResponse::Removed)
    }
}

// ---------------------------------------------------------------------------------------
// Migration review
// ---------------------------------------------------------------------------------------

/// A permission the access-control migration looked at.
#[derive(Object)]
struct MigrationReviewView {
    id: Uuid,
    category: MigrationCategory,
    status: MigrationStatus,
    user_id: Option<Uuid>,
    username: Option<String>,
    group_id: Option<Uuid>,
    group_name: Option<String>,
    target_id: Option<Uuid>,
    target_name: Option<String>,
    /// The earlier permission, in words.
    legacy_permission: String,
    /// What the migration did, or why it could not.
    reason: String,
    /// The accounts an administrator may choose from.
    candidates: Vec<AssignableAccountRef>,
    /// The group's membership is managed by an SSO provider's role mappings.
    sso_managed: bool,
    resolution: String,
    resolved_by: Option<Uuid>,
    resolved_at: Option<OffsetDateTime>,
    created_at: OffsetDateTime,
}

#[derive(Object)]
struct AssignableAccountRef {
    id: Uuid,
    account: String,
}

#[derive(Object)]
struct ConfirmMigrationReviewRequest {
    /// The account to grant; required on a target with accounts.
    account_id: Option<Uuid>,
    #[oai(default)]
    note: String,
}

#[derive(Object)]
struct RejectMigrationReviewRequest {
    #[oai(default)]
    note: String,
}

#[derive(ApiResponse)]
enum ListMigrationReviewsResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<MigrationReviewView>>),
}

#[derive(ApiResponse)]
enum ResolveMigrationReviewResponse {
    #[oai(status = 200)]
    Ok(Json<MigrationReviewView>),
    #[oai(status = 400)]
    BadRequest(Json<String>),
    #[oai(status = 404)]
    NotFound,
    #[oai(status = 409)]
    Conflict(Json<String>),
}

async fn present_review(
    db: &DatabaseConnection,
    lookup: &Lookup,
    groups: &HashMap<Uuid, String>,
    sso: &HashSet<String>,
    review: &AccessMigrationReview::Model,
) -> MigrationReviewView {
    let mut candidates = vec![];
    for id in review.candidate_accounts() {
        let account = account_name(db, Some(id)).await;
        if !account.is_empty() {
            candidates.push(AssignableAccountRef { id, account });
        }
    }
    let group_name = review.role_id.and_then(|id| groups.get(&id).cloned());
    MigrationReviewView {
        id: review.id,
        category: review.category,
        status: review.status,
        user_id: review.user_id,
        username: review.user_id.and_then(|id| lookup.users.get(&id).cloned()),
        sso_managed: group_name.as_ref().is_some_and(|name| sso.contains(name)),
        group_id: review.role_id,
        group_name,
        target_id: review.target_id,
        target_name: review
            .target_id
            .and_then(|id| lookup.targets.get(&id).map(|(name, _)| name.clone())),
        legacy_permission: review.legacy_permission.clone(),
        reason: review.reason.clone(),
        candidates,
        resolution: review.resolution.clone(),
        resolved_by: review.resolved_by,
        resolved_at: review.resolved_at,
        created_at: review.created_at,
    }
}

async fn review_context(
    services: &Services,
) -> Result<(Lookup, HashMap<Uuid, String>, HashSet<String>), WarpgateError> {
    let db = &services.db;
    let lookup = Lookup::load(db).await?;
    let groups = Role::Entity::find()
        .all(db)
        .await?
        .into_iter()
        .map(|role| (role.id, role.name))
        .collect();
    let sso = sso_managed_roles(&*services.config.lock().await);
    Ok((lookup, groups, sso))
}

pub struct MigrationReviewApi;

#[OpenApi]
impl MigrationReviewApi {
    /// The access-control migration's report; `status` filters it (`pending` for what waits
    /// for a decision).
    #[oai(
        path = "/access-migration/reviews",
        method = "get",
        operation_id = "list_access_migration_reviews"
    )]
    async fn api_list(
        &self,
        admin: AdminContext,
        status: Query<Option<MigrationStatus>>,
    ) -> Result<ListMigrationReviewsResponse, WarpgateError> {
        admin.require(AdminPermission::AccessRolesAssign)?;
        let services = admin.services();
        let db = &services.db;
        let mut query = AccessMigrationReview::Entity::find();
        if let Some(status) = status.0 {
            query = query.filter(AccessMigrationReview::Column::Status.eq(status));
        }
        let reviews = query
            .order_by_asc(AccessMigrationReview::Column::CreatedAt)
            .all(db)
            .await?;
        let (lookup, groups, sso) = review_context(services).await?;
        let mut presented = vec![];
        for review in &reviews {
            presented.push(present_review(db, &lookup, &groups, &sso, review).await);
        }
        Ok(ListMigrationReviewsResponse::Ok(Json(presented)))
    }

    /// Confirm a pending item with the account to grant: a direct assignment for a user's
    /// permission, a group grant for a group's.
    #[oai(
        path = "/access-migration/reviews/:id/confirm",
        method = "post",
        operation_id = "confirm_access_migration_review"
    )]
    async fn api_confirm(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
        body: Json<ConfirmMigrationReviewRequest>,
    ) -> Result<ResolveMigrationReviewResponse, WarpgateError> {
        admin.require(AdminPermission::AccessRolesAssign)?;
        let services = admin.services();
        let db = &services.db;
        let body = body.0;
        let Some(review) = AccessMigrationReview::Entity::find_by_id(id.0)
            .one(db)
            .await?
        else {
            return Ok(ResolveMigrationReviewResponse::NotFound);
        };
        if review.status != MigrationStatus::Pending {
            return Ok(ResolveMigrationReviewResponse::Conflict(Json(
                "This item was already decided.".into(),
            )));
        }
        let Some(target_id) = review.target_id else {
            return Ok(ResolveMigrationReviewResponse::BadRequest(Json(
                "The item names no target.".into(),
            )));
        };
        let actor = admin.auth.user_id();
        let resolution = match (review.user_id, review.role_id) {
            (Some(user_id), _) => {
                match create_direct(
                    db,
                    user_id,
                    target_id,
                    body.account_id,
                    true,
                    None,
                    &format!("Confirmed in the migration review. {}", body.note.trim()),
                    AssignmentOrigin::Review,
                    actor,
                )
                .await?
                {
                    Ok(_) => "Granted as a direct assignment.".to_owned(),
                    Err(SaveAccessAssignmentResponse::BadRequest(message))
                    | Err(SaveAccessAssignmentResponse::Conflict(message))
                    | Err(SaveAccessAssignmentResponse::NotFound(message)) => {
                        return Ok(ResolveMigrationReviewResponse::BadRequest(message));
                    }
                    Err(SaveAccessAssignmentResponse::Ok(_)) => String::new(),
                }
            }
            (None, Some(group_id)) => {
                match access_groups::add_grant(
                    db,
                    group_id,
                    target_id,
                    body.account_id,
                    Some(actor),
                )
                .await
                {
                    Ok(grant) => {
                        let group_name = Role::Entity::find_by_id(group_id)
                            .one(db)
                            .await?
                            .map(|role| role.name)
                            .unwrap_or_default();
                        AuditEvent::AccessGroupGrantChanged {
                            action: "added".into(),
                            group_id,
                            group_name,
                            target_id,
                            target_name: Target::Entity::find_by_id(target_id)
                                .one(db)
                                .await?
                                .map(|target| target.name)
                                .unwrap_or_default(),
                            account: account_name(db, grant.target_account_id).await,
                            account_id: grant.target_account_id,
                            affected_users: "the group's members (migration review)".into(),
                            actor_user_id: actor,
                        }
                        .emit();
                        "Granted to the access group.".to_owned()
                    }
                    Err(error) => {
                        return match resource_message(&error) {
                            Some(message) => {
                                Ok(ResolveMigrationReviewResponse::BadRequest(Json(message)))
                            }
                            None => Err(error.into()),
                        };
                    }
                }
            }
            (None, None) => {
                return Ok(ResolveMigrationReviewResponse::BadRequest(Json(
                    "The item names no user or group.".into(),
                )));
            }
        };
        let resolved =
            resolve_review(db, review, MigrationStatus::Confirmed, &resolution, actor).await?;
        AuditEvent::AccessMigrationReviewResolved {
            review_id: resolved.id,
            decision: "confirmed".into(),
            target_id: resolved.target_id,
            user_id: resolved.user_id,
            group_id: resolved.role_id,
            account_id: body.account_id,
            actor_user_id: actor,
        }
        .emit();
        let (lookup, groups, sso) = review_context(services).await?;
        Ok(ResolveMigrationReviewResponse::Ok(Json(
            present_review(db, &lookup, &groups, &sso, &resolved).await,
        )))
    }

    /// Decide a pending item grants nothing.
    #[oai(
        path = "/access-migration/reviews/:id/reject",
        method = "post",
        operation_id = "reject_access_migration_review"
    )]
    async fn api_reject(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
        body: Json<RejectMigrationReviewRequest>,
    ) -> Result<ResolveMigrationReviewResponse, WarpgateError> {
        admin.require(AdminPermission::AccessRolesAssign)?;
        let services = admin.services();
        let db = &services.db;
        let Some(review) = AccessMigrationReview::Entity::find_by_id(id.0)
            .one(db)
            .await?
        else {
            return Ok(ResolveMigrationReviewResponse::NotFound);
        };
        if review.status != MigrationStatus::Pending {
            return Ok(ResolveMigrationReviewResponse::Conflict(Json(
                "This item was already decided.".into(),
            )));
        }
        let actor = admin.auth.user_id();
        let note = body.note.trim();
        let resolution = if note.is_empty() {
            "Rejected: grants nothing.".to_owned()
        } else {
            format!("Rejected: grants nothing. {note}")
        };
        let resolved =
            resolve_review(db, review, MigrationStatus::Rejected, &resolution, actor).await?;
        AuditEvent::AccessMigrationReviewResolved {
            review_id: resolved.id,
            decision: "rejected".into(),
            target_id: resolved.target_id,
            user_id: resolved.user_id,
            group_id: resolved.role_id,
            account_id: None,
            actor_user_id: actor,
        }
        .emit();
        let (lookup, groups, sso) = review_context(services).await?;
        Ok(ResolveMigrationReviewResponse::Ok(Json(
            present_review(db, &lookup, &groups, &sso, &resolved).await,
        )))
    }
}

async fn resolve_review(
    db: &DatabaseConnection,
    review: AccessMigrationReview::Model,
    status: MigrationStatus,
    resolution: &str,
    actor: Uuid,
) -> Result<AccessMigrationReview::Model, WarpgateError> {
    let mut model: AccessMigrationReview::ActiveModel = review.into();
    model.status = Set(status);
    model.resolution = Set(resolution.to_owned());
    model.resolved_by = Set(Some(actor));
    model.resolved_at = Set(Some(OffsetDateTime::now_utc()));
    Ok(model.update(db).await?)
}

#[cfg(test)]
mod tests {
    use time::OffsetDateTime;
    use uuid::Uuid;
    use warpgate_db_entities::TargetAccount::{self, TargetAccountAuthMethod, TargetAccountKind};

    use super::{account_label, describe_state};

    fn account(name: &str, domain: Option<&str>, kind: TargetAccountKind) -> TargetAccount::Model {
        let now = OffsetDateTime::now_utc();
        TargetAccount::Model {
            id: Uuid::nil(),
            target_id: Uuid::nil(),
            kind,
            name: name.into(),
            domain: domain.map(Into::into),
            auth_method: TargetAccountAuthMethod::TypedPassword,
            credential: None,
            username_format: None,
            enabled: true,
            is_primary: false,
            description: String::new(),
            account_key: String::new(),
            created_by: None,
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn accounts_read_as_people_write_them() {
        assert_eq!(
            account_label(&account(
                "support",
                Some("WIN-SRV-01"),
                TargetAccountKind::Local
            )),
            "WIN-SRV-01\\support"
        );
        assert_eq!(
            account_label(&account(
                r"CORP\sqladmin",
                Some("IGNORED"),
                TargetAccountKind::Domain
            )),
            r"CORP\sqladmin"
        );
        assert_eq!(
            account_label(&account("", None, TargetAccountKind::Directory)),
            "Linked directory account (each user's own)"
        );
    }

    #[test]
    fn states_are_described_without_secrets() {
        let described = describe_state(false, None, "deploy");
        assert_eq!(described, "disabled, never expires, account deploy");
    }
}
