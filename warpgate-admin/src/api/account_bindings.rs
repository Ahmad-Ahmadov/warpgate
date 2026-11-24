//! Account access: assigning remote accounts to users on targets (Access Control).
//!
//! Every endpoint needs [`AdminPermission::AccessRolesAssign`], the permission that already
//! governs who may reach what. An assignment never grants access to a target by itself: the
//! user's roles still decide that, and the response says when they do not allow it yet.
//! Revoking, disabling or changing an assignment ends the user's live sessions on the
//! target, so a session never outlives the decision that let it sign in.

use poem_openapi::param::{Path, Query};
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, QueryOrder, Set};
use time::OffsetDateTime;
use tracing::warn;
use uuid::Uuid;
use warpgate_common::audit::AuditEvent;
use warpgate_common::{AdminPermission, TargetOptions, WarpgateError};
use warpgate_core::ConfigProvider;
use warpgate_core::account_binding::{
    BindingProtocol, BoundTarget, DirectoryUsernameFormat, TargetAccountAuthMethod,
    TargetAccountKind, TargetCredential, check_combination, close_sessions_on_target, methods_for,
    unusable_because,
};
use warpgate_core::rdp_account::directory_account_names;
use warpgate_db_entities::TargetAccountBinding::{self, Model as Binding};
use warpgate_db_entities::{Target, User};

use super::AdminContext;

/// The longest local account name taken: what an RDP Client Info PDU carries.
const MAX_ACCOUNT_NAME_CHARS: usize = 256;

/// A remote account assigned to a user on a target.
#[derive(Object)]
struct AccountBinding {
    id: Uuid,
    user_id: Uuid,
    /// Empty if the user has been deleted.
    username: String,
    target_id: Uuid,
    /// Empty if the target has been deleted.
    target_name: String,
    /// `rdp` or `ssh`.
    protocol: String,
    account_kind: TargetAccountKind,
    /// A local account's name, as configured. Directory accounts are read from the
    /// directory, and managed ones are the target's.
    account_name: Option<String>,
    /// The target's configured account, for a managed assignment.
    managed_account: Option<String>,
    username_format: Option<DirectoryUsernameFormat>,
    auth_method: TargetAccountAuthMethod,
    enabled: bool,
    expires_at: Option<OffsetDateTime>,
    created_by: Option<Uuid>,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    /// Why the assignment cannot be used now (disabled, expired, the user's directory link
    /// changed, the target no longer authenticates this way), if it cannot.
    problem: Option<String>,
    /// Whether the user's roles let them reach the target at all. An assignment does not.
    has_target_access: bool,
}

#[derive(Object)]
struct CreateAccountBindingRequest {
    user_id: Uuid,
    target_id: Uuid,
    account_kind: TargetAccountKind,
    /// A local account's name: `name`, or `COMPUTER\name` on a Windows target. Not taken for
    /// a directory or managed account.
    #[oai(validator(max_length = 256))]
    account_name: Option<String>,
    // How a directory account is named to the target; not taken for other accounts. A plain
    // comment: a field description wraps the enum in allOf, which typescript-fetch
    // misgenerates.
    username_format: Option<DirectoryUsernameFormat>,
    auth_method: TargetAccountAuthMethod,
    #[oai(default = "default_enabled")]
    enabled: bool,
    expires_at: Option<OffsetDateTime>,
}

const fn default_enabled() -> bool {
    true
}

#[derive(Object)]
struct UpdateAccountBindingRequest {
    #[oai(validator(max_length = 256))]
    account_name: Option<String>,
    username_format: Option<DirectoryUsernameFormat>,
    auth_method: TargetAccountAuthMethod,
    enabled: bool,
    expires_at: Option<OffsetDateTime>,
}

/// A way an account of some kind can sign in to a target.
#[derive(Object)]
struct AccountKindOption {
    account_kind: TargetAccountKind,
    /// The authentication methods it can use there; empty when the kind cannot be used.
    auth_methods: Vec<TargetAccountAuthMethod>,
    /// Why it cannot be used, when it cannot.
    problem: Option<String>,
}

/// A directory account name in one of the formats a target may know it by.
#[derive(Object)]
struct DirectoryAccountName {
    format: DirectoryUsernameFormat,
    account: String,
}

/// What can be assigned to a user on a target.
#[derive(Object)]
struct AccountBindingOptions {
    /// `rdp` or `ssh`.
    protocol: String,
    has_target_access: bool,
    /// Whether the user is linked to a directory entry.
    directory_linked: bool,
    /// The user's directory account, as each format names it, read from the directory now.
    directory_accounts: Vec<DirectoryAccountName>,
    /// Why the directory account could not be read, when it could not.
    directory_problem: Option<String>,
    /// Local accounts configured for this target: an RDP target's assignable accounts, and
    /// names already assigned to someone on it. Configured, not checked on the server.
    local_accounts: Vec<String>,
    /// The target's own account, for a managed assignment.
    managed_account: Option<String>,
    kinds: Vec<AccountKindOption>,
}

#[derive(ApiResponse)]
enum ListAccountBindingsResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<AccountBinding>>),
}

#[derive(ApiResponse)]
enum CreateAccountBindingResponse {
    #[oai(status = 201)]
    Created(Json<AccountBinding>),
    #[oai(status = 400)]
    BadRequest(Json<String>),
    #[oai(status = 404)]
    NotFound(Json<String>),
    #[oai(status = 409)]
    Conflict(Json<String>),
}

#[derive(ApiResponse)]
enum UpdateAccountBindingResponse {
    #[oai(status = 200)]
    Ok(Json<AccountBinding>),
    #[oai(status = 400)]
    BadRequest(Json<String>),
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum DeleteAccountBindingResponse {
    #[oai(status = 204)]
    Deleted,
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum GetAccountBindingOptionsResponse {
    #[oai(status = 200)]
    Ok(Json<AccountBindingOptions>),
    #[oai(status = 400)]
    BadRequest(Json<String>),
    #[oai(status = 404)]
    NotFound(Json<String>),
}

/// A target bindings apply to: its model and options, or why it is not one.
struct BindableTarget {
    model: Target::Model,
    options: TargetOptions,
}

impl BindableTarget {
    async fn find(
        db: &sea_orm::DatabaseConnection,
        id: Uuid,
    ) -> Result<Option<Self>, WarpgateError> {
        let Some(model) = Target::Entity::find_by_id(id).one(db).await? else {
            return Ok(None);
        };
        let options: TargetOptions = serde_json::from_value(model.options.clone())?;
        Ok(Some(Self { model, options }))
    }

    fn bound(&self) -> Option<BoundTarget<'_>> {
        BoundTarget::of(self.model.id, &self.model.name, &self.options)
    }

    /// The target's configured account, where it has one to assign.
    fn managed_account(&self) -> Option<String> {
        match &self.options {
            TargetOptions::Rdp(options) => {
                (TargetCredential::rdp(options) == TargetCredential::RdpStoredPassword).then(|| {
                    match options.domain.as_deref().filter(|d| !d.is_empty()) {
                        Some(domain) => format!("{domain}\\{}", options.username),
                        None => options.username.clone(),
                    }
                })
            }
            TargetOptions::Ssh(options) => Some(if options.username.is_empty() {
                "(the user's Warpgate username)".to_owned()
            } else {
                options.username.clone()
            }),
            _ => None,
        }
    }
}

/// A local account name as an administrator typed it, or why it cannot be one.
fn local_account_name(name: Option<&str>) -> Result<String, &'static str> {
    let name = name.map(str::trim).unwrap_or_default();
    if name.is_empty() {
        return Err("Enter the local account's name.");
    }
    if name.chars().count() > MAX_ACCOUNT_NAME_CHARS {
        return Err("The account name is too long.");
    }
    if name.chars().any(char::is_control) {
        return Err("The account name contains control characters.");
    }
    Ok(name.to_owned())
}

async fn present(
    admin: &AdminContext,
    binding: Binding,
    now: OffsetDateTime,
) -> Result<AccountBinding, WarpgateError> {
    let db = &admin.services().db;
    let user = User::Entity::find_by_id(binding.user_id).one(db).await?;
    let target = BindableTarget::find(db, binding.target_id).await?;
    let problem = match (&user, target.as_ref().and_then(BindableTarget::bound)) {
        (Some(user), Some(bound)) => {
            unusable_because(&binding, user, bound.protocol, bound.credential, now)
                .map(str::to_owned)
        }
        _ => Some("the user or target no longer exists".to_owned()),
    };
    let has_target_access = admin
        .services()
        .config_provider
        .authorize_target_by_id(binding.user_id, binding.target_id)
        .await
        .unwrap_or(false);
    Ok(AccountBinding {
        id: binding.id,
        user_id: binding.user_id,
        username: user.map(|user| user.username).unwrap_or_default(),
        target_id: binding.target_id,
        target_name: target
            .as_ref()
            .map(|target| target.model.name.clone())
            .unwrap_or_default(),
        protocol: target
            .as_ref()
            .and_then(BindableTarget::bound)
            .map(|bound| bound.protocol.as_str().to_owned())
            .unwrap_or_default(),
        account_kind: binding.account_kind,
        managed_account: (binding.account_kind == TargetAccountKind::Managed)
            .then(|| target.as_ref().and_then(BindableTarget::managed_account))
            .flatten(),
        account_name: binding.account_name,
        username_format: binding.username_format,
        auth_method: binding.auth_method,
        enabled: binding.enabled,
        expires_at: binding.expires_at,
        created_by: binding.created_by,
        created_at: binding.created_at,
        updated_at: binding.updated_at,
        problem,
        has_target_access,
    })
}

/// What a binding names, for the audit log: never anything secret.
fn audit_account(binding: &Binding) -> String {
    match binding.account_kind {
        TargetAccountKind::Local => binding.account_name.clone().unwrap_or_default(),
        TargetAccountKind::Managed => "managed account".to_owned(),
        TargetAccountKind::Directory => format!(
            "directory entry {}",
            binding
                .ldap_object_uuid
                .map(|id| id.to_string())
                .unwrap_or_default()
        ),
    }
}

const fn method_name(method: TargetAccountAuthMethod) -> &'static str {
    match method {
        TargetAccountAuthMethod::DirectoryPassword => "directory_password",
        TargetAccountAuthMethod::TypedPassword => "typed_password",
        TargetAccountAuthMethod::TargetCredential => "target_credential",
    }
}

const fn kind_name(kind: TargetAccountKind) -> &'static str {
    match kind {
        TargetAccountKind::Directory => "directory",
        TargetAccountKind::Local => "local",
        TargetAccountKind::Managed => "managed",
    }
}

pub struct Api;

#[OpenApi]
impl Api {
    /// The remote accounts assigned to users on targets, filtered by user or target.
    #[oai(
        path = "/account-bindings",
        method = "get",
        operation_id = "list_account_bindings"
    )]
    async fn api_list_account_bindings(
        &self,
        admin: AdminContext,
        user_id: Query<Option<Uuid>>,
        target_id: Query<Option<Uuid>>,
    ) -> Result<ListAccountBindingsResponse, WarpgateError> {
        admin.require(AdminPermission::AccessRolesAssign)?;
        let db = &admin.services().db;
        let mut query = TargetAccountBinding::Entity::find();
        if let Some(user_id) = user_id.0 {
            query = query.filter(TargetAccountBinding::Column::UserId.eq(user_id));
        }
        if let Some(target_id) = target_id.0 {
            query = query.filter(TargetAccountBinding::Column::TargetId.eq(target_id));
        }
        let bindings = query
            .order_by_asc(TargetAccountBinding::Column::CreatedAt)
            .all(db)
            .await?;
        let now = OffsetDateTime::now_utc();
        let mut presented = Vec::with_capacity(bindings.len());
        for binding in bindings {
            presented.push(present(&admin, binding, now).await?);
        }
        Ok(ListAccountBindingsResponse::Ok(Json(presented)))
    }

    /// What can be assigned to a user on a target: the user's directory account as the
    /// directory names it now, the target's configured local and managed accounts, and the
    /// authentication methods each kind can use there.
    #[oai(
        path = "/account-bindings/options",
        method = "get",
        operation_id = "get_account_binding_options"
    )]
    async fn api_get_account_binding_options(
        &self,
        admin: AdminContext,
        user_id: Query<Uuid>,
        target_id: Query<Uuid>,
    ) -> Result<GetAccountBindingOptionsResponse, WarpgateError> {
        admin.require(AdminPermission::AccessRolesAssign)?;
        let db = &admin.services().db;
        let Some(user) = User::Entity::find_by_id(user_id.0).one(db).await? else {
            return Ok(GetAccountBindingOptionsResponse::NotFound(Json(
                "User not found".into(),
            )));
        };
        let Some(target) = BindableTarget::find(db, target_id.0).await? else {
            return Ok(GetAccountBindingOptionsResponse::NotFound(Json(
                "Target not found".into(),
            )));
        };
        let Some(bound) = target.bound() else {
            return Ok(GetAccountBindingOptionsResponse::BadRequest(Json(
                "Accounts can be assigned on RDP and SSH targets only".into(),
            )));
        };
        let directory_linked = user.ldap_server_id.is_some() && user.ldap_object_uuid.is_some();
        let (directory_accounts, directory_problem) = if directory_linked {
            match directory_account_names(db, user.id).await {
                Ok(names) => (
                    names
                        .into_iter()
                        .map(|(format, account)| DirectoryAccountName { format, account })
                        .collect(),
                    None,
                ),
                Err(error) => (vec![], Some(error.to_string())),
            }
        } else {
            (
                vec![],
                Some("The user is not linked to a directory account".to_owned()),
            )
        };

        let mut local_accounts: Vec<String> = match &target.options {
            TargetOptions::Rdp(options) => match &options.auth {
                warpgate_common::RdpTargetAuth::LocalAccount(auth) => auth
                    .accounts
                    .iter()
                    .map(|account| account.username.trim().to_owned())
                    .filter(|name| !name.is_empty())
                    .collect(),
                _ => vec![],
            },
            _ => vec![],
        };
        for binding in TargetAccountBinding::Entity::find()
            .filter(TargetAccountBinding::Column::TargetId.eq(target.model.id))
            .filter(TargetAccountBinding::Column::AccountKind.eq(TargetAccountKind::Local))
            .all(db)
            .await?
        {
            if let Some(name) = binding.account_name
                && !local_accounts
                    .iter()
                    .any(|known| known.eq_ignore_ascii_case(&name))
            {
                local_accounts.push(name);
            }
        }

        let kinds = [
            TargetAccountKind::Directory,
            TargetAccountKind::Local,
            TargetAccountKind::Managed,
        ]
        .into_iter()
        .map(|kind| {
            let auth_methods = methods_for(bound.protocol, kind, bound.credential);
            let problem = if kind == TargetAccountKind::Directory && !directory_linked {
                Some("The user is not linked to a directory account".to_owned())
            } else if auth_methods.is_empty() {
                Some(match (bound.protocol, kind) {
                    (BindingProtocol::Rdp, TargetAccountKind::Managed) => {
                        "The target has no stored password to sign in with".to_owned()
                    }
                    _ => "The target's credential cannot sign in to other accounts: use Warpgate's SSH keys or a Vault-signed certificate".to_owned(),
                })
            } else {
                None
            };
            AccountKindOption {
                account_kind: kind,
                auth_methods: if problem.is_some() { vec![] } else { auth_methods },
                problem,
            }
        })
        .collect();

        let has_target_access = admin
            .services()
            .config_provider
            .authorize_target_by_id(user.id, target.model.id)
            .await
            .unwrap_or(false);

        Ok(GetAccountBindingOptionsResponse::Ok(Json(
            AccountBindingOptions {
                protocol: bound.protocol.as_str().to_owned(),
                has_target_access,
                directory_linked,
                directory_accounts,
                directory_problem,
                local_accounts,
                managed_account: target.managed_account(),
                kinds,
            },
        )))
    }

    /// Assign a remote account to a user on a target.
    #[oai(
        path = "/account-bindings",
        method = "post",
        operation_id = "create_account_binding"
    )]
    async fn api_create_account_binding(
        &self,
        admin: AdminContext,
        body: Json<CreateAccountBindingRequest>,
    ) -> Result<CreateAccountBindingResponse, WarpgateError> {
        admin.require(AdminPermission::AccessRolesAssign)?;
        let db = &admin.services().db;
        let body = body.0;
        let Some(user) = User::Entity::find_by_id(body.user_id).one(db).await? else {
            return Ok(CreateAccountBindingResponse::NotFound(Json(
                "User not found".into(),
            )));
        };
        let Some(target) = BindableTarget::find(db, body.target_id).await? else {
            return Ok(CreateAccountBindingResponse::NotFound(Json(
                "Target not found".into(),
            )));
        };
        let Some(bound) = target.bound() else {
            return Ok(CreateAccountBindingResponse::BadRequest(Json(
                "Accounts can be assigned on RDP and SSH targets only".into(),
            )));
        };
        if let Err(error) = check_combination(
            bound.protocol,
            body.account_kind,
            body.auth_method,
            bound.credential,
        ) {
            return Ok(CreateAccountBindingResponse::BadRequest(Json(
                error.user_message().into(),
            )));
        }

        // The account: a local one by name; a directory one as the user's link, never a
        // name; the managed one as the target's.
        let (account_name, link, username_format) = match body.account_kind {
            TargetAccountKind::Local => match local_account_name(body.account_name.as_deref()) {
                Ok(name) => (Some(name), None, None),
                Err(message) => {
                    return Ok(CreateAccountBindingResponse::BadRequest(Json(
                        message.into(),
                    )));
                }
            },
            TargetAccountKind::Directory => {
                let (Some(server), Some(entry)) = (user.ldap_server_id, user.ldap_object_uuid)
                else {
                    return Ok(CreateAccountBindingResponse::BadRequest(Json(
                        "The user is not linked to a directory account".into(),
                    )));
                };
                (None, Some((server, entry)), body.username_format)
            }
            TargetAccountKind::Managed => (None, None, None),
        };
        let account_key = Binding::key_for(
            body.account_kind,
            account_name.as_deref(),
            link.map(|(_, entry)| entry),
        );
        let duplicate = TargetAccountBinding::Entity::find()
            .filter(TargetAccountBinding::Column::UserId.eq(user.id))
            .filter(TargetAccountBinding::Column::TargetId.eq(target.model.id))
            .filter(TargetAccountBinding::Column::AccountKey.eq(account_key.clone()))
            .one(db)
            .await?;
        if duplicate.is_some() {
            return Ok(CreateAccountBindingResponse::Conflict(Json(
                "This account is already assigned to the user on this target".into(),
            )));
        }

        let now = OffsetDateTime::now_utc();
        let binding = TargetAccountBinding::ActiveModel {
            id: Set(Uuid::new_v4()),
            user_id: Set(user.id),
            target_id: Set(target.model.id),
            account_kind: Set(body.account_kind),
            account_name: Set(account_name),
            ldap_server_id: Set(link.map(|(server, _)| server)),
            ldap_object_uuid: Set(link.map(|(_, entry)| entry)),
            username_format: Set(username_format),
            auth_method: Set(body.auth_method),
            enabled: Set(body.enabled),
            expires_at: Set(body.expires_at),
            created_by: Set(Some(admin.auth.user_id())),
            created_at: Set(now),
            updated_at: Set(now),
            account_key: Set(account_key),
        }
        .insert(db)
        .await?;

        AuditEvent::AccountBindingCreated {
            binding_id: binding.id,
            user_id: user.id,
            username: user.username.clone(),
            target_id: target.model.id,
            target_name: target.model.name.clone(),
            account_kind: kind_name(binding.account_kind).to_owned(),
            account: audit_account(&binding),
            auth_method: method_name(binding.auth_method).to_owned(),
            actor_user_id: admin.auth.user_id(),
        }
        .emit();

        Ok(CreateAccountBindingResponse::Created(Json(
            present(&admin, binding, now).await?,
        )))
    }

    /// Change an assignment: its local account name, directory name format, authentication,
    /// whether it is enabled, and its expiry. The user's live sessions on the target end.
    #[oai(
        path = "/account-bindings/:id",
        method = "put",
        operation_id = "update_account_binding"
    )]
    async fn api_update_account_binding(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
        body: Json<UpdateAccountBindingRequest>,
    ) -> Result<UpdateAccountBindingResponse, WarpgateError> {
        admin.require(AdminPermission::AccessRolesAssign)?;
        let db = &admin.services().db;
        let body = body.0;
        let Some(binding) = TargetAccountBinding::Entity::find_by_id(id.0)
            .one(db)
            .await?
        else {
            return Ok(UpdateAccountBindingResponse::NotFound);
        };
        let Some(target) = BindableTarget::find(db, binding.target_id).await? else {
            return Ok(UpdateAccountBindingResponse::NotFound);
        };
        let Some(bound) = target.bound() else {
            return Ok(UpdateAccountBindingResponse::NotFound);
        };
        if let Err(error) = check_combination(
            bound.protocol,
            binding.account_kind,
            body.auth_method,
            bound.credential,
        ) {
            return Ok(UpdateAccountBindingResponse::BadRequest(Json(
                error.user_message().into(),
            )));
        }
        let mut model: TargetAccountBinding::ActiveModel = binding.clone().into();
        match binding.account_kind {
            TargetAccountKind::Local => {
                let name = match local_account_name(body.account_name.as_deref()) {
                    Ok(name) => name,
                    Err(message) => {
                        return Ok(UpdateAccountBindingResponse::BadRequest(Json(
                            message.into(),
                        )));
                    }
                };
                let key = Binding::key_for(TargetAccountKind::Local, Some(&name), None);
                if key != binding.account_key
                    && TargetAccountBinding::Entity::find()
                        .filter(TargetAccountBinding::Column::UserId.eq(binding.user_id))
                        .filter(TargetAccountBinding::Column::TargetId.eq(binding.target_id))
                        .filter(TargetAccountBinding::Column::AccountKey.eq(key.clone()))
                        .one(db)
                        .await?
                        .is_some()
                {
                    return Ok(UpdateAccountBindingResponse::BadRequest(Json(
                        "This account is already assigned to the user on this target".into(),
                    )));
                }
                model.account_name = Set(Some(name));
                model.account_key = Set(key);
            }
            TargetAccountKind::Directory => model.username_format = Set(body.username_format),
            TargetAccountKind::Managed => {}
        }
        let now = OffsetDateTime::now_utc();
        model.auth_method = Set(body.auth_method);
        model.enabled = Set(body.enabled);
        model.expires_at = Set(body.expires_at);
        model.updated_at = Set(now);
        let updated = model.update(db).await?;

        let username = User::Entity::find_by_id(updated.user_id)
            .one(db)
            .await?
            .map(|user| user.username)
            .unwrap_or_default();
        AuditEvent::AccountBindingUpdated {
            binding_id: updated.id,
            user_id: updated.user_id,
            username,
            target_id: updated.target_id,
            target_name: target.model.name.clone(),
            account: audit_account(&updated),
            enabled: updated.enabled,
            auth_method: method_name(updated.auth_method).to_owned(),
            actor_user_id: admin.auth.user_id(),
        }
        .emit();

        // A session that signed in under the old terms ends: it must not outlive them.
        if let Err(error) =
            close_sessions_on_target(admin.services(), updated.user_id, updated.target_id).await
        {
            warn!(%error, "Could not end the user's sessions after an assignment changed");
        }

        Ok(UpdateAccountBindingResponse::Ok(Json(
            present(&admin, updated, now).await?,
        )))
    }

    /// Revoke an assignment. The user's live sessions on the target end.
    #[oai(
        path = "/account-bindings/:id",
        method = "delete",
        operation_id = "delete_account_binding"
    )]
    async fn api_delete_account_binding(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
    ) -> Result<DeleteAccountBindingResponse, WarpgateError> {
        admin.require(AdminPermission::AccessRolesAssign)?;
        let db = &admin.services().db;
        let Some(binding) = TargetAccountBinding::Entity::find_by_id(id.0)
            .one(db)
            .await?
        else {
            return Ok(DeleteAccountBindingResponse::NotFound);
        };
        TargetAccountBinding::Entity::delete_by_id(binding.id)
            .exec(db)
            .await?;

        let username = User::Entity::find_by_id(binding.user_id)
            .one(db)
            .await?
            .map(|user| user.username)
            .unwrap_or_default();
        let target_name = Target::Entity::find_by_id(binding.target_id)
            .one(db)
            .await?
            .map(|target| target.name)
            .unwrap_or_default();
        AuditEvent::AccountBindingRevoked {
            binding_id: binding.id,
            user_id: binding.user_id,
            username,
            target_id: binding.target_id,
            target_name,
            account: audit_account(&binding),
            actor_user_id: admin.auth.user_id(),
        }
        .emit();

        if let Err(error) =
            close_sessions_on_target(admin.services(), binding.user_id, binding.target_id).await
        {
            warn!(%error, "Could not end the user's sessions after an assignment was revoked");
        }
        Ok(DeleteAccountBindingResponse::Deleted)
    }
}

#[cfg(test)]
mod tests {
    use super::local_account_name;

    #[test]
    fn local_account_names_are_checked() {
        assert_eq!(
            local_account_name(Some("  deploy ")).as_deref(),
            Ok("deploy")
        );
        assert!(local_account_name(Some("")).is_err());
        assert!(local_account_name(None).is_err());
        assert!(local_account_name(Some("dep\nloy")).is_err());
        assert!(local_account_name(Some(&"x".repeat(257))).is_err());
    }
}
