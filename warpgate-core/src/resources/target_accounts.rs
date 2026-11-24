//! A target's Accounts: the remote accounts Warpgate can sign in to it as.
//!
//! An account grants nobody anything: Access Control assignments decide who may use it.
//! Its credential is stored here once (encrypted, or as a secret reference) and never shown
//! again. API clients written before accounts existed still send a credential in the
//! target's own settings (`username`, `auth`, RDP `domain`): that is the target's primary
//! account, and [`sync_primary`] keeps it, while the settings themselves keep none.

use poem_openapi::Object;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, QueryOrder, Set,
    TransactionTrait,
};
use time::OffsetDateTime;
use uuid::Uuid;
use warpgate_common::{
    DatabaseTargetAuth, DatabaseTargetPasswordAuth, MaybeSecretRef, RdpTargetAuth,
    RdpTargetPasswordAuth, SSHTargetAuth, SshTargetPublicKeyAuth, StoredSecrets, Target,
    TargetAccountCredential, TargetAccountPasswordCredential, TargetOptions, WarpgateError,
};
use warpgate_db_entities::TargetAccount::{
    self, DirectoryUsernameFormat, TargetAccountAuthMethod, TargetAccountKind,
};
use warpgate_db_entities::{AccessAssignment, AccessGroupExclusion, AccessGroupGrant};

use super::ResourceError;
use crate::access_control::{check_account, protocol_of};
use crate::db::is_unique_violation;

/// The longest account name taken: what an RDP Client Info PDU carries.
pub const MAX_ACCOUNT_NAME_CHARS: usize = 256;

/// An account as an administrator sets it up.
#[derive(Object, Clone, Debug)]
pub struct TargetAccountDataRequest {
    pub kind: TargetAccountKind,
    /// `deploy`, `WIN-SRV-01\support`, `CORP\sqladmin`, `svc@corp.example.com`. Empty for a
    /// linked directory account, and, on SSH, for "the user's Warpgate username".
    #[oai(validator(max_length = 256))]
    pub name: String,
    /// RDP: the computer (local account) or the domain's NetBIOS name (directory account)
    /// the account belongs to, when its name does not say.
    #[oai(validator(max_length = 256))]
    pub domain: Option<String>,
    pub auth_method: TargetAccountAuthMethod,
    // For a stored credential; a blank password keeps the stored one. A plain comment: a
    // field description wraps the union in allOf, which typescript-fetch misgenerates.
    pub credential: Option<TargetAccountCredential>,
    // How a linked directory account is named to the target. A plain comment: a field
    // description wraps the enum in allOf, which typescript-fetch misgenerates.
    pub username_format: Option<DirectoryUsernameFormat>,
    #[oai(default = "default_true")]
    pub enabled: bool,
    /// The target's primary account (one per target): jump-host hops and ticket connections
    /// without an assignment sign in as it. It grants nobody anything.
    #[oai(default)]
    pub is_primary: bool,
    #[oai(default)]
    pub description: String,
}

const fn default_true() -> bool {
    true
}

fn clean_name(kind: TargetAccountKind, name: &str) -> Result<String, ResourceError> {
    let name = name.trim();
    if name.chars().count() > MAX_ACCOUNT_NAME_CHARS {
        return Err(ResourceError::Invalid("The account name is too long."));
    }
    if name.chars().any(char::is_control) {
        return Err(ResourceError::Invalid(
            "The account name contains control characters.",
        ));
    }
    Ok(match kind {
        // Each user's own: it has no name of its own.
        TargetAccountKind::Directory => String::new(),
        TargetAccountKind::Local | TargetAccountKind::Domain => name.to_owned(),
    })
}

/// The row an account request makes, checked: what it may sign in to the target as, and how.
fn build(
    target: &warpgate_db_entities::Target::Model,
    data: &TargetAccountDataRequest,
    existing: Option<&TargetAccount::Model>,
) -> Result<TargetAccount::Model, ResourceError> {
    let now = OffsetDateTime::now_utc();
    let name = clean_name(data.kind, &data.name)?;
    let domain = data
        .domain
        .as_deref()
        .map(str::trim)
        .filter(|domain| !domain.is_empty())
        .map(str::to_owned);
    let username_format = match data.kind {
        TargetAccountKind::Directory => {
            Some(data.username_format.unwrap_or(DirectoryUsernameFormat::Upn))
        }
        TargetAccountKind::Local | TargetAccountKind::Domain => None,
    };
    let credential = match data.auth_method {
        TargetAccountAuthMethod::StoredCredential => {
            let Some(credential) = data.credential.clone() else {
                return Err(ResourceError::Invalid("Enter the account's credential."));
            };
            let stored = existing.and_then(|existing| existing.credential().ok().flatten());
            // A blank password keeps the stored one; with none stored, it is the account's
            // password (a database user may have none).
            let mut credential = credential.keeping_stored_password(stored.as_ref());
            credential.encrypt_all().map_err(WarpgateError::from)?;
            Some(serde_json::to_value(credential).map_err(WarpgateError::from)?)
        }
        // A password the user types is never stored.
        TargetAccountAuthMethod::TypedPassword | TargetAccountAuthMethod::DirectoryPassword => None,
    };
    let model = TargetAccount::Model {
        id: existing.map_or_else(Uuid::new_v4, |existing| existing.id),
        target_id: target.id,
        kind: data.kind,
        account_key: TargetAccount::Model::key_for(data.kind, &name, username_format),
        name,
        domain,
        auth_method: data.auth_method,
        credential,
        username_format,
        enabled: data.enabled,
        is_primary: data.is_primary,
        description: data.description.trim().to_owned(),
        created_by: existing.and_then(|existing| existing.created_by),
        created_at: existing.map_or(now, |existing| existing.created_at),
        updated_at: now,
    };
    check_account(protocol_of(target.kind), &model).map_err(ResourceError::Invalid)?;
    Ok(model)
}

fn taken(error: sea_orm::DbErr) -> ResourceError {
    if is_unique_violation(&error) {
        ResourceError::AccountTaken
    } else {
        error.into()
    }
}

/// Clear the primary flag of the target's other accounts.
async fn demote_others<C: ConnectionTrait>(
    db: &C,
    target_id: Uuid,
    keep: Uuid,
) -> Result<(), ResourceError> {
    TargetAccount::Entity::update_many()
        .col_expr(
            TargetAccount::Column::IsPrimary,
            sea_orm::sea_query::Expr::value(false),
        )
        .filter(TargetAccount::Column::TargetId.eq(target_id))
        .filter(TargetAccount::Column::Id.ne(keep))
        .exec(db)
        .await?;
    Ok(())
}

async fn find_target<C: ConnectionTrait>(
    db: &C,
    target_id: Uuid,
) -> Result<warpgate_db_entities::Target::Model, ResourceError> {
    warpgate_db_entities::Target::Entity::find_by_id(target_id)
        .one(db)
        .await?
        .ok_or(ResourceError::NotFound)
}

/// The target's accounts, in the order they were added.
pub async fn list<C: ConnectionTrait>(
    db: &C,
    target_id: Uuid,
) -> Result<Vec<TargetAccount::Model>, ResourceError> {
    Ok(TargetAccount::Entity::find()
        .filter(TargetAccount::Column::TargetId.eq(target_id))
        .order_by_desc(TargetAccount::Column::IsPrimary)
        .order_by_asc(TargetAccount::Column::CreatedAt)
        .order_by_asc(TargetAccount::Column::Id)
        .all(db)
        .await?)
}

pub async fn create<C: ConnectionTrait + TransactionTrait>(
    db: &C,
    target_id: Uuid,
    data: &TargetAccountDataRequest,
    actor: Option<Uuid>,
) -> Result<TargetAccount::Model, ResourceError> {
    let txn = db.begin().await?;
    let target = find_target(&txn, target_id).await?;
    let mut model = build(&target, data, None)?;
    model.created_by = actor;
    let model: TargetAccount::ActiveModel = model.into();
    let model = model.insert(&txn).await.map_err(taken)?;
    if model.is_primary {
        demote_others(&txn, target_id, model.id).await?;
    }
    txn.commit().await?;
    Ok(model)
}

/// Change an account. Returns it as it was, and as it is.
pub async fn update<C: ConnectionTrait + TransactionTrait>(
    db: &C,
    target_id: Uuid,
    account_id: Uuid,
    data: &TargetAccountDataRequest,
) -> Result<(TargetAccount::Model, TargetAccount::Model), ResourceError> {
    let txn = db.begin().await?;
    let target = find_target(&txn, target_id).await?;
    let existing = TargetAccount::Entity::find_by_id(account_id)
        .one(&txn)
        .await?
        .filter(|account| account.target_id == target_id)
        .ok_or(ResourceError::NotFound)?;
    if existing.kind != data.kind {
        return Err(ResourceError::Invalid(
            "An account's kind cannot be changed: add another account instead.",
        ));
    }
    let model = build(&target, data, Some(&existing))?;
    let mut active: TargetAccount::ActiveModel = existing.clone().into();
    active.name = Set(model.name);
    active.domain = Set(model.domain);
    active.auth_method = Set(model.auth_method);
    active.credential = Set(model.credential);
    active.username_format = Set(model.username_format);
    active.enabled = Set(model.enabled);
    active.is_primary = Set(model.is_primary);
    active.description = Set(model.description);
    active.account_key = Set(model.account_key);
    active.updated_at = Set(model.updated_at);
    let updated = active.update(&txn).await.map_err(taken)?;
    if updated.is_primary {
        demote_others(&txn, target_id, updated.id).await?;
    }
    txn.commit().await?;
    Ok((existing, updated))
}

/// What deleting an account took with it.
pub struct DeletedAccount {
    pub account: TargetAccount::Model,
    /// Direct assignments of it, now revoked.
    pub assignments: Vec<AccessAssignment::Model>,
    /// Access-group grants of it, now removed.
    pub grants: Vec<AccessGroupGrant::Model>,
}

/// Delete an account, and in the same transaction every assignment and grant of it: nothing
/// is left that names an account that is gone.
pub async fn delete<C: ConnectionTrait + TransactionTrait>(
    db: &C,
    target_id: Uuid,
    account_id: Uuid,
) -> Result<DeletedAccount, ResourceError> {
    let txn = db.begin().await?;
    let account = TargetAccount::Entity::find_by_id(account_id)
        .one(&txn)
        .await?
        .filter(|account| account.target_id == target_id)
        .ok_or(ResourceError::NotFound)?;
    let assignments = AccessAssignment::Entity::find()
        .filter(AccessAssignment::Column::TargetAccountId.eq(account_id))
        .all(&txn)
        .await?;
    let grants = AccessGroupGrant::Entity::find()
        .filter(AccessGroupGrant::Column::TargetAccountId.eq(account_id))
        .all(&txn)
        .await?;
    AccessAssignment::Entity::delete_many()
        .filter(AccessAssignment::Column::TargetAccountId.eq(account_id))
        .exec(&txn)
        .await?;
    AccessGroupExclusion::Entity::delete_many()
        .filter(AccessGroupExclusion::Column::TargetAccountId.eq(account_id))
        .exec(&txn)
        .await?;
    AccessGroupGrant::Entity::delete_many()
        .filter(AccessGroupGrant::Column::TargetAccountId.eq(account_id))
        .exec(&txn)
        .await?;
    TargetAccount::Entity::delete_by_id(account_id)
        .exec(&txn)
        .await?;
    for grant in &grants {
        super::access_groups::unmirror_if_last(&txn, grant.role_id, grant.target_id).await?;
    }
    txn.commit().await?;
    Ok(DeletedAccount {
        account,
        assignments,
        grants,
    })
}

/// The account a target's own settings name, as an API client written before accounts sent
/// it; `None` when they name none (blank, as the Warpgate UI now sends them).
pub fn legacy_account(options: &TargetOptions) -> Option<TargetAccountDataRequest> {
    let account = |kind, name: &str, domain: Option<String>, credential| TargetAccountDataRequest {
        kind,
        name: name.trim().to_owned(),
        domain,
        auth_method: TargetAccountAuthMethod::StoredCredential,
        credential: Some(credential),
        username_format: None,
        enabled: true,
        is_primary: true,
        description: "The target's primary account.".to_owned(),
    };
    match options {
        TargetOptions::Rdp(rdp) => {
            let name = rdp.username.trim();
            if name.is_empty() {
                return None;
            }
            let domain = rdp
                .domain
                .as_deref()
                .map(str::trim)
                .filter(|domain| !domain.is_empty())
                .map(str::to_owned);
            let kind = if domain.is_some() || name.contains('\\') || name.contains('@') {
                TargetAccountKind::Domain
            } else {
                TargetAccountKind::Local
            };
            let RdpTargetAuth::Password(auth) = &rdp.auth;
            Some(account(
                kind,
                name,
                domain,
                TargetAccountCredential::Password(TargetAccountPasswordCredential {
                    password: auth.password.clone(),
                }),
            ))
        }
        TargetOptions::Ssh(ssh) => {
            let blank = ssh.username.trim().is_empty()
                && ssh.auth == SSHTargetAuth::PublicKey(SshTargetPublicKeyAuth::default());
            (!blank).then(|| {
                account(
                    TargetAccountKind::Local,
                    &ssh.username,
                    None,
                    TargetAccountCredential::from_ssh_auth(&ssh.auth),
                )
            })
        }
        TargetOptions::MySql(mysql) => database_account(&mysql.username, &mysql.auth)
            .map(|credential| account(TargetAccountKind::Local, &mysql.username, None, credential)),
        TargetOptions::Postgres(postgres) => database_account(&postgres.username, &postgres.auth)
            .map(|credential| {
                account(
                    TargetAccountKind::Local,
                    &postgres.username,
                    None,
                    credential,
                )
            }),
        TargetOptions::Http(_) | TargetOptions::Kubernetes(_) | TargetOptions::Vnc(_) => None,
    }
}

fn database_account(username: &str, auth: &DatabaseTargetAuth) -> Option<TargetAccountCredential> {
    (!username.trim().is_empty()).then(|| TargetAccountCredential::from_database_auth(auth))
}

/// Blank the account fields of a target's settings: accounts live in its Accounts.
pub fn strip_account_fields(options: &mut TargetOptions) {
    match options {
        TargetOptions::Rdp(rdp) => {
            rdp.username = String::new();
            rdp.domain = None;
            rdp.auth = RdpTargetAuth::Password(RdpTargetPasswordAuth {
                password: MaybeSecretRef::default(),
            });
        }
        TargetOptions::Ssh(ssh) => {
            ssh.username = String::new();
            ssh.auth = SSHTargetAuth::PublicKey(SshTargetPublicKeyAuth::default());
        }
        TargetOptions::MySql(mysql) => {
            mysql.username = String::new();
            mysql.auth = DatabaseTargetAuth::Password(DatabaseTargetPasswordAuth::default());
        }
        TargetOptions::Postgres(postgres) => {
            postgres.username = String::new();
            postgres.auth = DatabaseTargetAuth::Password(DatabaseTargetPasswordAuth::default());
        }
        TargetOptions::Http(_) | TargetOptions::Kubernetes(_) | TargetOptions::Vnc(_) => {}
    }
}

/// Translate a legacy target write: the account its settings name becomes (or updates) the
/// target's primary account. Creates no assignment, so it grants nobody anything.
pub async fn sync_primary<C: ConnectionTrait>(
    db: &C,
    target: &warpgate_db_entities::Target::Model,
    options: &TargetOptions,
    actor: Option<Uuid>,
) -> Result<(), ResourceError> {
    let Some(data) = legacy_account(options) else {
        return Ok(());
    };
    let key = TargetAccount::Model::key_for(data.kind, data.name.trim(), None);
    let accounts = TargetAccount::Entity::find()
        .filter(TargetAccount::Column::TargetId.eq(target.id))
        .all(db)
        .await?;
    let existing = accounts
        .iter()
        .find(|account| account.is_primary)
        .or_else(|| accounts.iter().find(|account| account.account_key == key));
    let model = build(target, &data, existing)?;
    match existing {
        Some(existing) => {
            let mut active: TargetAccount::ActiveModel = existing.clone().into();
            active.kind = Set(model.kind);
            active.name = Set(model.name);
            active.domain = Set(model.domain);
            active.auth_method = Set(model.auth_method);
            active.credential = Set(model.credential);
            active.username_format = Set(model.username_format);
            active.is_primary = Set(true);
            active.account_key = Set(model.account_key);
            active.updated_at = Set(model.updated_at);
            let updated = active.update(db).await.map_err(taken)?;
            demote_others(db, target.id, updated.id).await?;
        }
        None => {
            let mut model = model;
            model.created_by = actor;
            let active: TargetAccount::ActiveModel = model.into();
            let created = active.insert(db).await.map_err(taken)?;
            demote_others(db, target.id, created.id).await?;
        }
    }
    Ok(())
}

/// Show each target's primary account in its settings, as API clients written before
/// accounts expect, with no secret in it.
pub async fn show_primaries<C: ConnectionTrait>(
    db: &C,
    targets: &mut [Target],
) -> Result<(), WarpgateError> {
    if targets.is_empty() {
        return Ok(());
    }
    let primaries = TargetAccount::Entity::find()
        .filter(TargetAccount::Column::IsPrimary.eq(true))
        .filter(TargetAccount::Column::TargetId.is_in(targets.iter().map(|target| target.id)))
        .all(db)
        .await?;
    for target in targets.iter_mut() {
        let Some(primary) = primaries
            .iter()
            .find(|account| account.target_id == target.id)
        else {
            continue;
        };
        let credential = primary
            .credential()
            .ok()
            .flatten()
            .map(|credential| credential.redacted());
        let name = primary.name.clone();
        match &mut target.options {
            TargetOptions::Rdp(rdp) if primary.kind != TargetAccountKind::Directory => {
                rdp.username = name;
                rdp.domain = primary.domain.clone();
            }
            TargetOptions::Ssh(ssh) => {
                ssh.username = name;
                if let Some(credential) = &credential {
                    ssh.auth = credential.to_ssh_auth();
                }
            }
            TargetOptions::MySql(mysql) => {
                mysql.username = name;
                if let Some(auth) = credential.as_ref().and_then(|c| c.to_database_auth()) {
                    mysql.auth = auth;
                }
            }
            TargetOptions::Postgres(postgres) => {
                postgres.username = name;
                if let Some(auth) = credential.as_ref().and_then(|c| c.to_database_auth()) {
                    postgres.auth = auth;
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// Hide a stored credential: a password is never returned once saved (a secret reference,
/// which is no secret, is).
pub fn redacted_credential(account: &TargetAccount::Model) -> Option<TargetAccountCredential> {
    account
        .credential()
        .ok()
        .flatten()
        .map(|credential| credential.redacted())
}
