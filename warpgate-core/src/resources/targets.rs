use poem_openapi::Object;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, ModelTrait, QueryFilter, Set,
    TransactionTrait,
};
use uuid::Uuid;
use warpgate_common::{StoredSecrets, TargetOptions, WarpgateError};
use warpgate_db_entities::{
    AccessAssignment, AccessGroupExclusion, AccessGroupGrant, AccessMigrationReview, KnownHost,
    Target, TargetAccount, TargetRoleAssignment, TargetSession, Ticket, TicketRequest,
};

use super::{AdmittedSessions, ResourceError, check_name, name_taken};
use crate::access_control::{protocol_of, uses_accounts};

#[derive(Object)]
pub struct TargetDataRequest {
    pub name: String,
    pub description: Option<String>,
    pub options: TargetOptions,
    pub rate_limit_bytes_per_second: Option<u32>,
    pub group_id: Option<Uuid>,
    #[oai(validator(minimum(value = "1")))]
    pub ticket_max_duration_seconds: Option<i64>,
    pub ticket_requests_disabled: bool,
    pub ticket_require_approval: bool,
    pub require_approval: bool,
    #[oai(validator(minimum(value = "1")))]
    pub ticket_max_uses: Option<i16>,
}

/// What a target's settings are stored as: encrypted, and with no account in them (those
/// live in its Accounts, see [`super::target_accounts`]).
fn serialize_options_for_storage(
    mut options: TargetOptions,
) -> Result<serde_json::Value, WarpgateError> {
    super::target_accounts::strip_account_fields(&mut options);
    options.encrypt_all()?;
    Ok(serde_json::to_value(options)?)
}

fn set_data(
    model: &mut Target::ActiveModel,
    data: &TargetDataRequest,
) -> Result<(), ResourceError> {
    model.name = Set(data.name.clone());
    model.description = Set(data.description.clone().unwrap_or_default());
    model.options = Set(serialize_options_for_storage(data.options.clone())?);
    model.rate_limit_bytes_per_second = Set(data.rate_limit_bytes_per_second.map(i64::from));
    model.group_id = Set(data.group_id);
    model.ticket_max_duration_seconds = Set(data.ticket_max_duration_seconds);
    model.ticket_requests_disabled = Set(data.ticket_requests_disabled);
    model.ticket_require_approval = Set(data.ticket_require_approval);
    model.require_approval = Set(data.require_approval);
    model.ticket_max_uses = Set(data.ticket_max_uses);
    Ok(())
}

/// Create a target. An account its settings name (as API clients written before target
/// accounts send one) becomes its primary account; it grants nobody anything.
pub async fn create<C: ConnectionTrait + TransactionTrait>(
    db: &C,
    data: &TargetDataRequest,
    actor: Option<Uuid>,
) -> Result<Target::Model, ResourceError> {
    check_name(&data.name)?;
    let txn = db.begin().await?;
    let mut model = Target::ActiveModel {
        id: Set(Uuid::new_v4()),
        kind: Set((&data.options).into()),
        ..Default::default()
    };
    set_data(&mut model, data)?;
    let target = model.insert(&txn).await.map_err(name_taken)?;
    super::target_accounts::sync_primary(&txn, &target, &data.options, actor).await?;
    txn.commit().await?;
    Ok(target)
}

/// Update a target. As on [`create`], an account its settings name updates its primary
/// account; the Warpgate UI sends them blank and manages accounts on their own.
pub async fn update<C: ConnectionTrait + TransactionTrait>(
    db: &C,
    id: Uuid,
    data: &TargetDataRequest,
    actor: Option<Uuid>,
) -> Result<Target::Model, ResourceError> {
    check_name(&data.name)?;
    let txn = db.begin().await?;
    let target = Target::Entity::find_by_id(id)
        .one(&txn)
        .await?
        .ok_or(ResourceError::NotFound)?;
    if target.kind != (&data.options).into() {
        return Err(ResourceError::ProtocolChange);
    }

    let mut model: Target::ActiveModel = target.into();
    set_data(&mut model, data)?;
    let target = model.update(&txn).await.map_err(name_taken)?;
    super::target_accounts::sync_primary(&txn, &target, &data.options, actor).await?;
    txn.commit().await?;
    Ok(target)
}

pub async fn delete<C: ConnectionTrait + TransactionTrait>(
    db: &C,
    id: Uuid,
) -> Result<AdmittedSessions, ResourceError> {
    let txn = db.begin().await?;
    let target = Target::Entity::find_by_id(id)
        .one(&txn)
        .await?
        .ok_or(ResourceError::NotFound)?;

    TargetRoleAssignment::Entity::delete_many()
        .filter(TargetRoleAssignment::Column::TargetId.eq(target.id))
        .exec(&txn)
        .await?;

    // Access Control: everything that named the target or its accounts goes with it.
    AccessGroupExclusion::Entity::delete_many()
        .filter(AccessGroupExclusion::Column::TargetId.eq(target.id))
        .exec(&txn)
        .await?;
    AccessGroupGrant::Entity::delete_many()
        .filter(AccessGroupGrant::Column::TargetId.eq(target.id))
        .exec(&txn)
        .await?;
    AccessAssignment::Entity::delete_many()
        .filter(AccessAssignment::Column::TargetId.eq(target.id))
        .exec(&txn)
        .await?;
    AccessMigrationReview::Entity::delete_many()
        .filter(AccessMigrationReview::Column::TargetId.eq(target.id))
        .exec(&txn)
        .await?;
    TargetAccount::Entity::delete_many()
        .filter(TargetAccount::Column::TargetId.eq(target.id))
        .exec(&txn)
        .await?;

    TicketRequest::Entity::delete_many()
        .filter(TicketRequest::Column::TargetId.eq(target.id))
        .exec(&txn)
        .await?;

    let admitted = TargetSession::open_user_sessions_admitted_by_tickets(
        &txn,
        Ticket::Column::TargetId.eq(target.id),
    )
    .await?;
    Ticket::Entity::delete_many()
        .filter(Ticket::Column::TargetId.eq(target.id))
        .exec(&txn)
        .await?;

    let options = serde_json::from_value::<TargetOptions>(target.options.clone())
        .map_err(WarpgateError::from)?;
    if let TargetOptions::Ssh(ssh_options) = &options {
        KnownHost::Entity::delete_many()
            .filter(KnownHost::Column::Host.eq(&ssh_options.host))
            .filter(KnownHost::Column::Port.eq(i32::from(ssh_options.port)))
            .exec(&txn)
            .await?;
    }

    target.delete(&txn).await?;
    txn.commit().await?;
    Ok(AdmittedSessions(admitted))
}

/// The legacy "allow a role on a target", translated into Access Control: the group of
/// that role is granted the target's primary account (or, on a protocol with no accounts,
/// the target). A target with accounts and no primary one refuses, rather than pick an
/// account that could widen access.
pub async fn add_role<C: ConnectionTrait + TransactionTrait>(
    db: &C,
    target_id: Uuid,
    role_id: Uuid,
    actor: Option<Uuid>,
) -> Result<warpgate_db_entities::AccessGroupGrant::Model, ResourceError> {
    let target = Target::Entity::find_by_id(target_id)
        .one(db)
        .await?
        .ok_or(ResourceError::NotFound)?;
    let account_id = if uses_accounts(protocol_of(target.kind)) {
        let primary = TargetAccount::Entity::find()
            .filter(TargetAccount::Column::TargetId.eq(target_id))
            .filter(TargetAccount::Column::IsPrimary.eq(true))
            .one(db)
            .await?
            .ok_or(ResourceError::NoPrimaryAccount)?;
        Some(primary.id)
    } else {
        None
    };
    super::access_groups::add_grant(db, role_id, target_id, account_id, actor).await
}

/// The legacy "disallow a role on a target": every grant of the group on the target is
/// removed (with its members' exclusions). Returns what was removed.
pub async fn remove_role<C: ConnectionTrait + TransactionTrait>(
    db: &C,
    target_id: Uuid,
    role_id: Uuid,
) -> Result<Vec<warpgate_db_entities::AccessGroupGrant::Model>, ResourceError> {
    let grants = AccessGroupGrant::Entity::find()
        .filter(AccessGroupGrant::Column::RoleId.eq(role_id))
        .filter(AccessGroupGrant::Column::TargetId.eq(target_id))
        .all(db)
        .await?;
    let legacy = TargetRoleAssignment::Entity::delete_by_id((target_id, role_id))
        .exec(db)
        .await?;
    if grants.is_empty() && legacy.rows_affected == 0 {
        return Err(ResourceError::NotFound);
    }
    for grant in &grants {
        super::access_groups::remove_grant(db, grant.id).await?;
    }
    Ok(grants)
}
