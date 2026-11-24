//! Access groups' grants (Access Control, Access Groups): which target, as which account,
//! a group's members may connect to.
//!
//! A group is a role; its membership is managed as before (admin API, SSO role mappings,
//! LDAP import, default roles). What it grants is only ever these rows, worked out for each
//! member by [`crate::access_control`]. The legacy `target_roles` table is kept in step (a
//! role has a row for a target while it grants anything there), for API clients that read
//! it and for a rollback past m00098; nothing authorizes from it.

use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, PaginatorTrait, QueryFilter, Set,
    TransactionTrait,
};
use time::OffsetDateTime;
use uuid::Uuid;
use warpgate_db_entities::{
    AccessAssignment, AccessGroupExclusion, AccessGroupGrant, Role, TargetAccount,
    TargetRoleAssignment,
};

use super::ResourceError;
use crate::access_control::{check_account, protocol_of, uses_accounts};
use crate::db::is_unique_violation;

/// Keep the legacy `target_roles` row for a group and target that grants something there.
async fn mirror<C: ConnectionTrait>(
    db: &C,
    role_id: Uuid,
    target_id: Uuid,
) -> Result<(), ResourceError> {
    let present = TargetRoleAssignment::Entity::find_by_id((target_id, role_id))
        .one(db)
        .await?
        .is_some();
    if !present {
        TargetRoleAssignment::ActiveModel {
            target_id: Set(target_id),
            role_id: Set(role_id),
        }
        .insert(db)
        .await?;
    }
    Ok(())
}

/// Drop the legacy `target_roles` row once the group grants nothing on the target.
pub(crate) async fn unmirror_if_last<C: ConnectionTrait>(
    db: &C,
    role_id: Uuid,
    target_id: Uuid,
) -> Result<(), ResourceError> {
    let left = AccessGroupGrant::Entity::find()
        .filter(AccessGroupGrant::Column::RoleId.eq(role_id))
        .filter(AccessGroupGrant::Column::TargetId.eq(target_id))
        .count(db)
        .await?;
    if left == 0 {
        TargetRoleAssignment::Entity::delete_by_id((target_id, role_id))
            .exec(db)
            .await?;
    }
    Ok(())
}

/// Let a group's members connect to the target as `account_id` (`None` on a protocol with
/// no accounts). The account must be the target's, and able to sign in there.
pub async fn add_grant<C: ConnectionTrait + TransactionTrait>(
    db: &C,
    role_id: Uuid,
    target_id: Uuid,
    account_id: Option<Uuid>,
    actor: Option<Uuid>,
) -> Result<AccessGroupGrant::Model, ResourceError> {
    let txn = db.begin().await?;
    Role::Entity::find_by_id(role_id)
        .one(&txn)
        .await?
        .ok_or(ResourceError::NotFound)?;
    let target = warpgate_db_entities::Target::Entity::find_by_id(target_id)
        .one(&txn)
        .await?
        .ok_or(ResourceError::NotFound)?;
    let protocol = protocol_of(target.kind);
    match (uses_accounts(protocol), account_id) {
        (true, None) => {
            return Err(ResourceError::Invalid(
                "Choose the account the group's members sign in to this target as.",
            ));
        }
        (false, Some(_)) => {
            return Err(ResourceError::Invalid(
                "This target's protocol has no remote accounts.",
            ));
        }
        (true, Some(account_id)) => {
            let account = TargetAccount::Entity::find_by_id(account_id)
                .one(&txn)
                .await?
                .filter(|account| account.target_id == target_id)
                .ok_or(ResourceError::Invalid(
                    "The account is not one of the target's.",
                ))?;
            check_account(protocol, &account).map_err(ResourceError::Invalid)?;
        }
        (false, None) => {}
    }
    let grant = AccessGroupGrant::ActiveModel {
        id: Set(Uuid::new_v4()),
        role_id: Set(role_id),
        target_id: Set(target_id),
        target_account_id: Set(account_id),
        account_key: Set(AccessAssignment::account_key(account_id)),
        created_by: Set(actor),
        created_at: Set(OffsetDateTime::now_utc()),
    }
    .insert(&txn)
    .await
    .map_err(|error| {
        if is_unique_violation(&error) {
            ResourceError::RoleAlreadyAssigned
        } else {
            error.into()
        }
    })?;
    mirror(&txn, role_id, target_id).await?;
    txn.commit().await?;
    Ok(grant)
}

/// Remove a grant; its members' exclusions from it go with it.
pub async fn remove_grant<C: ConnectionTrait + TransactionTrait>(
    db: &C,
    grant_id: Uuid,
) -> Result<AccessGroupGrant::Model, ResourceError> {
    let txn = db.begin().await?;
    let grant = AccessGroupGrant::Entity::find_by_id(grant_id)
        .one(&txn)
        .await?
        .ok_or(ResourceError::NotFound)?;
    AccessGroupExclusion::Entity::delete_many()
        .filter(AccessGroupExclusion::Column::RoleId.eq(grant.role_id))
        .filter(AccessGroupExclusion::Column::TargetId.eq(grant.target_id))
        .filter(AccessGroupExclusion::Column::AccountKey.eq(grant.account_key.clone()))
        .exec(&txn)
        .await?;
    AccessGroupGrant::Entity::delete_by_id(grant_id)
        .exec(&txn)
        .await?;
    unmirror_if_last(&txn, grant.role_id, grant.target_id).await?;
    txn.commit().await?;
    Ok(grant)
}

/// Take one member out of one of a group's grants (or put them back with
/// [`include_member`]): revokes that group-derived assignment for them alone. Their direct
/// assignments, and the group's other members, are untouched.
pub async fn exclude_member<C: ConnectionTrait>(
    db: &C,
    grant: &AccessGroupGrant::Model,
    user_id: Uuid,
    note: &str,
    actor: Option<Uuid>,
) -> Result<AccessGroupExclusion::Model, ResourceError> {
    AccessGroupExclusion::ActiveModel {
        id: Set(Uuid::new_v4()),
        role_id: Set(grant.role_id),
        user_id: Set(user_id),
        target_id: Set(grant.target_id),
        target_account_id: Set(grant.target_account_id),
        account_key: Set(grant.account_key.clone()),
        note: Set(note.to_owned()),
        created_by: Set(actor),
        created_at: Set(OffsetDateTime::now_utc()),
    }
    .insert(db)
    .await
    .map_err(|error| {
        if is_unique_violation(&error) {
            ResourceError::RoleAlreadyAssigned
        } else {
            error.into()
        }
    })
}

/// Undo [`exclude_member`].
pub async fn include_member<C: ConnectionTrait>(
    db: &C,
    exclusion_id: Uuid,
) -> Result<AccessGroupExclusion::Model, ResourceError> {
    let exclusion = AccessGroupExclusion::Entity::find_by_id(exclusion_id)
        .one(db)
        .await?
        .ok_or(ResourceError::NotFound)?;
    AccessGroupExclusion::Entity::delete_by_id(exclusion_id)
        .exec(db)
        .await?;
    Ok(exclusion)
}
