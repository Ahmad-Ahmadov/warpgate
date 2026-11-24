//! What an access group grants (Access Control, Access Groups): its members may connect to
//! the target as the account named (or, on a target with no accounts, to the target), for as
//! long as their membership is active.
//!
//! An access group is a role (`Role`, `UserRoleAssignment`): the same groups, the same
//! membership, managed by the same APIs, SSO role mappings and LDAP imports. A group grants
//! nothing except through these rows, and every assignment they make is worked out by the
//! one resolver (`warpgate_core::access_control`) and shown in Access Control, with the
//! group as its source. `AccessGroupExclusion` takes one member out of one grant.

use sea_orm::entity::prelude::*;
use serde::Serialize;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize)]
#[sea_orm(table_name = "access_group_grants")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// The group (a role).
    pub role_id: Uuid,
    pub target_id: Uuid,
    /// The account on the target; `None` on a target whose protocol has none.
    pub target_account_id: Option<Uuid>,
    /// `AccessAssignment::account_key`: unique per group and target.
    #[sea_orm(column_type = "String(StringLen::N(64))")]
    pub account_key: String,
    pub created_by: Option<Uuid>,
    pub created_at: OffsetDateTime,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::Role::Entity",
        from = "Column::RoleId",
        to = "super::Role::Column::Id",
        on_delete = "Cascade"
    )]
    Role,
    #[sea_orm(
        belongs_to = "super::Target::Entity",
        from = "Column::TargetId",
        to = "super::Target::Column::Id",
        on_delete = "Cascade"
    )]
    Target,
    #[sea_orm(
        belongs_to = "super::TargetAccount::Entity",
        from = "Column::TargetAccountId",
        to = "super::TargetAccount::Column::Id",
        on_delete = "Cascade"
    )]
    TargetAccount,
}

impl Related<super::Role::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Role.def()
    }
}

impl Related<super::Target::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Target.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
