//! One member taken out of one of an access group's grants: revoking a group-derived
//! assignment for that user alone, without changing the group, and without touching any
//! direct assignment the user also has. The migration also makes these, where a member's
//! own account assignments used to restrict them more than their group did.

use sea_orm::entity::prelude::*;
use serde::Serialize;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize)]
#[sea_orm(table_name = "access_group_exclusions")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub role_id: Uuid,
    pub user_id: Uuid,
    pub target_id: Uuid,
    pub target_account_id: Option<Uuid>,
    /// `AccessAssignment::account_key` of the grant it excludes the user from.
    #[sea_orm(column_type = "String(StringLen::N(64))")]
    pub account_key: String,
    #[sea_orm(column_type = "Text")]
    pub note: String,
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
        belongs_to = "super::User::Entity",
        from = "Column::UserId",
        to = "super::User::Column::Id",
        on_delete = "Cascade"
    )]
    User,
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

impl ActiveModelBehavior for ActiveModel {}
