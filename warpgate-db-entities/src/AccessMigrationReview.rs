//! The access-control migration's report (m00098): every earlier permission it looked at,
//! what it did with it, and the ones it could not map safely, which wait for an
//! administrator's decision. A pending item grants nothing until it is confirmed.

use poem_openapi::Enum;
use sea_orm::entity::prelude::*;
use serde::Serialize;
use time::OffsetDateTime;
use uuid::Uuid;

/// What the migration found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Enum, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(32))")]
#[oai(rename = "AccessMigrationCategory")]
pub enum MigrationCategory {
    /// Mapped automatically, to an equivalent assignment or group grant.
    #[sea_orm(string_value = "migrated")]
    #[oai(rename = "migrated")]
    Migrated,
    /// An account assignment that already had the new model's shape (user, target, account).
    #[sea_orm(string_value = "already_matching")]
    #[oai(rename = "already_matching")]
    AlreadyMatching,
    /// The same account given to the same user more than once; kept once.
    #[sea_orm(string_value = "duplicate")]
    #[oai(rename = "duplicate")]
    Duplicate,
    /// A permission with no remote account that can be identified.
    #[sea_orm(string_value = "no_account")]
    #[oai(rename = "no_account")]
    NoAccount,
    /// Access that came from several overlapping rules (a group, and a member's own account
    /// assignments that restricted them): mapped without widening anyone's access.
    #[sea_orm(string_value = "overlapping")]
    #[oai(rename = "overlapping")]
    Overlapping,
    /// An account assignment that granted nothing (the user's roles did not reach the
    /// target), so it was not carried over as access.
    #[sea_orm(string_value = "ineffective")]
    #[oai(rename = "ineffective")]
    Ineffective,
    /// Several accounts could apply and choosing one could widen access.
    #[sea_orm(string_value = "ambiguous")]
    #[oai(rename = "ambiguous")]
    Ambiguous,
}

/// Whether an administrator has to decide.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Enum, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(16))")]
#[oai(rename = "AccessMigrationStatus")]
pub enum MigrationStatus {
    /// For the record: nothing to decide.
    #[sea_orm(string_value = "info")]
    #[oai(rename = "info")]
    Info,
    /// Pending migration review: grants nothing until an administrator confirms it.
    #[sea_orm(string_value = "pending")]
    #[oai(rename = "pending")]
    Pending,
    /// An administrator confirmed it, with the account they chose.
    #[sea_orm(string_value = "confirmed")]
    #[oai(rename = "confirmed")]
    Confirmed,
    /// An administrator decided it grants nothing.
    #[sea_orm(string_value = "rejected")]
    #[oai(rename = "rejected")]
    Rejected,
}

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize)]
#[sea_orm(table_name = "access_migration_reviews")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub category: MigrationCategory,
    pub status: MigrationStatus,
    /// The user it is about, for a user's permission.
    pub user_id: Option<Uuid>,
    /// The group (role) it is about, for a group's permission.
    pub role_id: Option<Uuid>,
    pub target_id: Option<Uuid>,
    /// The earlier permission, as an administrator would describe it.
    #[sea_orm(column_type = "Text")]
    pub legacy_permission: String,
    /// What the migration did, or why it could not map it.
    #[sea_orm(column_type = "Text")]
    pub reason: String,
    /// The target accounts an administrator may choose from (a JSON array of ids).
    pub candidate_account_ids: serde_json::Value,
    #[sea_orm(column_type = "Text")]
    pub resolution: String,
    pub resolved_by: Option<Uuid>,
    pub resolved_at: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
}

impl Model {
    pub fn candidate_accounts(&self) -> Vec<Uuid> {
        serde_json::from_value(self.candidate_account_ids.clone()).unwrap_or_default()
    }
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::User::Entity",
        from = "Column::UserId",
        to = "super::User::Column::Id",
        on_delete = "Cascade"
    )]
    User,
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
}

impl ActiveModelBehavior for ActiveModel {}
