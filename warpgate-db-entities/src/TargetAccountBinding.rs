//! Legacy: the user–target–account bindings of migration m00097, kept as written.
//!
//! Migration m00098 carried every binding over to the unified model (target accounts and
//! Access Control assignments) and left this table untouched, so a rollback finds it as it
//! was. Nothing reads it for authorization any more, and nothing writes it; it is copied by
//! `copy-database` like any other table, and dropped by a later migration once rollback past
//! m00098 is no longer supported.

use sea_orm::entity::prelude::*;
use serde::Serialize;
use time::OffsetDateTime;
use uuid::Uuid;

pub use super::TargetAccount::DirectoryUsernameFormat;

/// What kind of remote account a binding named.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(16))")]
pub enum LegacyAccountKind {
    /// The user's own directory account, from their LDAP link.
    #[sea_orm(string_value = "directory")]
    Directory,
    /// An account of the target itself, by name.
    #[sea_orm(string_value = "local")]
    Local,
    /// The account configured on the target.
    #[sea_orm(string_value = "managed")]
    Managed,
}

/// How a binding authenticated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(32))")]
pub enum LegacyAuthMethod {
    #[sea_orm(string_value = "directory_password")]
    DirectoryPassword,
    #[sea_orm(string_value = "typed_password")]
    TypedPassword,
    #[sea_orm(string_value = "target_credential")]
    TargetCredential,
}

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize)]
#[sea_orm(table_name = "target_account_bindings")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub user_id: Uuid,
    pub target_id: Uuid,
    pub account_kind: LegacyAccountKind,
    #[sea_orm(column_type = "String(StringLen::N(256))", nullable)]
    pub account_name: Option<String>,
    pub ldap_server_id: Option<Uuid>,
    pub ldap_object_uuid: Option<Uuid>,
    pub username_format: Option<DirectoryUsernameFormat>,
    pub auth_method: LegacyAuthMethod,
    pub enabled: bool,
    pub expires_at: Option<OffsetDateTime>,
    pub created_by: Option<Uuid>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    #[sea_orm(column_type = "String(StringLen::N(300))")]
    pub account_key: String,
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
        belongs_to = "super::Target::Entity",
        from = "Column::TargetId",
        to = "super::Target::Column::Id",
        on_delete = "Cascade"
    )]
    Target,
}

impl ActiveModelBehavior for ActiveModel {}
