//! A direct assignment (Access Control): the user may connect to the target, as the
//! account named, while it is enabled and not expired. It is both the permission to reach
//! the target and the permission to use that account there; nothing else is needed.
//!
//! On a protocol with no remote account (HTTP, Kubernetes, VNC) an assignment names no
//! account: it is the user's entitlement to the target itself. Access groups grant the same
//! way, through `AccessGroupGrant`; their assignments are worked out from membership and
//! are not stored here.
//!
//! A directory account assignment records the user's LDAP link when it was made, and is
//! good only while the user is still linked to that same entry.

use poem_openapi::Enum;
use sea_orm::entity::prelude::*;
use serde::Serialize;
use time::OffsetDateTime;
use uuid::Uuid;

/// Where a direct assignment came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Enum, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(16))")]
#[oai(rename = "AccessAssignmentOrigin")]
pub enum AssignmentOrigin {
    /// An administrator made it.
    #[sea_orm(string_value = "direct")]
    #[oai(rename = "direct")]
    Direct,
    /// The access-control migration made it from an earlier permission (see `note`).
    #[sea_orm(string_value = "migrated")]
    #[oai(rename = "migrated")]
    Migrated,
    /// An administrator confirmed it while reviewing the migration.
    #[sea_orm(string_value = "review")]
    #[oai(rename = "review")]
    Review,
}

impl AssignmentOrigin {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Migrated => "migrated",
            Self::Review => "review",
        }
    }
}

/// The key of an assignment to an account, or to a target with no accounts.
pub fn account_key(target_account_id: Option<Uuid>) -> String {
    match target_account_id {
        Some(id) => format!("account:{id}"),
        None => "target".to_owned(),
    }
}

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize)]
#[sea_orm(table_name = "access_assignments")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub user_id: Uuid,
    pub target_id: Uuid,
    /// The account on the target; `None` on a target whose protocol has none.
    pub target_account_id: Option<Uuid>,
    /// [`account_key`]: unique per user and target, so one account is assigned once.
    #[sea_orm(column_type = "String(StringLen::N(64))")]
    pub account_key: String,
    /// For a directory account: the user's LDAP link when it was assigned.
    pub ldap_server_id: Option<Uuid>,
    pub ldap_object_uuid: Option<Uuid>,
    pub enabled: bool,
    pub expires_at: Option<OffsetDateTime>,
    pub origin: AssignmentOrigin,
    /// What it was made from, for a migrated one; an administrator's note otherwise.
    #[sea_orm(column_type = "Text")]
    pub note: String,
    pub created_by: Option<Uuid>,
    pub updated_by: Option<Uuid>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

impl Model {
    /// Enabled, and not past its expiry, at `now`.
    pub fn is_active_at(&self, now: OffsetDateTime) -> bool {
        self.enabled && self.expires_at.is_none_or(|expires| expires > now)
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

impl Related<super::User::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::User.def()
    }
}

impl Related<super::Target::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Target.def()
    }
}

impl Related<super::TargetAccount::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::TargetAccount.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_tell_accounts_from_targets() {
        let id = Uuid::from_u128(9);
        assert_eq!(account_key(Some(id)), format!("account:{id}"));
        assert_eq!(account_key(None), "target");
    }
}
