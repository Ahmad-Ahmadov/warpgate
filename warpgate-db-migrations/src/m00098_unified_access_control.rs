//! Unified Access Control: target accounts, assignments, access-group grants, and the
//! migration of every earlier permission into them.
//!
//! Before this, reaching a target took a role that granted it (`target_roles`), and which
//! account a connection used came from the target's own settings, from accounts assigned
//! in those settings (RDP), or from the account bindings of m00097. Afterwards one model
//! decides both: an assignment of user, target and account, made directly or by an access
//! group (a role's grants). Nothing else grants access.
//!
//! The migration keeps every user's effective access as it was, and never widens it:
//!
//! - **Accounts.** Each RDP, SSH, MySQL and PostgreSQL target's configured account becomes
//!   an account in its inventory, marked primary, with its credential moved there (not
//!   copied: the target's settings keep none). The RDP "Active Directory Authentication"
//!   mode becomes a linked directory account; its "assigned Windows accounts" become local
//!   accounts; binding-only accounts are added too.
//! - **Roles.** A role granting a target becomes the same group granting the target's
//!   primary account (or the target itself, where the protocol has no accounts). A member
//!   who had account bindings on that target was held to those, so they are excluded from
//!   the group's grant there, and keep only what their bindings gave them.
//! - **Bindings and assigned Windows accounts** become direct assignments for users whose
//!   roles reached the target, expiring no later than both the binding and the roles did.
//!   For users whose roles did not reach it they granted nothing, and they wait for review.
//! - **Ambiguous** permissions (a role on a target whose accounts were assigned user by
//!   user; a target with no account to sign in as) wait for an administrator's decision in
//!   `access_migration_reviews`, and grant nothing until it is made.
//!
//! The earlier tables (`target_roles`, `user_roles`, `target_account_bindings`) are left as
//! they were, so a rollback (this migration's `down`, which also puts the credentials back
//! in the targets' settings) restores the earlier behaviour. `preview` runs the same
//! planning without writing anything, for the `access-migration-preview` command.

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;

use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, Schema, Set,
};
use sea_orm_migration::prelude::*;
use serde_json::{Value, json};
use time::OffsetDateTime;
use uuid::Uuid;

pub mod target_account {
    use sea_orm::entity::prelude::*;
    use time::OffsetDateTime;
    use uuid::Uuid;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "target_accounts")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub target_id: Uuid,
        #[sea_orm(column_type = "String(StringLen::N(16))")]
        pub kind: String,
        #[sea_orm(column_type = "String(StringLen::N(256))")]
        pub name: String,
        #[sea_orm(column_type = "String(StringLen::N(256))", nullable)]
        pub domain: Option<String>,
        #[sea_orm(column_type = "String(StringLen::N(32))")]
        pub auth_method: String,
        pub credential: Option<serde_json::Value>,
        #[sea_orm(column_type = "String(StringLen::N(16))", nullable)]
        pub username_format: Option<String>,
        pub enabled: bool,
        pub is_primary: bool,
        #[sea_orm(column_type = "Text")]
        pub description: String,
        #[sea_orm(column_type = "String(StringLen::N(300))")]
        pub account_key: String,
        pub created_by: Option<Uuid>,
        pub created_at: OffsetDateTime,
        pub updated_at: OffsetDateTime,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {
        #[sea_orm(
            belongs_to = "crate::m00007_targets_and_roles::target::Entity",
            from = "Column::TargetId",
            to = "crate::m00007_targets_and_roles::target::Column::Id",
            on_delete = "Cascade"
        )]
        Target,
        #[sea_orm(
            belongs_to = "crate::m00044_ticket_requests::user::Entity",
            from = "Column::CreatedBy",
            to = "crate::m00044_ticket_requests::user::Column::Id",
            on_delete = "SetNull"
        )]
        CreatedBy,
    }

    impl ActiveModelBehavior for ActiveModel {}
}

pub mod access_assignment {
    use sea_orm::entity::prelude::*;
    use time::OffsetDateTime;
    use uuid::Uuid;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "access_assignments")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub user_id: Uuid,
        pub target_id: Uuid,
        pub target_account_id: Option<Uuid>,
        #[sea_orm(column_type = "String(StringLen::N(64))")]
        pub account_key: String,
        pub ldap_server_id: Option<Uuid>,
        pub ldap_object_uuid: Option<Uuid>,
        pub enabled: bool,
        pub expires_at: Option<OffsetDateTime>,
        #[sea_orm(column_type = "String(StringLen::N(16))")]
        pub origin: String,
        #[sea_orm(column_type = "Text")]
        pub note: String,
        pub created_by: Option<Uuid>,
        pub updated_by: Option<Uuid>,
        pub created_at: OffsetDateTime,
        pub updated_at: OffsetDateTime,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {
        #[sea_orm(
            belongs_to = "crate::m00044_ticket_requests::user::Entity",
            from = "Column::UserId",
            to = "crate::m00044_ticket_requests::user::Column::Id",
            on_delete = "Cascade"
        )]
        User,
        #[sea_orm(
            belongs_to = "crate::m00007_targets_and_roles::target::Entity",
            from = "Column::TargetId",
            to = "crate::m00007_targets_and_roles::target::Column::Id",
            on_delete = "Cascade"
        )]
        Target,
        #[sea_orm(
            belongs_to = "super::target_account::Entity",
            from = "Column::TargetAccountId",
            to = "super::target_account::Column::Id",
            on_delete = "Cascade"
        )]
        TargetAccount,
        #[sea_orm(
            belongs_to = "crate::m00020_ldap_server::ldap_server::Entity",
            from = "Column::LdapServerId",
            to = "crate::m00020_ldap_server::ldap_server::Column::Id",
            on_delete = "SetNull"
        )]
        LdapServer,
        #[sea_orm(
            belongs_to = "crate::m00044_ticket_requests::user::Entity",
            from = "Column::CreatedBy",
            to = "crate::m00044_ticket_requests::user::Column::Id",
            on_delete = "SetNull"
        )]
        CreatedBy,
        #[sea_orm(
            belongs_to = "crate::m00044_ticket_requests::user::Entity",
            from = "Column::UpdatedBy",
            to = "crate::m00044_ticket_requests::user::Column::Id",
            on_delete = "SetNull"
        )]
        UpdatedBy,
    }

    impl ActiveModelBehavior for ActiveModel {}
}

pub mod access_group_grant {
    use sea_orm::entity::prelude::*;
    use time::OffsetDateTime;
    use uuid::Uuid;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "access_group_grants")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub role_id: Uuid,
        pub target_id: Uuid,
        pub target_account_id: Option<Uuid>,
        #[sea_orm(column_type = "String(StringLen::N(64))")]
        pub account_key: String,
        pub created_by: Option<Uuid>,
        pub created_at: OffsetDateTime,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {
        #[sea_orm(
            belongs_to = "crate::m00007_targets_and_roles::role::Entity",
            from = "Column::RoleId",
            to = "crate::m00007_targets_and_roles::role::Column::Id",
            on_delete = "Cascade"
        )]
        Role,
        #[sea_orm(
            belongs_to = "crate::m00007_targets_and_roles::target::Entity",
            from = "Column::TargetId",
            to = "crate::m00007_targets_and_roles::target::Column::Id",
            on_delete = "Cascade"
        )]
        Target,
        #[sea_orm(
            belongs_to = "super::target_account::Entity",
            from = "Column::TargetAccountId",
            to = "super::target_account::Column::Id",
            on_delete = "Cascade"
        )]
        TargetAccount,
        #[sea_orm(
            belongs_to = "crate::m00044_ticket_requests::user::Entity",
            from = "Column::CreatedBy",
            to = "crate::m00044_ticket_requests::user::Column::Id",
            on_delete = "SetNull"
        )]
        CreatedBy,
    }

    impl ActiveModelBehavior for ActiveModel {}
}

pub mod access_group_exclusion {
    use sea_orm::entity::prelude::*;
    use time::OffsetDateTime;
    use uuid::Uuid;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "access_group_exclusions")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub role_id: Uuid,
        pub user_id: Uuid,
        pub target_id: Uuid,
        pub target_account_id: Option<Uuid>,
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
            belongs_to = "crate::m00007_targets_and_roles::role::Entity",
            from = "Column::RoleId",
            to = "crate::m00007_targets_and_roles::role::Column::Id",
            on_delete = "Cascade"
        )]
        Role,
        #[sea_orm(
            belongs_to = "crate::m00044_ticket_requests::user::Entity",
            from = "Column::UserId",
            to = "crate::m00044_ticket_requests::user::Column::Id",
            on_delete = "Cascade"
        )]
        User,
        #[sea_orm(
            belongs_to = "crate::m00007_targets_and_roles::target::Entity",
            from = "Column::TargetId",
            to = "crate::m00007_targets_and_roles::target::Column::Id",
            on_delete = "Cascade"
        )]
        Target,
        #[sea_orm(
            belongs_to = "super::target_account::Entity",
            from = "Column::TargetAccountId",
            to = "super::target_account::Column::Id",
            on_delete = "Cascade"
        )]
        TargetAccount,
        #[sea_orm(
            belongs_to = "crate::m00044_ticket_requests::user::Entity",
            from = "Column::CreatedBy",
            to = "crate::m00044_ticket_requests::user::Column::Id",
            on_delete = "SetNull"
        )]
        CreatedBy,
    }

    impl ActiveModelBehavior for ActiveModel {}
}

pub mod access_migration_review {
    use sea_orm::entity::prelude::*;
    use time::OffsetDateTime;
    use uuid::Uuid;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "access_migration_reviews")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        #[sea_orm(column_type = "String(StringLen::N(32))")]
        pub category: String,
        #[sea_orm(column_type = "String(StringLen::N(16))")]
        pub status: String,
        pub user_id: Option<Uuid>,
        pub role_id: Option<Uuid>,
        pub target_id: Option<Uuid>,
        #[sea_orm(column_type = "Text")]
        pub legacy_permission: String,
        #[sea_orm(column_type = "Text")]
        pub reason: String,
        pub candidate_account_ids: serde_json::Value,
        #[sea_orm(column_type = "Text")]
        pub resolution: String,
        pub resolved_by: Option<Uuid>,
        pub resolved_at: Option<OffsetDateTime>,
        pub created_at: OffsetDateTime,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {
        #[sea_orm(
            belongs_to = "crate::m00044_ticket_requests::user::Entity",
            from = "Column::UserId",
            to = "crate::m00044_ticket_requests::user::Column::Id",
            on_delete = "Cascade"
        )]
        User,
        #[sea_orm(
            belongs_to = "crate::m00007_targets_and_roles::role::Entity",
            from = "Column::RoleId",
            to = "crate::m00007_targets_and_roles::role::Column::Id",
            on_delete = "Cascade"
        )]
        Role,
        #[sea_orm(
            belongs_to = "crate::m00007_targets_and_roles::target::Entity",
            from = "Column::TargetId",
            to = "crate::m00007_targets_and_roles::target::Column::Id",
            on_delete = "Cascade"
        )]
        Target,
        #[sea_orm(
            belongs_to = "crate::m00044_ticket_requests::user::Entity",
            from = "Column::ResolvedBy",
            to = "crate::m00044_ticket_requests::user::Column::Id",
            on_delete = "SetNull"
        )]
        ResolvedBy,
    }

    impl ActiveModelBehavior for ActiveModel {}
}

/// The earlier tables, read as they are; only the columns the migration needs.
mod read {
    pub mod user {
        use sea_orm::entity::prelude::*;
        use uuid::Uuid;

        #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
        #[sea_orm(table_name = "users")]
        pub struct Model {
            #[sea_orm(primary_key, auto_increment = false)]
            pub id: Uuid,
            pub username: String,
            pub ldap_server_id: Option<Uuid>,
            #[sea_orm(column_type = "Text", nullable)]
            pub ldap_object_uuid: Option<Uuid>,
        }

        #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
        pub enum Relation {}

        impl ActiveModelBehavior for ActiveModel {}
    }

    pub mod role {
        use sea_orm::entity::prelude::*;
        use uuid::Uuid;

        #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
        #[sea_orm(table_name = "roles")]
        pub struct Model {
            #[sea_orm(primary_key, auto_increment = false)]
            pub id: Uuid,
            pub name: String,
        }

        #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
        pub enum Relation {}

        impl ActiveModelBehavior for ActiveModel {}
    }

    pub mod user_role {
        use sea_orm::entity::prelude::*;
        use time::OffsetDateTime;
        use uuid::Uuid;

        #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
        #[sea_orm(table_name = "user_roles")]
        pub struct Model {
            #[sea_orm(primary_key, auto_increment = false)]
            pub user_id: Uuid,
            #[sea_orm(primary_key, auto_increment = false)]
            pub role_id: Uuid,
            pub expires_at: Option<OffsetDateTime>,
            pub revoked_at: Option<OffsetDateTime>,
        }

        #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
        pub enum Relation {}

        impl ActiveModelBehavior for ActiveModel {}
    }

    pub mod target_role {
        use sea_orm::entity::prelude::*;
        use uuid::Uuid;

        #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
        #[sea_orm(table_name = "target_roles")]
        pub struct Model {
            #[sea_orm(primary_key, auto_increment = false)]
            pub target_id: Uuid,
            #[sea_orm(primary_key, auto_increment = false)]
            pub role_id: Uuid,
        }

        #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
        pub enum Relation {}

        impl ActiveModelBehavior for ActiveModel {}
    }

    pub mod target {
        use sea_orm::entity::prelude::*;
        use uuid::Uuid;

        /// `kind` as a string: the migration reads every protocol, including any added later.
        #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
        #[sea_orm(table_name = "targets")]
        pub struct Model {
            #[sea_orm(primary_key, auto_increment = false)]
            pub id: Uuid,
            pub name: String,
            #[sea_orm(column_type = "String(StringLen::N(16))")]
            pub kind: String,
            pub options: serde_json::Value,
        }

        #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
        pub enum Relation {}

        impl ActiveModelBehavior for ActiveModel {}
    }

    pub mod binding {
        use sea_orm::entity::prelude::*;
        use time::OffsetDateTime;
        use uuid::Uuid;

        #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
        #[sea_orm(table_name = "target_account_bindings")]
        pub struct Model {
            #[sea_orm(primary_key, auto_increment = false)]
            pub id: Uuid,
            pub user_id: Uuid,
            pub target_id: Uuid,
            #[sea_orm(column_type = "String(StringLen::N(16))")]
            pub account_kind: String,
            #[sea_orm(column_type = "String(StringLen::N(256))", nullable)]
            pub account_name: Option<String>,
            pub ldap_server_id: Option<Uuid>,
            pub ldap_object_uuid: Option<Uuid>,
            #[sea_orm(column_type = "String(StringLen::N(16))", nullable)]
            pub username_format: Option<String>,
            #[sea_orm(column_type = "String(StringLen::N(32))")]
            pub auth_method: String,
            pub enabled: bool,
            pub expires_at: Option<OffsetDateTime>,
            pub created_at: OffsetDateTime,
        }

        #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
        pub enum Relation {}

        impl ActiveModelBehavior for ActiveModel {}
    }
}

// ---- What the migration reads ----

#[derive(Clone, Debug)]
pub(crate) struct LegacyUser {
    pub username: String,
    pub ldap_server_id: Option<Uuid>,
    pub ldap_object_uuid: Option<Uuid>,
}

#[derive(Clone, Debug)]
pub(crate) struct LegacyMembership {
    pub user_id: Uuid,
    pub role_id: Uuid,
    pub expires_at: Option<OffsetDateTime>,
    pub revoked_at: Option<OffsetDateTime>,
}

#[derive(Clone, Debug)]
pub(crate) struct LegacyTarget {
    pub id: Uuid,
    pub name: String,
    pub kind: String,
    pub options: Value,
}

#[derive(Clone, Debug)]
pub(crate) struct LegacyBinding {
    pub id: Uuid,
    pub user_id: Uuid,
    pub target_id: Uuid,
    pub account_kind: String,
    pub account_name: Option<String>,
    pub ldap_server_id: Option<Uuid>,
    pub ldap_object_uuid: Option<Uuid>,
    pub username_format: Option<String>,
    pub auth_method: String,
    pub enabled: bool,
    pub expires_at: Option<OffsetDateTime>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct Legacy {
    pub users: HashMap<Uuid, LegacyUser>,
    pub roles: HashMap<Uuid, String>,
    pub memberships: Vec<LegacyMembership>,
    /// `(target, role)`
    pub target_roles: Vec<(Uuid, Uuid)>,
    pub targets: Vec<LegacyTarget>,
    pub bindings: Vec<LegacyBinding>,
}

async fn load_legacy<C: ConnectionTrait>(db: &C) -> Result<Legacy, DbErr> {
    let mut legacy = Legacy::default();
    for user in read::user::Entity::find().all(db).await? {
        legacy.users.insert(
            user.id,
            LegacyUser {
                username: user.username,
                ldap_server_id: user.ldap_server_id,
                ldap_object_uuid: user.ldap_object_uuid,
            },
        );
    }
    for role in read::role::Entity::find().all(db).await? {
        legacy.roles.insert(role.id, role.name);
    }
    legacy.memberships = read::user_role::Entity::find()
        .all(db)
        .await?
        .into_iter()
        .map(|m| LegacyMembership {
            user_id: m.user_id,
            role_id: m.role_id,
            expires_at: m.expires_at,
            revoked_at: m.revoked_at,
        })
        .collect();
    legacy.target_roles = read::target_role::Entity::find()
        .all(db)
        .await?
        .into_iter()
        .map(|tr| (tr.target_id, tr.role_id))
        .collect();
    legacy.targets = read::target::Entity::find()
        .all(db)
        .await?
        .into_iter()
        .map(|t| LegacyTarget {
            id: t.id,
            name: t.name,
            kind: t.kind,
            options: t.options,
        })
        .collect();
    let mut bindings = read::binding::Entity::find().all(db).await?;
    bindings.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.cmp(&b.id)));
    legacy.bindings = bindings
        .into_iter()
        .map(|b| LegacyBinding {
            id: b.id,
            user_id: b.user_id,
            target_id: b.target_id,
            account_kind: b.account_kind,
            account_name: b.account_name,
            ldap_server_id: b.ldap_server_id,
            ldap_object_uuid: b.ldap_object_uuid,
            username_format: b.username_format,
            auth_method: b.auth_method,
            enabled: b.enabled,
            expires_at: b.expires_at,
        })
        .collect();
    Ok(legacy)
}

// ---- What the migration writes ----

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NewAccount {
    pub id: Uuid,
    pub target_id: Uuid,
    pub kind: &'static str,
    pub name: String,
    pub domain: Option<String>,
    pub auth_method: &'static str,
    pub credential: Option<Value>,
    pub username_format: Option<&'static str>,
    pub is_primary: bool,
    pub description: String,
    pub account_key: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NewAssignment {
    pub id: Uuid,
    pub user_id: Uuid,
    pub target_id: Uuid,
    pub account_id: Option<Uuid>,
    pub ldap_server_id: Option<Uuid>,
    pub ldap_object_uuid: Option<Uuid>,
    pub enabled: bool,
    pub expires_at: Option<OffsetDateTime>,
    pub note: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NewGrant {
    pub id: Uuid,
    pub role_id: Uuid,
    pub target_id: Uuid,
    pub account_id: Option<Uuid>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NewExclusion {
    pub id: Uuid,
    pub role_id: Uuid,
    pub user_id: Uuid,
    pub target_id: Uuid,
    pub account_id: Option<Uuid>,
    pub note: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NewReview {
    pub id: Uuid,
    pub category: &'static str,
    pub status: &'static str,
    pub user_id: Option<Uuid>,
    pub role_id: Option<Uuid>,
    pub target_id: Option<Uuid>,
    pub legacy_permission: String,
    pub reason: String,
    pub candidates: Vec<Uuid>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct Plan {
    pub accounts: Vec<NewAccount>,
    pub assignments: Vec<NewAssignment>,
    pub grants: Vec<NewGrant>,
    pub exclusions: Vec<NewExclusion>,
    pub reviews: Vec<NewReview>,
    /// Targets whose settings lose their credentials (now in their accounts).
    pub option_updates: Vec<(Uuid, Value)>,
}

const MIGRATED: &str = "migrated";
const ALREADY_MATCHING: &str = "already_matching";
const DUPLICATE: &str = "duplicate";
const NO_ACCOUNT: &str = "no_account";
const OVERLAPPING: &str = "overlapping";
const INEFFECTIVE: &str = "ineffective";
const AMBIGUOUS: &str = "ambiguous";

const INFO: &str = "info";
const PENDING: &str = "pending";

/// What `account_key` an account of a name, or a directory account of a format, has.
fn name_key(name: &str) -> String {
    format!("name:{}", name.trim().to_lowercase())
}

fn directory_key(format: &str) -> String {
    format!("directory:{format}")
}

fn assignment_key(account_id: Option<Uuid>) -> String {
    match account_id {
        Some(id) => format!("account:{id}"),
        None => "target".to_owned(),
    }
}

fn non_empty(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

/// The username a target's settings name, as the settings read it: `root` when the key is
/// missing, empty when it is blank.
fn username_of(block: &Value) -> String {
    match block.get("username") {
        None => "root".to_owned(),
        Some(Value::String(name)) => name.trim().to_owned(),
        Some(_) => String::new(),
    }
}

/// The later of two expiries, where `None` is never.
fn latest(a: Option<OffsetDateTime>, b: Option<OffsetDateTime>) -> Option<OffsetDateTime> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.max(b)),
        _ => None,
    }
}

/// The earlier of two expiries, where `None` is never.
fn earliest(a: Option<OffsetDateTime>, b: Option<OffsetDateTime>) -> Option<OffsetDateTime> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(a), None) => Some(a),
        (None, b) => b,
    }
}

fn is_account_protocol(kind: &str) -> bool {
    matches!(kind, "rdp" | "ssh" | "mysql" | "postgres")
}

impl Plan {
    #[allow(clippy::too_many_arguments)]
    fn review(
        &mut self,
        category: &'static str,
        status: &'static str,
        user_id: Option<Uuid>,
        role_id: Option<Uuid>,
        target_id: Option<Uuid>,
        legacy_permission: String,
        reason: &str,
        candidates: Vec<Uuid>,
    ) {
        self.reviews.push(NewReview {
            id: Uuid::new_v4(),
            category,
            status,
            user_id,
            role_id,
            target_id,
            legacy_permission,
            reason: reason.to_owned(),
            candidates,
        });
    }
}

/// One target's inventory while it is being planned.
struct Inventory {
    target_id: Uuid,
    accounts: Vec<NewAccount>,
}

impl Inventory {
    /// The id and authentication method of the account under `key`, if there is one.
    fn find(&self, key: &str) -> Option<(Uuid, &'static str)> {
        self.accounts
            .iter()
            .find(|account| account.account_key == key)
            .map(|account| (account.id, account.auth_method))
    }

    #[allow(clippy::too_many_arguments)]
    fn add(
        &mut self,
        kind: &'static str,
        name: &str,
        domain: Option<String>,
        auth_method: &'static str,
        credential: Option<Value>,
        username_format: Option<&'static str>,
        is_primary: bool,
        description: &str,
    ) -> Uuid {
        let account_key = match username_format {
            Some(format) if kind == "directory" => directory_key(format),
            _ => name_key(name),
        };
        if let Some((existing, _)) = self.find(&account_key) {
            return existing;
        }
        let id = Uuid::new_v4();
        self.accounts.push(NewAccount {
            id,
            target_id: self.target_id,
            kind,
            name: name.to_owned(),
            domain,
            auth_method,
            credential,
            username_format,
            is_primary,
            description: description.to_owned(),
            account_key,
        });
        id
    }

    fn name_of(&self, id: Uuid) -> String {
        self.accounts
            .iter()
            .find(|account| account.id == id)
            .map(|account| match (account.kind, account.name.is_empty()) {
                ("directory", _) => "the user's own directory account".to_owned(),
                (_, true) => "the user's Warpgate username".to_owned(),
                (_, false) => account.name.clone(),
            })
            .unwrap_or_default()
    }
}

/// Map the earlier permissions onto the unified model. Pure: what it reads is `legacy`, and
/// `now` decides which role memberships are active.
pub(crate) fn plan(legacy: &Legacy, now: OffsetDateTime) -> Plan {
    let mut plan = Plan::default();

    // Which roles reach each target, and each role's active members.
    let mut roles_of_target: HashMap<Uuid, Vec<Uuid>> = HashMap::new();
    for (target_id, role_id) in &legacy.target_roles {
        let roles = roles_of_target.entry(*target_id).or_default();
        if !roles.contains(role_id) {
            roles.push(*role_id);
        }
    }
    let mut members: HashMap<Uuid, Vec<&LegacyMembership>> = HashMap::new();
    for membership in &legacy.memberships {
        let active = membership.revoked_at.is_none()
            && membership.expires_at.is_none_or(|expires| expires > now);
        if active && legacy.users.contains_key(&membership.user_id) {
            members
                .entry(membership.role_id)
                .or_default()
                .push(membership);
        }
    }
    // Whether the user's roles reach the target, and until when (`Some(None)`: no end).
    let role_access = |user_id: Uuid, target_id: Uuid| -> Option<Option<OffsetDateTime>> {
        let mut access: Option<Option<OffsetDateTime>> = None;
        for role_id in roles_of_target.get(&target_id).into_iter().flatten() {
            for membership in members.get(role_id).into_iter().flatten() {
                if membership.user_id != user_id {
                    continue;
                }
                access = Some(match access {
                    None => membership.expires_at,
                    Some(until) => latest(until, membership.expires_at),
                });
            }
        }
        access
    };

    let mut targets: Vec<&LegacyTarget> = legacy.targets.iter().collect();
    targets.sort_by(|a, b| a.name.cmp(&b.name).then(a.id.cmp(&b.id)));

    for target in targets {
        let protocol = target.kind.as_str();
        let account_based = is_account_protocol(protocol);
        let block = target.options.get(protocol).cloned().unwrap_or(Value::Null);
        let mut inventory = Inventory {
            target_id: target.id,
            accounts: vec![],
        };
        let mut primary: Option<Uuid> = None;
        // Whether the primary account signs in with a stored credential.
        let mut primary_is_stored = false;
        // RDP "assigned Windows accounts": the accounts, and who each was assigned to.
        let mut per_user_accounts: Option<Vec<(Uuid, Vec<Uuid>)>> = None;
        // RDP: the target's Domain field, and what it meant in the target's mode.
        let rdp_domain = non_empty(block.get("domain").and_then(Value::as_str));
        let mut rdp_directory_format = "upn";
        let mut rdp_directory_mode = false;
        // SSH: how the target signed in, which its other accounts also used.
        let ssh_auth = block
            .get("auth")
            .cloned()
            .filter(Value::is_object)
            .unwrap_or_else(|| json!({"kind": "publickey"}));
        let ssh_auth_is_password = ssh_auth.get("kind").and_then(Value::as_str) == Some("password");

        match protocol {
            "rdp" => {
                let auth = block
                    .get("auth")
                    .cloned()
                    .filter(Value::is_object)
                    .unwrap_or_else(|| json!({"kind": "password", "password": ""}));
                match auth
                    .get("kind")
                    .and_then(Value::as_str)
                    .unwrap_or("password")
                {
                    "domain_account" => {
                        rdp_directory_mode = true;
                        rdp_directory_format =
                            match auth.get("username_format").and_then(Value::as_str) {
                                Some("down_level") => "down_level",
                                _ => "upn",
                            };
                        primary = Some(inventory.add(
                            "directory",
                            "",
                            rdp_domain.clone(),
                            "directory_password",
                            None,
                            Some(rdp_directory_format),
                            true,
                            "From the target's \"Active Directory Authentication\" sign-in setting.",
                        ));
                    }
                    "local_account" => {
                        let mut assigned = vec![];
                        for entry in auth
                            .get("accounts")
                            .and_then(Value::as_array)
                            .into_iter()
                            .flatten()
                        {
                            let Some(name) =
                                non_empty(entry.get("username").and_then(Value::as_str))
                            else {
                                continue;
                            };
                            let users: Vec<Uuid> = entry
                                .get("users")
                                .and_then(Value::as_array)
                                .into_iter()
                                .flatten()
                                .filter_map(Value::as_str)
                                .filter_map(|id| Uuid::parse_str(id).ok())
                                .collect();
                            let id = inventory.add(
                                "local",
                                &name,
                                rdp_domain.clone(),
                                "typed_password",
                                None,
                                None,
                                false,
                                "From the target's assigned Windows accounts.",
                            );
                            assigned.push((id, users));
                        }
                        per_user_accounts = Some(assigned);
                    }
                    _ => {
                        let username = username_of(&block);
                        if !username.is_empty() {
                            let password = auth
                                .get("password")
                                .cloned()
                                .unwrap_or_else(|| Value::String(String::new()));
                            let kind = if rdp_domain.is_some()
                                || username.contains('\\')
                                || username.contains('@')
                            {
                                "domain"
                            } else {
                                "local"
                            };
                            primary = Some(inventory.add(
                                kind,
                                &username,
                                rdp_domain.clone(),
                                "stored_credential",
                                Some(json!({"kind": "password", "password": password})),
                                None,
                                true,
                                "From the target's connection settings.",
                            ));
                            primary_is_stored = true;
                        }
                    }
                }
            }
            "ssh" => {
                let username = username_of(&block);
                primary = Some(inventory.add(
                    "local",
                    &username,
                    None,
                    "stored_credential",
                    Some(ssh_auth.clone()),
                    None,
                    true,
                    "From the target's connection settings.",
                ));
                primary_is_stored = true;
            }
            "mysql" | "postgres" => {
                let username = username_of(&block);
                if !username.is_empty() {
                    let auth = block
                        .get("auth")
                        .cloned()
                        .filter(Value::is_object)
                        .unwrap_or_else(|| json!({"kind": "password", "password": ""}));
                    primary = Some(inventory.add(
                        "local",
                        &username,
                        None,
                        "stored_credential",
                        Some(auth),
                        None,
                        true,
                        "From the target's connection settings.",
                    ));
                    primary_is_stored = true;
                }
            }
            _ => {}
        }

        // Users with account bindings here were held to them.
        let bindings: Vec<&LegacyBinding> = legacy
            .bindings
            .iter()
            .filter(|binding| {
                binding.target_id == target.id && legacy.users.contains_key(&binding.user_id)
            })
            .collect();
        let restricted: HashSet<Uuid> = bindings.iter().map(|binding| binding.user_id).collect();
        let mut assigned: HashSet<(Uuid, Option<Uuid>)> = HashSet::new();

        // Bindings: direct assignments for the users their roles let in.
        for binding in &bindings {
            let username = legacy
                .users
                .get(&binding.user_id)
                .map(|user| user.username.clone())
                .unwrap_or_default();
            let described = match binding.account_kind.as_str() {
                "directory" => "their own directory account".to_owned(),
                "managed" => "the target's configured account".to_owned(),
                _ => format!(
                    "account \"{}\"",
                    binding.account_name.as_deref().unwrap_or_default()
                ),
            };
            let permission = format!(
                "{username} was assigned {described} on \"{}\" (account binding)",
                target.name
            );
            let valid = match (
                protocol,
                binding.account_kind.as_str(),
                binding.auth_method.as_str(),
            ) {
                ("rdp", "directory", "directory_password")
                | ("rdp", "local", "typed_password")
                | ("rdp", "managed", "target_credential") => true,
                ("ssh", "managed", "target_credential") => true,
                ("ssh", "directory" | "local", "target_credential") => !ssh_auth_is_password,
                _ => false,
            };
            if !valid {
                plan.review(
                    INEFFECTIVE,
                    INFO,
                    Some(binding.user_id),
                    None,
                    Some(target.id),
                    permission,
                    "Not carried over: the target could not sign in this way, so the binding never worked.",
                    vec![],
                );
                continue;
            }
            let account: Result<Uuid, (&'static str, &'static str, Vec<Uuid>)> = match binding
                .account_kind
                .as_str()
            {
                "managed" => match primary.filter(|_| primary_is_stored) {
                    Some(id) => Ok(id),
                    None => Err((
                        NO_ACCOUNT,
                        "The target had no stored account for the binding to use.",
                        vec![],
                    )),
                },
                "local" => match non_empty(binding.account_name.as_deref()) {
                    None => Err((NO_ACCOUNT, "The binding named no account.", vec![])),
                    Some(name) => {
                        let wanted = if protocol == "rdp" {
                            "typed_password"
                        } else {
                            "stored_credential"
                        };
                        let existing = inventory.find(&name_key(&name));
                        match existing {
                            Some((id, method)) if method == wanted => Ok(id),
                            Some((id, _)) => Err((
                                AMBIGUOUS,
                                "The target's stored account has the same name, but the binding signed in with a password the user typed; using the stored one could widen access.",
                                vec![id],
                            )),
                            None if protocol == "rdp" => Ok(inventory.add(
                                "local",
                                &name,
                                if per_user_accounts.is_some() {
                                    rdp_domain.clone()
                                } else {
                                    None
                                },
                                "typed_password",
                                None,
                                None,
                                false,
                                "From an account binding.",
                            )),
                            None => Ok(inventory.add(
                                "local",
                                &name,
                                None,
                                "stored_credential",
                                Some(ssh_auth.clone()),
                                None,
                                false,
                                "From an account binding; signs in as the target did.",
                            )),
                        }
                    }
                },
                _ => {
                    let format: &'static str = match binding.username_format.as_deref() {
                        Some("down_level") => "down_level",
                        Some("account_name") => "account_name",
                        Some("account_at_domain") => "account_at_domain",
                        Some("upn") => "upn",
                        _ if protocol == "ssh" => "account_at_domain",
                        _ if rdp_directory_mode => rdp_directory_format,
                        _ => "upn",
                    };
                    Ok(if protocol == "rdp" {
                        inventory.add(
                            "directory",
                            "",
                            if rdp_directory_mode {
                                rdp_domain.clone()
                            } else {
                                None
                            },
                            "directory_password",
                            None,
                            Some(format),
                            false,
                            "From an account binding.",
                        )
                    } else {
                        inventory.add(
                            "directory",
                            "",
                            None,
                            "stored_credential",
                            Some(ssh_auth.clone()),
                            Some(format),
                            false,
                            "From an account binding; signs in as the target did.",
                        )
                    })
                }
            };
            let account_id = match account {
                Ok(id) => id,
                Err((category, reason, candidates)) => {
                    plan.review(
                        category,
                        PENDING,
                        Some(binding.user_id),
                        None,
                        Some(target.id),
                        permission,
                        reason,
                        candidates,
                    );
                    continue;
                }
            };
            let Some(role_expiry) = role_access(binding.user_id, target.id) else {
                plan.review(
                    INEFFECTIVE,
                    PENDING,
                    Some(binding.user_id),
                    None,
                    Some(target.id),
                    permission,
                    "Not carried over: none of the user's roles reached the target, so the binding granted nothing. Confirm it to grant it now.",
                    vec![account_id],
                );
                continue;
            };
            if !assigned.insert((binding.user_id, Some(account_id))) {
                plan.review(
                    DUPLICATE,
                    INFO,
                    Some(binding.user_id),
                    None,
                    Some(target.id),
                    permission,
                    "The same account was already assigned to the user; it is assigned once.",
                    vec![account_id],
                );
                continue;
            }
            let link = if binding.account_kind == "directory" {
                (binding.ldap_server_id, binding.ldap_object_uuid)
            } else {
                (None, None)
            };
            plan.assignments.push(NewAssignment {
                id: Uuid::new_v4(),
                user_id: binding.user_id,
                target_id: target.id,
                account_id: Some(account_id),
                ldap_server_id: link.0,
                ldap_object_uuid: link.1,
                enabled: binding.enabled,
                expires_at: earliest(binding.expires_at, role_expiry),
                note: format!("Migrated from account binding {}", binding.id),
            });
            plan.review(
                ALREADY_MATCHING,
                INFO,
                Some(binding.user_id),
                None,
                Some(target.id),
                permission,
                "Carried over as a direct assignment, expiring no later than the binding or the user's roles did.",
                vec![account_id],
            );
        }

        // RDP assigned Windows accounts: direct assignments for the users their roles let in.
        if let Some(accounts) = &per_user_accounts {
            for (account_id, users) in accounts {
                let account_name = inventory.name_of(*account_id);
                for user_id in users {
                    let Some(user) = legacy.users.get(user_id) else {
                        continue;
                    };
                    let permission = format!(
                        "{} was assigned Windows account \"{account_name}\" in the settings of \"{}\"",
                        user.username, target.name
                    );
                    if restricted.contains(user_id) {
                        plan.review(
                            OVERLAPPING,
                            INFO,
                            Some(*user_id),
                            None,
                            Some(target.id),
                            permission,
                            "Not carried over: the user's own account bindings on the target applied instead, as before.",
                            vec![*account_id],
                        );
                        continue;
                    }
                    let Some(role_expiry) = role_access(*user_id, target.id) else {
                        plan.review(
                            INEFFECTIVE,
                            PENDING,
                            Some(*user_id),
                            None,
                            Some(target.id),
                            permission,
                            "Not carried over: none of the user's roles reached the target, so it granted nothing. Confirm it to grant it now.",
                            vec![*account_id],
                        );
                        continue;
                    };
                    if !assigned.insert((*user_id, Some(*account_id))) {
                        plan.review(
                            DUPLICATE,
                            INFO,
                            Some(*user_id),
                            None,
                            Some(target.id),
                            permission,
                            "The same account was already assigned to the user; it is assigned once.",
                            vec![*account_id],
                        );
                        continue;
                    }
                    plan.assignments.push(NewAssignment {
                        id: Uuid::new_v4(),
                        user_id: *user_id,
                        target_id: target.id,
                        account_id: Some(*account_id),
                        ldap_server_id: None,
                        ldap_object_uuid: None,
                        enabled: true,
                        expires_at: role_expiry,
                        note: "Migrated from the target's assigned Windows accounts".to_owned(),
                    });
                    plan.review(
                        MIGRATED,
                        INFO,
                        Some(*user_id),
                        None,
                        Some(target.id),
                        permission,
                        "Carried over as a direct assignment, expiring no later than the user's roles did.",
                        vec![*account_id],
                    );
                }
            }
        }

        // Roles: the same group, granting the target's primary account.
        let all_accounts: Vec<Uuid> = inventory.accounts.iter().map(|a| a.id).collect();
        for role_id in roles_of_target.get(&target.id).into_iter().flatten() {
            let role_name = legacy
                .roles
                .get(role_id)
                .cloned()
                .unwrap_or_else(|| role_id.to_string());
            let permission = format!("Role \"{role_name}\" granted \"{}\"", target.name);
            if !account_based {
                plan.grants.push(NewGrant {
                    id: Uuid::new_v4(),
                    role_id: *role_id,
                    target_id: target.id,
                    account_id: None,
                });
                plan.review(
                    MIGRATED,
                    INFO,
                    None,
                    Some(*role_id),
                    Some(target.id),
                    permission,
                    "Granted by the access group of the same name; this protocol has no remote account.",
                    vec![],
                );
                continue;
            }
            if per_user_accounts.is_some() {
                plan.review(
                    AMBIGUOUS,
                    PENDING,
                    None,
                    Some(*role_id),
                    Some(target.id),
                    permission,
                    "The target's Windows accounts were assigned user by user, so its members' assignments were carried over one by one. Members without one get nothing on this target until you choose the account the group grants, or reject this.",
                    all_accounts.clone(),
                );
                continue;
            }
            let Some(account_id) = primary else {
                plan.review(
                    NO_ACCOUNT,
                    PENDING,
                    None,
                    Some(*role_id),
                    Some(target.id),
                    permission,
                    "The target had no account set up to sign in as. Add it to the target's Accounts, then confirm the account here.",
                    all_accounts.clone(),
                );
                continue;
            };
            plan.grants.push(NewGrant {
                id: Uuid::new_v4(),
                role_id: *role_id,
                target_id: target.id,
                account_id: Some(account_id),
            });
            plan.review(
                MIGRATED,
                INFO,
                None,
                Some(*role_id),
                Some(target.id),
                permission,
                "Granted by the access group of the same name, as the target's primary account.",
                vec![account_id],
            );
            for membership in members.get(role_id).into_iter().flatten() {
                if !restricted.contains(&membership.user_id) {
                    continue;
                }
                let username = legacy
                    .users
                    .get(&membership.user_id)
                    .map(|user| user.username.clone())
                    .unwrap_or_default();
                plan.exclusions.push(NewExclusion {
                    id: Uuid::new_v4(),
                    role_id: *role_id,
                    user_id: membership.user_id,
                    target_id: target.id,
                    account_id: Some(account_id),
                    note:
                        "Migration: the user's own account bindings restricted them on this target"
                            .to_owned(),
                });
                plan.review(
                    OVERLAPPING,
                    INFO,
                    Some(membership.user_id),
                    Some(*role_id),
                    Some(target.id),
                    format!(
                        "{username} reached \"{}\" through role \"{role_name}\" and had their own account bindings there",
                        target.name
                    ),
                    "Excluded from the group's account on this target: the user keeps only their own assignments there, as before.",
                    vec![account_id],
                );
            }
        }

        // The target's settings keep no credential.
        if account_based {
            let mut options = target.options.clone();
            if let Some(settings) = options.get_mut(protocol).and_then(Value::as_object_mut) {
                settings.insert("username".into(), Value::String(String::new()));
                match protocol {
                    "rdp" => {
                        settings.insert("domain".into(), Value::Null);
                        settings.insert("auth".into(), json!({"kind": "password", "password": ""}));
                    }
                    "ssh" => {
                        settings
                            .insert("auth".into(), json!({"kind": "publickey", "key_id": null}));
                    }
                    _ => {
                        settings.insert("auth".into(), json!({"kind": "password", "password": ""}));
                    }
                }
            }
            if options != target.options {
                plan.option_updates.push((target.id, options));
            }
        }

        plan.accounts.extend(inventory.accounts);
    }

    plan
}

/// A session's snapshot of an RDP target in a sign-in mode that no longer exists reads as
/// no target at all; it becomes a plain one (snapshots carry no credential).
fn normalize_snapshot(snapshot: &mut Value) -> bool {
    let Some(auth) = snapshot
        .get_mut("rdp")
        .and_then(Value::as_object_mut)
        .and_then(|rdp| rdp.get_mut("auth"))
    else {
        return false;
    };
    if auth.get("kind").and_then(Value::as_str) == Some("password") {
        return false;
    }
    *auth = json!({"kind": "password", "password": ""});
    true
}

async fn apply<C: ConnectionTrait>(db: &C, plan: &Plan) -> Result<(), DbErr> {
    let now = OffsetDateTime::now_utc();
    for account in &plan.accounts {
        target_account::ActiveModel {
            id: Set(account.id),
            target_id: Set(account.target_id),
            kind: Set(account.kind.to_owned()),
            name: Set(account.name.clone()),
            domain: Set(account.domain.clone()),
            auth_method: Set(account.auth_method.to_owned()),
            credential: Set(account.credential.clone()),
            username_format: Set(account.username_format.map(str::to_owned)),
            enabled: Set(true),
            is_primary: Set(account.is_primary),
            description: Set(account.description.clone()),
            account_key: Set(account.account_key.clone()),
            created_by: Set(None),
            created_at: Set(now),
            updated_at: Set(now),
        }
        .insert(db)
        .await?;
    }
    for (target_id, options) in &plan.option_updates {
        read::target::Entity::update_many()
            .col_expr(read::target::Column::Options, Expr::value(options.clone()))
            .filter(read::target::Column::Id.eq(*target_id))
            .exec(db)
            .await?;
    }
    for assignment in &plan.assignments {
        access_assignment::ActiveModel {
            id: Set(assignment.id),
            user_id: Set(assignment.user_id),
            target_id: Set(assignment.target_id),
            target_account_id: Set(assignment.account_id),
            account_key: Set(assignment_key(assignment.account_id)),
            ldap_server_id: Set(assignment.ldap_server_id),
            ldap_object_uuid: Set(assignment.ldap_object_uuid),
            enabled: Set(assignment.enabled),
            expires_at: Set(assignment.expires_at),
            origin: Set("migrated".to_owned()),
            note: Set(assignment.note.clone()),
            created_by: Set(None),
            updated_by: Set(None),
            created_at: Set(now),
            updated_at: Set(now),
        }
        .insert(db)
        .await?;
    }
    for grant in &plan.grants {
        access_group_grant::ActiveModel {
            id: Set(grant.id),
            role_id: Set(grant.role_id),
            target_id: Set(grant.target_id),
            target_account_id: Set(grant.account_id),
            account_key: Set(assignment_key(grant.account_id)),
            created_by: Set(None),
            created_at: Set(now),
        }
        .insert(db)
        .await?;
    }
    for exclusion in &plan.exclusions {
        access_group_exclusion::ActiveModel {
            id: Set(exclusion.id),
            role_id: Set(exclusion.role_id),
            user_id: Set(exclusion.user_id),
            target_id: Set(exclusion.target_id),
            target_account_id: Set(exclusion.account_id),
            account_key: Set(assignment_key(exclusion.account_id)),
            note: Set(exclusion.note.clone()),
            created_by: Set(None),
            created_at: Set(now),
        }
        .insert(db)
        .await?;
    }
    for review in &plan.reviews {
        access_migration_review::ActiveModel {
            id: Set(review.id),
            category: Set(review.category.to_owned()),
            status: Set(review.status.to_owned()),
            user_id: Set(review.user_id),
            role_id: Set(review.role_id),
            target_id: Set(review.target_id),
            legacy_permission: Set(review.legacy_permission.clone()),
            reason: Set(review.reason.clone()),
            candidate_account_ids: Set(json!(review.candidates)),
            resolution: Set(String::new()),
            resolved_by: Set(None),
            resolved_at: Set(None),
            created_at: Set(now),
        }
        .insert(db)
        .await?;
    }
    Ok(())
}

const SNAPSHOT_BATCH: u64 = 1000;

async fn normalize_snapshots<C: ConnectionTrait>(db: &C) -> Result<(), DbErr> {
    let backend = db.get_database_backend();
    let sessions = Alias::new("target_sessions");
    let id_col = Alias::new("id");
    let snapshot_col = Alias::new("target_snapshot");
    let mut last_id: Option<Uuid> = None;
    loop {
        let mut select = Query::select()
            .column(id_col.clone())
            .column(snapshot_col.clone())
            .from(sessions.clone())
            .and_where(Expr::col(snapshot_col.clone()).is_not_null())
            .order_by(id_col.clone(), Order::Asc)
            .limit(SNAPSHOT_BATCH)
            .to_owned();
        if let Some(last_id) = last_id {
            select.and_where(Expr::col(id_col.clone()).gt(last_id));
        }
        let rows = db.query_all(backend.build(&select)).await?;
        let done = (rows.len() as u64) < SNAPSHOT_BATCH;
        for row in &rows {
            let id: Uuid = row.try_get("", "id")?;
            last_id = Some(id);
            let snapshot: String = row.try_get("", "target_snapshot")?;
            let Ok(mut value) = serde_json::from_str::<Value>(&snapshot) else {
                continue;
            };
            if normalize_snapshot(&mut value) {
                let update = Query::update()
                    .table(sessions.clone())
                    .value(snapshot_col.clone(), value.to_string())
                    .and_where(Expr::col(id_col.clone()).eq(id))
                    .to_owned();
                db.execute(backend.build(&update)).await?;
            }
        }
        if done {
            return Ok(());
        }
    }
}

/// What the migration would do to the database as it is, written for an administrator:
/// for `warpgate access-migration-preview`, before upgrading. Writes nothing.
pub async fn preview<C: ConnectionTrait>(db: &C) -> Result<String, DbErr> {
    let legacy = load_legacy(db).await?;
    let plan = plan(&legacy, OffsetDateTime::now_utc());
    Ok(render(&legacy, &plan))
}

fn render(legacy: &Legacy, plan: &Plan) -> String {
    let target_name = |id: Option<Uuid>| {
        id.and_then(|id| legacy.targets.iter().find(|t| t.id == id))
            .map(|t| t.name.clone())
            .unwrap_or_default()
    };
    let mut out = String::new();
    let pending = plan.reviews.iter().filter(|r| r.status == PENDING).count();
    let _ = writeln!(out, "Access Control migration preview");
    let _ = writeln!(out, "================================");
    let _ = writeln!(
        out,
        "Target accounts to create:        {}",
        plan.accounts.len()
    );
    let _ = writeln!(
        out,
        "Direct assignments to create:     {}",
        plan.assignments.len()
    );
    let _ = writeln!(
        out,
        "Access-group grants to create:    {}",
        plan.grants.len()
    );
    let _ = writeln!(
        out,
        "Group exclusions to create:       {}",
        plan.exclusions.len()
    );
    let _ = writeln!(
        out,
        "Targets whose credentials move:   {}",
        plan.option_updates.len()
    );
    let _ = writeln!(out, "Items pending administrator review: {pending}");
    for (title, category) in [
        ("Ambiguous: an administrator must choose", AMBIGUOUS),
        ("No identifiable remote account", NO_ACCOUNT),
        ("Granted nothing before (not carried over)", INEFFECTIVE),
        ("Overlapping rules (mapped without widening)", OVERLAPPING),
        ("Duplicates (kept once)", DUPLICATE),
        ("Already in the new shape", ALREADY_MATCHING),
        ("Migrated automatically", MIGRATED),
    ] {
        let items: Vec<&NewReview> = plan
            .reviews
            .iter()
            .filter(|review| review.category == category)
            .collect();
        if items.is_empty() {
            continue;
        }
        let _ = writeln!(out, "\n{title} ({}):", items.len());
        for item in items {
            let status = if item.status == PENDING {
                "PENDING REVIEW"
            } else {
                "info"
            };
            let _ = writeln!(
                out,
                "  [{status}] {} (target {})\n      {}",
                item.legacy_permission,
                target_name(item.target_id),
                item.reason
            );
        }
    }
    let _ = writeln!(
        out,
        "\nSSO role mappings and API clients keep managing role membership; a role's grants decide what it gives. Users in a pending item have no access through it until it is confirmed."
    );
    out
}

/// Put the credentials back in the targets' settings, from their primary (and RDP assigned)
/// accounts, for `down`.
async fn restore_target_settings<C: ConnectionTrait>(db: &C) -> Result<(), DbErr> {
    let accounts = target_account::Entity::find().all(db).await?;
    for target in read::target::Entity::find().all(db).await? {
        let protocol = target.kind.clone();
        let mine: Vec<&target_account::Model> = accounts
            .iter()
            .filter(|account| account.target_id == target.id)
            .collect();
        let primary = mine.iter().find(|account| account.is_primary).copied();
        let mut options = target.options.clone();
        let Some(settings) = options
            .get_mut(protocol.as_str())
            .and_then(Value::as_object_mut)
        else {
            continue;
        };
        match (protocol.as_str(), primary) {
            ("rdp", Some(account)) if account.kind == "directory" => {
                let format = match account.username_format.as_deref() {
                    Some("down_level") => "down_level",
                    _ => "upn",
                };
                settings.insert(
                    "auth".into(),
                    json!({"kind": "domain_account", "username_format": format}),
                );
                settings.insert("domain".into(), json!(account.domain));
            }
            ("rdp", Some(account)) => {
                let password = account
                    .credential
                    .as_ref()
                    .and_then(|credential| credential.get("password"))
                    .cloned()
                    .unwrap_or_else(|| Value::String(String::new()));
                settings.insert("username".into(), Value::String(account.name.clone()));
                settings.insert("domain".into(), json!(account.domain));
                settings.insert(
                    "auth".into(),
                    json!({"kind": "password", "password": password}),
                );
            }
            ("rdp", None) => {
                let typed: Vec<&&target_account::Model> = mine
                    .iter()
                    .filter(|account| account.auth_method == "typed_password")
                    .collect();
                if typed.is_empty() {
                    continue;
                }
                let assignments = access_assignment::Entity::find()
                    .filter(access_assignment::Column::TargetId.eq(target.id))
                    .all(db)
                    .await?;
                let assigned: Vec<Value> = typed
                    .iter()
                    .map(|account| {
                        let users: Vec<String> = assignments
                            .iter()
                            .filter(|a| a.target_account_id == Some(account.id) && a.enabled)
                            .map(|a| a.user_id.to_string())
                            .collect();
                        json!({"username": account.name, "users": users})
                    })
                    .collect();
                settings.insert(
                    "auth".into(),
                    json!({"kind": "local_account", "accounts": assigned}),
                );
                settings.insert(
                    "domain".into(),
                    json!(typed.first().and_then(|account| account.domain.clone())),
                );
            }
            ("ssh", Some(account)) => {
                settings.insert("username".into(), Value::String(account.name.clone()));
                settings.insert(
                    "auth".into(),
                    account
                        .credential
                        .clone()
                        .unwrap_or_else(|| json!({"kind": "publickey"})),
                );
            }
            ("mysql" | "postgres", Some(account)) => {
                settings.insert("username".into(), Value::String(account.name.clone()));
                settings.insert(
                    "auth".into(),
                    account
                        .credential
                        .clone()
                        .unwrap_or_else(|| json!({"kind": "password", "password": ""})),
                );
            }
            _ => continue,
        }
        read::target::Entity::update_many()
            .col_expr(read::target::Column::Options, Expr::value(options))
            .filter(read::target::Column::Id.eq(target.id))
            .exec(db)
            .await?;
    }
    Ok(())
}

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let schema = Schema::new(manager.get_database_backend());
        manager
            .create_table(schema.create_table_from_entity(target_account::Entity))
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_target_accounts_unique")
                    .table(target_account::Entity)
                    .col(target_account::Column::TargetId)
                    .col(target_account::Column::AccountKey)
                    .unique()
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(schema.create_table_from_entity(access_assignment::Entity))
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_access_assignments_unique")
                    .table(access_assignment::Entity)
                    .col(access_assignment::Column::UserId)
                    .col(access_assignment::Column::TargetId)
                    .col(access_assignment::Column::AccountKey)
                    .unique()
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_access_assignments_target")
                    .table(access_assignment::Entity)
                    .col(access_assignment::Column::TargetId)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_access_assignments_account")
                    .table(access_assignment::Entity)
                    .col(access_assignment::Column::TargetAccountId)
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(schema.create_table_from_entity(access_group_grant::Entity))
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_access_group_grants_unique")
                    .table(access_group_grant::Entity)
                    .col(access_group_grant::Column::RoleId)
                    .col(access_group_grant::Column::TargetId)
                    .col(access_group_grant::Column::AccountKey)
                    .unique()
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_access_group_grants_target")
                    .table(access_group_grant::Entity)
                    .col(access_group_grant::Column::TargetId)
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(schema.create_table_from_entity(access_group_exclusion::Entity))
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_access_group_exclusions_unique")
                    .table(access_group_exclusion::Entity)
                    .col(access_group_exclusion::Column::RoleId)
                    .col(access_group_exclusion::Column::UserId)
                    .col(access_group_exclusion::Column::TargetId)
                    .col(access_group_exclusion::Column::AccountKey)
                    .unique()
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(schema.create_table_from_entity(access_migration_review::Entity))
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_access_migration_reviews_status")
                    .table(access_migration_review::Entity)
                    .col(access_migration_review::Column::Status)
                    .to_owned(),
            )
            .await?;

        let db = manager.get_connection();
        let legacy = load_legacy(db).await?;
        let plan = plan(&legacy, OffsetDateTime::now_utc());
        apply(db, &plan).await?;
        normalize_snapshots(db).await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        restore_target_settings(manager.get_connection()).await?;
        for table in [
            access_migration_review::Entity.into_table_ref(),
            access_group_exclusion::Entity.into_table_ref(),
            access_group_grant::Entity.into_table_ref(),
            access_assignment::Entity.into_table_ref(),
            target_account::Entity.into_table_ref(),
        ] {
            manager
                .drop_table(Table::drop().table(table).to_owned())
                .await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use time::Duration;

    use super::*;

    fn user(legacy: &mut Legacy, name: &str) -> Uuid {
        let id = Uuid::new_v4();
        legacy.users.insert(
            id,
            LegacyUser {
                username: name.to_owned(),
                ldap_server_id: None,
                ldap_object_uuid: None,
            },
        );
        id
    }

    fn role(legacy: &mut Legacy, name: &str, members: &[(Uuid, Option<OffsetDateTime>)]) -> Uuid {
        let id = Uuid::new_v4();
        legacy.roles.insert(id, name.to_owned());
        for (user_id, expires_at) in members {
            legacy.memberships.push(LegacyMembership {
                user_id: *user_id,
                role_id: id,
                expires_at: *expires_at,
                revoked_at: None,
            });
        }
        id
    }

    fn target(legacy: &mut Legacy, name: &str, kind: &str, settings: Value) -> Uuid {
        let id = Uuid::new_v4();
        legacy.targets.push(LegacyTarget {
            id,
            name: name.to_owned(),
            kind: kind.to_owned(),
            options: json!({ kind: settings }),
        });
        id
    }

    fn binding(
        legacy: &mut Legacy,
        user_id: Uuid,
        target_id: Uuid,
        kind: &str,
        name: Option<&str>,
        method: &str,
    ) -> Uuid {
        let id = Uuid::new_v4();
        legacy.bindings.push(LegacyBinding {
            id,
            user_id,
            target_id,
            account_kind: kind.to_owned(),
            account_name: name.map(str::to_owned),
            ldap_server_id: None,
            ldap_object_uuid: None,
            username_format: None,
            auth_method: method.to_owned(),
            enabled: true,
            expires_at: None,
        });
        id
    }

    fn pending(plan: &Plan) -> Vec<&NewReview> {
        plan.reviews
            .iter()
            .filter(|r| r.status == PENDING)
            .collect()
    }

    /// 21: a role reaching an SSH target becomes the same group granting its account, and the
    /// target's settings keep no credential.
    #[test]
    fn a_role_becomes_a_group_grant_of_the_primary_account() {
        let mut legacy = Legacy::default();
        let ahmad = user(&mut legacy, "ahmad");
        let ops = role(&mut legacy, "ops", &[(ahmad, None)]);
        let server = target(
            &mut legacy,
            "LINUX-SRV-01",
            "ssh",
            json!({"host": "h", "username": "deploy", "auth": {"kind": "password", "password": "enc"}}),
        );
        legacy.target_roles.push((server, ops));

        let plan = plan(&legacy, OffsetDateTime::now_utc());
        assert_eq!(plan.accounts.len(), 1);
        let account = &plan.accounts[0];
        assert_eq!(account.name, "deploy");
        assert!(account.is_primary);
        assert_eq!(
            account.credential,
            Some(json!({"kind": "password", "password": "enc"}))
        );
        assert_eq!(plan.grants.len(), 1);
        assert_eq!(plan.grants[0].account_id, Some(account.id));
        assert!(plan.assignments.is_empty() && plan.exclusions.is_empty());
        assert!(pending(&plan).is_empty());
        let (_, options) = &plan.option_updates[0];
        assert_eq!(options["ssh"]["username"], "");
        assert_eq!(options["ssh"]["auth"]["kind"], "publickey");
        assert_eq!(options["ssh"]["host"], "h");
    }

    /// 20, 23: a binding is carried over for a user the roles let in, expiring no later than
    /// the role did; the group's account is excluded for them, as their binding restricted
    /// them. A binding for a user the roles did not let in grants nothing, and waits.
    #[test]
    fn bindings_become_assignments_without_widening_access() {
        let mut legacy = Legacy::default();
        let ahmad = user(&mut legacy, "ahmad");
        let yusif = user(&mut legacy, "yusif");
        let outsider = user(&mut legacy, "outsider");
        let soon = OffsetDateTime::now_utc() + Duration::days(3);
        let admins = role(
            &mut legacy,
            "windows-admins",
            &[(ahmad, Some(soon)), (yusif, None)],
        );
        let server = target(
            &mut legacy,
            "WIN-SRV-01",
            "rdp",
            json!({"host": "w", "username": "administrator", "auth": {"kind": "password", "password": "enc"}}),
        );
        legacy.target_roles.push((server, admins));
        binding(
            &mut legacy,
            ahmad,
            server,
            "local",
            Some(r"WIN-SRV-01\support"),
            "typed_password",
        );
        binding(
            &mut legacy,
            outsider,
            server,
            "local",
            Some("backup"),
            "typed_password",
        );

        let plan = plan(&legacy, OffsetDateTime::now_utc());
        // administrator (primary), support (ahmad's), backup (the outsider's, for review)
        assert_eq!(plan.accounts.len(), 3);
        assert_eq!(plan.assignments.len(), 1);
        let assignment = &plan.assignments[0];
        assert_eq!(assignment.user_id, ahmad);
        assert_eq!(assignment.expires_at, Some(soon), "no later than the role");
        assert_eq!(plan.exclusions.len(), 1);
        assert_eq!(plan.exclusions[0].user_id, ahmad);
        assert!(
            !plan.assignments.iter().any(|a| a.user_id == outsider),
            "the outsider's binding granted nothing before, and grants nothing now"
        );
        let waiting = pending(&plan);
        assert_eq!(waiting.len(), 1);
        assert_eq!(waiting[0].user_id, Some(outsider));
        assert_eq!(waiting[0].category, INEFFECTIVE);
    }

    /// 22: a role on an RDP target whose accounts were assigned user by user is ambiguous;
    /// its members' own assignments are carried over one by one.
    #[test]
    fn per_user_windows_accounts_need_a_decision_for_the_group() {
        let mut legacy = Legacy::default();
        let ahmad = user(&mut legacy, "ahmad");
        let yusif = user(&mut legacy, "yusif");
        let admins = role(&mut legacy, "admins", &[(ahmad, None), (yusif, None)]);
        let server = target(
            &mut legacy,
            "WIN-SRV-02",
            "rdp",
            json!({"host": "w", "domain": "WIN-SRV-02", "auth": {"kind": "local_account", "accounts": [
                {"username": "support", "users": [ahmad.to_string()]},
                {"username": "SUPPORT", "users": [yusif.to_string()]},
            ]}}),
        );
        legacy.target_roles.push((server, admins));

        let plan = plan(&legacy, OffsetDateTime::now_utc());
        assert_eq!(
            plan.accounts.len(),
            1,
            "one account, however it was written"
        );
        assert_eq!(plan.accounts[0].auth_method, "typed_password");
        assert_eq!(plan.accounts[0].domain.as_deref(), Some("WIN-SRV-02"));
        assert_eq!(plan.assignments.len(), 2);
        assert!(plan.grants.is_empty(), "no account is chosen for the group");
        let waiting = pending(&plan);
        assert_eq!(waiting.len(), 1);
        assert_eq!(waiting[0].category, AMBIGUOUS);
        assert_eq!(waiting[0].role_id, Some(admins));
        assert_eq!(waiting[0].candidates, vec![plan.accounts[0].id]);
    }

    /// 24: the same account bound twice is assigned once.
    #[test]
    fn duplicates_are_assigned_once() {
        let mut legacy = Legacy::default();
        let ahmad = user(&mut legacy, "ahmad");
        let ops = role(&mut legacy, "ops", &[(ahmad, None)]);
        let server = target(
            &mut legacy,
            "LINUX-SRV-01",
            "ssh",
            json!({"host": "h", "username": "deploy"}),
        );
        legacy.target_roles.push((server, ops));
        binding(
            &mut legacy,
            ahmad,
            server,
            "local",
            Some("deploy"),
            "target_credential",
        );
        binding(
            &mut legacy,
            ahmad,
            server,
            "managed",
            None,
            "target_credential",
        );

        let plan = plan(&legacy, OffsetDateTime::now_utc());
        assert_eq!(plan.accounts.len(), 1, "deploy is the primary account");
        assert_eq!(plan.assignments.len(), 1);
        assert!(plan.reviews.iter().any(|r| r.category == DUPLICATE));
    }

    /// Protocols without accounts get an accountless grant; a database target with no
    /// username is left for review.
    #[test]
    fn accountless_targets_and_missing_accounts() {
        let mut legacy = Legacy::default();
        let ahmad = user(&mut legacy, "ahmad");
        let ops = role(&mut legacy, "ops", &[(ahmad, None)]);
        let web = target(&mut legacy, "web", "http", json!({"url": "http://x"}));
        let db = target(
            &mut legacy,
            "db",
            "postgres",
            json!({"host": "d", "username": ""}),
        );
        legacy.target_roles.push((web, ops));
        legacy.target_roles.push((db, ops));

        let plan = plan(&legacy, OffsetDateTime::now_utc());
        assert_eq!(plan.grants.len(), 1);
        assert_eq!(plan.grants[0].target_id, web);
        assert_eq!(plan.grants[0].account_id, None);
        let waiting = pending(&plan);
        assert_eq!(waiting.len(), 1);
        assert_eq!(waiting[0].category, NO_ACCOUNT);
        assert_eq!(waiting[0].target_id, Some(db));
    }

    /// Expired and revoked memberships reached nothing, so they migrate nothing.
    #[test]
    fn inactive_memberships_carry_nothing() {
        let mut legacy = Legacy::default();
        let ahmad = user(&mut legacy, "ahmad");
        let past = OffsetDateTime::now_utc() - Duration::days(1);
        let ops = role(&mut legacy, "ops", &[(ahmad, Some(past))]);
        let server = target(&mut legacy, "LINUX", "ssh", json!({"host": "h"}));
        legacy.target_roles.push((server, ops));
        binding(
            &mut legacy,
            ahmad,
            server,
            "local",
            Some("deploy"),
            "target_credential",
        );

        let plan = plan(&legacy, OffsetDateTime::now_utc());
        assert!(plan.assignments.is_empty());
        assert!(plan.exclusions.is_empty());
        assert_eq!(
            plan.accounts[0].name, "root",
            "the settings' default username"
        );
    }

    #[test]
    fn snapshots_lose_retired_sign_in_modes() {
        let mut snapshot = json!({"name": "w", "rdp": {"auth": {"kind": "domain_account"}}});
        assert!(normalize_snapshot(&mut snapshot));
        assert_eq!(snapshot["rdp"]["auth"]["kind"], "password");
        assert!(!normalize_snapshot(&mut snapshot));
        let mut ssh = json!({"name": "s", "ssh": {"auth": {"kind": "password"}}});
        assert!(!normalize_snapshot(&mut ssh));
    }

    #[test]
    fn the_preview_lists_pending_items() {
        let mut legacy = Legacy::default();
        let ops = role(&mut legacy, "ops", &[]);
        let db = target(
            &mut legacy,
            "db",
            "mysql",
            json!({"host": "d", "username": ""}),
        );
        legacy.target_roles.push((db, ops));
        let report = render(&legacy, &plan(&legacy, OffsetDateTime::now_utc()));
        assert!(report.contains("PENDING REVIEW"), "{report}");
        assert!(
            report.contains("Items pending administrator review: 1"),
            "{report}"
        );
    }
}
