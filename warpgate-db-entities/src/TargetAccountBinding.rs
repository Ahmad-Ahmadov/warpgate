//! An administrator's assignment of a remote account to a user on a target: which account
//! on that server the user may sign in as, and how Warpgate authenticates it there.
//!
//! A directory account is not copied by name: the binding records the user's LDAP link
//! (`ldap_server_id`, `ldap_object_uuid`) as it was when the account was assigned, and is
//! only good while the user is still linked to that same entry. The name signed in with is
//! read from the directory each time. No binding holds a password.

use poem_openapi::Enum;
use sea_orm::entity::prelude::*;
use serde::Serialize;
use time::OffsetDateTime;
use uuid::Uuid;

/// What kind of remote account a binding names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Enum, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(16))")]
#[oai(rename = "TargetAccountKind")]
pub enum TargetAccountKind {
    /// The user's own directory (LDAP / Active Directory) account, from their LDAP link.
    #[sea_orm(string_value = "directory")]
    #[oai(rename = "directory")]
    Directory,
    /// An account of the target itself (a local Windows or Linux account), by name.
    #[sea_orm(string_value = "local")]
    #[oai(rename = "local")]
    Local,
    /// The account configured on the target, with its stored or Vault credential.
    #[sea_orm(string_value = "managed")]
    #[oai(rename = "managed")]
    Managed,
}

/// How Warpgate authenticates a bound account to the target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Enum, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(32))")]
#[oai(rename = "TargetAccountAuthMethod")]
pub enum TargetAccountAuthMethod {
    /// The user's directory password: checked with the directory, used for one connection.
    /// A native RDP connection reuses the password the user signed in to Warpgate with.
    #[sea_orm(string_value = "directory_password")]
    #[oai(rename = "directory_password")]
    DirectoryPassword,
    /// The account's password, typed by the user when connecting, checked by the target.
    #[sea_orm(string_value = "typed_password")]
    #[oai(rename = "typed_password")]
    TypedPassword,
    /// The credential configured on the target: a stored or Vault password, Warpgate's SSH
    /// keys, a Vault-signed SSH certificate, or an AWS role.
    #[sea_orm(string_value = "target_credential")]
    #[oai(rename = "target_credential")]
    TargetCredential,
}

/// How a directory account is named to the target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Enum, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(16))")]
#[oai(rename = "DirectoryUsernameFormat")]
pub enum DirectoryUsernameFormat {
    /// `alice@corp.example.com`, the user principal name.
    #[sea_orm(string_value = "upn")]
    #[oai(rename = "upn")]
    Upn,
    /// `CORP\alice`, the domain and account name.
    #[sea_orm(string_value = "down_level")]
    #[oai(rename = "down_level")]
    DownLevel,
    /// `alice`, the account name alone (SSSD with `use_fully_qualified_names = False`).
    #[sea_orm(string_value = "account_name")]
    #[oai(rename = "account_name")]
    AccountName,
    /// `alice@corp.example.com` built from the account name and the DNS domain (SSSD's
    /// fully-qualified names), which can differ from the user principal name.
    #[sea_orm(string_value = "account_at_domain")]
    #[oai(rename = "account_at_domain")]
    AccountAtDomain,
}

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize)]
#[sea_orm(table_name = "target_account_bindings")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub user_id: Uuid,
    pub target_id: Uuid,
    pub account_kind: TargetAccountKind,
    /// A local account's name. `None` for a directory account (read from the directory) and
    /// a managed one (the target's configured account).
    #[sea_orm(column_type = "String(StringLen::N(256))", nullable)]
    pub account_name: Option<String>,
    /// The user's LDAP link when a directory account was assigned. The binding is good only
    /// while the user is still linked to this same entry.
    pub ldap_server_id: Option<Uuid>,
    pub ldap_object_uuid: Option<Uuid>,
    pub username_format: Option<DirectoryUsernameFormat>,
    pub auth_method: TargetAccountAuthMethod,
    pub enabled: bool,
    pub expires_at: Option<OffsetDateTime>,
    pub created_by: Option<Uuid>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    /// The account in a form that does not change with how it is written, unique per user
    /// and target: `directory:<entry UUID>`, `local:<name in lower case>` or `managed`.
    #[sea_orm(column_type = "String(StringLen::N(300))")]
    pub account_key: String,
}

impl Model {
    /// The key a binding of this kind and name is stored under.
    pub fn key_for(
        kind: TargetAccountKind,
        account_name: Option<&str>,
        ldap_object_uuid: Option<Uuid>,
    ) -> String {
        match kind {
            TargetAccountKind::Directory => format!(
                "directory:{}",
                ldap_object_uuid
                    .map(|id| id.to_string())
                    .unwrap_or_default()
            ),
            TargetAccountKind::Local => format!(
                "local:{}",
                account_name.unwrap_or_default().trim().to_lowercase()
            ),
            TargetAccountKind::Managed => "managed".to_owned(),
        }
    }

    /// Whether the binding may be used at `now`: enabled, and not past its expiry.
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

impl ActiveModelBehavior for ActiveModel {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_account_is_keyed_the_same_however_it_is_written() {
        assert_eq!(
            Model::key_for(TargetAccountKind::Local, Some(" Deploy "), None),
            "local:deploy"
        );
        let entry = Uuid::from_u128(5);
        assert_eq!(
            Model::key_for(TargetAccountKind::Directory, Some("ignored"), Some(entry)),
            format!("directory:{entry}")
        );
        assert_eq!(
            Model::key_for(TargetAccountKind::Managed, None, None),
            "managed"
        );
    }
}
