//! A remote account of a target: an identity Warpgate can sign in to the target as, with
//! how it authenticates there (its Accounts section, the target's inventory).
//!
//! Accounts never grant access: only an Access Control assignment lets a user connect as
//! one (`AccessAssignment`, or an access group's grant). A target can hold any number of
//! them. A stored credential is kept here once, encrypted (or as a secret reference), and
//! never returned by the API once saved. A linked directory account names no one: it stands
//! for each user's own directory identity, resolved from their verified LDAP link when they
//! connect, and Warpgate keeps no password for it.

use poem_openapi::Enum;
use sea_orm::entity::prelude::*;
use serde::Serialize;
use time::OffsetDateTime;
use uuid::Uuid;
use warpgate_common::TargetAccountCredential;

/// What kind of identity an account is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Enum, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(16))")]
#[oai(rename = "TargetAccountKind")]
pub enum TargetAccountKind {
    /// An account of the target itself: a local Windows or Linux account, a database user.
    #[sea_orm(string_value = "local")]
    #[oai(rename = "local")]
    Local,
    /// A named domain account (`CORP\sqladmin`), the same for every user assigned to it.
    #[sea_orm(string_value = "domain")]
    #[oai(rename = "domain")]
    Domain,
    /// Each connecting user's own directory (LDAP / Active Directory) account, from their
    /// verified LDAP link. No user can stand in for another through it.
    #[sea_orm(string_value = "directory")]
    #[oai(rename = "directory")]
    Directory,
}

impl TargetAccountKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Domain => "domain",
            Self::Directory => "directory",
        }
    }
}

/// How Warpgate authenticates an account to the target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Enum, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(32))")]
#[oai(rename = "TargetAccountAuthMethod")]
pub enum TargetAccountAuthMethod {
    /// The account's own credential, held by Warpgate: a password (encrypted, or a secret
    /// reference), Warpgate's SSH keys, a Vault-signed SSH certificate, or a cloud role.
    #[sea_orm(string_value = "stored_credential")]
    #[oai(rename = "stored_credential")]
    StoredCredential,
    /// A password the user types when connecting; the target checks it (RDP).
    #[sea_orm(string_value = "typed_password")]
    #[oai(rename = "typed_password")]
    TypedPassword,
    /// The user's own directory password, checked with the directory first (RDP). A native
    /// RDP connection reuses the password the user signed in to Warpgate with.
    #[sea_orm(string_value = "directory_password")]
    #[oai(rename = "directory_password")]
    DirectoryPassword,
}

impl TargetAccountAuthMethod {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StoredCredential => "stored_credential",
            Self::TypedPassword => "typed_password",
            Self::DirectoryPassword => "directory_password",
        }
    }
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

impl DirectoryUsernameFormat {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Upn => "upn",
            Self::DownLevel => "down_level",
            Self::AccountName => "account_name",
            Self::AccountAtDomain => "account_at_domain",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize)]
#[sea_orm(table_name = "target_accounts")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub target_id: Uuid,
    pub kind: TargetAccountKind,
    /// The account's name on the target, as an administrator writes it: `deploy`,
    /// `WIN-SRV-01\support`, `.\support`, `CORP\sqladmin`, `svc@corp.example.com`. Empty for a
    /// directory account (each user's own), and, on SSH, for "the user's Warpgate username".
    #[sea_orm(column_type = "String(StringLen::N(256))")]
    pub name: String,
    /// RDP: the computer (for a local account) or the domain's NetBIOS name (for a directory
    /// account) the account belongs to, when its name does not say.
    #[sea_orm(column_type = "String(StringLen::N(256))", nullable)]
    pub domain: Option<String>,
    pub auth_method: TargetAccountAuthMethod,
    /// A [`TargetAccountCredential`], secrets encrypted; only for a stored credential.
    pub credential: Option<serde_json::Value>,
    /// How a directory account is named to the target.
    pub username_format: Option<DirectoryUsernameFormat>,
    pub enabled: bool,
    /// The target's primary account: the one its connection settings named before accounts
    /// existed. Jump-host hops sign in as it, a ticket without an assignment connects as it,
    /// and the legacy API reads and writes it. It grants nobody anything.
    pub is_primary: bool,
    #[sea_orm(column_type = "Text")]
    pub description: String,
    /// The account in a form that does not change with how it is written, unique per target:
    /// `name:<name in lower case>` or `directory:<format>`.
    #[sea_orm(column_type = "String(StringLen::N(300))")]
    pub account_key: String,
    pub created_by: Option<Uuid>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

impl Model {
    /// The key an account of this kind, name and format is stored under.
    pub fn key_for(
        kind: TargetAccountKind,
        name: &str,
        format: Option<DirectoryUsernameFormat>,
    ) -> String {
        match kind {
            TargetAccountKind::Directory => format!(
                "directory:{}",
                format.unwrap_or(DirectoryUsernameFormat::Upn).as_str()
            ),
            TargetAccountKind::Local | TargetAccountKind::Domain => {
                format!("name:{}", name.trim().to_lowercase())
            }
        }
    }

    /// The stored credential, decoded (secrets still encrypted).
    pub fn credential(&self) -> Result<Option<TargetAccountCredential>, serde_json::Error> {
        self.credential
            .clone()
            .map(serde_json::from_value)
            .transpose()
    }

    /// The account as people write it, for lists and the audit log.
    pub fn display_name(&self) -> String {
        match self.kind {
            TargetAccountKind::Directory => {
                "Linked directory account (each user's own)".to_owned()
            }
            TargetAccountKind::Local | TargetAccountKind::Domain if self.name.is_empty() => {
                "The user's Warpgate username".to_owned()
            }
            TargetAccountKind::Local | TargetAccountKind::Domain => self.name.clone(),
        }
    }
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::Target::Entity",
        from = "Column::TargetId",
        to = "super::Target::Column::Id",
        on_delete = "Cascade"
    )]
    Target,
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
            Model::key_for(TargetAccountKind::Local, " Deploy ", None),
            "name:deploy"
        );
        assert_eq!(
            Model::key_for(TargetAccountKind::Domain, r"CORP\SqlAdmin", None),
            Model::key_for(TargetAccountKind::Local, r"corp\sqladmin", None),
            "one name is one account, whatever kind it is filed under"
        );
        assert_eq!(
            Model::key_for(
                TargetAccountKind::Directory,
                "ignored",
                Some(DirectoryUsernameFormat::DownLevel)
            ),
            "directory:down_level"
        );
    }
}
