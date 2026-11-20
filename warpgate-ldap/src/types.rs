use poem_openapi::Enum;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use warpgate_tls::TlsMode;

#[derive(Debug, Clone, Copy, Enum)]
pub enum LdapUsernameAttribute {
    Cn,
    Uid,
    Email,
    UserPrincipalName,
    SamAccountName,
}

impl LdapUsernameAttribute {
    pub const fn attribute_name(self) -> &'static str {
        match self {
            Self::Cn => "cn",
            Self::Uid => "uid",
            Self::Email => "mail",
            Self::UserPrincipalName => "userPrincipalName",
            Self::SamAccountName => "sAMAccountName",
        }
    }
}

impl TryFrom<&str> for LdapUsernameAttribute {
    type Error = ();

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(match value {
            "cn" => Self::Cn,
            "uid" => Self::Uid,
            "mail" => Self::Email,
            "userPrincipalName" => Self::UserPrincipalName,
            "sAMAccountName" => Self::SamAccountName,
            _ => return Err(()),
        })
    }
}

#[derive(Debug, Clone)]
pub struct LdapConfig {
    pub host: String,
    pub port: u16,
    pub bind_dn: String,
    pub bind_password: String,
    pub tls_mode: TlsMode,
    pub tls_verify: bool,
    pub base_dns: Vec<String>,
    pub user_filter: String,
    pub username_attribute: LdapUsernameAttribute,
    pub ssh_key_attribute: String,
    pub uuid_attribute: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdapUser {
    pub username: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub dn: String,
    pub object_uuid: Uuid,
    pub ssh_public_keys: Vec<String>,
    /// The directory's record of the last password change, as the server
    /// returned it — Active Directory's `pwdLastSet`, or `pwdChangedTime`
    /// where a password policy overlay keeps one. Opaque: compared, never
    /// parsed. Never the password or anything derived from it.
    #[serde(default)]
    pub password_last_set: Option<String>,
    /// Active Directory's pre-Windows 2000 account name (`alice`), when the entry has one.
    #[serde(default)]
    pub sam_account_name: Option<String>,
    /// The entry's user principal name (`alice@corp.example.com`), when it has one.
    #[serde(default)]
    pub user_principal_name: Option<String>,
}

/// The answer to a user's password, from [`crate::authenticate_user`].
#[derive(Debug, Clone)]
pub enum LdapAuthOutcome {
    /// The directory accepted a bind as this entry with the password.
    Authenticated(LdapUser),
    /// The directory, or the checks before it, refused the user.
    Rejected(LdapBindRejection),
}

/// Why a user's password was refused.
///
/// For the server's log only. A client is told nothing more than that the
/// login failed, so these never distinguish "no such user" from "wrong
/// password" to whoever is trying passwords.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LdapBindRejection {
    /// Not in the directory any more, or no longer matched by the server's
    /// user filter (which is where a filter excluding disabled accounts
    /// takes effect).
    UserNotFound,
    /// Refused before contacting the directory: an empty password makes a
    /// simple bind "unauthenticated" (RFC 4513 §5.1.2), which many servers
    /// answer with success without checking anything.
    EmptyPassword,
    InvalidCredentials,
    AccountDisabled,
    AccountLocked,
    AccountExpired,
    PasswordExpired,
    PasswordMustChange,
    /// Outside the account's permitted logon hours or workstations.
    LogonRestricted,
    /// Any other refusal of the bind, by LDAP result code.
    Refused {
        result_code: u32,
    },
}

impl std::fmt::Display for LdapBindRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UserNotFound => {
                f.write_str("no directory entry matches the linked user and the user filter")
            }
            Self::EmptyPassword => f.write_str("empty password"),
            Self::InvalidCredentials => f.write_str("invalid credentials"),
            Self::AccountDisabled => f.write_str("account disabled"),
            Self::AccountLocked => f.write_str("account locked out"),
            Self::AccountExpired => f.write_str("account expired"),
            Self::PasswordExpired => f.write_str("password expired"),
            Self::PasswordMustChange => f.write_str("password must be changed"),
            Self::LogonRestricted => {
                f.write_str("logon not permitted at this time or from this workstation")
            }
            Self::Refused { result_code } => {
                write!(f, "bind refused with LDAP result code {result_code}")
            }
        }
    }
}
