//! Signing in to an RDP target as the connecting user's own directory account.
//!
//! A target whose authentication is [`RdpTargetAuth::DomainAccount`] has no stored password.
//! The user types their directory (Active Directory) password when they connect, and Warpgate
//! signs in to the target with it, so the Windows session runs as that user.
//!
//! The account is never the user's choice: it is the directory entry their Warpgate user is
//! linked to (`ldap_server_id` and `ldap_object_uuid`, set when an administrator imported or
//! linked them), looked up by that entry's UUID. Nothing a client sends names it, so no request
//! can sign in as somebody else.
//!
//! The password is checked first by binding to the directory as that entry
//! ([`warpgate_ldap::authenticate_user`], LDAPS or StartTLS only). That gives the user a
//! precise answer (wrong password, disabled, locked, expired) before the target is tried,
//! and applies the directory's own restrictions. The target then checks it again, through
//! network-level authentication, and applies its own (who may sign in over RDP).
//!
//! The password lives in [`DomainCredentials`] only, in memory, until the connection to the
//! target has used it, and is wiped when that is dropped. It is never stored, logged, sent
//! to the viewer or recorded: it goes to the target in the CredSSP exchange, not as input.

use std::fmt;

use sea_orm::{DatabaseConnection, EntityTrait};
use tracing::{info, warn};
use uuid::Uuid;
use warpgate_common::{RdpDomainUsernameFormat, RdpTargetAuth, TargetRdpOptions};
use warpgate_db_entities::{LdapServer, User};
use warpgate_ldap::{LdapAuthOutcome, LdapBindRejection, LdapConfig, LdapUser};
/// Re-exported for the protocol crates that take the password, so they wipe it the same way.
pub use zeroize::{Zeroize, Zeroizing};

/// The longest domain password taken: what an RDP Client Info PDU carries, and more than
/// Active Directory allows.
pub const MAX_DOMAIN_PASSWORD_CHARS: usize = 256;

/// Whether a target signs users in as their own directory account.
pub const fn uses_domain_account(options: &TargetRdpOptions) -> bool {
    matches!(options.auth, RdpTargetAuth::DomainAccount(_))
}

/// The directory account a user signs in to a target as.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DomainAccount {
    /// The name the target is given: a user principal name, or an account name to go with
    /// `domain`.
    pub username: String,
    pub domain: Option<String>,
}

impl DomainAccount {
    /// The account as a person writes it: `CORP\alice` or `alice@corp.example.com`.
    pub fn display_name(&self) -> String {
        match &self.domain {
            Some(domain) => format!("{domain}\\{}", self.username),
            None => self.username.clone(),
        }
    }
}

/// A directory account and the password the user typed for it, for one connection to a
/// target. The password is wiped from memory when this is dropped, and never printed.
pub struct DomainCredentials {
    account: DomainAccount,
    password: Zeroizing<String>,
}

impl DomainCredentials {
    pub const fn account(&self) -> &DomainAccount {
        &self.account
    }

    pub fn password(&self) -> &str {
        &self.password
    }
}

impl fmt::Debug for DomainCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DomainCredentials")
            .field("account", &self.account)
            .field("password", &"<redacted>")
            .finish()
    }
}

/// Why a user cannot sign in to a target as their directory account.
#[derive(Debug, thiserror::Error)]
pub enum DomainAccountError {
    /// The Warpgate user is not linked to a directory entry, or its server is gone.
    #[error("the user is not linked to a directory account")]
    NotLinked,
    /// The directory entry has neither a user principal name nor an account name.
    #[error("the directory account has no name to sign in with")]
    NoAccountName,
    /// The directory refused the password, or the account.
    #[error("the directory refused the sign-in: {0}")]
    Rejected(LdapBindRejection),
    /// The directory could not be asked: disabled here, unreachable, misconfigured.
    #[error("the directory could not check the password: {0}")]
    DirectoryUnavailable(String),
    #[error(transparent)]
    Database(#[from] sea_orm::DbErr),
}

impl DomainAccountError {
    /// What to tell the user. The account is their own, so the directory's reason is
    /// theirs to know; nothing here says anything about any other account.
    pub const fn user_message(&self) -> &'static str {
        match self {
            Self::NotLinked => {
                "Your Warpgate account is not linked to a directory account, so it cannot sign in to this target. Ask an administrator."
            }
            Self::NoAccountName => {
                "Your directory account has no user principal name or account name to sign in with. Ask an administrator."
            }
            Self::Rejected(reason) => match reason {
                LdapBindRejection::InvalidCredentials | LdapBindRejection::EmptyPassword => {
                    "The domain password is incorrect."
                }
                LdapBindRejection::AccountDisabled => "Your domain account is disabled.",
                LdapBindRejection::AccountLocked => "Your domain account is locked out.",
                LdapBindRejection::AccountExpired => "Your domain account has expired.",
                LdapBindRejection::PasswordExpired | LdapBindRejection::PasswordMustChange => {
                    "Your domain password has expired. Change it, then connect again."
                }
                LdapBindRejection::LogonRestricted => {
                    "Your domain account may not sign in at this time or from here."
                }
                LdapBindRejection::UserNotFound => {
                    "Your directory account was not found, or may no longer sign in."
                }
                LdapBindRejection::Refused { .. } => "The directory refused the sign-in.",
            },
            Self::DirectoryUnavailable(_) | Self::Database(_) => {
                "The directory could not check the password right now. Try again later."
            }
        }
    }

    /// Whether the user may try another password: the directory gave a verdict on this one.
    pub const fn may_retry(&self) -> bool {
        matches!(
            self,
            Self::Rejected(
                LdapBindRejection::InvalidCredentials | LdapBindRejection::EmptyPassword
            ) | Self::DirectoryUnavailable(_)
        )
    }
}

/// The directory of the Warpgate user `user_id`: its server's settings and the user's entry.
async fn directory_of(
    db: &DatabaseConnection,
    user_id: Uuid,
) -> Result<(LdapConfig, Uuid), DomainAccountError> {
    let user = User::Entity::find_by_id(user_id)
        .one(db)
        .await?
        .ok_or(DomainAccountError::NotLinked)?;
    let (Some(server_id), Some(object_uuid)) = (user.ldap_server_id, user.ldap_object_uuid) else {
        return Err(DomainAccountError::NotLinked);
    };
    let server = LdapServer::Entity::find_by_id(server_id)
        .one(db)
        .await?
        .ok_or(DomainAccountError::NotLinked)?;
    if !server.enabled {
        return Err(DomainAccountError::DirectoryUnavailable(format!(
            "the LDAP server {} is disabled",
            server.name
        )));
    }
    let config = LdapConfig::try_from(&server)
        .map_err(|error| DomainAccountError::DirectoryUnavailable(error.to_string()))?;
    Ok((config, object_uuid))
}

fn username_format(options: &TargetRdpOptions) -> RdpDomainUsernameFormat {
    match &options.auth {
        RdpTargetAuth::DomainAccount(auth) => auth.username_format,
        RdpTargetAuth::Password(_) => RdpDomainUsernameFormat::default(),
    }
}

/// The account `user_id` would sign in to the target as, looked up in the directory with
/// Warpgate's service account: to show the user who they will be before they type a password.
pub async fn find_domain_account(
    db: &DatabaseConnection,
    user_id: Uuid,
    options: &TargetRdpOptions,
) -> Result<DomainAccount, DomainAccountError> {
    let (config, object_uuid) = directory_of(db, user_id).await?;
    let entry = warpgate_ldap::find_user_by_uuid(&config, &object_uuid)
        .await
        .map_err(|error| DomainAccountError::DirectoryUnavailable(error.to_string()))?
        .ok_or(DomainAccountError::Rejected(
            LdapBindRejection::UserNotFound,
        ))?;
    account_of(&entry, username_format(options), options.domain.as_deref())
        .ok_or(DomainAccountError::NoAccountName)
}

/// Check `password` for `user_id`'s own directory entry, by binding to the directory as it,
/// and return what to sign in to the target with.
pub async fn verify_domain_password(
    db: &DatabaseConnection,
    user_id: Uuid,
    options: &TargetRdpOptions,
    password: Zeroizing<String>,
) -> Result<DomainCredentials, DomainAccountError> {
    let (config, object_uuid) = directory_of(db, user_id).await?;
    let entry = match warpgate_ldap::authenticate_user(&config, &object_uuid, &password).await {
        Ok(LdapAuthOutcome::Authenticated(entry)) => entry,
        Ok(LdapAuthOutcome::Rejected(reason)) => {
            warn!(%user_id, %reason, "The directory refused the domain password for a target sign-in");
            return Err(DomainAccountError::Rejected(reason));
        }
        Err(error) => {
            warn!(%user_id, %error, "Could not check the domain password with the directory");
            return Err(DomainAccountError::DirectoryUnavailable(error.to_string()));
        }
    };
    let account = account_of(&entry, username_format(options), options.domain.as_deref())
        .ok_or(DomainAccountError::NoAccountName)?;
    info!(
        %user_id,
        account = %account.display_name(),
        "Domain password verified; signing in to the target as the user's own account"
    );
    Ok(DomainCredentials { account, password })
}

/// The account `entry` signs in to a target as, named as `format` says, or in the other form
/// when the entry lacks what that one needs.
fn account_of(
    entry: &LdapUser,
    format: RdpDomainUsernameFormat,
    target_domain: Option<&str>,
) -> Option<DomainAccount> {
    let upn = entry
        .user_principal_name
        .as_deref()
        .map(str::trim)
        .filter(|upn| upn.contains('@'))
        .map(|upn| DomainAccount {
            username: upn.to_owned(),
            domain: None,
        });
    let down_level = entry
        .sam_account_name
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .and_then(|name| {
            let domain = target_domain
                .map(str::trim)
                .filter(|domain| !domain.is_empty())
                .map(str::to_owned)
                .or_else(|| dns_domain_of(&entry.dn))?;
            Some(DomainAccount {
                username: name.to_owned(),
                domain: Some(domain),
            })
        });
    match format {
        RdpDomainUsernameFormat::Upn => upn.or(down_level),
        RdpDomainUsernameFormat::DownLevel => down_level.or(upn),
    }
}

/// The DNS domain of a distinguished name: its `DC=` parts, in order
/// (`CN=Alice,OU=Staff,DC=corp,DC=example,DC=com` is `corp.example.com`).
fn dns_domain_of(dn: &str) -> Option<String> {
    let labels: Vec<&str> = dn
        .split(',')
        .filter_map(|part| {
            let (attribute, value) = part.trim().split_once('=')?;
            attribute
                .trim()
                .eq_ignore_ascii_case("dc")
                .then(|| value.trim())
                .filter(|value| !value.is_empty())
        })
        .collect();
    (!labels.is_empty()).then(|| labels.join("."))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(sam: Option<&str>, upn: Option<&str>) -> LdapUser {
        LdapUser {
            username: "alice".into(),
            email: None,
            display_name: None,
            dn: "CN=Alice,OU=Staff,DC=corp,DC=example,DC=com".into(),
            object_uuid: Uuid::nil(),
            ssh_public_keys: vec![],
            password_last_set: None,
            sam_account_name: sam.map(Into::into),
            user_principal_name: upn.map(Into::into),
        }
    }

    fn account(username: &str, domain: Option<&str>) -> DomainAccount {
        DomainAccount {
            username: username.into(),
            domain: domain.map(Into::into),
        }
    }

    #[test]
    fn a_distinguished_name_gives_its_dns_domain() {
        assert_eq!(
            dns_domain_of("CN=Alice,OU=Staff,DC=corp,DC=example,DC=com").as_deref(),
            Some("corp.example.com")
        );
        assert_eq!(
            dns_domain_of("uid=alice, ou=people, dc=Example, dc=org").as_deref(),
            Some("Example.org")
        );
        assert_eq!(dns_domain_of("CN=Alice,O=Example"), None);
    }

    #[test]
    fn the_account_is_named_as_the_target_asks() {
        let full = entry(Some("alice"), Some("alice@corp.example.com"));
        assert_eq!(
            account_of(&full, RdpDomainUsernameFormat::Upn, Some("CORP")),
            Some(account("alice@corp.example.com", None))
        );
        assert_eq!(
            account_of(&full, RdpDomainUsernameFormat::DownLevel, Some("CORP")),
            Some(account("alice", Some("CORP")))
        );
        // Without a domain on the target, the directory's own.
        assert_eq!(
            account_of(&full, RdpDomainUsernameFormat::DownLevel, Some("  ")),
            Some(account("alice", Some("corp.example.com")))
        );
    }

    #[test]
    fn a_missing_part_falls_back_to_the_other_form() {
        let no_upn = entry(Some("alice"), None);
        assert_eq!(
            account_of(&no_upn, RdpDomainUsernameFormat::Upn, None),
            Some(account("alice", Some("corp.example.com")))
        );
        let no_sam = entry(None, Some("alice@corp.example.com"));
        assert_eq!(
            account_of(&no_sam, RdpDomainUsernameFormat::DownLevel, Some("CORP")),
            Some(account("alice@corp.example.com", None))
        );
        assert_eq!(
            account_of(
                &entry(None, Some("not a upn")),
                RdpDomainUsernameFormat::Upn,
                None
            ),
            None
        );
    }

    #[test]
    fn accounts_are_written_as_people_write_them() {
        assert_eq!(account("alice", Some("CORP")).display_name(), "CORP\\alice");
        assert_eq!(
            account("alice@corp.example.com", None).display_name(),
            "alice@corp.example.com"
        );
    }

    #[test]
    fn credentials_never_print_their_password() {
        let credentials = DomainCredentials {
            account: account("alice", Some("CORP")),
            password: Zeroizing::new("hunter2".into()),
        };
        let printed = format!("{credentials:?}");
        assert!(!printed.contains("hunter2"), "{printed}");
        assert_eq!(credentials.password(), "hunter2");
    }

    #[test]
    fn the_user_is_told_why_and_whether_to_try_again() {
        let wrong = DomainAccountError::Rejected(LdapBindRejection::InvalidCredentials);
        assert_eq!(wrong.user_message(), "The domain password is incorrect.");
        assert!(wrong.may_retry());
        let disabled = DomainAccountError::Rejected(LdapBindRejection::AccountDisabled);
        assert_eq!(disabled.user_message(), "Your domain account is disabled.");
        assert!(!disabled.may_retry());
        assert!(!DomainAccountError::NotLinked.may_retry());
    }
}
