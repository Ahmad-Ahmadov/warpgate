//! Checking a user's password by binding to the directory as them.

use std::time::Duration;

use tracing::debug;
use uuid::Uuid;
use warpgate_tls::TlsMode;

use crate::connection::{connect, open};
use crate::error::{LdapError, Result};
use crate::queries::find_user_by_uuid_on;
use crate::types::{LdapAuthOutcome, LdapBindRejection, LdapConfig};

/// The whole exchange: the service bind, the lookup and the user's bind.
/// Each connect already has its own 10-second limit; this bounds a server
/// that accepts the connection and then stops answering.
const AUTHENTICATION_TIMEOUT: Duration = Duration::from_secs(20);

/// Checks `password` for the directory entry `object_uuid` by binding as it.
///
/// The entry is looked up with the service account by the UUID the user was
/// imported or linked with, not by username, so a rename or a move in the
/// directory is followed, and through the server's user filter, so an entry
/// the filter no longer matches is refused. The bind itself then applies
/// everything the directory enforces — disabled, locked and expired accounts,
/// expired passwords, logon hours — and its current password, so a change
/// made in the directory applies at the next login.
///
/// The password goes into that one bind over LDAPS or StartTLS and nowhere
/// else: nothing derived from it is returned, logged or kept.
///
/// `Ok(Rejected)` is a verdict on the user. `Err` means the directory could
/// not give one — unreachable, TLS failure, the service account refused, a
/// bind result that is about the server rather than the user — and should
/// not count against the user.
pub async fn authenticate_user(
    config: &LdapConfig,
    object_uuid: &Uuid,
    password: &str,
) -> Result<LdapAuthOutcome> {
    if matches!(config.tls_mode, TlsMode::Disabled) {
        return Err(LdapError::InsecureTransport);
    }

    if password.is_empty() {
        return Ok(LdapAuthOutcome::Rejected(LdapBindRejection::EmptyPassword));
    }

    tokio::time::timeout(
        AUTHENTICATION_TIMEOUT,
        bind_as_user(config, object_uuid, password),
    )
    .await
    .map_err(|_| {
        LdapError::ConnectionFailed(format!(
            "no answer within {} seconds",
            AUTHENTICATION_TIMEOUT.as_secs()
        ))
    })?
}

async fn bind_as_user(
    config: &LdapConfig,
    object_uuid: &Uuid,
    password: &str,
) -> Result<LdapAuthOutcome> {
    let mut service = connect(config).await?;
    let found = find_user_by_uuid_on(&mut service, config, object_uuid).await;
    let _ = service.unbind().await;

    let Some(user) = found? else {
        return Ok(LdapAuthOutcome::Rejected(LdapBindRejection::UserNotFound));
    };

    // An empty DN with a password is an anonymous bind on some servers.
    if user.dn.is_empty() {
        return Ok(LdapAuthOutcome::Rejected(LdapBindRejection::UserNotFound));
    }

    // A connection of its own, so the user's bind never replaces the service
    // account's on a connection something else might still use.
    let mut ldap = open(config).await?;
    let result = ldap
        .simple_bind(&user.dn, password)
        .await
        .map_err(|e| LdapError::ConnectionFailed(e.to_string()));
    let _ = ldap.unbind().await;
    let result = result?;

    match classify_bind_result(result.rc, &result.text) {
        BindVerdict::Accepted => Ok(LdapAuthOutcome::Authenticated(user)),
        BindVerdict::Rejected(rejection) => {
            // The server's diagnostic text names no secret (an AD one reads
            // "AcceptSecurityContext error, data 52e, v4563").
            debug!(dn = %user.dn, rc = result.rc, text = %result.text, "LDAP bind refused");
            Ok(LdapAuthOutcome::Rejected(rejection))
        }
        BindVerdict::Failed => Err(LdapError::BindFailed {
            result_code: result.rc,
            text: result.text,
        }),
    }
}

#[derive(Debug, PartialEq, Eq)]
enum BindVerdict {
    Accepted,
    Rejected(LdapBindRejection),
    /// The result says nothing about the user: the server is busy,
    /// unavailable, or wants a stronger connection than it was given.
    Failed,
}

// LDAP result codes, RFC 4511 appendix A.
const SUCCESS: u32 = 0;
const NO_SUCH_OBJECT: u32 = 32;
const INVALID_CREDENTIALS: u32 = 49;
const INSUFFICIENT_ACCESS_RIGHTS: u32 = 50;
const UNWILLING_TO_PERFORM: u32 = 53;

fn classify_bind_result(rc: u32, text: &str) -> BindVerdict {
    match rc {
        SUCCESS => BindVerdict::Accepted,
        INVALID_CREDENTIALS => BindVerdict::Rejected(match active_directory_sub_code(text) {
            Some(0x525) => LdapBindRejection::UserNotFound,
            Some(0x530 | 0x531) => LdapBindRejection::LogonRestricted,
            Some(0x532) => LdapBindRejection::PasswordExpired,
            Some(0x533) => LdapBindRejection::AccountDisabled,
            Some(0x701) => LdapBindRejection::AccountExpired,
            Some(0x773) => LdapBindRejection::PasswordMustChange,
            Some(0x775) => LdapBindRejection::AccountLocked,
            _ => LdapBindRejection::InvalidCredentials,
        }),
        // Moved or deleted between the lookup and the bind.
        NO_SUCH_OBJECT => BindVerdict::Rejected(LdapBindRejection::UserNotFound),
        // How 389 Directory Server and others refuse an inactivated or
        // locked entry.
        INSUFFICIENT_ACCESS_RIGHTS | UNWILLING_TO_PERFORM => {
            BindVerdict::Rejected(LdapBindRejection::Refused { result_code: rc })
        }
        _ => BindVerdict::Failed,
    }
}

/// Active Directory explains an `invalidCredentials` result in its
/// diagnostic text: `80090308: LdapErr: DSID-0C09044E, comment:
/// AcceptSecurityContext error, data 52e, v4563`. The `data` value is a
/// Win32 error code in hex.
fn active_directory_sub_code(text: &str) -> Option<u32> {
    let (_, rest) = text.split_once(", data ")?;
    let code = rest.split(|c: char| c == ',' || c.is_whitespace()).next()?;
    u32::from_str_radix(code, 16).ok()
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;
    use warpgate_tls::TlsMode;

    use super::{BindVerdict, active_directory_sub_code, authenticate_user, classify_bind_result};
    use crate::LdapError;
    use crate::types::{LdapAuthOutcome, LdapBindRejection, LdapConfig, LdapUsernameAttribute};

    fn ad_text(data: &str) -> String {
        format!(
            "80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext error, data {data}, v4563\0"
        )
    }

    fn config(tls_mode: TlsMode) -> LdapConfig {
        LdapConfig {
            // Nothing listens here; the tests below must finish before any
            // connection would be attempted.
            host: "ldap.invalid".into(),
            port: 636,
            bind_dn: String::new(),
            bind_password: String::new(),
            tls_mode,
            tls_verify: true,
            base_dns: vec!["dc=example,dc=com".into()],
            user_filter: "(objectClass=person)".into(),
            username_attribute: LdapUsernameAttribute::Cn,
            ssh_key_attribute: "sshPublicKey".into(),
            uuid_attribute: None,
        }
    }

    #[test]
    fn a_successful_bind_is_accepted() {
        assert_eq!(classify_bind_result(0, ""), BindVerdict::Accepted);
    }

    #[test]
    fn active_directory_reasons_are_told_apart() {
        for (data, expected) in [
            ("52e", LdapBindRejection::InvalidCredentials),
            ("525", LdapBindRejection::UserNotFound),
            ("530", LdapBindRejection::LogonRestricted),
            ("531", LdapBindRejection::LogonRestricted),
            ("532", LdapBindRejection::PasswordExpired),
            ("533", LdapBindRejection::AccountDisabled),
            ("701", LdapBindRejection::AccountExpired),
            ("773", LdapBindRejection::PasswordMustChange),
            ("775", LdapBindRejection::AccountLocked),
        ] {
            assert_eq!(
                classify_bind_result(49, &ad_text(data)),
                BindVerdict::Rejected(expected),
                "data {data}"
            );
        }
    }

    #[test]
    fn invalid_credentials_without_a_reason_are_just_invalid() {
        // OpenLDAP says nothing more, by design.
        assert_eq!(
            classify_bind_result(49, ""),
            BindVerdict::Rejected(LdapBindRejection::InvalidCredentials)
        );
        assert_eq!(
            classify_bind_result(49, &ad_text("zzz")),
            BindVerdict::Rejected(LdapBindRejection::InvalidCredentials)
        );
    }

    #[test]
    fn the_sub_code_is_read_from_the_data_field_only() {
        assert_eq!(active_directory_sub_code(&ad_text("775")), Some(0x775));
        assert_eq!(active_directory_sub_code("DSID-0C09044E, v4563"), None);
        assert_eq!(active_directory_sub_code("metadata 533"), None);
    }

    #[test]
    fn inactivated_entries_are_refusals() {
        for rc in [50, 53] {
            assert_eq!(
                classify_bind_result(rc, "Account inactivated. Contact system administrator."),
                BindVerdict::Rejected(LdapBindRejection::Refused { result_code: rc })
            );
        }
        assert_eq!(
            classify_bind_result(32, ""),
            BindVerdict::Rejected(LdapBindRejection::UserNotFound)
        );
    }

    #[test]
    fn server_side_results_are_failures_not_verdicts() {
        // busy, unavailable, other, strongerAuthRequired, confidentialityRequired
        for rc in [51, 52, 80, 8, 13, 1, 2] {
            assert_eq!(classify_bind_result(rc, ""), BindVerdict::Failed, "rc {rc}");
        }
    }

    #[tokio::test]
    async fn a_password_is_never_sent_without_tls() {
        let result = authenticate_user(&config(TlsMode::Disabled), &Uuid::nil(), "secret").await;
        assert!(
            matches!(result, Err(LdapError::InsecureTransport)),
            "{result:?}"
        );
    }

    #[tokio::test]
    async fn an_empty_password_is_refused_before_any_bind() {
        for tls_mode in [TlsMode::Preferred, TlsMode::Required] {
            let result = authenticate_user(&config(tls_mode), &Uuid::nil(), "").await;
            assert!(
                matches!(
                    result,
                    Ok(LdapAuthOutcome::Rejected(LdapBindRejection::EmptyPassword))
                ),
                "{result:?}"
            );
        }
    }
}
