//! Which Windows account an RDP connection signs in to the target as, and the checks that
//! keep every user to the accounts they may use.
//!
//! The accounts are the target's (its Accounts inventory), and a user may sign in only as
//! one Access Control authorized for them on the target ([`crate::access_control`]): an
//! account assigned to them directly or through an access group. How each signs in
//! ([`SignInKind`]) is the account's:
//!
//! * **Managed**: a stored credential (kept by Warpgate, or a Vault reference). The user
//!   never sees the password.
//! * **Domain account**: the user's own directory (Active Directory) account, from the
//!   directory entry their Warpgate user is linked to (`ldap_server_id` and
//!   `ldap_object_uuid`, set when an administrator imported or linked them), never one a
//!   client names. Its password is checked by binding to the directory as that entry
//!   ([`warpgate_ldap::authenticate_user`], LDAPS or StartTLS only) before the target is
//!   dialed; a native RDP connection reuses the password the user signed in to Warpgate with.
//! * **Local account**: a named Windows account, with its password typed by the user when
//!   connecting; the target checks it.
//!
//! The native RDP listener and the browser client both resolve the account with
//! [`plan_sign_in`] and [`verify_sign_in`], against the user and target Warpgate admitted, so
//! neither can be talked into another account: whatever account a client asks for is only
//! looked up among the ones Access Control allows. What they connect with is an
//! [`AuthorizedSignIn`], which only this module makes.
//!
//! The account signed in with is also what the target must report when the session logs on
//! ([`LogonIdentity`]): the RDP client compares the target's logon notification with it and
//! ends a session that logs on as anyone else, which is what catches an account typed into
//! the target's own sign-in screen.
//!
//! A typed password lives in [`TargetCredentials`] only, in memory, until the connection to
//! the target has used it, and is wiped when that is dropped. It is never stored, logged,
//! sent to the viewer or recorded: it goes to the target in the CredSSP exchange.

use std::fmt;

use sea_orm::{DatabaseConnection, EntityTrait};
use tracing::{info, warn};
use uuid::Uuid;
use warpgate_common::MaybeSecretRef;
use warpgate_common::audit::AuditEvent;
use warpgate_db_entities::TargetAccount::{
    DirectoryUsernameFormat, TargetAccountAuthMethod, TargetAccountKind,
};
use warpgate_db_entities::{LdapServer, User};
use warpgate_ldap::{LdapAuthOutcome, LdapBindRejection, LdapConfig, LdapUser};
/// Re-exported for the protocol crates that take the password, so they wipe it the same way.
pub use zeroize::{Zeroize, Zeroizing};

use crate::access_control::{AccessError, AuthorizedAccount, ConnectingUser, connection_accounts};

/// The longest password taken: what an RDP Client Info PDU carries, and more than Active
/// Directory or Windows allow.
pub const MAX_ACCOUNT_PASSWORD_CHARS: usize = 256;

/// How an account signs in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignInKind {
    /// With its stored credential.
    Managed,
    /// The user's own directory account, with the password they type (or signed in with).
    DomainAccount,
    /// A named Windows account, with the password the user types.
    LocalAccount,
}

impl SignInKind {
    /// Whether the user types a password for the target when connecting to it.
    pub const fn asks_for_password(self) -> bool {
        !matches!(self, Self::Managed)
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Managed => "managed",
            Self::DomainAccount => "domain_account",
            Self::LocalAccount => "local_account",
        }
    }
}

/// A Windows account: a name, and the domain (or computer) it belongs to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WindowsAccount {
    /// The name the target is given: an account name to go with `domain`, or a user
    /// principal name (`alice@corp.example.com`) with no domain.
    pub username: String,
    pub domain: Option<String>,
}

impl WindowsAccount {
    /// The account as a person writes it: `CORP\alice`, `alice@corp.example.com` or `alice`.
    pub fn display_name(&self) -> String {
        match &self.domain {
            Some(domain) => format!("{domain}\\{}", self.username),
            None => self.username.clone(),
        }
    }

    /// An account as an administrator wrote it: `DOMAIN\name`, `.\name` (the target's own),
    /// a user principal name, or a bare `name`, which takes `default_domain`.
    fn parse(name: &str, default_domain: Option<&str>) -> Option<Self> {
        let name = name.trim();
        let default_domain = default_domain
            .map(str::trim)
            .filter(|domain| !domain.is_empty());
        let (domain, username) = match name.split_once('\\') {
            Some((".", username)) => (None, username.trim()),
            Some((domain, username)) => (Some(domain.trim()), username.trim()),
            None if name.contains('@') => (None, name),
            None => (default_domain, name),
        };
        (!username.is_empty() && !username.contains('\\')).then(|| Self {
            username: username.to_owned(),
            domain: domain
                .filter(|domain| !domain.is_empty())
                .map(str::to_owned),
        })
    }

    /// Whether `name`, as a client sent it, is this account.
    fn is_named(&self, name: &str) -> bool {
        self.display_name().eq_ignore_ascii_case(name.trim())
    }

    /// The name part of the account, as a target reports it: a user principal name is
    /// reported by its account name, which is most often the part before the `@`.
    fn logon_name(&self) -> &str {
        match (&self.domain, self.username.split_once('@')) {
            (None, Some((name, _suffix))) => name,
            _ => &self.username,
        }
    }
}

/// The account a session must log on as, in the form a target reports a logon in (MS-RDPBCGR
/// 2.2.10.1.1): an account name, and the NetBIOS name of its domain, or of the computer for
/// a local account. Compared without regard to case, as Windows compares them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogonIdentity {
    /// The account as Warpgate signed in with it, for messages and the audit log.
    account: String,
    /// The account names the logon may report.
    usernames: Vec<String>,
    /// The domain names the logon may report. Empty when no domain is known: the first
    /// logon's is taken, and every later logon must report that one.
    domains: Vec<String>,
    /// The user principal names the logon may report the account by instead, with no
    /// domain: a UPN names one account wherever it is used.
    upns: Vec<String>,
}

impl LogonIdentity {
    /// What a logon as `account` reports: its name, and its domain (or computer) when it has
    /// one. A directory account is known by more names, see `domain_identity_of`.
    pub fn for_account(account: &WindowsAccount) -> Self {
        let mut identity = Self {
            account: account.display_name(),
            usernames: vec![],
            domains: vec![],
            upns: vec![],
        };
        identity.add_username(account.logon_name());
        match &account.domain {
            Some(domain) => identity.add_domain(domain),
            None => identity.add_upn(&account.username),
        }
        identity
    }

    /// Add a user principal name the account is known by; anything else is not one.
    fn add_upn(&mut self, upn: &str) {
        let upn = upn.trim().to_lowercase();
        if upn.contains('@') && !self.upns.contains(&upn) {
            self.upns.push(upn);
        }
    }

    fn add_username(&mut self, name: &str) {
        let name = name.trim().to_lowercase();
        if !name.is_empty() && !self.usernames.contains(&name) {
            self.usernames.push(name);
        }
    }

    /// Add a domain by any of its names: `CORP`, or `corp.example.com`, whose first label
    /// is most often the NetBIOS name Windows reports.
    fn add_domain(&mut self, domain: &str) {
        let domain = domain.trim().to_lowercase();
        if domain.is_empty() || domain == "." {
            return;
        }
        let first_label = domain
            .split_once('.')
            .map(|(label, _rest)| label.to_owned())
            .filter(|label| !label.is_empty());
        for name in std::iter::once(domain).chain(first_label) {
            if !self.domains.contains(&name) {
                self.domains.push(name);
            }
        }
    }

    /// The account Warpgate signed in with, as a person writes it.
    pub fn account(&self) -> &str {
        &self.account
    }

    /// Whether a logon the target reported as `domain\username` is this account. Without a
    /// known domain, the first logon's becomes the one every later logon must report.
    pub fn admits(&mut self, domain: &str, username: &str) -> bool {
        let username = username.trim().to_lowercase();
        let domain = domain.trim().to_lowercase();
        if username.contains('@') {
            return self.upns.contains(&username);
        }
        if !self.usernames.contains(&username) {
            return false;
        }
        if self.domains.is_empty() {
            if !domain.is_empty() {
                self.domains.push(domain);
            }
            return true;
        }
        self.domains.contains(&domain)
    }
}

/// What a session signed in with a stored credential must log on as: that account. `None`
/// for an interactive-logon target, which shows the target's own sign-in screen and leaves
/// the account to whoever is at it: Warpgate records that account, but cannot hold it to one.
pub fn stored_logon_identity(
    account: &WindowsAccount,
    interactive_logon: bool,
) -> Option<LogonIdentity> {
    (!interactive_logon).then(|| LogonIdentity::for_account(account))
}

/// An account's stored credential, for the RDP client to resolve (decrypt, or fetch from the
/// secret backend) when it connects. Never printed.
#[derive(Clone)]
pub struct StoredCredential {
    pub account: WindowsAccount,
    pub password: MaybeSecretRef,
}

impl fmt::Debug for StoredCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoredCredential")
            .field("account", &self.account)
            .field("password", &"<redacted>")
            .finish()
    }
}

/// One account a user may sign in to an RDP target as.
#[derive(Clone, Debug)]
pub struct SignInChoice {
    /// The target account.
    pub account_id: Uuid,
    pub kind: SignInKind,
    /// The Windows account it signs in as.
    pub account: WindowsAccount,
    /// How a directory account is named to the target.
    format: DirectoryUsernameFormat,
    /// A directory account's domain, as the target account sets it.
    domain_hint: Option<String>,
    /// A managed account's stored password.
    stored: Option<MaybeSecretRef>,
}

impl SignInChoice {
    /// The account as people write it, which is also how a client names its choice.
    pub fn label(&self) -> String {
        self.account.display_name()
    }

    /// Whether the user types a password for this account.
    pub const fn asks_for_password(&self) -> bool {
        self.kind.asks_for_password()
    }
}

/// Who a user may sign in to a target as, before they type a password: one account, or
/// several to choose from. Only ever made by [`plan_sign_in`], for one user and target.
#[derive(Clone, Debug)]
pub struct SignInPlan {
    user_id: Uuid,
    target_id: Uuid,
    choices: Vec<SignInChoice>,
}

/// What a client answered: the account it chose, by id or by name, if it chose.
#[derive(Clone, Copy, Debug, Default)]
pub struct SignInAnswer<'a> {
    pub account_id: Option<Uuid>,
    pub account: Option<&'a str>,
}

impl SignInPlan {
    pub fn choices(&self) -> &[SignInChoice] {
        &self.choices
    }

    /// The accounts the user may sign in as, as people write them, in order.
    pub fn account_names(&self) -> Vec<String> {
        self.choices.iter().map(SignInChoice::label).collect()
    }

    /// The sign-in that needs nothing from the user: the only choice is a managed account,
    /// with its stored credential.
    pub fn stored_sign_in(&self) -> Option<AuthorizedSignIn> {
        match self.choices.as_slice() {
            [only] if only.kind == SignInKind::Managed => {
                Some(AuthorizedSignIn::stored(self.user_id, self.target_id, only))
            }
            _ => None,
        }
    }

    /// What a password prompt is about: the user's own domain account when that is all
    /// there is, a Windows account otherwise.
    pub fn prompt_kind(&self) -> SignInKind {
        if self
            .choices
            .iter()
            .all(|choice| choice.kind == SignInKind::DomainAccount)
        {
            SignInKind::DomainAccount
        } else {
            SignInKind::LocalAccount
        }
    }

    /// The user's own directory account among the choices, if it is one.
    pub fn directory_choice(&self) -> Option<&SignInChoice> {
        self.choices
            .iter()
            .find(|choice| choice.kind == SignInKind::DomainAccount)
    }

    /// The choice a client's answer names: only ever one of this plan's.
    fn select(&self, answer: SignInAnswer<'_>) -> Result<&SignInChoice, SignInError> {
        if let Some(id) = answer.account_id {
            return self
                .choices
                .iter()
                .find(|choice| choice.account_id == id)
                .ok_or(SignInError::AccountNotAllowed);
        }
        if let Some(name) = answer
            .account
            .map(str::trim)
            .filter(|name| !name.is_empty())
        {
            return self
                .choices
                .iter()
                .find(|choice| choice.account.is_named(name))
                .ok_or(SignInError::AccountNotAllowed);
        }
        match self.choices.as_slice() {
            [only] => Ok(only),
            _ => Err(SignInError::AccountNotChosen),
        }
    }
}

/// What a connection to an RDP target signs in with, decided for the user and target
/// Warpgate admitted: an account's stored credential, or an account the user may use with the
/// password they typed. Only this module makes one, so a protocol cannot connect without
/// going through the checks here.
#[derive(Debug)]
pub struct AuthorizedSignIn {
    user_id: Uuid,
    target_id: Uuid,
    account_id: Uuid,
    kind: SignInKind,
    account: String,
    credentials: Option<TargetCredentials>,
    stored: Option<StoredCredential>,
}

impl AuthorizedSignIn {
    fn stored(user_id: Uuid, target_id: Uuid, choice: &SignInChoice) -> Self {
        Self {
            user_id,
            target_id,
            account_id: choice.account_id,
            kind: SignInKind::Managed,
            account: choice.label(),
            credentials: None,
            stored: choice.stored.clone().map(|password| StoredCredential {
                account: choice.account.clone(),
                password,
            }),
        }
    }

    fn typed(plan: &SignInPlan, choice: &SignInChoice, credentials: TargetCredentials) -> Self {
        Self {
            user_id: plan.user_id,
            target_id: plan.target_id,
            account_id: choice.account_id,
            kind: choice.kind,
            account: credentials.account().display_name(),
            credentials: Some(credentials),
            stored: None,
        }
    }

    /// The Warpgate user it was decided for: only they may connect with it.
    pub const fn user_id(&self) -> Uuid {
        self.user_id
    }

    /// The target it was decided for.
    pub const fn target_id(&self) -> Uuid {
        self.target_id
    }

    /// The target account, for the audit log.
    pub const fn account_id(&self) -> Uuid {
        self.account_id
    }

    pub const fn kind(&self) -> SignInKind {
        self.kind
    }

    /// The account, as people write it, for the audit log.
    pub fn account(&self) -> &str {
        &self.account
    }

    /// The account and password the user typed, if they typed one.
    pub const fn credentials(&self) -> Option<&TargetCredentials> {
        self.credentials.as_ref()
    }

    /// The account's stored credential, for a managed account.
    pub const fn stored_credential(&self) -> Option<&StoredCredential> {
        self.stored.as_ref()
    }

    /// What the connection signs in with (and wipes): the typed credentials, or the stored.
    pub fn into_parts(self) -> (Option<TargetCredentials>, Option<StoredCredential>) {
        (self.credentials, self.stored)
    }
}

/// An account and the password the user typed for it, for one connection to a target. The
/// password is wiped from memory when this is dropped, and never printed.
pub struct TargetCredentials {
    user_id: Uuid,
    kind: SignInKind,
    account: WindowsAccount,
    identity: LogonIdentity,
    password: Zeroizing<String>,
}

impl TargetCredentials {
    /// The Warpgate user the account was resolved for: only they may connect with it.
    pub const fn user_id(&self) -> Uuid {
        self.user_id
    }

    pub const fn kind(&self) -> SignInKind {
        self.kind
    }

    pub const fn account(&self) -> &WindowsAccount {
        &self.account
    }

    /// What the target must report when the session logs on.
    pub const fn identity(&self) -> &LogonIdentity {
        &self.identity
    }

    pub fn password(&self) -> &str {
        &self.password
    }
}

impl fmt::Debug for TargetCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TargetCredentials")
            .field("user_id", &self.user_id)
            .field("kind", &self.kind)
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

/// Why a user cannot sign in to a target as the account they asked for.
#[derive(Debug, thiserror::Error)]
pub enum SignInError {
    #[error(transparent)]
    Domain(#[from] DomainAccountError),
    /// Access Control does not allow it.
    #[error(transparent)]
    Access(#[from] AccessError),
    /// The password the user signed in to Warpgate with cannot be used for this account:
    /// it was not checked by the account's own directory, or the account is not theirs.
    #[error("the sign-in password cannot be reused for this account")]
    PasswordNotReusable,
    /// Several accounts are assigned to the user, and the request named none.
    #[error("no account was chosen")]
    AccountNotChosen,
    /// The request named an account the user may not sign in as.
    #[error("the account is not assigned to the user")]
    AccountNotAllowed,
    /// An assigned account cannot sign in to an RDP target as it is configured.
    #[error("the account cannot sign in to this target")]
    AccountUnusable,
    #[error("no password was given")]
    PasswordMissing,
    #[error("the password is too long")]
    PasswordTooLong,
}

impl SignInError {
    /// What to tell the user. Nothing here confirms anything about an account that is not
    /// the user's to use.
    pub const fn user_message(&self) -> &'static str {
        match self {
            Self::Domain(error) => error.user_message(),
            Self::Access(error) => match error {
                AccessError::NoAccess => {
                    "No account on this target is assigned to you. Ask an administrator to assign one."
                }
                AccessError::NotChosen(_) => "Choose the account to sign in as.",
                AccessError::NotAllowed => "You may not sign in to this target as that account.",
                AccessError::NotLinked => {
                    "Your Warpgate account is not linked to a directory account. Ask an administrator."
                }
                AccessError::Unsupported(reason) => *reason,
                AccessError::Directory(_) | AccessError::Database(_) => {
                    "The account could not be looked up right now. Try again later."
                }
            },
            Self::PasswordNotReusable => "Enter the account's password.",
            Self::AccountNotChosen => "Choose the account to sign in as.",
            Self::AccountNotAllowed => "You may not sign in to this target as that account.",
            Self::AccountUnusable => {
                "The account assigned to you cannot sign in to this target. Ask an administrator."
            }
            Self::PasswordMissing => "Enter the account's password.",
            Self::PasswordTooLong => "The password is too long.",
        }
    }

    /// Whether the user may try again: the answer was about what they typed or chose.
    pub const fn may_retry(&self) -> bool {
        match self {
            Self::Domain(error) => error.may_retry(),
            Self::Access(error) => error.may_retry(),
            Self::PasswordNotReusable
            | Self::AccountNotChosen
            | Self::AccountNotAllowed
            | Self::PasswordMissing
            | Self::PasswordTooLong => true,
            Self::AccountUnusable => false,
        }
    }
}

/// Audit an account a client asked for that is not the user's, or a user with none.
fn refuse(
    user: ConnectingUser<'_>,
    target_id: Uuid,
    target_name: &str,
    requested: Option<String>,
    reason: &str,
) {
    AuditEvent::AccessAssignmentRefused {
        user_id: user.id,
        username: user.username.to_owned(),
        target_id,
        target_name: target_name.to_owned(),
        requested_account: requested,
        reason: reason.to_owned(),
    }
    .emit();
}

/// The choice an authorized account makes for an RDP target.
async fn choice_for(
    db: &DatabaseConnection,
    user_id: Uuid,
    authorized: &AuthorizedAccount,
) -> Result<SignInChoice, SignInError> {
    let account = &authorized.account;
    let parse = || {
        WindowsAccount::parse(&account.name, account.domain.as_deref())
            .ok_or(SignInError::AccountUnusable)
    };
    match (account.kind, account.auth_method) {
        (TargetAccountKind::Directory, TargetAccountAuthMethod::DirectoryPassword) => {
            let format = account
                .username_format
                .unwrap_or(DirectoryUsernameFormat::Upn);
            let (windows, _) =
                find_domain_account(db, user_id, format, account.domain.as_deref()).await?;
            Ok(SignInChoice {
                account_id: account.id,
                kind: SignInKind::DomainAccount,
                account: windows,
                format,
                domain_hint: account.domain.clone(),
                stored: None,
            })
        }
        (
            TargetAccountKind::Local | TargetAccountKind::Domain,
            TargetAccountAuthMethod::TypedPassword,
        ) => Ok(SignInChoice {
            account_id: account.id,
            kind: SignInKind::LocalAccount,
            account: parse()?,
            format: DirectoryUsernameFormat::Upn,
            domain_hint: None,
            stored: None,
        }),
        (
            TargetAccountKind::Local | TargetAccountKind::Domain,
            TargetAccountAuthMethod::StoredCredential,
        ) => {
            let password = account
                .credential()
                .ok()
                .flatten()
                .and_then(|credential| credential.password().cloned())
                .ok_or(SignInError::AccountUnusable)?;
            Ok(SignInChoice {
                account_id: account.id,
                kind: SignInKind::Managed,
                account: parse()?,
                format: DirectoryUsernameFormat::Upn,
                domain_hint: None,
                stored: Some(password),
            })
        }
        _ => Err(SignInError::AccountUnusable),
    }
}

/// Who `user` signs in to the target as, before any password is typed: to tell the user
/// which account they will be (or may choose from), and to turn away a user who has none
/// before an approval is asked for. Only the accounts Access Control authorized for them
/// there (or, for a ticket without an assignment, the target's primary account); one that
/// cannot be resolved now (the directory unreachable, say) is left out, and if that leaves
/// none, the first reason is the answer.
pub async fn plan_sign_in(
    db: &DatabaseConnection,
    user: ConnectingUser<'_>,
    target_id: Uuid,
    target_name: &str,
    via_ticket: bool,
) -> Result<SignInPlan, SignInError> {
    let accounts = connection_accounts(db, user, target_id, via_ticket).await?;
    if accounts.is_empty() {
        refuse(
            user,
            target_id,
            target_name,
            None,
            "no usable access assignment on the target",
        );
        return Err(SignInError::Access(AccessError::NoAccess));
    }
    let mut choices: Vec<SignInChoice> = Vec::new();
    let mut first_error = None;
    for authorized in &accounts {
        let choice = match choice_for(db, user.id, authorized).await {
            Ok(choice) => choice,
            Err(error) => {
                warn!(account_id = %authorized.account.id, %error, "Could not resolve an authorized account");
                first_error.get_or_insert(error);
                continue;
            }
        };
        // The same Windows account authorized twice (by two names for it) is offered once.
        if !choices
            .iter()
            .any(|known| known.kind == choice.kind && known.account.is_named(&choice.label()))
        {
            choices.push(choice);
        }
    }
    if choices.is_empty() {
        return Err(first_error.unwrap_or(SignInError::AccountUnusable));
    }
    Ok(SignInPlan {
        user_id: user.id,
        target_id,
        choices,
    })
}

fn check_password(password: &str) -> Result<(), SignInError> {
    if password.is_empty() {
        return Err(SignInError::PasswordMissing);
    }
    if password.chars().count() > MAX_ACCOUNT_PASSWORD_CHARS {
        return Err(SignInError::PasswordTooLong);
    }
    Ok(())
}

/// Check what `user` answered to sign in to the target, and return what to sign in with.
///
/// The plan is made again here, server-side: the account the client chose (by id or by
/// name) is only ever looked up among the user's own choices, and anything else is refused
/// and audited. A domain password is checked with the directory; a local account's is left
/// to the target; a managed account takes none.
pub async fn verify_sign_in(
    db: &DatabaseConnection,
    user: ConnectingUser<'_>,
    target_id: Uuid,
    target_name: &str,
    via_ticket: bool,
    answer: SignInAnswer<'_>,
    password: Zeroizing<String>,
) -> Result<AuthorizedSignIn, SignInError> {
    let plan = plan_sign_in(db, user, target_id, target_name, via_ticket).await?;
    let choice = match plan.select(answer) {
        Ok(choice) => choice.clone(),
        Err(error) => {
            if matches!(error, SignInError::AccountNotAllowed) {
                refuse(
                    user,
                    target_id,
                    target_name,
                    answer
                        .account_id
                        .map(|id| id.to_string())
                        .or_else(|| answer.account.map(str::to_owned)),
                    "the account is not assigned to the user on this target",
                );
            }
            return Err(error);
        }
    };
    authorize_choice(db, &plan, &choice, password).await
}

/// Sign in as the user's own directory account with the password they signed in to Warpgate
/// with, on this same connection, so they type it once.
///
/// Only when that password was the directory's: the user's LDAP server checks their Warpgate
/// password (`authenticate_users`), so a successful sign-in means the directory accepted it,
/// for the very entry the directory account comes from. It is checked with the directory
/// again here, and never offered to any other account: not someone else's, not a local one.
pub async fn reuse_sign_in_password(
    db: &DatabaseConnection,
    plan: &SignInPlan,
    account: Option<&str>,
    password: Zeroizing<String>,
) -> Result<AuthorizedSignIn, SignInError> {
    let choice = match account.map(str::trim).filter(|name| !name.is_empty()) {
        Some(name) => plan
            .choices
            .iter()
            .find(|choice| choice.account.is_named(name)),
        None => plan.directory_choice(),
    }
    .filter(|choice| choice.kind == SignInKind::DomainAccount)
    .cloned()
    .ok_or(SignInError::PasswordNotReusable)?;
    let user = User::Entity::find_by_id(plan.user_id)
        .one(db)
        .await
        .map_err(DomainAccountError::from)?
        .ok_or(SignInError::PasswordNotReusable)?;
    if user
        .ldap_password_server(db)
        .await
        .map_err(DomainAccountError::from)?
        .is_none()
    {
        return Err(SignInError::PasswordNotReusable);
    }
    authorize_choice(db, plan, &choice, password).await
}

async fn authorize_choice(
    db: &DatabaseConnection,
    plan: &SignInPlan,
    choice: &SignInChoice,
    password: Zeroizing<String>,
) -> Result<AuthorizedSignIn, SignInError> {
    let user_id = plan.user_id;
    match choice.kind {
        // The stored credential signs in; anything typed is dropped, and wiped, unused.
        SignInKind::Managed => Ok(AuthorizedSignIn::stored(user_id, plan.target_id, choice)),
        SignInKind::DomainAccount => {
            check_password(&password)?;
            let (account, identity) = verify_domain_password(
                db,
                user_id,
                choice.format,
                choice.domain_hint.as_deref(),
                &password,
            )
            .await?;
            info!(
                %user_id,
                account = %account.display_name(),
                account_id = %choice.account_id,
                "Domain password verified; signing in to the target as the user's own account"
            );
            let credentials = TargetCredentials {
                user_id,
                kind: SignInKind::DomainAccount,
                account,
                identity,
                password,
            };
            Ok(AuthorizedSignIn::typed(plan, choice, credentials))
        }
        SignInKind::LocalAccount => {
            check_password(&password)?;
            info!(
                %user_id,
                account = %choice.label(),
                account_id = %choice.account_id,
                "Signing in to the target as an account assigned to the user"
            );
            let credentials = TargetCredentials {
                user_id,
                kind: SignInKind::LocalAccount,
                identity: LogonIdentity::for_account(&choice.account),
                account: choice.account.clone(),
                password,
            };
            Ok(AuthorizedSignIn::typed(plan, choice, credentials))
        }
    }
}

/// The name of `user_id`'s own directory account, as `format` writes it: for a target (an
/// SSH server with SSSD, say) that knows directory users by one of these names.
pub async fn directory_account_name(
    db: &DatabaseConnection,
    user_id: Uuid,
    format: DirectoryUsernameFormat,
) -> Result<String, DomainAccountError> {
    let (account, _) = find_domain_account(db, user_id, format, None).await?;
    Ok(account.display_name())
}

/// The names of `user_id`'s own directory account in every format an account can use, looked
/// up once: for an administrator to see which account an assignment would sign in as.
pub async fn directory_account_names(
    db: &DatabaseConnection,
    user_id: Uuid,
) -> Result<Vec<(DirectoryUsernameFormat, String)>, DomainAccountError> {
    let (config, object_uuid) = directory_of(db, user_id).await?;
    let entry = warpgate_ldap::find_user_by_uuid(&config, &object_uuid)
        .await
        .map_err(|error| DomainAccountError::DirectoryUnavailable(error.to_string()))?
        .ok_or(DomainAccountError::Rejected(
            LdapBindRejection::UserNotFound,
        ))?;
    Ok([
        DirectoryUsernameFormat::Upn,
        DirectoryUsernameFormat::DownLevel,
        DirectoryUsernameFormat::AccountName,
        DirectoryUsernameFormat::AccountAtDomain,
    ]
    .into_iter()
    .filter_map(|format| {
        account_of(&entry, format, None).map(|account| (format, account.display_name()))
    })
    .collect())
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

/// The account `user_id` would sign in to the target as, looked up in the directory with
/// Warpgate's service account, and what its logon must report.
async fn find_domain_account(
    db: &DatabaseConnection,
    user_id: Uuid,
    format: DirectoryUsernameFormat,
    target_domain: Option<&str>,
) -> Result<(WindowsAccount, LogonIdentity), DomainAccountError> {
    let (config, object_uuid) = directory_of(db, user_id).await?;
    let entry = warpgate_ldap::find_user_by_uuid(&config, &object_uuid)
        .await
        .map_err(|error| DomainAccountError::DirectoryUnavailable(error.to_string()))?
        .ok_or(DomainAccountError::Rejected(
            LdapBindRejection::UserNotFound,
        ))?;
    domain_account_of(&entry, format, target_domain)
}

/// Check `password` for `user_id`'s own directory entry, by binding to the directory as it,
/// and return the account to sign in to the target as.
async fn verify_domain_password(
    db: &DatabaseConnection,
    user_id: Uuid,
    format: DirectoryUsernameFormat,
    target_domain: Option<&str>,
    password: &str,
) -> Result<(WindowsAccount, LogonIdentity), DomainAccountError> {
    let (config, object_uuid) = directory_of(db, user_id).await?;
    let entry = match warpgate_ldap::authenticate_user(&config, &object_uuid, password).await {
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
    domain_account_of(&entry, format, target_domain)
}

fn domain_account_of(
    entry: &LdapUser,
    format: DirectoryUsernameFormat,
    target_domain: Option<&str>,
) -> Result<(WindowsAccount, LogonIdentity), DomainAccountError> {
    let account =
        account_of(entry, format, target_domain).ok_or(DomainAccountError::NoAccountName)?;
    let identity = domain_identity_of(entry, &account, target_domain);
    Ok((account, identity))
}

/// The account `entry` signs in to a target as, named as `format` says; a UPN or down-level
/// name falls back to the other form when the entry lacks what it needs.
fn account_of(
    entry: &LdapUser,
    format: DirectoryUsernameFormat,
    target_domain: Option<&str>,
) -> Option<WindowsAccount> {
    let account_name = entry
        .sam_account_name
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty());
    let upn = entry
        .user_principal_name
        .as_deref()
        .map(str::trim)
        .filter(|upn| upn.contains('@'))
        .map(|upn| WindowsAccount {
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
                .or_else(|| netbios_domain_of(entry))
                .or_else(|| dns_domain_of(&entry.dn))?;
            Some(WindowsAccount {
                username: name.to_owned(),
                domain: Some(domain),
            })
        });
    match format {
        DirectoryUsernameFormat::Upn => upn.or(down_level),
        DirectoryUsernameFormat::DownLevel => down_level.or(upn),
        DirectoryUsernameFormat::AccountName => account_name.map(|name| WindowsAccount {
            username: name.to_owned(),
            domain: None,
        }),
        DirectoryUsernameFormat::AccountAtDomain => {
            let domain = dns_domain_of(&entry.dn)?;
            account_name.map(|name| WindowsAccount {
                username: format!("{name}@{domain}"),
                domain: None,
            })
        }
    }
}

/// What a logon as `entry`'s account reports: its account name, which Windows reports
/// however the account signed in, and its domain by every name Warpgate knows it by.
fn domain_identity_of(
    entry: &LdapUser,
    account: &WindowsAccount,
    target_domain: Option<&str>,
) -> LogonIdentity {
    let mut identity = LogonIdentity {
        account: account.display_name(),
        usernames: vec![],
        domains: vec![],
        upns: vec![],
    };
    if let Some(upn) = &entry.user_principal_name {
        identity.add_upn(upn);
    }
    if account.domain.is_none() {
        identity.add_upn(&account.username);
    }
    match entry
        .sam_account_name
        .as_deref()
        .filter(|name| !name.trim().is_empty())
    {
        Some(name) => identity.add_username(name),
        None => identity.add_username(account.logon_name()),
    }
    let known_domains = [
        netbios_domain_of(entry),
        target_domain.map(str::to_owned),
        account.domain.clone(),
        dns_domain_of(&entry.dn),
    ];
    for domain in known_domains.iter().flatten() {
        identity.add_domain(domain);
    }
    identity
}

/// The NetBIOS name of `entry`'s domain, from Active Directory's `CORP\alice`.
fn netbios_domain_of(entry: &LdapUser) -> Option<String> {
    entry
        .nt_account_name
        .as_deref()
        .and_then(|name| name.split_once('\\'))
        .map(|(domain, _name)| domain.trim())
        .filter(|domain| !domain.is_empty())
        .map(str::to_owned)
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

    const BACKSLASH: char = '\\';

    /// `domain\name`, spelled without a backslash escape.
    fn down_level(domain: &str, name: &str) -> String {
        format!("{domain}{BACKSLASH}{name}")
    }

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
            nt_account_name: None,
        }
    }

    fn account(username: &str, domain: Option<&str>) -> WindowsAccount {
        WindowsAccount {
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
            account_of(&full, DirectoryUsernameFormat::Upn, Some("CORP")),
            Some(account("alice@corp.example.com", None))
        );
        assert_eq!(
            account_of(&full, DirectoryUsernameFormat::DownLevel, Some("CORP")),
            Some(account("alice", Some("CORP")))
        );
        // Without a domain on the account, the directory's own.
        assert_eq!(
            account_of(&full, DirectoryUsernameFormat::DownLevel, Some("  ")),
            Some(account("alice", Some("corp.example.com")))
        );
        // Active Directory's NetBIOS name, when it gave one.
        let mut netbios = full.clone();
        netbios.nt_account_name = Some(down_level("CORP", "alice"));
        assert_eq!(
            account_of(&netbios, DirectoryUsernameFormat::DownLevel, None),
            Some(account("alice", Some("CORP")))
        );
    }

    #[test]
    fn a_missing_part_falls_back_to_the_other_form() {
        let no_upn = entry(Some("alice"), None);
        assert_eq!(
            account_of(&no_upn, DirectoryUsernameFormat::Upn, None),
            Some(account("alice", Some("corp.example.com")))
        );
        let no_sam = entry(None, Some("alice@corp.example.com"));
        assert_eq!(
            account_of(&no_sam, DirectoryUsernameFormat::DownLevel, Some("CORP")),
            Some(account("alice@corp.example.com", None))
        );
        assert_eq!(
            account_of(
                &entry(None, Some("not a upn")),
                DirectoryUsernameFormat::Upn,
                None
            ),
            None
        );
    }

    #[test]
    fn accounts_are_written_as_people_write_them() {
        assert_eq!(
            account("alice", Some("CORP")).display_name(),
            down_level("CORP", "alice")
        );
        assert_eq!(
            account("alice@corp.example.com", None).display_name(),
            "alice@corp.example.com"
        );
    }

    #[test]
    fn accounts_are_read_as_administrators_write_them() {
        assert_eq!(
            WindowsAccount::parse(&down_level("SRV01", "operator"), Some("IGNORED")),
            Some(account("operator", Some("SRV01")))
        );
        assert_eq!(
            WindowsAccount::parse(&down_level(".", "operator"), Some("SRV01")),
            Some(account("operator", None))
        );
        assert_eq!(
            WindowsAccount::parse(" operator ", Some("SRV01")),
            Some(account("operator", Some("SRV01")))
        );
        assert_eq!(
            WindowsAccount::parse("operator", Some("")),
            Some(account("operator", None))
        );
        assert_eq!(
            WindowsAccount::parse("ops@corp.example.com", Some("SRV01")),
            Some(account("ops@corp.example.com", None))
        );
        assert_eq!(WindowsAccount::parse(&down_level("SRV01", ""), None), None);
        assert_eq!(WindowsAccount::parse("  ", None), None);
    }

    #[test]
    fn credentials_never_print_their_password() {
        let credentials = TargetCredentials {
            user_id: Uuid::nil(),
            kind: SignInKind::DomainAccount,
            account: account("alice", Some("CORP")),
            identity: LogonIdentity::for_account(&account("alice", Some("CORP"))),
            password: Zeroizing::new("hunter2".into()),
        };
        let printed = format!("{credentials:?}");
        assert!(!printed.contains("hunter2"), "{printed}");
        assert_eq!(credentials.password(), "hunter2");

        let stored = StoredCredential {
            account: account("operator", None),
            password: "hunter2".parse().unwrap(),
        };
        assert!(!format!("{stored:?}").contains("hunter2"));
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
        assert!(!SignInError::Domain(DomainAccountError::NotLinked).may_retry());
        assert!(!SignInError::Access(AccessError::NoAccess).may_retry());
        assert!(SignInError::AccountNotAllowed.may_retry());
    }

    #[test]
    fn a_domain_logon_is_recognised_by_any_name_of_its_domain() {
        let mut entry = entry(Some("asmith"), Some("alice.smith@corp.example.com"));
        entry.nt_account_name = Some(down_level("CORPNT", "asmith"));
        let account = account("alice.smith@corp.example.com", None);
        let identity = domain_identity_of(&entry, &account, None);
        for domain in ["CORPNT", "corp", "corp.example.com"] {
            assert!(identity.clone().admits(domain, "ASMITH"), "{domain}");
        }
        // Another account, or the same name on the target itself.
        assert!(!identity.clone().admits("CORPNT", "administrator"));
        assert!(!identity.clone().admits("SRV01", "asmith"));
        // The part of the UPN before the `@` is not the account name here.
        assert!(!identity.clone().admits("CORPNT", "alice.smith"));
        // A logon reported by user principal name, with no domain.
        assert!(identity.clone().admits("", "Alice.Smith@corp.example.com"));
        assert!(!identity.clone().admits("", "bob@corp.example.com"));
    }

    #[test]
    fn a_logon_without_a_known_domain_holds_to_the_first_one() {
        let mut identity = LogonIdentity::for_account(&account("operator", None));
        assert!(identity.admits("SRV01", "Operator"));
        assert!(identity.admits("srv01", "operator"));
        assert!(!identity.admits("CORP", "operator"));
        assert!(!identity.admits("SRV01", "administrator"));
    }

    /// 34: a stored-credential account logs on as itself; on an interactive-logon target
    /// Warpgate records the account but cannot hold it to one.
    #[test]
    fn a_stored_account_logs_on_as_itself() {
        let operator = WindowsAccount::parse("operator", Some("corp.example.com")).unwrap();
        let mut identity = stored_logon_identity(&operator, false).unwrap();
        assert_eq!(
            identity.account(),
            down_level("corp.example.com", "operator")
        );
        assert!(identity.admits("CORP", "operator"));
        assert!(!identity.admits("CORP", "administrator"));
        assert_eq!(stored_logon_identity(&operator, true), None);
    }

    fn choice(id: u128, kind: SignInKind, account: WindowsAccount) -> SignInChoice {
        SignInChoice {
            account_id: Uuid::from_u128(id),
            kind,
            account,
            format: DirectoryUsernameFormat::Upn,
            domain_hint: None,
            stored: (kind == SignInKind::Managed).then(|| "stored".parse().unwrap()),
        }
    }

    fn plan(choices: Vec<SignInChoice>) -> SignInPlan {
        SignInPlan {
            user_id: Uuid::from_u128(1),
            target_id: Uuid::from_u128(2),
            choices,
        }
    }

    fn two_accounts() -> SignInPlan {
        plan(vec![
            choice(
                10,
                SignInKind::DomainAccount,
                account("ahmad", Some("CORP")),
            ),
            choice(
                11,
                SignInKind::LocalAccount,
                account("support", Some("WIN-SRV-01")),
            ),
        ])
    }

    #[test]
    fn a_plan_names_the_accounts_to_choose_from() {
        let plan = two_accounts();
        assert_eq!(
            plan.account_names(),
            vec![
                down_level("CORP", "ahmad"),
                down_level("WIN-SRV-01", "support")
            ]
        );
        assert_eq!(plan.prompt_kind(), SignInKind::LocalAccount);
        assert_eq!(
            plan.directory_choice().map(|choice| choice.account_id),
            Some(Uuid::from_u128(10))
        );
        assert!(plan.stored_sign_in().is_none());
        assert!(!SignInKind::Managed.asks_for_password());
        assert!(SignInKind::DomainAccount.asks_for_password());
    }

    /// 7, 10, 28: a client chooses only among its own accounts, by id or by name; a forged
    /// id or another name is refused, and several accounts need a choice.
    #[test]
    fn a_client_chooses_only_among_its_own_accounts() {
        let plan = two_accounts();
        let by_id = SignInAnswer {
            account_id: Some(Uuid::from_u128(11)),
            account: None,
        };
        assert_eq!(
            plan.select(by_id).unwrap().label(),
            down_level("WIN-SRV-01", "support")
        );
        let typed = format!(" {} ", down_level("corp", "AHMAD"));
        let by_name = SignInAnswer {
            account_id: None,
            account: Some(&typed),
        };
        assert_eq!(
            plan.select(by_name).unwrap().kind,
            SignInKind::DomainAccount
        );
        for forged in [
            SignInAnswer {
                account_id: Some(Uuid::from_u128(99)),
                account: None,
            },
            SignInAnswer {
                account_id: None,
                account: Some("administrator"),
            },
        ] {
            assert!(matches!(
                plan.select(forged),
                Err(SignInError::AccountNotAllowed)
            ));
        }
        assert!(matches!(
            plan.select(SignInAnswer::default()),
            Err(SignInError::AccountNotChosen)
        ));
    }

    /// 34: an account with a stored credential connects without asking, with that account's
    /// own credential.
    #[test]
    fn a_stored_account_alone_needs_no_prompt() {
        let plan = plan(vec![choice(
            12,
            SignInKind::Managed,
            account("operator", None),
        )]);
        let sign_in = plan.stored_sign_in().unwrap();
        assert_eq!(sign_in.kind(), SignInKind::Managed);
        assert!(sign_in.credentials().is_none());
        assert_eq!(sign_in.account_id(), Uuid::from_u128(12));
        let stored = sign_in.stored_credential().unwrap();
        assert_eq!(stored.account, account("operator", None));
        assert_eq!(
            (sign_in.user_id(), sign_in.target_id()),
            (Uuid::from_u128(1), Uuid::from_u128(2))
        );
    }

    /// 35: the password the user signed in with is offered to their own directory account
    /// only: never to a local account, whatever the client names.
    #[tokio::test]
    async fn the_sign_in_password_is_never_offered_to_another_account() {
        let plan = plan(vec![choice(
            11,
            SignInKind::LocalAccount,
            account("support", Some("WIN-SRV-01")),
        )]);
        let db = DatabaseConnection::Disconnected;
        let label = down_level("WIN-SRV-01", "support");
        for named in [None, Some("support"), Some(label.as_str())] {
            assert!(matches!(
                reuse_sign_in_password(&db, &plan, named, Zeroizing::new("p".into())).await,
                Err(SignInError::PasswordNotReusable)
            ));
        }
    }
}
