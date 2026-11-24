//! Account access: which remote accounts a user may sign in to a target as.
//!
//! An administrator binds a user to a target and an account on it (Access Control, account
//! access): the user's own directory account, a local account of the target by name, or the
//! target's managed account. The bindings add to target access, they never grant it: a
//! connection still needs the user's roles to allow the target, and its second factor and
//! approval, before any of this is looked at.
//!
//! - A user with bindings on a target may only use those (the active ones: enabled, not
//!   expired, and, for a directory account, still linked to the same directory entry).
//! - A user with none uses the target as it is set up, unless the target requires a binding
//!   (`require_account_binding`), in which case they are refused. Bindings never turn into
//!   access by themselves, and existing targets behave as before until bindings are added.
//!
//! Every protocol resolves the account here, from the user and target Warpgate admitted, so
//! no client can name an account it was not given: a binding id a client sends is only ever
//! looked up among the user's own bindings on that target.

use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder};
use time::OffsetDateTime;
use tracing::warn;
use uuid::Uuid;
use warpgate_common::audit::AuditEvent;
use warpgate_common::{
    RdpTargetAuth, SSHTargetAuth, TargetOptions, TargetRdpOptions, TargetSSHOptions,
};
use warpgate_db_entities::TargetAccountBinding::{self, Model as Binding};
pub use warpgate_db_entities::TargetAccountBinding::{
    DirectoryUsernameFormat, TargetAccountAuthMethod, TargetAccountKind,
};
use warpgate_db_entities::{TargetSession, User, UserSession};

use crate::{Services, SessionsFilter};

/// The protocol a binding is used over.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindingProtocol {
    Rdp,
    Ssh,
}

impl BindingProtocol {
    pub const fn of(options: &TargetOptions) -> Option<Self> {
        match options {
            TargetOptions::Rdp(_) => Some(Self::Rdp),
            TargetOptions::Ssh(_) => Some(Self::Ssh),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rdp => "rdp",
            Self::Ssh => "ssh",
        }
    }
}

/// What a target authenticates with, as far as bound accounts are concerned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetCredential {
    /// RDP with a stored or Vault password, for the target's configured account.
    RdpStoredPassword,
    /// RDP with no stored password (it signs in with a password the user types).
    RdpNoStoredPassword,
    /// SSH with a stored or Vault password, which belongs to the configured account alone.
    SshPassword,
    /// SSH with Warpgate's keys, a Vault-signed certificate or an AWS role: credentials a
    /// target can accept for whichever account it is set up to trust them for.
    SshKey,
}

impl TargetCredential {
    pub const fn rdp(options: &TargetRdpOptions) -> Self {
        match options.auth {
            RdpTargetAuth::Password(_) => Self::RdpStoredPassword,
            RdpTargetAuth::DomainAccount(_) | RdpTargetAuth::LocalAccount(_) => {
                Self::RdpNoStoredPassword
            }
        }
    }

    pub const fn ssh(options: &TargetSSHOptions) -> Self {
        match options.auth {
            SSHTargetAuth::Password(_) => Self::SshPassword,
            SSHTargetAuth::PublicKey(_)
            | SSHTargetAuth::Certificate(_)
            | SSHTargetAuth::IamRole(_) => Self::SshKey,
        }
    }
}

/// Why an account cannot be bound, or used.
#[derive(Debug, thiserror::Error)]
pub enum BindingError {
    /// The target requires a binding, and the user has none.
    #[error("no account on the target is assigned to the user")]
    NoBinding,
    /// The user has bindings on the target, and none of them can be used now.
    #[error("none of the accounts assigned to the user on the target can be used")]
    NoActiveBinding,
    /// The binding a request named is not one of the user's on this target.
    #[error("the account is not assigned to the user on this target")]
    NotFound,
    /// The binding is the user's, and disabled, expired or out of date.
    #[error("the account assignment is disabled, expired or out of date")]
    Inactive,
    /// A directory account for a user who is not linked to a directory.
    #[error("the user is not linked to a directory account")]
    NotLinked,
    /// Several accounts are assigned, and the request chose none.
    #[error("the account to sign in as was not chosen")]
    NotChosen,
    /// The combination of protocol, account and authentication cannot be made to work.
    #[error("{0}")]
    Unsupported(&'static str),
    /// Looking the directory account up failed.
    #[error("the directory account could not be looked up: {0}")]
    Directory(String),
    #[error(transparent)]
    Database(#[from] sea_orm::DbErr),
}

impl BindingError {
    /// What to tell the user. Nothing here says anything about anyone else's accounts.
    pub const fn user_message(&self) -> &'static str {
        match self {
            Self::NoBinding => {
                "No account on this target is assigned to you. Ask an administrator to assign one."
            }
            Self::NoActiveBinding => {
                "The accounts assigned to you on this target are disabled or expired. Ask an administrator."
            }
            Self::NotFound => "You may not sign in to this target as that account.",
            Self::Inactive => {
                "That account assignment is disabled or expired. Ask an administrator."
            }
            Self::NotLinked => {
                "Your Warpgate account is not linked to a directory account. Ask an administrator."
            }
            Self::NotChosen => "Choose the account to sign in as.",
            Self::Unsupported(reason) => *reason,
            Self::Directory(_) | Self::Database(_) => {
                "The account could not be looked up right now. Try again later."
            }
        }
    }
}

/// Whether an account of `kind`, authenticated with `method`, can be used over `protocol`
/// on a target that authenticates with `credential`.
pub fn check_combination(
    protocol: BindingProtocol,
    kind: TargetAccountKind,
    method: TargetAccountAuthMethod,
    credential: TargetCredential,
) -> Result<(), BindingError> {
    use TargetAccountAuthMethod as M;
    use TargetAccountKind as K;
    match (protocol, kind, method) {
        (BindingProtocol::Rdp, K::Directory, M::DirectoryPassword)
        | (BindingProtocol::Rdp, K::Local, M::TypedPassword) => Ok(()),
        (BindingProtocol::Rdp, K::Managed, M::TargetCredential) => {
            if credential == TargetCredential::RdpStoredPassword {
                Ok(())
            } else {
                Err(BindingError::Unsupported(
                    "The target has no stored password, so it has no managed account to assign.",
                ))
            }
        }
        (BindingProtocol::Rdp, ..) => Err(BindingError::Unsupported(
            "On an RDP target, a directory account signs in with the directory password, a local account with its own password typed when connecting, and the managed account with the target's stored credential.",
        )),
        (BindingProtocol::Ssh, K::Managed, M::TargetCredential) => Ok(()),
        (BindingProtocol::Ssh, K::Directory | K::Local, M::TargetCredential) => {
            if credential == TargetCredential::SshKey {
                Ok(())
            } else {
                Err(BindingError::Unsupported(
                    "The target's stored password belongs to its configured account. Another account needs the target to sign in with Warpgate's SSH keys, a Vault-signed certificate or an AWS role.",
                ))
            }
        }
        (BindingProtocol::Ssh, ..) => Err(BindingError::Unsupported(
            "SSH targets cannot be signed in to with a password the user types: assign the account with the target's credential (Warpgate's SSH keys or a Vault-signed certificate the target trusts for it).",
        )),
    }
}

/// The authentication methods an account of `kind` can use over `protocol`.
pub fn methods_for(
    protocol: BindingProtocol,
    kind: TargetAccountKind,
    credential: TargetCredential,
) -> Vec<TargetAccountAuthMethod> {
    [
        TargetAccountAuthMethod::DirectoryPassword,
        TargetAccountAuthMethod::TypedPassword,
        TargetAccountAuthMethod::TargetCredential,
    ]
    .into_iter()
    .filter(|method| check_combination(protocol, kind, *method, credential).is_ok())
    .collect()
}

/// Whether a binding still names the account it was made for: a directory account only
/// while the user is linked to the same directory entry it was assigned from, so relinking
/// a user (to another entry, or another directory) never carries old assignments over.
pub fn link_matches(binding: &Binding, user: &User::Model) -> bool {
    match binding.account_kind {
        TargetAccountKind::Directory => {
            binding.ldap_server_id.is_some()
                && binding.ldap_object_uuid.is_some()
                && binding.ldap_server_id == user.ldap_server_id
                && binding.ldap_object_uuid == user.ldap_object_uuid
        }
        TargetAccountKind::Local | TargetAccountKind::Managed => true,
    }
}

/// Why a binding cannot be used now, if it cannot.
pub fn unusable_because(
    binding: &Binding,
    user: &User::Model,
    protocol: BindingProtocol,
    credential: TargetCredential,
    now: OffsetDateTime,
) -> Option<&'static str> {
    if !binding.enabled {
        return Some("disabled");
    }
    if binding.expires_at.is_some_and(|expires| expires <= now) {
        return Some("expired");
    }
    if !link_matches(binding, user) {
        return Some("the user's directory link changed");
    }
    if check_combination(
        protocol,
        binding.account_kind,
        binding.auth_method,
        credential,
    )
    .is_err()
    {
        return Some("the target no longer authenticates this way");
    }
    None
}

/// What the bindings let a user sign in to a target as.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AccountAccess {
    /// No account is assigned to the user there, and the target requires none: it signs
    /// them in as it is set up.
    Unrestricted,
    /// Only these, in the order they were assigned.
    Restricted(Vec<Binding>),
}

/// The bindings of `user_id` on `target_id`, in the order they were assigned.
pub async fn bindings_of(
    db: &DatabaseConnection,
    user_id: Uuid,
    target_id: Uuid,
) -> Result<Vec<Binding>, sea_orm::DbErr> {
    TargetAccountBinding::Entity::find()
        .filter(TargetAccountBinding::Column::UserId.eq(user_id))
        .filter(TargetAccountBinding::Column::TargetId.eq(target_id))
        .order_by_asc(TargetAccountBinding::Column::CreatedAt)
        .order_by_asc(TargetAccountBinding::Column::Id)
        .all(db)
        .await
}

/// The target a connection is for, as far as bindings are concerned.
#[derive(Clone, Copy, Debug)]
pub struct BoundTarget<'a> {
    pub id: Uuid,
    pub name: &'a str,
    pub protocol: BindingProtocol,
    pub credential: TargetCredential,
    /// The target requires every user to have a binding (`require_account_binding`).
    pub required: bool,
}

impl<'a> BoundTarget<'a> {
    pub const fn rdp(id: Uuid, name: &'a str, options: &TargetRdpOptions) -> Self {
        Self {
            id,
            name,
            protocol: BindingProtocol::Rdp,
            credential: TargetCredential::rdp(options),
            required: options.require_account_binding,
        }
    }

    pub const fn ssh(id: Uuid, name: &'a str, options: &TargetSSHOptions) -> Self {
        Self {
            id,
            name,
            protocol: BindingProtocol::Ssh,
            credential: TargetCredential::ssh(options),
            required: options.require_account_binding,
        }
    }

    /// A target bindings apply to (RDP or SSH); `None` for any other kind.
    pub const fn of(id: Uuid, name: &'a str, options: &TargetOptions) -> Option<Self> {
        match options {
            TargetOptions::Rdp(options) => Some(Self::rdp(id, name, options)),
            TargetOptions::Ssh(options) => Some(Self::ssh(id, name, options)),
            _ => None,
        }
    }
}

/// The user a connection is for.
#[derive(Clone, Copy)]
pub struct BoundUser<'a> {
    pub id: Uuid,
    pub username: &'a str,
}

/// What the bindings let `user` sign in to `target` as now. A refusal is audited.
pub async fn account_access(
    db: &DatabaseConnection,
    user: BoundUser<'_>,
    target: BoundTarget<'_>,
    now: OffsetDateTime,
) -> Result<AccountAccess, BindingError> {
    let (protocol, credential) = (target.protocol, target.credential);
    let bindings = bindings_of(db, user.id, target.id).await?;
    if bindings.is_empty() {
        if target.required {
            refuse(user, target, None, None, &BindingError::NoBinding);
            return Err(BindingError::NoBinding);
        }
        return Ok(AccountAccess::Unrestricted);
    }
    let Some(user_model) = User::Entity::find_by_id(user.id).one(db).await? else {
        return Err(BindingError::NoActiveBinding);
    };
    let mut usable = Vec::new();
    for binding in bindings {
        match unusable_because(&binding, &user_model, protocol, credential, now) {
            None => usable.push(binding),
            Some(reason) => warn!(
                user = %user.username,
                target = %target.name,
                binding_id = %binding.id,
                reason,
                "Skipping an account assignment that cannot be used"
            ),
        }
    }
    if usable.is_empty() {
        refuse(user, target, None, None, &BindingError::NoActiveBinding);
        return Err(BindingError::NoActiveBinding);
    }
    Ok(AccountAccess::Restricted(usable))
}

/// Which of the usable bindings a connection uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindingChoice {
    /// The one the client asked for, by id; only ever one of the user's own.
    Id(Uuid),
    /// The only one; several are a refusal ([`BindingError::NotChosen`]).
    Only,
    /// The first assigned, for clients that have no way to choose (native SSH).
    First,
}

/// Pick the binding a connection uses among `access`. `Ok(None)` when the user is not
/// restricted to bindings on the target. A binding id that is not one of the user's usable
/// ones on this target is refused, and audited.
pub fn choose(
    access: &AccountAccess,
    choice: BindingChoice,
    user: BoundUser<'_>,
    target: BoundTarget<'_>,
) -> Result<Option<Binding>, BindingError> {
    let bindings = match access {
        AccountAccess::Unrestricted => {
            return match choice {
                BindingChoice::Id(id) => {
                    refuse(user, target, Some(id), None, &BindingError::NotFound);
                    Err(BindingError::NotFound)
                }
                BindingChoice::Only | BindingChoice::First => Ok(None),
            };
        }
        AccountAccess::Restricted(bindings) => bindings,
    };
    match choice {
        BindingChoice::Id(id) => match bindings.iter().find(|binding| binding.id == id) {
            Some(binding) => Ok(Some(binding.clone())),
            None => {
                refuse(user, target, Some(id), None, &BindingError::NotFound);
                Err(BindingError::NotFound)
            }
        },
        BindingChoice::Only => match bindings.as_slice() {
            [only] => Ok(Some(only.clone())),
            _ => Err(BindingError::NotChosen),
        },
        BindingChoice::First => Ok(bindings.first().cloned()),
    }
}

/// Audit a refused account: no binding, an unusable one, or one that was not the user's.
pub fn refuse(
    user: BoundUser<'_>,
    target: BoundTarget<'_>,
    binding_id: Option<Uuid>,
    requested_account: Option<&str>,
    error: &BindingError,
) {
    AuditEvent::AccountBindingRefused {
        user_id: user.id,
        username: user.username.to_owned(),
        target_id: target.id,
        target_name: target.name.to_owned(),
        binding_id,
        requested_account: requested_account.map(str::to_owned),
        reason: error.to_string(),
    }
    .emit();
}

/// End the user's live sessions on the target, once an assignment they may be using is
/// revoked, disabled or changed: a session that signed in as the account must not outlive
/// the decision that allowed it.
pub async fn close_sessions_on_target(
    services: &Services,
    user_id: Uuid,
    target_id: Uuid,
) -> Result<(), warpgate_common::WarpgateError> {
    let live: Vec<_> = TargetSession::Entity::find()
        .filter(TargetSession::Column::TargetId.eq(target_id))
        .filter(TargetSession::Column::Ended.is_null())
        .find_also_related(UserSession::Entity)
        .all(&services.db)
        .await?
        .into_iter()
        .filter_map(|(_, session)| session)
        .filter(|session| session.user_id == Some(user_id) && session.ended.is_none())
        .map(|session| session.id)
        .collect();
    if live.is_empty() {
        return Ok(());
    }
    services
        .close_sessions(SessionsFilter::Sessions { ids: live })
        .await
}

/// An account a user signs in to an SSH target as, from one of their assignments there.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoundSshAccount {
    pub binding_id: Uuid,
    pub kind: TargetAccountKind,
    pub auth_method: TargetAccountAuthMethod,
    /// The destination username: the local account, the directory account as the target
    /// names it, or the target's configured account.
    pub username: String,
}

/// The username a binding signs in to an SSH target as.
async fn ssh_username(
    db: &DatabaseConnection,
    user: BoundUser<'_>,
    options: &TargetSSHOptions,
    binding: &Binding,
) -> Result<String, BindingError> {
    match binding.account_kind {
        TargetAccountKind::Local => binding
            .account_name
            .as_deref()
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(str::to_owned)
            .ok_or(BindingError::Inactive),
        // As the target is set up: its account, or the user's own name where it has none.
        TargetAccountKind::Managed => Ok(if options.username.is_empty() {
            user.username.to_owned()
        } else {
            options.username.clone()
        }),
        // A Linux server joined with realmd knows directory users by their fully qualified
        // name by default (`alice@corp.example.com`); a binding says otherwise when it does.
        TargetAccountKind::Directory => crate::rdp_account::directory_account_name(
            db,
            user.id,
            binding
                .username_format
                .unwrap_or(DirectoryUsernameFormat::AccountAtDomain),
        )
        .await
        .map_err(|error| BindingError::Directory(error.to_string())),
    }
}

/// The accounts `user` may sign in to the SSH target as: their usable assignments, with the
/// usernames they sign in with. Empty when no account is assigned to them there and the
/// target requires none: it then signs them in as it is set up.
pub async fn ssh_accounts(
    db: &DatabaseConnection,
    user: BoundUser<'_>,
    target_id: Uuid,
    target_name: &str,
    options: &TargetSSHOptions,
) -> Result<Vec<BoundSshAccount>, BindingError> {
    let target = BoundTarget::ssh(target_id, target_name, options);
    let AccountAccess::Restricted(bindings) =
        account_access(db, user, target, OffsetDateTime::now_utc()).await?
    else {
        return Ok(vec![]);
    };
    let mut accounts = Vec::new();
    for binding in bindings {
        match ssh_username(db, user, options, &binding).await {
            Ok(username) => accounts.push(BoundSshAccount {
                binding_id: binding.id,
                kind: binding.account_kind,
                auth_method: binding.auth_method,
                username,
            }),
            Err(error) => {
                warn!(binding_id = %binding.id, %error, "Could not resolve an assigned SSH account")
            }
        }
    }
    Ok(accounts)
}

/// The account `user` signs in to the SSH target as, when accounts are assigned to them
/// there: the one `choice` picks among their own. `None` when they are not restricted to
/// assigned accounts on it.
pub async fn resolve_ssh_account(
    db: &DatabaseConnection,
    user: BoundUser<'_>,
    target_id: Uuid,
    target_name: &str,
    options: &TargetSSHOptions,
    choice: BindingChoice,
) -> Result<Option<BoundSshAccount>, BindingError> {
    let target = BoundTarget::ssh(target_id, target_name, options);
    let access = account_access(db, user, target, OffsetDateTime::now_utc()).await?;
    let Some(binding) = choose(&access, choice, user, target)? else {
        return Ok(None);
    };
    let username = ssh_username(db, user, options, &binding).await?;
    Ok(Some(BoundSshAccount {
        binding_id: binding.id,
        kind: binding.account_kind,
        auth_method: binding.auth_method,
        username,
    }))
}

#[cfg(test)]
mod tests {
    use sea_orm::ActiveValue::Set;
    use sea_orm::{ActiveModelTrait, Database};
    use warpgate_common::{
        RdpTargetDomainAccountAuth, RdpTargetPasswordAuth, SshTargetPublicKeyAuth,
        TargetRdpOptions, TargetSSHOptions,
    };
    use warpgate_db_entities::Parameters::{ConfigMigrationValues, set_config_migration_values};
    use warpgate_db_migrations::migrate_database;

    use super::*;

    async fn migrated_db() -> DatabaseConnection {
        set_config_migration_values(ConfigMigrationValues::default());
        let db = Database::connect("sqlite::memory:").await.unwrap();
        migrate_database(&db).await.unwrap();
        db
    }

    async fn user(db: &DatabaseConnection, name: &str, link: Option<(Uuid, Uuid)>) -> Uuid {
        let id = Uuid::new_v4();
        User::ActiveModel {
            id: Set(id),
            username: Set(name.to_owned()),
            description: Set(String::new()),
            credential_policy: Set(serde_json::json!(null)),
            ldap_server_id: Set(link.map(|(server, _)| server)),
            ldap_object_uuid: Set(link.map(|(_, entry)| entry)),
            ..Default::default()
        }
        .insert(db)
        .await
        .unwrap();
        id
    }

    async fn ldap_server(db: &DatabaseConnection) -> Uuid {
        warpgate_db_entities::LdapServer::ActiveModel {
            id: Set(Uuid::new_v4()),
            name: Set(format!("directory-{}", Uuid::new_v4())),
            host: Set("ldap.invalid".to_owned()),
            port: Set(636),
            bind_dn: Set(String::new()),
            bind_password: Set(String::new()),
            user_filter: Set("(objectClass=person)".to_owned()),
            base_dns: Set(serde_json::json!(["dc=example,dc=com"])),
            tls_mode: Set("preferred".to_owned()),
            tls_verify: Set(true),
            enabled: Set(true),
            auto_link_sso_users: Set(false),
            description: Set(String::new()),
            username_attribute: Set("cn".to_owned()),
            ssh_key_attribute: Set("sshPublicKey".to_owned()),
            uuid_attribute: Set(String::new()),
            authenticate_users: Set(true),
        }
        .insert(db)
        .await
        .unwrap()
        .id
    }

    async fn target(db: &DatabaseConnection, name: &str, options: &TargetOptions) -> Uuid {
        let id = Uuid::new_v4();
        warpgate_db_entities::Target::ActiveModel {
            id: Set(id),
            name: Set(name.to_owned()),
            description: Set(String::new()),
            kind: Set(warpgate_db_entities::Target::TargetKind::from(options)),
            options: Set(serde_json::to_value(options).unwrap()),
            ticket_requests_disabled: Set(false),
            ticket_require_approval: Set(false),
            require_approval: Set(false),
            ..Default::default()
        }
        .insert(db)
        .await
        .unwrap();
        id
    }

    struct NewBinding {
        kind: TargetAccountKind,
        name: Option<&'static str>,
        link: Option<(Uuid, Uuid)>,
        method: TargetAccountAuthMethod,
        enabled: bool,
        expires_at: Option<OffsetDateTime>,
    }

    impl NewBinding {
        const fn local(name: &'static str, method: TargetAccountAuthMethod) -> Self {
            Self {
                kind: TargetAccountKind::Local,
                name: Some(name),
                link: None,
                method,
                enabled: true,
                expires_at: None,
            }
        }
    }

    async fn bind(
        db: &DatabaseConnection,
        user_id: Uuid,
        target_id: Uuid,
        new: NewBinding,
    ) -> Uuid {
        let id = Uuid::new_v4();
        let now = OffsetDateTime::now_utc();
        TargetAccountBinding::ActiveModel {
            id: Set(id),
            user_id: Set(user_id),
            target_id: Set(target_id),
            account_kind: Set(new.kind),
            account_name: Set(new.name.map(str::to_owned)),
            ldap_server_id: Set(new.link.map(|(server, _)| server)),
            ldap_object_uuid: Set(new.link.map(|(_, entry)| entry)),
            username_format: Set(None),
            auth_method: Set(new.method),
            enabled: Set(new.enabled),
            expires_at: Set(new.expires_at),
            created_by: Set(None),
            created_at: Set(now),
            updated_at: Set(now),
            account_key: Set(Binding::key_for(
                new.kind,
                new.name,
                new.link.map(|(_, entry)| entry),
            )),
        }
        .insert(db)
        .await
        .unwrap();
        id
    }

    fn rdp(auth: RdpTargetAuth, required: bool) -> TargetOptions {
        let mut options: TargetRdpOptions =
            serde_json::from_value(serde_json::json!({"host": "win-srv-01"})).unwrap();
        options.auth = auth;
        options.require_account_binding = required;
        TargetOptions::Rdp(options)
    }

    fn ssh(auth: SSHTargetAuth) -> TargetOptions {
        let mut options: TargetSSHOptions =
            serde_json::from_value(serde_json::json!({"host": "linux-srv-01"})).unwrap();
        options.auth = auth;
        TargetOptions::Ssh(options)
    }

    fn stored_password() -> RdpTargetAuth {
        RdpTargetAuth::Password(RdpTargetPasswordAuth {
            password: warpgate_common::MaybeSecretRef::default(),
        })
    }

    async fn access(
        db: &DatabaseConnection,
        user_id: Uuid,
        target_id: Uuid,
        options: &TargetOptions,
    ) -> Result<AccountAccess, BindingError> {
        account_access(
            db,
            BoundUser {
                id: user_id,
                username: "ahmad",
            },
            on(target_id, options),
            OffsetDateTime::now_utc(),
        )
        .await
    }

    fn ids(access: &AccountAccess) -> Vec<Uuid> {
        match access {
            AccountAccess::Unrestricted => vec![],
            AccountAccess::Restricted(bindings) => bindings.iter().map(|b| b.id).collect(),
        }
    }

    fn who<'a>(user_id: Uuid) -> BoundUser<'a> {
        BoundUser {
            id: user_id,
            username: "ahmad",
        }
    }

    fn on(target_id: Uuid, options: &TargetOptions) -> BoundTarget<'static> {
        BoundTarget::of(target_id, "WIN-SRV-01", options).unwrap()
    }

    /// 1, 2, 7: the user's assigned accounts are theirs to choose among, and only those.
    #[tokio::test]
    async fn an_assigned_account_is_used_and_only_assigned_ones() {
        let db = migrated_db().await;
        let options = rdp(stored_password(), false);
        let ahmad = user(&db, "ahmad", None).await;
        let server = target(&db, "WIN-SRV-01", &options).await;
        let support = bind(
            &db,
            ahmad,
            server,
            NewBinding::local(
                r"WIN-SRV-01\support",
                TargetAccountAuthMethod::TypedPassword,
            ),
        )
        .await;
        let managed = bind(
            &db,
            ahmad,
            server,
            NewBinding {
                kind: TargetAccountKind::Managed,
                name: None,
                link: None,
                method: TargetAccountAuthMethod::TargetCredential,
                enabled: true,
                expires_at: None,
            },
        )
        .await;

        let access = access(&db, ahmad, server, &options).await.unwrap();
        assert_eq!(ids(&access), vec![support, managed]);
        let picked = choose(
            &access,
            BindingChoice::Id(support),
            who(ahmad),
            on(server, &options),
        )
        .unwrap()
        .unwrap();
        assert_eq!(picked.account_name.as_deref(), Some(r"WIN-SRV-01\support"));
        // Several: a client must choose, or get the first where it cannot.
        assert!(matches!(
            choose(
                &access,
                BindingChoice::Only,
                who(ahmad),
                on(server, &options)
            ),
            Err(BindingError::NotChosen)
        ));
        assert_eq!(
            choose(
                &access,
                BindingChoice::First,
                who(ahmad),
                on(server, &options)
            )
            .unwrap()
            .map(|b| b.id),
            Some(support)
        );
    }

    /// 3, 4, 5: a forged id, or another user's binding, is refused.
    #[tokio::test]
    async fn another_users_or_a_forged_binding_is_refused() {
        let db = migrated_db().await;
        let options = rdp(RdpTargetAuth::LocalAccount(Default::default()), false);
        let ahmad = user(&db, "ahmad", None).await;
        let yusif = user(&db, "yusif", None).await;
        let server = target(&db, "WIN-SRV-01", &options).await;
        bind(
            &db,
            ahmad,
            server,
            NewBinding::local("support", TargetAccountAuthMethod::TypedPassword),
        )
        .await;
        let yusifs = bind(
            &db,
            yusif,
            server,
            NewBinding::local("administrator", TargetAccountAuthMethod::TypedPassword),
        )
        .await;

        let access = access(&db, ahmad, server, &options).await.unwrap();
        for forged in [yusifs, Uuid::new_v4()] {
            assert!(matches!(
                choose(
                    &access,
                    BindingChoice::Id(forged),
                    who(ahmad),
                    on(server, &options)
                ),
                Err(BindingError::NotFound)
            ));
        }
        // A binding id where the user has none at all is refused too.
        let other = target(&db, "WIN-SRV-02", &options).await;
        let unrestricted = access_of(&db, ahmad, other, &options).await;
        assert_eq!(unrestricted, AccountAccess::Unrestricted);
        assert!(matches!(
            choose(
                &unrestricted,
                BindingChoice::Id(yusifs),
                who(ahmad),
                on(other, &options)
            ),
            Err(BindingError::NotFound)
        ));
    }

    async fn access_of(
        db: &DatabaseConnection,
        user_id: Uuid,
        target_id: Uuid,
        options: &TargetOptions,
    ) -> AccountAccess {
        access(db, user_id, target_id, options).await.unwrap()
    }

    /// 6, 9: disabled and expired bindings cannot be used; with nothing else, the user is
    /// refused rather than let back in as the target is set up.
    #[tokio::test]
    async fn disabled_and_expired_bindings_refuse() {
        let db = migrated_db().await;
        let options = rdp(RdpTargetAuth::LocalAccount(Default::default()), false);
        let ahmad = user(&db, "ahmad", None).await;
        let server = target(&db, "WIN-SRV-01", &options).await;
        bind(
            &db,
            ahmad,
            server,
            NewBinding {
                enabled: false,
                ..NewBinding::local("support", TargetAccountAuthMethod::TypedPassword)
            },
        )
        .await;
        bind(
            &db,
            ahmad,
            server,
            NewBinding {
                expires_at: Some(OffsetDateTime::now_utc() - time::Duration::hours(1)),
                ..NewBinding::local("backup", TargetAccountAuthMethod::TypedPassword)
            },
        )
        .await;
        assert!(matches!(
            access(&db, ahmad, server, &options).await,
            Err(BindingError::NoActiveBinding)
        ));
    }

    /// A target that requires bindings refuses a user with none; one that does not lets
    /// them in as it is set up, so existing targets keep working.
    #[tokio::test]
    async fn only_a_strict_target_refuses_users_without_bindings() {
        let db = migrated_db().await;
        let ahmad = user(&db, "ahmad", None).await;
        let lenient = rdp(stored_password(), false);
        let strict = rdp(stored_password(), true);
        let lenient_id = target(&db, "WIN-SRV-01", &lenient).await;
        let strict_id = target(&db, "WIN-SRV-02", &strict).await;
        assert_eq!(
            access(&db, ahmad, lenient_id, &lenient).await.unwrap(),
            AccountAccess::Unrestricted
        );
        assert!(matches!(
            access(&db, ahmad, strict_id, &strict).await,
            Err(BindingError::NoBinding)
        ));
    }

    /// 13, 14: a directory binding is good only while the user stays linked to the entry,
    /// and the directory, it was made for.
    #[tokio::test]
    async fn a_directory_binding_follows_the_users_link() {
        let db = migrated_db().await;
        let options = rdp(
            RdpTargetAuth::DomainAccount(RdpTargetDomainAccountAuth::default()),
            false,
        );
        let corp = ldap_server(&db).await;
        let other_directory = ldap_server(&db).await;
        let entry = Uuid::new_v4();
        let ahmad = user(&db, "ahmad", Some((corp, entry))).await;
        let server = target(&db, "WIN-SRV-01", &options).await;
        let binding = bind(
            &db,
            ahmad,
            server,
            NewBinding {
                kind: TargetAccountKind::Directory,
                name: None,
                link: Some((corp, entry)),
                method: TargetAccountAuthMethod::DirectoryPassword,
                enabled: true,
                expires_at: None,
            },
        )
        .await;
        assert_eq!(
            ids(&access_of(&db, ahmad, server, &options).await),
            vec![binding]
        );

        // Relinked: to another entry in the same directory, then to another directory
        // with the same entry UUID. Neither carries the assignment over.
        for link in [(corp, Uuid::new_v4()), (other_directory, entry)] {
            User::ActiveModel {
                id: Set(ahmad),
                ldap_server_id: Set(Some(link.0)),
                ldap_object_uuid: Set(Some(link.1)),
                ..Default::default()
            }
            .update(&db)
            .await
            .unwrap();
            assert!(matches!(
                access(&db, ahmad, server, &options).await,
                Err(BindingError::NoActiveBinding)
            ));
        }
    }

    /// 17: local assignments are per target.
    #[tokio::test]
    async fn local_assignments_stay_on_their_target() {
        let db = migrated_db().await;
        let options = rdp(RdpTargetAuth::LocalAccount(Default::default()), false);
        let ahmad = user(&db, "ahmad", None).await;
        let first = target(&db, "WIN-SRV-01", &options).await;
        let second = target(&db, "WIN-SRV-02", &options).await;
        bind(
            &db,
            ahmad,
            first,
            NewBinding::local("support", TargetAccountAuthMethod::TypedPassword),
        )
        .await;
        assert_eq!(ids(&access_of(&db, ahmad, first, &options).await).len(), 1);
        assert_eq!(
            access_of(&db, ahmad, second, &options).await,
            AccountAccess::Unrestricted
        );
    }

    /// 37: combinations that cannot work are refused, at assignment and at use.
    #[tokio::test]
    async fn unsupported_combinations_fail_safely() {
        use TargetAccountAuthMethod as M;
        use TargetAccountKind as K;
        let key = TargetCredential::SshKey;
        assert!(
            check_combination(BindingProtocol::Ssh, K::Local, M::TargetCredential, key).is_ok()
        );
        assert!(
            check_combination(BindingProtocol::Ssh, K::Directory, M::TargetCredential, key).is_ok()
        );
        for (kind, method) in [
            (K::Directory, M::DirectoryPassword),
            (K::Local, M::TypedPassword),
        ] {
            assert!(check_combination(BindingProtocol::Ssh, kind, method, key).is_err());
        }
        // A stored SSH password is the configured account's, not another's.
        assert!(
            check_combination(
                BindingProtocol::Ssh,
                K::Local,
                M::TargetCredential,
                TargetCredential::SshPassword
            )
            .is_err()
        );
        assert!(
            check_combination(
                BindingProtocol::Rdp,
                K::Managed,
                M::TargetCredential,
                TargetCredential::RdpNoStoredPassword
            )
            .is_err()
        );
        assert_eq!(
            methods_for(
                BindingProtocol::Rdp,
                K::Directory,
                TargetCredential::RdpStoredPassword
            ),
            vec![M::DirectoryPassword]
        );

        // An assignment the target can no longer honour is skipped at use.
        let db = migrated_db().await;
        let options = ssh(SSHTargetAuth::Password(
            warpgate_common::SshTargetPasswordAuth {
                password: warpgate_common::MaybeSecretRef::default(),
            },
        ));
        let ahmad = user(&db, "ahmad", None).await;
        let server = target(&db, "LINUX-SRV-01", &options).await;
        bind(
            &db,
            ahmad,
            server,
            NewBinding::local("deploy", TargetAccountAuthMethod::TargetCredential),
        )
        .await;
        assert!(matches!(
            access(&db, ahmad, server, &options).await,
            Err(BindingError::NoActiveBinding)
        ));
        let keyed = ssh(SSHTargetAuth::PublicKey(SshTargetPublicKeyAuth::default()));
        let keyed_id = target(&db, "LINUX-SRV-02", &keyed).await;
        bind(
            &db,
            ahmad,
            keyed_id,
            NewBinding::local("deploy", TargetAccountAuthMethod::TargetCredential),
        )
        .await;
        assert_eq!(ids(&access_of(&db, ahmad, keyed_id, &keyed).await).len(), 1);
    }
}
