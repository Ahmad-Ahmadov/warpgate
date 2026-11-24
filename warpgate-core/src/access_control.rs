//! Access Control: the one place that decides whether a user may connect to a target, and
//! as which remote account.
//!
//! The relationship is user → target → account. A user may connect only through an
//! assignment that is in force:
//!
//! * a **direct assignment** (`access_assignments`), made by an administrator, or carried
//!   over by the m00098 migration; or
//! * an **access group's grant** (`access_group_grants`) to a group (a role) the user is an
//!   active member of, unless the user was excluded from it (`access_group_exclusions`).
//!
//! On RDP, SSH, MySQL and PostgreSQL an assignment names an account from the target's
//! inventory (`target_accounts`), and the connection signs in as that account and nothing
//! else; on HTTP, Kubernetes and VNC it names none, and is the entitlement to the target.
//! Holding a role, or a target having a credential, grants nothing by itself.
//!
//! Every connection path asks here: the coarse check (may this user reach this target at
//! all) through [`crate::ConfigProvider`], which every protocol's authorization goes through,
//! and the account choice through [`resolve_connection`], fresh, when the connection is
//! made. A client can only ever name an account: by id or by name, looked up among the
//! user's own usable ones on that target, and refused (and audited) otherwise. Second
//! factors, approvals and session policies apply on top, unchanged.
//!
//! A ticket is the one administrator-issued exception: it admits its user to its target
//! without an assignment. On a target with accounts, such a connection uses the user's own
//! assigned account when they have one, and the target's primary account otherwise.

use std::collections::{HashMap, HashSet};

use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder};
use time::OffsetDateTime;
use tracing::{info, warn};
use uuid::Uuid;
use warpgate_common::audit::AuditEvent;
use warpgate_common::{Protocol, Target, TargetAccountCredential, TargetOptions, WarpgateError};
pub use warpgate_db_entities::AccessAssignment::AssignmentOrigin;
use warpgate_db_entities::Target::TargetKind;
pub use warpgate_db_entities::TargetAccount::{
    DirectoryUsernameFormat, TargetAccountAuthMethod, TargetAccountKind,
};
use warpgate_db_entities::{
    AccessAssignment, AccessGroupExclusion, AccessGroupGrant, Role, TargetAccount, TargetSession,
    User, UserRoleAssignment, UserSession,
};

use crate::{AdmittedTarget, Services, SessionsFilter};

/// Whether a protocol signs in to the target as a remote account.
pub const fn uses_accounts(protocol: Protocol) -> bool {
    matches!(
        protocol,
        Protocol::Rdp | Protocol::Ssh | Protocol::MySql | Protocol::Postgres
    )
}

/// The protocol of a stored target.
pub const fn protocol_of(kind: TargetKind) -> Protocol {
    match kind {
        TargetKind::Http => Protocol::Http,
        TargetKind::Kubernetes => Protocol::Kubernetes,
        TargetKind::MySql => Protocol::MySql,
        TargetKind::Ssh => Protocol::Ssh,
        TargetKind::Postgres => Protocol::Postgres,
        TargetKind::Vnc => Protocol::Vnc,
        TargetKind::Rdp => Protocol::Rdp,
    }
}

/// Whether an account can sign in to a target of `protocol` as it is configured; why not
/// otherwise. Checked when an account is saved, and again whenever it is used.
pub fn check_account(
    protocol: Protocol,
    account: &TargetAccount::Model,
) -> Result<(), &'static str> {
    use TargetAccountAuthMethod as M;
    use TargetAccountKind as K;
    if !uses_accounts(protocol) {
        return Err("This protocol has no remote accounts.");
    }
    let name_needed = match (protocol, account.kind) {
        (_, K::Directory) => false,
        (Protocol::Ssh, K::Local) => false,
        _ => true,
    };
    if name_needed && account.name.trim().is_empty() {
        return Err("Enter the account's name.");
    }
    if account.kind != K::Directory && account.name.chars().any(char::is_control) {
        return Err("The account name contains control characters.");
    }
    match (protocol, account.kind, account.auth_method) {
        (Protocol::Rdp, K::Directory, M::DirectoryPassword)
        | (Protocol::Rdp, K::Local | K::Domain, M::TypedPassword) => Ok(()),
        (Protocol::Rdp, K::Directory, _) => Err(
            "On RDP, a linked directory account signs in with the user's own directory password, which Warpgate never stores.",
        ),
        (
            Protocol::Rdp | Protocol::Ssh | Protocol::MySql | Protocol::Postgres,
            _,
            M::StoredCredential,
        ) => {
            let credential = account
                .credential()
                .map_err(|_| "The account's stored credential cannot be read.")?
                .ok_or("Enter the account's credential.")?;
            if !credential.supports(protocol) {
                return Err(match protocol {
                    Protocol::Rdp => "RDP accounts sign in with a password.",
                    _ => "Database accounts sign in with a password or a cloud role.",
                });
            }
            if account.kind == K::Directory {
                if protocol != Protocol::Ssh {
                    return Err("A linked directory account can only be used over RDP and SSH.");
                }
                if credential.password().is_some() {
                    return Err(
                        "A linked directory account is each user's own: it cannot share one stored password. Use Warpgate's SSH keys or a certificate the server trusts for directory users.",
                    );
                }
            }
            Ok(())
        }
        (Protocol::Rdp, _, M::DirectoryPassword) => {
            Err("Only a linked directory account signs in with the user's directory password.")
        }
        (Protocol::Ssh | Protocol::MySql | Protocol::Postgres, _, _) => Err(
            "This protocol cannot take a password typed when connecting: give the account a stored credential.",
        ),
        _ => Err("This account cannot sign in to this target."),
    }
}

/// Where an assignment comes from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AssignmentSource {
    /// A direct assignment.
    Direct {
        assignment_id: Uuid,
        origin: AssignmentOrigin,
    },
    /// An access group's grant, through the user's membership.
    Group {
        group_id: Uuid,
        group_name: String,
        grant_id: Uuid,
    },
}

impl AssignmentSource {
    /// As the audit log and the admin UI name it.
    pub fn describe(&self) -> String {
        match self {
            Self::Direct { origin, .. } => match origin {
                AssignmentOrigin::Direct => "direct".to_owned(),
                AssignmentOrigin::Migrated => "direct (migrated)".to_owned(),
                AssignmentOrigin::Review => "direct (migration review)".to_owned(),
            },
            Self::Group { group_name, .. } => format!("group {group_name}"),
        }
    }
}

/// One way a user may reach a target: an assignment, and whether it can be used now.
#[derive(Clone, Debug)]
pub struct EffectiveAssignment {
    pub user_id: Uuid,
    pub target_id: Uuid,
    pub account_id: Option<Uuid>,
    /// The account it names, as it is now; `None` when it names none (or it is gone).
    pub account: Option<TargetAccount::Model>,
    pub source: AssignmentSource,
    /// Direct: the assignment's switch. Group-derived: always on.
    pub enabled: bool,
    /// Direct: the assignment's. Group-derived: the membership's.
    pub expires_at: Option<OffsetDateTime>,
    /// Group-derived, and the user was excluded from it: the exclusion.
    pub exclusion_id: Option<Uuid>,
    /// Why it cannot be used now; `None` when it can.
    pub problem: Option<&'static str>,
}

impl EffectiveAssignment {
    pub const fn usable(&self) -> bool {
        self.problem.is_none()
    }
}

/// Which assignments to work out.
#[derive(Clone, Copy, Debug, Default)]
pub struct AssignmentFilter {
    pub user_id: Option<Uuid>,
    pub target_id: Option<Uuid>,
    /// Only those this group grants.
    pub group_id: Option<Uuid>,
    /// Only direct assignments.
    pub direct_only: bool,
}

struct Candidate {
    user_id: Uuid,
    target_id: Uuid,
    account_id: Option<Uuid>,
    source: AssignmentSource,
    enabled: bool,
    expires_at: Option<OffsetDateTime>,
    /// Direct directory assignments: the user's LDAP link when it was made.
    link: Option<(Option<Uuid>, Option<Uuid>)>,
    exclusion_id: Option<Uuid>,
}

/// Every assignment `filter` selects, direct and group-derived (excluded ones included,
/// marked), each with why it cannot be used now, if it cannot. The one place the rules are
/// applied: authorization, the admin API and the session sweep all read it.
pub async fn effective_assignments(
    db: &DatabaseConnection,
    filter: AssignmentFilter,
    now: OffsetDateTime,
) -> Result<Vec<EffectiveAssignment>, sea_orm::DbErr> {
    let mut candidates: Vec<Candidate> = vec![];

    if filter.group_id.is_none() {
        let mut query = AccessAssignment::Entity::find();
        if let Some(user_id) = filter.user_id {
            query = query.filter(AccessAssignment::Column::UserId.eq(user_id));
        }
        if let Some(target_id) = filter.target_id {
            query = query.filter(AccessAssignment::Column::TargetId.eq(target_id));
        }
        for assignment in query
            .order_by_asc(AccessAssignment::Column::CreatedAt)
            .order_by_asc(AccessAssignment::Column::Id)
            .all(db)
            .await?
        {
            candidates.push(Candidate {
                user_id: assignment.user_id,
                target_id: assignment.target_id,
                account_id: assignment.target_account_id,
                source: AssignmentSource::Direct {
                    assignment_id: assignment.id,
                    origin: assignment.origin,
                },
                enabled: assignment.enabled,
                expires_at: assignment.expires_at,
                link: Some((assignment.ldap_server_id, assignment.ldap_object_uuid)),
                exclusion_id: None,
            });
        }
    }

    if !filter.direct_only {
        let mut grants = AccessGroupGrant::Entity::find();
        if let Some(target_id) = filter.target_id {
            grants = grants.filter(AccessGroupGrant::Column::TargetId.eq(target_id));
        }
        if let Some(group_id) = filter.group_id {
            grants = grants.filter(AccessGroupGrant::Column::RoleId.eq(group_id));
        }
        let grants = grants
            .order_by_asc(AccessGroupGrant::Column::CreatedAt)
            .order_by_asc(AccessGroupGrant::Column::Id)
            .all(db)
            .await?;
        if !grants.is_empty() {
            let group_ids: HashSet<Uuid> = grants.iter().map(|grant| grant.role_id).collect();
            let mut memberships = UserRoleAssignment::Entity::find_active()
                .filter(UserRoleAssignment::Column::RoleId.is_in(group_ids.iter().copied()));
            if let Some(user_id) = filter.user_id {
                memberships = memberships.filter(UserRoleAssignment::Column::UserId.eq(user_id));
            }
            let memberships = memberships.all(db).await?;
            let names: HashMap<Uuid, String> = Role::Entity::find()
                .filter(Role::Column::Id.is_in(group_ids.iter().copied()))
                .all(db)
                .await?
                .into_iter()
                .map(|role| (role.id, role.name))
                .collect();
            let mut exclusions = AccessGroupExclusion::Entity::find()
                .filter(AccessGroupExclusion::Column::RoleId.is_in(group_ids.iter().copied()));
            if let Some(user_id) = filter.user_id {
                exclusions = exclusions.filter(AccessGroupExclusion::Column::UserId.eq(user_id));
            }
            if let Some(target_id) = filter.target_id {
                exclusions =
                    exclusions.filter(AccessGroupExclusion::Column::TargetId.eq(target_id));
            }
            let exclusions: HashMap<(Uuid, Uuid, Uuid, String), Uuid> = exclusions
                .all(db)
                .await?
                .into_iter()
                .map(|e| ((e.role_id, e.user_id, e.target_id, e.account_key), e.id))
                .collect();
            for grant in &grants {
                for membership in memberships.iter().filter(|m| m.role_id == grant.role_id) {
                    let exclusion_id = exclusions
                        .get(&(
                            grant.role_id,
                            membership.user_id,
                            grant.target_id,
                            grant.account_key.clone(),
                        ))
                        .copied();
                    candidates.push(Candidate {
                        user_id: membership.user_id,
                        target_id: grant.target_id,
                        account_id: grant.target_account_id,
                        source: AssignmentSource::Group {
                            group_id: grant.role_id,
                            group_name: names.get(&grant.role_id).cloned().unwrap_or_default(),
                            grant_id: grant.id,
                        },
                        enabled: true,
                        expires_at: membership.expires_at,
                        link: None,
                        exclusion_id,
                    });
                }
            }
        }
    }

    if candidates.is_empty() {
        return Ok(vec![]);
    }

    let target_ids: HashSet<Uuid> = candidates.iter().map(|c| c.target_id).collect();
    let protocols: HashMap<Uuid, Protocol> = warpgate_db_entities::Target::Entity::find()
        .filter(warpgate_db_entities::Target::Column::Id.is_in(target_ids.iter().copied()))
        .all(db)
        .await?
        .into_iter()
        .map(|target| (target.id, protocol_of(target.kind)))
        .collect();
    let account_ids: HashSet<Uuid> = candidates.iter().filter_map(|c| c.account_id).collect();
    let accounts: HashMap<Uuid, TargetAccount::Model> = if account_ids.is_empty() {
        HashMap::new()
    } else {
        TargetAccount::Entity::find()
            .filter(TargetAccount::Column::Id.is_in(account_ids.iter().copied()))
            .all(db)
            .await?
            .into_iter()
            .map(|account| (account.id, account))
            .collect()
    };
    let user_ids: HashSet<Uuid> = candidates.iter().map(|c| c.user_id).collect();
    let links: HashMap<Uuid, (Option<Uuid>, Option<Uuid>)> = User::Entity::find()
        .filter(User::Column::Id.is_in(user_ids.iter().copied()))
        .all(db)
        .await?
        .into_iter()
        .map(|user| (user.id, (user.ldap_server_id, user.ldap_object_uuid)))
        .collect();

    Ok(candidates
        .into_iter()
        .filter(|c| protocols.contains_key(&c.target_id))
        .map(|candidate| {
            let account = candidate
                .account_id
                .and_then(|id| accounts.get(&id).cloned());
            let problem = problem_of(
                &candidate,
                account.as_ref(),
                protocols.get(&candidate.target_id).copied(),
                links.get(&candidate.user_id).copied(),
                now,
            );
            EffectiveAssignment {
                user_id: candidate.user_id,
                target_id: candidate.target_id,
                account_id: candidate.account_id,
                account,
                source: candidate.source,
                enabled: candidate.enabled,
                expires_at: candidate.expires_at,
                exclusion_id: candidate.exclusion_id,
                problem,
            }
        })
        .collect())
}

fn problem_of(
    candidate: &Candidate,
    account: Option<&TargetAccount::Model>,
    protocol: Option<Protocol>,
    link: Option<(Option<Uuid>, Option<Uuid>)>,
    now: OffsetDateTime,
) -> Option<&'static str> {
    let Some(protocol) = protocol else {
        return Some("the target no longer exists");
    };
    if candidate.exclusion_id.is_some() {
        return Some("excluded for this user");
    }
    if !candidate.enabled {
        return Some("disabled");
    }
    if candidate.expires_at.is_some_and(|expires| expires <= now) {
        return Some("expired");
    }
    if !uses_accounts(protocol) {
        return candidate
            .account_id
            .map(|_| "this target's protocol has no remote accounts");
    }
    let Some(account_id) = candidate.account_id else {
        return Some("it names no account, and this target needs one");
    };
    let Some(account) = account else {
        return Some("the account was deleted");
    };
    if account.id != account_id || account.target_id != candidate.target_id {
        return Some("the account belongs to another target");
    }
    if !account.enabled {
        return Some("the account is disabled");
    }
    if check_account(protocol, account).is_err() {
        return Some("the account cannot sign in to this target as configured");
    }
    if account.kind == TargetAccountKind::Directory {
        let Some((Some(server), Some(entry))) = link else {
            return Some("the user is not linked to a directory account");
        };
        if let Some(snapshot) = candidate.link
            && snapshot != (Some(server), Some(entry))
        {
            return Some("the user's directory link changed since it was assigned");
        }
    }
    None
}

/// The usable assignments of `user_id` on `target_id`.
pub async fn usable_assignments(
    db: &DatabaseConnection,
    user_id: Uuid,
    target_id: Uuid,
) -> Result<Vec<EffectiveAssignment>, sea_orm::DbErr> {
    Ok(effective_assignments(
        db,
        AssignmentFilter {
            user_id: Some(user_id),
            target_id: Some(target_id),
            ..Default::default()
        },
        OffsetDateTime::now_utc(),
    )
    .await?
    .into_iter()
    .filter(EffectiveAssignment::usable)
    .collect())
}

/// Whether `user_id` may reach `target_id` at all: they hold a usable assignment there.
pub async fn has_access(
    db: &DatabaseConnection,
    user_id: Uuid,
    target_id: Uuid,
) -> Result<bool, sea_orm::DbErr> {
    Ok(!usable_assignments(db, user_id, target_id).await?.is_empty())
}

/// Every target `user_id` may reach.
pub async fn authorized_target_ids(
    db: &DatabaseConnection,
    user_id: Uuid,
) -> Result<HashSet<Uuid>, sea_orm::DbErr> {
    Ok(effective_assignments(
        db,
        AssignmentFilter {
            user_id: Some(user_id),
            ..Default::default()
        },
        OffsetDateTime::now_utc(),
    )
    .await?
    .into_iter()
    .filter(EffectiveAssignment::usable)
    .map(|assignment| assignment.target_id)
    .collect())
}

/// The account a client asks to connect as.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AccountRequest {
    /// By the target account's id (browser clients).
    Id(Uuid),
    /// By name, as the user typed it (native SSH `user:target:account`, database clients).
    Name(String),
}

/// Why a user cannot connect to a target as an account.
#[derive(Debug, thiserror::Error)]
pub enum AccessError {
    /// No usable assignment at all.
    #[error("no usable access assignment on the target")]
    NoAccess,
    /// Several accounts are assigned, and the request named none.
    #[error("the account to sign in as was not chosen")]
    NotChosen(Vec<String>),
    /// The request named an account that is not one of the user's usable ones there.
    #[error("the account is not assigned to the user on this target")]
    NotAllowed,
    #[error("the user is not linked to a directory account")]
    NotLinked,
    /// Looking the directory account up failed.
    #[error("the directory account could not be looked up: {0}")]
    Directory(String),
    #[error("{0}")]
    Unsupported(&'static str),
    #[error(transparent)]
    Database(#[from] sea_orm::DbErr),
}

impl AccessError {
    /// What to tell the user. Nothing here says anything about anyone else's accounts.
    pub fn user_message(&self, target_name: &str) -> String {
        match self {
            Self::NoAccess => format!(
                "You have no access assignment on {target_name}. Ask an administrator to assign you an account there."
            ),
            Self::NotChosen(names) => format!(
                "Several accounts are assigned to you on {target_name}: {}. Choose one; for SSH and database clients, append it to the target name, as in user:{target_name}:ACCOUNT.",
                names.join(", ")
            ),
            Self::NotAllowed => format!("You may not sign in to {target_name} as that account."),
            Self::NotLinked => {
                "Your Warpgate account is not linked to a directory account. Ask an administrator."
                    .to_owned()
            }
            Self::Unsupported(reason) => (*reason).to_owned(),
            Self::Directory(_) | Self::Database(_) => {
                "The account could not be looked up right now. Try again later.".to_owned()
            }
        }
    }

    /// Whether the user can fix it by choosing differently.
    pub const fn may_retry(&self) -> bool {
        matches!(self, Self::NotChosen(_) | Self::NotAllowed)
    }
}

impl From<AccessError> for WarpgateError {
    fn from(error: AccessError) -> Self {
        match error {
            AccessError::Database(error) => error.into(),
            error => Self::InvalidRequest(error.to_string()),
        }
    }
}

/// The user a connection is for.
#[derive(Clone, Copy, Debug)]
pub struct ConnectingUser<'a> {
    pub id: Uuid,
    pub username: &'a str,
}

/// An account a connection may sign in as, and the assignments that allow it.
#[derive(Clone, Debug)]
pub struct AuthorizedAccount {
    pub account: TargetAccount::Model,
    pub sources: Vec<AssignmentSource>,
    /// A ticket admitted the connection, and the user holds no assignment there.
    pub via_ticket: bool,
}

impl AuthorizedAccount {
    /// The sources, for the connection's log line.
    pub fn describe_sources(&self) -> String {
        if self.via_ticket {
            return "ticket".to_owned();
        }
        self.sources
            .iter()
            .map(AssignmentSource::describe)
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// What a connection to a target is authorized as.
#[derive(Clone, Debug)]
pub enum ConnectionAccess {
    /// A protocol with no remote account: the user's entitlement to the target.
    Accountless,
    Account(AuthorizedAccount),
}

/// The accounts `user` may sign in to `target` as now, one entry per account (with every
/// assignment allowing it), in the order assigned. A ticket-admitted connection by a user with
/// no assignment there gets the target's primary account.
pub async fn connection_accounts(
    db: &DatabaseConnection,
    user: ConnectingUser<'_>,
    target_id: Uuid,
    via_ticket: bool,
) -> Result<Vec<AuthorizedAccount>, AccessError> {
    let mut accounts: Vec<AuthorizedAccount> = vec![];
    for assignment in usable_assignments(db, user.id, target_id).await? {
        let Some(account) = assignment.account else {
            continue;
        };
        match accounts
            .iter_mut()
            .find(|known| known.account.id == account.id)
        {
            Some(known) => known.sources.push(assignment.source),
            None => accounts.push(AuthorizedAccount {
                account,
                sources: vec![assignment.source],
                via_ticket: false,
            }),
        }
    }
    if accounts.is_empty()
        && via_ticket
        && let Some(primary) = primary_account(db, target_id).await?
    {
        info!(
            user = %user.username,
            %target_id,
            account = %primary.display_name(),
            "A ticket admits the user without an assignment: signing in as the target's primary account"
        );
        accounts.push(AuthorizedAccount {
            account: primary,
            sources: vec![],
            via_ticket: true,
        });
    }
    Ok(accounts)
}

/// The target's primary account, if it has a usable one: for jump-host hops, ticket
/// connections without an assignment, and the legacy API.
pub async fn primary_account(
    db: &DatabaseConnection,
    target_id: Uuid,
) -> Result<Option<TargetAccount::Model>, sea_orm::DbErr> {
    let Some(target) = warpgate_db_entities::Target::Entity::find_by_id(target_id)
        .one(db)
        .await?
    else {
        return Ok(None);
    };
    Ok(TargetAccount::Entity::find()
        .filter(TargetAccount::Column::TargetId.eq(target_id))
        .filter(TargetAccount::Column::IsPrimary.eq(true))
        .one(db)
        .await?
        .filter(|account| {
            account.enabled && check_account(protocol_of(target.kind), account).is_ok()
        }))
}

/// Whether a name a client sent names `account` (not counting a directory account, whose
/// name is the user's own and has to be looked up).
fn names_account(account: &TargetAccount::Model, name: &str) -> bool {
    let name = name.trim();
    account.id.to_string() == name
        || (!account.name.is_empty() && account.name.trim().eq_ignore_ascii_case(name))
}

/// Pick the account a connection signs in as, among `accounts` (the user's own). A request
/// naming any other is refused; with none, the only one is it, and several are a refusal.
pub async fn choose_account(
    db: &DatabaseConnection,
    user: ConnectingUser<'_>,
    accounts: Vec<AuthorizedAccount>,
    request: Option<&AccountRequest>,
) -> Result<AuthorizedAccount, AccessError> {
    match request {
        Some(AccountRequest::Id(id)) => accounts
            .into_iter()
            .find(|candidate| candidate.account.id == *id)
            .ok_or(AccessError::NotAllowed),
        Some(AccountRequest::Name(name)) => {
            let mut found = accounts
                .iter()
                .position(|candidate| names_account(&candidate.account, name));
            if found.is_none() {
                // The user's own directory account, by the name the target knows it by.
                for (index, candidate) in accounts.iter().enumerate() {
                    if candidate.account.kind != TargetAccountKind::Directory {
                        continue;
                    }
                    let resolved = remote_username(db, user, &candidate.account).await?;
                    if resolved.eq_ignore_ascii_case(name.trim()) {
                        found = Some(index);
                        break;
                    }
                }
            }
            match found {
                Some(index) => accounts
                    .into_iter()
                    .nth(index)
                    .ok_or(AccessError::NotAllowed),
                None => Err(AccessError::NotAllowed),
            }
        }
        None => match accounts.len() {
            0 => Err(AccessError::NoAccess),
            1 => accounts.into_iter().next().ok_or(AccessError::NoAccess),
            _ => Err(AccessError::NotChosen(
                accounts
                    .iter()
                    .map(|candidate| candidate.account.display_name())
                    .collect(),
            )),
        },
    }
}

/// Decide what a connection by `user` to `target` signs in as: the single place where both
/// browser and native clients of every protocol get it. Refusals are audited.
pub async fn resolve_connection(
    db: &DatabaseConnection,
    user: ConnectingUser<'_>,
    target: &Target,
    request: Option<&AccountRequest>,
    via_ticket: bool,
) -> Result<ConnectionAccess, AccessError> {
    let protocol = target.options.protocol();
    let result = if uses_accounts(protocol) {
        match connection_accounts(db, user, target.id, via_ticket).await {
            Ok(accounts) if accounts.is_empty() => Err(AccessError::NoAccess),
            Ok(accounts) => choose_account(db, user, accounts, request)
                .await
                .map(ConnectionAccess::Account),
            Err(error) => Err(error),
        }
    } else if via_ticket || has_access(db, user.id, target.id).await? {
        Ok(ConnectionAccess::Accountless)
    } else {
        Err(AccessError::NoAccess)
    };
    if let Err(error) = &result
        && !matches!(error, AccessError::Database(_) | AccessError::NotChosen(_))
    {
        refuse(user, target, request, error);
    }
    result
}

/// The name an account signs in to an SSH or database target as: its own, the user's own
/// directory account as the account's format names it, or the user's Warpgate username.
pub async fn remote_username(
    db: &DatabaseConnection,
    user: ConnectingUser<'_>,
    account: &TargetAccount::Model,
) -> Result<String, AccessError> {
    match account.kind {
        TargetAccountKind::Directory => crate::rdp_account::directory_account_name(
            db,
            user.id,
            account
                .username_format
                .unwrap_or(DirectoryUsernameFormat::AccountAtDomain),
        )
        .await
        .map_err(|error| match error {
            crate::rdp_account::DomainAccountError::NotLinked => AccessError::NotLinked,
            error => AccessError::Directory(error.to_string()),
        }),
        TargetAccountKind::Local | TargetAccountKind::Domain if account.name.trim().is_empty() => {
            Ok(user.username.to_owned())
        }
        TargetAccountKind::Local | TargetAccountKind::Domain => Ok(account.name.trim().to_owned()),
    }
}

/// Fill in a target's options with the account a connection signs in as (SSH and database
/// targets; RDP takes its account from `rdp_account`).
pub fn apply_account(
    options: &mut TargetOptions,
    username: &str,
    account: &TargetAccount::Model,
) -> Result<(), AccessError> {
    let credential: Option<TargetAccountCredential> = account
        .credential()
        .map_err(|_| AccessError::Unsupported("The account's stored credential cannot be read."))?;
    let credential = credential.ok_or(AccessError::Unsupported(
        "The account has no stored credential.",
    ))?;
    match options {
        TargetOptions::Ssh(ssh) => {
            ssh.username = username.to_owned();
            ssh.auth = credential.to_ssh_auth();
        }
        TargetOptions::MySql(mysql) => {
            mysql.username = username.to_owned();
            mysql.auth = credential
                .to_database_auth()
                .ok_or(AccessError::Unsupported(
                    "Database accounts sign in with a password or a cloud role.",
                ))?;
        }
        TargetOptions::Postgres(postgres) => {
            postgres.username = username.to_owned();
            postgres.auth = credential
                .to_database_auth()
                .ok_or(AccessError::Unsupported(
                    "Database accounts sign in with a password or a cloud role.",
                ))?;
        }
        TargetOptions::Rdp(_)
        | TargetOptions::Http(_)
        | TargetOptions::Kubernetes(_)
        | TargetOptions::Vnc(_) => {}
    }
    Ok(())
}

/// For an SSH or database connection, once admitted: decide the account (fresh, after any
/// approval), and fill it into the connection's options. The protocol then dials exactly
/// that account.
pub async fn admit_account<O: warpgate_common::TargetOptionsVariant>(
    db: &DatabaseConnection,
    admitted: AdmittedTarget<O>,
) -> Result<(AdmittedTarget<O>, ConnectionAccess), WarpgateError> {
    let user_info = admitted.user_info().clone();
    let target = admitted.target().clone();
    let user = ConnectingUser {
        id: user_info.id,
        username: &user_info.username,
    };
    let access = resolve_connection(
        db,
        user,
        &target,
        admitted.account_request(),
        admitted.ticket_id().is_some(),
    )
    .await
    .map_err(|error| match error {
        AccessError::Database(error) => error.into(),
        error => WarpgateError::InvalidRequest(error.user_message(&target.name)),
    })?;
    let ConnectionAccess::Account(authorized) = access.clone() else {
        return Ok((admitted, access));
    };
    let username = remote_username(db, user, &authorized.account)
        .await
        .map_err(|error| WarpgateError::InvalidRequest(error.user_message(&target.name)))?;
    let account = authorized.account;
    // Checked on a copy first: a connection never goes ahead without its account filled in.
    apply_account(&mut target.options.clone(), &username, &account)
        .map_err(|error| WarpgateError::InvalidRequest(error.user_message(&target.name)))?;
    info!(
        user = %user.username,
        target = %target.name,
        target_account = %username,
        account_id = %account.id,
        source = %if authorized.via_ticket {
            "ticket".to_owned()
        } else {
            authorized
                .sources
                .iter()
                .map(AssignmentSource::describe)
                .collect::<Vec<_>>()
                .join(", ")
        },
        "Signing in to the target as the account Access Control authorized"
    );
    let admitted = admitted.with_target_options(|options| {
        if let Err(error) = apply_account(options, &username, &account) {
            warn!(%error, "Could not apply the authorized account");
        }
    })?;
    Ok((admitted, access))
}

/// Audit a refused connection: no usable assignment, or an account that was not the user's.
pub fn refuse(
    user: ConnectingUser<'_>,
    target: &Target,
    request: Option<&AccountRequest>,
    error: &AccessError,
) {
    AuditEvent::AccessAssignmentRefused {
        user_id: user.id,
        username: user.username.to_owned(),
        target_id: target.id,
        target_name: target.name.clone(),
        requested_account: request.map(|request| match request {
            AccountRequest::Id(id) => id.to_string(),
            AccountRequest::Name(name) => name.clone(),
        }),
        reason: error.to_string(),
    }
    .emit();
}

/// End the user's live sessions on the target, once an assignment they may be using is
/// revoked, disabled or changed: a session must not outlive the decision that allowed it.
pub async fn close_sessions_on_target(
    services: &Services,
    user_id: Uuid,
    target_id: Uuid,
) -> Result<(), WarpgateError> {
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

/// Split what a client sent as a target into the target and, optionally, an account:
/// `TARGET:ACCOUNT` or `TARGET#ACCOUNT`, at the last separator. The caller first looks the
/// whole string up as a target name, so a target whose name has a separator still works.
pub fn split_account_selector(selector: &str) -> Option<(&str, &str)> {
    let at = selector.rfind(['#', ':'])?;
    let (target, account) = (&selector[..at], &selector[at + 1..]);
    (!target.is_empty() && !account.trim().is_empty()).then_some((target, account))
}

#[cfg(all(test, feature = "sqlite"))]
mod tests;
