//! Access policies: the one place that decides *when* a user may start a connection, and
//! whether doing so needs an approval. Every protocol asks it through the common admission
//! path (`WarpgateServerHandle::start_target_session`, and the approval gate behind it), after
//! Access Control has said the user may reach the target at all. A policy only ever restricts:
//! it never grants access, and nothing here is ever decided by the browser.
//!
//! # What applies to a connection
//!
//! Every enabled policy whose scope matches the connection: a policy names a user, an access
//! group, a target and/or an account, and applies when each one it names matches (see
//! `warpgate_db_entities::AccessPolicy`). A direct assignment's own schedule is such a policy,
//! scoped to that user, target and account. Where the account is not yet known (a user with
//! several accounts who has not said which), a policy on any of their accounts applies, which
//! can only make the result stricter.
//!
//! # Precedence: security first
//!
//! Each applicable policy reads its own rules at the moment of the connection (weekly windows
//! in its timezone, the most restrictive window winning, `outside` when no window contains the
//! moment) and says `Allow`, `RequireApproval` or `Deny`. The results combine by restriction,
//! never by specificity or order, so a policy that allows can never undo one that restricts:
//!
//! 1. **Any `Deny` denies.** Nobody can approve it.
//! 2. **Otherwise any `RequireApproval` requires approval.** If several do, the request is
//!    asked with the *shortest* request expiry and the *shortest* approval validity among
//!    them, and every one that names approvers must be satisfied by whoever approves (an
//!    approver the policies do not all accept cannot approve it).
//! 3. **Otherwise `Allow`.** No applicable policy at all is also `Allow`: a connection that no
//!    policy covers behaves exactly as it did before policies existed.
//!
//! A policy whose rules cannot be read counts as `Deny`. Ties are ordered by policy name and
//! id, so the policy a message names is deterministic.
//!
//! # What it does not do
//!
//! The result decides whether a connection may *start*. A session already open is not ended
//! when a window closes; ending it is the job of access being revoked or expiring, which
//! Access Control already does.

use std::collections::HashSet;

use chrono::{DateTime, Datelike, Timelike, Utc};
use chrono_tz::Tz;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Condition, DatabaseConnection, EntityTrait, QueryFilter,
    QueryOrder, Set,
};
use time::OffsetDateTime;
use uuid::Uuid;
use warpgate_common::{
    AccessRules, MAX_APPROVAL_SECONDS, RuleAction, RuleApproval, RuleWeekday, WarpgateError,
};
use warpgate_db_entities::{
    AccessApprovalContext, AccessAssignment, AccessPolicy, Role, SessionApprovalRequest, Target,
    TargetAccount, User, UserRoleAssignment,
};

use crate::access_control::{
    AccessError, AccountRequest, AuthorizedAccount, ConnectingUser, connection_accounts,
    names_account, uses_accounts,
};
use crate::config_providers::TargetAuthorization;

#[cfg(all(test, feature = "sqlite"))]
mod tests;

// ---------------------------------------------------------------------------------------
// Reading one set of rules
// ---------------------------------------------------------------------------------------

/// The timezone an IANA name stands for.
pub fn parse_timezone(name: &str) -> Option<Tz> {
    name.trim().parse::<Tz>().ok()
}

/// The weekday and minute since midnight at `at`, as the clocks of `tz` read it. Starts from
/// the UTC instant, so a daylight-saving change is the timezone database's to apply: there is
/// no local time that is ambiguous or missing in this direction.
fn local_clock(tz: Tz, at: OffsetDateTime) -> Option<(RuleWeekday, u16)> {
    let utc = DateTime::<Utc>::from_timestamp(at.unix_timestamp(), 0)?;
    let local = utc.with_timezone(&tz);
    let day =
        RuleWeekday::from_index(usize::try_from(local.weekday().num_days_from_monday()).ok()?);
    let minute = u16::try_from(local.hour() * 60 + local.minute()).ok()?;
    Some((day, minute))
}

/// What one set of rules says at one moment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evaluation {
    pub action: RuleAction,
    /// The moment as the rules' own clocks read it, `Tue 20:15 Europe/Berlin`.
    pub local_time: String,
}

/// Read `rules` at `at`: the most restrictive window that contains the moment, or `outside`.
/// Fails (and the caller denies) when the rules' timezone is not one.
pub fn evaluate_rules(rules: &AccessRules, at: OffsetDateTime) -> Result<Evaluation, String> {
    let tz = parse_timezone(&rules.timezone)
        .ok_or_else(|| format!("the timezone \"{}\" is not known", rules.timezone))?;
    let (day, minute) =
        local_clock(tz, at).ok_or_else(|| "the time could not be converted".to_owned())?;
    let mut action: Option<RuleAction> = None;
    for window in &rules.windows {
        if window.contains(day, minute) {
            action = Some(action.map_or(window.action, |known| known.max(window.action)));
        }
    }
    Ok(Evaluation {
        action: action.unwrap_or(rules.outside),
        local_time: format!(
            "{} {} {}",
            day.name(),
            warpgate_common::format_clock(minute),
            rules.timezone.trim()
        ),
    })
}

/// Whether `rules` can be saved; the message says what to fix.
pub fn validate_rules(rules: &AccessRules) -> Result<(), String> {
    if parse_timezone(&rules.timezone).is_none() {
        return Err(format!(
            "\"{}\" is not a timezone. Use an IANA name such as Europe/Berlin or UTC.",
            rules.timezone
        ));
    }
    if rules.windows.len() > 64 {
        return Err("Use at most 64 time windows.".to_owned());
    }
    for (index, window) in rules.windows.iter().enumerate() {
        let number = index + 1;
        if window.days.is_empty() {
            return Err(format!("Window {number}: choose at least one day."));
        }
        if window.bounds().is_none() {
            return Err(format!(
                "Window {number}: times are HH:MM (24-hour), and the start and end must differ."
            ));
        }
    }
    for (what, seconds) in [
        ("request expiry", rules.approval.request_expiry_seconds),
        ("approval validity", rules.approval.valid_for_seconds),
    ] {
        if let Some(seconds) = seconds
            && !(1..=MAX_APPROVAL_SECONDS).contains(&seconds)
        {
            return Err(format!(
                "The {what} must be between one second and {} days.",
                MAX_APPROVAL_SECONDS / 86400
            ));
        }
    }
    if rules.approval.approver_user_ids.len() > 100 || rules.approval.approver_role_ids.len() > 100
    {
        return Err("Name at most 100 approvers.".to_owned());
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------
// Combining policies
// ---------------------------------------------------------------------------------------

/// One applicable policy, read at the moment of the connection.
#[derive(Debug, Clone)]
pub struct Applied {
    pub policy_id: Option<Uuid>,
    pub name: String,
    pub action: RuleAction,
    pub rules: AccessRules,
    pub local_time: String,
    /// Why its rules could not be read, when they could not (and it denies).
    pub problem: Option<String>,
}

/// Why a connection is refused. Written for the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRefusal {
    pub policy_name: String,
    pub reason: String,
}

/// What a connection must be given before it may start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalRequirement {
    /// The first requiring policy, by name; the others are in `policy_name`.
    pub policy_id: Option<Uuid>,
    pub policy_name: String,
    /// In words an approver reads.
    pub reason: String,
    pub request_expiry_seconds: Option<u32>,
    pub valid_for_seconds: Option<u32>,
    /// One entry per requiring policy that names approvers; an approver must satisfy all.
    pub approvers: Vec<RuleApproval>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    Allow,
    RequireApproval(ApprovalRequirement),
    Deny(PolicyRefusal),
}

/// The precedence in the module documentation, as a pure function.
pub fn decide(mut applied: Vec<Applied>) -> PolicyDecision {
    applied.sort_by(|a, b| a.name.cmp(&b.name).then(a.policy_id.cmp(&b.policy_id)));

    if let Some(denying) = applied
        .iter()
        .find(|policy| policy.action == RuleAction::Deny)
    {
        let reason = match &denying.problem {
            Some(problem) => format!(
                "Access is blocked by policy \"{}\", which cannot be read ({problem}). Ask an administrator.",
                denying.name
            ),
            None => format!(
                "Connections are not allowed now by policy \"{}\" ({}): {}.",
                denying.name,
                denying.local_time,
                denying.rules.describe()
            ),
        };
        return PolicyDecision::Deny(PolicyRefusal {
            policy_name: denying.name.clone(),
            reason,
        });
    }

    let requiring: Vec<&Applied> = applied
        .iter()
        .filter(|policy| policy.action == RuleAction::RequireApproval)
        .collect();
    let Some(first) = requiring.first() else {
        return PolicyDecision::Allow;
    };
    let shortest = |pick: fn(&RuleApproval) -> Option<u32>| {
        requiring
            .iter()
            .filter_map(|policy| pick(&policy.rules.approval))
            .min()
    };
    PolicyDecision::RequireApproval(ApprovalRequirement {
        policy_id: first.policy_id,
        policy_name: requiring
            .iter()
            .map(|policy| policy.name.as_str())
            .collect::<Vec<_>>()
            .join(", "),
        reason: requiring
            .iter()
            .map(|policy| {
                format!(
                    "policy \"{}\" requires approval now ({}): {}",
                    policy.name,
                    policy.local_time,
                    policy.rules.describe()
                )
            })
            .collect::<Vec<_>>()
            .join("; "),
        request_expiry_seconds: shortest(|approval| approval.request_expiry_seconds),
        valid_for_seconds: shortest(|approval| approval.valid_for_seconds),
        approvers: requiring
            .iter()
            .map(|policy| &policy.rules.approval)
            .filter(|approval| {
                !approval.approver_user_ids.is_empty() || !approval.approver_role_ids.is_empty()
            })
            .map(|approval| RuleApproval {
                request_expiry_seconds: None,
                valid_for_seconds: None,
                approver_user_ids: approval.approver_user_ids.clone(),
                approver_role_ids: approval.approver_role_ids.clone(),
            })
            .collect(),
    })
}

fn apply_policy(policy: &AccessPolicy::Model, at: OffsetDateTime) -> Applied {
    let unreadable = |problem: String| Applied {
        policy_id: Some(policy.id),
        name: policy.name.clone(),
        action: RuleAction::Deny,
        rules: AccessRules::new("UTC", RuleAction::Deny),
        local_time: String::new(),
        problem: Some(problem),
    };
    let rules = match policy.rules() {
        Ok(rules) => rules,
        Err(error) => return unreadable(error.to_string()),
    };
    match evaluate_rules(&rules, at) {
        Ok(evaluation) => Applied {
            policy_id: Some(policy.id),
            name: policy.name.clone(),
            action: evaluation.action,
            rules,
            local_time: evaluation.local_time,
            problem: None,
        },
        Err(problem) => unreadable(problem),
    }
}

// ---------------------------------------------------------------------------------------
// Which policies apply, and the decision for one connection
// ---------------------------------------------------------------------------------------

/// What a connection is, for the purpose of finding the policies that cover it.
#[derive(Clone, Copy)]
pub struct ConnectionFacts<'a> {
    pub user_id: Uuid,
    pub username: &'a str,
    pub target: &'a warpgate_common::Target,
    pub request: Option<&'a AccountRequest>,
    pub via_ticket: bool,
}

/// The decision for a connection, and what it is about.
#[derive(Debug, Clone)]
pub struct Evaluated {
    pub decision: PolicyDecision,
    /// The account it will sign in as, when that is settled.
    pub account: Option<(Uuid, String)>,
    /// Every account it might sign in as: more than one means the user has not chosen.
    pub candidate_names: Vec<String>,
}

fn narrow_candidates(
    accounts: Vec<AuthorizedAccount>,
    request: Option<&AccountRequest>,
) -> Vec<AuthorizedAccount> {
    match request {
        None => accounts,
        Some(AccountRequest::Id(id)) => accounts
            .into_iter()
            .filter(|candidate| candidate.account.id == *id)
            .collect(),
        Some(AccountRequest::Name(name)) => {
            let named: Vec<AuthorizedAccount> = accounts
                .iter()
                .filter(|candidate| names_account(&candidate.account, name))
                .cloned()
                .collect();
            if named.is_empty() {
                // A linked directory account is known by a name that has to be looked up:
                // keep every candidate, which can only make the result stricter.
                accounts
            } else {
                named
            }
        }
    }
}

async fn user_role_ids(
    db: &DatabaseConnection,
    user_id: Uuid,
) -> Result<HashSet<Uuid>, sea_orm::DbErr> {
    Ok(UserRoleAssignment::Entity::find_active()
        .filter(UserRoleAssignment::Column::UserId.eq(user_id))
        .all(db)
        .await?
        .into_iter()
        .map(|assignment| assignment.role_id)
        .collect())
}

/// Whether any policy is enabled at all. When none is, nothing here applies and a connection
/// is admitted exactly as it was before policies existed.
pub async fn any_enabled(db: &DatabaseConnection) -> Result<bool, sea_orm::DbErr> {
    Ok(AccessPolicy::Entity::find()
        .filter(AccessPolicy::Column::Enabled.eq(true))
        .one(db)
        .await?
        .is_some())
}

/// The enabled policies that cover a connection by `user_id` to `target_id` as one of
/// `account_ids`, with the roles `role_ids` the user holds.
pub async fn applicable_policies(
    db: &DatabaseConnection,
    user_id: Uuid,
    target_id: Uuid,
    role_ids: &HashSet<Uuid>,
    account_ids: &[Uuid],
) -> Result<Vec<AccessPolicy::Model>, sea_orm::DbErr> {
    let mut role_scope = Condition::any().add(AccessPolicy::Column::RoleId.is_null());
    if !role_ids.is_empty() {
        role_scope = role_scope.add(AccessPolicy::Column::RoleId.is_in(role_ids.iter().copied()));
    }
    let candidates = AccessPolicy::Entity::find()
        .filter(AccessPolicy::Column::Enabled.eq(true))
        .filter(
            Condition::any()
                .add(AccessPolicy::Column::UserId.is_null())
                .add(AccessPolicy::Column::UserId.eq(user_id)),
        )
        .filter(role_scope)
        .filter(
            Condition::any()
                .add(AccessPolicy::Column::TargetId.is_null())
                .add(AccessPolicy::Column::TargetId.eq(target_id)),
        )
        .order_by_asc(AccessPolicy::Column::Name)
        .order_by_asc(AccessPolicy::Column::Id)
        .all(db)
        .await?;
    Ok(candidates
        .into_iter()
        .filter(|policy| {
            policy
                .target_account_id
                .is_none_or(|account| account_ids.contains(&account))
        })
        .collect())
}

/// Decide a connection at `now`. The coarse question (may the user reach the target at all)
/// has been answered by Access Control already; this is only about timing and approval.
pub async fn evaluate_connection(
    db: &DatabaseConnection,
    facts: ConnectionFacts<'_>,
    now: OffsetDateTime,
) -> Result<Evaluated, WarpgateError> {
    let protocol = facts.target.options.protocol();
    let candidates = if uses_accounts(protocol) {
        match connection_accounts(
            db,
            ConnectingUser {
                id: facts.user_id,
                username: facts.username,
            },
            facts.target.id,
            facts.via_ticket,
        )
        .await
        {
            Ok(accounts) => narrow_candidates(accounts, facts.request),
            Err(AccessError::Database(error)) => return Err(error.into()),
            // No account is the account step's refusal to give, not this one's.
            Err(_) => vec![],
        }
    } else {
        vec![]
    };
    let account_ids: Vec<Uuid> = candidates
        .iter()
        .map(|candidate| candidate.account.id)
        .collect();
    let role_ids = user_role_ids(db, facts.user_id).await?;
    let policies =
        applicable_policies(db, facts.user_id, facts.target.id, &role_ids, &account_ids).await?;
    let decision = decide(
        policies
            .iter()
            .map(|policy| apply_policy(policy, now))
            .collect(),
    );
    let account = match candidates.as_slice() {
        [only] => Some((only.account.id, only.account.display_name())),
        _ => None,
    };
    Ok(Evaluated {
        decision,
        account,
        candidate_names: candidates
            .iter()
            .map(|candidate| candidate.account.display_name())
            .collect(),
    })
}

/// [`evaluate_connection`] for an authorization, which carries everything it needs.
pub async fn evaluate_authorization<O>(
    db: &DatabaseConnection,
    authorization: &TargetAuthorization<O>,
    now: OffsetDateTime,
) -> Result<Evaluated, WarpgateError> {
    let user = authorization.user_info();
    evaluate_connection(
        db,
        ConnectionFacts {
            user_id: user.id,
            username: &user.username,
            target: authorization.target(),
            request: authorization.account_request(),
            via_ticket: authorization.ticket_id().is_some(),
        },
        now,
    )
    .await
}

/// Whether `user_id` can still sign in to `target` as `account_id` through Access Control:
/// an approval never outlives the assignment under it.
pub async fn still_authorized(
    db: &DatabaseConnection,
    user: ConnectingUser<'_>,
    target: &warpgate_common::Target,
    account_id: Option<Uuid>,
    via_ticket: bool,
) -> Result<bool, WarpgateError> {
    if uses_accounts(target.options.protocol()) {
        let accounts = match connection_accounts(db, user, target.id, via_ticket).await {
            Ok(accounts) => accounts,
            Err(AccessError::Database(error)) => return Err(error.into()),
            Err(_) => return Ok(false),
        };
        Ok(accounts
            .iter()
            .any(|candidate| Some(candidate.account.id) == account_id))
    } else {
        Ok(via_ticket || crate::access_control::has_access(db, user.id, target.id).await?)
    }
}

/// Whether `actor_user_id` satisfies every approver list in `constraints`: named directly, or
/// a member of a named role. No constraints means any administrator allowed to approve.
pub async fn approver_allowed(
    db: &DatabaseConnection,
    constraints: &[RuleApproval],
    actor_user_id: Uuid,
) -> Result<bool, sea_orm::DbErr> {
    if constraints.is_empty() {
        return Ok(true);
    }
    let roles = user_role_ids(db, actor_user_id).await?;
    Ok(constraints.iter().all(|constraint| {
        constraint.approver_user_ids.contains(&actor_user_id)
            || constraint
                .approver_role_ids
                .iter()
                .any(|role| roles.contains(role))
    }))
}

// ---------------------------------------------------------------------------------------
// Policies as administrators manage them
// ---------------------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    /// Something to fix before it can be saved; the text says what.
    #[error("{0}")]
    Invalid(String),
    #[error("policy not found")]
    NotFound,
    #[error("{0}")]
    Conflict(String),
    #[error(transparent)]
    Database(#[from] sea_orm::DbErr),
}

/// Who and what a policy covers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PolicyScope {
    pub user_id: Option<Uuid>,
    pub role_id: Option<Uuid>,
    pub target_id: Option<Uuid>,
    pub target_account_id: Option<Uuid>,
}

pub struct PolicyData {
    pub name: String,
    pub description: String,
    pub enabled: bool,
    pub scope: PolicyScope,
    pub rules: AccessRules,
}

/// The scope a stored policy has.
pub fn scope_of(policy: &AccessPolicy::Model) -> PolicyScope {
    PolicyScope {
        user_id: policy.user_id,
        role_id: policy.role_id,
        target_id: policy.target_id,
        target_account_id: policy.target_account_id,
    }
}

/// Whether `rules` can be saved, including that the approvers it names exist.
pub async fn check_rules(db: &DatabaseConnection, rules: &AccessRules) -> Result<(), PolicyError> {
    validate_rules(rules).map_err(PolicyError::Invalid)?;
    validate_approvers(db, &rules.approval).await
}

/// What became of an approval request an access policy asked for. The request's own status
/// says whether it was decided; whether an approval is *used* or has *expired* is read off the
/// context, so it can never disagree with the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, poem_openapi::Enum)]
#[oai(rename = "AccessApprovalStatus")]
pub enum AccessApprovalStatus {
    /// Waiting for an approver.
    #[oai(rename = "pending")]
    Pending,
    /// Approved, and still good for starting a connection.
    #[oai(rename = "approved")]
    Approved,
    #[oai(rename = "rejected")]
    Rejected,
    /// Nobody answered in time, or the approval was not used within its validity.
    #[oai(rename = "expired")]
    Expired,
    /// A connection started on it; it cannot be used again.
    #[oai(rename = "used")]
    Used,
    /// The connection that asked went away before anyone answered.
    #[oai(rename = "abandoned")]
    Abandoned,
}

pub fn approval_status(
    status: SessionApprovalRequest::ApprovalRequestStatus,
    context: &AccessApprovalContext::Model,
    now: OffsetDateTime,
) -> AccessApprovalStatus {
    use SessionApprovalRequest::ApprovalRequestStatus as Status;
    match status {
        Status::Rejected => AccessApprovalStatus::Rejected,
        Status::Abandoned => AccessApprovalStatus::Abandoned,
        Status::TimedOut => AccessApprovalStatus::Expired,
        Status::Pending if context.expires_at <= now => AccessApprovalStatus::Expired,
        Status::Pending => AccessApprovalStatus::Pending,
        Status::Approved if context.used_at.is_some() => AccessApprovalStatus::Used,
        Status::Approved if context.valid_until.is_none_or(|until| until < now) => {
            AccessApprovalStatus::Expired
        }
        Status::Approved => AccessApprovalStatus::Approved,
    }
}

/// The scope in words, for the audit log and the policy list.
pub async fn describe_scope(db: &DatabaseConnection, scope: PolicyScope) -> String {
    let mut parts: Vec<String> = vec![];
    if let Some(id) = scope.user_id {
        let name = User::Entity::find_by_id(id)
            .one(db)
            .await
            .ok()
            .flatten()
            .map_or_else(|| "a deleted user".to_owned(), |user| user.username);
        parts.push(format!("user {name}"));
    }
    if let Some(id) = scope.role_id {
        let name = Role::Entity::find_by_id(id)
            .one(db)
            .await
            .ok()
            .flatten()
            .map_or_else(|| "a deleted group".to_owned(), |role| role.name);
        parts.push(format!("group {name}"));
    }
    if let Some(id) = scope.target_id {
        let name = Target::Entity::find_by_id(id)
            .one(db)
            .await
            .ok()
            .flatten()
            .map_or_else(|| "a deleted target".to_owned(), |target| target.name);
        parts.push(format!("target {name}"));
    }
    if let Some(id) = scope.target_account_id {
        let name = TargetAccount::Entity::find_by_id(id)
            .one(db)
            .await
            .ok()
            .flatten()
            .map_or_else(
                || "a deleted account".to_owned(),
                |account| account.display_name(),
            );
        parts.push(format!("account {name}"));
    }
    parts.join(", ")
}

async fn validate_scope(db: &DatabaseConnection, scope: PolicyScope) -> Result<(), PolicyError> {
    if scope.user_id.is_none()
        && scope.role_id.is_none()
        && scope.target_id.is_none()
        && scope.target_account_id.is_none()
    {
        return Err(PolicyError::Invalid(
            "Choose who or what the policy covers: a user, an access group or a target.".into(),
        ));
    }
    if let Some(id) = scope.user_id
        && User::Entity::find_by_id(id).one(db).await?.is_none()
    {
        return Err(PolicyError::Invalid("The user does not exist.".into()));
    }
    if let Some(id) = scope.role_id
        && Role::Entity::find_by_id(id).one(db).await?.is_none()
    {
        return Err(PolicyError::Invalid(
            "The access group does not exist.".into(),
        ));
    }
    if let Some(id) = scope.target_id
        && Target::Entity::find_by_id(id).one(db).await?.is_none()
    {
        return Err(PolicyError::Invalid("The target does not exist.".into()));
    }
    if let Some(account_id) = scope.target_account_id {
        let Some(target_id) = scope.target_id else {
            return Err(PolicyError::Invalid(
                "An account belongs to a target: choose the target as well.".into(),
            ));
        };
        let account = TargetAccount::Entity::find_by_id(account_id)
            .one(db)
            .await?;
        if account.is_none_or(|account| account.target_id != target_id) {
            return Err(PolicyError::Invalid(
                "The account is not one of the target's.".into(),
            ));
        }
    }
    Ok(())
}

async fn validate_approvers(
    db: &DatabaseConnection,
    approval: &RuleApproval,
) -> Result<(), PolicyError> {
    for id in &approval.approver_user_ids {
        if User::Entity::find_by_id(*id).one(db).await?.is_none() {
            return Err(PolicyError::Invalid(
                "An approver is not a user (any more).".into(),
            ));
        }
    }
    for id in &approval.approver_role_ids {
        if Role::Entity::find_by_id(*id).one(db).await?.is_none() {
            return Err(PolicyError::Invalid(
                "An approver group does not exist (any more).".into(),
            ));
        }
    }
    Ok(())
}

async fn validate_policy(
    db: &DatabaseConnection,
    data: &PolicyData,
    own_id: Option<Uuid>,
    needs_unique_name: bool,
) -> Result<(), PolicyError> {
    let name = data.name.trim();
    if name.is_empty() || name.chars().count() > 256 {
        return Err(PolicyError::Invalid(
            "Give the policy a name of up to 256 characters.".into(),
        ));
    }
    validate_rules(&data.rules).map_err(PolicyError::Invalid)?;
    validate_scope(db, data.scope).await?;
    validate_approvers(db, &data.rules.approval).await?;
    if needs_unique_name {
        let clash = AccessPolicy::Entity::find()
            .filter(AccessPolicy::Column::AssignmentId.is_null())
            .all(db)
            .await?
            .into_iter()
            .any(|policy| Some(policy.id) != own_id && policy.name.eq_ignore_ascii_case(name));
        if clash {
            return Err(PolicyError::Conflict(
                "Another policy has this name.".into(),
            ));
        }
    }
    Ok(())
}

pub async fn list_policies(
    db: &DatabaseConnection,
) -> Result<Vec<AccessPolicy::Model>, sea_orm::DbErr> {
    AccessPolicy::Entity::find()
        .filter(AccessPolicy::Column::AssignmentId.is_null())
        .order_by_asc(AccessPolicy::Column::Name)
        .all(db)
        .await
}

pub async fn find_policy(
    db: &DatabaseConnection,
    id: Uuid,
) -> Result<Option<AccessPolicy::Model>, sea_orm::DbErr> {
    AccessPolicy::Entity::find_by_id(id).one(db).await
}

pub async fn create_policy(
    db: &DatabaseConnection,
    data: PolicyData,
    actor: Option<Uuid>,
) -> Result<AccessPolicy::Model, PolicyError> {
    validate_policy(db, &data, None, true).await?;
    let now = OffsetDateTime::now_utc();
    Ok(AccessPolicy::ActiveModel {
        id: Set(Uuid::new_v4()),
        name: Set(data.name.trim().to_owned()),
        description: Set(data.description.trim().to_owned()),
        enabled: Set(data.enabled),
        user_id: Set(data.scope.user_id),
        role_id: Set(data.scope.role_id),
        target_id: Set(data.scope.target_id),
        target_account_id: Set(data.scope.target_account_id),
        assignment_id: Set(None),
        rules: Set(rules_json(&data.rules)?),
        created_by: Set(actor),
        created_at: Set(now),
        updated_at: Set(now),
    }
    .insert(db)
    .await?)
}

pub async fn update_policy(
    db: &DatabaseConnection,
    id: Uuid,
    data: PolicyData,
    _actor: Option<Uuid>,
) -> Result<AccessPolicy::Model, PolicyError> {
    let existing = find_policy(db, id).await?.ok_or(PolicyError::NotFound)?;
    if existing.is_assignment_schedule() {
        return Err(PolicyError::Invalid(
            "This is an assignment's own schedule: change it by editing the assignment.".into(),
        ));
    }
    validate_policy(db, &data, Some(id), true).await?;
    let mut model: AccessPolicy::ActiveModel = existing.into();
    model.name = Set(data.name.trim().to_owned());
    model.description = Set(data.description.trim().to_owned());
    model.enabled = Set(data.enabled);
    model.user_id = Set(data.scope.user_id);
    model.role_id = Set(data.scope.role_id);
    model.target_id = Set(data.scope.target_id);
    model.target_account_id = Set(data.scope.target_account_id);
    model.rules = Set(rules_json(&data.rules)?);
    model.updated_at = Set(OffsetDateTime::now_utc());
    Ok(model.update(db).await?)
}

pub async fn delete_policy(
    db: &DatabaseConnection,
    id: Uuid,
) -> Result<AccessPolicy::Model, PolicyError> {
    let existing = find_policy(db, id).await?.ok_or(PolicyError::NotFound)?;
    if existing.is_assignment_schedule() {
        return Err(PolicyError::Invalid(
            "This is an assignment's own schedule: remove it by editing the assignment.".into(),
        ));
    }
    AccessPolicy::Entity::delete_by_id(id).exec(db).await?;
    Ok(existing)
}

fn rules_json(rules: &AccessRules) -> Result<serde_json::Value, PolicyError> {
    serde_json::to_value(rules).map_err(|error| PolicyError::Invalid(error.to_string()))
}

/// The schedule that belongs to a direct assignment, if it has one.
pub async fn assignment_policy(
    db: &DatabaseConnection,
    assignment_id: Uuid,
) -> Result<Option<AccessPolicy::Model>, sea_orm::DbErr> {
    AccessPolicy::Entity::find()
        .filter(AccessPolicy::Column::AssignmentId.eq(assignment_id))
        .one(db)
        .await
}

pub async fn delete_assignment_policy(
    db: &DatabaseConnection,
    assignment_id: Uuid,
) -> Result<(), sea_orm::DbErr> {
    AccessPolicy::Entity::delete_many()
        .filter(AccessPolicy::Column::AssignmentId.eq(assignment_id))
        .exec(db)
        .await?;
    Ok(())
}

/// Set (or, with `None`, remove) a direct assignment's own schedule and approval rules. The
/// policy covers the assignment's user, target and account, and goes with the assignment.
pub async fn save_assignment_rules(
    db: &DatabaseConnection,
    assignment: &AccessAssignment::Model,
    label: &str,
    rules: Option<AccessRules>,
    actor: Option<Uuid>,
) -> Result<Option<AccessPolicy::Model>, PolicyError> {
    let Some(rules) = rules else {
        delete_assignment_policy(db, assignment.id).await?;
        return Ok(None);
    };
    validate_rules(&rules).map_err(PolicyError::Invalid)?;
    validate_approvers(db, &rules.approval).await?;
    let now = OffsetDateTime::now_utc();
    let json = rules_json(&rules)?;
    match assignment_policy(db, assignment.id).await? {
        Some(existing) => {
            let mut model: AccessPolicy::ActiveModel = existing.into();
            model.name = Set(label.to_owned());
            model.enabled = Set(true);
            model.rules = Set(json);
            model.updated_at = Set(now);
            Ok(Some(model.update(db).await?))
        }
        None => Ok(Some(
            AccessPolicy::ActiveModel {
                id: Set(Uuid::new_v4()),
                name: Set(label.to_owned()),
                description: Set(String::new()),
                enabled: Set(true),
                user_id: Set(Some(assignment.user_id)),
                role_id: Set(None),
                target_id: Set(Some(assignment.target_id)),
                target_account_id: Set(assignment.target_account_id),
                assignment_id: Set(Some(assignment.id)),
                rules: Set(json),
                created_by: Set(actor),
                created_at: Set(now),
                updated_at: Set(now),
            }
            .insert(db)
            .await?,
        )),
    }
}

#[cfg(test)]
mod pure_tests {
    use warpgate_common::RuleWindow;

    use super::*;

    /// "2026-03-02T11:00:00Z" as an instant, without the `time` crate's optional parser.
    fn at(text: &str) -> OffsetDateTime {
        let number = |range: std::ops::Range<usize>| text[range].parse::<u8>().unwrap();
        let year: i32 = text[0..4].parse().unwrap();
        time::Date::from_calendar_date(
            year,
            time::Month::try_from(number(5..7)).unwrap(),
            number(8..10),
        )
        .unwrap()
        .with_hms(number(11..13), number(14..16), number(17..19))
        .unwrap()
        .assume_utc()
    }

    fn weekdays() -> Vec<RuleWeekday> {
        RuleWeekday::ALL[..5].to_vec()
    }

    fn office(timezone: &str, outside: RuleAction) -> AccessRules {
        let mut rules = AccessRules::new(timezone, outside);
        rules.windows.push(RuleWindow {
            days: weekdays(),
            start: "09:00".into(),
            end: "18:00".into(),
            action: RuleAction::Allow,
        });
        rules
    }

    fn applied(name: &str, rules: AccessRules, now: OffsetDateTime) -> Applied {
        let evaluation = evaluate_rules(&rules, now).unwrap();
        Applied {
            policy_id: Some(Uuid::new_v4()),
            name: name.into(),
            action: evaluation.action,
            rules,
            local_time: evaluation.local_time,
            problem: None,
        }
    }

    fn action_at(rules: &AccessRules, when: &str) -> RuleAction {
        evaluate_rules(rules, at(when)).unwrap().action
    }

    #[test]
    fn office_hours_allow_and_the_rest_asks_for_approval() {
        let rules = office("Europe/Berlin", RuleAction::RequireApproval);
        // 2026-03-02 is a Monday. Berlin is UTC+1 in March before the 29th.
        assert_eq!(action_at(&rules, "2026-03-02T11:00:00Z"), RuleAction::Allow);
        // 20:00 in Berlin on a Monday.
        assert_eq!(
            action_at(&rules, "2026-03-02T19:00:00Z"),
            RuleAction::RequireApproval
        );
        // 07:00 in Berlin on a Wednesday.
        assert_eq!(
            action_at(&rules, "2026-03-04T06:00:00Z"),
            RuleAction::RequireApproval
        );
        // Saturday and Sunday.
        assert_eq!(
            action_at(&rules, "2026-03-07T11:00:00Z"),
            RuleAction::RequireApproval
        );
        assert_eq!(
            action_at(&rules, "2026-03-08T11:00:00Z"),
            RuleAction::RequireApproval
        );
    }

    #[test]
    fn the_same_instant_reads_differently_in_another_timezone() {
        let berlin = office("Europe/Berlin", RuleAction::Deny);
        let new_york = office("America/New_York", RuleAction::Deny);
        // 15:00Z is 16:00 Berlin and 10:00 New York: inside for both.
        assert_eq!(
            action_at(&berlin, "2026-03-02T15:00:00Z"),
            RuleAction::Allow
        );
        assert_eq!(
            action_at(&new_york, "2026-03-02T15:00:00Z"),
            RuleAction::Allow
        );
        // 22:00Z is 23:00 Berlin (outside) and 17:00 New York (inside).
        assert_eq!(action_at(&berlin, "2026-03-02T22:00:00Z"), RuleAction::Deny);
        assert_eq!(
            action_at(&new_york, "2026-03-02T22:00:00Z"),
            RuleAction::Allow
        );
    }

    #[test]
    fn the_day_is_the_rules_own_not_utcs() {
        // 2026-03-02T23:30Z is already Tuesday 00:30 in Berlin, so a Monday-only window does
        // not contain it, whatever day it is in UTC or on the server.
        let mut rules = AccessRules::new("Europe/Berlin", RuleAction::Deny);
        rules.windows.push(RuleWindow {
            days: vec![RuleWeekday::Mon],
            start: "00:00".into(),
            end: "24:00".into(),
            action: RuleAction::Allow,
        });
        assert_eq!(action_at(&rules, "2026-03-02T22:30:00Z"), RuleAction::Allow);
        assert_eq!(action_at(&rules, "2026-03-02T23:30:00Z"), RuleAction::Deny);
    }

    #[test]
    fn daylight_saving_moves_the_window_in_utc() {
        let rules = office("Europe/Berlin", RuleAction::Deny);
        // Berlin goes to summer time on 2026-03-29. 2026-03-27 is a Friday (UTC+1) and
        // 2026-03-30 a Monday (UTC+2): 09:00 Berlin is 08:00Z, then 07:00Z.
        assert_eq!(action_at(&rules, "2026-03-27T07:30:00Z"), RuleAction::Deny);
        assert_eq!(action_at(&rules, "2026-03-27T08:30:00Z"), RuleAction::Allow);
        assert_eq!(action_at(&rules, "2026-03-30T06:30:00Z"), RuleAction::Deny);
        assert_eq!(action_at(&rules, "2026-03-30T07:30:00Z"), RuleAction::Allow);
        // The end follows the clock too: 18:00 Berlin is 16:00Z in summer.
        assert_eq!(action_at(&rules, "2026-03-30T15:59:00Z"), RuleAction::Allow);
        assert_eq!(action_at(&rules, "2026-03-30T16:00:00Z"), RuleAction::Deny);
    }

    #[test]
    fn the_hour_that_does_not_exist_and_the_hour_that_happens_twice() {
        // Spring forward: 02:00-03:00 on 2026-03-29 does not exist in Berlin. A window that
        // covers it (01:00-04:00 on Sunday) contains every instant around it.
        let mut spring = AccessRules::new("Europe/Berlin", RuleAction::Deny);
        spring.windows.push(RuleWindow {
            days: vec![RuleWeekday::Sun],
            start: "01:00".into(),
            end: "04:00".into(),
            action: RuleAction::Allow,
        });
        // 00:59Z is 01:59 CET; 01:00Z is 03:00 CEST; 02:00Z is 04:00 CEST (the end).
        assert_eq!(
            action_at(&spring, "2026-03-29T00:59:00Z"),
            RuleAction::Allow
        );
        assert_eq!(
            action_at(&spring, "2026-03-29T01:00:00Z"),
            RuleAction::Allow
        );
        assert_eq!(
            action_at(&spring, "2026-03-29T01:59:00Z"),
            RuleAction::Allow
        );
        assert_eq!(action_at(&spring, "2026-03-29T02:00:00Z"), RuleAction::Deny);

        // Fall back: 02:00-03:00 on 2026-10-25 happens twice. Both passes are inside a window
        // that covers them.
        let mut autumn = AccessRules::new("Europe/Berlin", RuleAction::Deny);
        autumn.windows.push(RuleWindow {
            days: vec![RuleWeekday::Sun],
            start: "02:00".into(),
            end: "03:00".into(),
            action: RuleAction::Allow,
        });
        assert_eq!(
            action_at(&autumn, "2026-10-25T00:30:00Z"),
            RuleAction::Allow
        ); // 02:30 CEST
        assert_eq!(
            action_at(&autumn, "2026-10-25T01:30:00Z"),
            RuleAction::Allow
        ); // 02:30 CET
        assert_eq!(action_at(&autumn, "2026-10-25T02:30:00Z"), RuleAction::Deny); // 03:30 CET
    }

    #[test]
    fn several_windows_on_one_day_and_overnight_ones() {
        let mut rules = AccessRules::new("UTC", RuleAction::Deny);
        for (start, end) in [("08:00", "12:00"), ("13:00", "17:00")] {
            rules.windows.push(RuleWindow {
                days: vec![RuleWeekday::Tue],
                start: start.into(),
                end: end.into(),
                action: RuleAction::Allow,
            });
        }
        // 2026-03-03 is a Tuesday.
        assert_eq!(action_at(&rules, "2026-03-03T09:00:00Z"), RuleAction::Allow);
        assert_eq!(
            action_at(&rules, "2026-03-03T12:30:00Z"),
            RuleAction::Deny,
            "the gap between them"
        );
        assert_eq!(action_at(&rules, "2026-03-03T14:00:00Z"), RuleAction::Allow);

        let mut night = AccessRules::new("UTC", RuleAction::RequireApproval);
        night.windows.push(RuleWindow {
            days: vec![RuleWeekday::Fri],
            start: "22:00".into(),
            end: "06:00".into(),
            action: RuleAction::Allow,
        });
        // 2026-03-06 is a Friday.
        assert_eq!(action_at(&night, "2026-03-06T23:00:00Z"), RuleAction::Allow);
        assert_eq!(
            action_at(&night, "2026-03-07T05:59:00Z"),
            RuleAction::Allow,
            "Saturday morning"
        );
        assert_eq!(
            action_at(&night, "2026-03-07T06:00:00Z"),
            RuleAction::RequireApproval
        );
        assert_eq!(
            action_at(&night, "2026-03-06T05:00:00Z"),
            RuleAction::RequireApproval,
            "Friday morning belongs to Thursday night"
        );
    }

    #[test]
    fn overlapping_windows_resolve_to_the_most_restrictive() {
        let mut rules = AccessRules::new("UTC", RuleAction::Allow);
        rules.windows.push(RuleWindow {
            days: RuleWeekday::ALL.to_vec(),
            start: "00:00".into(),
            end: "24:00".into(),
            action: RuleAction::Allow,
        });
        rules.windows.push(RuleWindow {
            days: vec![RuleWeekday::Sat, RuleWeekday::Sun],
            start: "00:00".into(),
            end: "24:00".into(),
            action: RuleAction::RequireApproval,
        });
        rules.windows.push(RuleWindow {
            days: vec![RuleWeekday::Sun],
            start: "00:00".into(),
            end: "24:00".into(),
            action: RuleAction::Deny,
        });
        assert_eq!(action_at(&rules, "2026-03-04T12:00:00Z"), RuleAction::Allow);
        assert_eq!(
            action_at(&rules, "2026-03-07T12:00:00Z"),
            RuleAction::RequireApproval
        );
        assert_eq!(action_at(&rules, "2026-03-08T12:00:00Z"), RuleAction::Deny);
    }

    #[test]
    fn an_unknown_timezone_cannot_be_evaluated_or_saved() {
        let rules = office("Mars/Olympus_Mons", RuleAction::Allow);
        assert!(evaluate_rules(&rules, at("2026-03-02T11:00:00Z")).is_err());
        assert!(validate_rules(&rules).is_err());
    }

    #[test]
    fn rules_are_validated() {
        assert!(validate_rules(&office("Europe/Berlin", RuleAction::Deny)).is_ok());

        let mut no_days = office("UTC", RuleAction::Deny);
        no_days.windows[0].days.clear();
        assert!(
            validate_rules(&no_days)
                .unwrap_err()
                .contains("at least one day")
        );

        let mut bad_time = office("UTC", RuleAction::Deny);
        bad_time.windows[0].start = "9am".into();
        assert!(validate_rules(&bad_time).is_err());

        let mut empty = office("UTC", RuleAction::Deny);
        empty.windows[0].end = "09:00".into();
        assert!(
            validate_rules(&empty).is_err(),
            "a window that starts when it ends"
        );

        let mut long = office("UTC", RuleAction::RequireApproval);
        long.approval.request_expiry_seconds = Some(0);
        assert!(validate_rules(&long).is_err());
        long.approval.request_expiry_seconds = Some(MAX_APPROVAL_SECONDS + 1);
        assert!(validate_rules(&long).is_err());
        long.approval.request_expiry_seconds = Some(900);
        long.approval.valid_for_seconds = Some(1800);
        assert!(validate_rules(&long).is_ok());
    }

    #[test]
    fn no_policy_allows() {
        assert_eq!(decide(vec![]), PolicyDecision::Allow);
    }

    #[test]
    fn a_denial_beats_an_approval_requirement_beats_an_allowance() {
        let now = at("2026-03-07T12:00:00Z"); // a Saturday
        let allow = applied("Anytime", AccessRules::new("UTC", RuleAction::Allow), now);
        let approval = applied("Weekdays", office("UTC", RuleAction::RequireApproval), now);
        let deny = applied("Frozen", AccessRules::new("UTC", RuleAction::Deny), now);

        assert!(matches!(
            decide(vec![allow.clone(), approval.clone()]),
            PolicyDecision::RequireApproval(_)
        ));
        match decide(vec![allow.clone(), approval.clone(), deny.clone()]) {
            PolicyDecision::Deny(refusal) => assert_eq!(refusal.policy_name, "Frozen"),
            other => panic!("expected a denial, got {other:?}"),
        }
        // Order is irrelevant.
        match decide(vec![deny, allow, approval]) {
            PolicyDecision::Deny(refusal) => assert_eq!(refusal.policy_name, "Frozen"),
            other => panic!("expected a denial, got {other:?}"),
        }
    }

    #[test]
    fn a_permissive_policy_cannot_lift_a_restrictive_one() {
        let now = at("2026-03-07T12:00:00Z");
        let always_allowed = applied("Everyone", AccessRules::new("UTC", RuleAction::Allow), now);
        let weekend_approval = applied("Weekends", office("UTC", RuleAction::RequireApproval), now);
        assert!(matches!(
            decide(vec![always_allowed, weekend_approval]),
            PolicyDecision::RequireApproval(_)
        ));
    }

    #[test]
    fn approval_terms_take_the_strictest_of_the_policies() {
        let now = at("2026-03-07T12:00:00Z");
        let mut first = office("UTC", RuleAction::RequireApproval);
        first.approval.request_expiry_seconds = Some(1800);
        first.approval.valid_for_seconds = Some(3600);
        let alice = Uuid::new_v4();
        first.approval.approver_user_ids = vec![alice];
        let mut second = office("UTC", RuleAction::RequireApproval);
        second.approval.request_expiry_seconds = Some(300);
        let third = office("UTC", RuleAction::RequireApproval);

        let PolicyDecision::RequireApproval(requirement) = decide(vec![
            applied("B", first, now),
            applied("A", second, now),
            applied("C", third, now),
        ]) else {
            panic!("expected an approval requirement");
        };
        assert_eq!(
            requirement.request_expiry_seconds,
            Some(300),
            "the shortest request expiry"
        );
        assert_eq!(
            requirement.valid_for_seconds,
            Some(3600),
            "the only validity named"
        );
        assert_eq!(
            requirement.approvers.len(),
            1,
            "only the policy that names approvers constrains them"
        );
        assert_eq!(requirement.approvers[0].approver_user_ids, vec![alice]);
        assert_eq!(requirement.policy_name, "A, B, C", "named in order");
    }

    #[test]
    fn a_policy_that_cannot_be_read_denies() {
        let policy = AccessPolicy::Model {
            id: Uuid::new_v4(),
            name: "Broken".into(),
            description: String::new(),
            enabled: true,
            user_id: Some(Uuid::new_v4()),
            role_id: None,
            target_id: None,
            target_account_id: None,
            assignment_id: None,
            rules: serde_json::json!({"timezone": 7}),
            created_by: None,
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
        };
        let applied = apply_policy(&policy, at("2026-03-02T11:00:00Z"));
        assert_eq!(applied.action, RuleAction::Deny);
        assert!(applied.problem.is_some());
        assert!(matches!(decide(vec![applied]), PolicyDecision::Deny(_)));
    }

    #[test]
    fn a_denial_says_when_and_what_is_allowed() {
        let now = at("2026-03-07T12:00:00Z");
        let PolicyDecision::Deny(refusal) = decide(vec![applied(
            "Office hours",
            office("Europe/Berlin", RuleAction::Deny),
            now,
        )]) else {
            panic!("expected a denial");
        };
        assert!(refusal.reason.contains("Office hours"));
        assert!(refusal.reason.contains("Sat 13:00 Europe/Berlin"));
        assert!(refusal.reason.contains("Mon–Fri 09:00–18:00"));
    }
}
