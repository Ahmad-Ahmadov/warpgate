//! The access-policy side of the approval gate (see [`crate::access_policy`] for what a policy
//! decides and how several combine).
//!
//! The approval system stays one system. An approval an access policy requires is a request in
//! `session_approval_requests`, found, decided and audited like any other. What the policy adds
//! is a context row under the same key (`access_approval_contexts`), and these rules on top:
//!
//! * **Two clocks.** The request lapses unanswered at `expires_at`, and nobody can approve it
//!   after. An approval, once given, can start a connection until `valid_until`. They are
//!   separate settings and both are enforced here, on the server.
//! * **Bound.** The approval is for the user, the target and the account it was asked for. The
//!   statement that spends it checks all three.
//! * **Single use.** Spending it is one conditional `UPDATE`; of any number of connections
//!   racing for it, one wins.
//! * **Never an override.** Spending it re-checks, at that moment, that the assignment under
//!   it is still in force and that no policy now denies the connection.
//!
//! A request that no policy asked for (the target's own "require approval" setting) behaves as
//! it always did, including remembered approvals.

use sea_orm::{ActiveModelTrait, Set, SqlErr};
use uuid::Uuid;
use warpgate_common::audit::AuditEvent;
use warpgate_common::auth::ApprovalKind;
use warpgate_db_entities::AccessApprovalContext;

use super::*;
use crate::access_control::{AccessError, ConnectingUser, uses_accounts};
use crate::access_policy::{self, ApprovalRequirement, PolicyDecision};
use crate::config_providers::TargetAuthorization;
use crate::services::Services;

/// What the gate asks of a connection.
pub(crate) enum Requirement {
    /// It may start.
    None,
    /// The target's own "require approval" setting: remembered approvals and all.
    TargetSetting,
    /// An access policy requires it.
    Policy(Box<PolicyAsk>),
}

pub(crate) struct PolicyAsk {
    pub(crate) requirement: ApprovalRequirement,
    /// The account it will sign in as.
    pub(crate) account: Option<(Uuid, String)>,
    pub(crate) target_id: Uuid,
}

/// What the gate must ask for. A policy that denies refuses here (and is audited), before
/// anyone is asked anything.
pub(crate) async fn requirement_for<O>(
    db: &DatabaseConnection,
    authorization: &TargetAuthorization<O>,
) -> Result<Requirement, WarpgateError> {
    let target = authorization.target();
    let fallback = || {
        if target.require_approval {
            Requirement::TargetSetting
        } else {
            Requirement::None
        }
    };
    // The common case, and the one that must stay exactly as it was: no policy exists.
    if !access_policy::any_enabled(db).await? {
        return Ok(fallback());
    }

    let user = authorization.user_info();
    let evaluated =
        access_policy::evaluate_authorization(db, authorization, OffsetDateTime::now_utc()).await?;
    let account_label = evaluated.account.as_ref().map(|(_, label)| label.clone());
    match evaluated.decision {
        PolicyDecision::Allow => Ok(fallback()),
        PolicyDecision::Deny(refusal) => {
            AuditEvent::AccessPolicyDenied {
                user_id: user.id,
                username: user.username.clone(),
                target_id: target.id,
                target_name: target.name.clone(),
                account: account_label,
                policy_name: refusal.policy_name,
                reason: refusal.reason.clone(),
            }
            .emit();
            Err(WarpgateError::AccessPolicyDenied(refusal.reason))
        }
        PolicyDecision::RequireApproval(requirement) => {
            // An approval is for one account. Do not ask for one while it is not settled
            // which account the connection is for: the account step would refuse it anyway.
            if uses_accounts(target.options.protocol()) && evaluated.account.is_none() {
                let error = if evaluated.candidate_names.len() > 1 {
                    AccessError::NotChosen(evaluated.candidate_names)
                } else {
                    AccessError::NoAccess
                };
                return Err(WarpgateError::InvalidRequest(
                    error.user_message(&target.name),
                ));
            }
            Ok(Requirement::Policy(Box::new(PolicyAsk {
                requirement,
                account: evaluated.account,
                target_id: target.id,
            })))
        }
    }
}

/// How a spent approval turned out.
pub(super) enum Spent {
    Yes,
    /// It cannot be used (lapsed, already used, or for something else): ask again.
    NeedsNewRequest,
    /// The connection must not start, however it was approved.
    Refused,
}

fn emit_refused<O>(authorization: &TargetAuthorization<O>, account: Option<String>, reason: &str) {
    let user = authorization.user_info();
    let target = authorization.target();
    AuditEvent::AccessApprovalRefused {
        user_id: user.id,
        username: user.username.clone(),
        target_id: target.id,
        target_name: target.name.clone(),
        account,
        reason: reason.to_owned(),
    }
    .emit();
}

impl Services {
    /// Make the ground ready to ask: forget a single-use approval that was used or has lapsed,
    /// close a request that went unanswered past its expiry, and write the context a fresh
    /// request carries. Called before every (re)ask of a policy request.
    pub(super) async fn prepare_policy_request(
        &self,
        subject: &ApprovalSubject,
        ask: &PolicyAsk,
    ) -> Result<(), WarpgateError> {
        use SessionApprovalRequest::ApprovalRequestStatus as Status;

        let db = &self.db;
        let session_id = subject.session_id;
        let target_name = subject.target_name.as_str();
        let now = OffsetDateTime::now_utc();

        if let Some(context) =
            AccessApprovalContext::find(db, session_id, ApprovalKind::Admin, target_name).await?
        {
            match find_row(db, session_id, ApprovalKind::Admin, target_name).await? {
                None => {
                    AccessApprovalContext::delete(db, session_id, ApprovalKind::Admin, target_name)
                        .await?;
                }
                Some(row) => match row.status {
                    Status::Pending if context.expires_at <= now => {
                        close_timed_out(db, subject).await?;
                    }
                    Status::Approved
                        if context.used_at.is_some()
                            || context.valid_until.is_none_or(|until| until < now) =>
                    {
                        self.discard_policy_request(subject).await?;
                    }
                    _ => {}
                },
            }
        }

        let row = find_row(db, session_id, ApprovalKind::Admin, target_name).await?;
        let reopening = match &row {
            None => true,
            Some(row) => matches!(row.status, Status::TimedOut | Status::Abandoned),
        };
        let existing =
            AccessApprovalContext::find(db, session_id, ApprovalKind::Admin, target_name).await?;
        if !reopening && existing.is_some() {
            return Ok(());
        }
        if existing.is_some() {
            AccessApprovalContext::delete(db, session_id, ApprovalKind::Admin, target_name).await?;
        }

        let window_seconds: i64 = match ask.requirement.request_expiry_seconds {
            Some(seconds) => i64::from(seconds),
            None => {
                i64::try_from(self.admin_approval_timeout().await?.as_secs()).unwrap_or(i64::MAX)
            }
        };
        let valid_for_seconds = ask
            .requirement
            .valid_for_seconds
            .map_or(window_seconds, i64::from);
        let terms = serde_json::to_value(&ask.requirement.approvers)
            .map_err(|error| WarpgateError::InconsistentState(error.to_string()))?;
        let context = AccessApprovalContext::ActiveModel {
            session_id: Set(session_id),
            kind: Set(ApprovalKind::Admin),
            target: Set(target_name.to_owned()),
            policy_id: Set(ask.requirement.policy_id),
            policy_name: Set(ask.requirement.policy_name.clone()),
            reason: Set(ask.requirement.reason.clone()),
            user_id: Set(subject.user_info.id),
            target_id: Set(ask.target_id),
            target_account_id: Set(ask.account.as_ref().map(|(id, _)| *id)),
            account_name: Set(ask.account.as_ref().map(|(_, name)| name.clone())),
            expires_at: Set(now + time::Duration::seconds(window_seconds)),
            valid_for_seconds: Set(valid_for_seconds),
            valid_until: Set(None),
            used_at: Set(None),
            terms: Set(terms),
            created_at: Set(now),
        };
        match context.insert(db).await {
            Ok(_) => Ok(()),
            // A concurrent attempt of the same session wrote it first: the question is the same.
            Err(error) if matches!(error.sql_err(), Some(SqlErr::UniqueConstraintViolation(_))) => {
                Ok(())
            }
            Err(error) => Err(error.into()),
        }
    }

    /// How long a policy request still has to be answered.
    pub(super) async fn policy_wait(
        &self,
        subject: &ApprovalSubject,
    ) -> Result<Duration, WarpgateError> {
        let context = AccessApprovalContext::find(
            &self.db,
            subject.session_id,
            ApprovalKind::Admin,
            &subject.target_name,
        )
        .await?;
        let Some(context) = context else {
            return self.admin_approval_timeout().await;
        };
        let left = (context.expires_at - OffsetDateTime::now_utc()).whole_seconds();
        Ok(Duration::from_secs(u64::try_from(left).unwrap_or(0)))
    }

    /// Announce, once, that a policy asked for this approval.
    pub(super) async fn emit_policy_request<O>(
        &self,
        authorization: &TargetAuthorization<O>,
        subject: &ApprovalSubject,
        ask: &PolicyAsk,
    ) -> Result<(), WarpgateError> {
        let context = AccessApprovalContext::find(
            &self.db,
            subject.session_id,
            ApprovalKind::Admin,
            &subject.target_name,
        )
        .await?;
        let user = authorization.user_info();
        AuditEvent::AccessApprovalRequested {
            user_id: user.id,
            username: user.username.clone(),
            target_id: ask.target_id,
            target_name: authorization.target().name.clone(),
            account: ask.account.as_ref().map(|(_, name)| name.clone()),
            policy_name: ask.requirement.policy_name.clone(),
            reason: ask.requirement.reason.clone(),
            expires_at: context
                .map(|context| context.expires_at.to_string())
                .unwrap_or_default(),
        }
        .emit();
        Ok(())
    }

    /// Forget a policy request's approval and its context, so the question can be asked anew.
    pub(super) async fn discard_policy_request(
        &self,
        subject: &ApprovalSubject,
    ) -> Result<(), WarpgateError> {
        SessionApprovalRequest::forget_approved(
            &self.db,
            subject.session_id,
            ApprovalKind::Admin,
            &subject.target_name,
        )
        .await?;
        AccessApprovalContext::delete(
            &self.db,
            subject.session_id,
            ApprovalKind::Admin,
            &subject.target_name,
        )
        .await?;
        Ok(())
    }

    /// Use the approval to start the connection, if it is still good for exactly this one:
    /// re-check now that no policy denies it and the assignment under it is in force, then spend
    /// it (once, atomically, for this user, target and account).
    pub(super) async fn spend_policy_approval<O>(
        &self,
        authorization: &TargetAuthorization<O>,
        subject: &ApprovalSubject,
    ) -> Result<Spent, WarpgateError> {
        let db = &self.db;
        let user = authorization.user_info();
        let target = authorization.target();
        let now = OffsetDateTime::now_utc();

        let evaluated = access_policy::evaluate_authorization(db, authorization, now).await?;
        let account_id = evaluated.account.as_ref().map(|(id, _)| *id);
        let account_label = evaluated.account.as_ref().map(|(_, label)| label.clone());

        if let PolicyDecision::Deny(refusal) = &evaluated.decision {
            emit_refused(
                authorization,
                account_label,
                &format!(
                    "policy \"{}\" now denies the connection; an approval does not override it",
                    refusal.policy_name
                ),
            );
            return Ok(Spent::Refused);
        }
        if uses_accounts(target.options.protocol()) && account_id.is_none() {
            emit_refused(
                authorization,
                account_label,
                "the account to sign in as is not settled",
            );
            return Ok(Spent::Refused);
        }
        let still_authorized = access_policy::still_authorized(
            db,
            ConnectingUser {
                id: user.id,
                username: &user.username,
            },
            target,
            account_id,
            authorization.ticket_id().is_some(),
        )
        .await?;
        if !still_authorized {
            emit_refused(
                authorization,
                account_label,
                "the access under the approval was revoked, disabled or has expired",
            );
            return Ok(Spent::Refused);
        }

        let claim = AccessApprovalContext::Claim {
            session_id: subject.session_id,
            kind: ApprovalKind::Admin,
            target: &subject.target_name,
            user_id: user.id,
            target_id: target.id,
            target_account_id: account_id,
        };
        if !AccessApprovalContext::consume(db, &claim, now).await? {
            emit_refused(
                authorization,
                account_label,
                "the approval has expired, was already used, or is for a different account",
            );
            return Ok(Spent::NeedsNewRequest);
        }

        let context = AccessApprovalContext::find(
            db,
            subject.session_id,
            ApprovalKind::Admin,
            &subject.target_name,
        )
        .await?;
        let approved_by = find_row(
            db,
            subject.session_id,
            ApprovalKind::Admin,
            &subject.target_name,
        )
        .await?
        .and_then(|row| row.resolved_by_username);
        AuditEvent::AccessApprovalConsumed {
            user_id: user.id,
            username: user.username.clone(),
            target_id: target.id,
            target_name: target.name.clone(),
            account: account_label,
            policy_name: context
                .map(|context| context.policy_name)
                .unwrap_or_default(),
            approved_by,
        }
        .emit();
        Ok(Spent::Yes)
    }

    /// What a user waiting for approval is told: why, for which account, and for how long the
    /// request stands. `None` when the request is not one an access policy asked for.
    pub async fn pending_approval_notice(
        &self,
        session_id: warpgate_common::UserSessionId,
        target_name: &str,
    ) -> Option<String> {
        let context =
            AccessApprovalContext::find(&self.db, session_id, ApprovalKind::Admin, target_name)
                .await
                .ok()
                .flatten()?;
        let minutes = ((context.expires_at - OffsetDateTime::now_utc()).whole_seconds() + 59) / 60;
        let account = context
            .account_name
            .as_deref()
            .map(|name| format!(" as {name}"))
            .unwrap_or_default();
        Some(format!(
            "Approval is required to connect to {target_name}{account}: {} \
             The request waits {} more minute(s).",
            context.reason,
            minutes.max(0)
        ))
    }
}
