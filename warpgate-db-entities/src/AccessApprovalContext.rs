//! What an access policy adds to an administrator's approval request
//! (`session_approval_requests`): why it was needed, which account it is for, how long the
//! request waits, and how long an approval can be used. One row per request, under the same
//! key, so the approval system itself (the request, its decision, its status, its audit trail)
//! stays one system.
//!
//! The lifecycle, on top of the request's own `pending` → `approved` / `rejected` /
//! `timed_out` / `abandoned`:
//!
//! * `expires_at`: when an unanswered request lapses. An approver cannot approve it after.
//! * `valid_until`: set when it is approved: the last moment the approval can start a
//!   connection. Separate from `expires_at`, and never a session length.
//! * `used_at`: set when a connection started on it. An approval is single use: the update
//!   that sets it is conditional, so two attempts racing for one approval cannot both win.
//!
//! "Expired" is therefore `timed_out`, or `approved` past `valid_until` unused; "used" is
//! `approved` with `used_at` set. Both are derived, never stored, so they cannot disagree
//! with the request.

use sea_orm::entity::prelude::*;
use sea_orm::{Condition, QueryFilter};
use time::OffsetDateTime;
use uuid::Uuid;
use warpgate_common::auth::ApprovalKind;
use warpgate_common::{RuleApproval, UserSessionId};

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "access_approval_contexts")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub session_id: UserSessionId,
    #[sea_orm(primary_key, auto_increment = false)]
    pub kind: ApprovalKind,
    #[sea_orm(primary_key, auto_increment = false)]
    pub target: String,
    /// The policy that required approval; `None` once it was deleted.
    pub policy_id: Option<Uuid>,
    /// The policy's name when the request was made.
    #[sea_orm(column_type = "String(StringLen::N(256))")]
    pub policy_name: String,
    /// Why approval was required, in words an approver reads.
    #[sea_orm(column_type = "Text")]
    pub reason: String,
    /// The user the approval is for. Checked again when it is used.
    pub user_id: Uuid,
    pub target_id: Uuid,
    /// The account the approval is for; `None` on a protocol with no remote accounts.
    pub target_account_id: Option<Uuid>,
    #[sea_orm(column_type = "String(StringLen::N(300))", nullable)]
    pub account_name: Option<String>,
    pub expires_at: OffsetDateTime,
    /// How long an approval stays usable once given.
    pub valid_for_seconds: i64,
    pub valid_until: Option<OffsetDateTime>,
    pub used_at: Option<OffsetDateTime>,
    /// The approver lists of the policies that required it, as they were when the request was
    /// made: an array of [`RuleApproval`], one per policy that named approvers. Whoever
    /// approves must satisfy every one.
    pub terms: serde_json::Value,
    pub created_at: OffsetDateTime,
}

impl Model {
    /// The approver constraints. Unreadable ones are an impossible constraint (nobody
    /// satisfies it), never "no constraint".
    pub fn approver_constraints(&self) -> Vec<RuleApproval> {
        serde_json::from_value(self.terms.clone()).unwrap_or_else(|_| {
            vec![RuleApproval {
                approver_user_ids: vec![Uuid::nil()],
                ..RuleApproval::default()
            }]
        })
    }
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

fn key_filter(session_id: UserSessionId, kind: ApprovalKind, target: &str) -> Condition {
    Condition::all()
        .add(Column::SessionId.eq(session_id))
        .add(Column::Kind.eq(kind))
        .add(Column::Target.eq(target))
}

pub async fn find(
    db: &DatabaseConnection,
    session_id: UserSessionId,
    kind: ApprovalKind,
    target: &str,
) -> Result<Option<Model>, DbErr> {
    Entity::find()
        .filter(key_filter(session_id, kind, target))
        .one(db)
        .await
}

/// Forget a request's context (its request row is being replaced, or is gone).
pub async fn delete(
    db: &DatabaseConnection,
    session_id: UserSessionId,
    kind: ApprovalKind,
    target: &str,
) -> Result<(), DbErr> {
    Entity::delete_many()
        .filter(key_filter(session_id, kind, target))
        .exec(db)
        .await?;
    Ok(())
}

/// Record that the request is being approved: from now, it can start a connection for
/// `valid_for_seconds`. Only the first approval counts; returns whether this was it. Written
/// *before* the request itself is marked approved, so an approved request is never without it
/// (and an approval nobody can use is the only thing a failed race leaves behind).
pub async fn mark_approved(
    db: &DatabaseConnection,
    session_id: UserSessionId,
    kind: ApprovalKind,
    target: &str,
    now: OffsetDateTime,
) -> Result<bool, DbErr> {
    let Some(context) = find(db, session_id, kind, target).await? else {
        return Ok(false);
    };
    let valid_until = now + time::Duration::seconds(context.valid_for_seconds);
    let result = Entity::update_many()
        .col_expr(Column::ValidUntil, valid_until.into())
        .filter(key_filter(session_id, kind, target))
        .filter(Column::ValidUntil.is_null())
        .filter(Column::UsedAt.is_null())
        .exec(db)
        .await?;
    Ok(result.rows_affected == 1)
}

/// What a connection claims about itself when it spends an approval. All of it is checked in
/// the same statement that spends it.
pub struct Claim<'a> {
    pub session_id: UserSessionId,
    pub kind: ApprovalKind,
    pub target: &'a str,
    pub user_id: Uuid,
    pub target_id: Uuid,
    /// The account the connection will sign in as.
    pub target_account_id: Option<Uuid>,
}

/// Spend the approval, once. The single conditional `UPDATE` is the whole check: the approval
/// must be for this user, this target and this account, be approved and within its validity,
/// and be unspent; of any number of concurrent attempts exactly one changes the row.
pub async fn consume(
    db: &DatabaseConnection,
    claim: &Claim<'_>,
    now: OffsetDateTime,
) -> Result<bool, DbErr> {
    let mut update = Entity::update_many()
        .col_expr(Column::UsedAt, now.into())
        .filter(key_filter(claim.session_id, claim.kind, claim.target))
        .filter(Column::UserId.eq(claim.user_id))
        .filter(Column::TargetId.eq(claim.target_id))
        .filter(Column::UsedAt.is_null())
        .filter(Column::ValidUntil.gte(now));
    update = match claim.target_account_id {
        Some(account) => update.filter(Column::TargetAccountId.eq(account)),
        None => update.filter(Column::TargetAccountId.is_null()),
    };
    Ok(update.exec(db).await?.rows_affected == 1)
}

/// Remove the contexts older than `cutoff` whose request is gone (cleaned up with the old
/// requests themselves).
pub async fn delete_orphans_before(
    db: &DatabaseConnection,
    cutoff: OffsetDateTime,
) -> Result<(), DbErr> {
    let old = Entity::find()
        .filter(Column::CreatedAt.lt(cutoff))
        .all(db)
        .await?;
    for context in old {
        let request = super::SessionApprovalRequest::Entity::find_by_id((
            context.session_id,
            context.kind,
            context.target.clone(),
        ))
        .one(db)
        .await?;
        if request.is_none() {
            delete(db, context.session_id, context.kind, &context.target).await?;
        }
    }
    Ok(())
}
