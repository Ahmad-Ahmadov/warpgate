//! An access policy: *when* connections may start, and what happens outside those times,
//! for the users, targets and accounts it covers.
//!
//! The scope is the set of columns that are filled in; a policy applies to a connection only
//! when every one of them matches it:
//!
//! | `user_id` | `role_id` | `target_id` | `target_account_id` | covers |
//! |---|---|---|---|---|
//! | set | | | | one user, everywhere |
//! | | set | | | the members of an access group (a role), everywhere |
//! | | | set | | everyone, on one target |
//! | set | | set | | one user on one target |
//! | | set | set | | the members of a group on one target |
//! | set | | set | set | one user as one account on one target |
//!
//! A direct assignment's own schedule is the last row, with `assignment_id` set so it is
//! edited with the assignment and goes when the assignment does. At least one scope column is
//! always set: there is no global policy.
//!
//! Policies only ever restrict (see `warpgate_core::access_policy` for how several combine),
//! and a policy never grants access: that is the assignment's job.

use sea_orm::entity::prelude::*;
use serde::Serialize;
use time::OffsetDateTime;
use uuid::Uuid;
use warpgate_common::AccessRules;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize)]
#[sea_orm(table_name = "access_policies")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    #[sea_orm(column_type = "String(StringLen::N(256))")]
    pub name: String,
    #[sea_orm(column_type = "Text")]
    pub description: String,
    pub enabled: bool,
    pub user_id: Option<Uuid>,
    /// An access group: a role.
    pub role_id: Option<Uuid>,
    pub target_id: Option<Uuid>,
    pub target_account_id: Option<Uuid>,
    /// The direct assignment this is the schedule of, if it is one.
    pub assignment_id: Option<Uuid>,
    /// An [`AccessRules`].
    pub rules: serde_json::Value,
    pub created_by: Option<Uuid>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

impl Model {
    /// The rules, decoded. A policy whose rules cannot be read is treated as denying: see
    /// `warpgate_core::access_policy`.
    pub fn rules(&self) -> Result<AccessRules, serde_json::Error> {
        serde_json::from_value(self.rules.clone())
    }

    /// Whether the policy belongs to one direct assignment rather than standing alone.
    pub const fn is_assignment_schedule(&self) -> bool {
        self.assignment_id.is_some()
    }
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
