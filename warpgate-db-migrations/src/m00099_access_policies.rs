//! Access policies: schedules and approval rules for connections, and the approval context
//! an administrator's approval request carries when a policy required it.
//!
//! Two new tables and nothing altered, so existing assignments, approvals and the targets'
//! own "require approval" setting keep working untouched:
//!
//! * `access_policies`: who and what a set of rules covers, and the rules (an `AccessRules`
//!   as JSON). A connection with no policy that covers it behaves exactly as before.
//! * `access_approval_contexts`: one row beside a `session_approval_requests` row, under the
//!   same key, for requests a policy required: why, which account, how long the request
//!   waits, how long the approval is good, and whether it was used.
//!
//! `down` drops both; the approval requests themselves stay as they were.

use sea_orm::Schema;
use sea_orm_migration::prelude::*;

pub mod access_policy {
    use sea_orm::entity::prelude::*;
    use time::OffsetDateTime;
    use uuid::Uuid;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
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
        pub role_id: Option<Uuid>,
        pub target_id: Option<Uuid>,
        pub target_account_id: Option<Uuid>,
        pub assignment_id: Option<Uuid>,
        pub rules: serde_json::Value,
        pub created_by: Option<Uuid>,
        pub created_at: OffsetDateTime,
        pub updated_at: OffsetDateTime,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

pub mod access_approval_context {
    use sea_orm::entity::prelude::*;
    use time::OffsetDateTime;
    use uuid::Uuid;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "access_approval_contexts")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub session_id: Uuid,
        #[sea_orm(primary_key, auto_increment = false)]
        #[sea_orm(column_type = "String(StringLen::N(16))")]
        pub kind: String,
        #[sea_orm(primary_key, auto_increment = false)]
        pub target: String,
        pub policy_id: Option<Uuid>,
        #[sea_orm(column_type = "String(StringLen::N(256))")]
        pub policy_name: String,
        #[sea_orm(column_type = "Text")]
        pub reason: String,
        pub user_id: Uuid,
        pub target_id: Uuid,
        pub target_account_id: Option<Uuid>,
        #[sea_orm(column_type = "String(StringLen::N(300))", nullable)]
        pub account_name: Option<String>,
        pub expires_at: OffsetDateTime,
        pub valid_for_seconds: i64,
        pub valid_until: Option<OffsetDateTime>,
        pub used_at: Option<OffsetDateTime>,
        pub terms: serde_json::Value,
        pub created_at: OffsetDateTime,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let schema = Schema::new(manager.get_database_backend());

        manager
            .create_table(schema.create_table_from_entity(access_policy::Entity))
            .await?;
        for (name, column) in [
            ("idx_access_policies_user", access_policy::Column::UserId),
            ("idx_access_policies_role", access_policy::Column::RoleId),
            (
                "idx_access_policies_target",
                access_policy::Column::TargetId,
            ),
        ] {
            manager
                .create_index(
                    Index::create()
                        .name(name)
                        .table(access_policy::Entity)
                        .col(column)
                        .to_owned(),
                )
                .await?;
        }
        // One schedule per assignment. Policies that are not an assignment's have no value
        // here, and a unique index lets any number of them share that.
        manager
            .create_index(
                Index::create()
                    .name("idx_access_policies_assignment")
                    .table(access_policy::Entity)
                    .col(access_policy::Column::AssignmentId)
                    .unique()
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(schema.create_table_from_entity(access_approval_context::Entity))
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_access_approval_contexts_user")
                    .table(access_approval_context::Entity)
                    .col(access_approval_context::Column::UserId)
                    .col(access_approval_context::Column::TargetId)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(access_approval_context::Entity)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(Table::drop().table(access_policy::Entity).to_owned())
            .await
    }
}
