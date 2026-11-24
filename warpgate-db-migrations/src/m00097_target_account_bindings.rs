use sea_orm::Schema;
use sea_orm_migration::prelude::*;

/// Which remote account a user may sign in to a target as: an administrator's explicit
/// assignment of user, target and account. A new table, so existing installations keep
/// behaving as before until an administrator assigns accounts.
pub mod target_account_binding {
    use sea_orm::entity::prelude::*;
    use time::OffsetDateTime;
    use uuid::Uuid;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "target_account_bindings")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub user_id: Uuid,
        pub target_id: Uuid,
        #[sea_orm(column_type = "String(StringLen::N(16))")]
        pub account_kind: String,
        #[sea_orm(column_type = "String(StringLen::N(256))", nullable)]
        pub account_name: Option<String>,
        pub ldap_server_id: Option<Uuid>,
        pub ldap_object_uuid: Option<Uuid>,
        #[sea_orm(column_type = "String(StringLen::N(16))", nullable)]
        pub username_format: Option<String>,
        #[sea_orm(column_type = "String(StringLen::N(32))")]
        pub auth_method: String,
        pub enabled: bool,
        pub expires_at: Option<OffsetDateTime>,
        pub created_by: Option<Uuid>,
        pub created_at: OffsetDateTime,
        pub updated_at: OffsetDateTime,
        #[sea_orm(column_type = "String(StringLen::N(300))")]
        pub account_key: String,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {
        #[sea_orm(
            belongs_to = "crate::m00044_ticket_requests::user::Entity",
            from = "Column::UserId",
            to = "crate::m00044_ticket_requests::user::Column::Id",
            on_delete = "Cascade"
        )]
        User,
        #[sea_orm(
            belongs_to = "crate::m00007_targets_and_roles::target::Entity",
            from = "Column::TargetId",
            to = "crate::m00007_targets_and_roles::target::Column::Id",
            on_delete = "Cascade"
        )]
        Target,
        #[sea_orm(
            belongs_to = "crate::m00020_ldap_server::ldap_server::Entity",
            from = "Column::LdapServerId",
            to = "crate::m00020_ldap_server::ldap_server::Column::Id",
            on_delete = "Cascade"
        )]
        LdapServer,
        #[sea_orm(
            belongs_to = "crate::m00044_ticket_requests::user::Entity",
            from = "Column::CreatedBy",
            to = "crate::m00044_ticket_requests::user::Column::Id",
            on_delete = "SetNull"
        )]
        CreatedBy,
    }

    impl ActiveModelBehavior for ActiveModel {}
}

use target_account_binding::{Column, Entity};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let schema = Schema::new(manager.get_database_backend());
        manager
            .create_table(schema.create_table_from_entity(Entity))
            .await?;
        // One assignment per user, target and account. `account_key` names the account in a
        // form that does not change with how it is written (the directory entry's UUID, or
        // the local name in lower case), so the same account cannot be assigned twice.
        manager
            .create_index(
                Index::create()
                    .name("idx_target_account_bindings_unique")
                    .table(Entity)
                    .col(Column::UserId)
                    .col(Column::TargetId)
                    .col(Column::AccountKey)
                    .unique()
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_target_account_bindings_target")
                    .table(Entity)
                    .col(Column::TargetId)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Entity).to_owned())
            .await
    }
}
