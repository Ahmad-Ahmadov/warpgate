use sea_orm_migration::prelude::*;

use super::m00020_ldap_server::ldap_server;

const COLUMN: &str = "authenticate_users";

/// Whether users linked to an LDAP server sign in with their directory
/// password, checked by binding to the server. Off for existing servers, so
/// upgrading changes no one's login until an administrator turns it on.
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(ldap_server::Entity)
                    .add_column(
                        ColumnDef::new(Alias::new(COLUMN))
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(ldap_server::Entity)
                    .drop_column(Alias::new(COLUMN))
                    .to_owned(),
            )
            .await
    }
}
