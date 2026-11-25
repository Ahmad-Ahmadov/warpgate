use std::fmt::Display;

use sea_orm::{DatabaseBackend, DatabaseConnection, TransactionTrait};
use sea_orm_migration::MigrationTrait;
use sea_orm_migration::prelude::*;

mod m00001_create_ticket;
mod m00002_create_session;
mod m00003_create_recording;
mod m00004_create_known_host;
mod m00005_create_log_entry;
mod m00006_add_session_protocol;
mod m00007_targets_and_roles;
mod m00008_users;
mod m00009_credential_models;
mod m00010_parameters;
mod m00011_rsa_key_algos;
mod m00012_add_openssh_public_key_label;
mod m00013_add_openssh_public_key_dates;
mod m00014_api_tokens;
mod m00015_fix_public_key_dates;
mod m00016_fix_public_key_length;
mod m00017_descriptions;
mod m00018_ticket_description;
mod m00019_rate_limits;
mod m00020_ldap_server;
mod m00020_target_groups;
mod m00021_user_ldap_link;
mod m00023_ldap_username_attribute;
mod m00024_ssh_key_attribute;
mod m00025_ldap_uuid_attribute;
mod m00025_ssh_client_auth;
mod m00027_ca;
mod m00028_certificate_credentials;
mod m00029_certificate_revocation;
mod m00030_add_recording_metadata;
mod m00031_minimize_password_login;
mod m00032_admin_roles;
mod m00033_add_log_target;
mod m00034_add_log_related_fields;
mod m00035_ticket_user_target_id;
mod m00036_user_role_expiry_history;
mod m00037_allowed_ip_range;
mod m00037_database_target_auth;
mod m00037_show_session_menu;
mod m00038_fix_target_auth_tags;
mod m00041_fix_user_role_assignment_dates;
mod m00042_database_target_auth_again;
mod m00043_unique_usernames;
mod m00044_ticket_requests;
mod m00045_role_default_flag;
mod m00046_max_api_token_duration;
mod m00047_record_scp;
mod m00048_target_click_action;
mod m00049_text_columns;
mod m00050_password_policy;
mod m00051_tutorial_dismissed;
mod m00052_log_text_column;
mod m00053_login_protection;
mod m00054_login_protection_params;
mod m00055_ssh_banner;
mod m00056_web_ssh_enabled;
mod m00057_password_login_mode;
mod m00058_analytics;
mod m00059_web_auth_max_age;
mod m00060_recording_generation;
mod m00061_rename_web_ssh_enabled;
mod m00062_web_approval_grace_period;
mod m00063_recordings_storage;
mod m00064_cluster;
mod m00065_authorization_indexes;
mod m00066_cluster_token;
mod m00067_node_tls_pin;
mod m00068_rename_ssh_banner;
mod m00069_ssh_client_keys;
mod m00070_http_sessions;
mod m00071_ssh_host_key_verification;
mod m00072_session_node_id_not_null;
mod m00073_redact_session_target_snapshots;
mod m00074_encryption_key_rotation;
mod m00075_hash_ticket_and_api_token_secrets;
mod m00076_open_targets_in_new_tab;
mod m00077_session_user_target_id;
mod m00078_assignment_composite_pks;
mod m00079_unique_target_and_group_names;
mod m00080_user_and_target_sessions;
mod m00081_http_session_user_session_id;
mod m00082_target_session_columns;
mod m00083_record_desktop_keyboard_input;
mod m00084_mfa_enforcement;
mod m00085_default_credential_policy;
mod m00086_jit_session_approval;
mod m00087_drop_null_target_options;
mod m00088_ssh_host_keys;
mod m00089_secret_backends;
mod m00090_logo;
mod m00091_drop_cluster_token;
mod m00092_http_session_sso_identity;
mod m00093_log_session_id_nullable;
mod m00094_unique_role_names;
mod m00095_kubernetes_sessions;
mod m00096_ldap_authenticate_users;
mod m00097_target_account_bindings;
mod m00098_unified_access_control;
mod m00099_access_policies;

pub(crate) mod helpers;

pub use m00098_unified_access_control::preview as preview_access_control_migration;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m00001_create_ticket::Migration),
            Box::new(m00002_create_session::Migration),
            Box::new(m00003_create_recording::Migration),
            Box::new(m00004_create_known_host::Migration),
            Box::new(m00005_create_log_entry::Migration),
            Box::new(m00006_add_session_protocol::Migration),
            Box::new(m00007_targets_and_roles::Migration),
            Box::new(m00008_users::Migration),
            Box::new(m00009_credential_models::Migration),
            Box::new(m00010_parameters::Migration),
            Box::new(m00011_rsa_key_algos::Migration),
            Box::new(m00012_add_openssh_public_key_label::Migration),
            Box::new(m00013_add_openssh_public_key_dates::Migration),
            Box::new(m00014_api_tokens::Migration),
            Box::new(m00015_fix_public_key_dates::Migration),
            Box::new(m00016_fix_public_key_length::Migration),
            Box::new(m00017_descriptions::Migration),
            Box::new(m00018_ticket_description::Migration),
            Box::new(m00019_rate_limits::Migration),
            Box::new(m00020_target_groups::Migration),
            Box::new(m00020_ldap_server::Migration),
            Box::new(m00021_user_ldap_link::Migration),
            Box::new(m00023_ldap_username_attribute::Migration),
            Box::new(m00024_ssh_key_attribute::Migration),
            Box::new(m00025_ldap_uuid_attribute::Migration),
            Box::new(m00025_ssh_client_auth::Migration),
            Box::new(m00027_ca::Migration),
            Box::new(m00028_certificate_credentials::Migration),
            Box::new(m00029_certificate_revocation::Migration),
            Box::new(m00030_add_recording_metadata::Migration),
            Box::new(m00031_minimize_password_login::Migration),
            Box::new(m00032_admin_roles::Migration),
            Box::new(m00033_add_log_target::Migration),
            Box::new(m00034_add_log_related_fields::Migration),
            Box::new(m00035_ticket_user_target_id::Migration),
            Box::new(m00036_user_role_expiry_history::Migration),
            Box::new(m00037_database_target_auth::Migration),
            Box::new(m00038_fix_target_auth_tags::Migration),
            Box::new(m00037_show_session_menu::Migration),
            Box::new(m00037_allowed_ip_range::Migration),
            Box::new(m00041_fix_user_role_assignment_dates::Migration),
            Box::new(m00042_database_target_auth_again::Migration),
            Box::new(m00043_unique_usernames::Migration),
            Box::new(m00044_ticket_requests::Migration),
            Box::new(m00045_role_default_flag::Migration),
            Box::new(m00046_max_api_token_duration::Migration),
            Box::new(m00047_record_scp::Migration),
            Box::new(m00048_target_click_action::Migration),
            Box::new(m00049_text_columns::Migration),
            Box::new(m00050_password_policy::Migration),
            Box::new(m00051_tutorial_dismissed::Migration),
            Box::new(m00052_log_text_column::Migration),
            Box::new(m00053_login_protection::Migration),
            Box::new(m00054_login_protection_params::Migration),
            Box::new(m00055_ssh_banner::Migration),
            Box::new(m00056_web_ssh_enabled::Migration),
            Box::new(m00057_password_login_mode::Migration),
            Box::new(m00058_analytics::Migration),
            Box::new(m00059_web_auth_max_age::Migration),
            Box::new(m00060_recording_generation::Migration),
            Box::new(m00061_rename_web_ssh_enabled::Migration),
            Box::new(m00062_web_approval_grace_period::Migration),
            Box::new(m00063_recordings_storage::Migration),
            Box::new(m00064_cluster::Migration),
            Box::new(m00065_authorization_indexes::Migration),
            Box::new(m00066_cluster_token::Migration),
            Box::new(m00067_node_tls_pin::Migration),
            Box::new(m00068_rename_ssh_banner::Migration),
            Box::new(m00069_ssh_client_keys::Migration),
            Box::new(m00070_http_sessions::Migration),
            Box::new(m00071_ssh_host_key_verification::Migration),
            Box::new(m00072_session_node_id_not_null::Migration),
            Box::new(m00073_redact_session_target_snapshots::Migration),
            Box::new(m00074_encryption_key_rotation::Migration),
            Box::new(m00075_hash_ticket_and_api_token_secrets::Migration),
            Box::new(m00076_open_targets_in_new_tab::Migration),
            Box::new(m00077_session_user_target_id::Migration),
            Box::new(m00078_assignment_composite_pks::Migration),
            Box::new(m00079_unique_target_and_group_names::Migration),
            Box::new(m00080_user_and_target_sessions::Migration),
            Box::new(m00081_http_session_user_session_id::Migration),
            Box::new(m00082_target_session_columns::Migration),
            Box::new(m00083_record_desktop_keyboard_input::Migration),
            Box::new(m00084_mfa_enforcement::Migration),
            Box::new(m00085_default_credential_policy::Migration),
            Box::new(m00086_jit_session_approval::Migration),
            Box::new(m00087_drop_null_target_options::Migration),
            Box::new(m00088_ssh_host_keys::Migration),
            Box::new(m00089_secret_backends::Migration),
            Box::new(m00090_logo::Migration),
            Box::new(m00091_drop_cluster_token::Migration),
            Box::new(m00092_http_session_sso_identity::Migration),
            Box::new(m00093_log_session_id_nullable::Migration),
            Box::new(m00094_unique_role_names::Migration),
            Box::new(m00095_kubernetes_sessions::Migration),
            Box::new(m00096_ldap_authenticate_users::Migration),
            Box::new(m00097_target_account_bindings::Migration),
            Box::new(m00098_unified_access_control::Migration),
            Box::new(m00099_access_policies::Migration),
        ]
    }
}

/// Where a database stands with the access-control migration (m00098).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessControlMigrationState {
    /// Every earlier migration has run, and m00098 has not: it can be previewed.
    Pending,
    /// Earlier migrations have not run either: the preview needs the release before this one.
    EarlierMigrationsPending,
    /// m00098 has run; its report is in Access Control, Migration review.
    Applied,
}

const ACCESS_CONTROL_MIGRATION: &str = "m00098_unified_access_control";

pub async fn access_control_migration_state<C: ConnectionTrait>(
    db: &C,
) -> Result<AccessControlMigrationState, DbErr> {
    let pending: Vec<String> = Migrator::get_pending_migrations(db)
        .await?
        .iter()
        .map(|migration| migration.name().to_owned())
        .collect();
    let Some(position) = pending
        .iter()
        .position(|name| name == ACCESS_CONTROL_MIGRATION)
    else {
        return Ok(AccessControlMigrationState::Applied);
    };
    Ok(if position == 0 {
        AccessControlMigrationState::Pending
    } else {
        AccessControlMigrationState::EarlierMigrationsPending
    })
}

const MIGRATION_LOCK_KEY: i64 = 0x1337_1337_1337_1337;

async fn run_locked<
    RF: Future<Output = Result<R, DbErr>> + Send,
    F: FnOnce() -> RF + Send,
    R: Send,
>(
    connection: &DatabaseConnection,
    key: impl Display,
    f: F,
) -> Result<R, DbErr> {
    use sea_orm::{ConnectionTrait, DatabaseBackend, Statement, TransactionTrait};

    match connection.get_database_backend() {
        DatabaseBackend::Postgres => {
            let lock = connection.begin().await?;
            // lock is tx scoped
            lock.execute(Statement::from_string(
                DatabaseBackend::Postgres,
                format!("SELECT pg_advisory_xact_lock({key})"),
            ))
            .await?;
            let result = f().await;
            lock.commit().await?;
            result
        }
        DatabaseBackend::MySql => {
            let lock = connection.begin().await?;
            // lock is session scoped
            lock.execute(Statement::from_string(
                DatabaseBackend::MySql,
                format!("SELECT GET_LOCK('warpgate_migration_{key}', -1)"),
            ))
            .await?;
            let result = f().await;
            let release = lock
                .execute(Statement::from_string(
                    DatabaseBackend::MySql,
                    format!("SELECT RELEASE_LOCK('warpgate_migration_{key}')"),
                ))
                .await;
            lock.commit().await?;
            release?;
            result
        }
        DatabaseBackend::Sqlite => f().await,
    }
}

/// Migrations need an explicit TX on SQLite, otherwise pooled connections
/// might see different DB state
pub async fn migrate_database(connection: &DatabaseConnection) -> Result<(), DbErr> {
    run_locked(connection, MIGRATION_LOCK_KEY, async move || {
        run_maybe_in_tx(connection, Direction::Up, None).await
    })
    .await?;

    Ok(())
}

/// Apply `steps` pending migrations.
pub async fn migrate_database_up(connection: &DatabaseConnection, steps: u32) -> Result<(), DbErr> {
    run_maybe_in_tx(connection, Direction::Up, Some(steps)).await
}

/// Revert `steps` applied migrations.
pub async fn migrate_database_down(
    connection: &DatabaseConnection,
    steps: u32,
) -> Result<(), DbErr> {
    run_maybe_in_tx(connection, Direction::Down, Some(steps)).await
}

enum Direction {
    Up,
    Down,
}

/// Migrations need an explicit TX on SQLite (only), otherwise pooled connections
/// might see different DB state
async fn run_maybe_in_tx(
    connection: &DatabaseConnection,
    direction: Direction,
    steps: Option<u32>,
) -> Result<(), DbErr> {
    if connection.get_database_backend() == DatabaseBackend::Sqlite {
        let tx = connection.begin().await?;
        run(&tx, direction, steps).await?;
        tx.commit().await
    } else {
        run(connection, direction, steps).await
    }
}

async fn run<'c, C: IntoSchemaManagerConnection<'c>>(
    db: C,
    direction: Direction,
    steps: Option<u32>,
) -> Result<(), DbErr> {
    match direction {
        Direction::Up => Migrator::up(db, steps).await,
        Direction::Down => Migrator::down(db, steps).await,
    }
}

#[cfg(test)]
mod tests {
    use sea_orm::{ConnectOptions, Database};
    use warpgate_db_entities::Parameters::{ConfigMigrationValues, set_config_migration_values};

    use super::{migrate_database, migrate_database_down, migrate_database_up};

    /// The full chain, and a step back and forth, through a pooled file-backed
    /// SQLite connection - the shape a real install uses.
    #[tokio::test]
    async fn sqlite_migrations_run_through_a_pool() {
        set_config_migration_values(ConfigMigrationValues::default());
        let path = std::env::temp_dir().join(format!(
            "warpgate-migrations-{}.sqlite3",
            std::process::id()
        ));
        let mut opt = ConnectOptions::new(format!("sqlite://{}?mode=rwc", path.display()));
        opt.max_connections(100);
        let db = Database::connect(opt).await.unwrap();

        migrate_database(&db).await.unwrap();
        migrate_database_down(&db, 1).await.unwrap();
        migrate_database_up(&db, 1).await.unwrap();

        db.close().await.unwrap();
        std::fs::remove_file(path).unwrap();
    }

    /// 20, 25, 26: the access-control migration on a database as m00097 left it. Access is
    /// carried over, a rollback puts the credentials back in the target's settings, and
    /// running it again gives the same result. The deployed m00097 keeps its place.
    #[tokio::test]
    async fn the_access_control_migration_carries_access_over_and_reruns_cleanly() {
        use sea_orm::{ActiveModelTrait, EntityTrait, PaginatorTrait, Set};
        use sea_orm_migration::{MigrationName, MigratorTrait};
        use time::OffsetDateTime;
        use uuid::Uuid;
        use warpgate_db_entities::{
            AccessAssignment, AccessGroupExclusion, AccessGroupGrant, AccessMigrationReview, Role,
            Target, TargetAccount, TargetAccountBinding, TargetRoleAssignment, User,
            UserRoleAssignment,
        };

        use super::{AccessControlMigrationState, Migrator, access_control_migration_state};

        set_config_migration_values(ConfigMigrationValues::default());
        let db = Database::connect("sqlite::memory:").await.unwrap();
        let names: Vec<String> = Migrator::migrations()
            .iter()
            .map(|migration| migration.name().to_owned())
            .collect();
        let m00097 = names
            .iter()
            .position(|name| name == "m00097_target_account_bindings")
            .unwrap();
        assert_eq!(
            names.get(m00097 + 1).map(String::as_str),
            Some("m00098_unified_access_control"),
            "the deployed m00097 is not rewritten; the change is a new migration after it"
        );
        migrate_database_up(&db, u32::try_from(m00097 + 1).unwrap())
            .await
            .unwrap();
        assert_eq!(
            access_control_migration_state(&db).await.unwrap(),
            AccessControlMigrationState::Pending
        );

        let now = OffsetDateTime::now_utc();
        let mut users = vec![];
        for name in ["ahmad", "yusif"] {
            let id = Uuid::new_v4();
            User::ActiveModel {
                id: Set(id),
                username: Set(name.into()),
                description: Set(String::new()),
                credential_policy: Set(serde_json::json!({})),
                rate_limit_bytes_per_second: Set(None),
                ldap_server_id: Set(None),
                ldap_object_uuid: Set(None),
                allowed_ip_ranges: Set(serde_json::Value::Null),
            }
            .insert(&db)
            .await
            .unwrap();
            users.push(id);
        }
        let (ahmad, yusif) = (users[0], users[1]);
        let ops = Uuid::new_v4();
        Role::ActiveModel {
            id: Set(ops),
            name: Set("ops".into()),
            description: Set(String::new()),
            is_default: Set(false),
        }
        .insert(&db)
        .await
        .unwrap();
        for user_id in [ahmad, yusif] {
            UserRoleAssignment::ActiveModel {
                user_id: Set(user_id),
                role_id: Set(ops),
                granted_at: Set(Some(now)),
                expires_at: Set(None),
                revoked_at: Set(None),
            }
            .insert(&db)
            .await
            .unwrap();
        }
        let server = Uuid::new_v4();
        Target::ActiveModel {
            id: Set(server),
            name: Set("LINUX-SRV-01".into()),
            description: Set(String::new()),
            kind: Set(warpgate_db_entities::Target::TargetKind::Ssh),
            options: Set(serde_json::json!({"ssh": {"host": "h", "username": "deploy"}})),
            rate_limit_bytes_per_second: Set(None),
            group_id: Set(None),
            ticket_max_duration_seconds: Set(None),
            ticket_requests_disabled: Set(false),
            ticket_require_approval: Set(false),
            ticket_max_uses: Set(None),
            require_approval: Set(false),
        }
        .insert(&db)
        .await
        .unwrap();
        TargetRoleAssignment::ActiveModel {
            target_id: Set(server),
            role_id: Set(ops),
        }
        .insert(&db)
        .await
        .unwrap();
        TargetAccountBinding::ActiveModel {
            id: Set(Uuid::new_v4()),
            user_id: Set(yusif),
            target_id: Set(server),
            account_kind: Set(TargetAccountBinding::LegacyAccountKind::Local),
            account_name: Set(Some("admin".into())),
            ldap_server_id: Set(None),
            ldap_object_uuid: Set(None),
            username_format: Set(None),
            auth_method: Set(TargetAccountBinding::LegacyAuthMethod::TargetCredential),
            enabled: Set(true),
            expires_at: Set(None),
            created_by: Set(None),
            created_at: Set(now),
            updated_at: Set(now),
            account_key: Set("local:admin".into()),
        }
        .insert(&db)
        .await
        .unwrap();

        async fn counts(db: &sea_orm::DatabaseConnection) -> [u64; 5] {
            [
                TargetAccount::Entity::find().count(db).await.unwrap(),
                AccessAssignment::Entity::find().count(db).await.unwrap(),
                AccessGroupGrant::Entity::find().count(db).await.unwrap(),
                AccessGroupExclusion::Entity::find()
                    .count(db)
                    .await
                    .unwrap(),
                AccessMigrationReview::Entity::find()
                    .count(db)
                    .await
                    .unwrap(),
            ]
        }

        migrate_database_up(&db, 1).await.unwrap();
        assert_eq!(
            access_control_migration_state(&db).await.unwrap(),
            AccessControlMigrationState::Applied
        );
        let first = counts(&db).await;
        // deploy (primary) and admin; yusif's binding; the role's grant; yusif excluded from it
        assert_eq!(&first[..4], &[2, 1, 1, 1]);
        let options = Target::Entity::find_by_id(server)
            .one(&db)
            .await
            .unwrap()
            .unwrap()
            .options;
        assert_eq!(
            options["ssh"]["username"], "",
            "the credential moved to the account"
        );
        // The earlier tables are left as they were, for a rollback.
        assert_eq!(
            TargetRoleAssignment::Entity::find()
                .count(&db)
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            TargetAccountBinding::Entity::find()
                .count(&db)
                .await
                .unwrap(),
            1
        );

        migrate_database_down(&db, 1).await.unwrap();
        let options = Target::Entity::find_by_id(server)
            .one(&db)
            .await
            .unwrap()
            .unwrap()
            .options;
        assert_eq!(
            options["ssh"]["username"], "deploy",
            "a rollback restores the settings"
        );

        migrate_database_up(&db, 1).await.unwrap();
        assert_eq!(
            counts(&db).await,
            first,
            "running it again gives the same result"
        );
    }
}
