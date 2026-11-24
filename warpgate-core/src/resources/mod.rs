pub mod access_groups;
pub mod roles;
pub mod target_accounts;
pub mod target_groups;
pub mod targets;

use sea_orm::DbErr;
use warpgate_common::{UserSessionId, WarpgateError};

use crate::db::is_unique_violation;

#[derive(Debug, thiserror::Error)]
pub enum ResourceError {
    #[error("name is empty")]
    EmptyName,
    #[error("name already taken")]
    NameTaken,
    #[error("not found")]
    NotFound,
    #[error("a target's protocol cannot be changed after creation")]
    ProtocolChange,
    #[error("the role is already assigned")]
    RoleAlreadyAssigned,
    /// The target already has an account by that name (or a linked directory account in
    /// that format).
    #[error("the target already has this account")]
    AccountTaken,
    /// A legacy role grant on a target with accounts, and the target has no primary
    /// account for it to grant: the grant has to name an account (Access Control).
    #[error(
        "this target has no primary account to grant: grant one of its accounts in Access Control, Access groups"
    )]
    NoPrimaryAccount,
    #[error("{0}")]
    Invalid(&'static str),

    #[error(transparent)]
    Other(#[from] WarpgateError),
}

impl From<DbErr> for ResourceError {
    fn from(err: DbErr) -> Self {
        Self::Other(err.into())
    }
}

impl From<ResourceError> for WarpgateError {
    fn from(err: ResourceError) -> Self {
        match err {
            ResourceError::Other(err) => err,
            err => Self::Other(Box::new(err)),
        }
    }
}

/// Open sessions admitted by rows that a delete removed. Closing them needs the
/// session registry and cluster peers, so the caller does it once the delete has
/// committed, with [`crate::Services::close_admitted_sessions`].
#[must_use]
pub struct AdmittedSessions(pub Vec<UserSessionId>);

const fn check_name(name: &str) -> Result<(), ResourceError> {
    if name.is_empty() {
        return Err(ResourceError::EmptyName);
    }
    Ok(())
}

fn name_taken(err: DbErr) -> ResourceError {
    if is_unique_violation(&err) {
        ResourceError::NameTaken
    } else {
        err.into()
    }
}

#[cfg(all(test, feature = "sqlite"))]
mod tests {
    use sea_orm::{Database, DatabaseConnection, EntityTrait};
    use serde_json::json;
    use uuid::Uuid;
    use warpgate_db_entities::Parameters::{ConfigMigrationValues, set_config_migration_values};
    use warpgate_db_entities::{Target, TargetRoleAssignment};
    use warpgate_db_migrations::migrate_database;

    use super::roles::RoleDataRequest;
    use super::target_groups::TargetGroupDataRequest;
    use super::targets::TargetDataRequest;
    use super::*;

    async fn db() -> DatabaseConnection {
        set_config_migration_values(ConfigMigrationValues::default());
        let db = Database::connect("sqlite::memory:").await.unwrap();
        migrate_database(&db).await.unwrap();
        db
    }

    fn target(name: &str, options: serde_json::Value) -> TargetDataRequest {
        TargetDataRequest {
            name: name.into(),
            description: None,
            options: serde_json::from_value(options).unwrap(),
            rate_limit_bytes_per_second: Some(1000),
            group_id: None,
            ticket_max_duration_seconds: None,
            ticket_requests_disabled: false,
            ticket_require_approval: false,
            require_approval: false,
            ticket_max_uses: None,
        }
    }

    fn ssh(name: &str) -> TargetDataRequest {
        target(name, json!({"ssh": {"host": "h"}}))
    }

    fn role(name: &str, is_default: Option<bool>) -> RoleDataRequest {
        RoleDataRequest {
            name: name.into(),
            description: None,
            is_default,
        }
    }

    async fn assignments(db: &DatabaseConnection) -> usize {
        TargetRoleAssignment::Entity::find()
            .all(db)
            .await
            .unwrap()
            .len()
    }

    #[tokio::test]
    async fn targets() {
        let db = db().await;
        let web = targets::create(&db, &ssh("web"), None).await.unwrap();
        assert_eq!(web.rate_limit_bytes_per_second, Some(1000));

        let result = targets::create(&db, &ssh("web"), None).await;
        assert!(matches!(result, Err(ResourceError::NameTaken)));
        let result = targets::create(&db, &ssh(""), None).await;
        assert!(matches!(result, Err(ResourceError::EmptyName)));
        let http = target("web", json!({"http": {"url": "https://web"}}));
        let result = targets::update(&db, web.id, &http, None).await;
        assert!(matches!(result, Err(ResourceError::ProtocolChange)));
        let result = targets::update(&db, Uuid::new_v4(), &ssh("other"), None).await;
        assert!(matches!(result, Err(ResourceError::NotFound)));

        let dba = roles::create(&db, &role("dba", None)).await.unwrap();
        targets::add_role(&db, web.id, dba.id, None).await.unwrap();
        let result = targets::add_role(&db, web.id, dba.id, None).await;
        assert!(matches!(result, Err(ResourceError::RoleAlreadyAssigned)));

        let admitted = targets::delete(&db, web.id).await.unwrap();
        assert!(admitted.0.is_empty());
        assert_eq!(assignments(&db).await, 0);
        let result = targets::delete(&db, web.id).await;
        assert!(matches!(result, Err(ResourceError::NotFound)));
    }

    #[tokio::test]
    async fn roles() {
        let db = db().await;
        let dba = roles::create(&db, &role("dba", Some(true))).await.unwrap();
        let result = roles::create(&db, &role("dba", None)).await;
        assert!(matches!(result, Err(ResourceError::NameTaken)));

        let ops = roles::create(&db, &role("ops", None)).await.unwrap();
        assert!(!ops.is_default);
        let result = roles::update(&db, ops.id, &role("dba", None)).await;
        assert!(matches!(result, Err(ResourceError::NameTaken)));

        let renamed = roles::update(&db, dba.id, &role("dbas", None))
            .await
            .unwrap();
        assert_eq!(renamed.name, "dbas");
        assert!(renamed.is_default, "an omitted is_default stays as it was");

        let web = targets::create(&db, &ssh("web"), None).await.unwrap();
        targets::add_role(&db, web.id, dba.id, None).await.unwrap();
        roles::delete(&db, dba.id).await.unwrap();
        assert_eq!(assignments(&db).await, 0);
        let result = targets::remove_role(&db, web.id, dba.id).await;
        assert!(matches!(result, Err(ResourceError::NotFound)));
    }

    #[tokio::test]
    async fn deleting_a_group_ungroups_its_targets() {
        let db = db().await;
        let group = TargetGroupDataRequest {
            name: "prod".into(),
            description: None,
            color: None,
        };
        let prod = target_groups::create(&db, &group).await.unwrap();
        let mut web = ssh("web");
        web.group_id = Some(prod.id);
        let web = targets::create(&db, &web, None).await.unwrap();

        target_groups::delete(&db, prod.id).await.unwrap();
        let web = Target::Entity::find_by_id(web.id)
            .one(&db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(web.group_id, None);
    }

    /// 11, 13 and the legacy API: a credential in a target's settings (as API clients
    /// written before target accounts send it) becomes its primary account, stored once
    /// there; the settings keep none, and reading the target shows the account again with
    /// no secret in it. A role allowed on the target grants that account.
    #[tokio::test]
    async fn a_legacy_target_credential_becomes_its_primary_account() {
        use warpgate_common::{StoredSecrets, TargetOptions};
        use warpgate_db_entities::{AccessGroupGrant, TargetAccount};

        let db = db().await;
        let mysql = targets::create(
            &db,
            &target(
                "db",
                json!({"mysql": {"host": "d", "username": "app",
                    "auth": {"kind": "password", "password": "hunter2"}}}),
            ),
            None,
        )
        .await
        .unwrap();

        let stored: TargetOptions = serde_json::from_value(mysql.options.clone()).unwrap();
        let TargetOptions::MySql(settings) = &stored else {
            unreachable!()
        };
        assert_eq!(settings.username, "", "the settings keep no account");
        assert!(
            TargetOptions::MySql(settings.clone())
                .stored_secrets_mut()
                .iter()
                .all(|secret| secret.stored_value().is_empty()),
            "nor any password"
        );

        let accounts = target_accounts::list(&db, mysql.id).await.unwrap();
        assert_eq!(accounts.len(), 1, "one account, the password stored once");
        let primary = &accounts[0];
        assert!(primary.is_primary);
        assert_eq!(primary.name, "app");

        let mut shown = [warpgate_common::Target::try_from(mysql.clone()).unwrap()];
        target_accounts::show_primaries(&db, &mut shown)
            .await
            .unwrap();
        let TargetOptions::MySql(shown) = &shown[0].options else {
            unreachable!()
        };
        assert_eq!(shown.username, "app");
        assert!(
            !serde_json::to_string(&shown.auth)
                .unwrap()
                .contains("hunter2"),
            "never the password"
        );

        // Saving the same settings with the password left blank keeps it.
        let again = target(
            "db",
            json!({"mysql": {"host": "d", "username": "app",
                "auth": {"kind": "password", "password": ""}}}),
        );
        targets::update(&db, mysql.id, &again, None).await.unwrap();
        let after = TargetAccount::Entity::find().all(&db).await.unwrap();
        assert_eq!(after.len(), 1);
        assert_eq!(after[0].credential, primary.credential);

        // The legacy role grant is a grant of the primary account.
        let dba = roles::create(&db, &role("dba", None)).await.unwrap();
        let grant = targets::add_role(&db, mysql.id, dba.id, None)
            .await
            .unwrap();
        assert_eq!(grant.target_account_id, Some(primary.id));
        assert_eq!(
            AccessGroupGrant::Entity::find()
                .all(&db)
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(assignments(&db).await, 1, "kept in step with target_roles");

        // A target with no primary account refuses, rather than pick an account.
        let bare = targets::create(
            &db,
            &target(
                "bare",
                json!({"ssh": {"host": "h", "username": "", "auth": {"kind": "publickey"}}}),
            ),
            None,
        )
        .await
        .unwrap();
        assert!(matches!(
            targets::add_role(&db, bare.id, dba.id, None).await,
            Err(ResourceError::NoPrimaryAccount)
        ));
    }
}
