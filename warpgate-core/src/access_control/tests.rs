//! Access Control against a migrated in-memory database: the resolver every protocol's
//! authorization goes through.

use sea_orm::ActiveValue::Set;
use sea_orm::{ActiveModelTrait, Database, EntityTrait, ModelTrait};
use serde_json::json;
use time::{Duration, OffsetDateTime};
use warpgate_common::{SSHTargetAuth, TargetOptions};
use warpgate_db_entities::Parameters::{ConfigMigrationValues, set_config_migration_values};
use warpgate_db_entities::{
    AccessAssignment as A, AccessGroupExclusion as X, AccessGroupGrant as G,
};
use warpgate_db_migrations::migrate_database;

use super::*;

async fn migrated_db() -> DatabaseConnection {
    set_config_migration_values(ConfigMigrationValues::default());
    let db = Database::connect("sqlite::memory:").await.unwrap();
    migrate_database(&db).await.unwrap();
    db
}

async fn user(db: &DatabaseConnection, name: &str, link: Option<(Uuid, Uuid)>) -> Uuid {
    let id = Uuid::new_v4();
    User::ActiveModel {
        id: Set(id),
        username: Set(name.to_owned()),
        description: Set(String::new()),
        credential_policy: Set(json!({})),
        rate_limit_bytes_per_second: Set(None),
        ldap_server_id: Set(link.map(|(server, _)| server)),
        ldap_object_uuid: Set(link.map(|(_, entry)| entry)),
        allowed_ip_ranges: Set(serde_json::Value::Null),
    }
    .insert(db)
    .await
    .unwrap();
    id
}

async fn target(db: &DatabaseConnection, name: &str, options: serde_json::Value) -> Target {
    let options: TargetOptions = serde_json::from_value(options).unwrap();
    let model = warpgate_db_entities::Target::ActiveModel {
        id: Set(Uuid::new_v4()),
        name: Set(name.to_owned()),
        description: Set(String::new()),
        kind: Set(TargetKind::from(&options)),
        options: Set(serde_json::to_value(&options).unwrap()),
        rate_limit_bytes_per_second: Set(None),
        group_id: Set(None),
        ticket_max_duration_seconds: Set(None),
        ticket_requests_disabled: Set(false),
        ticket_require_approval: Set(false),
        ticket_max_uses: Set(None),
        require_approval: Set(false),
    }
    .insert(db)
    .await
    .unwrap();
    Target::try_from(model).unwrap()
}

async fn ssh_target(db: &DatabaseConnection, name: &str) -> Target {
    target(db, name, json!({"ssh": {"host": "h"}})).await
}

struct NewAccount<'a> {
    kind: TargetAccountKind,
    name: &'a str,
    method: TargetAccountAuthMethod,
    credential: Option<serde_json::Value>,
    primary: bool,
}

impl<'a> NewAccount<'a> {
    fn key(name: &'a str) -> Self {
        Self {
            kind: TargetAccountKind::Local,
            name,
            method: TargetAccountAuthMethod::StoredCredential,
            credential: Some(json!({"kind": "publickey"})),
            primary: false,
        }
    }
}

async fn account(db: &DatabaseConnection, target_id: Uuid, new: NewAccount<'_>) -> Uuid {
    let id = Uuid::new_v4();
    let now = OffsetDateTime::now_utc();
    TargetAccount::ActiveModel {
        id: Set(id),
        target_id: Set(target_id),
        kind: Set(new.kind),
        name: Set(new.name.to_owned()),
        domain: Set(None),
        auth_method: Set(new.method),
        credential: Set(new.credential),
        username_format: Set(None),
        enabled: Set(true),
        is_primary: Set(new.primary),
        description: Set(String::new()),
        account_key: Set(TargetAccount::Model::key_for(new.kind, new.name, None)),
        created_by: Set(None),
        created_at: Set(now),
        updated_at: Set(now),
    }
    .insert(db)
    .await
    .unwrap();
    id
}

async fn assign(
    db: &DatabaseConnection,
    user_id: Uuid,
    target_id: Uuid,
    account_id: Option<Uuid>,
) -> Uuid {
    let id = Uuid::new_v4();
    let now = OffsetDateTime::now_utc();
    A::ActiveModel {
        id: Set(id),
        user_id: Set(user_id),
        target_id: Set(target_id),
        target_account_id: Set(account_id),
        account_key: Set(A::account_key(account_id)),
        ldap_server_id: Set(None),
        ldap_object_uuid: Set(None),
        enabled: Set(true),
        expires_at: Set(None),
        origin: Set(AssignmentOrigin::Direct),
        note: Set(String::new()),
        created_by: Set(None),
        updated_by: Set(None),
        created_at: Set(now),
        updated_at: Set(now),
    }
    .insert(db)
    .await
    .unwrap();
    id
}

async fn group(db: &DatabaseConnection, name: &str, members: &[Uuid]) -> Uuid {
    let id = Uuid::new_v4();
    Role::ActiveModel {
        id: Set(id),
        name: Set(name.to_owned()),
        description: Set(String::new()),
        is_default: Set(false),
    }
    .insert(db)
    .await
    .unwrap();
    for member in members {
        UserRoleAssignment::Entity::idempotent_grant(db, *member, id, None)
            .await
            .unwrap();
    }
    id
}

async fn grant(
    db: &DatabaseConnection,
    group_id: Uuid,
    target_id: Uuid,
    account_id: Option<Uuid>,
) -> Uuid {
    let id = Uuid::new_v4();
    G::ActiveModel {
        id: Set(id),
        role_id: Set(group_id),
        target_id: Set(target_id),
        target_account_id: Set(account_id),
        account_key: Set(A::account_key(account_id)),
        created_by: Set(None),
        created_at: Set(OffsetDateTime::now_utc()),
    }
    .insert(db)
    .await
    .unwrap();
    id
}

async fn exclude(
    db: &DatabaseConnection,
    group_id: Uuid,
    user_id: Uuid,
    target_id: Uuid,
    account_id: Option<Uuid>,
) {
    X::ActiveModel {
        id: Set(Uuid::new_v4()),
        role_id: Set(group_id),
        user_id: Set(user_id),
        target_id: Set(target_id),
        target_account_id: Set(account_id),
        account_key: Set(A::account_key(account_id)),
        note: Set(String::new()),
        created_by: Set(None),
        created_at: Set(OffsetDateTime::now_utc()),
    }
    .insert(db)
    .await
    .unwrap();
}

fn who(id: Uuid) -> ConnectingUser<'static> {
    ConnectingUser {
        id,
        username: "ahmad",
    }
}

async fn resolved_account(
    db: &DatabaseConnection,
    user_id: Uuid,
    target: &Target,
    request: Option<&AccountRequest>,
) -> Result<Uuid, AccessError> {
    match resolve_connection(db, who(user_id), target, request, false).await? {
        ConnectionAccess::Account(authorized) => Ok(authorized.account.id),
        ConnectionAccess::Accountless => Ok(Uuid::nil()),
    }
}

/// 1, 2, 30: a direct assignment lets the user in as its account, and only it; no
/// assignment, no access.
#[tokio::test]
async fn a_direct_assignment_grants_its_account_and_nothing_else_does() {
    let db = migrated_db().await;
    let ahmad = user(&db, "ahmad", None).await;
    let yusif = user(&db, "yusif", None).await;
    let server = ssh_target(&db, "LINUX-SRV-01").await;
    let deploy = account(&db, server.id, NewAccount::key("deploy")).await;
    assign(&db, ahmad, server.id, Some(deploy)).await;

    assert!(has_access(&db, ahmad, server.id).await.unwrap());
    assert_eq!(
        resolved_account(&db, ahmad, &server, None).await.unwrap(),
        deploy
    );
    assert!(!has_access(&db, yusif, server.id).await.unwrap());
    assert!(matches!(
        resolved_account(&db, yusif, &server, None).await,
        Err(AccessError::NoAccess)
    ));
    assert_eq!(
        authorized_target_ids(&db, ahmad).await.unwrap(),
        HashSet::from([server.id])
    );
}

/// 3: a role that reaches a target the old way (`target_roles`) grants nothing by itself.
#[tokio::test]
async fn an_access_role_alone_grants_nothing() {
    let db = migrated_db().await;
    let ahmad = user(&db, "ahmad", None).await;
    let server = ssh_target(&db, "LINUX-SRV-01").await;
    account(&db, server.id, NewAccount::key("deploy")).await;
    let ops = group(&db, "ops", &[ahmad]).await;
    warpgate_db_entities::TargetRoleAssignment::ActiveModel {
        target_id: Set(server.id),
        role_id: Set(ops),
    }
    .insert(&db)
    .await
    .unwrap();

    assert!(!has_access(&db, ahmad, server.id).await.unwrap());
}

/// 4, 5, 38: revoked, disabled and expired assignments let nobody in.
#[tokio::test]
async fn revoked_disabled_and_expired_assignments_deny() {
    let db = migrated_db().await;
    let ahmad = user(&db, "ahmad", None).await;
    let server = ssh_target(&db, "LINUX-SRV-01").await;
    let deploy = account(&db, server.id, NewAccount::key("deploy")).await;
    let id = assign(&db, ahmad, server.id, Some(deploy)).await;
    let assignment = A::Entity::find_by_id(id).one(&db).await.unwrap().unwrap();

    let mut disabled: A::ActiveModel = assignment.clone().into();
    disabled.enabled = Set(false);
    disabled.update(&db).await.unwrap();
    assert!(!has_access(&db, ahmad, server.id).await.unwrap());

    let mut expired: A::ActiveModel = assignment.clone().into();
    expired.enabled = Set(true);
    expired.expires_at = Set(Some(OffsetDateTime::now_utc() - Duration::minutes(1)));
    expired.update(&db).await.unwrap();
    assert!(!has_access(&db, ahmad, server.id).await.unwrap());
    let listed = effective_assignments(&db, AssignmentFilter::default(), OffsetDateTime::now_utc())
        .await
        .unwrap();
    assert_eq!(listed[0].problem, Some("expired"));

    assignment.delete(&db).await.unwrap();
    assert!(!has_access(&db, ahmad, server.id).await.unwrap());
}

/// 6: a disabled account lets nobody in, whatever is assigned.
#[tokio::test]
async fn a_disabled_account_denies() {
    let db = migrated_db().await;
    let ahmad = user(&db, "ahmad", None).await;
    let server = ssh_target(&db, "LINUX-SRV-01").await;
    let deploy = account(&db, server.id, NewAccount::key("deploy")).await;
    assign(&db, ahmad, server.id, Some(deploy)).await;
    let model = TargetAccount::Entity::find_by_id(deploy)
        .one(&db)
        .await
        .unwrap()
        .unwrap();
    let mut model: TargetAccount::ActiveModel = model.into();
    model.enabled = Set(false);
    model.update(&db).await.unwrap();

    assert!(!has_access(&db, ahmad, server.id).await.unwrap());
}

/// 7, 8, 9: a forged id, another target's account and another user's account are refused.
#[tokio::test]
async fn forged_and_foreign_accounts_are_refused() {
    let db = migrated_db().await;
    let ahmad = user(&db, "ahmad", None).await;
    let yusif = user(&db, "yusif", None).await;
    let server = ssh_target(&db, "LINUX-SRV-01").await;
    let other = ssh_target(&db, "LINUX-SRV-02").await;
    let deploy = account(&db, server.id, NewAccount::key("deploy")).await;
    let admin = account(&db, server.id, NewAccount::key("admin")).await;
    let elsewhere = account(&db, other.id, NewAccount::key("root")).await;
    assign(&db, ahmad, server.id, Some(deploy)).await;
    assign(&db, yusif, server.id, Some(admin)).await;

    for forged in [Uuid::new_v4(), admin, elsewhere] {
        assert!(
            matches!(
                resolved_account(&db, ahmad, &server, Some(&AccountRequest::Id(forged))).await,
                Err(AccessError::NotAllowed)
            ),
            "{forged}"
        );
    }
    assert!(matches!(
        resolved_account(
            &db,
            ahmad,
            &server,
            Some(&AccountRequest::Name("admin".into()))
        )
        .await,
        Err(AccessError::NotAllowed)
    ));

    // An assignment row naming another target's account (possible in the database, not
    // through the API) is never usable.
    assign(&db, ahmad, other.id, Some(admin)).await;
    assert!(!has_access(&db, ahmad, other.id).await.unwrap());
}

/// 10, 11, 12: a target holds any number of accounts; with several assigned, the user must
/// choose, by id or by name, and only among their own.
#[tokio::test]
async fn several_accounts_need_an_explicit_choice() {
    let db = migrated_db().await;
    let ahmad = user(&db, "ahmad", None).await;
    let server = ssh_target(&db, "LINUX-SRV-01").await;
    let mut accounts = vec![];
    for name in ["deploy", "backup", "monitor", "admin"] {
        accounts.push(account(&db, server.id, NewAccount::key(name)).await);
    }
    assign(&db, ahmad, server.id, Some(accounts[0])).await;
    assign(&db, ahmad, server.id, Some(accounts[1])).await;

    assert!(matches!(
        resolved_account(&db, ahmad, &server, None).await,
        Err(AccessError::NotChosen(names)) if names.len() == 2
    ));
    assert_eq!(
        resolved_account(
            &db,
            ahmad,
            &server,
            Some(&AccountRequest::Name("BACKUP".into()))
        )
        .await
        .unwrap(),
        accounts[1]
    );
    assert_eq!(
        resolved_account(&db, ahmad, &server, Some(&AccountRequest::Id(accounts[0])))
            .await
            .unwrap(),
        accounts[0]
    );
    // Accounts stay with their target.
    let other = ssh_target(&db, "LINUX-SRV-02").await;
    assert!(!has_access(&db, ahmad, other.id).await.unwrap());
}

/// 14: a linked directory account is each user's own: it keeps no password, follows the
/// user's link, and stops when the link changes.
#[tokio::test]
async fn directory_accounts_follow_the_users_link_and_store_no_password() {
    let db = migrated_db().await;
    let server = ssh_target(&db, "LINUX-SRV-01").await;
    let directory = account(
        &db,
        server.id,
        NewAccount {
            kind: TargetAccountKind::Directory,
            name: "",
            method: TargetAccountAuthMethod::StoredCredential,
            credential: Some(json!({"kind": "publickey"})),
            primary: false,
        },
    )
    .await;
    let model = TargetAccount::Entity::find_by_id(directory)
        .one(&db)
        .await
        .unwrap()
        .unwrap();
    let mut with_password = model.clone();
    with_password.credential = Some(json!({"kind": "password", "password": "p"}));
    assert!(check_account(Protocol::Ssh, &with_password).is_err());
    assert!(check_account(Protocol::Ssh, &model).is_ok());

    let unlinked = user(&db, "unlinked", None).await;
    assign(&db, unlinked, server.id, Some(directory)).await;
    assert!(!has_access(&db, unlinked, server.id).await.unwrap());

    // The assignment records the link it was made for; another entry does not inherit it.
    let directory_server = warpgate_db_entities::LdapServer::ActiveModel {
        id: Set(Uuid::new_v4()),
        name: Set("corp".to_owned()),
        host: Set("ldap.invalid".to_owned()),
        port: Set(636),
        bind_dn: Set(String::new()),
        bind_password: Set(String::new()),
        user_filter: Set("(objectClass=person)".to_owned()),
        base_dns: Set(json!(["dc=example,dc=com"])),
        tls_mode: Set("preferred".to_owned()),
        tls_verify: Set(true),
        enabled: Set(true),
        auto_link_sso_users: Set(false),
        description: Set(String::new()),
        username_attribute: Set("cn".to_owned()),
        ssh_key_attribute: Set("sshPublicKey".to_owned()),
        uuid_attribute: Set(String::new()),
        authenticate_users: Set(true),
    }
    .insert(&db)
    .await
    .unwrap()
    .id;
    let linked = user(&db, "linked", Some((directory_server, Uuid::new_v4()))).await;
    assign(&db, linked, server.id, Some(directory)).await;
    assert!(
        !has_access(&db, linked, server.id).await.unwrap(),
        "assigned without the user's link, so not theirs"
    );
}

/// 15: deleting an account takes what it allowed with it.
#[tokio::test]
async fn deleting_an_account_removes_its_access() {
    let db = migrated_db().await;
    let ahmad = user(&db, "ahmad", None).await;
    let server = ssh_target(&db, "LINUX-SRV-01").await;
    let deploy = account(&db, server.id, NewAccount::key("deploy")).await;
    assign(&db, ahmad, server.id, Some(deploy)).await;
    assert!(has_access(&db, ahmad, server.id).await.unwrap());

    TargetAccount::Entity::delete_by_id(deploy)
        .exec(&db)
        .await
        .unwrap();
    assert!(!has_access(&db, ahmad, server.id).await.unwrap());
}

/// 16, 19: a group's grant gives its active members the account; membership changes show at
/// once, and the assignment says which group it comes from.
#[tokio::test]
async fn group_grants_follow_membership() {
    let db = migrated_db().await;
    let ahmad = user(&db, "ahmad", None).await;
    let yusif = user(&db, "yusif", None).await;
    let server = ssh_target(&db, "LINUX-SRV-01").await;
    let deploy = account(&db, server.id, NewAccount::key("deploy")).await;
    let dbas = group(&db, "Database Administrators", &[ahmad]).await;
    grant(&db, dbas, server.id, Some(deploy)).await;

    assert!(has_access(&db, ahmad, server.id).await.unwrap());
    assert!(!has_access(&db, yusif, server.id).await.unwrap());
    let listed = usable_assignments(&db, ahmad, server.id).await.unwrap();
    assert!(matches!(
        &listed[0].source,
        AssignmentSource::Group { group_name, .. } if group_name == "Database Administrators"
    ));

    UserRoleAssignment::Entity::idempotent_grant(&db, yusif, dbas, None)
        .await
        .unwrap();
    assert!(has_access(&db, yusif, server.id).await.unwrap());

    let membership = UserRoleAssignment::Entity::find_by_id((ahmad, dbas))
        .one(&db)
        .await
        .unwrap()
        .unwrap();
    let mut revoked: UserRoleAssignment::ActiveModel = membership.into();
    revoked.revoked_at = Set(Some(OffsetDateTime::now_utc()));
    revoked.update(&db).await.unwrap();
    assert!(!has_access(&db, ahmad, server.id).await.unwrap());
}

/// 17: a group cannot grant past the rules: another target's account, or an excluded member.
#[tokio::test]
async fn group_changes_cannot_bypass_the_rules() {
    let db = migrated_db().await;
    let ahmad = user(&db, "ahmad", None).await;
    let server = ssh_target(&db, "LINUX-SRV-01").await;
    let other = ssh_target(&db, "LINUX-SRV-02").await;
    let elsewhere = account(&db, other.id, NewAccount::key("root")).await;
    let ops = group(&db, "ops", &[ahmad]).await;
    grant(&db, ops, server.id, Some(elsewhere)).await;
    assert!(!has_access(&db, ahmad, server.id).await.unwrap());

    let deploy = account(&db, server.id, NewAccount::key("deploy")).await;
    grant(&db, ops, server.id, Some(deploy)).await;
    exclude(&db, ops, ahmad, server.id, Some(deploy)).await;
    assert!(!has_access(&db, ahmad, server.id).await.unwrap());
}

/// 18: excluding a user from a group's grant leaves their direct assignment of the same
/// account in force.
#[tokio::test]
async fn excluding_from_a_group_keeps_direct_assignments() {
    let db = migrated_db().await;
    let ahmad = user(&db, "ahmad", None).await;
    let server = ssh_target(&db, "LINUX-SRV-01").await;
    let deploy = account(&db, server.id, NewAccount::key("deploy")).await;
    let ops = group(&db, "ops", &[ahmad]).await;
    grant(&db, ops, server.id, Some(deploy)).await;
    assign(&db, ahmad, server.id, Some(deploy)).await;
    exclude(&db, ops, ahmad, server.id, Some(deploy)).await;

    assert!(has_access(&db, ahmad, server.id).await.unwrap());
    let all = effective_assignments(
        &db,
        AssignmentFilter {
            user_id: Some(ahmad),
            ..Default::default()
        },
        OffsetDateTime::now_utc(),
    )
    .await
    .unwrap();
    assert_eq!(all.len(), 2);
    assert!(all.iter().any(|a| a.exclusion_id.is_some() && !a.usable()));
    assert!(
        all.iter()
            .any(|a| matches!(a.source, AssignmentSource::Direct { .. }) && a.usable())
    );
}

/// 33: HTTP and the other protocols without accounts take an accountless entitlement, and an
/// account-based target never does.
#[tokio::test]
async fn accountless_entitlements_are_for_accountless_protocols() {
    let db = migrated_db().await;
    let ahmad = user(&db, "ahmad", None).await;
    let web = target(&db, "web", json!({"http": {"url": "http://x"}})).await;
    let server = ssh_target(&db, "LINUX-SRV-01").await;
    assign(&db, ahmad, web.id, None).await;
    assign(&db, ahmad, server.id, None).await;

    assert!(has_access(&db, ahmad, web.id).await.unwrap());
    assert!(matches!(
        resolve_connection(&db, who(ahmad), &web, None, false).await,
        Ok(ConnectionAccess::Accountless)
    ));
    assert!(!has_access(&db, ahmad, server.id).await.unwrap());
}

/// A ticket admits its user without an assignment: as their own account when they have
/// one, and the target's primary account otherwise.
#[tokio::test]
async fn a_ticket_connects_as_the_primary_account_without_an_assignment() {
    let db = migrated_db().await;
    let ahmad = user(&db, "ahmad", None).await;
    let server = ssh_target(&db, "LINUX-SRV-01").await;
    let primary = account(
        &db,
        server.id,
        NewAccount {
            primary: true,
            ..NewAccount::key("deploy")
        },
    )
    .await;
    match resolve_connection(&db, who(ahmad), &server, None, true)
        .await
        .unwrap()
    {
        ConnectionAccess::Account(authorized) => {
            assert_eq!(authorized.account.id, primary);
            assert!(authorized.via_ticket);
        }
        ConnectionAccess::Accountless => panic!("an SSH target has accounts"),
    }
    assert!(
        resolve_connection(&db, who(ahmad), &server, None, false)
            .await
            .is_err(),
        "without the ticket, no assignment is no access"
    );
}

/// 31: SSH and database connections sign in with exactly the account's name and credential.
#[test]
fn the_authorized_account_fills_the_connection_in() {
    let now = OffsetDateTime::now_utc();
    let account = TargetAccount::Model {
        id: Uuid::new_v4(),
        target_id: Uuid::new_v4(),
        kind: TargetAccountKind::Local,
        name: "deploy".into(),
        domain: None,
        auth_method: TargetAccountAuthMethod::StoredCredential,
        credential: Some(json!({"kind": "certificate", "backend": "vault", "role": "deploy"})),
        username_format: None,
        enabled: true,
        is_primary: false,
        description: String::new(),
        account_key: "name:deploy".into(),
        created_by: None,
        created_at: now,
        updated_at: now,
    };
    let mut options: TargetOptions = serde_json::from_value(json!({"ssh": {"host": "h"}})).unwrap();
    apply_account(&mut options, "deploy", &account).unwrap();
    let TargetOptions::Ssh(ssh) = &options else {
        unreachable!()
    };
    assert_eq!(ssh.username, "deploy");
    assert!(matches!(ssh.auth, SSHTargetAuth::Certificate(_)));

    let mut mysql: TargetOptions = serde_json::from_value(json!({"mysql": {"host": "d"}})).unwrap();
    assert!(apply_account(&mut mysql, "app", &account).is_err());
}

#[test]
fn accounts_are_checked_for_their_protocol() {
    let now = OffsetDateTime::now_utc();
    let account = |kind, method, credential: Option<serde_json::Value>| TargetAccount::Model {
        id: Uuid::new_v4(),
        target_id: Uuid::new_v4(),
        kind,
        name: "operator".into(),
        domain: None,
        auth_method: method,
        credential,
        username_format: None,
        enabled: true,
        is_primary: false,
        description: String::new(),
        account_key: "name:operator".into(),
        created_by: None,
        created_at: now,
        updated_at: now,
    };
    use TargetAccountAuthMethod as M;
    use TargetAccountKind as K;
    let password = || Some(json!({"kind": "password", "password": "p"}));
    assert!(
        check_account(
            Protocol::Rdp,
            &account(K::Local, M::StoredCredential, password())
        )
        .is_ok()
    );
    assert!(check_account(Protocol::Rdp, &account(K::Domain, M::TypedPassword, None)).is_ok());
    assert!(
        check_account(
            Protocol::Rdp,
            &account(K::Directory, M::DirectoryPassword, None)
        )
        .is_ok()
    );
    assert!(
        check_account(
            Protocol::Rdp,
            &account(K::Directory, M::StoredCredential, password())
        )
        .is_err()
    );
    assert!(check_account(Protocol::Ssh, &account(K::Local, M::TypedPassword, None)).is_err());
    assert!(
        check_account(
            Protocol::MySql,
            &account(
                K::Local,
                M::StoredCredential,
                Some(json!({"kind": "publickey"}))
            )
        )
        .is_err()
    );
    assert!(
        check_account(
            Protocol::Http,
            &account(K::Local, M::StoredCredential, password())
        )
        .is_err()
    );
}

#[test]
fn an_account_can_follow_the_target_name() {
    assert_eq!(
        split_account_selector("LINUX-SRV-01:deploy"),
        Some(("LINUX-SRV-01", "deploy"))
    );
    assert_eq!(split_account_selector("db#app_ro"), Some(("db", "app_ro")));
    assert_eq!(
        split_account_selector("a:b:yusif@corp.local"),
        Some(("a:b", "yusif@corp.local"))
    );
    assert_eq!(split_account_selector("LINUX-SRV-01"), None);
    assert_eq!(split_account_selector("LINUX-SRV-01:"), None);
    assert_eq!(split_account_selector(":deploy"), None);
}
