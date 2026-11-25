//! Access policies against a migrated in-memory database: what a connection is told for each
//! combination of policies, and the life of an approval a policy asked for.
//!
//! The clock-reading rules themselves (windows, overnight, timezones, daylight saving,
//! precedence) are tested without a database in `pure_tests` in the parent module; these are
//! about scope, storage, and the guarantees an approval carries.

use sea_orm::{Database, EntityTrait};
use serde_json::json;
use time::Duration;
use warpgate_common::auth::{ApprovalKind, ApprovalScope, AuthStateUserInfo};
use warpgate_common::{NodeId, Protocol, RuleWindow, TargetOptions, UserSessionId};
use warpgate_db_entities::Parameters::{ConfigMigrationValues, set_config_migration_values};
use warpgate_db_entities::SessionApprovalRequest::{
    self as Requests, ApprovalActor, ApprovalRequestStatus,
};
use warpgate_db_entities::Target::TargetKind;
use warpgate_db_entities::{AccessAssignment as A, TargetAccount as Accounts};
use warpgate_db_migrations::migrate_database;

use super::*;
use crate::access_control::{TargetAccountAuthMethod, TargetAccountKind};
use crate::approvals::{ApprovalDecision, Requirement, record_decision, requirement_for};

type CommonTarget = warpgate_common::Target;

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

// A Monday, a Saturday and a Sunday, in March 2026.
const MONDAY_NOON: &str = "2026-03-02T12:00:00Z";
const MONDAY_NIGHT: &str = "2026-03-02T22:00:00Z";
const SATURDAY: &str = "2026-03-07T12:00:00Z";
const SUNDAY: &str = "2026-03-08T12:00:00Z";

async fn migrated_db() -> DatabaseConnection {
    set_config_migration_values(ConfigMigrationValues::default());
    let db = Database::connect("sqlite::memory:").await.unwrap();
    migrate_database(&db).await.unwrap();
    db
}

async fn user(db: &DatabaseConnection, name: &str) -> Uuid {
    let id = Uuid::new_v4();
    User::ActiveModel {
        id: Set(id),
        username: Set(name.to_owned()),
        description: Set(String::new()),
        credential_policy: Set(json!({})),
        rate_limit_bytes_per_second: Set(None),
        ldap_server_id: Set(None),
        ldap_object_uuid: Set(None),
        allowed_ip_ranges: Set(serde_json::Value::Null),
    }
    .insert(db)
    .await
    .unwrap();
    id
}

async fn ssh_target(db: &DatabaseConnection, name: &str, require_approval: bool) -> CommonTarget {
    let options: TargetOptions = serde_json::from_value(json!({"ssh": {"host": "h"}})).unwrap();
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
        require_approval: Set(require_approval),
    }
    .insert(db)
    .await
    .unwrap();
    CommonTarget::try_from(model).unwrap()
}

async fn account(db: &DatabaseConnection, target_id: Uuid, name: &str) -> Uuid {
    let id = Uuid::new_v4();
    let now = OffsetDateTime::now_utc();
    Accounts::ActiveModel {
        id: Set(id),
        target_id: Set(target_id),
        kind: Set(TargetAccountKind::Local),
        name: Set(name.to_owned()),
        domain: Set(None),
        auth_method: Set(TargetAccountAuthMethod::StoredCredential),
        credential: Set(Some(json!({"kind": "publickey"}))),
        username_format: Set(None),
        enabled: Set(true),
        is_primary: Set(false),
        description: Set(String::new()),
        account_key: Set(Accounts::Model::key_for(
            TargetAccountKind::Local,
            name,
            None,
        )),
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
    account_id: Uuid,
) -> A::Model {
    let now = OffsetDateTime::now_utc();
    A::ActiveModel {
        id: Set(Uuid::new_v4()),
        user_id: Set(user_id),
        target_id: Set(target_id),
        target_account_id: Set(Some(account_id)),
        account_key: Set(A::account_key(Some(account_id))),
        ldap_server_id: Set(None),
        ldap_object_uuid: Set(None),
        enabled: Set(true),
        expires_at: Set(None),
        origin: Set(crate::access_control::AssignmentOrigin::Direct),
        note: Set(String::new()),
        created_by: Set(None),
        updated_by: Set(None),
        created_at: Set(now),
        updated_at: Set(now),
    }
    .insert(db)
    .await
    .unwrap()
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

fn office(outside: RuleAction) -> AccessRules {
    let mut rules = AccessRules::new("UTC", outside);
    rules.windows.push(RuleWindow {
        days: RuleWeekday::ALL[..5].to_vec(),
        start: "09:00".into(),
        end: "18:00".into(),
        action: RuleAction::Allow,
    });
    rules
}

fn weekend(action: RuleAction) -> AccessRules {
    // Allowed otherwise, `action` on Saturdays and Sundays.
    let mut rules = AccessRules::new("UTC", RuleAction::Allow);
    rules.windows.push(RuleWindow {
        days: vec![RuleWeekday::Sat, RuleWeekday::Sun],
        start: "00:00".into(),
        end: "24:00".into(),
        action,
    });
    rules
}

async fn standing_policy(
    db: &DatabaseConnection,
    name: &str,
    scope: PolicyScope,
    rules: AccessRules,
) -> AccessPolicy::Model {
    create_policy(
        db,
        PolicyData {
            name: name.into(),
            description: String::new(),
            enabled: true,
            scope,
            rules,
        },
        None,
    )
    .await
    .unwrap()
}

fn facts<'a>(
    user_id: Uuid,
    target: &'a CommonTarget,
    request: Option<&'a AccountRequest>,
) -> ConnectionFacts<'a> {
    ConnectionFacts {
        user_id,
        username: "ahmad",
        target,
        request,
        via_ticket: false,
    }
}

async fn decision(
    db: &DatabaseConnection,
    user_id: Uuid,
    target: &CommonTarget,
    request: Option<&AccountRequest>,
    when: &str,
) -> PolicyDecision {
    evaluate_connection(db, facts(user_id, target, request), at(when))
        .await
        .unwrap()
        .decision
}

fn is_allow(decision: &PolicyDecision) -> bool {
    matches!(decision, PolicyDecision::Allow)
}

fn needs_approval(decision: &PolicyDecision) -> bool {
    matches!(decision, PolicyDecision::RequireApproval(_))
}

fn is_deny(decision: &PolicyDecision) -> bool {
    matches!(decision, PolicyDecision::Deny(_))
}

// ---------------------------------------------------------------------------------------
// What a connection is told
// ---------------------------------------------------------------------------------------

/// An assignment without a schedule, and a system without policies, behave as before.
#[tokio::test]
async fn a_connection_no_policy_covers_is_allowed_at_any_time() {
    let db = migrated_db().await;
    let ahmad = user(&db, "ahmad").await;
    let server = ssh_target(&db, "srv", false).await;
    let deploy = account(&db, server.id, "deploy").await;
    assign(&db, ahmad, server.id, deploy).await;

    assert!(!any_enabled(&db).await.unwrap());
    for when in [MONDAY_NOON, MONDAY_NIGHT, SATURDAY, SUNDAY] {
        assert!(
            is_allow(&decision(&db, ahmad, &server, None, when).await),
            "{when}"
        );
    }
}

/// 2, 3, 4: allowed in hours, approval at night and at weekends.
#[tokio::test]
async fn an_assignments_schedule_asks_for_approval_outside_its_hours() {
    let db = migrated_db().await;
    let ahmad = user(&db, "ahmad").await;
    let server = ssh_target(&db, "srv", false).await;
    let deploy = account(&db, server.id, "deploy").await;
    let assignment = assign(&db, ahmad, server.id, deploy).await;
    save_assignment_rules(
        &db,
        &assignment,
        "Schedule: ahmad on srv",
        Some(office(RuleAction::RequireApproval)),
        None,
    )
    .await
    .unwrap();

    assert!(is_allow(
        &decision(&db, ahmad, &server, None, MONDAY_NOON).await
    ));
    for when in [MONDAY_NIGHT, SATURDAY, SUNDAY] {
        let result = evaluate_connection(&db, facts(ahmad, &server, None), at(when))
            .await
            .unwrap();
        assert!(needs_approval(&result.decision), "{when}");
        assert_eq!(
            result.account.map(|(id, _)| id),
            Some(deploy),
            "the approval is for the account that will be used"
        );
    }
}

/// 5: a period the policy denies is denied whether or not anyone would approve.
#[tokio::test]
async fn a_denied_period_is_refused_even_though_approval_exists_elsewhere() {
    let db = migrated_db().await;
    let ahmad = user(&db, "ahmad").await;
    let server = ssh_target(&db, "srv", false).await;
    let deploy = account(&db, server.id, "deploy").await;
    let assignment = assign(&db, ahmad, server.id, deploy).await;
    // The assignment's own rules would ask for approval at weekends...
    save_assignment_rules(
        &db,
        &assignment,
        "Schedule",
        Some(weekend(RuleAction::RequireApproval)),
        None,
    )
    .await
    .unwrap();
    // ...but a target-wide policy denies Sundays.
    let mut sundays = AccessRules::new("UTC", RuleAction::Allow);
    sundays.windows.push(RuleWindow {
        days: vec![RuleWeekday::Sun],
        start: "00:00".into(),
        end: "24:00".into(),
        action: RuleAction::Deny,
    });
    standing_policy(
        &db,
        "No Sundays",
        PolicyScope {
            target_id: Some(server.id),
            ..PolicyScope::default()
        },
        sundays,
    )
    .await;

    assert!(is_allow(
        &decision(&db, ahmad, &server, None, MONDAY_NOON).await
    ));
    assert!(needs_approval(
        &decision(&db, ahmad, &server, None, SATURDAY).await
    ));
    assert!(is_deny(&decision(&db, ahmad, &server, None, SUNDAY).await));
}

/// 6: a permissive policy cannot lift a restrictive one.
#[tokio::test]
async fn a_policy_that_allows_does_not_cancel_one_that_restricts() {
    let db = migrated_db().await;
    let ahmad = user(&db, "ahmad").await;
    let server = ssh_target(&db, "srv", false).await;
    let deploy = account(&db, server.id, "deploy").await;
    assign(&db, ahmad, server.id, deploy).await;
    standing_policy(
        &db,
        "Anytime",
        PolicyScope {
            user_id: Some(ahmad),
            ..PolicyScope::default()
        },
        AccessRules::new("UTC", RuleAction::Allow),
    )
    .await;
    standing_policy(
        &db,
        "Office hours",
        PolicyScope {
            target_id: Some(server.id),
            ..PolicyScope::default()
        },
        office(RuleAction::RequireApproval),
    )
    .await;

    assert!(needs_approval(
        &decision(&db, ahmad, &server, None, SATURDAY).await
    ));
}

/// Who and what a policy covers decides whether it applies.
#[tokio::test]
async fn a_policy_applies_only_to_what_it_covers() {
    let db = migrated_db().await;
    let ahmad = user(&db, "ahmad").await;
    let yusif = user(&db, "yusif").await;
    let server = ssh_target(&db, "srv", false).await;
    let other = ssh_target(&db, "other", false).await;
    for (who, target) in [(ahmad, &server), (yusif, &server), (ahmad, &other)] {
        let deploy = account(&db, target.id, &format!("deploy-{who}")).await;
        assign(&db, who, target.id, deploy).await;
    }
    let ops = group(&db, "ops", &[yusif]).await;

    // A user, on one target.
    standing_policy(
        &db,
        "Ahmad on srv",
        PolicyScope {
            user_id: Some(ahmad),
            target_id: Some(server.id),
            ..PolicyScope::default()
        },
        office(RuleAction::Deny),
    )
    .await;
    assert!(is_deny(
        &decision(&db, ahmad, &server, None, SATURDAY).await
    ));
    assert!(
        is_allow(&decision(&db, ahmad, &other, None, SATURDAY).await),
        "not that target"
    );
    assert!(
        is_allow(&decision(&db, yusif, &server, None, SATURDAY).await),
        "not that user"
    );

    // A group.
    standing_policy(
        &db,
        "Ops after hours",
        PolicyScope {
            role_id: Some(ops),
            ..PolicyScope::default()
        },
        office(RuleAction::RequireApproval),
    )
    .await;
    assert!(needs_approval(
        &decision(&db, yusif, &server, None, SATURDAY).await
    ));
    assert!(
        is_allow(&decision(&db, ahmad, &other, None, SATURDAY).await),
        "not a member"
    );
}

#[tokio::test]
async fn a_disabled_policy_is_ignored() {
    let db = migrated_db().await;
    let ahmad = user(&db, "ahmad").await;
    let server = ssh_target(&db, "srv", false).await;
    let deploy = account(&db, server.id, "deploy").await;
    assign(&db, ahmad, server.id, deploy).await;
    let policy = standing_policy(
        &db,
        "Frozen",
        PolicyScope {
            target_id: Some(server.id),
            ..PolicyScope::default()
        },
        AccessRules::new("UTC", RuleAction::Deny),
    )
    .await;
    assert!(is_deny(
        &decision(&db, ahmad, &server, None, MONDAY_NOON).await
    ));

    let mut model: AccessPolicy::ActiveModel = policy.into();
    model.enabled = Set(false);
    model.update(&db).await.unwrap();
    assert!(!any_enabled(&db).await.unwrap());
    assert!(is_allow(
        &decision(&db, ahmad, &server, None, MONDAY_NOON).await
    ));
}

/// 15: a user cannot dodge a policy on an account by naming another, and a policy on one
/// account does not touch the user's other accounts.
#[tokio::test]
async fn a_policy_on_an_account_follows_the_account_the_connection_uses() {
    let db = migrated_db().await;
    let ahmad = user(&db, "ahmad").await;
    let server = ssh_target(&db, "srv", false).await;
    let deploy = account(&db, server.id, "deploy").await;
    let root = account(&db, server.id, "root").await;
    assign(&db, ahmad, server.id, deploy).await;
    assign(&db, ahmad, server.id, root).await;
    standing_policy(
        &db,
        "root needs approval",
        PolicyScope {
            target_id: Some(server.id),
            target_account_id: Some(root),
            ..PolicyScope::default()
        },
        AccessRules::new("UTC", RuleAction::RequireApproval),
    )
    .await;

    let as_deploy = AccountRequest::Name("deploy".into());
    let as_root = AccountRequest::Name("root".into());
    assert!(is_allow(
        &decision(&db, ahmad, &server, Some(&as_deploy), MONDAY_NOON).await
    ));
    assert!(needs_approval(
        &decision(&db, ahmad, &server, Some(&as_root), MONDAY_NOON).await
    ));

    // Not saying which account: the strictest reading applies, and no account is settled, so
    // nobody is asked to approve a connection that is not yet for any account.
    let unsettled = evaluate_connection(&db, facts(ahmad, &server, None), at(MONDAY_NOON))
        .await
        .unwrap();
    assert!(needs_approval(&unsettled.decision));
    assert!(unsettled.account.is_none());
    assert_eq!(unsettled.candidate_names.len(), 2);
}

// ---------------------------------------------------------------------------------------
// The gate's view: what a connection must be given
// ---------------------------------------------------------------------------------------

fn authorization(user_id: Uuid, target: CommonTarget) -> TargetAuthorization {
    TargetAuthorization::for_test(
        AuthStateUserInfo {
            id: user_id,
            username: "ahmad".into(),
        },
        target,
        Protocol::Ssh,
    )
}

#[tokio::test]
async fn the_gate_asks_for_nothing_where_nothing_is_configured() {
    let db = migrated_db().await;
    let ahmad = user(&db, "ahmad").await;
    let server = ssh_target(&db, "srv", false).await;
    let asked = requirement_for(&db, &authorization(ahmad, server))
        .await
        .unwrap();
    assert!(matches!(asked, Requirement::None));
}

/// The target's own setting is untouched by policies: still the same gate, still remembered.
#[tokio::test]
async fn the_targets_own_setting_still_asks_without_a_policy() {
    let db = migrated_db().await;
    let ahmad = user(&db, "ahmad").await;
    let server = ssh_target(&db, "srv", true).await;
    let asked = requirement_for(&db, &authorization(ahmad, server))
        .await
        .unwrap();
    assert!(matches!(asked, Requirement::TargetSetting));
}

#[tokio::test]
async fn the_gate_refuses_a_denied_connection_before_asking_anyone() {
    let db = migrated_db().await;
    let ahmad = user(&db, "ahmad").await;
    let server = ssh_target(&db, "srv", false).await;
    let deploy = account(&db, server.id, "deploy").await;
    assign(&db, ahmad, server.id, deploy).await;
    standing_policy(
        &db,
        "Frozen",
        PolicyScope {
            target_id: Some(server.id),
            ..PolicyScope::default()
        },
        AccessRules::new("UTC", RuleAction::Deny),
    )
    .await;
    match requirement_for(&db, &authorization(ahmad, server)).await {
        Err(WarpgateError::AccessPolicyDenied(reason)) => assert!(reason.contains("Frozen")),
        Err(error) => panic!("unexpected error: {error}"),
        Ok(_) => panic!("a denying policy must refuse"),
    }
}

#[tokio::test]
async fn the_gate_asks_for_an_approval_bound_to_the_account() {
    let db = migrated_db().await;
    let ahmad = user(&db, "ahmad").await;
    let server = ssh_target(&db, "srv", false).await;
    let deploy = account(&db, server.id, "deploy").await;
    assign(&db, ahmad, server.id, deploy).await;
    standing_policy(
        &db,
        "Always ask",
        PolicyScope {
            target_id: Some(server.id),
            ..PolicyScope::default()
        },
        AccessRules::new("UTC", RuleAction::RequireApproval),
    )
    .await;
    match requirement_for(&db, &authorization(ahmad, server))
        .await
        .unwrap()
    {
        Requirement::Policy(ask) => {
            assert_eq!(ask.account.map(|(id, _)| id), Some(deploy));
            assert!(ask.requirement.reason.contains("Always ask"));
        }
        _ => panic!("expected a policy approval"),
    }
}

// ---------------------------------------------------------------------------------------
// Policies as they are saved
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn a_policy_must_cover_something_and_be_readable() {
    let db = migrated_db().await;
    let server = ssh_target(&db, "srv", false).await;
    let nothing = create_policy(
        &db,
        PolicyData {
            name: "Nothing".into(),
            description: String::new(),
            enabled: true,
            scope: PolicyScope::default(),
            rules: office(RuleAction::Deny),
        },
        None,
    )
    .await;
    assert!(matches!(nothing, Err(PolicyError::Invalid(_))));

    let bad_zone = create_policy(
        &db,
        PolicyData {
            name: "Bad zone".into(),
            description: String::new(),
            enabled: true,
            scope: PolicyScope {
                target_id: Some(server.id),
                ..PolicyScope::default()
            },
            rules: AccessRules::new("Mars/Base", RuleAction::Deny),
        },
        None,
    )
    .await;
    assert!(matches!(bad_zone, Err(PolicyError::Invalid(_))));

    let account_without_target = create_policy(
        &db,
        PolicyData {
            name: "Orphan account".into(),
            description: String::new(),
            enabled: true,
            scope: PolicyScope {
                user_id: None,
                role_id: None,
                target_id: None,
                target_account_id: Some(Uuid::new_v4()),
            },
            rules: office(RuleAction::Deny),
        },
        None,
    )
    .await;
    assert!(matches!(
        account_without_target,
        Err(PolicyError::Invalid(_))
    ));
}

#[tokio::test]
async fn policy_names_are_unique_and_an_assignments_schedule_is_edited_with_it() {
    let db = migrated_db().await;
    let ahmad = user(&db, "ahmad").await;
    let server = ssh_target(&db, "srv", false).await;
    let deploy = account(&db, server.id, "deploy").await;
    let assignment = assign(&db, ahmad, server.id, deploy).await;
    let scope = PolicyScope {
        target_id: Some(server.id),
        ..PolicyScope::default()
    };
    standing_policy(&db, "Office hours", scope, office(RuleAction::Deny)).await;
    let duplicate = create_policy(
        &db,
        PolicyData {
            name: "office HOURS".into(),
            description: String::new(),
            enabled: true,
            scope,
            rules: office(RuleAction::Deny),
        },
        None,
    )
    .await;
    assert!(matches!(duplicate, Err(PolicyError::Conflict(_))));

    // The assignment's schedule is kept apart: not listed, not editable as a standing policy.
    let schedule = save_assignment_rules(
        &db,
        &assignment,
        "Schedule",
        Some(office(RuleAction::Deny)),
        None,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(list_policies(&db).await.unwrap().len(), 1);
    assert!(matches!(
        delete_policy(&db, schedule.id).await,
        Err(PolicyError::Invalid(_))
    ));

    // Saving again replaces it rather than adding another; saving none removes it.
    save_assignment_rules(
        &db,
        &assignment,
        "Schedule",
        Some(office(RuleAction::RequireApproval)),
        None,
    )
    .await
    .unwrap();
    assert_eq!(
        AccessPolicy::Entity::find()
            .filter(AccessPolicy::Column::AssignmentId.eq(assignment.id))
            .all(&db)
            .await
            .unwrap()
            .len(),
        1
    );
    save_assignment_rules(&db, &assignment, "Schedule", None, None)
        .await
        .unwrap();
    assert!(
        assignment_policy(&db, assignment.id)
            .await
            .unwrap()
            .is_none()
    );
}

// ---------------------------------------------------------------------------------------
// The life of an approval
// ---------------------------------------------------------------------------------------

struct Ask {
    session_id: UserSessionId,
    user_id: Uuid,
    target: CommonTarget,
    account_id: Option<Uuid>,
}

/// A pending approval request with its policy context, as the gate leaves one.
async fn ask(
    db: &DatabaseConnection,
    user_id: Uuid,
    target: &CommonTarget,
    account_id: Option<Uuid>,
    expires_in: Duration,
    valid_for_seconds: i64,
    constraints: &[RuleApproval],
) -> Ask {
    let session_id = UserSessionId(Uuid::new_v4());
    let now = OffsetDateTime::now_utc();
    Requests::upsert_request(
        db,
        Requests::NewRequest {
            session_id,
            target: target.name.clone(),
            node_id: NodeId(Uuid::new_v4()),
            protocol: "ssh".into(),
            username: "ahmad".into(),
            user_id,
            remote_address: None,
            match_digest: None,
            started: now,
            about: Requests::RequestAsk::Admin { ticket_id: None },
        },
    )
    .await
    .unwrap();
    AccessApprovalContext::ActiveModel {
        session_id: Set(session_id),
        kind: Set(ApprovalKind::Admin),
        target: Set(target.name.clone()),
        policy_id: Set(None),
        policy_name: Set("Always ask".into()),
        reason: Set("outside hours".into()),
        user_id: Set(user_id),
        target_id: Set(target.id),
        target_account_id: Set(account_id),
        account_name: Set(Some("deploy".into())),
        expires_at: Set(now + expires_in),
        valid_for_seconds: Set(valid_for_seconds),
        valid_until: Set(None),
        used_at: Set(None),
        terms: Set(serde_json::to_value(constraints).unwrap()),
        created_at: Set(now),
    }
    .insert(db)
    .await
    .unwrap();
    Ask {
        session_id,
        user_id,
        target: target.clone(),
        account_id,
    }
}

impl Ask {
    fn claim(&self) -> AccessApprovalContext::Claim<'_> {
        AccessApprovalContext::Claim {
            session_id: self.session_id,
            kind: ApprovalKind::Admin,
            target: &self.target.name,
            user_id: self.user_id,
            target_id: self.target.id,
            target_account_id: self.account_id,
        }
    }

    async fn approve_as(
        &self,
        db: &DatabaseConnection,
        approver: Uuid,
    ) -> Result<bool, WarpgateError> {
        record_decision(
            db,
            self.session_id,
            ApprovalKind::Admin,
            &self.target.name,
            ApprovalDecision::Approved(ApprovalScope::Target),
            ApprovalActor {
                username: Some("approver".into()),
                user_id: approver,
            },
        )
        .await
    }
}

/// 11, 18: spent once; a second attempt, or a concurrent one, gets nothing.
#[tokio::test]
async fn an_approval_is_single_use_even_when_attempts_race() {
    let db = migrated_db().await;
    let ahmad = user(&db, "ahmad").await;
    let server = ssh_target(&db, "srv", false).await;
    let deploy = account(&db, server.id, "deploy").await;
    let ask = ask(
        &db,
        ahmad,
        &server,
        Some(deploy),
        Duration::minutes(15),
        1800,
        &[],
    )
    .await;
    let now = OffsetDateTime::now_utc();

    // Not approved yet: nothing to spend.
    assert!(
        !AccessApprovalContext::consume(&db, &ask.claim(), now)
            .await
            .unwrap()
    );

    assert!(ask.approve_as(&db, Uuid::new_v4()).await.unwrap());
    let claims: Vec<_> = (0..8).map(|_| ask.claim()).collect();
    let attempts = futures::future::join_all(
        claims
            .iter()
            .map(|claim| AccessApprovalContext::consume(&db, claim, now)),
    )
    .await;
    let spent = attempts
        .into_iter()
        .filter(|r| *r.as_ref().unwrap())
        .count();
    assert_eq!(spent, 1, "exactly one connection gets the approval");
    assert!(
        !AccessApprovalContext::consume(&db, &ask.claim(), now)
            .await
            .unwrap()
    );
}

/// 11, 17: an approval is for the user, the target and the account it was asked for.
#[tokio::test]
async fn an_approval_cannot_be_moved_to_another_user_target_or_account() {
    let db = migrated_db().await;
    let ahmad = user(&db, "ahmad").await;
    let server = ssh_target(&db, "srv", false).await;
    let other = ssh_target(&db, "other", false).await;
    let deploy = account(&db, server.id, "deploy").await;
    let root = account(&db, server.id, "root").await;
    let ask = ask(
        &db,
        ahmad,
        &server,
        Some(deploy),
        Duration::minutes(15),
        1800,
        &[],
    )
    .await;
    ask.approve_as(&db, Uuid::new_v4()).await.unwrap();
    let now = OffsetDateTime::now_utc();

    let mut wrong_user = ask.claim();
    wrong_user.user_id = Uuid::new_v4();
    let mut wrong_target = ask.claim();
    wrong_target.target_id = other.id;
    let mut wrong_account = ask.claim();
    wrong_account.target_account_id = Some(root);
    let mut no_account = ask.claim();
    no_account.target_account_id = None;
    for claim in [wrong_user, wrong_target, wrong_account, no_account] {
        assert!(
            !AccessApprovalContext::consume(&db, &claim, now)
                .await
                .unwrap()
        );
    }
    assert!(
        AccessApprovalContext::consume(&db, &ask.claim(), now)
            .await
            .unwrap(),
        "the right claim still works: the wrong ones spent nothing"
    );
}

/// 8, 9, 10: the request lapses unanswered; an approval lapses unused; they are different clocks.
#[tokio::test]
async fn the_request_and_the_approval_expire_separately() {
    let db = migrated_db().await;
    let ahmad = user(&db, "ahmad").await;
    let server = ssh_target(&db, "srv", false).await;
    let deploy = account(&db, server.id, "deploy").await;

    // A request nobody answered in time can no longer be approved, and is closed.
    let lapsed = ask(
        &db,
        ahmad,
        &server,
        Some(deploy),
        Duration::seconds(-1),
        1800,
        &[],
    )
    .await;
    assert!(!lapsed.approve_as(&db, Uuid::new_v4()).await.unwrap());
    let row =
        Requests::Entity::find_by_id((lapsed.session_id, ApprovalKind::Admin, server.name.clone()))
            .one(&db)
            .await
            .unwrap()
            .unwrap();
    assert_eq!(row.status, ApprovalRequestStatus::TimedOut);
    let context =
        AccessApprovalContext::find(&db, lapsed.session_id, ApprovalKind::Admin, &server.name)
            .await
            .unwrap()
            .unwrap();
    assert_eq!(
        approval_status(row.status, &context, OffsetDateTime::now_utc()),
        AccessApprovalStatus::Expired
    );

    // An approval that was given in time is good for its own, separate validity.
    let timely = ask(
        &db,
        ahmad,
        &server,
        Some(deploy),
        Duration::minutes(15),
        60,
        &[],
    )
    .await;
    assert!(timely.approve_as(&db, Uuid::new_v4()).await.unwrap());
    let approved_at = OffsetDateTime::now_utc();
    assert!(
        !AccessApprovalContext::consume(&db, &timely.claim(), approved_at + Duration::seconds(120))
            .await
            .unwrap(),
        "an unused approval does not outlive its validity"
    );
    assert!(
        AccessApprovalContext::consume(&db, &timely.claim(), approved_at)
            .await
            .unwrap(),
        "within its validity it works"
    );
}

/// 10: who may approve is the policy's say, and nobody approves their own.
#[tokio::test]
async fn only_a_named_approver_may_approve_and_never_the_requester() {
    let db = migrated_db().await;
    let ahmad = user(&db, "ahmad").await;
    let alice = user(&db, "alice").await;
    let bob = user(&db, "bob").await;
    let server = ssh_target(&db, "srv", false).await;
    let deploy = account(&db, server.id, "deploy").await;
    let constraints = vec![RuleApproval {
        approver_user_ids: vec![alice],
        ..RuleApproval::default()
    }];
    let request = ask(
        &db,
        ahmad,
        &server,
        Some(deploy),
        Duration::minutes(15),
        1800,
        &constraints,
    )
    .await;

    assert!(matches!(
        request.approve_as(&db, bob).await,
        Err(WarpgateError::AccessPolicyDenied(_))
    ));
    assert!(matches!(
        request.approve_as(&db, ahmad).await,
        Err(WarpgateError::AccessPolicyDenied(_))
    ));
    assert!(request.approve_as(&db, alice).await.unwrap());

    // A group can be the approver.
    let ops = group(&db, "ops", &[bob]).await;
    let by_group = ask(
        &db,
        ahmad,
        &server,
        Some(deploy),
        Duration::minutes(15),
        1800,
        &[RuleApproval {
            approver_role_ids: vec![ops],
            ..RuleApproval::default()
        }],
    )
    .await;
    assert!(by_group.approve_as(&db, bob).await.unwrap());
}

/// A policy's approval is one connection: whatever scope the approver picked, it is not
/// remembered for later connections.
#[tokio::test]
async fn an_approval_cannot_be_widened_by_the_approver() {
    let db = migrated_db().await;
    let ahmad = user(&db, "ahmad").await;
    let server = ssh_target(&db, "srv", false).await;
    let deploy = account(&db, server.id, "deploy").await;
    let request = ask(
        &db,
        ahmad,
        &server,
        Some(deploy),
        Duration::minutes(15),
        1800,
        &[],
    )
    .await;
    // `approve_as` asks for `ApprovalScope::Target`.
    assert!(request.approve_as(&db, Uuid::new_v4()).await.unwrap());
    let row = Requests::Entity::find_by_id((
        request.session_id,
        ApprovalKind::Admin,
        server.name.clone(),
    ))
    .one(&db)
    .await
    .unwrap()
    .unwrap();
    assert_eq!(row.scope, Some(ApprovalScope::Once));
}

/// 13: an approval never outlives the access under it.
#[tokio::test]
async fn an_approval_does_not_survive_revoked_access() {
    let db = migrated_db().await;
    let ahmad = user(&db, "ahmad").await;
    let server = ssh_target(&db, "srv", false).await;
    let deploy = account(&db, server.id, "deploy").await;
    let assignment = assign(&db, ahmad, server.id, deploy).await;
    let who = ConnectingUser {
        id: ahmad,
        username: "ahmad",
    };
    assert!(
        still_authorized(&db, who, &server, Some(deploy), false)
            .await
            .unwrap()
    );
    assert!(
        !still_authorized(&db, who, &server, Some(Uuid::new_v4()), false)
            .await
            .unwrap(),
        "an account the user was not assigned"
    );

    A::Entity::delete_by_id(assignment.id)
        .exec(&db)
        .await
        .unwrap();
    assert!(
        !still_authorized(&db, who, &server, Some(deploy), false)
            .await
            .unwrap(),
        "revoked"
    );
}

/// 8: the statuses people see, from the request and its context.
#[tokio::test]
async fn statuses_are_read_off_the_request_and_its_context() {
    let db = migrated_db().await;
    let ahmad = user(&db, "ahmad").await;
    let server = ssh_target(&db, "srv", false).await;
    let deploy = account(&db, server.id, "deploy").await;
    let request = ask(
        &db,
        ahmad,
        &server,
        Some(deploy),
        Duration::minutes(15),
        1800,
        &[],
    )
    .await;
    let now = OffsetDateTime::now_utc();
    let status = |row: ApprovalRequestStatus,
                  context: &AccessApprovalContext::Model,
                  at: OffsetDateTime| { approval_status(row, context, at) };
    let context =
        AccessApprovalContext::find(&db, request.session_id, ApprovalKind::Admin, &server.name)
            .await
            .unwrap()
            .unwrap();

    assert_eq!(
        status(ApprovalRequestStatus::Pending, &context, now),
        AccessApprovalStatus::Pending
    );
    assert_eq!(
        status(
            ApprovalRequestStatus::Pending,
            &context,
            now + Duration::minutes(16)
        ),
        AccessApprovalStatus::Expired,
        "unanswered past its expiry"
    );
    assert_eq!(
        status(ApprovalRequestStatus::Rejected, &context, now),
        AccessApprovalStatus::Rejected
    );
    assert_eq!(
        status(ApprovalRequestStatus::TimedOut, &context, now),
        AccessApprovalStatus::Expired
    );
    assert_eq!(
        status(ApprovalRequestStatus::Abandoned, &context, now),
        AccessApprovalStatus::Abandoned
    );

    request.approve_as(&db, Uuid::new_v4()).await.unwrap();
    let approved =
        AccessApprovalContext::find(&db, request.session_id, ApprovalKind::Admin, &server.name)
            .await
            .unwrap()
            .unwrap();
    assert_eq!(
        status(ApprovalRequestStatus::Approved, &approved, now),
        AccessApprovalStatus::Approved
    );
    assert_eq!(
        status(
            ApprovalRequestStatus::Approved,
            &approved,
            now + Duration::hours(1)
        ),
        AccessApprovalStatus::Expired,
        "approved but not used in time"
    );
    AccessApprovalContext::consume(&db, &request.claim(), now)
        .await
        .unwrap();
    let used =
        AccessApprovalContext::find(&db, request.session_id, ApprovalKind::Admin, &server.name)
            .await
            .unwrap()
            .unwrap();
    assert_eq!(
        status(ApprovalRequestStatus::Approved, &used, now),
        AccessApprovalStatus::Used
    );
}

/// 20: nothing about an existing, unscheduled assignment changed: no context, no policy, the
/// original approval path is what a decision on a plain request goes through.
#[tokio::test]
async fn a_plain_request_is_decided_as_it_always_was() {
    let db = migrated_db().await;
    let ahmad = user(&db, "ahmad").await;
    let session_id = UserSessionId(Uuid::new_v4());
    Requests::upsert_request(
        &db,
        Requests::NewRequest {
            session_id,
            target: "srv".into(),
            node_id: NodeId(Uuid::new_v4()),
            protocol: "ssh".into(),
            username: "ahmad".into(),
            user_id: ahmad,
            remote_address: None,
            match_digest: None,
            started: OffsetDateTime::now_utc(),
            about: Requests::RequestAsk::Admin { ticket_id: None },
        },
    )
    .await
    .unwrap();
    // Even the requester may decide it here (the administrator API applies its own
    // self-approval rule); the scope they chose is kept.
    let decided = record_decision(
        &db,
        session_id,
        ApprovalKind::Admin,
        "srv",
        ApprovalDecision::Approved(ApprovalScope::AllTargets),
        ApprovalActor {
            username: Some("ahmad".into()),
            user_id: ahmad,
        },
    )
    .await
    .unwrap();
    assert!(decided);
    let row = Requests::Entity::find_by_id((session_id, ApprovalKind::Admin, "srv".to_owned()))
        .one(&db)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.scope, Some(ApprovalScope::AllTargets));
}
