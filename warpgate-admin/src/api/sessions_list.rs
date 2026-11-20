use std::collections::HashMap;

use poem::session::Session;
use poem::web::Data;
use poem::web::websocket::WebSocket;
use poem::{IntoResponse, handler};
use poem_openapi::param::Query;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, OpenApi};
use sea_orm::prelude::Expr;
use sea_orm::sea_query::{Func, Query, SelectStatement};
use sea_orm::{
    ColumnTrait, DatabaseConnection, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder,
    QuerySelect, Select,
};
use time::OffsetDateTime;
use warpgate_common::auth::ApprovalKind;
use warpgate_common::{AdminPermission, TargetSessionId, UserSessionId, WarpgateError};
use warpgate_common_http::AuthenticatedRequestContext;
use warpgate_core::cluster::{ClusterNotification, refresh_notification_stream};
use warpgate_core::{
    RecordingSnapshot, RecordingState, SessionApprovalRequestSnapshot, SessionsFilter,
    TargetSessionSnapshot, UserSessionSnapshot,
};
use warpgate_db_entities::Recording::{self, RecordingKind};
use warpgate_db_entities::{Node, SessionApprovalRequest, Target, TargetSession, UserSession};

use super::AdminContext;
use super::pagination::PaginatedResponse;
use crate::api::common::require_admin_permission;

/// The recordings the session list carries for each session: enough for its Recording column
/// (what "Watch" opens, and whether anything is live or still being finalized), not every
/// forwarded connection of a busy session. `recording_count` has the total.
const LISTED_RECORDINGS: usize = 5;

/// How long after its connection closes a recording not yet marked ended counts as being
/// finalized rather than abandoned. One cut off by a node going down is never marked ended.
const FINALIZING: time::Duration = time::Duration::minutes(5);

pub struct Api;

#[derive(ApiResponse)]
enum GetSessionsResponse {
    #[oai(status = 200)]
    Ok(Json<PaginatedResponse<UserSessionSnapshot>>),
}

#[derive(ApiResponse)]
enum CloseAllSessionsResponse {
    #[oai(status = 201)]
    Ok,
}

#[OpenApi]
impl Api {
    #[oai(path = "/sessions", method = "get", operation_id = "get_sessions")]
    #[allow(clippy::too_many_arguments)]
    async fn api_get_all_sessions(
        &self,
        admin: AdminContext,
        offset: Query<Option<u64>>,
        limit: Query<Option<u64>>,
        active_only: Query<Option<bool>>,
        logged_in_only: Query<Option<bool>>,
        username: Query<Option<String>>,
        has_recording: Query<Option<bool>>,
    ) -> poem::Result<GetSessionsResponse> {
        admin.require(AdminPermission::SessionsView)?;
        // Which sessions were recorded is itself recording information: filtering on it takes
        // the permission to view recordings, as seeing them does.
        if has_recording.is_some() {
            admin.require(AdminPermission::RecordingsView)?;
        }

        let db = &admin.services().db;

        let q = sessions_query(
            active_only.unwrap_or(false),
            logged_in_only.unwrap_or(false),
            username.as_deref(),
            *has_recording,
        );

        let offset = offset.unwrap_or(0);
        let limit = limit.unwrap_or(100);
        let total = q.clone().count(db).await.map_err(WarpgateError::from)?;
        let parents = q
            .offset(offset)
            .limit(limit)
            .all(db)
            .await
            .map_err(WarpgateError::from)?;
        let recordings = Recordings::for_admin(&admin, Some(LISTED_RECORDINGS)).await;
        let snapshots = user_session_snapshots(db, parents, &recordings).await?;

        Ok(GetSessionsResponse::Ok(Json(
            PaginatedResponse::from_parts(snapshots, offset, total),
        )))
    }

    #[oai(
        path = "/sessions",
        method = "delete",
        operation_id = "close_all_sessions"
    )]
    async fn api_close_all_sessions(
        &self,
        admin: AdminContext,
        session: &Session,
    ) -> poem::Result<CloseAllSessionsResponse> {
        admin.require(AdminPermission::SessionsTerminate)?;

        admin
            .services()
            .close_sessions(SessionsFilter::All)
            .await
            .map_err(poem::error::InternalServerError)?;

        session.purge();

        Ok(CloseAllSessionsResponse::Ok)
    }
}

/// The session list's query: newest first, narrowed by the list's filters.
fn sessions_query(
    active_only: bool,
    logged_in_only: bool,
    username: Option<&str>,
    has_recording: Option<bool>,
) -> Select<UserSession::Entity> {
    // sort by both as a sorting tiebreaker
    let mut q = UserSession::Entity::find()
        .order_by_desc(UserSession::Column::Started)
        .order_by_desc(UserSession::Column::Id);

    if active_only {
        q = q.filter(UserSession::Column::Ended.is_null());
    }
    if logged_in_only {
        q = q.filter(UserSession::Column::Username.is_not_null());
    }
    if let Some(username_filter) = username {
        q = q.filter(
            Expr::expr(Func::lower(Expr::col(UserSession::Column::Username)))
                .eq(username_filter.to_lowercase()),
        );
    }
    match has_recording {
        Some(true) => q = q.filter(UserSession::Column::Id.in_subquery(recorded_sessions())),
        Some(false) => q = q.filter(UserSession::Column::Id.not_in_subquery(recorded_sessions())),
        None => {}
    }
    q
}

/// The user sessions with at least one recording, on any of their target connections.
fn recorded_sessions() -> SelectStatement {
    Query::select()
        .column(TargetSession::Column::UserSessionId)
        .from(TargetSession::Entity)
        .and_where(
            Expr::col(TargetSession::Column::Id).in_subquery(
                Query::select()
                    .column(Recording::Column::SessionId)
                    .from(Recording::Entity)
                    .to_owned(),
            ),
        )
        .to_owned()
}

/// Whether [`user_session_snapshots`] attaches recordings.
pub(super) enum Recordings {
    /// The viewer may not see recordings, so none are attached and none are counted.
    Hidden,
    /// Attached, at most `limit` a session (all of them for `None`), each in the state it is in
    /// under this recording `retention`.
    Shown {
        retention: time::Duration,
        limit: Option<usize>,
    },
}

impl Recordings {
    /// What `admin` may be shown: recordings only with the permission to view them.
    pub(super) async fn for_admin(admin: &AdminContext, limit: Option<usize>) -> Self {
        if !admin.has_permission(AdminPermission::RecordingsView) {
            return Self::Hidden;
        }
        let retention = admin.services().config.lock().await.store.log.retention;
        Self::Shown {
            // The cleanup cannot convert a retention this long either, and deletes nothing.
            retention: time::Duration::try_from(retention).unwrap_or(time::Duration::MAX),
            limit,
        }
    }
}

/// The recordings of the target connections `targets`, by user session, newest first, each
/// with the state it is in now.
async fn recording_snapshots(
    db: &DatabaseConnection,
    targets: &[TargetSession::Model],
    retention: time::Duration,
) -> Result<HashMap<UserSessionId, Vec<RecordingSnapshot>>, WarpgateError> {
    if targets.is_empty() {
        return Ok(HashMap::new());
    }
    let connections: HashMap<TargetSessionId, (UserSessionId, Option<OffsetDateTime>)> = targets
        .iter()
        .map(|target| (target.id, (target.user_session_id, target.ended)))
        .collect();
    let rows = Recording::Entity::find()
        .filter(Recording::Column::SessionId.is_in(connections.keys().copied()))
        .order_by_desc(Recording::Column::Started)
        .all(db)
        .await?;

    let now = OffsetDateTime::now_utc();
    let mut by_session: HashMap<UserSessionId, Vec<RecordingSnapshot>> = HashMap::new();
    for recording in rows {
        let Some(&(session, connection_ended)) = connections.get(&recording.session_id) else {
            continue;
        };
        by_session
            .entry(session)
            .or_default()
            .push(RecordingSnapshot {
                id: recording.id,
                target_session_id: recording.session_id,
                state: recording_state(recording.ended, connection_ended, now, retention),
                kind: recording.kind,
                metadata: recording.metadata,
                started: recording.started,
                ended: recording.ended,
            });
    }
    Ok(by_session)
}

/// The state of a recording that ended at `recording_ended`, made on a target connection that
/// closed at `connection_ended`.
fn recording_state(
    recording_ended: Option<OffsetDateTime>,
    connection_ended: Option<OffsetDateTime>,
    now: OffsetDateTime,
    retention: time::Duration,
) -> RecordingState {
    let Some(connection_ended) = connection_ended else {
        // The connection is open: a recording still being written is live, and one that has
        // ended (an SSH exec channel, say) is complete.
        return if recording_ended.is_some() {
            RecordingState::Available
        } else {
            RecordingState::Live
        };
    };
    // The cleanup's own rule: a recording goes with its target connection once that closed
    // before the retention cutoff.
    if now
        .checked_sub(retention)
        .is_some_and(|cutoff| connection_ended < cutoff)
    {
        return RecordingState::Expired;
    }
    if recording_ended.is_none() && now - connection_ended < FINALIZING {
        return RecordingState::Processing;
    }
    RecordingState::Available
}

/// How much a recording tells someone looking at what happened in a session, most first: one
/// that can be watched before one that cannot; then one being recorded now, then one complete;
/// then a desktop or someone at a shell before a command or a forwarded connection; then the
/// earliest.
fn relevance(recording: &RecordingSnapshot) -> (bool, u8, u8, OffsetDateTime) {
    let replayable = matches!(
        recording.kind,
        RecordingKind::Terminal | RecordingKind::Desktop
    );
    let state = match recording.state {
        RecordingState::Live => 0,
        RecordingState::Available => 1,
        RecordingState::Processing => 2,
        RecordingState::Expired => 3,
    };
    let kind = match recording.kind {
        RecordingKind::Desktop => 0,
        RecordingKind::Terminal if is_interactive(&recording.metadata) => 1,
        RecordingKind::Terminal => 2,
        RecordingKind::Kubernetes => 3,
        RecordingKind::Traffic => 4,
    };
    (!replayable, state, kind, recording.started)
}

/// Whether a terminal recording is of someone at a shell or in a pod rather than of a command.
fn is_interactive(metadata: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(metadata)
        .ok()
        .and_then(|metadata| {
            metadata
                .get("type")
                .and_then(serde_json::Value::as_str)
                .map(|kind| matches!(kind, "ssh-shell" | "kubernetes-exec" | "kubernetes-attach"))
        })
        .unwrap_or(false)
}

pub(super) async fn user_session_snapshots(
    db: &DatabaseConnection,
    parents: Vec<UserSession::Model>,
    recordings: &Recordings,
) -> Result<Vec<UserSessionSnapshot>, WarpgateError> {
    let parent_ids = parents.iter().map(|session| session.id).collect::<Vec<_>>();

    let approvals = if parent_ids.is_empty() {
        vec![]
    } else {
        SessionApprovalRequest::Entity::find()
            .filter(SessionApprovalRequest::Column::SessionId.is_in(parent_ids.clone()))
            .filter(SessionApprovalRequest::Column::Kind.eq(ApprovalKind::Admin))
            .all(db)
            .await?
    };

    let approval_target_names = approvals
        .iter()
        .map(|a| a.target.clone())
        .collect::<Vec<_>>();
    let approval_targets = if approval_target_names.is_empty() {
        HashMap::new()
    } else {
        Target::Entity::find()
            .filter(Target::Column::Name.is_in(approval_target_names))
            .all(db)
            .await?
            .into_iter()
            .map(|t| (t.name.clone(), t))
            .collect::<HashMap<_, _>>()
    };

    let targets = if parent_ids.is_empty() {
        vec![]
    } else {
        TargetSession::Entity::find()
            .filter(TargetSession::Column::UserSessionId.is_in(parent_ids.clone()))
            .order_by_desc(TargetSession::Column::Started)
            .all(db)
            .await?
    };

    let mut node_ids = parents
        .iter()
        .filter_map(|session| session.node_id)
        .chain(targets.iter().filter_map(|session| session.node_id))
        .collect::<Vec<_>>();
    node_ids.sort_unstable();
    node_ids.dedup();
    let node_names = if node_ids.is_empty() {
        HashMap::new()
    } else {
        Node::Entity::find()
            .filter(Node::Column::Id.is_in(node_ids))
            .all(db)
            .await?
            .into_iter()
            .map(|node| (node.id, node.hostname))
            .collect::<HashMap<_, _>>()
    };

    let (mut recordings_by_session, listed) = match recordings {
        Recordings::Hidden => (HashMap::new(), None),
        Recordings::Shown { retention, limit } => {
            (recording_snapshots(db, &targets, *retention).await?, *limit)
        }
    };

    let mut approvals_by_session: HashMap<_, Vec<_>> = HashMap::new();
    for approval in approvals {
        let parent_id = approval.session_id;
        let target = approval.target.clone();
        let mut snapshot: SessionApprovalRequestSnapshot = approval.into();
        if let Some(target) = approval_targets.get(&target) {
            snapshot.target_id = Some(target.id);
        }
        approvals_by_session
            .entry(parent_id)
            .or_default()
            .push(snapshot);
    }

    let mut targets_by_parent: HashMap<_, Vec<_>> = HashMap::new();
    for target in targets {
        let parent_id = target.user_session_id;
        let mut snapshot: TargetSessionSnapshot = target.into();
        snapshot.node_hostname = snapshot.node_id.and_then(|id| node_names.get(&id).cloned());
        targets_by_parent
            .entry(parent_id)
            .or_default()
            .push(snapshot);
    }

    Ok(parents
        .into_iter()
        .map(|parent| {
            let mut snapshot: UserSessionSnapshot = parent.into();
            snapshot.node_hostname = snapshot.node_id.and_then(|id| node_names.get(&id).cloned());
            snapshot.target_sessions = targets_by_parent.remove(&snapshot.id).unwrap_or_default();
            snapshot.admin_approvals = approvals_by_session
                .remove(&snapshot.id)
                .unwrap_or_default();

            let mut session_recordings = recordings_by_session
                .remove(&snapshot.id)
                .unwrap_or_default();
            snapshot.recording_count = u32::try_from(session_recordings.len()).unwrap_or(u32::MAX);
            if let Some(limit) = listed
                && session_recordings.len() > limit
            {
                session_recordings.sort_by_key(relevance);
                session_recordings.truncate(limit);
            }
            snapshot.recordings = session_recordings;
            snapshot
        })
        .collect())
}

#[handler]
pub async fn api_get_sessions_changes_stream(
    ctx: Data<&AuthenticatedRequestContext>,
    ws: WebSocket,
) -> Result<impl IntoResponse, WarpgateError> {
    require_admin_permission(&ctx, Some(AdminPermission::SessionsView)).await?;
    Ok(refresh_notification_stream(
        ws,
        ctx.services().cluster.subscribe(),
        |msg| matches!(msg, ClusterNotification::SessionsChanged).then(String::new),
    ))
}

#[cfg(test)]
mod tests {
    use sea_orm::ActiveValue::Set;
    use sea_orm::{ActiveModelTrait, Database};
    use time::OffsetDateTime;
    use uuid::Uuid;
    use warpgate_db_entities::Parameters::{ConfigMigrationValues, set_config_migration_values};
    use warpgate_db_migrations::migrate_database;

    use super::*;

    #[tokio::test]
    async fn user_session_snapshot_contains_its_target_sessions() {
        set_config_migration_values(ConfigMigrationValues::default());
        let db = Database::connect("sqlite::memory:").await.unwrap();
        migrate_database(&db).await.unwrap();
        let parent_id = warpgate_common::UserSessionId(Uuid::new_v4());
        let node_id = warpgate_common::NodeId(Uuid::new_v4());
        let parent = UserSession::ActiveModel {
            id: Set(parent_id),
            username: Set(Some("alice".into())),
            user_id: Set(Some(Uuid::new_v4())),
            remote_address: Set("127.0.0.1:22".into()),
            started: Set(OffsetDateTime::now_utc()),
            ended: Set(None),
            protocol: Set("SSH".into()),
            node_id: Set(Some(node_id)),
            auth_state_node_id: Set(None),
        }
        .insert(&db)
        .await
        .unwrap();

        for _ in 0..2 {
            TargetSession::ActiveModel {
                id: Set(warpgate_common::TargetSessionId(Uuid::new_v4())),
                user_session_id: Set(parent_id),
                target_snapshot: Set(r#"{"name":"web"}"#.into()),
                target_id: Set(Uuid::new_v4()),
                started: Set(parent.started),
                ended: Set(None),
                ticket_id: Set(None),
                node_id: Set(Some(node_id)),
            }
            .insert(&db)
            .await
            .unwrap();
        }

        let snapshot = user_session_snapshots(&db, vec![parent], &Recordings::Hidden)
            .await
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        assert_eq!(snapshot.target_sessions.len(), 2);
    }

    async fn database() -> DatabaseConnection {
        set_config_migration_values(ConfigMigrationValues::default());
        let db = Database::connect("sqlite::memory:").await.unwrap();
        migrate_database(&db).await.unwrap();
        db
    }

    async fn user_session(db: &DatabaseConnection) -> UserSession::Model {
        UserSession::ActiveModel {
            id: Set(UserSessionId(Uuid::new_v4())),
            username: Set(Some("alice".into())),
            user_id: Set(Some(Uuid::new_v4())),
            remote_address: Set("127.0.0.1:22".into()),
            started: Set(OffsetDateTime::now_utc() - time::Duration::hours(2)),
            ended: Set(None),
            protocol: Set("SSH".into()),
            node_id: Set(None),
            auth_state_node_id: Set(None),
        }
        .insert(db)
        .await
        .unwrap()
    }

    async fn target_session(
        db: &DatabaseConnection,
        session: UserSessionId,
        ended: Option<OffsetDateTime>,
    ) -> TargetSessionId {
        let id = TargetSessionId(Uuid::new_v4());
        TargetSession::ActiveModel {
            id: Set(id),
            user_session_id: Set(session),
            target_snapshot: Set(r#"{"name":"web"}"#.into()),
            target_id: Set(Uuid::new_v4()),
            started: Set(OffsetDateTime::now_utc() - time::Duration::hours(2)),
            ended: Set(ended),
            ticket_id: Set(None),
            node_id: Set(None),
        }
        .insert(db)
        .await
        .unwrap();
        id
    }

    async fn recording(
        db: &DatabaseConnection,
        connection: TargetSessionId,
        kind: RecordingKind,
        metadata: &str,
        ended: Option<OffsetDateTime>,
    ) -> Uuid {
        let id = Uuid::new_v4();
        Recording::ActiveModel {
            id: Set(id),
            name: Set(id.to_string()),
            started: Set(OffsetDateTime::now_utc() - time::Duration::hours(1)),
            ended: Set(ended),
            session_id: Set(connection),
            kind: Set(kind),
            metadata: Set(metadata.into()),
            generation: Set(3),
        }
        .insert(db)
        .await
        .unwrap();
        id
    }

    #[test]
    fn a_recording_is_in_the_state_its_connection_and_the_retention_put_it_in() {
        let now = OffsetDateTime::now_utc();
        let week = time::Duration::days(7);
        let ago = |minutes: i64| Some(now - time::Duration::minutes(minutes));

        // Connection open: live while written, complete once it ended (an exec channel).
        assert_eq!(recording_state(None, None, now, week), RecordingState::Live);
        assert_eq!(
            recording_state(ago(1), None, now, week),
            RecordingState::Available
        );
        // Connection just closed: being finalized until marked ended.
        assert_eq!(
            recording_state(None, ago(1), now, week),
            RecordingState::Processing
        );
        assert_eq!(
            recording_state(ago(1), ago(1), now, week),
            RecordingState::Available
        );
        // Never marked ended long after: cut off, but what was written is there.
        assert_eq!(
            recording_state(None, ago(60), now, week),
            RecordingState::Available
        );
        // Closed before the retention cutoff: the next cleanup removes it.
        let eight_days_ago = Some(now - time::Duration::days(8));
        assert_eq!(
            recording_state(ago(60), eight_days_ago, now, week),
            RecordingState::Expired
        );
        // A retention too long to represent expires nothing.
        assert_eq!(
            recording_state(ago(60), eight_days_ago, now, time::Duration::MAX),
            RecordingState::Available
        );
    }

    #[tokio::test]
    async fn snapshots_carry_recordings_only_for_viewers_allowed_them() {
        let db = database().await;
        let session = user_session(&db).await;
        let open = target_session(&db, session.id, None).await;
        let closed = target_session(
            &db,
            session.id,
            Some(OffsetDateTime::now_utc() - time::Duration::hours(1)),
        )
        .await;
        let desktop = recording(
            &db,
            open,
            RecordingKind::Desktop,
            r#"{"type":"desktop","protocol":"RDP","target":"web"}"#,
            None,
        )
        .await;
        let shell = recording(
            &db,
            closed,
            RecordingKind::Terminal,
            r#"{"type":"ssh-shell","channel":0}"#,
            Some(OffsetDateTime::now_utc()),
        )
        .await;
        let forward = recording(
            &db,
            closed,
            RecordingKind::Traffic,
            r#"{"type":"ssh-direct-tcpip","host":"db","port":5432}"#,
            Some(OffsetDateTime::now_utc()),
        )
        .await;
        let week = time::Duration::days(7);

        let hidden = user_session_snapshots(&db, vec![session.clone()], &Recordings::Hidden)
            .await
            .unwrap()
            .remove(0);
        assert!(hidden.recordings.is_empty());
        assert_eq!(hidden.recording_count, 0);

        let all = user_session_snapshots(
            &db,
            vec![session.clone()],
            &Recordings::Shown {
                retention: week,
                limit: None,
            },
        )
        .await
        .unwrap()
        .remove(0);
        assert_eq!(all.recording_count, 3);
        let state_of = |id: Uuid| {
            all.recordings
                .iter()
                .find(|recording| recording.id == id)
                .map(|recording| recording.state)
        };
        assert_eq!(state_of(desktop), Some(RecordingState::Live));
        assert_eq!(state_of(shell), Some(RecordingState::Available));
        assert_eq!(state_of(forward), Some(RecordingState::Available));

        // The list keeps the ones that matter most, and counts them all.
        let listed = user_session_snapshots(
            &db,
            vec![session],
            &Recordings::Shown {
                retention: week,
                limit: Some(2),
            },
        )
        .await
        .unwrap()
        .remove(0);
        assert_eq!(listed.recording_count, 3);
        let ids: Vec<_> = listed
            .recordings
            .iter()
            .map(|recording| recording.id)
            .collect();
        assert_eq!(ids, [desktop, shell]);
    }

    #[tokio::test]
    async fn the_recording_filter_finds_sessions_by_whether_they_were_recorded() {
        async fn found(db: &DatabaseConnection, has_recording: Option<bool>) -> Vec<UserSessionId> {
            let mut ids: Vec<_> = sessions_query(false, false, None, has_recording)
                .all(db)
                .await
                .unwrap()
                .into_iter()
                .map(|session| session.id)
                .collect();
            ids.sort();
            ids
        }

        let db = database().await;
        let recorded = user_session(&db).await;
        let connection = target_session(&db, recorded.id, None).await;
        recording(
            &db,
            connection,
            RecordingKind::Terminal,
            r#"{"type":"ssh-shell","channel":0}"#,
            None,
        )
        .await;
        let unrecorded = user_session(&db).await;
        target_session(&db, unrecorded.id, None).await;
        let idle = user_session(&db).await;

        let mut others = vec![unrecorded.id, idle.id];
        others.sort();
        let mut everyone = vec![recorded.id, unrecorded.id, idle.id];
        everyone.sort();
        assert_eq!(found(&db, Some(true)).await, [recorded.id]);
        assert_eq!(found(&db, Some(false)).await, others);
        assert_eq!(found(&db, None).await, everyone);
    }
}
