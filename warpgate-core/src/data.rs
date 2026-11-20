use poem_openapi::{Enum, Object};
use serde::Serialize;
use time::OffsetDateTime;
use uuid::Uuid;
use warpgate_common::{NodeId, StoredSecrets, Target, TargetSessionId, UserSessionId};
use warpgate_db_entities::Recording::RecordingKind;
use warpgate_db_entities::{SessionApprovalRequest, TargetSession, UserSession};

#[derive(Serialize, Object)]
pub struct UserSessionSnapshot {
    pub id: UserSessionId,
    pub username: Option<String>,
    pub user_id: Option<Uuid>,
    pub started: OffsetDateTime,
    pub ended: Option<OffsetDateTime>,
    pub protocol: String,
    /// The node this session's lifetime is bound to; `None` for shared
    /// sessions, which any node serves.
    pub node_id: Option<NodeId>,
    /// Hostname of the bound node, while registered.
    pub node_hostname: Option<String>,
    pub remote_address: String,
    pub target_sessions: Vec<TargetSessionSnapshot>,
    pub admin_approvals: Vec<SessionApprovalRequestSnapshot>,
    /// The session's recordings, for a viewer allowed to see recordings, and otherwise none.
    /// The session list carries the few that matter most for each session, a single session
    /// all of them.
    pub recordings: Vec<RecordingSnapshot>,
    /// How many recordings the session has, for a viewer allowed to see recordings.
    pub recording_count: u32,
}

impl From<UserSession::Model> for UserSessionSnapshot {
    fn from(model: UserSession::Model) -> Self {
        Self {
            id: model.id,
            username: model.username,
            user_id: model.user_id,
            started: model.started,
            ended: model.ended,
            protocol: model.protocol,
            node_id: model.node_id,
            node_hostname: None,
            remote_address: model.remote_address,
            target_sessions: vec![],
            admin_approvals: vec![],
            recordings: vec![],
            recording_count: 0,
        }
    }
}

/// What can be done with a recording now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Enum)]
pub enum RecordingState {
    /// Being written: its target connection is still open.
    Live,
    /// Its connection has closed and it is being finalized; on object storage, its upload is
    /// finishing.
    Processing,
    /// Complete.
    Available,
    /// Past the recording retention period: removed with its session at the next cleanup.
    Expired,
}

/// A recording as the session screens show it, without its storage name or layout.
#[derive(Serialize, Object)]
pub struct RecordingSnapshot {
    pub id: Uuid,
    /// The target connection it was made on.
    pub target_session_id: TargetSessionId,
    pub kind: RecordingKind,
    /// What was recorded, as the recorder describes it: JSON with a `type` such as
    /// `ssh-shell` or `desktop`.
    pub metadata: String,
    pub started: OffsetDateTime,
    pub ended: Option<OffsetDateTime>,
    pub state: RecordingState,
}

#[derive(Serialize, Object)]
pub struct SessionApprovalRequestSnapshot {
    pub resolved_by_username: Option<String>,
    pub resolved_by_user_id: Option<Uuid>,
    pub resolved_at: Option<OffsetDateTime>,
    pub target_id: Option<Uuid>,
    pub target: String,
    pub status: SessionApprovalRequest::ApprovalRequestStatus,
}

impl From<SessionApprovalRequest::Model> for SessionApprovalRequestSnapshot {
    fn from(value: SessionApprovalRequest::Model) -> Self {
        Self {
            resolved_by_username: value.resolved_by_username,
            resolved_by_user_id: value.resolved_by_user_id,
            resolved_at: value.resolved_at,
            target: value.target,
            target_id: None,
            status: value.status,
        }
    }
}

#[derive(Serialize, Object)]
pub struct TargetSessionSnapshot {
    pub id: TargetSessionId,
    /// `None` only when the stored snapshot fails to parse.
    pub target: Option<Target>,
    pub target_id: Uuid,
    pub started: OffsetDateTime,
    pub ended: Option<OffsetDateTime>,
    pub ticket_id: Option<Uuid>,
    /// The node serving this target connection; `None` for shared (HTTP)
    /// target sessions, which are access records any node serves.
    pub node_id: Option<NodeId>,
    /// Hostname of the serving node, while registered.
    pub node_hostname: Option<String>,
}

impl From<TargetSession::Model> for TargetSessionSnapshot {
    fn from(model: TargetSession::Model) -> Self {
        Self {
            id: model.id,
            // Redacted on read as well as on write: rows predating snapshot
            // redaction (m00073 handled them, but defense in depth) must never
            // surface a secret through the API.
            target: serde_json::from_str::<Target>(&model.target_snapshot)
                .ok()
                .map(|target| target.redacted()),
            target_id: model.target_id,
            started: model.started,
            ended: model.ended,
            ticket_id: model.ticket_id,
            node_id: model.node_id,
            node_hostname: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use time::OffsetDateTime;
    use uuid::Uuid;
    use warpgate_common::{TargetSessionId, UserSessionId};
    use warpgate_db_entities::TargetSession;

    use super::TargetSessionSnapshot;

    #[test]
    fn snapshot_redacts_a_malformed_reference_on_read() {
        let malformed = "secret://not a valid ref";
        let target = serde_json::json!({
            "name": "t",
            "description": "",
            "mysql": {"host": "db", "auth": {"kind": "password", "password": malformed}},
            "ticket_requests_disabled": false,
            "ticket_require_approval": false,
            "require_approval": false,
        });

        let snapshot = TargetSessionSnapshot::from(TargetSession::Model {
            id: TargetSessionId(Uuid::nil()),
            user_session_id: UserSessionId(Uuid::nil()),
            target_snapshot: target.to_string(),
            target_id: Uuid::nil(),
            started: OffsetDateTime::UNIX_EPOCH,
            ended: None,
            ticket_id: None,
            node_id: None,
        });

        let rendered = serde_json::to_string(&snapshot.target.unwrap()).unwrap();
        assert!(!rendered.contains(malformed), "{rendered}");
    }
}
