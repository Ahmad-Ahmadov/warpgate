use std::fmt::Display;

use tracing::info;
use uuid::Uuid;

use crate::helpers::logging::format_related_ids;

#[derive(Clone)]
pub enum CredentialChangedVia {
    Admin,
    SelfService,
}

impl Display for CredentialChangedVia {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Admin => write!(f, "admin"),
            Self::SelfService => write!(f, "self-service"),
        }
    }
}

/// Who acted, and on which target. Every Kubernetes audit event carries exactly
/// this identity, built once per request.
#[derive(Clone)]
pub struct KubernetesAuditSubject {
    pub session_id: Uuid,
    pub user_id: Uuid,
    pub username: String,
    pub target_id: Uuid,
    pub target_name: String,
}

#[derive(Clone)]
pub enum AuditEvent {
    CredentialCreated {
        credential_type: String,
        credential_name: Option<String>,
        via: CredentialChangedVia,
        user_id: Uuid,
        username: String,
        actor_user_id: Uuid,
    },
    CredentialDeleted {
        credential_type: String,
        credential_name: Option<String>,
        via: CredentialChangedVia,
        user_id: Uuid,
        username: String,
        actor_user_id: Uuid,
    },
    UserCreated {
        user_id: Uuid,
        username: String,
        actor_user_id: Uuid,
    },
    UserDeleted {
        user_id: Uuid,
        username: String,
        actor_user_id: Uuid,
    },
    TargetSessionStarted {
        session_id: Uuid,
        target_name: String,
        target_id: Uuid,
        user_id: Uuid,
        username: String,
    },
    TargetSessionEnded {
        session_id: Uuid,
        target_name: String,
        target_id: Uuid,
        user_id: Uuid,
        username: String,
    },
    AccessRoleGranted {
        grantee_id: Uuid,
        grantee_username: String,
        role_id: Uuid,
        role_name: String,
        actor_user_id: Uuid,
        related_access_roles: String,
    },
    AccessRoleRevoked {
        grantee_id: Uuid,
        grantee_username: String,
        role_id: Uuid,
        role_name: String,
        actor_user_id: Uuid,
        related_access_roles: String,
    },
    AdminRoleGranted {
        grantee_id: Uuid,
        grantee_username: String,
        admin_role_id: Uuid,
        admin_role_name: String,
        actor_user_id: Uuid,
        related_admin_roles: String,
    },
    AdminRoleRevoked {
        grantee_id: Uuid,
        grantee_username: String,
        admin_role_id: Uuid,
        admin_role_name: String,
        actor_user_id: Uuid,
        related_admin_roles: String,
    },
    // currently used for RDP logon PDU
    TargetLogon {
        session_id: Uuid,
        target_name: String,
        target_id: Uuid,
        user_id: Uuid,
        username: String,
        /// for RPD, DOMAIN\user
        target_account: Option<String>,
        target_session_id: Option<u32>,
    },
    /// A user's access to a target as a remote account changed (Access Control): a direct
    /// assignment was created, changed, enabled, disabled or revoked, or a group-derived one
    /// was excluded for the user or restored. Never carries a credential.
    AccessAssignmentChanged {
        /// `created`, `updated`, `enabled`, `disabled`, `revoked`, `excluded` or `restored`.
        action: String,
        /// The direct assignment, when it is one.
        assignment_id: Option<Uuid>,
        user_id: Uuid,
        username: String,
        target_id: Uuid,
        target_name: String,
        /// The remote account, as written (`CORP\ahmad`, `deploy`); empty where the protocol
        /// has none.
        account: String,
        account_id: Option<Uuid>,
        /// Where it comes from: `direct`, `group <name>`, `migration review`, …
        source: String,
        previous_state: String,
        new_state: String,
        /// The administrator; `None` when Warpgate itself made the change.
        actor_user_id: Option<Uuid>,
    },
    /// A connection asked for an account the user may not use on the target, or the user
    /// has no usable assignment there.
    AccessAssignmentRefused {
        user_id: Uuid,
        username: String,
        target_id: Uuid,
        target_name: String,
        requested_account: Option<String>,
        reason: String,
    },
    /// An administrator added, changed, disabled or deleted an account in a target's
    /// inventory. Never carries the credential itself.
    TargetAccountChanged {
        /// `created`, `updated` or `deleted`.
        action: String,
        target_id: Uuid,
        target_name: String,
        account_id: Uuid,
        account: String,
        kind: String,
        auth_method: String,
        /// `password`, `publickey`, … or `none`: the kind of credential, never its value.
        credential: String,
        enabled: bool,
        actor_user_id: Uuid,
    },
    /// An administrator changed what an access group grants: a target and account added or
    /// removed. `affected_users` lists the members whose effective access changed.
    AccessGroupGrantChanged {
        /// `added` or `removed`.
        action: String,
        group_id: Uuid,
        group_name: String,
        target_id: Uuid,
        target_name: String,
        account: String,
        account_id: Option<Uuid>,
        affected_users: String,
        actor_user_id: Uuid,
    },
    /// An administrator decided a permission the access-control migration could not map.
    AccessMigrationReviewResolved {
        review_id: Uuid,
        /// `confirmed` or `rejected`.
        decision: String,
        target_id: Option<Uuid>,
        user_id: Option<Uuid>,
        group_id: Option<Uuid>,
        account_id: Option<Uuid>,
        actor_user_id: Uuid,
    },
    /// The target logged a session on as an account the user may not use there (an account
    /// typed into the target's own sign-in screen, say), so Warpgate ended the session.
    TargetLogonRefused {
        session_id: Uuid,
        target_name: String,
        target_id: Uuid,
        user_id: Uuid,
        username: String,
        /// The account the target reported, as DOMAIN\user.
        target_account: String,
        /// The account the user may sign in as, which Warpgate signed in with.
        allowed_account: String,
    },
    TicketCreated {
        ticket_id: Uuid,
        user_id: Uuid,
        username: String,
        target: String,
        actor_user_id: Uuid,
    },
    TicketDeleted {
        ticket_id: Uuid,
        user_id: Uuid,
        username: String,
        target: String,
        actor_user_id: Uuid,
    },
    SecretResolved {
        backend: String,
        reference: String,
        success: bool,
    },
    SshCertificateIssued {
        backend: String,
        role: String,
        principal: String,
        key_id: String,
        success: bool,
    },
    /// `kubectl exec` — a command run inside an existing container.
    KubernetesExecStarted {
        subject: KubernetesAuditSubject,
        namespace: String,
        pod: String,
        /// The container the client named. `None` when it named none: kubectl
        /// omits it for single-container pods and lets the API server choose,
        /// and guessing here would put an unverified name in the audit log.
        container: Option<String>,
        /// argv as a JSON array.
        command: String,
        tty: bool,
        stdin: bool,
    },
    /// `kubectl attach` — a client attached to a container's existing streams.
    KubernetesAttachStarted {
        subject: KubernetesAuditSubject,
        namespace: String,
        pod: String,
        container: Option<String>,
        tty: bool,
    },
    /// `kubectl port-forward` — a tunnel to a pod's port was opened.
    KubernetesPortForwardStarted {
        subject: KubernetesAuditSubject,
        namespace: String,
        pod: String,
        /// Requested ports as a JSON array, when the client named them in the
        /// query. The websocket port-forward protocol negotiates ports per
        /// stream instead and sends no query at all, so this is often absent —
        /// and an empty list would read as "no ports", which is not the same.
        ports: Option<String>,
    },
    /// The cluster refused a streaming request — typically RBAC. Recorded
    /// separately because a denied attempt is exactly as interesting as a
    /// successful one, and the `...Started` event alone cannot say which it was.
    KubernetesStreamRejected {
        subject: KubernetesAuditSubject,
        namespace: String,
        pod: String,
        /// `exec`, `attach` or `portforward`.
        subresource: String,
        status: u16,
    },
    /// `kubectl debug` against a running pod: an ephemeral container was added
    /// to it. One event per container in the request.
    KubernetesDebugContainerCreated {
        subject: KubernetesAuditSubject,
        namespace: String,
        pod: String,
        debug_container: String,
        image: String,
        /// The container whose namespaces the debug container joins.
        target_container: Option<String>,
        /// argv as a JSON array.
        command: String,
        tty: bool,
        response_status: u16,
    },
    /// A `Pod` object was created directly — how `kubectl debug node/...` and
    /// `kubectl debug --copy-to` land a debug workload. Pods that a workload
    /// object (Deployment, DaemonSet, Job) creates on the user's behalf are
    /// not summarised; only the generic request log records those.
    KubernetesPodCreated {
        subject: KubernetesAuditSubject,
        namespace: String,
        pod: String,
        /// Container images as a JSON array.
        images: String,
        node_name: Option<String>,
        host_pid: bool,
        host_network: bool,
        privileged: bool,
        response_status: u16,
    },
}

impl AuditEvent {
    pub fn emit(&self) {
        match self {
            Self::CredentialCreated {
                credential_type,
                credential_name,
                via,
                user_id,
                username,
                actor_user_id,
            } => {
                if let Some(credential_name) = credential_name {
                    info!(
                        target: "audit",
                        _type = "CredentialCreated1",
                        credential_type = %credential_type,
                        credential_name = %credential_name,
                        via = %via,
                        user_id = %user_id,
                        username = %username,
                        related_users = %format_related_ids(&[*user_id, *actor_user_id]),
                        "Created credential"
                    );
                } else {
                    info!(
                        target: "audit",
                        _type = "CredentialCreated1",
                        credential_type = %credential_type,
                        via = %via,
                        user_id = %user_id,
                        username = %username,
                        related_users = %format_related_ids(&[*user_id, *actor_user_id]),
                        "Created credential"
                    );
                }
            }
            Self::CredentialDeleted {
                credential_type,
                credential_name,
                via,
                user_id,
                username,
                actor_user_id,
            } => {
                if let Some(credential_name) = credential_name {
                    info!(
                        target: "audit",
                        _type = "CredentialDeleted1",
                        credential_type = %credential_type,
                        credential_name = %credential_name,
                        via = %via,
                        user_id = %user_id,
                        username = %username,
                        related_users = %format_related_ids(&[*user_id, *actor_user_id]),
                        "Deleted credential"
                    );
                } else {
                    info!(
                        target: "audit",
                        _type = "CredentialDeleted1",
                        credential_type = %credential_type,
                        via = %via,
                        user_id = %user_id,
                        username = %username,
                        related_users = %format_related_ids(&[*user_id, *actor_user_id]),
                        "Deleted credential"
                    );
                }
            }
            Self::UserCreated {
                user_id,
                username,
                actor_user_id,
            } => {
                info!(
                    target: "audit",
                    _type = "UserCreated1",
                    user_id = %user_id,
                    username = %username,
                        related_users = %format_related_ids(&[*user_id, *actor_user_id]),
                    "Created user"
                );
            }
            Self::UserDeleted {
                user_id,
                username,
                actor_user_id,
            } => {
                info!(
                    target: "audit",
                    _type = "UserDeleted1",
                    user_id = %user_id,
                    username = %username,
                        related_users = %format_related_ids(&[*user_id, *actor_user_id]),
                    "Deleted user"
                );
            }
            Self::AccessRoleGranted {
                grantee_id,
                grantee_username,
                role_id,
                role_name,
                actor_user_id,
                related_access_roles,
            } => {
                info!(
                    target: "audit",
                    _type = "AccessRoleGranted1",
                    grantee_id = %grantee_id,
                    grantee_username = %grantee_username,
                    role_id = %role_id,
                    role_name = %role_name,
                        related_users = %format_related_ids(&[*grantee_id, *actor_user_id]),
                    ?related_access_roles,
                    "Granted access role"
                );
            }
            Self::AccessRoleRevoked {
                grantee_id,
                grantee_username,
                role_id,
                role_name,
                actor_user_id,
                related_access_roles,
            } => {
                info!(
                    target: "audit",
                    _type = "AccessRoleRevoked1",
                    grantee_id = %grantee_id,
                    grantee_username = %grantee_username,
                    role_id = %role_id,
                    role_name = %role_name,
                        related_users = %format_related_ids(&[*grantee_id, *actor_user_id]),
                    ?related_access_roles,
                    "Revoked access role"
                );
            }
            Self::AdminRoleGranted {
                grantee_id,
                grantee_username,
                admin_role_id,
                admin_role_name,
                actor_user_id,
                related_admin_roles,
            } => {
                info!(
                    target: "audit",
                    _type = "AdminRoleGranted1",
                    grantee_id = %grantee_id,
                    grantee_username = %grantee_username,
                    admin_role_id = %admin_role_id,
                    admin_role_name = %admin_role_name,
                        related_users = %format_related_ids(&[*grantee_id, *actor_user_id]),
                    ?related_admin_roles,
                    "Granted admin role"
                );
            }
            Self::AdminRoleRevoked {
                grantee_id,
                grantee_username,
                admin_role_id,
                admin_role_name,
                actor_user_id,
                related_admin_roles,
            } => {
                info!(
                    target: "audit",
                    _type = "AdminRoleRevoked1",
                    grantee_id = %grantee_id,
                    grantee_username = %grantee_username,
                    admin_role_id = %admin_role_id,
                    admin_role_name = %admin_role_name,
                    related_users = %format_related_ids(&[*grantee_id, *actor_user_id]),
                    ?related_admin_roles,
                    "Revoked admin role"
                );
            }
            Self::TargetSessionStarted {
                session_id,
                target_id,
                target_name,
                user_id,
                username,
            } => {
                info!(
                    target: "audit",
                    _type = "TargetSessionStarted1",
                    session_id = %session_id,
                    target_id = %target_id,
                    target_name = %target_name,
                    user_id = %user_id,
                    username = %username,
                    related_users = %format_related_ids(&[*user_id]),
                    "Target session started"
                );
            }
            Self::TargetSessionEnded {
                session_id,
                target_id,
                target_name,
                user_id,
                username,
            } => {
                info!(
                    target: "audit",
                    _type = "TargetSessionEnded1",
                    session_id = %session_id,
                    target_id = %target_id,
                    target_name = %target_name,
                    user_id = %user_id,
                    username = %username,
                    related_users = %format_related_ids(&[*user_id]),
                    "Target session ended"
                );
            }
            Self::TargetLogon {
                session_id,
                target_name,
                target_id,
                user_id,
                username,
                target_account,
                target_session_id,
            } => {
                info!(
                    target: "audit",
                    _type = "TargetLogon1",
                    session_id = %session_id,
                    target_id = %target_id,
                    target_name = %target_name,
                    user_id = %user_id,
                    username = %username,
                    target_account = target_account.as_deref(),
                    target_session_id = *target_session_id,
                    related_users = %format_related_ids(&[*user_id]),
                    "Logged on to target"
                );
            }
            Self::AccessAssignmentChanged {
                action,
                assignment_id,
                user_id,
                username,
                target_id,
                target_name,
                account,
                account_id,
                source,
                previous_state,
                new_state,
                actor_user_id,
            } => {
                let related: Vec<Uuid> = std::iter::once(*user_id).chain(*actor_user_id).collect();
                info!(
                    target: "audit",
                    _type = "AccessAssignmentChanged1",
                    action = %action,
                    assignment_id = assignment_id.map(|id| id.to_string()),
                    user_id = %user_id,
                    username = %username,
                    target_id = %target_id,
                    target_name = %target_name,
                    account = %account,
                    account_id = account_id.map(|id| id.to_string()),
                    source = %source,
                    previous_state = %previous_state,
                    new_state = %new_state,
                    actor_user_id = actor_user_id.map(|id| id.to_string()),
                    related_users = %format_related_ids(&related),
                    "Access assignment changed"
                );
            }
            Self::AccessAssignmentRefused {
                user_id,
                username,
                target_id,
                target_name,
                requested_account,
                reason,
            } => {
                tracing::warn!(
                    target: "audit",
                    _type = "AccessAssignmentRefused1",
                    user_id = %user_id,
                    username = %username,
                    target_id = %target_id,
                    target_name = %target_name,
                    requested_account = requested_account.as_deref(),
                    reason = %reason,
                    related_users = %format_related_ids(&[*user_id]),
                    "Refused a connection without a usable access assignment"
                );
            }
            Self::TargetAccountChanged {
                action,
                target_id,
                target_name,
                account_id,
                account,
                kind,
                auth_method,
                credential,
                enabled,
                actor_user_id,
            } => {
                info!(
                    target: "audit",
                    _type = "TargetAccountChanged1",
                    action = %action,
                    target_id = %target_id,
                    target_name = %target_name,
                    account_id = %account_id,
                    account = %account,
                    kind = %kind,
                    auth_method = %auth_method,
                    credential = %credential,
                    enabled = *enabled,
                    actor_user_id = %actor_user_id,
                    related_users = %format_related_ids(&[*actor_user_id]),
                    "Target account changed"
                );
            }
            Self::AccessGroupGrantChanged {
                action,
                group_id,
                group_name,
                target_id,
                target_name,
                account,
                account_id,
                affected_users,
                actor_user_id,
            } => {
                info!(
                    target: "audit",
                    _type = "AccessGroupGrantChanged1",
                    action = %action,
                    group_id = %group_id,
                    group_name = %group_name,
                    target_id = %target_id,
                    target_name = %target_name,
                    account = %account,
                    account_id = account_id.map(|id| id.to_string()),
                    affected_users = %affected_users,
                    actor_user_id = %actor_user_id,
                    related_users = %format_related_ids(&[*actor_user_id]),
                    related_access_roles = %format_related_ids(&[*group_id]),
                    "Access group grant changed"
                );
            }
            Self::AccessMigrationReviewResolved {
                review_id,
                decision,
                target_id,
                user_id,
                group_id,
                account_id,
                actor_user_id,
            } => {
                let related: Vec<Uuid> = std::iter::once(*actor_user_id).chain(*user_id).collect();
                info!(
                    target: "audit",
                    _type = "AccessMigrationReviewResolved1",
                    review_id = %review_id,
                    decision = %decision,
                    target_id = target_id.map(|id| id.to_string()),
                    user_id = user_id.map(|id| id.to_string()),
                    group_id = group_id.map(|id| id.to_string()),
                    account_id = account_id.map(|id| id.to_string()),
                    actor_user_id = %actor_user_id,
                    related_users = %format_related_ids(&related),
                    "Access migration review resolved"
                );
            }
            Self::TargetLogonRefused {
                session_id,
                target_name,
                target_id,
                user_id,
                username,
                target_account,
                allowed_account,
            } => {
                tracing::warn!(
                    target: "audit",
                    _type = "TargetLogonRefused1",
                    session_id = %session_id,
                    target_id = %target_id,
                    target_name = %target_name,
                    user_id = %user_id,
                    username = %username,
                    target_account = %target_account,
                    allowed_account = %allowed_account,
                    related_users = %format_related_ids(&[*user_id]),
                    "Target logged on as an account the user may not use; session ended"
                );
            }
            Self::TicketCreated {
                ticket_id,
                user_id,
                username,
                target,
                actor_user_id,
            } => {
                info!(
                    target: "audit",
                    _type = "TicketCreated1",
                    ticket_id = %ticket_id,
                    username = %username,
                    target = %target,
                    related_users = %format_related_ids(&[*user_id, *actor_user_id]),
                    "Created ticket"
                );
            }
            Self::TicketDeleted {
                ticket_id,
                user_id,
                username,
                target,
                actor_user_id,
            } => {
                info!(
                    target: "audit",
                    _type = "TicketDeleted1",
                    ticket_id = %ticket_id,
                    username = %username,
                    target = %target,
                    related_users = %format_related_ids(&[*user_id, *actor_user_id]),
                    "Deleted ticket"
                );
            }
            Self::SecretResolved {
                backend,
                reference,
                success,
            } => {
                info!(
                    target: "audit",
                    _type = "SecretResolved1",
                    backend = %backend,
                    reference = %reference,
                    success = %success,
                    "Resolved secret from backend"
                );
            }
            Self::SshCertificateIssued {
                backend,
                role,
                principal,
                key_id,
                success,
            } => {
                info!(
                    target: "audit",
                    _type = "SshCertificateIssued1",
                    backend = %backend,
                    role = %role,
                    principal = %principal,
                    key_id = %key_id,
                    success = %success,
                    "Requested an SSH certificate from backend"
                );
            }
            Self::KubernetesExecStarted {
                subject,
                namespace,
                pod,
                container,
                command,
                tty,
                stdin,
            } => {
                // An absent optional field is left out of the row entirely
                // rather than rendered as a placeholder that would read like a
                // real name; tracing records nothing for a `None`.
                info!(
                    target: "audit",
                    _type = "KubernetesExecStarted1",
                    session = %subject.session_id,
                    user_id = %subject.user_id,
                    username = %subject.username,
                    target_id = %subject.target_id,
                    target_name = %subject.target_name,
                    related_users = %format_related_ids(&[subject.user_id]),
                    namespace = %namespace,
                    pod = %pod,
                    container = container.as_deref(),
                    command = %command,
                    tty = %tty,
                    stdin = %stdin,
                    "Kubernetes exec"
                );
            }
            Self::KubernetesAttachStarted {
                subject,
                namespace,
                pod,
                container,
                tty,
            } => {
                info!(
                    target: "audit",
                    _type = "KubernetesAttachStarted1",
                    session = %subject.session_id,
                    user_id = %subject.user_id,
                    username = %subject.username,
                    target_id = %subject.target_id,
                    target_name = %subject.target_name,
                    related_users = %format_related_ids(&[subject.user_id]),
                    namespace = %namespace,
                    pod = %pod,
                    container = container.as_deref(),
                    tty = %tty,
                    "Kubernetes attach"
                );
            }
            Self::KubernetesPortForwardStarted {
                subject,
                namespace,
                pod,
                ports,
            } => {
                info!(
                    target: "audit",
                    _type = "KubernetesPortForwardStarted1",
                    session = %subject.session_id,
                    user_id = %subject.user_id,
                    username = %subject.username,
                    target_id = %subject.target_id,
                    target_name = %subject.target_name,
                    related_users = %format_related_ids(&[subject.user_id]),
                    namespace = %namespace,
                    pod = %pod,
                    ports = ports.as_deref(),
                    "Kubernetes port forwarding"
                );
            }
            Self::KubernetesStreamRejected {
                subject,
                namespace,
                pod,
                subresource,
                status,
            } => {
                info!(
                    target: "audit",
                    _type = "KubernetesStreamRejected1",
                    session = %subject.session_id,
                    user_id = %subject.user_id,
                    username = %subject.username,
                    target_id = %subject.target_id,
                    target_name = %subject.target_name,
                    related_users = %format_related_ids(&[subject.user_id]),
                    namespace = %namespace,
                    pod = %pod,
                    subresource = %subresource,
                    status = %status,
                    "Kubernetes stream rejected by the cluster"
                );
            }
            Self::KubernetesDebugContainerCreated {
                subject,
                namespace,
                pod,
                debug_container,
                image,
                target_container,
                command,
                tty,
                response_status,
            } => {
                info!(
                    target: "audit",
                    _type = "KubernetesDebugContainerCreated1",
                    session = %subject.session_id,
                    user_id = %subject.user_id,
                    username = %subject.username,
                    target_id = %subject.target_id,
                    target_name = %subject.target_name,
                    related_users = %format_related_ids(&[subject.user_id]),
                    namespace = %namespace,
                    pod = %pod,
                    debug_container = %debug_container,
                    image = %image,
                    target_container = target_container.as_deref(),
                    command = %command,
                    tty = %tty,
                    response_status = %response_status,
                    "Kubernetes debug container"
                );
            }
            Self::KubernetesPodCreated {
                subject,
                namespace,
                pod,
                images,
                node_name,
                host_pid,
                host_network,
                privileged,
                response_status,
            } => {
                info!(
                    target: "audit",
                    _type = "KubernetesPodCreated1",
                    session = %subject.session_id,
                    user_id = %subject.user_id,
                    username = %subject.username,
                    target_id = %subject.target_id,
                    target_name = %subject.target_name,
                    related_users = %format_related_ids(&[subject.user_id]),
                    namespace = %namespace,
                    pod = %pod,
                    images = %images,
                    node_name = node_name.as_deref(),
                    host_pid = %host_pid,
                    host_network = %host_network,
                    privileged = %privileged,
                    response_status = %response_status,
                    "Kubernetes pod created"
                );
            }
        }
    }
}
