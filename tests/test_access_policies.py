"""Access policies, end to end over native SSH: a schedule or approval rule is enforced by
the server on the connection itself, so a native client cannot get around it.

Every rule here is time-independent (no windows: "always"), so the tests do not depend on the
clock. The clock-reading rules (windows, overnight, timezones, daylight saving, precedence) and
the approval lifecycle (expiry, single use, binding, concurrency) are unit-tested in
`warpgate-core/src/access_policy`.
"""

import subprocess
from uuid import uuid4

import pytest

from .api_client import admin_client, sdk
from .approval_util import wait_for_pending_approval
from .conftest import ProcessManager, WarpgateProcess
from .test_access_control import _account, _assign, _ls, _ssh_target, _user, common_args
from .util import wait_port


@pytest.fixture(scope="module")
def ssh_server(processes, wg_c_ed25519_pubkey):
    port = processes.start_ssh_server(trusted_keys=[wg_c_ed25519_pubkey.read_text()])
    wait_port(port)
    return port


def _rules(outside, windows=None, **approval):
    approval.setdefault("approver_user_ids", [])
    approval.setdefault("approver_role_ids", [])
    return sdk.AccessRules(
        timezone="UTC",
        windows=windows or [],
        outside=outside,
        approval=sdk.AccessRuleApproval(**approval),
    )


def _policy(api, rules, name=None, **scope):
    return api.create_access_policy(
        sdk.AccessPolicyDataRequest(name=name or f"policy-{uuid4()}", rules=rules, **scope)
    )


def _start_ls(processes, wg, selector):
    return processes.start_ssh_client(
        f"{selector}@localhost",
        "-p",
        str(wg.ssh_port),
        *common_args,
        "ls",
        "/bin/sh",
        password="123",
        stderr=subprocess.PIPE,
    )


def _ls_result(client, timeout):
    stdout, _ = client.communicate(timeout=timeout)
    return client.returncode == 0 and stdout == b"/bin/sh\n"


class Test:
    def test_policies_are_validated_when_saved(self, shared_wg: WarpgateProcess):
        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            user = _user(api)
            always_deny = _rules(sdk.AccessRuleAction.DENY)

            # It has to cover something.
            with pytest.raises(sdk.ApiException) as refused:
                _policy(api, always_deny)
            assert refused.value.status == 400

            # An unknown timezone, and a window that is not a time range.
            with pytest.raises(sdk.ApiException) as refused:
                _policy(
                    api,
                    sdk.AccessRules(
                        timezone="Mars/Olympus_Mons",
                        windows=[],
                        outside=sdk.AccessRuleAction.DENY,
                        approval=sdk.AccessRuleApproval(
                            approver_user_ids=[], approver_role_ids=[]
                        ),
                    ),
                    user_id=user.id,
                )
            assert refused.value.status == 400
            with pytest.raises(sdk.ApiException) as refused:
                _policy(
                    api,
                    sdk.AccessRules(
                        timezone="UTC",
                        windows=[
                            sdk.AccessRuleWindow(
                                days=[sdk.AccessRuleWeekday.MON],
                                start="9am",
                                end="17:00",
                                action=sdk.AccessRuleAction.ALLOW,
                            )
                        ],
                        outside=sdk.AccessRuleAction.DENY,
                        approval=sdk.AccessRuleApproval(
                            approver_user_ids=[], approver_role_ids=[]
                        ),
                    ),
                    user_id=user.id,
                )
            assert refused.value.status == 400

            # Names are unique.
            name = f"unique-{uuid4()}"
            _policy(api, always_deny, name=name, user_id=user.id)
            with pytest.raises(sdk.ApiException) as refused:
                _policy(api, always_deny, name=name.upper(), user_id=user.id)
            assert refused.value.status == 409

    def test_a_policy_that_denies_refuses_a_native_connection(
        self,
        processes: ProcessManager,
        timeout,
        ssh_server,
        shared_wg: WarpgateProcess,
    ):
        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            user = _user(api)
            target = _ssh_target(api, ssh_server)
            account = _account(api, target, "deploy")
            _assign(api, user, target, account)
            selector = f"{user.username}:{target.name}:deploy"

            # No policy: it works, as it always did.
            assert _ls(processes, shared_wg, selector, timeout)

            policy = _policy(
                api, _rules(sdk.AccessRuleAction.DENY), user_id=user.id, target_id=target.id
            )
            assert not _ls(processes, shared_wg, selector, timeout)

            # A disabled policy is ignored; deleting it ends it.
            api.update_access_policy(
                policy.id,
                sdk.AccessPolicyDataRequest(
                    name=policy.name,
                    enabled=False,
                    user_id=user.id,
                    target_id=target.id,
                    rules=policy.rules,
                ),
            )
            assert _ls(processes, shared_wg, selector, timeout)
            api.update_access_policy(
                policy.id,
                sdk.AccessPolicyDataRequest(
                    name=policy.name,
                    enabled=True,
                    user_id=user.id,
                    target_id=target.id,
                    rules=policy.rules,
                ),
            )
            assert not _ls(processes, shared_wg, selector, timeout)
            api.delete_access_policy(policy.id)
            assert _ls(processes, shared_wg, selector, timeout)

    def test_an_assignments_own_schedule_is_enforced_and_removable(
        self,
        processes: ProcessManager,
        timeout,
        ssh_server,
        shared_wg: WarpgateProcess,
    ):
        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            user = _user(api)
            other = _user(api)
            target = _ssh_target(api, ssh_server)
            account = _account(api, target, "deploy")
            granted = api.create_access_assignment(
                sdk.CreateAccessAssignmentRequest(
                    user_id=user.id,
                    target_id=target.id,
                    account_id=account.id,
                    rules=_rules(sdk.AccessRuleAction.DENY),
                )
            )
            _assign(api, other, target, account)
            assert granted.rules is not None

            # Its schedule binds its own user, not the other user with the same account.
            assert not _ls(processes, shared_wg, f"{user.username}:{target.name}:deploy", timeout)
            assert _ls(processes, shared_wg, f"{other.username}:{target.name}:deploy", timeout)

            # Editing something else leaves the schedule alone.
            kept = api.update_access_assignment(
                granted.id,
                sdk.UpdateAccessAssignmentRequest(
                    account_id=account.id, enabled=True, note="still scheduled"
                ),
            )
            assert kept.rules is not None
            assert not _ls(processes, shared_wg, f"{user.username}:{target.name}:deploy", timeout)

            # Removing it lifts the restriction.
            lifted = api.update_access_assignment(
                granted.id,
                sdk.UpdateAccessAssignmentRequest(
                    account_id=account.id, enabled=True, remove_rules=True
                ),
            )
            assert lifted.rules is None
            assert _ls(processes, shared_wg, f"{user.username}:{target.name}:deploy", timeout)

    def test_a_policy_that_asks_for_approval_holds_the_connection_until_it_is_approved(
        self,
        processes: ProcessManager,
        timeout,
        ssh_server,
        shared_wg: WarpgateProcess,
    ):
        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            user = _user(api)
            target = _ssh_target(api, ssh_server)
            account = _account(api, target, "deploy")
            _assign(api, user, target, account)
            _policy(
                api,
                _rules(
                    sdk.AccessRuleAction.REQUIRE_APPROVAL,
                    request_expiry_seconds=120,
                    valid_for_seconds=120,
                ),
                user_id=user.id,
                target_id=target.id,
            )

            client = _start_ls(processes, shared_wg, f"{user.username}:{target.name}:deploy")
            pending = wait_for_pending_approval(api, target.name, user.username)
            # What an approver is told: which policy, why, which account, until when.
            assert pending.policy_name is not None
            assert pending.reason
            assert pending.account == "deploy"
            assert pending.expires_at is not None
            assert pending.can_approve

            api.approve_session(
                pending.id,
                sdk.ApproveSessionRequest(
                    scope=sdk.ApprovalScope.ALL_TARGETS, target=pending.target
                ),
            )
            assert _ls_result(client, timeout)

            # Approved and used; whatever scope the approver picked, it was for that one
            # connection. A second connection asks again.
            second = _start_ls(processes, shared_wg, f"{user.username}:{target.name}:deploy")
            again = wait_for_pending_approval(api, target.name, user.username)
            api.reject_session(
                again.id, sdk.RejectSessionRequest(target=again.target)
            )
            assert not _ls_result(second, timeout)

            history = api.list_access_approvals()
            statuses = {item.status for item in history if item.username == user.username}
            assert sdk.AccessApprovalStatus.USED in statuses
            assert sdk.AccessApprovalStatus.REJECTED in statuses

    def test_an_unanswered_request_expires_and_cannot_be_used(
        self,
        processes: ProcessManager,
        timeout,
        ssh_server,
        shared_wg: WarpgateProcess,
    ):
        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            user = _user(api)
            target = _ssh_target(api, ssh_server)
            account = _account(api, target, "deploy")
            _assign(api, user, target, account)
            _policy(
                api,
                _rules(sdk.AccessRuleAction.REQUIRE_APPROVAL, request_expiry_seconds=3),
                user_id=user.id,
                target_id=target.id,
            )

            client = _start_ls(processes, shared_wg, f"{user.username}:{target.name}:deploy")
            pending = wait_for_pending_approval(api, target.name, user.username)
            # Nobody answers. The connection ends when the request lapses...
            assert not _ls_result(client, timeout)
            # ...and a request that has lapsed is no longer offered to approvers, so it can
            # not be approved after the fact.
            assert not [
                item
                for item in api.get_session_approvals()
                if item.id == pending.id and item.target == pending.target
            ]

    def test_only_the_named_approvers_may_approve(
        self,
        processes: ProcessManager,
        timeout,
        ssh_server,
        shared_wg: WarpgateProcess,
    ):
        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            user = _user(api)
            nominated = _user(api)
            target = _ssh_target(api, ssh_server)
            account = _account(api, target, "deploy")
            _assign(api, user, target, account)
            _policy(
                api,
                _rules(
                    sdk.AccessRuleAction.REQUIRE_APPROVAL,
                    request_expiry_seconds=30,
                    approver_user_ids=[nominated.id],
                ),
                user_id=user.id,
                target_id=target.id,
            )

            client = _start_ls(processes, shared_wg, f"{user.username}:{target.name}:deploy")
            pending = wait_for_pending_approval(api, target.name, user.username)
            # The admin API user is not the nominated approver.
            assert pending.approvers is not None
            assert not pending.can_approve
            with pytest.raises(sdk.ApiException) as refused:
                api.approve_session(
                    pending.id,
                    sdk.ApproveSessionRequest(
                        scope=sdk.ApprovalScope.ONCE, target=pending.target
                    ),
                )
            assert refused.value.status == 403
            # Rejecting is always open to an approver: it only restricts.
            api.reject_session(
                pending.id, sdk.RejectSessionRequest(target=pending.target)
            )
            assert not _ls_result(client, timeout)
