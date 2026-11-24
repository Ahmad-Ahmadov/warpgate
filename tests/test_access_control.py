"""Unified Access Control (m00098), end to end over native SSH.

A user connects only through an assignment of user, target and account; a target's
accounts grant nothing by themselves; several accounts need an explicit choice
(`user:target:account`); a revoked assignment, or someone else's account, lets nobody in.
"""

import subprocess
from uuid import uuid4

import pytest

from .api_client import admin_client, sdk
from .conftest import ProcessManager, WarpgateProcess
from .util import wait_port

common_args = [
    "-i",
    "/dev/null",
    "-o",
    "PreferredAuthentications=password",
]


@pytest.fixture(scope="module")
def ssh_server(processes, wg_c_ed25519_pubkey):
    port = processes.start_ssh_server(trusted_keys=[wg_c_ed25519_pubkey.read_text()])
    wait_port(port)
    return port


def _user(api):
    user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
    api.create_password_credential(user.id, sdk.NewPasswordCredential(password="123"))
    return user


def _ssh_target(api, port):
    # Blank account fields: the target's settings name no account; its accounts are
    # added on their own.
    return api.create_target(
        sdk.TargetDataRequest(
            name=f"ssh-{uuid4()}",
            require_approval=False,
            ticket_requests_disabled=False,
            ticket_require_approval=False,
            options=sdk.TargetOptions(
                sdk.TargetOptionsTargetSSHOptions(
                    kind="Ssh",
                    allow_insecure_algos=False,
                    host="localhost",
                    port=port,
                    username="",
                    auth=sdk.SSHTargetAuth(
                        sdk.SSHTargetAuthSshTargetPublicKeyAuth(kind="PublicKey")
                    ),
                )
            ),
        )
    )


def _account(api, target, name, primary=False):
    return api.create_target_account(
        target.id,
        sdk.TargetAccountDataRequest(
            kind=sdk.TargetAccountKind.LOCAL,
            name=name,
            auth_method=sdk.TargetAccountAuthMethod.STORED_CREDENTIAL,
            credential=sdk.TargetAccountCredential(
                sdk.TargetAccountCredentialSshTargetPublicKeyAuth(kind="PublicKey")
            ),
            is_primary=primary,
        ),
    )


def _assign(api, user, target, account):
    return api.create_access_assignment(
        sdk.CreateAccessAssignmentRequest(
            user_id=user.id, target_id=target.id, account_id=account.id
        )
    )


def _ls(processes, wg, selector, timeout):
    client = processes.start_ssh_client(
        f"{selector}@localhost",
        "-p",
        str(wg.ssh_port),
        *common_args,
        "ls",
        "/bin/sh",
        password="123",
        stderr=subprocess.PIPE,
    )
    stdout, _ = client.communicate(timeout=timeout)
    return client.returncode == 0 and stdout == b"/bin/sh\n"


class Test:
    def test_an_assignment_is_the_whole_permission(
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
            root = _account(api, target, "root")

            # 2: an account alone grants nothing.
            assert not _ls(processes, shared_wg, f"{user.username}:{target.name}", timeout)

            # 1: one assignment, chosen without asking.
            assignment = _assign(api, user, target, root)
            assert _ls(processes, shared_wg, f"{user.username}:{target.name}", timeout)

            # 4: revoked, it lets nobody in.
            api.delete_access_assignment(assignment.id)
            assert not _ls(processes, shared_wg, f"{user.username}:{target.name}", timeout)

    def test_several_accounts_need_an_explicit_choice(
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
            root = _account(api, target, "root")
            deploy = _account(api, target, "deploy")
            backup = _account(api, target, "backup")
            _assign(api, user, target, root)
            _assign(api, user, target, deploy)
            _assign(api, other, target, backup)

            # 10, 30: no implicit first account.
            assert not _ls(processes, shared_wg, f"{user.username}:{target.name}", timeout)
            assert _ls(processes, shared_wg, f"{user.username}:{target.name}:root", timeout)
            # 9: another user's account, or one that does not exist, is refused.
            for name in ["backup", "administrator"]:
                assert not _ls(
                    processes, shared_wg, f"{user.username}:{target.name}:{name}", timeout
                )

            listed = api.list_access_assignments(target_id=target.id)
            assert {(a.username, a.account) for a in listed} == {
                (user.username, "root"),
                (user.username, "deploy"),
                (other.username, "backup"),
            }

    def test_a_group_grants_through_the_same_rules(
        self,
        processes: ProcessManager,
        timeout,
        ssh_server,
        shared_wg: WarpgateProcess,
    ):
        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            user = _user(api)
            group = api.create_role(sdk.RoleDataRequest(name=f"group-{uuid4()}"))
            api.add_user_role(user.id, group.id)
            target = _ssh_target(api, ssh_server)

            # The legacy "allow a role on a target" has no account to grant yet: an
            # explicit refusal, not silent access.
            with pytest.raises(sdk.ApiException) as refused:
                api.add_target_role(target.id, group.id)
            assert refused.value.status == 409
            assert not _ls(processes, shared_wg, f"{user.username}:{target.name}", timeout)

            # With a primary account it translates into the group granting it.
            _account(api, target, "root", primary=True)
            api.add_target_role(target.id, group.id)
            assert _ls(processes, shared_wg, f"{user.username}:{target.name}", timeout)
            listed = api.list_access_assignments(target_id=target.id, group_id=group.id)
            assert [a.group_name for a in listed] == [group.name]

            # 18, 19: excluding the member from the grant takes it away from them alone.
            grant_id = listed[0].grant_id
            api.exclude_from_access_group_grant(
                grant_id, sdk.ExcludeFromGrantRequest(user_id=user.id)
            )
            assert not _ls(processes, shared_wg, f"{user.username}:{target.name}", timeout)

            # Restored, then gone again once the user leaves the group.
            api.delete_access_group_exclusion(
                next(
                    a.exclusion_id
                    for a in api.list_access_assignments(target_id=target.id)
                    if a.exclusion_id
                )
            )
            assert _ls(processes, shared_wg, f"{user.username}:{target.name}", timeout)
            api.delete_user_role(user.id, group.id)
            assert not _ls(processes, shared_wg, f"{user.username}:{target.name}", timeout)
