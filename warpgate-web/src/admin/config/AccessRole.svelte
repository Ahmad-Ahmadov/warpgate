<script lang="ts">
    import { api, type Role, type Target, type User } from 'admin/lib/api'
    import { stringifyError } from 'common/errors'
    import ItemList, { type PaginatedResponse } from 'common/ItemList.svelte'
    import Loadable from 'common/Loadable.svelte'
    import * as rx from 'rxjs'
    import { link, replace } from 'svelte-spa-router'
    import Button from 'ui/Button.svelte'
    import Callout from 'ui/Callout.svelte'
    import ConfirmDialog from 'ui/ConfirmDialog.svelte'
    import Input from 'ui/Input.svelte'
    import Toggle from 'ui/Toggle.svelte'
    import { adminPermissions } from '../lib/store'

    interface Props {
        params: { id: string }
    }

    let { params }: Props = $props()

    let error: string | null = $state(null)
    let role: Role | undefined = $state()
    const initPromise = init()

    async function init() {
        role = await api.getRole({ id: params.id })
        return role
    }

    function loadUsers(): rx.Observable<PaginatedResponse<User>> {
        return rx
            .from(
                api.getRoleUsers({
                    id: params.id,
                }),
            )
            .pipe(
                rx.map(targets => ({
                    items: targets,
                    offset: 0,
                    total: targets.length,
                })),
            )
    }

    function loadTargets(): rx.Observable<PaginatedResponse<Target>> {
        return rx
            .from(
                api.getRoleTargets({
                    id: params.id,
                }),
            )
            .pipe(
                rx.map(targets => ({
                    items: targets,
                    offset: 0,
                    total: targets.length,
                })),
            )
    }

    async function update() {
        if (!role) return
        try {
            role = await api.updateRole({
                id: params.id,
                roleDataRequest: role,
            })
        } catch (err) {
            error = await stringifyError(err)
        }
    }

    let removing = $state(false)

    async function confirmRemove() {
        if (!role) {
            return
        }
        await api.deleteRole(role)
        replace('/config/access-control/groups')
    }
</script>

<div class="container-max-md">
    <Loadable promise={initPromise} bind:value={role}>
        {#snippet children(role)}
            <div class="page-summary-bar">
                <div>
                    <h1>{role.name}</h1>
                    <div class="text-muted">access group</div>
                </div>
            </div>

            <Input label="Name" bind:value={role.name} />

            <Input label="Description" bind:value={role.description} />

            <div class="mb-4">
                <Toggle
                    id="isDefault"
                    label="Automatically assign to all new users"
                    bind:checked={role.isDefault}
                />
            </div>
        {/snippet}
    </Loadable>

    {#if error}
        <Callout tone="danger" title="Something went wrong">{error}</Callout>
    {/if}

    <div class="d-flex">
        <a
            href="/log/access-role/{params.id}"
            use:link
            class="btn btn-secondary"
        >
            Audit log
        </a>

        <Button
            variant="primary"
            disabled={!$adminPermissions.accessRolesEdit}
            class="ms-auto"
            click={update}
        >
            Update
        </Button>

        <Button
            class="ms-2"
            disabled={!$adminPermissions.accessRolesDelete}
            variant="destructive"
            onclick={() => (removing = true)}
        >
            Remove
        </Button>
    </div>

    <p class="mt-4">
        <a href="#/config/access-control/groups?group={params.id}">
            What this group grants, and the assignments it makes
        </a>
        (Access Control)
    </p>

    <h4 class="mt-5">Members</h4>

    <ItemList load={loadUsers}>
        {#snippet item(user)}
            <a
                class="list-group-item list-group-item-action"
                href="/config/users/{user.id}"
                use:link
            >
                <div>
                    <strong class="me-auto">
                        {user.username}
                    </strong>
                    {#if user.description}
                        <small class="d-block text-muted"
                            >{user.description}</small
                        >
                    {/if}
                </div>
            </a>
        {/snippet}
        {#snippet empty()}
            <Callout>This group has no members</Callout>
        {/snippet}
    </ItemList>

    <h4 class="mt-4">Targets it grants</h4>

    <ItemList load={loadTargets}>
        {#snippet item(target)}
            <a
                class="list-group-item list-group-item-action"
                href="/config/targets/{target.id}"
                use:link
            >
                <div class="me-auto">
                    <strong>
                        {target.name}
                    </strong>
                    {#if target.description}
                        <small class="d-block text-muted"
                            >{target.description}</small
                        >
                    {/if}
                </div>
            </a>
        {/snippet}
        {#snippet empty()}
            <Callout>This group grants no target</Callout>
        {/snippet}
    </ItemList>
</div>

<ConfirmDialog
    bind:open={removing}
    title="Delete {role?.name ?? 'this group'}?"
    confirmLabel="Delete group"
    confirmText={role?.name}
    confirmTextLabel="group name"
    onconfirm={confirmRemove}
    oncancel={() => (removing = false)}
>
    <p>
        Every member leaves it, and every assignment it makes ends: its grants
        and its exclusions are deleted, and members lose access they had only
        through it. Access Control, Access groups, lists both before you do.
    </p>
</ConfirmDialog>
