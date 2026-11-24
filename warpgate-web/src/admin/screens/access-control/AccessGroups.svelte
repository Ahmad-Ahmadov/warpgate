<script lang="ts">
    /**
     * Access Control → Access groups: optional templates for granting the same
     * access to many users. A group is a role: its name, members and "new users
     * join it" setting stay on the role page; what it grants is set here, as
     * target and account, and every assignment it makes is shown, with the
     * group as its source.
     *
     * Adding or removing a grant first asks the server who it would affect, and
     * says so before anything changes.
     */
    import {
        type AccessAssignment,
        type AccessGroupGrantView,
        type AccessGroupView,
        AccessAssignmentStatus,
        api,
        type Target,
        type TargetAccount,
    } from 'admin/lib/api'
    import { stringifyError } from 'common/errors'
    import Badge from 'ui/Badge.svelte'
    import Button from 'ui/Button.svelte'
    import Callout from 'ui/Callout.svelte'
    import ConfirmDialog from 'ui/ConfirmDialog.svelte'
    import EmptyState from 'ui/EmptyState.svelte'
    import Select from 'ui/Select.svelte'
    import SkeletonRow from 'ui/SkeletonRow.svelte'
    import { toast } from 'ui/toasts.svelte'
    import { adminPermissions } from '../../lib/store'

    interface Props {
        initialGroup?: string
    }

    let { initialGroup = '' }: Props = $props()

    const ACCOUNT_PROTOCOLS = new Set(['Rdp', 'Ssh', 'MySql', 'Postgres'])

    let groups = $state<AccessGroupView[]>([])
    let targets = $state<Target[]>([])
    let loading = $state(true)
    let error = $state<string | null>(null)
    // svelte-ignore state_referenced_locally
    let groupId = $state(initialGroup)

    const group = $derived(groups.find(g => g.id === groupId))

    async function loadGroups() {
        loading = true
        error = null
        try {
            ;[groups, targets] = await Promise.all([
                api.listAccessGroups(),
                api.getTargets(),
            ])
            const first = groups[0]
            if (!groups.some(g => g.id === groupId) && first) {
                groupId = first.id
            }
        } catch (e) {
            error = await stringifyError(e)
        } finally {
            loading = false
        }
    }

    // ---- the selected group's grants and assignments ----
    let grants = $state<AccessGroupGrantView[]>([])
    let effective = $state<AccessAssignment[]>([])
    let detailError = $state<string | null>(null)

    async function loadGroup(id: string) {
        detailError = null
        try {
            ;[grants, effective] = await Promise.all([
                api.listAccessGroupGrants({ id }),
                api.listAccessAssignments({ groupId: id }),
            ])
        } catch (e) {
            detailError = await stringifyError(e)
        }
    }

    $effect(() => {
        const id = groupId
        grants = []
        effective = []
        if (id) {
            loadGroup(id)
        }
    })

    // ---- adding a grant ----
    let grantTarget = $state('')
    let grantAccount = $state('')
    let targetAccounts = $state<TargetAccount[]>([])
    const grantTargetKind = $derived(
        targets.find(t => t.id === grantTarget)?.options.kind ?? '',
    )
    const needsAccount = $derived(ACCOUNT_PROTOCOLS.has(grantTargetKind))

    $effect(() => {
        const id = grantTarget
        targetAccounts = []
        grantAccount = ''
        if (!id || !ACCOUNT_PROTOCOLS.has(targets.find(t => t.id === id)?.options.kind ?? '')) {
            return
        }
        let cancelled = false
        api.listTargetAccounts({ id })
            .then(accounts => {
                if (!cancelled) {
                    targetAccounts = accounts
                    const usable = accounts.filter(a => a.enabled && !a.problem)
                    const only = usable[0]
                    if (usable.length === 1 && only) {
                        grantAccount = only.id
                    }
                }
            })
            .catch(async e => {
                if (!cancelled) {
                    detailError = await stringifyError(e)
                }
            })
        return () => {
            cancelled = true
        }
    })

    const targetOptions = $derived([
        { value: '', label: 'Select a target…' },
        ...[...targets]
            .sort((a, b) => a.name.localeCompare(b.name))
            .map(t => ({ value: t.id, label: `${t.name} (${t.options.kind})` })),
    ])
    const accountOptions = $derived([
        { value: '', label: 'Select an account…' },
        ...targetAccounts.map(a => ({
            value: a.id,
            label: a.problem
                ? `${a.displayName} (${a.problem})`
                : a.enabled
                  ? a.displayName
                  : `${a.displayName} (disabled)`,
            disabled: !!a.problem,
        })),
    ])

    // An impact preview waiting for confirmation: adding or removing.
    let pending = $state<{
        kind: 'add' | 'remove'
        summary: string
        users: string[]
        grantId?: string
    } | null>(null)

    async function previewAdd() {
        if (!groupId || !grantTarget) {
            return
        }
        try {
            const preview = await api.createAccessGroupGrant({
                id: groupId,
                createAccessGroupGrantRequest: {
                    targetId: grantTarget,
                    accountId: grantAccount || undefined,
                    dryRun: true,
                },
            })
            pending = {
                kind: 'add',
                summary: preview.summary,
                users: preview.affectedUsers,
            }
        } catch (e) {
            detailError = await stringifyError(e)
        }
    }

    async function previewRemove(grant: AccessGroupGrantView) {
        if (!groupId) {
            return
        }
        try {
            const preview = await api.deleteAccessGroupGrant({
                id: groupId,
                grantId: grant.id,
                dryRun: true,
            })
            pending = {
                kind: 'remove',
                summary: preview.summary,
                users: preview.affectedUsers,
                grantId: grant.id,
            }
        } catch (e) {
            detailError = await stringifyError(e)
        }
    }

    async function apply() {
        const change = pending
        pending = null
        if (!change || !groupId) {
            return
        }
        try {
            const result =
                change.kind === 'add'
                    ? await api.createAccessGroupGrant({
                          id: groupId,
                          createAccessGroupGrantRequest: {
                              targetId: grantTarget,
                              accountId: grantAccount || undefined,
                              dryRun: false,
                          },
                      })
                    : await api.deleteAccessGroupGrant({
                          id: groupId,
                          grantId: change.grantId ?? '',
                          dryRun: false,
                      })
            toast.success(result.summary)
            grantTarget = ''
            await Promise.all([loadGroup(groupId), loadGroups()])
        } catch (e) {
            detailError = await stringifyError(e)
        }
    }

    async function restore(a: AccessAssignment) {
        if (!a.exclusionId || !groupId) {
            return
        }
        try {
            await api.deleteAccessGroupExclusion({ id: a.exclusionId })
            toast.success(`${a.username} restored`)
            await loadGroup(groupId)
        } catch (e) {
            detailError = await stringifyError(e)
        }
    }

    async function exclude(a: AccessAssignment) {
        if (!a.grantId || !groupId) {
            return
        }
        try {
            await api.excludeFromAccessGroupGrant({
                grantId: a.grantId,
                excludeFromGrantRequest: { userId: a.userId, note: '' },
            })
            toast.success(`${a.username} excluded from this grant`)
            await loadGroup(groupId)
        } catch (e) {
            detailError = await stringifyError(e)
        }
    }

    loadGroups()
</script>

{#if error}
    <Callout tone="danger" title="Something went wrong">{error}</Callout>
{:else if loading}
    <SkeletonRow rows={4} columns={[2, 1, 1]} />
{:else if !groups.length}
    <EmptyState
        title="No access groups"
        hint="Groups are optional: they grant the same access to many users at once. Direct assignments work without them."
    >
        {#snippet action()}
            <Button
                variant="primary"
                size="compact"
                disabled={!$adminPermissions.accessRolesCreate}
                onclick={() => (location.hash = '#/config/access-roles/create')}
            >
                New access group
            </Button>
        {/snippet}
    </EmptyState>
{:else}
    <div class="layout">
        <nav class="groups" aria-label="Access groups">
            <div class="groups-head">
                <span>Groups</span>
                <a href="#/config/access-roles/create">New</a>
            </div>
            <ul>
                {#each groups as g (g.id)}
                    <li>
                        <button
                            type="button"
                            class:active={g.id === groupId}
                            onclick={() => (groupId = g.id)}
                        >
                            <span class="group-name">{g.name}</span>
                            <span class="group-meta">
                                {g.memberCount} member{g.memberCount === 1 ? '' : 's'},
                                {g.grantCount} grant{g.grantCount === 1 ? '' : 's'}
                            </span>
                        </button>
                    </li>
                {/each}
            </ul>
        </nav>

        <section class="detail">
            {#if group}
                <div class="detail-head">
                    <div>
                        <h2>{group.name}</h2>
                        {#if group.description}
                            <p class="muted">{group.description}</p>
                        {/if}
                        <div class="badges">
                            {#if group.isDefault}
                                <Badge>New users join it</Badge>
                            {/if}
                            {#if group.ssoManaged}
                                <Badge tone="primary">Membership managed by SSO</Badge>
                            {/if}
                        </div>
                    </div>
                    <a class="settings" href="#/config/access-roles/{group.id}">
                        Settings and members
                    </a>
                </div>

                {#if detailError}
                    <Callout tone="danger" title="Something went wrong">{detailError}</Callout>
                {/if}

                <h3>Grants</h3>
                {#if grants.length}
                    <div class="table-wrap">
                        <table>
                            <thead>
                                <tr>
                                    <th scope="col">Target</th>
                                    <th scope="col">Protocol</th>
                                    <th scope="col">Account</th>
                                    <th scope="col">Excluded members</th>
                                    <th scope="col"><span class="visually-hidden">Actions</span></th>
                                </tr>
                            </thead>
                            <tbody>
                                {#each grants as grant (grant.id)}
                                    <tr>
                                        <td>
                                            <a href="#/config/targets/{grant.targetId}">{grant.targetName}</a>
                                        </td>
                                        <td class="wg-mono">{grant.protocol.toUpperCase()}</td>
                                        <td class="wg-mono">{grant.account ?? '—'}</td>
                                        <td>{grant.excludedCount}</td>
                                        <td class="actions">
                                            <Button
                                                variant="destructive"
                                                size="compact"
                                                disabled={!$adminPermissions.accessRolesAssign}
                                                onclick={() => previewRemove(grant)}
                                            >
                                                Remove
                                            </Button>
                                        </td>
                                    </tr>
                                {/each}
                            </tbody>
                        </table>
                    </div>
                {:else}
                    <p class="muted">This group grants nothing yet.</p>
                {/if}

                <div class="add-grant">
                    <Select
                        label="Target"
                        size="compact"
                        options={targetOptions}
                        bind:value={grantTarget}
                    />
                    {#if needsAccount}
                        <Select
                            label="Account"
                            size="compact"
                            options={accountOptions}
                            bind:value={grantAccount}
                        />
                    {/if}
                    <Button
                        size="compact"
                        disabled={!$adminPermissions.accessRolesAssign ||
                            !grantTarget ||
                            (needsAccount && !grantAccount)}
                        onclick={previewAdd}
                    >
                        Add grant
                    </Button>
                </div>
                {#if needsAccount && grantTarget && !targetAccounts.length}
                    <Callout tone="warning" title="This target has no accounts yet">
                        Add one on <a href="#/config/targets/{grantTarget}">its page</a>, in Accounts.
                    </Callout>
                {/if}

                <h3>Assignments it makes</h3>
                {#if effective.length}
                    <div class="table-wrap">
                        <table>
                            <thead>
                                <tr>
                                    <th scope="col">User</th>
                                    <th scope="col">Target</th>
                                    <th scope="col">Account</th>
                                    <th scope="col">Status</th>
                                    <th scope="col"><span class="visually-hidden">Actions</span></th>
                                </tr>
                            </thead>
                            <tbody>
                                {#each effective as a (`${a.grantId}:${a.userId}`)}
                                    <tr>
                                        <td><a href="#/config/users/{a.userId}">{a.username}</a></td>
                                        <td>{a.targetName}</td>
                                        <td class="wg-mono">{a.account ?? '—'}</td>
                                        <td>
                                            <Badge
                                                tone={a.status === AccessAssignmentStatus.Active
                                                    ? 'success'
                                                    : a.status === AccessAssignmentStatus.Excluded
                                                      ? 'neutral'
                                                      : 'warning'}
                                            >
                                                {a.status === AccessAssignmentStatus.Active
                                                    ? 'Active'
                                                    : a.status === AccessAssignmentStatus.Excluded
                                                      ? 'Excluded'
                                                      : (a.problem ?? a.status)}
                                            </Badge>
                                        </td>
                                        <td class="actions">
                                            {#if a.exclusionId}
                                                <Button
                                                    variant="ghost"
                                                    size="compact"
                                                    disabled={!$adminPermissions.accessRolesAssign}
                                                    onclick={() => restore(a)}
                                                >
                                                    Restore
                                                </Button>
                                            {:else}
                                                <Button
                                                    variant="ghost"
                                                    size="compact"
                                                    disabled={!$adminPermissions.accessRolesAssign}
                                                    onclick={() => exclude(a)}
                                                >
                                                    Exclude
                                                </Button>
                                            {/if}
                                        </td>
                                    </tr>
                                {/each}
                            </tbody>
                        </table>
                    </div>
                {:else}
                    <p class="muted">
                        {group.memberCount
                            ? 'Its members get nothing until it grants a target.'
                            : 'It has no active members.'}
                    </p>
                {/if}
            {/if}
        </section>
    </div>
{/if}

<ConfirmDialog
    open={!!pending}
    title={pending?.kind === 'add' ? 'Add this grant?' : 'Remove this grant?'}
    confirmLabel={pending?.kind === 'add' ? 'Add grant' : 'Remove grant'}
    onconfirm={apply}
    oncancel={() => (pending = null)}
>
    {#if pending}
        <p>{pending.summary}.</p>
        {#if pending.users.length}
            <ul class="impact">
                {#each pending.users as user (user)}
                    <li>{user}</li>
                {/each}
            </ul>
        {/if}
        {#if pending.kind === 'remove'}
            <p>Their live sessions on the target end now.</p>
        {/if}
    {/if}
</ConfirmDialog>

<style>
    .layout {
        display: grid;
        grid-template-columns: minmax(12rem, 16rem) 1fr;
        gap: var(--wg-space-xl);
        margin-top: var(--wg-space-lg);
    }

    .groups ul {
        list-style: none;
        margin: 0;
        padding: 0;
        display: flex;
        flex-direction: column;
        gap: var(--wg-space-xs);
    }

    .groups-head {
        display: flex;
        justify-content: space-between;
        margin-bottom: var(--wg-space-sm);
        color: var(--wg-text-muted);
        font: var(--wg-text-label-md);
    }

    .groups button {
        display: flex;
        flex-direction: column;
        align-items: flex-start;
        width: 100%;
        padding: var(--wg-space-sm) var(--wg-space-md);
        border: var(--wg-border-width) solid transparent;
        border-radius: var(--wg-radius-md);
        background: none;
        color: var(--wg-text);
        text-align: left;
        cursor: pointer;
    }

    .groups button:hover {
        background: var(--wg-surface-container);
    }

    .groups button.active {
        border-color: var(--wg-border-strong);
        background: var(--wg-surface-container);
    }

    .groups button:focus-visible {
        outline: var(--wg-focus-ring);
        outline-offset: var(--wg-focus-ring-offset);
    }

    .group-name {
        font: var(--wg-text-body-md);
        font-weight: 600;
    }

    .group-meta,
    .muted {
        color: var(--wg-text-muted);
        font: var(--wg-text-label-md);
    }

    .detail-head {
        display: flex;
        justify-content: space-between;
        align-items: flex-start;
        gap: var(--wg-space-lg);
    }

    h2 {
        margin: 0;
        font: var(--wg-text-headline-md);
    }

    h3 {
        margin: var(--wg-space-xl) 0 var(--wg-space-sm);
        font: var(--wg-text-label-md);
        color: var(--wg-text-muted);
    }

    .badges {
        display: flex;
        gap: var(--wg-space-xs);
        margin-top: var(--wg-space-xs);
    }

    .settings {
        white-space: nowrap;
        color: var(--wg-primary);
    }

    .add-grant {
        display: flex;
        flex-wrap: wrap;
        align-items: flex-end;
        gap: var(--wg-space-md);
        margin: var(--wg-space-md) 0;
    }

    .add-grant > :global(*) {
        flex: 1 1 12rem;
        max-width: 20rem;
    }

    .add-grant > :global(button) {
        flex: 0 0 auto;
    }

    .table-wrap {
        overflow-x: auto;
        border: var(--wg-border-width) solid var(--wg-border);
        border-radius: var(--wg-radius-panel);
    }

    table {
        width: 100%;
        border-collapse: collapse;
        font: var(--wg-text-body-md);
    }

    th,
    td {
        padding: var(--wg-space-sm) var(--wg-space-md);
        text-align: left;
        vertical-align: middle;
        border-bottom: var(--wg-border-width) solid var(--wg-border);
    }

    th {
        color: var(--wg-text-muted);
        font: var(--wg-text-label-md);
        white-space: nowrap;
    }

    tbody tr:last-child td {
        border-bottom: 0;
    }

    td a {
        color: var(--wg-text);
    }

    .actions {
        text-align: right;
    }

    .impact {
        margin: var(--wg-space-sm) 0;
        padding-left: var(--wg-space-lg);
        max-height: 12rem;
        overflow-y: auto;
    }

    .visually-hidden {
        position: absolute;
        width: 1px;
        height: 1px;
        overflow: hidden;
        clip-path: inset(50%);
        white-space: nowrap;
    }

    @media (max-width: 900px) {
        .layout {
            grid-template-columns: 1fr;
        }
    }
</style>
