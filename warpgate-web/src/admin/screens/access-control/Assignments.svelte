<script lang="ts">
    /**
     * Access Control → Assignments: every effective assignment, direct and
     * group-derived, with where it comes from and whether it can be used now.
     *
     * A direct assignment is edited, disabled or revoked here. A group-derived
     * one is changed through its group, or taken away from one member alone by
     * excluding them from the group's grant, which leaves their own direct
     * assignments untouched. Bulk actions apply to direct assignments only, and
     * always show what they would change first.
     */
    import {
        type AccessAssignment,
        AccessAssignmentBulkAction,
        AccessAssignmentSource,
        AccessAssignmentStatus,
        api,
        type Target,
        TargetAccountAuthMethod,
        type User,
    } from 'admin/lib/api'
    import { describeRules } from 'common/accessRules'
    import { stringifyError } from 'common/errors'
    import ProtocolLabel from 'common/ProtocolLabel.svelte'
    import Badge from 'ui/Badge.svelte'
    import Button from 'ui/Button.svelte'
    import Callout from 'ui/Callout.svelte'
    import Checkbox from 'ui/Checkbox.svelte'
    import ConfirmDialog from 'ui/ConfirmDialog.svelte'
    import EmptyState from 'ui/EmptyState.svelte'
    import Input from 'ui/Input.svelte'
    import Select from 'ui/Select.svelte'
    import SkeletonRow from 'ui/SkeletonRow.svelte'
    import { toast } from 'ui/toasts.svelte'
    import { adminPermissions } from '../../lib/store'
    import GrantAccessModal from './GrantAccessModal.svelte'

    interface Props {
        initialUser?: string
        initialTarget?: string
    }

    let { initialUser = '', initialTarget = '' }: Props = $props()

    const METHOD_LABELS: Record<TargetAccountAuthMethod, string> = {
        [TargetAccountAuthMethod.StoredCredential]: 'Stored credential',
        [TargetAccountAuthMethod.TypedPassword]: 'Password typed when connecting',
        [TargetAccountAuthMethod.DirectoryPassword]: "User's own directory password",
    }

    const STATUS_LABELS: Record<AccessAssignmentStatus, string> = {
        [AccessAssignmentStatus.Active]: 'Active',
        [AccessAssignmentStatus.Disabled]: 'Disabled',
        [AccessAssignmentStatus.Expired]: 'Expired',
        [AccessAssignmentStatus.Excluded]: 'Excluded',
        [AccessAssignmentStatus.Invalid]: 'Not usable',
    }

    let assignments = $state<AccessAssignment[]>([])
    let users = $state<User[]>([])
    let targets = $state<Target[]>([])
    let loading = $state(true)
    let error = $state<string | null>(null)

    // svelte-ignore state_referenced_locally
    let filterUser = $state(initialUser)
    // svelte-ignore state_referenced_locally
    let filterTarget = $state(initialTarget)
    let filterSource = $state('')
    let filterStatus = $state('')
    let search = $state('')

    const sortedUsers = $derived(
        [...users].sort((a, b) => a.username.localeCompare(b.username)),
    )
    const sortedTargets = $derived(
        [...targets].sort((a, b) => a.name.localeCompare(b.name)),
    )

    const shown = $derived.by(() => {
        const needle = search.trim().toLowerCase()
        return assignments.filter(
            a =>
                (!filterUser || a.userId === filterUser) &&
                (!filterTarget || a.targetId === filterTarget) &&
                (!filterSource || a.source === filterSource) &&
                (!filterStatus || a.status === filterStatus) &&
                (!needle ||
                    [a.username, a.targetName, a.account ?? '', a.groupName ?? '']
                        .join(' ')
                        .toLowerCase()
                        .includes(needle)),
        )
    })

    function rowKey(a: AccessAssignment): string {
        return a.id ?? `${a.grantId}:${a.userId}`
    }

    async function load() {
        loading = true
        error = null
        try {
            ;[assignments, users, targets] = await Promise.all([
                api.listAccessAssignments({}),
                api.getUsers(),
                api.getTargets(),
            ])
            selected = new Set(
                [...selected].filter(id =>
                    assignments.some(a => a.id === id),
                ),
            )
        } catch (e) {
            error = await stringifyError(e)
        } finally {
            loading = false
        }
    }

    // ---- selection and bulk actions (direct assignments only) ----
    let selected = $state(new Set<string>())
    const selectable = $derived(
        shown.filter(a => a.source === AccessAssignmentSource.Direct && a.id),
    )
    const allSelected = $derived(
        selectable.length > 0 &&
            selectable.every(a => a.id && selected.has(a.id)),
    )

    function toggle(id: string | undefined, on: boolean) {
        if (!id) {
            return
        }
        const next = new Set(selected)
        if (on) {
            next.add(id)
        } else {
            next.delete(id)
        }
        selected = next
    }

    function toggleAll(on: boolean) {
        selected = on
            ? new Set(selectable.map(a => a.id).filter((id): id is string => !!id))
            : new Set()
    }

    let bulkAction = $state<AccessAssignmentBulkAction | null>(null)
    let bulkSummary = $state('')
    let bulkUsers = $state<string[]>([])

    async function previewBulk(action: AccessAssignmentBulkAction) {
        try {
            const preview = await api.bulkUpdateAccessAssignments({
                bulkAccessAssignmentRequest: {
                    ids: [...selected],
                    action,
                    dryRun: true,
                },
            })
            bulkAction = action
            bulkSummary = preview.summary
            bulkUsers = [
                ...new Set(
                    preview.affected.map(a => `${a.username} → ${a.targetName}`),
                ),
            ]
        } catch (e) {
            error = await stringifyError(e)
        }
    }

    async function applyBulk() {
        if (!bulkAction) {
            return
        }
        try {
            const result = await api.bulkUpdateAccessAssignments({
                bulkAccessAssignmentRequest: {
                    ids: [...selected],
                    action: bulkAction,
                    dryRun: false,
                },
            })
            toast.success(result.summary)
            selected = new Set()
            bulkAction = null
            await load()
        } catch (e) {
            error = await stringifyError(e)
            bulkAction = null
        }
    }

    // ---- Grant Access / Edit Access: one dialog (GrantAccessModal) ----
    let editorOpen = $state(false)
    let editing = $state<AccessAssignment | null>(null)

    function openAdd() {
        editing = null
        editorOpen = true
    }

    function openEdit(a: AccessAssignment) {
        editing = a
        editorOpen = true
    }

    async function setEnabled(a: AccessAssignment, value: boolean) {
        if (!a.id) {
            return
        }
        try {
            await api.updateAccessAssignment({
                id: a.id,
                updateAccessAssignmentRequest: {
                    accountId: a.accountId,
                    enabled: value,
                    expiresAt: a.expiresAt,
                    note: a.note,
                },
            })
            toast.success(value ? 'Access enabled' : 'Access switched off')
            await load()
        } catch (e) {
            error = await stringifyError(e)
        }
    }

    // ---- revoking, excluding, restoring ----
    let revoking = $state<AccessAssignment | null>(null)
    let excluding = $state<AccessAssignment | null>(null)

    async function revoke() {
        const target = revoking
        revoking = null
        if (!target?.id) {
            return
        }
        try {
            await api.deleteAccessAssignment({ id: target.id })
            toast.success('Access revoked')
            await load()
        } catch (e) {
            error = await stringifyError(e)
        }
    }

    async function exclude() {
        const target = excluding
        excluding = null
        if (!target?.grantId) {
            return
        }
        try {
            await api.excludeFromAccessGroupGrant({
                grantId: target.grantId,
                excludeFromGrantRequest: { userId: target.userId, note: '' },
            })
            toast.success(`${target.username} excluded from the group's grant`)
            await load()
        } catch (e) {
            error = await stringifyError(e)
        }
    }

    async function restore(a: AccessAssignment) {
        if (!a.exclusionId) {
            return
        }
        try {
            await api.deleteAccessGroupExclusion({ id: a.exclusionId })
            toast.success(`${a.username} restored to the group's grant`)
            await load()
        } catch (e) {
            error = await stringifyError(e)
        }
    }

    function statusTone(status: AccessAssignmentStatus) {
        switch (status) {
            case AccessAssignmentStatus.Active:
                return 'success' as const
            case AccessAssignmentStatus.Disabled:
            case AccessAssignmentStatus.Excluded:
                return 'neutral' as const
            default:
                return 'warning' as const
        }
    }

    load()
</script>

<div class="toolbar">
    <Input
        label="Search"
        labelHidden
        type="search"
        placeholder="Search users, targets, accounts, groups"
        class="search"
        bind:value={search}
    />
    <Select
        label="User"
        labelHidden
        size="compact"
        class="filter"
        options={[
            { value: '', label: 'All users' },
            ...sortedUsers.map(u => ({ value: u.id, label: u.username })),
        ]}
        bind:value={filterUser}
    />
    <Select
        label="Target"
        labelHidden
        size="compact"
        class="filter"
        options={[
            { value: '', label: 'All targets' },
            ...sortedTargets.map(t => ({ value: t.id, label: t.name })),
        ]}
        bind:value={filterTarget}
    />
    <Select
        label="Source"
        labelHidden
        size="compact"
        class="filter"
        options={[
            { value: '', label: 'Direct and group' },
            { value: AccessAssignmentSource.Direct, label: 'Direct' },
            { value: AccessAssignmentSource.Group, label: 'Access groups' },
        ]}
        bind:value={filterSource}
    />
    <Select
        label="Status"
        labelHidden
        size="compact"
        class="filter"
        options={[
            { value: '', label: 'Any status' },
            ...Object.values(AccessAssignmentStatus).map(s => ({
                value: s,
                label: STATUS_LABELS[s],
            })),
        ]}
        bind:value={filterStatus}
    />
    <div class="toolbar-end">
        <Button
            icon="plus"
            variant="primary"
            size="compact"
            disabled={!$adminPermissions.accessRolesAssign}
            onclick={openAdd}
        >
            Grant Access
        </Button>
    </div>
</div>

{#if selected.size}
    <section class="bulk" aria-label="Bulk actions">
        <span>{selected.size} direct assignment{selected.size === 1 ? '' : 's'} selected</span>
        <Button size="compact" onclick={() => previewBulk(AccessAssignmentBulkAction.Enable)}>
            Enable
        </Button>
        <Button size="compact" onclick={() => previewBulk(AccessAssignmentBulkAction.Disable)}>
            Disable
        </Button>
        <Button
            icon="trash"
            size="compact"
            variant="destructive"
            onclick={() => previewBulk(AccessAssignmentBulkAction.Revoke)}
        >
            Revoke
        </Button>
        <Button size="compact" variant="ghost" onclick={() => (selected = new Set())}>
            Clear
        </Button>
    </section>
{/if}

{#if error}
    <Callout tone="danger" title="Something went wrong">{error}</Callout>
{/if}

{#if loading}
    <SkeletonRow rows={5} columns={[1, 2, 2, 1, 2, 2, 2, 1, 1]} />
{:else if !shown.length}
    <EmptyState
        icon={assignments.length ? 'search' : 'access'}
        title={assignments.length ? 'Nothing matches' : 'No access granted'}
        hint="Users connect to a target only through access that was granted to them: directly, or through an access group."
    >
        {#snippet action()}
            <Button
                icon="plus"
                variant="primary"
                size="compact"
                disabled={!$adminPermissions.accessRolesAssign}
                onclick={openAdd}
            >
                Grant Access
            </Button>
        {/snippet}
    </EmptyState>
{:else}
    <div class="table-wrap">
        <table>
            <thead>
                <tr>
                    <th scope="col" class="check">
                        <Checkbox
                            label="Select all direct assignments shown"
                            labelHidden
                            checked={allSelected}
                            disabled={!selectable.length || !$adminPermissions.accessRolesAssign}
                            onchange={e => toggleAll((e.target as HTMLInputElement).checked)}
                        />
                    </th>
                    <th scope="col">User</th>
                    <th scope="col">Target</th>
                    <th scope="col">Protocol</th>
                    <th scope="col">Remote account</th>
                    <th scope="col">Authentication</th>
                    <th scope="col">Source</th>
                    <th scope="col">Status</th>
                    <th scope="col">Expires</th>
                    <th scope="col"><span class="visually-hidden">Actions</span></th>
                </tr>
            </thead>
            <tbody>
                {#each shown as a (rowKey(a))}
                    <tr>
                        <td class="check">
                            {#if a.source === AccessAssignmentSource.Direct && a.id}
                                <Checkbox
                                    label="Select {a.username} on {a.targetName}"
                                    labelHidden
                                    checked={selected.has(a.id)}
                                    disabled={!$adminPermissions.accessRolesAssign}
                                    onchange={e =>
                                        toggle(a.id, (e.target as HTMLInputElement).checked)}
                                />
                            {/if}
                        </td>
                        <td>
                            <a href="#/config/users/{a.userId}">
                                {a.username || '(deleted user)'}
                            </a>
                        </td>
                        <td>
                            <a href="#/config/targets/{a.targetId}">
                                {a.targetName || '(deleted target)'}
                            </a>
                        </td>
                        <td class="wg-mono">
                            <ProtocolLabel protocol={a.protocol}>
                                {a.protocol.toUpperCase()}
                            </ProtocolLabel>
                        </td>
                        <td class="wg-mono">{a.account ?? '—'}</td>
                        <td>
                            {#if a.authMethod}
                                <span title={a.credentialSource}>
                                    {METHOD_LABELS[a.authMethod]}
                                </span>
                            {:else}
                                <span class="muted">Target entitlement</span>
                            {/if}
                        </td>
                        <td>
                            {#if a.source === AccessAssignmentSource.Group}
                                <Badge
                                    tone="info"
                                    href="#/config/access-control/groups?group={a.groupId}"
                                >
                                    Group: {a.groupName}
                                </Badge>
                            {:else}
                                <Badge>
                                    Direct{a.origin && a.origin !== 'direct' ? ` (${a.origin})` : ''}
                                </Badge>
                            {/if}
                        </td>
                        <td>
                            <div class="status">
                                <Badge tone={statusTone(a.status)}>
                                    {STATUS_LABELS[a.status]}
                                </Badge>
                                {#if a.rules}
                                    <span title={describeRules(a.rules)}>
                                        <Badge tone="info">Scheduled</Badge>
                                    </span>
                                {/if}
                                {#if a.problem && a.status === AccessAssignmentStatus.Invalid}
                                    <span class="problem">{a.problem}</span>
                                {/if}
                            </div>
                        </td>
                        <td class="muted">
                            {a.expiresAt ? a.expiresAt.toLocaleString() : 'Never'}
                        </td>
                        <td>
                            <div class="row-actions">
                                {#if a.source === AccessAssignmentSource.Direct}
                                    <Button
                                        icon="edit"
                                        variant="ghost"
                                        size="compact"
                                        disabled={!$adminPermissions.accessRolesAssign}
                                        onclick={() => openEdit(a)}
                                    >
                                        Edit Access
                                    </Button>
                                    <Button
                                        variant="ghost"
                                        size="compact"
                                        disabled={!$adminPermissions.accessRolesAssign}
                                        onclick={() => setEnabled(a, !a.enabled)}
                                    >
                                        {a.enabled ? 'Disable' : 'Enable'}
                                    </Button>
                                    <Button
                                        icon="trash"
                                        variant="destructive"
                                        size="compact"
                                        disabled={!$adminPermissions.accessRolesAssign}
                                        onclick={() => (revoking = a)}
                                    >
                                        Revoke
                                    </Button>
                                {:else if a.exclusionId}
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
                                        variant="destructive"
                                        size="compact"
                                        disabled={!$adminPermissions.accessRolesAssign}
                                        onclick={() => (excluding = a)}
                                    >
                                        Exclude
                                    </Button>
                                {/if}
                            </div>
                        </td>
                    </tr>
                {/each}
            </tbody>
        </table>
    </div>
{/if}

<GrantAccessModal
    bind:open={editorOpen}
    {editing}
    {users}
    {targets}
    initialUser={filterUser}
    initialTarget={filterTarget}
    onsaved={load}
/>

<ConfirmDialog
    open={!!revoking}
    title="Revoke this access?"
    confirmLabel="Revoke"
    onconfirm={revoke}
    oncancel={() => (revoking = null)}
>
    {#if revoking}
        {revoking.username} will no longer connect to {revoking.targetName}
        {revoking.account ? `as ${revoking.account}` : ''} through this direct
        assignment. Access through a group, if any, is not affected. Their live
        sessions on the target end now.
    {/if}
</ConfirmDialog>

<ConfirmDialog
    open={!!excluding}
    title="Exclude from the group's grant?"
    confirmLabel="Exclude"
    onconfirm={exclude}
    oncancel={() => (excluding = null)}
>
    {#if excluding}
        {excluding.username} stays in {excluding.groupName}, but no longer gets
        {excluding.targetName}
        {excluding.account ? `as ${excluding.account}` : ''} through it. Their
        own direct assignments, and the group's other members, are not affected.
        Their live sessions on the target end now.
    {/if}
</ConfirmDialog>

<ConfirmDialog
    open={!!bulkAction}
    title="Apply to the selected access?"
    confirmLabel="Apply"
    onconfirm={applyBulk}
    oncancel={() => (bulkAction = null)}
>
    <p>{bulkSummary}</p>
    {#if bulkUsers.length}
        <ul class="impact">
            {#each bulkUsers as line (line)}
                <li>{line}</li>
            {/each}
        </ul>
    {/if}
</ConfirmDialog>

<style>
    .toolbar {
        display: flex;
        flex-wrap: wrap;
        align-items: center;
        gap: var(--wg-space-md);
        margin: var(--wg-space-lg) 0 var(--wg-space-md);
    }

    .toolbar :global(.filter) {
        min-width: 10rem;
        max-width: 16rem;
    }

    .toolbar :global(.search) {
        min-width: 14rem;
        flex: 1 1 14rem;
    }

    .toolbar-end {
        margin-left: auto;
    }

    .bulk {
        display: flex;
        flex-wrap: wrap;
        align-items: center;
        gap: var(--wg-space-sm);
        margin-bottom: var(--wg-space-md);
        padding: var(--wg-space-sm) var(--wg-space-md);
        border: var(--wg-border-width) solid var(--wg-border);
        border-radius: var(--wg-radius-panel);
        background: var(--wg-surface-container);
        font: var(--wg-text-body-md);
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

    .check {
        width: 2.5rem;
    }

    .muted {
        color: var(--wg-text-muted);
    }

    .status,
    .row-actions {
        display: flex;
        flex-wrap: wrap;
        align-items: center;
        gap: var(--wg-space-xs);
    }

    .row-actions {
        justify-content: flex-end;
        flex-wrap: nowrap;
    }

    .problem {
        color: var(--wg-text-muted);
        font: var(--wg-text-label-md);
    }

    .impact {
        margin: var(--wg-space-sm) 0 0;
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
</style>
