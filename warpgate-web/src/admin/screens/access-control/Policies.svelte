<script lang="ts">
    /**
     * Access Control → Policies: when connections may start, and what is asked
     * for outside those times, for a user, an access group, a target, or a pair
     * of them. A policy only ever restricts: it never grants access (that is
     * what Grant Access is for), and it never ends a session that is already
     * open.
     *
     * When several policies cover one connection the most restrictive wins, no
     * matter how specific or how new: any Deny denies; otherwise any Require
     * approval requires it (asked with the shortest request expiry and approval
     * validity among them, and by approvers every policy accepts); otherwise
     * Allow. The server decides all of it, in each policy's own timezone.
     */
    import {
        type AccessPolicy,
        AccessRuleAction,
        type AccessRules,
        api,
        type Role,
        type Target,
        type TargetAccount,
        type User,
    } from 'admin/lib/api'
    import {
        cloneRules,
        defaultRules,
        describeRules,
        validateRules,
        WEEKDAY_ORDER,
    } from 'common/accessRules'
    import { stringifyError } from 'common/errors'
    import Badge from 'ui/Badge.svelte'
    import Button from 'ui/Button.svelte'
    import Callout from 'ui/Callout.svelte'
    import Combobox, { type ComboboxOption } from 'ui/Combobox.svelte'
    import ConfirmDialog from 'ui/ConfirmDialog.svelte'
    import EmptyState from 'ui/EmptyState.svelte'
    import Input from 'ui/Input.svelte'
    import Modal from 'ui/Modal.svelte'
    import Select from 'ui/Select.svelte'
    import SkeletonRow from 'ui/SkeletonRow.svelte'
    import Textarea from 'ui/Textarea.svelte'
    import Toggle from 'ui/Toggle.svelte'
    import { toast } from 'ui/toasts.svelte'
    import { adminPermissions } from '../../lib/store'
    import ApprovalHistory from './ApprovalHistory.svelte'
    import ApproverPicker from './ApproverPicker.svelte'
    import DurationPicker from './DurationPicker.svelte'
    import ScheduleEditor from './ScheduleEditor.svelte'

    let policies = $state<AccessPolicy[]>([])
    let users = $state<User[]>([])
    let targets = $state<Target[]>([])
    let roles = $state<Role[]>([])
    let loading = $state(true)
    let error = $state<string | null>(null)
    let search = $state('')

    const shown = $derived.by(() => {
        const needle = search.trim().toLowerCase()
        return policies.filter(
            policy =>
                !needle ||
                [
                    policy.name,
                    policy.description,
                    policy.userName ?? '',
                    policy.roleName ?? '',
                    policy.targetName ?? '',
                    policy.account ?? '',
                ]
                    .join(' ')
                    .toLowerCase()
                    .includes(needle),
        )
    })

    async function load() {
        loading = true
        error = null
        try {
            ;[policies, users, targets, roles] = await Promise.all([
                api.listAccessPolicies(),
                api.getUsers(),
                api.getTargets(),
                api.getRoles(),
            ])
        } catch (e) {
            error = await stringifyError(e)
        } finally {
            loading = false
        }
    }

    // ---- the editor ----
    interface Template {
        id: string
        label: string
        build: () => AccessRules
    }

    const TEMPLATES: Template[] = [
        {
            id: 'business',
            label: 'Business hours; approval outside them',
            build: () => defaultRules(),
        },
        {
            id: 'business-deny',
            label: 'Business hours only; refuse outside them',
            build: () => ({
                ...defaultRules(),
                outside: AccessRuleAction.Deny,
            }),
        },
        {
            id: 'weekend',
            label: 'Approval at weekends only',
            build: () => ({
                ...defaultRules(),
                windows: [
                    {
                        days: WEEKDAY_ORDER.slice(0, 5),
                        start: '00:00',
                        end: '24:00',
                        action: AccessRuleAction.Allow,
                    },
                ],
                outside: AccessRuleAction.RequireApproval,
            }),
        },
        {
            id: 'always',
            label: 'Always require approval',
            build: () => ({
                ...defaultRules(),
                windows: [],
                outside: AccessRuleAction.RequireApproval,
            }),
        },
    ]

    let editorOpen = $state(false)
    let editing = $state<AccessPolicy | null>(null)
    let name = $state('')
    let description = $state('')
    let enabled = $state(true)
    let userId = $state('')
    let roleId = $state('')
    let targetId = $state('')
    let accountId = $state('')
    let rules = $state<AccessRules>(defaultRules())
    let requestExpiry = $state<number | undefined>(900)
    let validFor = $state<number | undefined>(1800)
    let approverUserIds = $state<string[]>([])
    let approverRoleIds = $state<string[]>([])
    let template = $state('business')
    let accounts = $state<TargetAccount[]>([])
    let saving = $state(false)
    let saveError = $state<string | null>(null)

    const userOptions = $derived<ComboboxOption[]>(
        [...users]
            .sort((a, b) => a.username.localeCompare(b.username))
            .map(user => ({
                value: user.id,
                label: user.username,
                description: user.description || undefined,
                tag: user.ldapServerId ? 'Directory' : undefined,
            })),
    )
    const roleOptions = $derived<ComboboxOption[]>(
        [...roles]
            .sort((a, b) => a.name.localeCompare(b.name))
            .map(role => ({ value: role.id, label: role.name })),
    )
    const targetOptions = $derived<ComboboxOption[]>(
        [...targets]
            .sort((a, b) => a.name.localeCompare(b.name))
            .map(target => ({
                value: target.id,
                label: target.name,
                description: target.options.kind,
            })),
    )
    const accountOptions = $derived<ComboboxOption[]>(
        accounts.map(account => ({
            value: account.id,
            label: account.displayName,
        })),
    )

    // The accounts of the chosen target, for narrowing a policy to one of them.
    $effect(() => {
        const target = targetId
        accounts = []
        if (!editorOpen || !target) {
            return
        }
        let cancelled = false
        api.listTargetAccounts({ id: target })
            .then(loaded => {
                if (!cancelled) {
                    accounts = loaded
                }
            })
            .catch(() => {})
        return () => {
            cancelled = true
        }
    })

    function applyApproval(approval: AccessRules['approval']) {
        requestExpiry = approval?.requestExpirySeconds ?? 900
        validFor = approval?.validForSeconds ?? 1800
        approverUserIds = [...(approval?.approverUserIds ?? [])]
        approverRoleIds = [...(approval?.approverRoleIds ?? [])]
    }

    function openAdd() {
        editing = null
        name = ''
        description = ''
        enabled = true
        userId = ''
        roleId = ''
        targetId = ''
        accountId = ''
        template = 'business'
        rules = defaultRules()
        applyApproval(rules.approval)
        saveError = null
        editorOpen = true
    }

    function openEdit(policy: AccessPolicy) {
        editing = policy
        name = policy.name
        description = policy.description
        enabled = policy.enabled
        userId = policy.userId ?? ''
        roleId = policy.roleId ?? ''
        targetId = policy.targetId ?? ''
        accountId = policy.targetAccountId ?? ''
        rules = cloneRules(policy.rules)
        applyApproval(policy.rules.approval)
        saveError = null
        editorOpen = true
    }

    function useTemplate(id: string) {
        template = id
        const chosen = TEMPLATES.find(t => t.id === id)
        if (chosen) {
            rules = chosen.build()
            applyApproval(rules.approval)
        }
    }

    const asksForApproval = $derived(
        rules.outside === AccessRuleAction.RequireApproval ||
            rules.windows.some(w => w.action === AccessRuleAction.RequireApproval),
    )
    const scopeProblem = $derived(
        !userId && !roleId && !targetId
            ? 'Choose who or what it covers: a user, an access group or a target.'
            : undefined,
    )
    const rulesProblem = $derived(validateRules(rules))
    const canSave = $derived(
        !!name.trim() && !scopeProblem && !rulesProblem && !saving,
    )

    async function save() {
        saving = true
        saveError = null
        const body = {
            name: name.trim(),
            description,
            enabled,
            userId: userId || undefined,
            roleId: roleId || undefined,
            targetId: targetId || undefined,
            targetAccountId: targetId ? accountId || undefined : undefined,
            rules: {
                ...cloneRules(rules),
                approval: {
                    requestExpirySeconds: requestExpiry,
                    validForSeconds: validFor,
                    approverUserIds,
                    approverRoleIds,
                },
            },
        }
        try {
            if (editing) {
                await api.updateAccessPolicy({
                    id: editing.id,
                    accessPolicyDataRequest: body,
                })
                toast.success('Policy updated')
            } else {
                await api.createAccessPolicy({ accessPolicyDataRequest: body })
                toast.success('Policy created')
            }
            editorOpen = false
            await load()
        } catch (e) {
            saveError = await stringifyError(e)
        } finally {
            saving = false
        }
    }

    // ---- delete ----
    let deleting = $state<AccessPolicy | null>(null)

    async function remove() {
        const policy = deleting
        deleting = null
        if (!policy) {
            return
        }
        try {
            await api.deleteAccessPolicy({ id: policy.id })
            toast.success('Policy deleted')
            await load()
        } catch (e) {
            error = await stringifyError(e)
        }
    }

    function covers(policy: AccessPolicy): string[] {
        const parts: string[] = []
        if (policy.userId) {
            parts.push(`User ${policy.userName || 'deleted user'}`)
        }
        if (policy.roleId) {
            parts.push(`Group ${policy.roleName || 'deleted group'}`)
        }
        if (policy.targetId) {
            parts.push(`Target ${policy.targetName || 'deleted target'}`)
        }
        if (policy.targetAccountId) {
            parts.push(`Account ${policy.account || 'deleted account'}`)
        }
        return parts
    }

    load()
</script>

<div class="toolbar">
    <Input
        label="Search"
        labelHidden
        type="search"
        placeholder="Search policies, users, groups, targets"
        class="search"
        bind:value={search}
    />
    <div class="toolbar-end">
        <Button
            variant="primary"
            size="compact"
            icon="plus"
            disabled={!$adminPermissions.accessRolesAssign}
            onclick={openAdd}
        >
            New policy
        </Button>
    </div>
</div>

<Callout title="How policies combine">
    A policy restricts when connections may start; it never grants access and
    never ends a session that is already open. When several apply to one
    connection the most restrictive wins: any <strong>Deny</strong> denies,
    otherwise any <strong>Require approval</strong> requires it, otherwise it is
    allowed. A connection that no policy covers is unaffected.
</Callout>

{#if error}
    <Callout tone="danger" title="Something went wrong">{error}</Callout>
{/if}

{#if loading}
    <SkeletonRow rows={4} columns={[2, 2, 3, 1, 1]} />
{:else if !shown.length}
    <EmptyState
        icon="access"
        title={policies.length ? 'Nothing matches' : 'No policies yet'}
        hint="Without a policy, access granted to a user is usable at any time. Add one to limit when connections can start, or to ask for approval outside working hours."
    >
        {#snippet action()}
            {#if !policies.length}
                <Button
                    variant="primary"
                    size="compact"
                    icon="plus"
                    disabled={!$adminPermissions.accessRolesAssign}
                    onclick={openAdd}
                >
                    New policy
                </Button>
            {/if}
        {/snippet}
    </EmptyState>
{:else}
    <div class="table-wrap">
        <table>
            <thead>
                <tr>
                    <th scope="col">Policy</th>
                    <th scope="col">Covers</th>
                    <th scope="col">Rules</th>
                    <th scope="col">Status</th>
                    <th scope="col"><span class="visually-hidden">Actions</span></th>
                </tr>
            </thead>
            <tbody>
                {#each shown as policy (policy.id)}
                    <tr>
                        <td>
                            <strong>{policy.name}</strong>
                            {#if policy.description}
                                <div class="muted">{policy.description}</div>
                            {/if}
                        </td>
                        <td>
                            <ul class="covers">
                                {#each covers(policy) as part (part)}
                                    <li>{part}</li>
                                {/each}
                            </ul>
                        </td>
                        <td class="rules">{describeRules(policy.rules)}</td>
                        <td>
                            <Badge tone={policy.enabled ? 'success' : 'neutral'}>
                                {policy.enabled ? 'On' : 'Off'}
                            </Badge>
                        </td>
                        <td>
                            <div class="row-actions">
                                <Button
                                    variant="ghost"
                                    size="compact"
                                    icon="edit"
                                    disabled={!$adminPermissions.accessRolesAssign}
                                    onclick={() => openEdit(policy)}
                                >
                                    Edit
                                </Button>
                                <Button
                                    variant="destructive"
                                    size="compact"
                                    icon="trash"
                                    disabled={!$adminPermissions.accessRolesAssign}
                                    onclick={() => (deleting = policy)}
                                >
                                    Delete
                                </Button>
                            </div>
                        </td>
                    </tr>
                {/each}
            </tbody>
        </table>
    </div>
{/if}

{#if $adminPermissions.approveSessions}
    <h2>Approval requests</h2>
    <ApprovalHistory />
{/if}

<Modal
    bind:open={editorOpen}
    title={editing ? 'Edit policy' : 'New policy'}
    size="lg"
>
    <form
        id="policy-form"
        class="form"
        onsubmit={event => {
            event.preventDefault()
            if (canSave) {
                save()
            }
        }}
    >
        <section class="section">
            <h3>Policy</h3>
            <div class="pair">
                <Input label="Name" required bind:value={name} placeholder="After-hours production access" />
                <Toggle
                    label="Policy is on"
                    checked={enabled}
                    onchange={value => (enabled = value)}
                    hint="An off policy is kept but ignored."
                />
            </div>
            <Textarea label="Description" rows={2} resize="vertical" bind:value={description} />
        </section>

        <section class="section">
            <h3>Covers</h3>
            <p class="hint">
                The policy applies when every item you choose matches the connection. Choose
                at least one.
            </p>
            <div class="pair">
                <Combobox label="User" options={userOptions} bind:value={userId} placeholder="Anyone" />
                <Combobox label="Access group" options={roleOptions} bind:value={roleId} placeholder="Any group" />
                <Combobox
                    label="Target"
                    options={targetOptions}
                    bind:value={targetId}
                    placeholder="Any target"
                    onchange={() => (accountId = '')}
                />
                {#if targetId}
                    <Combobox
                        label="Account"
                        options={accountOptions}
                        bind:value={accountId}
                        placeholder="Any account on the target"
                    />
                {/if}
            </div>
            {#if scopeProblem}
                <p class="problem" role="alert">{scopeProblem}</p>
            {/if}
        </section>

        <section class="section">
            <h3>When</h3>
            {#if !editing}
                <Select
                    label="Start from"
                    options={TEMPLATES.map(t => ({ value: t.id, label: t.label }))}
                    bind:value={template}
                    onchange={event =>
                        useTemplate((event.target as HTMLSelectElement).value)}
                />
            {/if}
            <ScheduleEditor bind:rules perWindowActions />

            {#if asksForApproval}
                <div class="approval">
                    <h4>Approval</h4>
                    <div class="pair">
                        <DurationPicker
                            label="Request waits"
                            bind:value={requestExpiry}
                            unsetLabel="Server default"
                            hint="How long an approver has to answer."
                        />
                        <DurationPicker
                            label="Approval valid for"
                            bind:value={validFor}
                            unsetLabel="Same as the request"
                            hint="How long an approval can start a connection. Used once."
                        />
                    </div>
                    <ApproverPicker
                        bind:userIds={approverUserIds}
                        bind:roleIds={approverRoleIds}
                        {users}
                        {roles}
                    />
                    <p class="hint">
                        An approval is for one user, one target and one account, and
                        can be used once. It never overrides a revoked or expired
                        grant, or a policy that denies.
                    </p>
                </div>
            {/if}
        </section>

        {#if saveError}
            <Callout tone="danger" title="Could not save">{saveError}</Callout>
        {/if}
    </form>

    {#snippet footer()}
        <Button variant="ghost" onclick={() => (editorOpen = false)}>Cancel</Button>
        <Button
            variant="primary"
            type="submit"
            form="policy-form"
            disabled={!canSave}
        >
            {saving ? 'Saving…' : editing ? 'Save changes' : 'Create policy'}
        </Button>
    {/snippet}
</Modal>

<ConfirmDialog
    open={!!deleting}
    title="Delete this policy?"
    confirmLabel="Delete"
    onconfirm={remove}
    oncancel={() => (deleting = null)}
>
    {#if deleting}
        Connections it restricted ({describeRules(deleting.rules)}) will no longer
        be limited by it. Sessions that are open are not affected.
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

    .toolbar :global(.search) {
        min-width: 14rem;
        flex: 1 1 14rem;
    }

    .toolbar-end {
        margin-left: auto;
    }

    h2 {
        margin: var(--wg-space-xl) 0 var(--wg-space-sm);
        font: var(--wg-text-headline-md);
    }

    .table-wrap {
        margin-top: var(--wg-space-md);
        overflow-x: auto;
    }

    table {
        width: 100%;
        border-collapse: collapse;
        font: var(--wg-text-body-md);
    }

    th {
        padding: var(--wg-space-xs) var(--wg-space-md);
        text-align: left;
        color: var(--wg-text-muted);
        font: var(--wg-text-label-md);
        border-bottom: var(--wg-border-width) solid var(--wg-border);
        white-space: nowrap;
    }

    td {
        padding: var(--wg-space-sm) var(--wg-space-md);
        border-bottom: var(--wg-border-width) solid var(--wg-border);
        vertical-align: top;
    }

    tbody tr {
        transition: background var(--wg-duration-fast) var(--wg-easing);
    }

    tbody tr:hover {
        background: var(--wg-row-hover);
    }

    .rules {
        max-width: 28rem;
        color: var(--wg-text-muted);
    }

    .muted {
        color: var(--wg-text-muted);
        font: var(--wg-text-label-md);
    }

    .covers {
        margin: 0;
        padding: 0;
        list-style: none;
    }

    .row-actions {
        display: flex;
        gap: var(--wg-space-xs);
        justify-content: flex-end;
    }

    .visually-hidden {
        position: absolute;
        width: 1px;
        height: 1px;
        overflow: hidden;
        clip-path: inset(50%);
        white-space: nowrap;
    }

    .form {
        display: flex;
        flex-direction: column;
        gap: var(--wg-space-lg);
    }

    .section {
        display: flex;
        flex-direction: column;
        gap: var(--wg-space-md);
        padding-bottom: var(--wg-space-lg);
        border-bottom: var(--wg-border-width) solid var(--wg-border);
    }

    .section:last-of-type {
        border-bottom: 0;
        padding-bottom: 0;
    }

    h3,
    h4 {
        margin: 0;
        font: var(--wg-text-label-md);
    }

    .pair {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: var(--wg-space-md);
    }

    @media (max-width: 640px) {
        .pair {
            grid-template-columns: 1fr;
        }
    }

    .approval {
        display: flex;
        flex-direction: column;
        gap: var(--wg-space-md);
        padding: var(--wg-space-md);
        background: var(--wg-secondary-tint);
        border-radius: var(--wg-radius-panel);
    }

    .hint {
        margin: 0;
        font: var(--wg-text-label-md);
        color: var(--wg-text-subtle);
    }

    .problem {
        margin: 0;
        font: var(--wg-text-label-md);
        color: var(--wg-error);
    }
</style>
