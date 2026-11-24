<script lang="ts">
    /**
     * Account access: which remote account each user may sign in to a target as
     * (Access Control). An administrator picks a user, an RDP or SSH target, the
     * account (the user's linked LDAP / AD account, a local account of the
     * target, or its managed account) and how it authenticates.
     *
     * The server decides everything that matters: which accounts a user may use,
     * that a directory account follows the user's LDAP link (and is never a name
     * typed here), which combinations can work, and that an assignment never
     * grants access to a target by itself. This screen only edits assignments,
     * and shows what the server says about them.
     */
    import {
        type AccountBinding,
        type AccountBindingOptions,
        api,
        DirectoryUsernameFormat,
        type Target,
        TargetAccountAuthMethod,
        TargetAccountKind,
        type User,
    } from 'admin/lib/api'
    import { stringifyError } from 'common/errors'
    import Badge from 'ui/Badge.svelte'
    import Button from 'ui/Button.svelte'
    import Callout from 'ui/Callout.svelte'
    import ConfirmDialog from 'ui/ConfirmDialog.svelte'
    import EmptyState from 'ui/EmptyState.svelte'
    import Input from 'ui/Input.svelte'
    import Modal from 'ui/Modal.svelte'
    import Select from 'ui/Select.svelte'
    import SkeletonRow from 'ui/SkeletonRow.svelte'
    import Toggle from 'ui/Toggle.svelte'
    import { toast } from 'ui/toasts.svelte'
    import { adminPermissions } from '../lib/store'

    const KIND_LABELS: Record<TargetAccountKind, string> = {
        [TargetAccountKind.Directory]: "User's linked LDAP / AD account",
        [TargetAccountKind.Local]: 'Local account',
        [TargetAccountKind.Managed]: 'Managed account',
    }

    const METHOD_LABELS: Record<TargetAccountAuthMethod, string> = {
        [TargetAccountAuthMethod.DirectoryPassword]:
            'Directory password, entered once',
        [TargetAccountAuthMethod.TypedPassword]:
            "Account's password, typed when connecting",
        [TargetAccountAuthMethod.TargetCredential]:
            "Target's credential (stored or Vault password, SSH key, certificate)",
    }

    const FORMAT_LABELS: Record<DirectoryUsernameFormat, string> = {
        [DirectoryUsernameFormat.Upn]: 'User principal name',
        [DirectoryUsernameFormat.DownLevel]: 'DOMAIN\\account',
        [DirectoryUsernameFormat.AccountName]: 'Account name only',
        [DirectoryUsernameFormat.AccountAtDomain]: 'account@dns.domain',
    }

    let bindings = $state<AccountBinding[]>([])
    let users = $state<User[]>([])
    let targets = $state<Target[]>([])
    let loading = $state(true)
    let error = $state<string | null>(null)
    let filterUser = $state('')
    let filterTarget = $state('')

    const bindableTargets = $derived(
        targets
            .filter(t => t.options.kind === 'Rdp' || t.options.kind === 'Ssh')
            .sort((a, b) => a.name.localeCompare(b.name)),
    )
    const sortedUsers = $derived(
        [...users].sort((a, b) => a.username.localeCompare(b.username)),
    )
    const shown = $derived(
        bindings.filter(
            b =>
                (!filterUser || b.userId === filterUser) &&
                (!filterTarget || b.targetId === filterTarget),
        ),
    )

    async function load() {
        loading = true
        error = null
        try {
            ;[bindings, users, targets] = await Promise.all([
                api.listAccountBindings({}),
                api.getUsers(),
                api.getTargets(),
            ])
        } catch (e) {
            error = await stringifyError(e)
        } finally {
            loading = false
        }
    }

    function targetLabel(t: Target): string {
        return `${t.name} (${t.options.kind === 'Rdp' ? 'RDP' : 'SSH'})`
    }

    function accountLabel(b: AccountBinding): string {
        switch (b.accountKind) {
            case TargetAccountKind.Local:
                return b.accountName ?? ''
            case TargetAccountKind.Managed:
                return b.managedAccount ?? 'Managed account'
            default:
                return b.usernameFormat
                    ? `LDAP / AD account (${FORMAT_LABELS[b.usernameFormat]})`
                    : 'LDAP / AD account'
        }
    }

    // ---- the add / edit dialog ----
    let editorOpen = $state(false)
    let editing = $state<AccountBinding | null>(null)
    let userSearch = $state('')
    let userId = $state('')
    let targetId = $state('')
    let kind = $state<TargetAccountKind | ''>('')
    let accountName = $state('')
    let usernameFormat = $state<DirectoryUsernameFormat>(
        DirectoryUsernameFormat.Upn,
    )
    let authMethod = $state<TargetAccountAuthMethod | ''>('')
    let enabled = $state(true)
    let expiresAt = $state('')
    let options = $state<AccountBindingOptions | null>(null)
    let optionsError = $state<string | null>(null)
    let saving = $state(false)
    let saveError = $state<string | null>(null)

    const userOptions = $derived([
        { value: '', label: 'Select a user…' },
        ...sortedUsers
            .filter(u =>
                u.username
                    .toLowerCase()
                    .includes(userSearch.trim().toLowerCase()),
            )
            .map(u => ({
                value: u.id,
                label: u.ldapServerId
                    ? `${u.username} (linked to LDAP / AD)`
                    : u.username,
            })),
    ])
    const targetOptions = $derived([
        { value: '', label: 'Select a target…' },
        ...bindableTargets.map(t => ({ value: t.id, label: targetLabel(t) })),
    ])
    const selectedUser = $derived(users.find(u => u.id === userId))
    const kindOption = $derived(options?.kinds.find(k => k.accountKind === kind))
    const kindOptions = $derived([
        { value: '', label: 'Select an account…' },
        ...(options?.kinds ?? []).map(k => ({
            value: k.accountKind,
            label: k.problem
                ? `${KIND_LABELS[k.accountKind]} (${k.problem})`
                : KIND_LABELS[k.accountKind],
            disabled: !!k.problem,
        })),
    ])
    const methodOptions = $derived(
        (kindOption?.authMethods ?? []).map(m => ({
            value: m,
            label: METHOD_LABELS[m],
        })),
    )
    const formatOptions = $derived(
        (options?.directoryAccounts ?? []).map(a => ({
            value: a.format,
            label: `${a.account} (${FORMAT_LABELS[a.format]})`,
        })),
    )
    const directoryAccount = $derived(
        options?.directoryAccounts.find(a => a.format === usernameFormat)
            ?.account,
    )
    const canSave = $derived(
        !!userId &&
            !!targetId &&
            !!kind &&
            !!authMethod &&
            (kind !== TargetAccountKind.Local || !!accountName.trim()) &&
            !saving,
    )

    // What can be assigned depends on the user and the target: ask the server.
    $effect(() => {
        const user = userId
        const target = targetId
        options = null
        optionsError = null
        if (!user || !target) {
            return
        }
        let cancelled = false
        api.getAccountBindingOptions({ userId: user, targetId: target })
            .then(loaded => {
                if (cancelled) {
                    return
                }
                options = loaded
                const firstFormat = loaded.directoryAccounts[0]?.format
                if (
                    !editing &&
                    firstFormat &&
                    !loaded.directoryAccounts.some(
                        a => a.format === usernameFormat,
                    )
                ) {
                    usernameFormat = firstFormat
                }
            })
            .catch(async e => {
                if (!cancelled) {
                    optionsError = await stringifyError(e)
                }
            })
        return () => {
            cancelled = true
        }
    })

    // Only the methods the kind can use there are offered; keep the choice valid.
    $effect(() => {
        const methods = kindOption?.authMethods ?? []
        const firstMethod = methods[0]
        if (firstMethod && !(methods as string[]).includes(authMethod)) {
            authMethod = firstMethod
        }
    })

    function toLocalInput(date?: Date): string {
        if (!date) {
            return ''
        }
        const local = new Date(date.getTime() - date.getTimezoneOffset() * 60000)
        return local.toISOString().slice(0, 16)
    }

    function openAdd() {
        editing = null
        userSearch = ''
        userId = filterUser
        targetId = filterTarget
        kind = ''
        accountName = ''
        usernameFormat = DirectoryUsernameFormat.Upn
        authMethod = ''
        enabled = true
        expiresAt = ''
        saveError = null
        editorOpen = true
    }

    function openEdit(b: AccountBinding) {
        editing = b
        userSearch = ''
        userId = b.userId
        targetId = b.targetId
        kind = b.accountKind
        accountName = b.accountName ?? ''
        usernameFormat = b.usernameFormat ?? DirectoryUsernameFormat.Upn
        authMethod = b.authMethod
        enabled = b.enabled
        expiresAt = toLocalInput(b.expiresAt)
        saveError = null
        editorOpen = true
    }

    async function save() {
        if (!kind || !authMethod) {
            return
        }
        saving = true
        saveError = null
        const expires = expiresAt ? new Date(expiresAt) : undefined
        const name = kind === TargetAccountKind.Local ? accountName.trim() : undefined
        const format =
            kind === TargetAccountKind.Directory ? usernameFormat : undefined
        try {
            if (editing) {
                await api.updateAccountBinding({
                    id: editing.id,
                    updateAccountBindingRequest: {
                        accountName: name,
                        usernameFormat: format,
                        authMethod,
                        enabled,
                        expiresAt: expires,
                    },
                })
                toast.success('Assignment updated')
            } else {
                await api.createAccountBinding({
                    createAccountBindingRequest: {
                        userId,
                        targetId,
                        accountKind: kind,
                        accountName: name,
                        usernameFormat: format,
                        authMethod,
                        enabled,
                        expiresAt: expires,
                    },
                })
                toast.success('Access added')
            }
            editorOpen = false
            await load()
        } catch (e) {
            saveError = await stringifyError(e)
        } finally {
            saving = false
        }
    }

    // ---- revoking ----
    let revoking = $state<AccountBinding | null>(null)

    async function revoke() {
        if (!revoking) {
            return
        }
        try {
            await api.deleteAccountBinding({ id: revoking.id })
            toast.success('Assignment revoked')
            revoking = null
            await load()
        } catch (e) {
            error = await stringifyError(e)
            revoking = null
        }
    }

    load()
</script>

<div class="head">
    <h1>Account access</h1>
    <div class="head-actions">
        <Button
            variant="primary"
            size="compact"
            disabled={!$adminPermissions.accessRolesAssign}
            onclick={openAdd}
        >
            Add access
        </Button>
    </div>
</div>

<p class="intro">
    Which remote account each user may sign in to an RDP or SSH target as. A user
    with assignments on a target can use only those, in the browser and in their
    own client; a target set to require assignments refuses users with none.
    Assignments never grant access to a target: the user's roles still decide that.
</p>

<div class="toolbar">
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
            ...bindableTargets.map(t => ({ value: t.id, label: targetLabel(t) })),
        ]}
        bind:value={filterTarget}
    />
</div>

{#if error}
    <Callout tone="danger" title="Something went wrong">{error}</Callout>
{:else if loading}
    <SkeletonRow rows={5} columns={[2, 2, 1, 2, 2, 2, 1, 1]} />
{:else if !shown.length}
    <EmptyState
        title="No accounts assigned"
        hint="Users sign in to targets as each target is set up until accounts are assigned to them."
    >
        {#snippet action()}
            <Button
                variant="primary"
                size="compact"
                disabled={!$adminPermissions.accessRolesAssign}
                onclick={openAdd}
            >
                Add access
            </Button>
        {/snippet}
    </EmptyState>
{:else}
    <div class="table-wrap">
        <table>
            <thead>
                <tr>
                    <th scope="col">User</th>
                    <th scope="col">Target</th>
                    <th scope="col">Protocol</th>
                    <th scope="col">Remote account</th>
                    <th scope="col">Account type</th>
                    <th scope="col">Authentication</th>
                    <th scope="col">Status</th>
                    <th scope="col"><span class="visually-hidden">Actions</span></th>
                </tr>
            </thead>
            <tbody>
                {#each shown as b (b.id)}
                    <tr>
                        <td>{b.username || '(deleted user)'}</td>
                        <td>{b.targetName || '(deleted target)'}</td>
                        <td class="wg-mono">{b.protocol.toUpperCase()}</td>
                        <td class="wg-mono">{accountLabel(b)}</td>
                        <td>{KIND_LABELS[b.accountKind]}</td>
                        <td>{METHOD_LABELS[b.authMethod]}</td>
                        <td>
                            <div class="status">
                                {#if b.problem}
                                    <Badge tone="warning">{b.problem}</Badge>
                                {:else if b.enabled}
                                    <Badge tone="success">Active</Badge>
                                {:else}
                                    <Badge tone="neutral">Disabled</Badge>
                                {/if}
                                {#if !b.hasTargetAccess}
                                    <Badge tone="warning">No role for target</Badge>
                                {/if}
                                {#if b.expiresAt}
                                    <span class="expires">
                                        until {b.expiresAt.toLocaleString()}
                                    </span>
                                {/if}
                            </div>
                        </td>
                        <td>
                            <div class="row-actions">
                                <Button
                                    variant="ghost"
                                    size="compact"
                                    disabled={!$adminPermissions.accessRolesAssign}
                                    onclick={() => openEdit(b)}
                                >
                                    Edit
                                </Button>
                                <Button
                                    variant="destructive"
                                    size="compact"
                                    disabled={!$adminPermissions.accessRolesAssign}
                                    onclick={() => (revoking = b)}
                                >
                                    Revoke
                                </Button>
                            </div>
                        </td>
                    </tr>
                {/each}
            </tbody>
        </table>
    </div>
{/if}

<Modal
    bind:open={editorOpen}
    title={editing ? 'Edit access' : 'Add access'}
    size="md"
>
    <div class="editor">
        {#if !editing}
            <Input
                label="Find a user"
                type="search"
                placeholder="Username"
                bind:value={userSearch}
            />
        {/if}
        <Select
            label="User"
            options={userOptions}
            bind:value={userId}
            disabled={!!editing}
            hint={selectedUser
                ? selectedUser.ldapServerId
                    ? 'Linked to an LDAP / AD directory.'
                    : 'Not linked to a directory: only local and managed accounts can be assigned.'
                : undefined}
        />
        <Select
            label="Target"
            options={targetOptions}
            bind:value={targetId}
            disabled={!!editing}
        />

        {#if optionsError}
            <Callout tone="danger" title="Could not load the target's accounts">
                {optionsError}
            </Callout>
        {/if}

        {#if options}
            {#if !options.hasTargetAccess}
                <Callout tone="warning" title="The user has no role for this target">
                    The assignment takes effect once one of the user's roles allows
                    the target. It does not grant access by itself.
                </Callout>
            {/if}

            <Select
                label="Remote account"
                options={kindOptions}
                bind:value={kind}
                disabled={!!editing}
            />

            {#if kind === TargetAccountKind.Directory}
                {#if formatOptions.length}
                    <Select
                        label="Name the target knows the account by"
                        options={formatOptions}
                        bind:value={usernameFormat}
                        hint="Read from the directory, from the user's link: it cannot be typed here."
                    />
                    <div class="derived">
                        <span class="derived-label">Signs in as</span>
                        <span class="wg-mono">{directoryAccount ?? '—'}</span>
                    </div>
                {:else}
                    <Callout tone="warning" title="The directory account could not be read">
                        {options.directoryProblem ??
                            'The directory did not return the account.'}
                    </Callout>
                {/if}
            {:else if kind === TargetAccountKind.Local}
                <Input
                    label="Local account"
                    mono
                    placeholder={options.protocol === 'rdp'
                        ? 'SRV01\\support'
                        : 'deploy'}
                    hint="Configured here, not checked on the server: make sure the account exists there."
                    bind:value={accountName}
                />
                {#if options.localAccounts.length}
                    <div class="known">
                        <span class="derived-label">Accounts on this target</span>
                        <div class="known-list">
                            {#each options.localAccounts as known (known)}
                                <button
                                    type="button"
                                    class="known-account wg-mono"
                                    onclick={() => (accountName = known)}
                                >
                                    {known}
                                </button>
                            {/each}
                        </div>
                    </div>
                {/if}
            {:else if kind === TargetAccountKind.Managed}
                <div class="derived">
                    <span class="derived-label">Signs in as</span>
                    <span class="wg-mono">{options.managedAccount ?? '—'}</span>
                </div>
            {/if}

            {#if kind && methodOptions.length}
                <Select
                    label="Authentication"
                    options={methodOptions}
                    bind:value={authMethod}
                />
            {/if}

            <Input
                label="Expires"
                type="datetime-local"
                hint="Optional. The assignment stops working at this time."
                bind:value={expiresAt}
            />
            <Toggle
                label="Enabled"
                checked={enabled}
                onchange={value => (enabled = value)}
            />
        {/if}

        {#if saveError}
            <Callout tone="danger" title="Could not save">{saveError}</Callout>
        {/if}
    </div>

    {#snippet footer()}
        <Button variant="ghost" onclick={() => (editorOpen = false)}>Cancel</Button>
        <Button variant="primary" disabled={!canSave} onclick={save}>
            {saving ? 'Saving…' : editing ? 'Save' : 'Add access'}
        </Button>
    {/snippet}
</Modal>

<ConfirmDialog
    open={!!revoking}
    title="Revoke this account?"
    confirmLabel="Revoke"
    onconfirm={revoke}
    oncancel={() => (revoking = null)}
>
    {#if revoking}
        {revoking.username} will no longer sign in to {revoking.targetName} as
        {accountLabel(revoking)}. Their live sessions on the target end now.
    {/if}
</ConfirmDialog>

<style>
    h1 {
        margin: 0;
        font: var(--wg-text-headline-lg);
    }

    .head {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: var(--wg-space-lg);
        flex-wrap: wrap;
        margin-bottom: var(--wg-space-sm);
    }

    .head-actions {
        display: flex;
        align-items: center;
        gap: var(--wg-space-sm);
    }

    .intro {
        margin: 0 0 var(--wg-space-lg);
        max-width: 72ch;
        font: var(--wg-text-body-md);
        color: var(--wg-text-muted);
    }

    .toolbar {
        display: flex;
        flex-wrap: wrap;
        align-items: center;
        gap: var(--wg-space-md);
        margin-bottom: var(--wg-space-md);
    }

    .toolbar :global(.filter) {
        min-width: 12rem;
        max-width: 20rem;
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

    .expires {
        color: var(--wg-text-muted);
        font: var(--wg-text-label-md);
    }

    .editor {
        display: flex;
        flex-direction: column;
        gap: var(--wg-space-md);
    }

    .derived,
    .known {
        display: flex;
        flex-direction: column;
        gap: var(--wg-space-xs);
    }

    .derived-label {
        color: var(--wg-text-muted);
        font: var(--wg-text-label-md);
    }

    .known-list {
        display: flex;
        flex-wrap: wrap;
        gap: var(--wg-space-xs);
    }

    .known-account {
        padding: var(--wg-space-xs) var(--wg-space-sm);
        border: var(--wg-border-width) solid var(--wg-border);
        border-radius: var(--wg-radius-sm);
        background: var(--wg-surface-container);
        color: var(--wg-text);
        cursor: pointer;
    }

    .known-account:hover {
        background: var(--wg-surface-container-high);
    }

    .known-account:focus-visible {
        outline: var(--wg-focus-ring);
        outline-offset: var(--wg-focus-ring-offset);
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
