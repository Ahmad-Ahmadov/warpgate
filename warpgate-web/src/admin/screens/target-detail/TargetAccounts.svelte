<script lang="ts">
    /**
     * A target's Accounts: the remote accounts Warpgate can sign in to it as.
     *
     * An account grants nobody anything: who may use it is decided in Access
     * Control. Each account says how it authenticates (a stored credential, a
     * password the user types, or the user's own directory password) and, for
     * a stored credential, keeps it here once: encrypted, or as a secret
     * reference. A saved password is never shown again; leaving it blank keeps
     * it.
     *
     * A linked directory account names no one: it stands for each user's own
     * directory identity, from their verified LDAP link, so one account serves
     * every directory user assigned to it.
     *
     * The primary account is the one the target's settings named before
     * accounts existed: jump-host hops and ticket connections without an
     * assignment sign in as it. It grants nobody anything either.
     */
    import {
        api,
        DirectoryUsernameFormat,
        type SSHClientKey,
        type TargetAccount,
        type TargetAccountCredential,
        TargetAccountAuthMethod,
        TargetAccountKind,
    } from 'admin/lib/api'
    import { adminPermissions } from 'admin/lib/store'
    import { stringifyError } from 'common/errors'
    import SecretRefInput, { loadSecretBackends } from 'common/SecretRefInput.svelte'
    import { serverInfo } from 'gateway/lib/store'
    import Badge from 'ui/Badge.svelte'
    import Button from 'ui/Button.svelte'
    import Callout from 'ui/Callout.svelte'
    import Checkbox from 'ui/Checkbox.svelte'
    import ConfirmDialog from 'ui/ConfirmDialog.svelte'
    import Input from 'ui/Input.svelte'
    import Modal from 'ui/Modal.svelte'
    import Select from 'ui/Select.svelte'
    import Toggle from 'ui/Toggle.svelte'
    import { toast } from 'ui/toasts.svelte'

    type Protocol = 'Rdp' | 'Ssh' | 'MySql' | 'Postgres'
    type CredentialKind = 'Password' | 'PublicKey' | 'Certificate' | 'IamRole'

    interface Props {
        targetId: string
        targetName: string
        protocol: Protocol
    }

    let { targetId, targetName, protocol }: Props = $props()

    const KIND_LABELS: Record<TargetAccountKind, string> = {
        [TargetAccountKind.Local]: 'Local account',
        [TargetAccountKind.Domain]: 'Domain account',
        [TargetAccountKind.Directory]: 'Linked directory account',
    }

    const METHOD_LABELS: Record<TargetAccountAuthMethod, string> = {
        [TargetAccountAuthMethod.StoredCredential]: 'Stored credential',
        [TargetAccountAuthMethod.TypedPassword]: 'Password typed when connecting',
        [TargetAccountAuthMethod.DirectoryPassword]: "User's own directory password",
    }

    const FORMAT_LABELS: Record<DirectoryUsernameFormat, string> = {
        [DirectoryUsernameFormat.Upn]: 'User principal name (alice@corp.example.com)',
        [DirectoryUsernameFormat.DownLevel]: 'Down-level logon name (CORP\\alice)',
        [DirectoryUsernameFormat.AccountName]: 'Account name only (alice)',
        [DirectoryUsernameFormat.AccountAtDomain]: 'Account at DNS domain (alice@corp.example.com)',
    }

    let accounts = $state<TargetAccount[]>([])
    let loading = $state(true)
    let error = $state<string | null>(null)
    let clientKeys = $state<SSHClientKey[]>([])
    let backends = $state<{ value: string; label: string }[]>([])

    async function load() {
        loading = true
        error = null
        try {
            accounts = await api.listTargetAccounts({ id: targetId })
        } catch (e) {
            error = await stringifyError(e)
        } finally {
            loading = false
        }
    }

    if (protocol === 'Ssh') {
        api.getSshOwnKeys().then(keys => {
            clientKeys = keys
        })
        loadSecretBackends().then(list => {
            backends = list.map(b => ({ value: b.name, label: b.name }))
        })
    }

    // ---- what each protocol takes ----
    const kindOptions = $derived(
        [
            { value: TargetAccountKind.Local, label: KIND_LABELS[TargetAccountKind.Local] },
            { value: TargetAccountKind.Domain, label: KIND_LABELS[TargetAccountKind.Domain] },
            ...(protocol === 'Rdp' || protocol === 'Ssh'
                ? [
                      {
                          value: TargetAccountKind.Directory,
                          label: 'Linked directory account (each user\'s own)',
                      },
                  ]
                : []),
        ],
    )

    function methodsFor(kind: TargetAccountKind): TargetAccountAuthMethod[] {
        if (protocol === 'Rdp') {
            return kind === TargetAccountKind.Directory
                ? [TargetAccountAuthMethod.DirectoryPassword]
                : [
                      TargetAccountAuthMethod.StoredCredential,
                      TargetAccountAuthMethod.TypedPassword,
                  ]
        }
        return [TargetAccountAuthMethod.StoredCredential]
    }

    function credentialKindsFor(kind: TargetAccountKind): CredentialKind[] {
        const iam: CredentialKind[] = $serverInfo?.runningOnEc2 ? ['IamRole'] : []
        switch (protocol) {
            case 'Rdp':
                return ['Password']
            case 'Ssh':
                return [
                    'PublicKey',
                    ...(kind === TargetAccountKind.Directory ? [] : (['Password'] as CredentialKind[])),
                    ...(backends.length || credentialKind === 'Certificate'
                        ? (['Certificate'] as CredentialKind[])
                        : []),
                    ...iam,
                ]
            default:
                return ['Password', ...iam]
        }
    }

    const CREDENTIAL_LABELS: Record<CredentialKind, string> = {
        Password: 'Password (encrypted, or a secret reference)',
        PublicKey: "Warpgate's own SSH keys",
        Certificate: "Certificate signed by a secret backend's SSH CA",
        IamRole: 'Cloud role (AWS IAM)',
    }

    // ---- the add / edit dialog ----
    let editorOpen = $state(false)
    let editing = $state<TargetAccount | null>(null)
    let kind = $state<TargetAccountKind>(TargetAccountKind.Local)
    let name = $state('')
    let domain = $state('')
    let authMethod = $state<TargetAccountAuthMethod>(TargetAccountAuthMethod.StoredCredential)
    let credentialKind = $state<CredentialKind>('Password')
    let password = $state('')
    let keyId = $state('')
    let certBackend = $state('')
    let certMount = $state('ssh')
    let certRole = $state('')
    let usernameFormat = $state<DirectoryUsernameFormat>(DirectoryUsernameFormat.Upn)
    let enabled = $state(true)
    let isPrimary = $state(false)
    let description = $state('')
    let saving = $state(false)
    let saveError = $state<string | null>(null)

    const methodOptions = $derived(
        methodsFor(kind).map(m => ({ value: m, label: METHOD_LABELS[m] })),
    )
    const credentialOptions = $derived(
        credentialKindsFor(kind).map(c => ({ value: c, label: CREDENTIAL_LABELS[c] })),
    )
    const formatOptions = $derived(
        (protocol === 'Rdp'
            ? [DirectoryUsernameFormat.Upn, DirectoryUsernameFormat.DownLevel]
            : Object.values(DirectoryUsernameFormat)
        ).map(f => ({ value: f, label: FORMAT_LABELS[f] })),
    )
    const keyOptions = $derived([
        { value: '', label: 'Use the default keys' },
        ...clientKeys.map(k => ({
            value: k.id,
            label: `${k.label} (${k.kind})${k.isDefault ? ' — default' : ''}`,
        })),
    ])
    const nameRequired = $derived(
        kind !== TargetAccountKind.Directory &&
            !(protocol === 'Ssh' && kind === TargetAccountKind.Local),
    )
    const canSave = $derived(
        !saving &&
            (!nameRequired || !!name.trim()) &&
            (credentialKind !== 'Certificate' ||
                authMethod !== TargetAccountAuthMethod.StoredCredential ||
                (!!certBackend && !!certRole)),
    )

    // Keep the method and credential choices valid for the kind.
    $effect(() => {
        const methods = methodsFor(kind)
        const first = methods[0]
        if (first && !methods.includes(authMethod)) {
            authMethod = first
        }
        const credentials = credentialKindsFor(kind)
        const firstCredential = credentials[0]
        if (firstCredential && !credentials.includes(credentialKind)) {
            credentialKind = firstCredential
        }
    })

    function openAdd() {
        editing = null
        kind = TargetAccountKind.Local
        name = ''
        domain = ''
        authMethod = methodsFor(TargetAccountKind.Local)[0] ?? TargetAccountAuthMethod.StoredCredential
        credentialKind = protocol === 'Ssh' ? 'PublicKey' : 'Password'
        password = ''
        keyId = ''
        certBackend = ''
        certMount = 'ssh'
        certRole = ''
        usernameFormat = protocol === 'Ssh'
            ? DirectoryUsernameFormat.AccountAtDomain
            : DirectoryUsernameFormat.Upn
        enabled = true
        isPrimary = accounts.length === 0
        description = ''
        saveError = null
        editorOpen = true
    }

    function openEdit(account: TargetAccount) {
        editing = account
        kind = account.kind
        name = account.name
        domain = account.domain ?? ''
        authMethod = account.authMethod
        const credential = account.credential
        credentialKind = (credential?.kind as CredentialKind | undefined) ?? 'Password'
        password = credential?.kind === 'Password' ? credential.password : ''
        keyId = credential?.kind === 'PublicKey' ? (credential.keyId ?? '') : ''
        certBackend = credential?.kind === 'Certificate' ? credential.backend : ''
        certMount =
            credential?.kind === 'Certificate' ? (credential.mount ?? 'ssh') : 'ssh'
        certRole = credential?.kind === 'Certificate' ? credential.role : ''
        usernameFormat = account.usernameFormat ?? DirectoryUsernameFormat.Upn
        enabled = account.enabled
        isPrimary = account.isPrimary
        description = account.description
        saveError = null
        editorOpen = true
    }

    function credential(): TargetAccountCredential | undefined {
        if (authMethod !== TargetAccountAuthMethod.StoredCredential) {
            return undefined
        }
        switch (credentialKind) {
            case 'Password':
                return { kind: 'Password', password }
            case 'PublicKey':
                return { kind: 'PublicKey', keyId: keyId || undefined }
            case 'Certificate':
                return {
                    kind: 'Certificate',
                    backend: certBackend,
                    mount: certMount || 'ssh',
                    role: certRole,
                }
            case 'IamRole':
                return { kind: 'IamRole' }
        }
    }

    async function save() {
        saving = true
        saveError = null
        const request = {
            kind,
            name: kind === TargetAccountKind.Directory ? '' : name.trim(),
            domain: protocol === 'Rdp' && domain.trim() ? domain.trim() : undefined,
            authMethod,
            credential: credential(),
            usernameFormat: kind === TargetAccountKind.Directory ? usernameFormat : undefined,
            enabled,
            isPrimary,
            description,
        }
        try {
            if (editing) {
                await api.updateTargetAccount({
                    id: targetId,
                    accountId: editing.id,
                    targetAccountDataRequest: request,
                })
                toast.success('Account saved')
            } else {
                await api.createTargetAccount({
                    id: targetId,
                    targetAccountDataRequest: request,
                })
                toast.success('Account added')
            }
            editorOpen = false
            await load()
        } catch (e) {
            saveError = await stringifyError(e)
        } finally {
            saving = false
        }
    }

    // ---- deleting ----
    let deleting = $state<TargetAccount | null>(null)

    async function remove() {
        const account = deleting
        deleting = null
        if (!account) {
            return
        }
        try {
            await api.deleteTargetAccount({ id: targetId, accountId: account.id })
            toast.success('Account deleted, and every assignment of it revoked')
            await load()
        } catch (e) {
            error = await stringifyError(e)
        }
    }

    load()
</script>

<p class="intro">
    The accounts Warpgate can sign in to {targetName} as. An account grants nobody
    anything: assign it to users, directly or through an access group, in
    <a href="#/config/access-control?target={targetId}">Access Control</a>.
</p>

{#if error}
    <Callout tone="danger" title="Something went wrong">{error}</Callout>
{/if}

{#if !loading && !accounts.length}
    <Callout tone="warning" title="No accounts">
        Nobody can connect to this target until it has an account and a user is
        assigned to it.
    </Callout>
{:else if accounts.length}
    <div class="table-wrap">
        <table>
            <thead>
                <tr>
                    <th scope="col">Account</th>
                    <th scope="col">Type</th>
                    <th scope="col">Authentication</th>
                    <th scope="col">Credential</th>
                    <th scope="col">Assigned</th>
                    <th scope="col">Status</th>
                    <th scope="col"><span class="visually-hidden">Actions</span></th>
                </tr>
            </thead>
            <tbody>
                {#each accounts as account (account.id)}
                    <tr>
                        <td>
                            <span class="wg-mono">{account.displayName}</span>
                            {#if account.isPrimary}
                                <Badge tone="primary">Primary</Badge>
                            {/if}
                        </td>
                        <td>{KIND_LABELS[account.kind]}</td>
                        <td>{METHOD_LABELS[account.authMethod]}</td>
                        <td class="muted">{account.credentialSource}</td>
                        <td>
                            <a href="#/config/access-control?target={targetId}">
                                {account.assignmentCount} direct, {account.groupGrantCount} group
                            </a>
                        </td>
                        <td>
                            {#if account.problem}
                                <Badge tone="warning">{account.problem}</Badge>
                            {:else if account.enabled}
                                <Badge tone="success">Enabled</Badge>
                            {:else}
                                <Badge>Disabled</Badge>
                            {/if}
                        </td>
                        <td>
                            <div class="row-actions">
                                <Button
                                    icon="edit"
                                    variant="ghost"
                                    size="compact"
                                    disabled={!$adminPermissions.targetsEdit}
                                    onclick={() => openEdit(account)}
                                >
                                    Edit
                                </Button>
                                <Button
                                    icon="trash"
                                    variant="destructive"
                                    size="compact"
                                    disabled={!$adminPermissions.targetsEdit}
                                    onclick={() => (deleting = account)}
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

<div class="add">
    <Button icon="plus" size="compact" disabled={!$adminPermissions.targetsEdit} onclick={openAdd}>
        Add account
    </Button>
</div>

<Modal bind:open={editorOpen} title={editing ? 'Edit account' : 'Add account'} size="md">
    <div class="editor">
        <Select
            label="Type"
            options={kindOptions}
            bind:value={kind}
            disabled={!!editing}
            hint={editing ? "An account's type cannot change: add another account instead." : undefined}
        />

        {#if kind === TargetAccountKind.Directory}
            <Callout title="Each user's own directory account">
                Signs each assigned user in as the directory (LDAP / Active Directory)
                account their Warpgate user is linked to, never one a client names.
                {#if protocol === 'Rdp'}
                    The user types their directory password once; it is checked with
                    the directory, used for that connection and never stored.
                {:else}
                    The server must trust Warpgate's credential for directory users.
                {/if}
            </Callout>
            <Select label="Name sent to the target" options={formatOptions} bind:value={usernameFormat} />
        {:else}
            <Input
                label="Account name"
                mono
                required={nameRequired}
                placeholder={protocol === 'Rdp'
                    ? kind === TargetAccountKind.Domain
                        ? 'CORP\\sqladmin'
                        : 'WIN-SRV-01\\support'
                    : protocol === 'Ssh'
                      ? "deploy (empty: the user's Warpgate username)"
                      : 'app_readonly'}
                hint="As the server knows it. Warpgate does not create or check accounts on the server."
                bind:value={name}
            />
        {/if}

        {#if protocol === 'Rdp'}
            <Input
                label={kind === TargetAccountKind.Directory ? 'Domain NetBIOS name' : 'Computer or domain'}
                mono
                hint={kind === TargetAccountKind.Directory
                    ? 'Optional (CORP): for the down-level name, and to recognise the logon Windows reports.'
                    : 'Optional, for a name written without one: the server (WIN-SRV-01) for a local account, or the domain.'}
                bind:value={domain}
            />
        {/if}

        {#if methodOptions.length > 1}
            <Select label="Authentication" options={methodOptions} bind:value={authMethod} />
        {:else}
            <p class="fixed">
                <span class="fixed-label">Authentication</span>
                {METHOD_LABELS[authMethod]}
            </p>
        {/if}

        {#if authMethod === TargetAccountAuthMethod.StoredCredential}
            {#if credentialOptions.length > 1}
                <Select label="Credential" options={credentialOptions} bind:value={credentialKind} />
            {/if}
            {#if credentialKind === 'Password'}
                <SecretRefInput
                    bind:value={password}
                    inlineLabel="Password"
                    disabled={!$adminPermissions.targetsEdit}
                />
                {#if editing}
                    <p class="hint">Leave blank to keep the stored password.</p>
                {/if}
            {:else if credentialKind === 'PublicKey'}
                <Select label="Key" options={keyOptions} bind:value={keyId} />
            {:else if credentialKind === 'Certificate'}
                <div class="row">
                    <Select
                        label="Secret backend"
                        required
                        placeholder="Choose a backend"
                        options={backends}
                        bind:value={certBackend}
                    />
                    <Input label="SSH engine mount" mono required bind:value={certMount} />
                    <Input label="Signing role" mono required bind:value={certRole} />
                </div>
            {/if}
        {:else if authMethod === TargetAccountAuthMethod.TypedPassword}
            <Callout title="Nothing is stored">
                The user types the account's password when connecting; the server checks
                it. It is used for that connection only.
            </Callout>
        {/if}

        <Checkbox
            label="Primary account"
            hint="Jump-host hops and ticket connections without an assignment sign in as it. It grants nobody anything."
            bind:checked={isPrimary}
        />
        <Toggle label="Enabled" checked={enabled} onchange={value => (enabled = value)} />
        <Input label="Description" bind:value={description} />

        {#if saveError}
            <Callout tone="danger" title="Could not save">{saveError}</Callout>
        {/if}
    </div>

    {#snippet footer()}
        <Button variant="ghost" onclick={() => (editorOpen = false)}>Cancel</Button>
        <Button variant="primary" disabled={!canSave} onclick={save}>
            {saving ? 'Saving…' : editing ? 'Save' : 'Add account'}
        </Button>
    {/snippet}
</Modal>

<ConfirmDialog
    open={!!deleting}
    title="Delete this account?"
    confirmLabel="Delete account"
    onconfirm={remove}
    oncancel={() => (deleting = null)}
>
    {#if deleting}
        <p>
            {deleting.displayName} is removed from {targetName}, with its
            {deleting.assignmentCount} direct assignment{deleting.assignmentCount === 1 ? '' : 's'}
            and {deleting.groupGrantCount} access-group grant{deleting.groupGrantCount === 1 ? '' : 's'}.
            Users connected as it are disconnected. Nothing changes on the server itself.
        </p>
    {/if}
</ConfirmDialog>

<style>
    .intro {
        margin: 0 0 var(--wg-space-md);
        color: var(--wg-text-muted);
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

    .muted {
        color: var(--wg-text-muted);
    }

    .row-actions {
        display: flex;
        justify-content: flex-end;
        gap: var(--wg-space-xs);
    }

    .add {
        margin: var(--wg-space-md) 0;
    }

    .editor {
        display: flex;
        flex-direction: column;
        gap: var(--wg-space-md);
    }

    .row {
        display: flex;
        flex-wrap: wrap;
        gap: var(--wg-space-md);
    }

    .row > :global(*) {
        flex: 1 1 10rem;
        min-width: 0;
    }

    .fixed {
        display: flex;
        flex-direction: column;
        gap: var(--wg-space-xs);
        margin: 0;
    }

    .fixed-label,
    .hint {
        color: var(--wg-text-muted);
        font: var(--wg-text-label-md);
    }

    .hint {
        margin: calc(var(--wg-space-sm) * -1) 0 0;
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
