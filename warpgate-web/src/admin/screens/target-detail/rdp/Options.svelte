<script lang="ts">
    /**
     * RDP target options — screen 4d.
     *
     * Every boolean here binds into `options` and is written when the parent
     * form saves, so all of them are Checkboxes rather than Toggles.
     *
     * Two of the selects carry real security weight and now say so:
     *   - a TLS 1.0 security level is a downgrade to ciphers that are broken,
     *     not merely old
     *   - certificate verification is off by default for RDP because these
     *     servers almost always present self-signed certificates; that is a
     *     legitimate default and worth stating rather than leaving as an
     *     unexplained unchecked box
     *
     * Authentication is one of three, each saying which Windows account a
     * user may sign in as:
     *   - a managed account: the stored username and password (kept by
     *     Warpgate, or a Vault reference), which users never see
     *   - the connecting user's own domain account, from the directory their
     *     Warpgate user is linked to
     *   - Windows accounts assigned here to named users, each of whom may only
     *     choose among their own
     * The last two keep no password: each user types the account's when
     * connecting. `setAuthKind` replaces the whole auth object, as the VNC
     * editor does, because they carry different shapes.
     *
     * The server enforces all of it (which account, for whom, and the account
     * Windows actually logs on as); this form only edits the configuration.
     */
    import {
        api,
        RdpDomainUsernameFormat,
        type RdpLocalAccountAssignment,
        RdpTargetCompression,
        RdpTlsSecurity,
        type TargetOptionsTargetRdpOptions,
        type User,
    } from 'admin/lib/api'
    import Button from 'ui/Button.svelte'
    import Callout from 'ui/Callout.svelte'
    import Checkbox from 'ui/Checkbox.svelte'
    import Chip from 'ui/Chip.svelte'
    import { adminPermissions } from 'admin/lib/store'
    import SecretRefInput from 'common/SecretRefInput.svelte'
    import Input from 'ui/Input.svelte'
    import Select from 'ui/Select.svelte'

    interface Props {
        options: TargetOptionsTargetRdpOptions
    }

    let { options = $bindable() }: Props = $props()

    const SECURITY_LEVELS = [
        { value: RdpTlsSecurity.Tls12, label: 'Windows 2016 / 10+ (TLS 1.2)' },
        {
            value: RdpTlsSecurity.Tls12WithLegacyCiphers,
            label: 'Windows 2012 / 8+ (TLS 1.2 with legacy ciphers)',
        },
        {
            value: RdpTlsSecurity.Tls10Unsafe,
            label: 'Windows 2008 R2 or older (TLS 1.0, unsafe ciphers)',
        },
    ]

    // Graphics pipeline is upstream #2621 (RDPEGFX). Upstream labels it
    // experimental; kept as upstream has it rather than judged here.
    const COMPRESSION = [
        { value: RdpTargetCompression.Lossless, label: 'Lossless' },
        { value: RdpTargetCompression.Remotefx, label: 'RemoteFX' },
        {
            value: RdpTargetCompression.GraphicsPipeline,
            label: 'Graphics pipeline (experimental)',
        },
    ]

    const unsafeTls = $derived(
        options.tlsSecurity === RdpTlsSecurity.Tls10Unsafe,
    )

    type AuthKind = 'Password' | 'DomainAccount' | 'LocalAccount'

    const AUTH_KINDS: { value: AuthKind; label: string }[] = [
        {
            value: 'Password',
            label: 'Managed account (stored password or Vault)',
        },
        { value: 'DomainAccount', label: 'My domain account' },
        { value: 'LocalAccount', label: 'Assigned Windows account' },
    ]

    const USERNAME_FORMATS = [
        {
            value: RdpDomainUsernameFormat.Upn,
            label: 'User principal name (alice@corp.example.com)',
        },
        {
            value: RdpDomainUsernameFormat.DownLevel,
            label: 'Down-level logon name (CORP\\alice)',
        },
    ]

    function setAuthKind(kind: AuthKind) {
        if (kind === options.auth.kind) {
            return
        }
        if (kind === 'DomainAccount') {
            options.auth = {
                kind: 'DomainAccount',
                usernameFormat: RdpDomainUsernameFormat.Upn,
            }
        } else if (kind === 'LocalAccount') {
            options.auth = { kind: 'LocalAccount', accounts: [] }
        } else {
            options.auth = { kind: 'Password', password: '' }
        }
    }

    // The users accounts can be assigned to. An assignment naming a user who
    // is gone (or who this administrator cannot list) is kept as it is and
    // shown by its id, rather than silently dropped on save.
    let users = $state<User[] | null>(null)
    let usersError = $state(false)
    $effect(() => {
        if (options.auth.kind !== 'LocalAccount' || users || usersError) {
            return
        }
        api.getUsers()
            .then(list => {
                users = [...list].sort((a, b) =>
                    a.username.localeCompare(b.username),
                )
            })
            .catch(() => {
                usersError = true
            })
    })

    function usernameOf(id: string): string {
        return users?.find(u => u.id === id)?.username ?? id
    }

    function updateAccounts(
        change: (
            accounts: RdpLocalAccountAssignment[],
        ) => RdpLocalAccountAssignment[],
    ) {
        if (options.auth.kind !== 'LocalAccount') {
            return
        }
        options.auth = {
            ...options.auth,
            accounts: change(options.auth.accounts ?? []),
        }
    }

    function addAccount() {
        updateAccounts(accounts => [...accounts, { username: '', users: [] }])
    }

    function removeAccount(index: number) {
        updateAccounts(accounts => accounts.filter((_, i) => i !== index))
    }

    function setAccountName(index: number, username: string) {
        updateAccounts(accounts =>
            accounts.map((a, i) => (i === index ? { ...a, username } : a)),
        )
    }

    function assign(index: number, userId: string) {
        if (!userId) {
            return
        }
        updateAccounts(accounts =>
            accounts.map((a, i) =>
                i === index && !(a.users ?? []).includes(userId)
                    ? { ...a, users: [...(a.users ?? []), userId] }
                    : a,
            ),
        )
    }

    function unassign(index: number, userId: string) {
        updateAccounts(accounts =>
            accounts.map((a, i) =>
                i === index
                    ? {
                          ...a,
                          users: (a.users ?? []).filter(id => id !== userId),
                      }
                    : a,
            ),
        )
    }

    function assignableUsers(
        account: RdpLocalAccountAssignment,
    ): { value: string; label: string }[] {
        const assigned = new Set(account.users ?? [])
        return [
            { value: '', label: 'Assign to a user…' },
            ...(users ?? [])
                .filter(u => !assigned.has(u.id))
                .map(u => ({ value: u.id, label: u.username })),
        ]
    }
</script>

<h5>Connection</h5>

<div class="row">
    <Input label="Target host" mono bind:value={options.host} />
    <Input
        label="Target port"
        type="number"
        mono
        class="port"
        value={String(options.port)}
        oninput={e => {
            const v = Number.parseInt((e.target as HTMLInputElement).value, 10)
            if (!Number.isNaN(v)) {
                options.port = v
            }
        }}
    />
</div>

<h5>Authentication</h5>

<Select
    label="Sign in with"
    options={AUTH_KINDS}
    value={options.auth.kind}
    disabled={!$adminPermissions.targetsEdit}
    onchange={e =>
        setAuthKind((e.target as HTMLSelectElement).value as AuthKind)}
/>

{#if options.auth.kind === 'DomainAccount'}
    <Callout title="Each user signs in as their own domain account">
        Users linked to an LDAP / Active Directory server type their domain
        password once, after any second factor and approval, in the browser or
        in their RDP client, and Windows signs them in with it. The account
        comes from the directory, not from the user, and the password is
        checked with the directory, used for that one connection and never
        stored. Users who are not linked to a directory cannot connect, and a
        session Windows logs on as any other account is ended.
    </Callout>

    <div class="row">
        <Select
            label="Account name sent to the target"
            options={USERNAME_FORMATS}
            bind:value={options.auth.usernameFormat}
        />
        <Input
            label="Domain"
            mono
            hint="Optional. The domain's NetBIOS name (CORP): for the down-level name, and to recognise the account when Windows reports its logon. Defaults to the directory's."
            bind:value={options.domain}
        />
    </div>
{:else if options.auth.kind === 'LocalAccount'}
    <Callout title="Each user signs in as a Windows account assigned to them">
        Assign each account to the users who may sign in as it. When connecting,
        in the browser or in their RDP client, a user picks one of the accounts
        assigned to them (they cannot type another) and enters its password
        once; Windows signs them in with it. The password is used for that one
        connection and never stored, and a session Windows logs on as any
        other account is ended.
    </Callout>

    <Input
        label="Computer name"
        mono
        hint="Recommended. The target's own name (SRV01), for accounts written without one: it tells a logon as the local account from one as a domain account of the same name."
        bind:value={options.domain}
    />

    {#if usersError}
        <Callout tone="warning" title="Users could not be listed">
            Assigned users are shown by their ID.
        </Callout>
    {/if}

    {#each options.auth.accounts ?? [] as account, index (index)}
        <div class="account">
            <div class="row account-name">
                <Input
                    label="Windows account"
                    mono
                    placeholder="operator or SRV01\operator"
                    value={account.username}
                    oninput={e =>
                        setAccountName(
                            index,
                            (e.target as HTMLInputElement).value,
                        )}
                    disabled={!$adminPermissions.targetsEdit}
                />
                <Button
                    variant="ghost"
                    size="compact"
                    disabled={!$adminPermissions.targetsEdit}
                    onclick={() => removeAccount(index)}
                >
                    Remove
                </Button>
            </div>
            <fieldset class="assigned">
                <legend>Assigned to</legend>
                {#each account.users ?? [] as userId (userId)}
                    <Chip
                        mono
                        disabled={!$adminPermissions.targetsEdit}
                        onRemove={() => unassign(index, userId)}
                    >
                        {usernameOf(userId)}
                    </Chip>
                {:else}
                    <span class="nobody">Not assigned to anyone yet</span>
                {/each}
            </fieldset>
            {#if users}
                <Select
                    label="Assign to a user"
                    labelHidden
                    size="compact"
                    options={assignableUsers(account)}
                    value=""
                    disabled={!$adminPermissions.targetsEdit}
                    onchange={e => {
                        const select = e.target as HTMLSelectElement
                        assign(index, select.value)
                        select.value = ''
                    }}
                />
            {/if}
        </div>
    {/each}

    <div class="add-account">
        <Button
            size="compact"
            disabled={!$adminPermissions.targetsEdit}
            onclick={addAccount}
        >
            Add account
        </Button>
    </div>
{:else}
    <div class="row">
        <Input label="Username" mono bind:value={options.username} />
        <Input label="Domain" mono hint="Optional." bind:value={options.domain} />
    </div>
{/if}

<!-- Upstream #2754. -->
<Input
    label="Kerberos KDC URL"
    mono
    placeholder="tcp://dc.example.com:88"
    pattern="(tcp|udp|https?)://.+"
    hint="Optional. Enables Kerberos authentication, which accounts in Protected Users require: a tcp://, udp:// or KDC proxy https:// URL. The target host must then be a DNS name, not an IP address."
    bind:value={options.kdcUrl}
/>

{#if options.auth.kind === 'Password'}
    <SecretRefInput
        bind:value={options.auth.password}
        inlineLabel="Password"
        disabled={!$adminPermissions.targetsEdit}
    />
{/if}

{#if options.auth.kind === 'Password'}
    <div class="check">
        <Checkbox
            label="Interactive logon"
            hint="Shows the target's sign-in screen instead of logging on automatically. The credentials above are still used for network-level authentication."
            bind:checked={options.interactiveLogon}
        />
    </div>
    {#if options.interactiveLogon}
        <Callout tone="warning" title="Any account can be signed in to">
            Users sign in on Windows' own screen, as any account whose password
            they know. Warpgate records which account, but cannot restrict it.
            To hold users to particular accounts, sign in with their domain
            account or assigned Windows accounts instead.
        </Callout>
    {/if}
{/if}

<h5>TLS</h5>

<Select
    label="Security level"
    options={SECURITY_LEVELS}
    bind:value={options.tlsSecurity}
/>

{#if unsafeTls}
    <Callout tone="warning" title="TLS 1.0 with unsafe ciphers">
        These ciphers are broken, not merely old — traffic to this target can be
        decrypted by anyone positioned on the path. Only select this for a host
        that genuinely cannot do better, and treat the segment it sits on as
        untrusted.
    </Callout>
{/if}

<div class="check">
    <Checkbox
        label="Verify certificate"
        hint="Off by default: RDP servers almost always present self-signed certificates, which verification would reject."
        bind:checked={options.verifyTls}
    />
</div>

<h5>Quality</h5>

<Select
    label="Compression between Warpgate and target"
    options={COMPRESSION}
    bind:value={options.compression}
    hint="If Warpgate and the RDP server share a network, lossless significantly improves image quality even for a remote client. GNOME Remote Desktop and KDE KRDP require the graphics pipeline."
/>

<style>
    h5 {
        margin: var(--wg-space-xl) 0 var(--wg-space-md);
        font: var(--wg-text-label-md);
        color: var(--wg-text-muted);
    }

    h5:first-child {
        margin-top: 0;
    }

    .row {
        display: flex;
        flex-wrap: wrap;
        gap: var(--wg-space-lg);
        margin-bottom: var(--wg-space-lg);
    }

    .row > :global(*) {
        flex: 1 1 12rem;
        min-width: 0;
    }

    .row > :global(.port) {
        flex: 0 1 8rem;
    }

    .check {
        margin: var(--wg-space-md) 0 var(--wg-space-lg);
    }

    .account {
        display: flex;
        flex-direction: column;
        gap: var(--wg-space-sm);
        margin: var(--wg-space-md) 0;
        padding: var(--wg-space-md);
        border: var(--wg-border-width) solid var(--wg-border);
        border-radius: var(--wg-radius-md);
    }

    .account-name {
        align-items: flex-end;
        margin-bottom: 0;
    }

    .account-name > :global(button) {
        flex: 0 0 auto;
    }

    .assigned {
        display: flex;
        flex-wrap: wrap;
        align-items: center;
        gap: var(--wg-space-xs);
        min-width: 0;
        margin: 0;
        padding: 0;
        border: 0;
    }

    .assigned legend {
        float: left;
        margin: 0 var(--wg-space-sm) 0 0;
        padding: 0;
        color: var(--wg-text-muted);
        font: var(--wg-text-label-md);
    }

    .nobody {
        color: var(--wg-text-muted);
        font: var(--wg-text-body-md);
    }

    .add-account {
        margin: var(--wg-space-md) 0 var(--wg-space-lg);
    }
</style>
