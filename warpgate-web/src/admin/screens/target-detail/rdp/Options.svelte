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
     * Authentication is a stored password (kept by Warpgate, or a Vault
     * reference) or the connecting user's own domain account, which keeps no
     * password at all: each user types theirs when connecting. `setAuthKind`
     * replaces the whole auth object, as the VNC editor does, because the two
     * carry different shapes.
     */
    import {
        RdpDomainUsernameFormat,
        RdpTargetCompression,
        RdpTlsSecurity,
        type TargetOptionsTargetRdpOptions,
    } from 'admin/lib/api'
    import Callout from 'ui/Callout.svelte'
    import Checkbox from 'ui/Checkbox.svelte'
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

    type AuthKind = 'Password' | 'DomainAccount'

    const AUTH_KINDS: { value: AuthKind; label: string }[] = [
        { value: 'Password', label: 'Stored password (managed or Vault)' },
        { value: 'DomainAccount', label: 'Use my domain account' },
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
        } else {
            options.auth = { kind: 'Password', password: '' }
        }
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
        password when they connect, in the browser or in their RDP client. The
        account comes from the directory, not from the user, and the password
        is checked with the directory, used for that one connection and never
        stored. Users who are not linked to a directory cannot connect.
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
            hint="Optional. For the down-level name; defaults to the directory's DNS domain."
            bind:value={options.domain}
        />
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

<div class="check">
    <Checkbox
        label="Interactive logon"
        hint="Shows the target's sign-in screen instead of logging on automatically. The credentials above are still used for network-level authentication."
        bind:checked={options.interactiveLogon}
    />
</div>

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
</style>
