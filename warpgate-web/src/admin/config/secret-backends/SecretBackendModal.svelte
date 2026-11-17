<script lang="ts">
    /**
     * Create or edit a secret backend (upstream #2185), on this fork's ui/
     * primitives.
     *
     * Secrets are write-only. The API never returns a stored token or AppRole
     * secret ID, and on update a blank one keeps what is stored, but only
     * while the authentication method stays the same (the server enforces
     * both). So the secret field is required when creating or when switching
     * method, and optional otherwise.
     *
     * Unlike upstream, the dialog stays open when saving fails and shows the
     * server's reason (a taken name, a missing secret), so nothing typed is
     * lost.
     */
    import type {
        BackendType,
        SecretBackend,
        SecretBackendAuth,
        SecretBackendRequest,
    } from 'admin/lib/api'
    import { stringifyError } from 'common/errors'
    import InfoBox from 'common/InfoBox.svelte'
    import { untrack } from 'svelte'
    import Button from 'ui/Button.svelte'
    import Callout from 'ui/Callout.svelte'
    import Checkbox from 'ui/Checkbox.svelte'
    import Input from 'ui/Input.svelte'
    import 'ui/layout.css'
    import Modal from 'ui/Modal.svelte'
    import Select from 'ui/Select.svelte'
    import Textarea from 'ui/Textarea.svelte'

    interface Props {
        isOpen: boolean
        instance?: SecretBackend
        save: (request: SecretBackendRequest) => Promise<void>
    }

    let { isOpen = $bindable(true), instance, save }: Props = $props()

    // Seeded once: mounted behind {#if}, so a fresh component exists per open.
    const seed = untrack(() => instance)
    const seedAuth = seed?.auth

    let name = $state(seed?.name ?? '')
    let backendType: BackendType = $state(seed?.backendType ?? 'vault')
    let address = $state(seed?.address ?? '')
    let namespace = $state(seed?.namespace ?? '')
    let method: SecretBackendAuth['method'] = $state(seedAuth?.method ?? 'Token')
    let mount = $state(
        (seedAuth?.method === 'Token' ? undefined : seedAuth?.mount) ?? '',
    )
    let token = $state('')
    let roleId = $state(seedAuth?.method === 'AppRole' ? seedAuth.roleId : '')
    let secretId = $state('')
    let kubernetesRole = $state(
        seedAuth?.method === 'Kubernetes' ? seedAuth.role : '',
    )
    let tlsSkipVerify = $state(seed?.tlsSkipVerify ?? false)
    let allowedPaths = $state(seed?.allowedPaths.join('\n') ?? '')

    // A stored secret exists only for the method the backend was saved with.
    const secretStored = $derived(seedAuth?.method === method)
    const secretHint = $derived(
        secretStored ? 'Leave blank to keep the stored value.' : undefined,
    )

    let saving = $state(false)
    let error: string | undefined = $state()

    const TYPES = [
        { value: 'vault' as BackendType, label: 'HashiCorp Vault' },
        { value: 'openbao' as BackendType, label: 'OpenBao' },
    ]
    const METHODS = [
        { value: 'Token' as const, label: 'Token' },
        { value: 'AppRole' as const, label: 'AppRole' },
        { value: 'Kubernetes' as const, label: 'Kubernetes service account' },
    ]

    function auth(): SecretBackendAuth {
        if (method === 'AppRole') {
            return { method, roleId, secretId, mount: mount || undefined }
        }
        if (method === 'Kubernetes') {
            return { method, role: kubernetesRole, mount: mount || undefined }
        }
        return { method: 'Token', token }
    }

    // Native validation gates submit, so this only runs with a valid form.
    async function commit() {
        error = undefined
        saving = true
        try {
            await save({
                name,
                backendType,
                address,
                namespace: namespace || undefined,
                auth: auth(),
                tlsSkipVerify,
                allowedPaths: allowedPaths
                    .split('\n')
                    .map(p => p.trim())
                    .filter(p => p),
            })
            isOpen = false
        } catch (e) {
            error = await stringifyError(e)
        } finally {
            saving = false
        }
    }

    function cancel() {
        isOpen = false
    }
</script>

<Modal
    bind:open={isOpen}
    title={seed ? `Edit ${seed.name}` : 'Add a secret backend'}
    size="md"
    onclose={cancel}
>
    <form
        id="wg-secret-backend-form"
        class="wg-field-stack"
        onsubmit={e => {
            e.preventDefault()
            commit()
        }}
    >
        {#if error}
            <Callout tone="danger" title="Could not save">{error}</Callout>
        {/if}

        <Input
            label="Name"
            required
            autofocus
            mono
            pattern={'[A-Za-z0-9._\\-]+'}
            hint="Used in references, as in secret://name/path#field. Letters, digits, dots, dashes and underscores. A backend still referenced cannot be renamed."
            bind:value={name}
        />
        <Select label="Type" options={TYPES} bind:value={backendType} />
        <Input
            label="Address"
            type="url"
            required
            mono
            placeholder="https://vault.example.com:8200"
            bind:value={address}
        />
        <Checkbox
            label="Skip TLS certificate verification"
            hint="Only for testing: anyone on the network path could then impersonate the backend and receive Warpgate's login."
            bind:checked={tlsSkipVerify}
        />
        <Input
            label="Namespace"
            mono
            hint="Optional. For Vault Enterprise and OpenBao namespaces."
            bind:value={namespace}
        />

        <Select label="Authentication" options={METHODS} bind:value={method} />
        {#if method === 'Token'}
            <Input
                label="Token"
                type="password"
                autocomplete="off"
                required={!secretStored}
                hint={secretHint}
                bind:value={token}
            />
        {:else if method === 'AppRole'}
            <Input label="Role ID" mono required bind:value={roleId} />
            <Input
                label="Secret ID"
                type="password"
                autocomplete="off"
                required={!secretStored}
                hint={secretHint}
                bind:value={secretId}
            />
            <Input
                label="Auth mount"
                mono
                placeholder="approle"
                hint="Optional. Defaults to approle."
                bind:value={mount}
            />
        {:else}
            <Input label="Role" mono required bind:value={kubernetesRole} />
            <Input
                label="Auth mount"
                mono
                placeholder="kubernetes"
                hint="Optional. Defaults to kubernetes. Warpgate logs in with its pod's service account token."
                bind:value={mount}
            />
        {/if}

        <Textarea
            label="Allowed path prefixes"
            rows={4}
            mono
            hint="One per line, matched on whole path segments. Empty allows any path."
            bind:value={allowedPaths}
        />
        <InfoBox>
            Use <code>mount/path</code> for KV secrets and
            <code>mount/sign/role</code> for SSH certificate signing.
        </InfoBox>
    </form>

    {#snippet footer()}
        <Button onclick={cancel}>Cancel</Button>
        <Button
            variant="primary"
            type="submit"
            form="wg-secret-backend-form"
            disabled={saving}
        >
            {saving ? 'Saving…' : 'Save'}
        </Button>
    {/snippet}
</Modal>
