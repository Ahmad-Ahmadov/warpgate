<script lang="ts">
    /**
     * Secret backends (upstream #2185): the Vault / OpenBao servers that
     * `secret://` references in target credentials, SSH client keys and SSH
     * certificate signing are resolved from. On this fork's ui/ primitives;
     * same API calls as upstream's screen.
     *
     * Everything here needs ConfigEdit, which the server enforces on every
     * call; the gate below only keeps the screen from offering what the
     * server would refuse.
     */
    import {
        api,
        type CheckHealthResponse,
        type SecretBackend,
        type SecretBackendRequest,
    } from 'admin/lib/api'
    import PermissionGate from 'admin/lib/PermissionGate.svelte'
    import { adminPermissions } from 'admin/lib/store'
    import { stringifyError } from 'common/errors'
    import InfoBox from 'common/InfoBox.svelte'
    import { invalidateSecretBackends } from 'common/SecretRefInput.svelte'
    import { SvelteMap } from 'svelte/reactivity'
    import Badge from 'ui/Badge.svelte'
    import Button from 'ui/Button.svelte'
    import Callout from 'ui/Callout.svelte'
    import ConfirmDialog from 'ui/ConfirmDialog.svelte'
    import EmptyState from 'ui/EmptyState.svelte'
    import Spinner from 'ui/Spinner.svelte'
    import StatusMarker from 'ui/StatusMarker.svelte'
    import SecretBackendModal from './SecretBackendModal.svelte'

    let backends: SecretBackend[] | undefined = $state()
    let error: string | undefined = $state()
    const health = new SvelteMap<string, CheckHealthResponse | 'checking'>()

    let modalOpen = $state(false)
    let editing: SecretBackend | undefined = $state()
    let deleting: SecretBackend | undefined = $state()
    let deleteOpen = $state(false)

    const METHOD_LABELS: Record<string, string> = {
        Token: 'token',
        AppRole: 'AppRole',
        Kubernetes: 'Kubernetes service account',
    }

    async function load() {
        const list = await api.getSecretBackends()
        backends = list.sort((a, b) => a.name.localeCompare(b.name))
        for (const backend of list) {
            checkHealth(backend)
        }
    }

    async function checkHealth(backend: SecretBackend) {
        health.set(backend.id, 'checking')
        try {
            health.set(
                backend.id,
                await api.checkSecretBackendHealth({ id: backend.id }),
            )
        } catch (e) {
            health.set(backend.id, { error: await stringifyError(e) })
        }
    }

    if ($adminPermissions.configEdit) {
        load().catch(async e => {
            error = await stringifyError(e)
        })
    }

    function openCreate() {
        editing = undefined
        modalOpen = true
    }

    function openEdit(backend: SecretBackend) {
        editing = backend
        modalOpen = true
    }

    // Throws on failure, so the dialog can show the reason and stay open.
    async function save(request: SecretBackendRequest) {
        const backend = editing
        if (backend) {
            await api.updateSecretBackend({
                id: backend.id,
                secretBackendRequest: request,
            })
        } else {
            await api.createSecretBackend({ secretBackendRequest: request })
        }
        invalidateSecretBackends()
        await load()
    }

    function askDelete(backend: SecretBackend) {
        deleting = backend
        deleteOpen = true
    }

    // The server refuses to delete a backend that is still referenced and
    // names who references it; that message is shown as is.
    async function remove() {
        const backend = deleting
        deleteOpen = false
        if (!backend) {
            return
        }
        error = undefined
        try {
            await api.deleteSecretBackend({ id: backend.id })
            invalidateSecretBackends()
            await load()
        } catch (e) {
            error = await stringifyError(e)
        }
    }
</script>

<div class="page-summary-bar">
    <h1>Secret backends</h1>
    {#if $adminPermissions.configEdit}
        <Button class="ms-auto" variant="primary" onclick={openCreate}>
            Add a secret backend
        </Button>
    {/if}
</div>

<PermissionGate
    perm="configEdit"
    message="Managing secret backends needs the configuration permission."
>
    <InfoBox>
        A target password or token, an SSH client key, or SSH certificate
        signing can use a secret held in Vault or OpenBao instead of a value
        stored by Warpgate. It is fetched each time it is needed and never
        written to Warpgate's database.
    </InfoBox>

    {#if error}
        <Callout tone="danger" title="Something went wrong">{error}</Callout>
    {/if}

    {#if !backends}
        {#if !error}
            <Spinner label="Loading secret backends" />
        {/if}
    {:else if !backends.length}
        <EmptyState
            title="No secret backends yet"
            hint="Add a Vault or OpenBao server to reference its secrets from targets and SSH keys."
        />
    {:else}
        <ul class="backends">
            {#each backends as backend (backend.id)}
                {@const probe = health.get(backend.id)}
                <li class="backend">
                    <div class="backend-head">
                        <strong class="backend-name">{backend.name}</strong>
                        <Badge mono>
                            {backend.backendType === 'openbao'
                                ? 'OpenBao'
                                : 'Vault'}
                        </Badge>
                        {#if probe === 'checking'}
                            <StatusMarker kind="pending" label="Checking" />
                        {:else if probe?.error}
                            <StatusMarker kind="failed" label="Unreachable" />
                        {:else if probe}
                            <StatusMarker kind="online" label="Healthy" />
                        {/if}
                        <div class="backend-actions">
                            <Button
                                variant="ghost"
                                size="compact"
                                disabled={probe === 'checking'}
                                click={() => checkHealth(backend)}
                            >
                                Check again
                            </Button>
                            <Button
                                variant="ghost"
                                size="compact"
                                onclick={() => openEdit(backend)}
                            >
                                Edit
                            </Button>
                            <Button
                                variant="ghost"
                                size="compact"
                                onclick={() => askDelete(backend)}
                            >
                                Delete
                            </Button>
                        </div>
                    </div>
                    <p class="backend-detail">
                        <code>{backend.address}</code>
                        {#if backend.namespace}
                            · namespace <code>{backend.namespace}</code>
                        {/if}
                        · {METHOD_LABELS[backend.auth.method] ??
                            backend.auth.method} login ·
                        {backend.allowedPaths.length
                            ? `${backend.allowedPaths.length} allowed path prefix${backend.allowedPaths.length === 1 ? '' : 'es'}`
                            : 'any path'}
                    </p>
                    {#if backend.tlsSkipVerify}
                        <p class="backend-warning">
                            TLS certificate verification is off.
                        </p>
                    {/if}
                    {#if probe && probe !== 'checking' && probe.error}
                        <p class="backend-error" role="status">
                            {probe.error}
                        </p>
                    {/if}
                </li>
            {/each}
        </ul>
    {/if}
</PermissionGate>

{#if modalOpen}
    <SecretBackendModal
        bind:isOpen={modalOpen}
        instance={editing}
        {save}
    />
{/if}

{#if deleting}
    <ConfirmDialog
        bind:open={deleteOpen}
        title="Delete {deleting.name}?"
        confirmLabel="Delete secret backend"
        onconfirm={remove}
        oncancel={() => (deleteOpen = false)}
    >
        <p>
            References to this backend would stop resolving, so Warpgate refuses
            while a target or SSH key still uses it.
        </p>
    </ConfirmDialog>
{/if}

<style>
    .backends {
        display: flex;
        flex-direction: column;
        margin: 0;
        padding: 0;
        list-style: none;
    }

    .backend {
        display: flex;
        flex-direction: column;
        gap: var(--wg-space-xs);
        padding: var(--wg-space-md) 0;
        border-bottom: var(--wg-border-width) solid var(--wg-border);
    }

    .backend:last-child {
        border-bottom: 0;
    }

    .backend-head {
        display: flex;
        flex-wrap: wrap;
        align-items: center;
        gap: var(--wg-space-sm);
    }

    .backend-name {
        overflow-wrap: anywhere;
    }

    .backend-actions {
        display: flex;
        flex-wrap: wrap;
        gap: var(--wg-space-xs);
        margin-left: auto;
    }

    .backend-detail,
    .backend-warning,
    .backend-error {
        margin: 0;
        font: var(--wg-text-body-md);
        overflow-wrap: anywhere;
    }

    .backend-detail {
        color: var(--wg-text-muted);
    }

    .backend-warning {
        color: var(--wg-secondary);
    }

    .backend-error {
        color: var(--wg-error);
    }
</style>
