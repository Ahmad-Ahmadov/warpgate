<script module lang="ts">
    /**
     * A credential field that holds either a value or a reference to a secret in
     * a secret backend (Vault / OpenBao), written `secret://backend/path#field`
     * and resolved by the server at use time. Upstream #2185 and #2734.
     *
     * Same path and module exports as upstream's component, so callers and
     * later upstream changes line up; drawn on this fork's ui/ primitives.
     * Upstream puts the picker behind an icon-only button inside the field.
     * ui/Input renders its affixes aria-hidden, so here the actions are real,
     * labelled buttons under the field instead.
     */
    import {
        api,
        type SecretBackendSummary,
        type SecretReferenceUsageInstance,
    } from 'admin/lib/api'

    let backendsPromise: Promise<SecretBackendSummary[]> | null = null

    export function invalidateSecretBackends(): void {
        backendsPromise = null
    }

    /** Names and types only: readable by any admin, so editors can pick one. */
    export function loadSecretBackends(): Promise<SecretBackendSummary[]> {
        if (!backendsPromise) {
            backendsPromise = api.getSecretBackendsSummary().catch(() => {
                backendsPromise = null
                return []
            })
        }
        return backendsPromise
    }

    const REFERENCE_SCHEME = 'secret://'

    export function isSecretRef(v: string | undefined): boolean {
        return (v ?? '').startsWith(REFERENCE_SCHEME)
    }

    export interface ParsedRef {
        backend: string
        path: string
        key: string
    }

    export function parseSecretRef(v: string): ParsedRef {
        if (!isSecretRef(v)) {
            return { backend: '', path: '', key: '' }
        }
        const rest = v.slice(REFERENCE_SCHEME.length)
        const slash = rest.indexOf('/')
        const backend = slash === -1 ? rest : rest.slice(0, slash)
        const afterBackend = slash === -1 ? '' : rest.slice(slash + 1)
        const hash = afterBackend.indexOf('#')
        const path = hash === -1 ? afterBackend : afterBackend.slice(0, hash)
        const key = hash === -1 ? '' : afterBackend.slice(hash + 1)
        return { backend, path, key }
    }

    export function composeSecretRef(p: ParsedRef): string {
        const base = `${REFERENCE_SCHEME}${p.backend}/${p.path}`
        return p.key ? `${base}#${p.key}` : base
    }

    /**
     * Context key a screen sets to say which object its credential fields
     * belong to, so the picker can leave that object out of "also used by".
     * The value is a function, so a rename is picked up.
     */
    export const SECRET_USAGE_CONTEXT = Symbol('secret-ref-usage')
    export type SecretUsageContext = () => SecretReferenceUsageInstance | undefined
</script>

<script lang="ts">
    import { adminPermissions } from 'admin/lib/store'
    import { stringifyError } from 'common/errors'
    import { dequal } from 'dequal'
    import { getContext } from 'svelte'
    import Button from 'ui/Button.svelte'
    import Callout from 'ui/Callout.svelte'
    import Input from 'ui/Input.svelte'
    import Modal from 'ui/Modal.svelte'
    import Select from 'ui/Select.svelte'
    import StatusMarker from 'ui/StatusMarker.svelte'

    interface Props {
        // Undefined when the parent's auth block has no value yet, e.g. right
        // after switching to password auth; treated as empty.
        value?: string
        disabled?: boolean
        /**
         * When set, the value may also be entered directly, under this label.
         * Without it the field only takes a reference.
         */
        inlineLabel?: string
        hint?: string
        intendedUsage?: SecretReferenceUsageInstance
    }

    let {
        value = $bindable(),
        disabled = false,
        inlineLabel,
        hint,
        intendedUsage,
    }: Props = $props()

    const contextUsage = getContext<SecretUsageContext | undefined>(
        SECRET_USAGE_CONTEXT,
    )
    const ownUsage = $derived(intendedUsage ?? contextUsage?.())

    let backends = $state<SecretBackendSummary[]>([])
    let backendsLoaded = $state(false)
    loadSecretBackends().then(list => {
        backends = list
        backendsLoaded = true
    })

    // svelte-ignore state_referenced_locally
    let refMode = $state(!inlineLabel || isSecretRef(value))
    // A reference set from outside (the loaded target) switches to reference
    // mode; clearing the value on a mode switch does not switch back.
    $effect(() => {
        if (isSecretRef(value)) {
            refMode = true
        }
    })

    const current = $derived(parseSecretRef(value ?? ''))
    const chosen = $derived(
        isSecretRef(value) && Boolean(current.backend && current.path),
    )
    const shown = $derived(
        chosen
            ? `${current.backend}: ${current.path}${current.key ? `#${current.key}` : ''}`
            : 'No secret chosen',
    )

    function switchMode(toRef: boolean) {
        value = ''
        if (toRef) {
            open()
        } else {
            refMode = false
        }
    }

    let modalOpen = $state(false)
    let usage = $state<{ reference: string; usages: SecretReferenceUsageInstance[] }[]>([])

    // The draft only becomes `value` on Save.
    let draftBackend = $state('')
    let draftPath = $state('')
    let draftKey = $state('')

    const draft = $derived(
        composeSecretRef({
            backend: draftBackend,
            path: draftPath,
            key: draftKey,
        }),
    )
    const complete = $derived(Boolean(draftBackend && draftPath && draftKey))
    const sharedWith = $derived(
        (usage.find(u => u.reference === draft)?.usages ?? []).filter(
            u => !dequal(ownUsage, u),
        ),
    )

    // Usage is per backend; a reply for a backend no longer selected is dropped.
    $effect(() => {
        const id = backends.find(b => b.name === draftBackend)?.id
        usage = []
        if (!modalOpen || !id) {
            return
        }
        let wanted = true
        api.getSecretReferenceUsage({ id })
            .then(list => {
                if (wanted) {
                    usage = list
                }
            })
            .catch(() => {})
        return () => {
            wanted = false
        }
    })

    let testing = $state(false)
    let testResult = $state<{ ok: boolean; error?: string } | null>(null)
    let testSequence = 0

    // Retrieval is checked as the draft changes, after a short pause in typing;
    // a reply for an older draft is dropped.
    $effect(() => {
        const reference = draft
        if (!modalOpen || !complete) {
            testResult = null
            testing = false
            return
        }
        const sequence = ++testSequence
        testResult = null
        const timer = setTimeout(async () => {
            testing = true
            let result: { ok: boolean; error?: string }
            try {
                await api.testSecretResolve({
                    testResolveRequest: { reference },
                })
                result = { ok: true }
            } catch (e) {
                result = { ok: false, error: await stringifyError(e) }
            }
            if (sequence === testSequence) {
                testResult = result
                testing = false
            }
        }, 500)
        return () => clearTimeout(timer)
    })

    function open() {
        draftBackend = current.backend
        draftPath = current.path
        draftKey = current.key
        modalOpen = true
        loadSecretBackends().then(list => {
            backends = list
            backendsLoaded = true
            if (!draftBackend && list.length) {
                draftBackend = list[0]?.name ?? ''
            }
        })
    }

    function save() {
        if (!complete) {
            return
        }
        value = draft
        refMode = true
        modalOpen = false
    }

    const backendOptions = $derived(
        backends.map(b => ({
            value: b.name,
            label: `${b.name} (${b.backendType === 'openbao' ? 'OpenBao' : 'Vault'})`,
        })),
    )
</script>

<div class="secret-field">
    {#if refMode}
        <Input
            label={inlineLabel ?? 'Secret'}
            readonly
            mono
            value={shown}
            hint={hint ?? 'Resolved from the secret backend each time it is used.'}
        />
        <div class="secret-actions">
            <Button size="compact" {disabled} onclick={open}>
                {chosen ? 'Change secret…' : 'Choose secret…'}
            </Button>
            {#if inlineLabel}
                <Button
                    variant="ghost"
                    size="compact"
                    {disabled}
                    onclick={() => switchMode(false)}
                >
                    Enter directly
                </Button>
            {/if}
        </div>
    {:else}
        <Input
            label={inlineLabel}
            type="password"
            autocomplete="off"
            {disabled}
            {hint}
            bind:value
        />
        {#if backends.length}
            <div class="secret-actions">
                <Button
                    variant="ghost"
                    size="compact"
                    {disabled}
                    onclick={() => switchMode(true)}
                >
                    Use a secret from a secret backend
                </Button>
            </div>
        {/if}
    {/if}
</div>

{#if modalOpen}
    <Modal
        open={modalOpen}
        title="Secret reference"
        size="md"
        onclose={() => (modalOpen = false)}
    >
        <form
            id="wg-secret-ref-form"
            class="wg-field-stack"
            onsubmit={e => {
                e.preventDefault()
                save()
            }}
        >
            {#if backendsLoaded && !backends.length}
                <Callout tone="warning" title="No secret backends yet">
                    {#if $adminPermissions.configEdit}
                        Add one under
                        <a href="/@warpgate/admin#/config/secret-backends"
                            >Configuration → Secret backends</a
                        >.
                    {:else}
                        An administrator with configuration rights can add
                        one.
                    {/if}
                </Callout>
            {:else}
                <Select
                    label="Backend"
                    required
                    options={backendOptions}
                    bind:value={draftBackend}
                />
            {/if}
            <Input
                label="Path"
                mono
                required
                placeholder="secret/myapp"
                hint="mount/path for KV version 2, without the data/ segment."
                bind:value={draftPath}
            />
            <Input
                label="Field"
                mono
                required
                placeholder="password"
                bind:value={draftKey}
            />

            <div class="check" aria-live="polite">
                {#if testing}
                    <StatusMarker kind="pending" label="Checking…" />
                {:else if testResult?.ok}
                    <StatusMarker kind="online" label="Secret is available" />
                {:else if testResult}
                    <StatusMarker kind="failed" label="Not available" />
                    <span class="check-error">{testResult.error}</span>
                {/if}
            </div>

            {#if sharedWith.length}
                <p class="shared">
                    Also used by
                    {#each sharedWith as other, i (i)}
                        {i ? ', ' : ''}
                        {#if other.kind === 'Target'}
                            <a href="/@warpgate/admin#/config/targets/{other.id}"
                                >target {other.name}</a
                            >
                        {:else}
                            <a href="/@warpgate/admin#/config/ssh"
                                >SSH client key {other.label}</a
                            >
                        {/if}
                    {/each}
                </p>
            {/if}
        </form>

        {#snippet footer()}
            <Button onclick={() => (modalOpen = false)}>Cancel</Button>
            <Button
                variant="primary"
                type="submit"
                form="wg-secret-ref-form"
                disabled={!complete}
            >
                Use this secret
            </Button>
        {/snippet}
    </Modal>
{/if}

<style>
    .secret-field {
        display: flex;
        flex-direction: column;
        gap: var(--wg-space-xs);
    }

    .secret-actions {
        display: flex;
        flex-wrap: wrap;
        gap: var(--wg-space-sm);
    }

    .check {
        display: flex;
        flex-wrap: wrap;
        align-items: center;
        gap: var(--wg-space-sm);
        min-height: 1.5rem;
    }

    .check-error {
        color: var(--wg-error);
        font: var(--wg-text-label-sm);
    }

    .shared {
        margin: 0;
        color: var(--wg-text-muted);
        font: var(--wg-text-body-md);
    }
</style>
