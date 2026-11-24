<script lang="ts">
    /**
     * SSH target options — screen 4b.
     *
     * Behaviour preserved from config/targets/ssh/Options.svelte, including
     * the parts that look odd out of context:
     *
     *   - `hostKeyCheckInvalidated` hides the key checker the moment host or
     *     port changes, because the checker's result refers to the *saved*
     *     host. An effect on `options` clears it after a save reassigns the
     *     prop.
     *   - the jump-host and client-key selects keep local state synced through
     *     `untrack`, in both directions. This is not redundancy: the select
     *     writes into `options`, and `options` is replaced wholesale when the
     *     form saves, so each needs to follow the other without looping.
     *   - jump hosts exclude this target, so it cannot be its own jump host.
     *
     * Which accounts the target has, and how each signs in (Warpgate's keys,
     * a password or Vault reference, a Vault-signed certificate, a cloud role),
     * are the target's Accounts; who may use which is Access Control. When this
     * target is another's jump host, the hop signs in as its primary account.
     *
     * `allowInsecureAlgos` is a **Checkbox**, not a Toggle. It binds into
     * `options` and is written when the form saves — a deferred write, so
     * "this will be true when you save" is the honest announcement. The
     * switches on the parent page write through on change and stay switches.
     */
    import {
        api,
        type Target,
        type TargetOptionsTargetSSHOptions,
    } from 'admin/lib/api'
    import { adminPermissions } from 'admin/lib/store'
    import { TargetKind } from 'gateway/lib/api'
    import { untrack } from 'svelte'
    import Callout from 'ui/Callout.svelte'
    import Checkbox from 'ui/Checkbox.svelte'
    import Input from 'ui/Input.svelte'
    import Select from 'ui/Select.svelte'
    import TargetSshHostKeyChecker from './KeyChecker.svelte'

    interface Props {
        id: string
        options: TargetOptionsTargetSSHOptions
    }

    let { id, options }: Props = $props()

    let hostKeyCheckInvalidated = $state(false)
    let sshTargets = $state<Target[]>([])

    $effect(() => {
        // Runs when options are reassigned after saving
        options
        hostKeyCheckInvalidated = false
    })

    api.getTargets().then(targets => {
        sshTargets = targets.filter(
            t => t.options.kind === TargetKind.Ssh && t.id !== id,
        )
    })

    // svelte-ignore state_referenced_locally
    let jumpHostSelectValue = $state(options.jumpHost ?? '')

    $effect(() => {
        const val = jumpHostSelectValue
        untrack(() => {
            options.jumpHost = val || undefined
        })
    })

    $effect(() => {
        const jumpHost = options.jumpHost
        untrack(() => {
            jumpHostSelectValue = jumpHost ?? ''
        })
    })

    const jumpHostOptions = $derived([
        { value: '', label: 'Direct connection' },
        ...sshTargets.map(t => ({ value: t.id, label: t.name })),
    ])
</script>

<h5>Connection</h5>

<div class="row">
    {#if sshTargets.length}
        <Select
            label="Jump host"
            options={jumpHostOptions}
            bind:value={jumpHostSelectValue}
        />
    {/if}
    <Input
        label="Target host"
        mono
        bind:value={options.host}
        oninput={() => (hostKeyCheckInvalidated = true)}
    />
    <Input
        label="Target port"
        type="number"
        mono
        value={String(options.port)}
        class="port"
        oninput={e => {
            const v = Number.parseInt((e.target as HTMLInputElement).value, 10)
            if (!Number.isNaN(v)) {
                options.port = v
            }
            hostKeyCheckInvalidated = true
        }}
    />
</div>

{#if $adminPermissions.targetsEdit}
    <div class="key-check">
        {#if hostKeyCheckInvalidated}
            <Callout
                title="Save changes to see the host key validation status"
            />
        {:else}
            <TargetSshHostKeyChecker {id} {options} />
        {/if}
    </div>
{/if}

<div class="insecure">
    <Checkbox
        label="Allow insecure SSH algorithms"
        hint="Needed by some older network devices. Saved with the rest of the form."
        bind:checked={options.allowInsecureAlgos}
    />
</div>


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
        align-items: flex-end;
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

    .key-check {
        margin-bottom: var(--wg-space-lg);
    }

    .insecure {
        margin-top: var(--wg-space-lg);
    }
</style>
