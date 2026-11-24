<script lang="ts">
    /**
     * Access Control → Migration review: what the upgrade to unified access
     * control found in the earlier permissions (roles granting targets, account
     * bindings, RDP accounts assigned in a target's settings), and what it did.
     *
     * Everything it could map without widening anyone's access was migrated.
     * The rest waits here, "pending migration review", and grants nothing until
     * an administrator confirms it with an account, or rejects it. Choosing an
     * account is the administrator's call: the migration never picks one that
     * could give more than before.
     */
    import {
        AccessMigrationCategory,
        AccessMigrationStatus,
        api,
        type MigrationReviewView,
    } from 'admin/lib/api'
    import { stringifyError } from 'common/errors'
    import Badge from 'ui/Badge.svelte'
    import Button from 'ui/Button.svelte'
    import Callout from 'ui/Callout.svelte'
    import EmptyState from 'ui/EmptyState.svelte'
    import Input from 'ui/Input.svelte'
    import Select from 'ui/Select.svelte'
    import SkeletonRow from 'ui/SkeletonRow.svelte'
    import { toast } from 'ui/toasts.svelte'
    import { adminPermissions } from '../../lib/store'

    interface Props {
        onchange?: () => void
    }

    let { onchange }: Props = $props()

    const CATEGORY_LABELS: Record<AccessMigrationCategory, string> = {
        [AccessMigrationCategory.Migrated]: 'Migrated automatically',
        [AccessMigrationCategory.AlreadyMatching]: 'Already user, target and account',
        [AccessMigrationCategory.Duplicate]: 'Duplicate, kept once',
        [AccessMigrationCategory.NoAccount]: 'No identifiable remote account',
        [AccessMigrationCategory.Overlapping]: 'Overlapping rules',
        [AccessMigrationCategory.Ineffective]: 'Granted nothing before',
        [AccessMigrationCategory.Ambiguous]: 'Ambiguous: choose the account',
    }

    let items = $state<MigrationReviewView[]>([])
    let loading = $state(true)
    let error = $state<string | null>(null)
    let showReport = $state(false)
    let choices = $state<Record<string, string>>({})
    let notes = $state<Record<string, string>>({})

    const pendingItems = $derived(
        items.filter(i => i.status === AccessMigrationStatus.Pending),
    )
    const decided = $derived(
        items.filter(i => i.status !== AccessMigrationStatus.Pending),
    )
    const byCategory = $derived.by(() => {
        const counts = new Map<AccessMigrationCategory, number>()
        for (const item of items) {
            counts.set(item.category, (counts.get(item.category) ?? 0) + 1)
        }
        return [...counts.entries()]
    })

    async function load() {
        loading = true
        error = null
        try {
            items = await api.listAccessMigrationReviews({})
            for (const item of items) {
                const only = item.candidates[0]
                if (item.candidates.length === 1 && only && !choices[item.id]) {
                    choices[item.id] = only.id
                }
            }
        } catch (e) {
            error = await stringifyError(e)
        } finally {
            loading = false
        }
    }

    async function confirm(item: MigrationReviewView) {
        try {
            await api.confirmAccessMigrationReview({
                id: item.id,
                confirmMigrationReviewRequest: {
                    accountId: choices[item.id] || undefined,
                    note: notes[item.id] ?? '',
                },
            })
            toast.success('Confirmed: access granted')
            await load()
            onchange?.()
        } catch (e) {
            error = await stringifyError(e)
        }
    }

    async function reject(item: MigrationReviewView) {
        try {
            await api.rejectAccessMigrationReview({
                id: item.id,
                rejectMigrationReviewRequest: { note: notes[item.id] ?? '' },
            })
            toast.success('Rejected: it grants nothing')
            await load()
            onchange?.()
        } catch (e) {
            error = await stringifyError(e)
        }
    }

    function subject(item: MigrationReviewView): string {
        if (item.username) {
            return `User ${item.username}`
        }
        if (item.groupName) {
            return `Group ${item.groupName}`
        }
        return ''
    }

    load()
</script>

{#if error}
    <Callout tone="danger" title="Something went wrong">{error}</Callout>
{/if}

{#if loading}
    <SkeletonRow rows={4} columns={[3, 2, 2]} />
{:else if !items.length}
    <EmptyState
        icon="check"
        title="Nothing to review"
        hint="The upgrade found no earlier permissions to migrate."
    />
{:else}
    <div class="summary">
        {#each byCategory as [category, count] (category)}
            <Badge>{CATEGORY_LABELS[category]}: {count}</Badge>
        {/each}
    </div>

    <h3>Pending migration review ({pendingItems.length})</h3>
    {#if !pendingItems.length}
        <p class="muted">Every item has been decided.</p>
    {/if}
    <ul class="items">
        {#each pendingItems as item (item.id)}
            <li class="item">
                <div class="item-head">
                    <Badge tone="warning">{CATEGORY_LABELS[item.category]}</Badge>
                    {#if item.ssoManaged}
                        <Badge tone="primary">Membership managed by SSO</Badge>
                    {/if}
                    <span class="muted">{subject(item)}</span>
                    {#if item.targetId}
                        <a href="#/config/targets/{item.targetId}">{item.targetName}</a>
                    {/if}
                </div>
                <p class="permission">{item.legacyPermission}</p>
                <p class="muted">{item.reason}</p>
                <div class="decide">
                    {#if item.candidates.length}
                        <Select
                            label="Account to grant"
                            size="compact"
                            options={[
                                { value: '', label: 'Choose an account…' },
                                ...item.candidates.map(c => ({
                                    value: c.id,
                                    label: c.account,
                                })),
                            ]}
                            bind:value={choices[item.id]}
                        />
                    {:else if item.targetId}
                        <span class="muted">
                            Add an account to
                            <a href="#/config/targets/{item.targetId}">the target</a>
                            first, or reject.
                        </span>
                    {/if}
                    <Input
                        label="Note"
                        placeholder="Optional"
                        value={notes[item.id] ?? ''}
                        oninput={e => (notes[item.id] = (e.target as HTMLInputElement).value)}
                    />
                    <Button
                        icon="check"
                        size="compact"
                        variant="primary"
                        disabled={!$adminPermissions.accessRolesAssign ||
                            (item.candidates.length > 0 && !choices[item.id])}
                        onclick={() => confirm(item)}
                    >
                        Confirm
                    </Button>
                    <Button
                        icon="close"
                        size="compact"
                        variant="ghost"
                        disabled={!$adminPermissions.accessRolesAssign}
                        onclick={() => reject(item)}
                    >
                        Reject
                    </Button>
                </div>
            </li>
        {/each}
    </ul>

    <button type="button" class="toggle" onclick={() => (showReport = !showReport)}>
        {showReport ? 'Hide' : 'Show'} the rest of the migration report ({decided.length})
    </button>
    {#if showReport}
        <ul class="items report">
            {#each decided as item (item.id)}
                <li class="item">
                    <div class="item-head">
                        <Badge>{CATEGORY_LABELS[item.category]}</Badge>
                        {#if item.status !== AccessMigrationStatus.Info}
                            <Badge tone={item.status === AccessMigrationStatus.Confirmed ? 'success' : 'neutral'}>
                                {item.status === AccessMigrationStatus.Confirmed ? 'Confirmed' : 'Rejected'}
                            </Badge>
                        {/if}
                        <span class="muted">{subject(item)}</span>
                        {#if item.targetName}
                            <span>{item.targetName}</span>
                        {/if}
                    </div>
                    <p class="permission">{item.legacyPermission}</p>
                    <p class="muted">{item.resolution || item.reason}</p>
                </li>
            {/each}
        </ul>
    {/if}
{/if}

<style>
    .summary {
        display: flex;
        flex-wrap: wrap;
        gap: var(--wg-space-xs);
        margin: var(--wg-space-lg) 0;
    }

    h3 {
        margin: var(--wg-space-lg) 0 var(--wg-space-sm);
        font: var(--wg-text-label-md);
        color: var(--wg-text-muted);
    }

    .items {
        list-style: none;
        margin: 0;
        padding: 0;
        display: flex;
        flex-direction: column;
        gap: var(--wg-space-md);
    }

    .item {
        padding: var(--wg-space-md);
        border: var(--wg-border-width) solid var(--wg-border);
        border-radius: var(--wg-radius-panel);
    }

    .item-head {
        display: flex;
        flex-wrap: wrap;
        align-items: center;
        gap: var(--wg-space-sm);
    }

    .permission {
        margin: var(--wg-space-sm) 0 var(--wg-space-xs);
        font: var(--wg-text-body-md);
    }

    .muted {
        margin: 0;
        color: var(--wg-text-muted);
        font: var(--wg-text-body-md);
    }

    .decide {
        display: flex;
        flex-wrap: wrap;
        align-items: flex-end;
        gap: var(--wg-space-md);
        margin-top: var(--wg-space-md);
    }

    .decide > :global(*) {
        flex: 1 1 12rem;
        max-width: 20rem;
    }

    .decide > :global(button) {
        flex: 0 0 auto;
    }

    .toggle {
        margin-top: var(--wg-space-lg);
        padding: 0;
        border: 0;
        background: none;
        color: var(--wg-primary);
        font: var(--wg-text-label-md);
        cursor: pointer;
    }

    .toggle:focus-visible {
        outline: var(--wg-focus-ring);
        outline-offset: var(--wg-focus-ring-offset);
    }

    .report {
        margin-top: var(--wg-space-md);
    }
</style>
