<script lang="ts">
    /**
     * The approval requests that access policies asked for, and what became of
     * each: pending, approved, rejected, expired (nobody answered, or an approval
     * was not used in time) or used (a connection started on it, once).
     *
     * These are the same requests the approvals screen decides; this is only the
     * record. Deciding a pending one happens there.
     */
    import {
        type AccessApproval,
        AccessApprovalStatus,
        api,
    } from 'admin/lib/api'
    import { stringifyError } from 'common/errors'
    import Badge, { type BadgeTone } from 'ui/Badge.svelte'
    import Callout from 'ui/Callout.svelte'
    import EmptyState from 'ui/EmptyState.svelte'
    import RelativeDate from 'ui/RelativeDate.svelte'
    import SkeletonRow from 'ui/SkeletonRow.svelte'

    const LABELS: Record<AccessApprovalStatus, string> = {
        [AccessApprovalStatus.Pending]: 'Pending',
        [AccessApprovalStatus.Approved]: 'Approved',
        [AccessApprovalStatus.Rejected]: 'Rejected',
        [AccessApprovalStatus.Expired]: 'Expired',
        [AccessApprovalStatus.Used]: 'Used',
        [AccessApprovalStatus.Abandoned]: 'Withdrawn',
    }

    const TONES: Record<AccessApprovalStatus, BadgeTone> = {
        [AccessApprovalStatus.Pending]: 'warning',
        [AccessApprovalStatus.Approved]: 'primary',
        [AccessApprovalStatus.Rejected]: 'danger',
        [AccessApprovalStatus.Expired]: 'neutral',
        [AccessApprovalStatus.Used]: 'success',
        [AccessApprovalStatus.Abandoned]: 'neutral',
    }

    let items = $state<AccessApproval[]>([])
    let loading = $state(true)
    let error = $state<string | null>(null)

    async function load() {
        try {
            items = await api.listAccessApprovals()
            error = null
        } catch (e) {
            error = await stringifyError(e)
        } finally {
            loading = false
        }
    }

    load()
</script>

{#if error}
    <Callout tone="danger" title="Could not load approval requests">{error}</Callout>
{:else if loading}
    <SkeletonRow rows={3} columns={[2, 2, 2, 1, 2]} />
{:else if !items.length}
    <EmptyState
        icon="inbox"
        size="compact"
        title="No approval requests yet"
        hint="When a policy asks for approval, the request and what became of it are listed here."
    />
{:else}
    <div class="table-wrap">
        <table>
            <thead>
                <tr>
                    <th scope="col">Requested</th>
                    <th scope="col">User</th>
                    <th scope="col">Target</th>
                    <th scope="col">Policy</th>
                    <th scope="col">Status</th>
                    <th scope="col">Details</th>
                </tr>
            </thead>
            <tbody>
                {#each items as item (`${item.id}:${item.target}:${item.requestedAt.getTime()}`)}
                    <tr>
                        <td><RelativeDate date={item.requestedAt} /></td>
                        <td>{item.username}</td>
                        <td>
                            <span class="wg-mono">{item.target}</span>
                            {#if item.account}
                                <span class="muted"> as {item.account}</span>
                            {/if}
                        </td>
                        <td title={item.reason}>{item.policyName}</td>
                        <td>
                            <Badge tone={TONES[item.status]}>{LABELS[item.status]}</Badge>
                        </td>
                        <td class="muted">
                            {#if item.status === AccessApprovalStatus.Pending}
                                Answer by {item.expiresAt.toLocaleString()}
                            {:else if item.status === AccessApprovalStatus.Approved}
                                By {item.resolvedBy ?? 'an approver'}; valid until
                                {item.validUntil?.toLocaleString()}
                            {:else if item.status === AccessApprovalStatus.Used}
                                By {item.resolvedBy ?? 'an approver'}; used
                                {item.usedAt?.toLocaleString()}
                            {:else if item.status === AccessApprovalStatus.Rejected}
                                By {item.resolvedBy ?? 'an approver'}
                            {:else if item.status === AccessApprovalStatus.Expired}
                                {item.validUntil
                                    ? `Approved, not used by ${item.validUntil.toLocaleString()}`
                                    : `Nobody answered by ${item.expiresAt.toLocaleString()}`}
                            {:else}
                                The connection went away
                            {/if}
                        </td>
                    </tr>
                {/each}
            </tbody>
        </table>
    </div>
{/if}

<style>
    .table-wrap {
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

    .muted {
        color: var(--wg-text-muted);
    }
</style>
