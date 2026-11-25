<script lang="ts">
    /**
     * Access Control — the one place access is granted, reviewed and revoked.
     *
     * The relationship is user → target → account. An assignment is both the
     * permission to reach the target and the permission to sign in there as
     * that account; nothing else grants access (a role alone does not, nor a
     * credential on a target). Three tabs:
     *
     *   - Assignments: every effective assignment, direct and group-derived,
     *     with where it comes from and whether it can be used now.
     *   - Access groups: what each group (a role) grants its members; the
     *     group's settings and members stay on the role page.
     *   - Policies: when connections may start, and what is asked for outside
     *     those times (a schedule, an approval), for a user, group or target.
     *   - Migration review: what the upgrade could not map without widening
     *     anyone's access, waiting for a decision.
     *
     * The server decides every rule; these screens edit and show.
     */
    import { AccessMigrationStatus, api } from 'admin/lib/api'
    import { push, router } from 'svelte-spa-router'
    import Tabs from 'ui/Tabs.svelte'
    import AccessGroups from './AccessGroups.svelte'
    import Assignments from './Assignments.svelte'
    import MigrationReview from './MigrationReview.svelte'
    import Policies from './Policies.svelte'

    type TabValue = 'assignments' | 'groups' | 'policies' | 'review'

    interface Props {
        params?: { tab?: string }
        /** For the legacy routes this screen replaces. */
        defaultTab?: TabValue
    }

    let { params = {}, defaultTab = 'assignments' }: Props = $props()

    function valid(value: string | undefined): TabValue {
        return value === 'groups' ||
            value === 'policies' ||
            value === 'review' ||
            value === 'assignments'
            ? value
            : defaultTab
    }

    let tab = $state<TabValue>('assignments')
    $effect(() => {
        tab = valid(params.tab)
    })

    // Filters handed over in the query string: from a target's page
    // (?target=…), a user's (?user=…) or a group's (?group=…).
    const query = $derived(new URLSearchParams(router.querystring ?? ''))
    const initialUser = $derived(query.get('user') ?? '')
    const initialTarget = $derived(query.get('target') ?? '')
    const initialGroup = $derived(query.get('group') ?? '')

    let pending = $state(0)
    function refreshPending() {
        api.listAccessMigrationReviews({ status: AccessMigrationStatus.Pending })
            .then(items => {
                pending = items.length
            })
            .catch(() => {
                pending = 0
            })
    }
    refreshPending()

    const tabs = $derived([
        { value: 'assignments' as const, label: 'Assignments' },
        { value: 'groups' as const, label: 'Access groups' },
        { value: 'policies' as const, label: 'Policies' },
        {
            value: 'review' as const,
            label: 'Migration review',
            badge: pending || undefined,
        },
    ])

    function onchange(value: TabValue) {
        push(
            value === 'assignments'
                ? '/config/access-control'
                : `/config/access-control/${value}`,
        )
    }
</script>

<div class="head">
    <h1>Access control</h1>
</div>

<p class="intro">
    Who may connect to which target, as which remote account, and when. Grant
    Access gives a user an account on a target, directly or through an access
    group; that is the whole permission. Policies limit when connections can
    start and ask for approval outside working hours. Second factors and
    session limits still apply on top. Admin roles, which govern this console,
    are separate.
</p>

{#if pending}
    <p class="pending-note">
        <a href="#/config/access-control/review">
            {pending} permission{pending === 1 ? '' : 's'} from before the upgrade
            {pending === 1 ? 'waits' : 'wait'} for review
        </a>: they grant nothing until confirmed.
    </p>
{/if}

<Tabs label="Access control" bind:value={tab} {tabs} {onchange}>
    {#snippet children(active)}
        {#if active === 'assignments'}
            {#key `${initialUser}|${initialTarget}`}
                <Assignments {initialUser} {initialTarget} />
            {/key}
        {:else if active === 'groups'}
            <AccessGroups {initialGroup} />
        {:else if active === 'policies'}
            <Policies />
        {:else}
            <MigrationReview onchange={refreshPending} />
        {/if}
    {/snippet}
</Tabs>

<style>
    h1 {
        margin: 0;
        font: var(--wg-text-headline-lg);
    }

    .head {
        margin-bottom: var(--wg-space-sm);
    }

    .intro {
        margin: 0 0 var(--wg-space-lg);
        max-width: 80ch;
        font: var(--wg-text-body-md);
        color: var(--wg-text-muted);
    }

    .pending-note {
        margin: 0 0 var(--wg-space-lg);
        font: var(--wg-text-body-md);
    }

    .pending-note a {
        color: var(--wg-secondary);
        font-weight: 600;
    }
</style>
