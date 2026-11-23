<script lang="ts">
    /**
     * My targets — screen 13.
     *
     * ── Enumeration of gateway/TargetList.svelte, asserted present ───────
     * Load:     getTargets({ search }) with the same three-level natural sort
     *           — ungrouped first, then by group name, then by target name.
     * Stores:   collapsedTargetGroups, openTargetsInNewTab,
     *           openTargetsInNewTabForced, setOpenTargetsInNewTab.
     * Gates:    canEditTargets from serverInfo.adminPermissions.targetsEdit;
     *           webClientsEnabled from serverInfo.webClientsEnabled, default
     *           true.
     * urlForTarget: HTTP -> externalHost carrying location.port, else
     *           `/?warpgate-target=<name>`; SSH -> #/web-ssh/start/<id>;
     *           VNC and RDP -> #/web-desktop/start/<id>.
     * selectTarget: HTTP navigates; SSH shows instructions when web clients
     *           are off OR targetClickAction is ShowInstructions, otherwise
     *           opens the web terminal; VNC/RDP show instructions when web
     *           clients are off, otherwise open the web desktop; anything
     *           else shows instructions.
     * openInBrowser: sets openingTarget, surfaces a failure into openError,
     *           clears in `finally`. A target behind approval holds this until
     *           an administrator decides and answers 403 if they refuse, so
     *           it needs both a sign of progress and somewhere for the
     *           refusal to land.
     * loadURL:  honours openTargetsInNewTab for HTTP targets.
     * Row:      name, description, protocol label for all seven kinds,
     *           ctrl/cmd-click falls through to the browser so a target can
     *           still be opened in a new tab, and `target="_blank"` on HTTP
     *           rows when the preference is set.
     * Menu:     Web terminal (SSH + web clients), Web desktop (VNC/RDP + web
     *           clients), Connection instructions, Edit target (when
     *           canEditTargets).
     * Modal:    ConnectionInstructions with the defaultDatabaseName plumbing,
     *           a Web terminal action for SSH, and Close.
     * Chrome:   GettingStarted when setupState is present; the
     *           "no other targets yet" empty state when setupState says there
     *           are none; the access empty state otherwise.
     *
     * ── Cards, with the fields that exist ────────────────────────────────
     * The mockup's card grid suits a portal — a handful of items, roomier
     * than an admin table — so the shape is kept. Its contents mostly cannot
     * be: `TargetSnapshot` is id, name, description, kind, externalHost,
     * group and defaultDatabaseName. There is no host, no port, no role list
     * and no health.
     *
     * Omitted rather than faked:
     *   "bastion-core-01.internal:22"  no host or port on the portal
     *                                  snapshot — deliberate on the server's
     *                                  part, the portal does not publish
     *                                  internal addresses.
     *   "ROLE oncall sre-lead"         no roles on the snapshot.
     *   Online / Unreachable, and      no health or reachability anywhere in
     *   "11 operational / 1 degraded"  the API. Same gap as the admin
     *                                  Targets screen.
     *   "RECENTLY USED" strip          no per-user usage history.
     *   "ZONE: PROD-EU-CENTRAL-1"      no zones.
     *   per-card copy button           nothing to copy; the address the
     *                                  mockup copies is the one field that
     *                                  does not exist.
     *
     * What a card does show is real: a protocol icon and label from `kind`;
     * the public host of an HTTP target (the one urlForTarget opens, not an
     * internal address) and the default database of a database target; the
     * description, two lines at most so cards keep one height; and the
     * action, at the foot of every card at the same height.
     *
     * The protocol filter chips are kept — those are derived from `kind`,
     * which is real, and they are the part of the design that earns its place
     * once the list is long. Each says how many targets it covers.
     *
     * ── The toolbar is outside the list ──────────────────────────────────
     * A protocol filter re-mounts the list (it filters in `loadTargets`).
     * With the search field and the chips inside it, each change of protocol
     * cleared the search and took the focus off the chip just chosen. They
     * sit above it, the search text reaching the list through its bindable
     * `filter`, and "/" focuses the search, as in the mockup.
     */
    import CollapsibleGroupHeader from 'common/CollapsibleGroupHeader.svelte'
    import ConnectionInstructions from 'common/ConnectionInstructions.svelte'
    import { stringifyError } from 'common/errors'
    import GettingStarted from 'common/GettingStarted.svelte'
    import { orderForGroupedList, resolveGroup } from 'common/groups'
    import ItemList, {
        type GroupControls,
        type LoadOptions,
        type PaginatedResponse,
    } from 'common/ItemList.svelte'
    import ListOverflowMenu from 'common/ListOverflowMenu.svelte'
    import { TARGET_KIND_ICONS, TARGET_KIND_LABELS } from 'common/targetKinds'
    import {
        api,
        TargetClickAction,
        TargetKind,
        type TargetSnapshot,
    } from 'gateway/lib/api'
    import { from, map, type Observable } from 'rxjs'
    import { get } from 'svelte/store'
    import Badge from 'ui/Badge.svelte'
    import Button from 'ui/Button.svelte'
    import Callout from 'ui/Callout.svelte'
    import EmptyState from 'ui/EmptyState.svelte'
    import Input from 'ui/Input.svelte'
    import Menu from 'ui/Menu.svelte'
    import Modal from 'ui/Modal.svelte'
    import SegmentedControl from 'ui/SegmentedControl.svelte'
    import {
        collapsedTargetGroups,
        openTargetsInNewTab,
        openTargetsInNewTabForced,
        serverInfo,
        setOpenTargetsInNewTab,
    } from '../lib/store'
    import {
        openWebDesktopSession,
        openWebSshSession,
    } from '../lib/webSessions'

    interface Props {
        /**
         * Called just before this screen replaces the page with an HTTP
         * target. The shell uses it to show "Opening your session" for the
         * gap between the click and the browser leaving, which on a slow
         * target is long enough to look like nothing happened.
         */
        onnavigate?: () => void
    }

    const { onnavigate }: Props = $props()

    /** The primary action's icon, drawn as the target kind icons are. */
    const ACTION_ICONS = {
        // An arrow out of a box: the target opens as a page of its own.
        open: 'M9 3h4v4M13 3 7.5 8.5M11 9.5V13H3V5h3.5',
        // Play: a session starts in the browser.
        start: 'M5 3.5v9l7.5-4.5z',
        // An i in a circle: how to reach it from a client of your own.
        instructions: 'M8 14A6 6 0 108 2a6 6 0 000 12zM8 7.5V11M8 5v.01',
    }

    let instructionsTarget: TargetSnapshot | undefined = $state()
    // The target an in-browser session is being opened for. Opening one can
    // take as long as an administrator takes to approve it, and until then
    // there is nothing else on screen to say the click did anything.
    let openingTarget: TargetSnapshot | undefined = $state()
    let openError: string | undefined = $state()
    let kindFilter: string = $state('all')
    let search = $state('')
    let searchElement: HTMLInputElement | undefined = $state()
    // What the last load found: every kind among the search results with how
    // many there are, and the targets the protocol filter then left.
    let kindCounts: Record<string, number> = $state({})
    let total = $state(0)
    let visible: TargetSnapshot[] = $state.raw([])

    const canEditTargets = $derived(
        $serverInfo?.adminPermissions?.targetsEdit ?? false,
    )
    const webClientsEnabled = $derived($serverInfo?.webClientsEnabled ?? true)

    function loadTargets(
        options: LoadOptions,
    ): Observable<PaginatedResponse<TargetSnapshot>> {
        return from(api.getTargets({ search: options.search })).pipe(
            map(result => {
                // Alphabetical by group then name, EXCEPT while searching: the
                // server ranks fuzzy matches (upstream #2714) and re-sorting
                // would bury the best one. See common/groups.
                const sorted = orderForGroupedList(result, options.search, {
                    groupId: t => t.group?.id,
                    groupName: t => t.group?.name ?? '',
                    name: t => t.name,
                })

                // Chips reflect everything the search returned, not what the
                // chip filter then narrows it to — otherwise picking one chip
                // makes the others vanish.
                const counts: Record<string, number> = {}
                for (const target of sorted) {
                    counts[target.kind] = (counts[target.kind] ?? 0) + 1
                }
                kindCounts = counts
                total = sorted.length

                const items =
                    kindFilter === 'all'
                        ? sorted
                        : sorted.filter(t => t.kind === kindFilter)
                visible = items

                return {
                    items,
                    offset: 0,
                    total: items.length,
                }
            }),
        )
    }

    function urlForTarget(target: TargetSnapshot): string | undefined {
        if (target.kind === TargetKind.Http) {
            if (target.externalHost) {
                const port = location.port ? `:${location.port}` : ''
                return `${location.protocol}//${target.externalHost}${port}`
            } else {
                return `/?warpgate-target=${encodeURIComponent(target.name)}`
            }
        } else if (target.kind === TargetKind.Ssh) {
            return `/@warpgate/#/web-ssh/start/${target.id}`
        } else if (
            target.kind === TargetKind.Vnc ||
            target.kind === TargetKind.Rdp
        ) {
            return `/@warpgate/#/web-desktop/start/${target.id}`
        }
    }

    function selectTarget(target: TargetSnapshot) {
        if (target.kind === TargetKind.Http) {
            // biome-ignore lint/style/noNonNullAssertion: .
            loadURL(urlForTarget(target)!)
        } else if (target.kind === TargetKind.Ssh) {
            const targetClickAction = $serverInfo?.targetClickAction
            if (
                !webClientsEnabled ||
                targetClickAction === TargetClickAction.ShowInstructions
            ) {
                instructionsTarget = target
            } else {
                void openInBrowser(target, () => openWebSshSession(target.id))
            }
        } else if (
            target.kind === TargetKind.Vnc ||
            target.kind === TargetKind.Rdp
        ) {
            if (!webClientsEnabled) {
                instructionsTarget = target
            } else {
                openWebDesktopSession(target.id)
            }
        } else {
            instructionsTarget = target
        }
    }

    // A target that needs administrator approval holds this until someone
    // decides, and answers 403 if they say no — so it needs both a sign that
    // it is in progress and somewhere for the refusal to land.
    async function openInBrowser(
        target: TargetSnapshot,
        open: () => void | Promise<void>,
    ) {
        openError = undefined
        openingTarget = target
        try {
            await open()
        } catch (err) {
            openError = await stringifyError(err)
        } finally {
            openingTarget = undefined
        }
    }

    function showInstructions(target: TargetSnapshot) {
        instructionsTarget = target
    }

    function loadURL(url: string) {
        // Only HTTP targets navigate via loadURL. Honour the opt-in preference
        // to open them in a new tab (mirrors how SSH/desktop targets already
        // use window.open) so the target list isn't lost.
        if (get(openTargetsInNewTab)) {
            window.open(url, '_blank')
        } else {
            // The shell swaps the page for "Opening your session" while the
            // browser leaves. Only on this branch: a new tab leaves this one
            // where it was, and a spinner over a list that is still usable
            // would be a lie.
            onnavigate?.()
            location.href = url
        }
    }

    function groupInfoFromTarget(target: TargetSnapshot) {
        return resolveGroup(target.group)
    }

    function kindLabel(kind: string): string {
        return TARGET_KIND_LABELS[kind as TargetKind] ?? kind
    }

    function kindIcon(kind: string): string {
        return (
            TARGET_KIND_ICONS[kind as TargetKind] ??
            TARGET_KIND_ICONS[TargetKind.Ssh]
        )
    }

    /** The verb on the primary button, which differs by protocol. */
    function actionLabel(target: TargetSnapshot): string {
        if (target.kind === TargetKind.Http) {
            return 'Open web'
        }
        if (target.kind === TargetKind.Rdp || target.kind === TargetKind.Vnc) {
            return webClientsEnabled ? 'Launch desktop' : 'How to connect'
        }
        if (target.kind === TargetKind.Ssh) {
            return webClientsEnabled &&
                $serverInfo?.targetClickAction !==
                    TargetClickAction.ShowInstructions
                ? 'Connect'
                : 'How to connect'
        }
        return 'How to connect'
    }

    function actionIcon(target: TargetSnapshot): string {
        if (target.kind === TargetKind.Http) {
            return ACTION_ICONS.open
        }
        return actionLabel(target) === 'How to connect'
            ? ACTION_ICONS.instructions
            : ACTION_ICONS.start
    }

    /**
     * A line of machine data under the name, from the fields the snapshot
     * has: where an HTTP target opens, and a database target's default
     * database. Nothing for the rest rather than something made up.
     */
    function detailFor(target: TargetSnapshot): string | undefined {
        if (target.kind === TargetKind.Http) {
            return target.externalHost ?? undefined
        }
        if (
            (target.kind === TargetKind.MySql ||
                target.kind === TargetKind.Postgres) &&
            target.defaultDatabaseName
        ) {
            return `db ${target.defaultDatabaseName}`
        }
        return undefined
    }

    function menuGroupsFor(target: TargetSnapshot) {
        const items = []
        if (target.kind === TargetKind.Ssh && webClientsEnabled) {
            items.push({
                id: 'web-terminal',
                label: 'Web terminal',
                onselect: () =>
                    void openInBrowser(target, () =>
                        openWebSshSession(target.id),
                    ),
            })
        }
        if (
            (target.kind === TargetKind.Vnc ||
                target.kind === TargetKind.Rdp) &&
            webClientsEnabled
        ) {
            items.push({
                id: 'web-desktop',
                label: 'Web desktop',
                onselect: () => openWebDesktopSession(target.id),
            })
        }
        items.push({
            id: 'instructions',
            label: 'Connection instructions',
            onselect: () => showInstructions(target),
        })
        if (canEditTargets) {
            items.push({
                id: 'edit',
                label: 'Edit target',
                href: `/@warpgate/admin#/config/targets/${target.id}`,
            })
        }
        return [{ items }]
    }

    const kindSegments = $derived.by(() => {
        const kinds = Object.keys(kindCounts)
        // A chosen kind the search no longer finds stays on the bar, at
        // zero, so it is clear what is filtering and one click undoes it.
        if (kindFilter !== 'all' && !kinds.includes(kindFilter)) {
            kinds.push(kindFilter)
        }
        return [
            { value: 'all', label: 'All', count: total },
            ...kinds.map(kind => ({
                value: kind,
                label: kindLabel(kind),
                count: kindCounts[kind] ?? 0,
            })),
        ]
    })

    // Before the first load, and for a user with no targets, there is nothing
    // to search or filter.
    const showToolbar = $derived(search !== '' || total > 0)

    // Collapse all and Expand all, as the list would offer them: only with
    // more than one group on screen (a lone group has no header to collapse)
    // and not while searching, when every group is shown open.
    const visibleGroupIds = $derived([
        ...new Set(visible.map(t => groupInfoFromTarget(t).id)),
    ])
    const groupControls: GroupControls = $derived({
        available: visibleGroupIds.length > 1 && !search,
        collapseAll: () => {
            $collapsedTargetGroups = visibleGroupIds
        },
        expandAll: () => {
            $collapsedTargetGroups = []
        },
    })

    const preferenceGroup = $derived([
        {
            label: 'Preferences',
            items: [
                {
                    id: 'new-tab',
                    label: 'Open targets in a new tab',
                    checked: $openTargetsInNewTab,
                    disabled: $openTargetsInNewTabForced,
                    hint: $openTargetsInNewTabForced
                        ? 'Managed by the administrator'
                        : undefined,
                    onselect: () =>
                        setOpenTargetsInNewTab(!$openTargetsInNewTab),
                },
            ],
        },
    ])

    // "/" focuses the search, unless it is being typed somewhere else or a
    // dialog is up.
    function onWindowKeydown(event: KeyboardEvent) {
        if (
            event.key !== '/' ||
            event.ctrlKey ||
            event.metaKey ||
            event.altKey ||
            event.defaultPrevented ||
            instructionsTarget
        ) {
            return
        }
        const origin = event.target
        if (
            origin instanceof HTMLElement &&
            (origin.isContentEditable ||
                origin.closest('input, textarea, select'))
        ) {
            return
        }
        if (searchElement) {
            event.preventDefault()
            searchElement.focus()
        }
    }

    function onSearchKeydown(event: KeyboardEvent) {
        if (event.key === 'Escape' && search) {
            event.preventDefault()
            search = ''
        }
    }
</script>

<svelte:window onkeydown={onWindowKeydown} />

<div class="head">
    <h1>My targets</h1>
    <p class="lede">Everything you can reach through Warpgate.</p>
</div>

{#if $serverInfo?.setupState}
    <GettingStarted setupState={$serverInfo?.setupState} />
{/if}

{#if openingTarget}
    <div class="notice">
        <Callout title="Connecting to {openingTarget.name}">
            If this target needs approval, it will start once an administrator
            approves it.
        </Callout>
    </div>
{/if}

{#if openError}
    <div class="notice">
        <Callout tone="danger" title="Could not open that target">
            {openError}
        </Callout>
    </div>
{/if}

{#if showToolbar}
    <div class="toolbar">
        <div class="toolbar-search">
            <Input
                label="Search targets"
                labelHidden
                type="search"
                size="compact"
                placeholder="Search targets…"
                bind:value={search}
                bind:inner={searchElement}
                onkeydown={onSearchKeydown}
            >
                {#snippet prefix()}
                    <svg
                        viewBox="0 0 16 16"
                        width="14"
                        height="14"
                        aria-hidden="true"
                    >
                        <circle
                            cx="7"
                            cy="7"
                            r="4.5"
                            fill="none"
                            stroke="currentColor"
                            stroke-width="1.5"
                        />
                        <path
                            d="M10.5 10.5L14 14"
                            stroke="currentColor"
                            stroke-width="1.5"
                            stroke-linecap="round"
                        />
                    </svg>
                {/snippet}
                {#snippet suffix()}
                    {#if !search}
                        <kbd class="shortcut">/</kbd>
                    {/if}
                {/snippet}
            </Input>
        </div>

        {#if kindSegments.length > 2}
            <div class="toolbar-filters">
                <SegmentedControl
                    label="Filter by protocol"
                    size="compact"
                    segments={kindSegments}
                    bind:value={kindFilter}
                />
            </div>
        {/if}

        <div class="toolbar-end">
            <span class="result-count" aria-live="polite">
                {visible.length}
                {visible.length === 1 ? 'target' : 'targets'}
            </span>
            <ListOverflowMenu
                {groupControls}
                extraGroups={preferenceGroup}
                label="Target list options"
            />
        </div>
    </div>
{/if}

{#key kindFilter}
    <ItemList
        load={loadTargets}
        bind:filter={search}
        groupObject={groupInfoFromTarget}
        groupKey={group => group.id}
        bind:collapsedGroups={$collapsedTargetGroups}
    >
        {#snippet empty()}
            <EmptyState
                title={kindFilter === 'all'
                    ? "You don't have access to any targets yet"
                    : 'No targets of that kind'}
                hint={kindFilter === 'all'
                    ? `Ask an administrator to give ${$serverInfo?.username ?? 'your account'} a role with the targets you need.`
                    : undefined}
            />
        {/snippet}

        {#snippet groupHeader(group, state)}
            <!-- A row of the grid of its own, across every column. -->
            <li class="group-row">
                <CollapsibleGroupHeader {group} {state} />
            </li>
        {/snippet}

        {#snippet container(rows, items)}
            <!--
              Below four cards the grid's own visual language is the problem:
              auto-fill lays out tracks for a full row whatever the content, so
              one card sits in the left track with three empty ones beside it
              and reads as a layout fault rather than as "you have one target".
              Capping the width lets the same cards size themselves against a
              measure that matches the content.
            -->
            <ul class="grid" class:grid-sparse={items.length < 4}>
                {@render rows()}
            </ul>
        {/snippet}

        {#snippet item(target)}
            {@const detail = detailFor(target)}
            <li class="card" aria-busy={openingTarget?.id === target.id}>
                <div class="card-head">
                    <span class="card-icon" aria-hidden="true">
                        <svg
                            viewBox="0 0 16 16"
                            width="18"
                            height="18"
                            aria-hidden="true"
                        >
                            <path
                                d={kindIcon(target.kind)}
                                fill="none"
                                stroke="currentColor"
                                stroke-width="1.3"
                                stroke-linecap="round"
                                stroke-linejoin="round"
                            />
                        </svg>
                    </span>

                    <div class="card-title">
                        <a
                            class="card-name"
                            href={urlForTarget(target)}
                            title={target.name}
                            target={target.kind === TargetKind.Http &&
                            $openTargetsInNewTab
                                ? '_blank'
                                : undefined}
                            onclick={e => {
                                // Let the browser handle a modified click, so a
                                // target can still be opened in a new tab
                                // deliberately.
                                if (e.metaKey || e.ctrlKey) {
                                    return
                                }
                                e.preventDefault()
                                e.stopPropagation()
                                selectTarget(target)
                            }}
                        >
                            {target.name}
                        </a>
                        <div class="card-meta">
                            <Badge mono>{kindLabel(target.kind)}</Badge>
                            {#if detail}
                                <span class="card-detail" title={detail}
                                    >{detail}</span
                                >
                            {/if}
                        </div>
                    </div>

                    <div class="card-menu">
                        <Menu
                            groups={menuGroupsFor(target)}
                            label="Actions for {target.name}"
                        />
                    </div>
                </div>

                {#if target.description}
                    <p class="card-description" title={target.description}>
                        {target.description}
                    </p>
                {/if}

                <div class="card-actions">
                    <Button
                        variant="primary"
                        size="compact"
                        onclick={() => selectTarget(target)}
                    >
                        <svg
                            viewBox="0 0 16 16"
                            width="13"
                            height="13"
                            aria-hidden="true"
                        >
                            <path
                                d={actionIcon(target)}
                                fill="none"
                                stroke="currentColor"
                                stroke-width="1.6"
                                stroke-linecap="round"
                                stroke-linejoin="round"
                            />
                        </svg>
                        {actionLabel(target)}
                    </Button>
                </div>
            </li>
        {/snippet}
    </ItemList>
{/key}

{#if $serverInfo?.setupState && !$serverInfo.setupState.hasTargets}
    <EmptyState
        title="No other targets yet"
        hint="Once you add targets and assign access, they will appear here"
    />
{/if}

<Modal
    open={!!instructionsTarget}
    title="Connect to {instructionsTarget?.name ?? ''}"
    size="lg"
    onclose={() => (instructionsTarget = undefined)}
>
    {#if instructionsTarget}
        {@const t = instructionsTarget}
        <ConnectionInstructions
            targetName={t.name}
            username={$serverInfo?.username}
            targetKind={t.kind ?? TargetKind.Ssh}
            targetDefaultDatabaseName={t.kind === TargetKind.MySql ||
            t.kind === TargetKind.Postgres
                ? t.defaultDatabaseName
                : undefined}
        />
    {/if}

    {#snippet footer()}
        {#if instructionsTarget?.kind === TargetKind.Ssh && webClientsEnabled}
            {@const sshTarget = instructionsTarget}
            <Button
                variant="primary"
                onclick={() => {
                    instructionsTarget = undefined
                    void openInBrowser(sshTarget, () =>
                        openWebSshSession(sshTarget.id),
                    )
                }}
            >
                Web terminal
            </Button>
        {/if}
        <Button onclick={() => (instructionsTarget = undefined)}>Close</Button>
    {/snippet}
</Modal>

<style>
    .head {
        margin-bottom: var(--wg-space-xl);
    }

    h1 {
        margin: 0;
        font: var(--wg-text-headline-lg);
    }

    .lede {
        margin: var(--wg-space-xs) 0 0;
        color: var(--wg-text-muted);
        font: var(--wg-text-body-md);
    }

    .notice {
        margin-bottom: var(--wg-space-lg);
    }

    /* ── Toolbar ─────────────────────────────────────────────────────── */

    /* The list adds a row of its own under this, a space-sm high. */
    .toolbar {
        display: flex;
        flex-wrap: wrap;
        align-items: center;
        gap: var(--wg-space-sm) var(--wg-space-md);
        margin-bottom: var(--wg-space-sm);
    }

    .toolbar-search {
        flex: 1 1 16rem;
        max-width: 26rem;
        min-width: 0;
    }

    /* Many protocols scroll sideways rather than wrapping into a second
     * line of chips. */
    .toolbar-filters {
        flex: 0 1 auto;
        min-width: 0;
        max-width: 100%;
        overflow-x: auto;
        scrollbar-width: thin;
    }

    .toolbar-end {
        display: flex;
        align-items: center;
        gap: var(--wg-space-sm);
        margin-left: auto;
    }

    .result-count {
        color: var(--wg-text-subtle);
        font: var(--wg-text-label-sm);
        font-variant-numeric: tabular-nums;
        white-space: nowrap;
    }

    .shortcut {
        display: inline-block;
        min-width: 1.1rem;
        padding: 0 3px;
        border: var(--wg-border-width) solid var(--wg-border);
        border-radius: var(--wg-radius-sm);
        background: var(--wg-surface-container-high);
        color: var(--wg-text-subtle);
        font: var(--wg-text-code-sm);
        text-align: center;
    }

    /* ── Grid ────────────────────────────────────────────────────────── */

    .grid {
        display: grid;
        grid-template-columns: repeat(auto-fill, minmax(17rem, 1fr));
        gap: var(--wg-space-md);
        list-style: none;
        margin: 0;
        padding: 0;
    }

    /*
     * 1-3 targets. One track per card up to three, so the row is full at any
     * count in that range and nothing is left hanging beside an empty track.
     * The cap stops two cards stretching to half a wide screen each.
     */
    .grid-sparse {
        grid-template-columns: repeat(auto-fit, minmax(17rem, 22rem));
    }

    .group-row {
        grid-column: 1 / -1;
        min-width: 0;
    }

    /* ── Card ────────────────────────────────────────────────────────── */

    .card {
        display: flex;
        flex-direction: column;
        gap: var(--wg-space-sm);
        min-width: 0;
        padding: var(--wg-space-lg);
        background: var(--wg-surface-container);
        border: var(--wg-border-width) solid var(--wg-border);
        border-radius: var(--wg-radius-panel);
        transition: border-color var(--wg-duration-fast) var(--wg-easing);
    }

    /* The card is not a control; its link and buttons are. The border says
     * which card the pointer or the focus is in. */
    .card:hover {
        border-color: var(--wg-border-strong);
    }

    .card:focus-within {
        border-color: var(--wg-primary);
    }

    .card[aria-busy="true"] {
        border-color: var(--wg-secondary);
    }

    .card-head {
        display: flex;
        align-items: flex-start;
        gap: var(--wg-space-md);
        min-width: 0;
    }

    .card-icon {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        flex: none;
        width: 2.25rem;
        height: 2.25rem;
        border: var(--wg-border-width) solid var(--wg-border);
        border-radius: var(--wg-radius-md);
        background: var(--wg-surface-container-high);
        color: var(--wg-text-muted);
        transition: color var(--wg-duration-fast) var(--wg-easing);
    }

    .card:hover .card-icon,
    .card:focus-within .card-icon {
        color: var(--wg-primary);
    }

    .card-title {
        display: flex;
        flex: 1 1 auto;
        flex-direction: column;
        gap: var(--wg-space-xs);
        min-width: 0;
    }

    .card-name {
        display: block;
        overflow: hidden;
        color: var(--wg-text);
        font: var(--wg-text-body-lg);
        font-weight: 600;
        text-decoration: none;
        text-overflow: ellipsis;
        white-space: nowrap;
        border-radius: var(--wg-radius-sm);
    }

    .card-name:hover {
        text-decoration: underline;
    }

    .card-name:focus-visible {
        outline: var(--wg-focus-ring);
        outline-offset: var(--wg-focus-ring-offset);
    }

    .card-meta {
        display: flex;
        align-items: center;
        gap: var(--wg-space-sm);
        min-width: 0;
    }

    .card-detail {
        min-width: 0;
        overflow: hidden;
        color: var(--wg-text-subtle);
        font: var(--wg-text-code-sm);
        text-overflow: ellipsis;
        white-space: nowrap;
    }

    /* Pulls the kebab into the corner, level with the name. */
    .card-menu {
        flex: none;
        margin: calc(-1 * var(--wg-space-xs)) calc(-1 * var(--wg-space-sm)) 0 0;
    }

    .card-description {
        display: -webkit-box;
        margin: 0;
        overflow: hidden;
        color: var(--wg-text-muted);
        font: var(--wg-text-body-md);
        overflow-wrap: anywhere;
        -webkit-box-orient: vertical;
        -webkit-line-clamp: 2;
        line-clamp: 2;
    }

    /* At the foot of the card whatever is above it, so a row of cards has
     * its actions in a line. */
    .card-actions {
        display: flex;
        align-items: center;
        gap: var(--wg-space-sm);
        margin-top: auto;
        padding-top: var(--wg-space-md);
        border-top: var(--wg-border-width) solid var(--wg-border);
    }

    @media (max-width: 640px) {
        h1 {
            font: var(--wg-text-headline-lg-mobile);
        }

        .toolbar-search {
            flex-basis: 100%;
            max-width: none;
        }

        .grid,
        .grid-sparse {
            grid-template-columns: 1fr;
        }
    }

    @media (prefers-reduced-motion: reduce) {
        .card,
        .card-icon {
            transition: none;
        }
    }
</style>
