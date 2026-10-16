<script lang="ts" module>
    export interface LoadOptions {
        search?: string
        offset: number
        limit?: number
    }

    export interface PaginatedResponse<T> {
        items: T[]
        offset: number
        total: number
    }

    export interface GroupState {
        collapsed: boolean
        // False while a search is active, where every group is force-expanded:
        // a toggle would rewrite the persisted state without visible effect.
        collapsible: boolean
        toggle: () => void
    }

    export interface GroupControls {
        // False when there is nothing to collapse: either the list renders no
        // group headers, or a search is active, where the loaded items are only
        // a subset and "collapse all" would silently skip the rest.
        available: boolean
        collapseAll: () => void
        expandAll: () => void
    }
</script>

<script lang="ts" generics="T, G = unknown, GK = unknown">
    /**
     * Merged from upstream #2650 (virtual lists) and this fork's redesign.
     *
     * Upstream's half: group headers are ENTRIES in a flat list
     * (`{ kind: 'group' } | { kind: 'item' }`) rather than a flag on the row
     * that follows them, which is what lets `VirtualList` window them like any
     * other row; and the loaded state lives in a plain subscription rather
     * than `svelte-observable` stores awaited in markup.
     *
     * This fork's half, re-applied on that model: a labelled `ui/Input` for
     * search instead of sveltestrap's, the `searchInput` and `container`
     * snippets that let a screen supply its own search field or row markup
     * (a card grid, a real `<table>`), and suppression of a lone group header.
     *
     * `virtual` and `container` do not combine. VirtualList positions its own
     * rows absolutely, so it cannot live inside a caller's grid or table; when
     * both are given, `virtual` wins.
     */
    import {
        combineLatest,
        debounceTime,
        distinctUntilChanged,
        type Observable,
        Subject,
        switchMap,
        tap,
    } from 'rxjs'
    import { onDestroy, onMount, type Snippet } from 'svelte'
    import Input from 'ui/Input.svelte'
    import DelayedSpinner from './DelayedSpinner.svelte'
    import EmptyState from './EmptyState.svelte'
    import Pagination from './Pagination.svelte'
    import VirtualList from './VirtualList.svelte'

    interface Props {
        page?: number
        pageSize?: number | undefined
        load: (_: LoadOptions) => Observable<PaginatedResponse<T>>
        groupObject?: (_: T) => G
        groupKey?: (_: G) => GK
        showSearch?: boolean
        header?: Snippet<[T[] | null, GroupControls]>
        item?: Snippet<[T]>
        footer?: Snippet<[T[]]>
        empty?: Snippet<[]>
        groupHeader?: Snippet<[G, GroupState]>
        collapsedGroups?: GK[]
        /** Window the rows, for lists long enough to need it. Upstream #2650. */
        virtual?: boolean
        /**
         * Wraps the rendered rows. Lets a caller supply real table markup
         * (`<table><tbody>…`) or a card grid in place of the default list
         * without duplicating any of the loading, search, grouping or
         * pagination behaviour above. Receives the rows snippet and the loaded
         * items, so a header outside the row loop can still reflect them.
         * Ignored when `virtual` is set; see the note at the top.
         */
        container?: Snippet<[Snippet, T[]]>
        /**
         * Replaces the built-in search field. Receives the current value and a
         * setter, so a caller can render its own input without reaching into
         * the debounce pipeline.
         */
        searchInput?: Snippet<[string, (_: string) => void]>
    }

    let {
        page = $bindable(0),
        pageSize = undefined,
        load,
        showSearch = false,
        groupObject,
        groupKey,
        header,
        item,
        footer,
        empty,
        groupHeader,
        collapsedGroups = $bindable([]),
        virtual = false,
        container,
        searchInput,
    }: Props = $props()

    let filter = $state('')
    let loaded = $state(false)
    let list = $state.raw<T[] | null>(null)
    let total = $state(0)

    const page$ = new Subject<number>()
    const filter$ = new Subject<string>()

    const subscription = combineLatest([
        page$,
        filter$.pipe(
            tap(() => {
                loaded = false
            }),
            debounceTime(200),
        ),
    ])
        .pipe(
            distinctUntilChanged(),
            switchMap(([p, f]) => {
                page = p
                loaded = false
                return load({
                    search: f,
                    offset: p * (pageSize ?? 0),
                    limit: pageSize,
                })
            }),
        )
        .subscribe(response => {
            loaded = true
            list = response.items
            total = response.total
        })

    type Entry =
        | { kind: 'group'; group: G; key: GK; collapsed: boolean }
        | { kind: 'item'; item: T }

    const built = $derived(buildEntries(list ?? []))

    // Groups are detected by adjacency, so the caller is expected to hand us
    // items already sorted by group. Items of collapsed groups are left out.
    function buildEntries(items: T[]): { entries: Entry[]; keys: GK[] } {
        const getGroup = groupObject
        const getKey = groupKey
        const flat = (): { entries: Entry[]; keys: GK[] } => ({
            entries: items.map(_item => ({ kind: 'item', item: _item })),
            keys: [],
        })

        if (!getGroup || !getKey) {
            return flat()
        }

        // One group is not a grouping. A lone "Ungrouped" header above a
        // single card is hierarchy with nothing to organise: it draws the eye,
        // implies siblings that do not exist, and makes a sparse list read as
        // a broken one. `keys` is emptied too — that is what
        // GroupControls.available reads, so "collapse all" disappears with the
        // header rather than becoming a trap.
        //
        // The collapse state has to be ignored here as well. In the entry model
        // a collapsed group drops its items, so a persisted "collapsed" on the
        // only group would leave an empty list with its header suppressed and
        // nothing on screen to expand it.
        const distinct = new Set(items.map(_item => getKey(getGroup(_item))))
        if (distinct.size <= 1) {
            return flat()
        }

        // An active search expands everything, so that matches can't hide
        // inside a collapsed group - without touching the persisted state.
        const hidden = filter ? new Set<GK>() : new Set(collapsedGroups)
        const entries: Entry[] = []
        const keys: GK[] = []

        for (const _item of items) {
            const group = getGroup(_item)
            const key = getKey(group)
            if (!keys.length || keys.at(-1) !== key) {
                keys.push(key)
                entries.push({
                    kind: 'group',
                    group,
                    key,
                    collapsed: hidden.has(key),
                })
            }
            if (!hidden.has(key)) {
                entries.push({ kind: 'item', item: _item })
            }
        }

        return { entries, keys }
    }

    // Keys of groups that no longer exist are dropped on every write, so the
    // persisted set can't accumulate them as groups come and go.
    function toggleGroup(key: GK, present: GK[]) {
        const next = collapsedGroups.includes(key)
            ? collapsedGroups.filter(k => k !== key)
            : [...collapsedGroups, key]
        collapsedGroups = next.filter(k => present.includes(k))
    }

    onMount(() => {
        if (groupHeader && (!groupObject || !groupKey)) {
            throw new Error(
                'groupObject and groupKey must be provided when using groupHeader',
            )
        }
    })

    onDestroy(() => {
        subscription.unsubscribe()
        page$.complete()
        filter$.complete()
    })

    $effect(() => {
        page$.next(page)
    })
    $effect(() => {
        filter$.next(filter)
    })

    filter$.subscribe(() => {
        page = 0
    })
</script>

{#snippet row(entry: Entry)}
    {#if entry.kind === 'item'}
        {@render item?.(entry.item)}
    {:else if groupHeader}
        {@render groupHeader(entry.group, {
            collapsed: entry.collapsed,
            collapsible: !filter,
            toggle: () => toggleGroup(entry.key, built.keys),
        })}
    {/if}
{/snippet}

{#snippet rows()}
    {#each built.entries as _entry (_entry.kind === 'item' ? _entry.item : _entry.key)}
        {@render row(_entry)}
    {/each}
{/snippet}

{#if !list}
    <DelayedSpinner />
{:else}
    <div class="d-flex align-items-center mb-2" hidden={!loaded}>
        <!-- either filtering or not filtering and there are at least some items at all -->
        {#if showSearch && (filter || !!list.length)}
            {#if searchInput}
                {@render searchInput(filter, v => {
                    filter = v
                })}
            {:else}
                <Input
                    label="Search"
                    labelHidden
                    type="search"
                    size="compact"
                    placeholder="Search…"
                    class="item-list-search"
                    bind:value={filter}
                />
            {/if}
        {/if}
        {@render header?.(list, {
            available: built.keys.length > 0 && !filter,
            collapseAll: () => {
                collapsedGroups = built.keys
            },
            expandAll: () => {
                collapsedGroups = []
            },
        })}
    </div>

    {#if virtual}
        <VirtualList items={built.entries} {row} />
    {:else if container}
        {@render container(rows, list)}
    {:else}
        <div
            class="list-group list-group-flush mb-3"
            hidden={!built.entries.length}
        >
            {@render rows()}
        </div>
    {/if}
    {@render footer?.(list)}

    {#if loaded && !list.length}
        {#if filter}
            <EmptyState title="Nothing found" />
        {:else}
            {@render empty?.()}
        {/if}
    {/if}
{/if}

{#if pageSize && total > pageSize}
    <Pagination {total} bind:page {pageSize} />
{/if}

<style lang="scss">
    // ui/Input renders its own wrapper, so the flex-grow that used to sit on
    // the sveltestrap Input has to target that wrapper instead.
    :global(.item-list-search) {
        flex-grow: 1;
    }
</style>
