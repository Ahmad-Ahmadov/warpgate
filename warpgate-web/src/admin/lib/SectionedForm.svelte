<script lang="ts">
    /**
     * A long form split into `Section`s, with links to each that follow the
     * section in view.
     *
     * The links take one of two shapes, chosen by the width this form gets
     * rather than the viewport's — a container query, because the sidebar
     * can be expanded or collapsed:
     *
     *   - **strip** (the target screen's 48rem column, laptops): a row of links
     *     that sticks under the app's top bar. When the links do not fit it
     *     scrolls sideways inside itself, never the page; the scrollbar is
     *     hidden, the edges fade to show there is more, and the current
     *     section is kept in view.
     *   - **list** (from 56rem, e.g. Parameters on a desktop): a vertical list
     *     beside the form, sticky under the top bar.
     *
     * Both stick at `--wg-topbar-height`, under the top bar. The top bar is
     * sticky at 0 as well, and the strip used to stick there too and paint
     * over it.
     *
     * `Section` takes its `scroll-margin-top` from
     * `--wg-section-scroll-offset`, which this component sets for each shape.
     * The scroll spy reads that same value back, so a section scrolled to is
     * the section highlighted.
     */
    import { onMount, type Snippet } from 'svelte'

    interface Props {
        class?: string
        children?: Snippet
    }

    const props: Props = $props()

    interface SectionEntry {
        id: string
        title: string
        element: HTMLElement
    }

    let sections: SectionEntry[] = $state.raw([])
    let activeSection = $state<string | null>(null)
    let contentElement: HTMLElement | null = $state(null)
    let listElement: HTMLElement | null = $state(null)
    let fadeStart = $state(false)
    let fadeEnd = $state(false)

    // A click scrolls smoothly past other sections. Until that scroll
    // settles, the clicked section stays the highlighted one.
    let pinned = false
    let pinTimer: ReturnType<typeof setTimeout> | undefined
    const PIN_SETTLE_MS = 200

    function pinUntilScrollSettles() {
        pinned = true
        clearTimeout(pinTimer)
        pinTimer = setTimeout(() => {
            pinned = false
        }, PIN_SETTLE_MS)
    }

    function prefersReducedMotion(): boolean {
        return (
            window.matchMedia?.('(prefers-reduced-motion: reduce)').matches ??
            false
        )
    }

    function updateActiveSection() {
        const first = sections[0]
        if (!first) {
            return
        }

        // Where a section's top comes to rest when scrolled to: just under the
        // top bar and, in the strip shape, the strip.
        const line =
            Number.parseFloat(
                getComputedStyle(first.element).scrollMarginTop,
            ) || 0

        let current = first
        for (const section of sections) {
            if (section.element.getBoundingClientRect().top - line > 4) {
                break
            }
            current = section
        }

        // The last sections can be too short to ever reach the line. Once the
        // page is scrolled to its end, the last of them is the current one.
        const scroller = document.scrollingElement ?? document.documentElement
        const atEnd =
            scroller.scrollTop > 0 &&
            scroller.scrollTop + window.innerHeight >= scroller.scrollHeight - 2
        if (atEnd) {
            current = sections[sections.length - 1] ?? current
        }

        activeSection = current.id
    }

    function updateFades() {
        const list = listElement
        if (!list) {
            return
        }
        const overflow = list.scrollWidth - list.clientWidth
        fadeStart = overflow > 1 && list.scrollLeft > 1
        fadeEnd = overflow > 1 && list.scrollLeft < overflow - 1
    }

    /** Scrolls the list itself (never the page) to show the current link. */
    function revealActiveLink() {
        const list = listElement
        const link = list?.querySelector<HTMLElement>(
            '[aria-current="location"]',
        )
        if (!list || !link) {
            return
        }
        // Clear of the faded edge.
        const margin = 32
        const behavior = prefersReducedMotion() ? 'auto' : 'smooth'

        if (list.scrollWidth > list.clientWidth) {
            const start = link.offsetLeft - margin
            const end =
                link.offsetLeft + link.offsetWidth + margin - list.clientWidth
            if (list.scrollLeft > start) {
                list.scrollTo({ left: start, behavior })
            } else if (list.scrollLeft < end) {
                list.scrollTo({ left: end, behavior })
            }
        }

        if (list.scrollHeight > list.clientHeight) {
            const start = link.offsetTop - margin
            const end =
                link.offsetTop + link.offsetHeight + margin - list.clientHeight
            if (list.scrollTop > start) {
                list.scrollTo({ top: start, behavior })
            } else if (list.scrollTop < end) {
                list.scrollTo({ top: end, behavior })
            }
        }
    }

    $effect(() => {
        if (activeSection) {
            revealActiveLink()
        }
    })

    onMount(() => {
        sections = Array.from(
            contentElement?.querySelectorAll<HTMLElement>('[data-section]') ??
                [],
        ).map(element => ({
            id: element.dataset.section ?? '',
            title: element.dataset.sectionTitle ?? '',
            element,
        }))
        activeSection = sections[0]?.id ?? null

        let frame = 0
        const schedule = () => {
            if (frame) {
                return
            }
            frame = requestAnimationFrame(() => {
                frame = 0
                if (!pinned) {
                    updateActiveSection()
                }
                updateFades()
            })
        }

        const onScroll = () => {
            if (pinned) {
                pinUntilScrollSettles()
                return
            }
            schedule()
        }

        window.addEventListener('scroll', onScroll, { passive: true })
        // Covers the window, the sidebar collapsing and the switch between
        // the strip and the list, none of which is a window resize alone.
        const resizeObserver = new ResizeObserver(schedule)
        if (contentElement) {
            resizeObserver.observe(contentElement)
        }
        if (listElement) {
            resizeObserver.observe(listElement)
        }

        schedule()

        return () => {
            window.removeEventListener('scroll', onScroll)
            resizeObserver.disconnect()
            cancelAnimationFrame(frame)
            clearTimeout(pinTimer)
        }
    })

    function scrollToSection(sectionId: string) {
        const section = sections.find(s => s.id === sectionId)
        if (!section) {
            return
        }
        activeSection = sectionId
        pinUntilScrollSettles()
        section.element.scrollIntoView({
            behavior: prefersReducedMotion() ? 'auto' : 'smooth',
            block: 'start',
        })
    }
</script>

<div class="sectioned-form {props.class ?? ''}">
    <div class="sectioned-form-layout">
        <nav
            class="sectioned-form-nav"
            aria-label="Sections"
            hidden={sections.length === 0}
        >
            <div
                class="section-tabs"
                class:fade-start={fadeStart}
                class:fade-end={fadeEnd}
                bind:this={listElement}
                onscroll={updateFades}
            >
                {#each sections as section (section.id)}
                    <a
                        href={`#${section.id}-heading`}
                        class="section-tab"
                        class:active={activeSection === section.id}
                        aria-current={activeSection === section.id
                            ? 'location'
                            : undefined}
                        onclick={event => {
                            // The app routes on the hash, so the link must
                            // not reach the address bar.
                            event.preventDefault()
                            scrollToSection(section.id)
                        }}
                    >
                        {section.title}
                    </a>
                {/each}
            </div>
        </nav>

        <div class="sectioned-form-content" bind:this={contentElement}>
            {@render props.children?.()}
        </div>
    </div>
</div>

<style>
    .sectioned-form {
        container: sectioned-form / inline-size;
    }

    /* ── strip: the default, for narrow forms ─────────────────────────── */

    .sectioned-form-layout {
        /* The strip: a compact link plus the list's padding and the rule. */
        --sectioned-form-strip-height: calc(
            var(--wg-control-height-compact) +
            2 *
            var(--wg-space-sm) +
            var(--wg-border-width)
        );
        /* Read by Section's scroll-margin-top and by the scroll spy. */
        --wg-section-scroll-offset: calc(
            var(--wg-topbar-height) +
            var(--sectioned-form-strip-height) +
            var(--wg-space-lg)
        );

        display: grid;
        grid-template-columns: minmax(0, 1fr);
        grid-template-areas:
            "nav"
            "content";
    }

    .sectioned-form-nav {
        grid-area: nav;
        position: sticky;
        top: var(--wg-topbar-height);
        /* Below the top bar (10) where the two meet, above the form. */
        z-index: 9;
        margin-bottom: var(--wg-space-xl);
        background: var(--wg-surface);
        border-bottom: var(--wg-border-width) solid var(--wg-border);
    }

    .sectioned-form-nav[hidden] {
        display: none;
    }

    .section-tabs {
        /* The offset parent revealActiveLink measures links against. */
        position: relative;
        display: flex;
        gap: var(--wg-space-sm);
        /* Inline padding only so the first and last links' focus rings are
           not clipped by the scroll box. */
        padding: var(--wg-space-sm) var(--wg-space-xs);
        overflow-x: auto;
        overflow-y: hidden;
        overscroll-behavior-x: contain;
        scrollbar-width: none;
    }

    .section-tabs::-webkit-scrollbar {
        display: none;
    }

    /* Links scrolled out of view, on either side, fade into the edge. */
    .section-tabs.fade-start {
        mask-image: linear-gradient(
            to right,
            transparent,
            #000 var(--wg-space-2xl)
        );
    }

    .section-tabs.fade-end {
        mask-image: linear-gradient(
            to left,
            transparent,
            #000 var(--wg-space-2xl)
        );
    }

    .section-tabs.fade-start.fade-end {
        mask-image: linear-gradient(
            to right,
            transparent,
            #000 var(--wg-space-2xl),
            #000 calc(100% - var(--wg-space-2xl)),
            transparent
        );
    }

    .section-tab {
        flex: none;
        display: inline-flex;
        align-items: center;
        height: var(--wg-control-height-compact);
        padding: 0 var(--wg-control-padding-x-compact);
        border-radius: var(--wg-radius-control);
        color: var(--wg-text-muted);
        text-decoration: none;
        font: var(--wg-text-label-md);
        white-space: nowrap;
    }

    .section-tab:hover {
        background: var(--wg-surface-container-high);
        color: var(--wg-text);
    }

    .section-tab.active {
        background: var(--wg-surface-container-highest);
        color: var(--wg-text);
        box-shadow: inset 2px 0 0 var(--wg-primary);
    }

    .section-tab:focus-visible {
        outline: var(--wg-focus-ring);
        outline-offset: var(--wg-focus-ring-offset);
    }

    .sectioned-form-content {
        grid-area: content;
        min-width: 0;
    }

    /* ── list: beside the form, once there is room for both ────────────── */

    /* 12rem of list, the 2rem gap, and at least 42rem of form. */
    @container sectioned-form (min-width: 56rem) {
        .sectioned-form-layout {
            --wg-section-scroll-offset: calc(
                var(--wg-topbar-height) +
                var(--wg-space-xl)
            );

            grid-template-columns: 12rem minmax(0, 48rem);
            grid-template-areas: "nav content";
            column-gap: var(--wg-space-2xl);
            align-items: start;
        }

        .sectioned-form-nav {
            top: calc(var(--wg-topbar-height) + var(--wg-space-xl));
            margin-bottom: 0;
            background: none;
            border-bottom: 0;
        }

        .section-tabs {
            flex-direction: column;
            gap: var(--wg-space-xs);
            /* A long form on a short window scrolls its list, not past it. */
            max-height: calc(
                100vh -
                var(--wg-topbar-height) -
                2 *
                var(--wg-space-xl)
            );
            padding: var(--wg-space-xs);
            overflow-x: hidden;
            overflow-y: auto;
        }

        .section-tabs,
        .section-tabs.fade-start,
        .section-tabs.fade-end {
            mask-image: none;
        }

        .section-tab {
            height: auto;
            min-height: var(--wg-control-height-compact);
            padding-block: var(--wg-space-xs);
            white-space: normal;
        }
    }
</style>
