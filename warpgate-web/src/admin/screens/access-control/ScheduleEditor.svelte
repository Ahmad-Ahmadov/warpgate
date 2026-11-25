<script lang="ts">
    /**
     * The weekly schedule of an access rule: which days and hours a connection
     * may start, what happens outside them, and in which timezone the hours are
     * meant. No cron: seven days, time ranges, and a picture of the week.
     *
     * A window that ends before it starts runs overnight (22:00–06:00 is the
     * evening of the chosen day and the morning after it). Where windows overlap
     * the most restrictive wins. Only the server decides; this draws what it will
     * be asked to enforce, and says it in words underneath.
     */
    import {
        AccessRuleAction,
        type AccessRules,
        type AccessRuleWeekday,
        type AccessRuleWindow,
    } from 'admin/lib/api'
    import {
        ACTION_LABELS,
        describeRules,
        isOvernight,
        MINUTES_PER_DAY,
        parseClock,
        timezoneNames,
        validateRules,
        WEEKDAY_ORDER,
        WEEKDAYS,
    } from 'common/accessRules'
    import Button from 'ui/Button.svelte'
    import Combobox from 'ui/Combobox.svelte'
    import Input from 'ui/Input.svelte'
    import SegmentedControl from 'ui/SegmentedControl.svelte'
    import Select from 'ui/Select.svelte'

    interface Props {
        rules: AccessRules
        /**
         * Offer each window its own action (allow, require approval or deny),
         * as an access policy does. Off, a window is simply "allowed", and the
         * time outside the windows is one choice.
         */
        perWindowActions?: boolean
        disabled?: boolean
    }

    let { rules = $bindable(), perWindowActions = false, disabled = false }: Props = $props()

    const zones = timezoneNames().map(name => ({ value: name, label: name }))
    const weekdays = [...WEEKDAY_ORDER]
    const WEEKEND = weekdays.slice(5)
    const WORKDAYS = weekdays.slice(0, 5)

    const outsideOptions = $derived(
        (perWindowActions
            ? [AccessRuleAction.Allow, AccessRuleAction.RequireApproval, AccessRuleAction.Deny]
            : [AccessRuleAction.RequireApproval, AccessRuleAction.Deny]
        ).map(action => ({ value: action, label: ACTION_LABELS[action] })),
    )

    const problem = $derived(validateRules(rules))
    const summary = $derived(describeRules(rules))

    // ---- editing ----
    function addWindow() {
        rules.windows.push({
            days: [...WORKDAYS],
            start: '09:00',
            end: '18:00',
            action: AccessRuleAction.Allow,
        })
    }

    function removeWindow(index: number) {
        rules.windows.splice(index, 1)
    }

    function duplicateWindow(index: number) {
        const window = rules.windows[index]
        if (window) {
            rules.windows.splice(index + 1, 0, { ...window, days: [...window.days] })
        }
    }

    function toggleDay(window: AccessRuleWindow, day: AccessRuleWeekday) {
        window.days = window.days.includes(day)
            ? window.days.filter(d => d !== day)
            : weekdays.filter(d => d === day || window.days.includes(d))
    }

    function setDays(window: AccessRuleWindow, days: AccessRuleWeekday[]) {
        window.days = [...days]
    }

    // ---- the picture of the week ----
    interface Segment {
        from: number
        to: number
        action: AccessRuleAction
    }

    const SEVERITY: Record<AccessRuleAction, number> = {
        [AccessRuleAction.Allow]: 0,
        [AccessRuleAction.RequireApproval]: 1,
        [AccessRuleAction.Deny]: 2,
    }

    /** What each day shows: the windows that touch it, the overnight ones included. */
    function segmentsFor(day: AccessRuleWeekday): Segment[] {
        const index = weekdays.indexOf(day)
        const previous = weekdays[(index + 6) % 7]
        const out: Segment[] = []
        for (const window of rules.windows) {
            const start = parseClock(window.start)
            const end = parseClock(window.end, true)
            if (start === undefined || end === undefined || start === end) {
                continue
            }
            if (start < end) {
                if (window.days.includes(day)) {
                    out.push({ from: start, to: end, action: window.action })
                }
            } else {
                if (window.days.includes(day)) {
                    out.push({ from: start, to: MINUTES_PER_DAY, action: window.action })
                }
                if (previous && window.days.includes(previous)) {
                    out.push({ from: 0, to: end, action: window.action })
                }
            }
        }
        // The most restrictive is drawn last, so it is the one on top.
        return out.sort((a, b) => SEVERITY[a.action] - SEVERITY[b.action])
    }

    const bars = $derived(
        WEEKDAYS.map(day => ({ day, segments: segmentsFor(day.value) })),
    )

    function readable(day: string, segments: Segment[]): string {
        if (!segments.length) {
            return `${day}: ${ACTION_LABELS[rules.outside].toLowerCase()} all day`
        }
        return `${day}: ${segments
            .map(
                s =>
                    `${ACTION_LABELS[s.action].toLowerCase()} ${format(s.from)}–${format(s.to)}`,
            )
            .join(', ')}; otherwise ${ACTION_LABELS[rules.outside].toLowerCase()}`
    }

    function format(minutes: number): string {
        const hours = Math.floor(minutes / 60)
        return `${String(hours).padStart(2, '0')}:${String(minutes % 60).padStart(2, '0')}`
    }

    function tone(action: AccessRuleAction): string {
        switch (action) {
            case AccessRuleAction.Allow:
                return 'allow'
            case AccessRuleAction.RequireApproval:
                return 'approval'
            default:
                return 'deny'
        }
    }
</script>

<div class="schedule">
    <div class="zone">
        <Combobox
            label="Timezone"
            bind:value={rules.timezone}
            options={zones}
            placeholder="Search timezones…"
            emptyText="No such timezone"
            clearable={false}
            {disabled}
            hint="The hours below are read in this timezone, daylight saving included. Times are stored in UTC."
        />
    </div>

    <fieldset class="week">
        <legend class="sr-only">Weekly schedule</legend>
        <div class="axis" aria-hidden="true">
            <span class="axis-day"></span>
            <span class="axis-scale">
                <span style="left: 0%">0</span>
                <span style="left: 25%">6</span>
                <span style="left: 50%">12</span>
                <span style="left: 75%">18</span>
                <span style="left: 100%">24</span>
            </span>
        </div>
        {#each bars as { day, segments } (day.value)}
            <div class="row">
                <span class="row-day">{day.short}</span>
                <span class="bar bar-{tone(rules.outside)}" aria-hidden="true">
                    {#each segments as segment, i (i)}
                        <span
                            class="segment segment-{tone(segment.action)}"
                            style="left: {(segment.from / MINUTES_PER_DAY) *
                                100}%; width: {((segment.to - segment.from) /
                                MINUTES_PER_DAY) *
                                100}%"
                        ></span>
                    {/each}
                </span>
                <span class="sr-only">{readable(day.long, segments)}</span>
            </div>
        {/each}
        <div class="legend" aria-hidden="true">
            <span><i class="swatch segment-allow"></i> Allowed</span>
            <span><i class="swatch segment-approval"></i> Needs approval</span>
            <span><i class="swatch segment-deny"></i> Denied</span>
        </div>
    </fieldset>

    <div class="windows">
        {#each rules.windows as window, index (index)}
            <div class="window" class:window-off={!window.days.length}>
                <fieldset class="window-days">
                    <legend class="sr-only">Days of window {index + 1}</legend>
                    {#each WEEKDAYS as day (day.value)}
                        <button
                            type="button"
                            class="day"
                            class:on={window.days.includes(day.value)}
                            aria-pressed={window.days.includes(day.value)}
                            aria-label={day.long}
                            {disabled}
                            onclick={() => toggleDay(window, day.value)}
                        >
                            {day.short}
                        </button>
                    {/each}
                    <span class="presets">
                        <button type="button" class="preset" {disabled} onclick={() => setDays(window, WORKDAYS)}>
                            Weekdays
                        </button>
                        <button type="button" class="preset" {disabled} onclick={() => setDays(window, WEEKEND)}>
                            Weekend
                        </button>
                        <button type="button" class="preset" {disabled} onclick={() => setDays(window, weekdays)}>
                            Every day
                        </button>
                    </span>
                </fieldset>
                <div class="window-times">
                    <Input
                        label="From"
                        type="time"
                        size="compact"
                        bind:value={window.start}
                        {disabled}
                    />
                    <Input
                        label="To"
                        type="time"
                        size="compact"
                        bind:value={window.end}
                        {disabled}
                    />
                    {#if perWindowActions}
                        <Select
                            label="Then"
                            size="compact"
                            bind:value={window.action}
                            {disabled}
                            options={[
                                { value: AccessRuleAction.Allow, label: ACTION_LABELS[AccessRuleAction.Allow] },
                                { value: AccessRuleAction.RequireApproval, label: ACTION_LABELS[AccessRuleAction.RequireApproval] },
                                { value: AccessRuleAction.Deny, label: ACTION_LABELS[AccessRuleAction.Deny] },
                            ]}
                        />
                    {/if}
                    <span class="window-actions">
                        <Button
                            variant="ghost"
                            size="compact"
                            icon="plus"
                            {disabled}
                            onclick={() => duplicateWindow(index)}
                            label="Duplicate window {index + 1}"
                        />
                        <Button
                            variant="ghost"
                            size="compact"
                            icon="trash"
                            {disabled}
                            onclick={() => removeWindow(index)}
                            label="Remove window {index + 1}"
                        />
                    </span>
                </div>
                {#if isOvernight(window)}
                    <p class="note">
                        Runs overnight: from {window.start} on each chosen day until
                        {window.end} the next morning.
                    </p>
                {/if}
            </div>
        {/each}
        <div>
            <Button size="compact" icon="plus" {disabled} onclick={addWindow}>
                Add time window
            </Button>
        </div>
    </div>

    <div class="outside">
        <SegmentedControl
            label={perWindowActions ? 'Outside every window' : 'Outside these hours'}
            size="compact"
            segments={outsideOptions}
            bind:value={rules.outside}
            {disabled}
        />
    </div>

    <p class="summary" aria-live="polite">{summary}</p>
    {#if problem}
        <p class="problem" role="alert">{problem}</p>
    {/if}
</div>

<style>
    .schedule {
        display: flex;
        flex-direction: column;
        gap: var(--wg-space-md);
    }

    .zone {
        max-width: 22rem;
    }

    fieldset {
        min-width: 0;
        margin: 0;
    }

    /* ---- the week ---- */
    .week {
        display: flex;
        flex-direction: column;
        gap: 3px;
        padding: var(--wg-space-sm) var(--wg-space-md);
        background: var(--wg-surface-container-low);
        border: var(--wg-border-width) solid var(--wg-border);
        border-radius: var(--wg-radius-panel);
    }

    .axis,
    .row {
        display: grid;
        grid-template-columns: 2.25rem 1fr;
        align-items: center;
        gap: var(--wg-space-sm);
    }

    .axis-scale {
        position: relative;
        height: 1rem;
        font: var(--wg-text-label-sm);
        color: var(--wg-text-subtle);
    }

    .axis-scale span {
        position: absolute;
        transform: translateX(-50%);
    }

    .axis-scale span:first-child {
        transform: none;
    }

    .axis-scale span:last-child {
        transform: translateX(-100%);
    }

    .row-day {
        font: var(--wg-text-label-sm);
        color: var(--wg-text-muted);
    }

    .bar {
        position: relative;
        display: block;
        height: 0.75rem;
        overflow: hidden;
        border-radius: 3px;
    }

    .bar-allow {
        background: var(--wg-tertiary-tint);
    }
    .bar-approval {
        background: var(--wg-secondary-tint);
    }
    .bar-deny {
        background: var(--wg-error-tint);
    }

    .segment {
        position: absolute;
        top: 0;
        bottom: 0;
    }

    .segment-allow {
        background: var(--wg-tertiary);
    }
    .segment-approval {
        background: var(--wg-secondary);
    }
    .segment-deny {
        background: var(--wg-error);
    }

    .legend {
        display: flex;
        flex-wrap: wrap;
        gap: var(--wg-space-md);
        margin-top: var(--wg-space-xs);
        font: var(--wg-text-label-sm);
        color: var(--wg-text-muted);
    }

    .swatch {
        display: inline-block;
        width: 0.65rem;
        height: 0.65rem;
        margin-right: 0.25rem;
        border-radius: 2px;
        vertical-align: -1px;
    }

    /* ---- the windows ---- */
    .windows {
        display: flex;
        flex-direction: column;
        gap: var(--wg-space-sm);
    }

    .window {
        display: flex;
        flex-direction: column;
        gap: var(--wg-space-sm);
        padding: var(--wg-space-sm) var(--wg-space-md);
        background: var(--wg-surface-container-low);
        border: var(--wg-border-width) solid var(--wg-border);
        border-radius: var(--wg-radius-panel);
        transition: border-color var(--wg-duration-fast) var(--wg-easing);
    }

    .window:hover {
        border-color: var(--wg-border-strong);
    }

    .window-off {
        border-color: var(--wg-error);
    }

    .window-days {
        display: flex;
        flex-wrap: wrap;
        align-items: center;
        gap: var(--wg-space-xs);
        padding: 0;
        border: 0;
    }

    .day {
        min-width: 2.5rem;
        height: var(--wg-control-height-compact);
        padding: 0 var(--wg-space-sm);
        border: var(--wg-border-width) solid var(--wg-border-strong);
        border-radius: var(--wg-radius-control);
        background: var(--wg-surface-container);
        color: var(--wg-text-muted);
        font: var(--wg-text-label-sm);
        cursor: pointer;
        transition:
            background var(--wg-duration-fast) var(--wg-easing),
            border-color var(--wg-duration-fast) var(--wg-easing),
            color var(--wg-duration-fast) var(--wg-easing);
    }

    .day:hover:not(:disabled) {
        border-color: var(--wg-outline);
        color: var(--wg-text);
    }

    .day.on {
        background: var(--wg-primary-tint-strong);
        border-color: var(--wg-primary);
        color: var(--wg-primary);
    }

    .day:focus-visible,
    .preset:focus-visible {
        outline: var(--wg-focus-ring);
        outline-offset: var(--wg-focus-ring-offset);
    }

    .day:disabled,
    .preset:disabled {
        opacity: 0.45;
        cursor: not-allowed;
    }

    .presets {
        display: inline-flex;
        gap: var(--wg-space-xs);
        margin-left: auto;
    }

    .preset {
        padding: 0 var(--wg-space-xs);
        border: 0;
        background: none;
        color: var(--wg-text-muted);
        font: var(--wg-text-label-sm);
        text-decoration: underline;
        text-underline-offset: 2px;
        cursor: pointer;
    }

    .preset:hover:not(:disabled) {
        color: var(--wg-primary);
    }

    .window-times {
        display: flex;
        flex-wrap: wrap;
        align-items: flex-end;
        gap: var(--wg-space-md);
    }

    .window-times :global(.wg-field) {
        width: 8.5rem;
    }

    .window-actions {
        display: inline-flex;
        margin-left: auto;
    }

    .note {
        margin: 0;
        font: var(--wg-text-label-sm);
        color: var(--wg-text-subtle);
    }

    .outside {
        display: flex;
        flex-wrap: wrap;
        align-items: center;
        gap: var(--wg-space-sm);
    }

    .summary {
        margin: 0;
        font: var(--wg-text-body-md);
        color: var(--wg-text-muted);
    }

    .problem {
        margin: 0;
        font: var(--wg-text-label-md);
        color: var(--wg-error);
    }

    .sr-only {
        position: absolute;
        width: 1px;
        height: 1px;
        padding: 0;
        margin: -1px;
        overflow: hidden;
        clip-path: inset(50%);
        white-space: nowrap;
        border: 0;
    }

    @media (prefers-reduced-motion: reduce) {
        .window,
        .day {
            transition: none;
        }
    }
</style>
