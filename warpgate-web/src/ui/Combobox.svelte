<script lang="ts" module>
    export interface ComboboxOption {
        value: string
        label: string
        /** A second, quieter line: a full name, a type. Searched too. */
        description?: string
        /** A short trailing mark, such as "AD". */
        tag?: string
        /** Text that is searched but not shown. */
        keywords?: string
        disabled?: boolean
    }
</script>

<script lang="ts">
    /**
     * A select you can type into: the list narrows as you type, so a long list
     * (every user of a directory, say) stays usable. One field, not a search
     * box above a dropdown.
     *
     * Keyboard: type to filter, ↑/↓ move, Enter chooses, Escape closes (and
     * does not close the dialog it sits in), Tab leaves. Only the first
     * `MAX_SHOWN` matches are drawn, so a list of thousands stays quick; the
     * field says so and asks for more typing instead of paging.
     *
     * The list is positioned under the field inside its own container rather
     * than in a floating layer, so it works inside a scrolling dialog: the
     * dialog scrolls to reveal it instead of the list being clipped.
     */
    import { tick } from 'svelte'
    import Icon from './Icon.svelte'
    import Spinner from './Spinner.svelte'

    interface Props {
        /** The chosen option's `value`; empty when none is. */
        value?: string
        options: ComboboxOption[]
        label?: string
        placeholder?: string
        /** Shown when nothing matches what was typed. */
        emptyText?: string
        /** The options are still being fetched. */
        loading?: boolean
        /** They could not be fetched. */
        loadError?: string
        disabled?: boolean
        required?: boolean
        invalid?: boolean
        error?: string
        hint?: string
        /** Show a button that clears the choice. */
        clearable?: boolean
        id?: string
        class?: string
        onchange?: (value: string) => void
    }

    let {
        value = $bindable(''),
        options,
        label,
        placeholder = 'Search…',
        emptyText = 'Nothing matches',
        loading = false,
        loadError,
        disabled = false,
        required = false,
        invalid = false,
        error,
        hint,
        clearable = true,
        id = `wg-combobox-${Math.random().toString(36).slice(2, 9)}`,
        class: className = '',
        onchange,
    }: Props = $props()

    const MAX_SHOWN = 100

    let open = $state(false)
    let query = $state('')
    let active = $state(0)
    let input: HTMLInputElement | undefined = $state()
    let list: HTMLElement | undefined = $state()

    const isInvalid = $derived(invalid || !!error)
    const selected = $derived(options.find(option => option.value === value))
    const matches = $derived.by(() => {
        const words = query.trim().toLowerCase().split(/\s+/).filter(Boolean)
        if (!words.length) {
            return options
        }
        return options.filter(option => {
            const haystack =
                `${option.label} ${option.description ?? ''} ${option.keywords ?? ''}`.toLowerCase()
            return words.every(word => haystack.includes(word))
        })
    })
    const shown = $derived(matches.slice(0, MAX_SHOWN))
    const describedBy = $derived(
        [error ? `${id}-error` : null, hint ? `${id}-hint` : null]
            .filter(Boolean)
            .join(' ') || undefined,
    )

    function firstEnabled(from = 0, step = 1): number {
        for (let i = 0; i < shown.length; i++) {
            const index = (from + i * step + shown.length * 2) % shown.length
            if (!shown[index]?.disabled) {
                return index
            }
        }
        return 0
    }

    function openList() {
        if (disabled || open) {
            return
        }
        open = true
        query = ''
        const current = shown.findIndex(option => option.value === value)
        active = current >= 0 ? current : firstEnabled()
        tick().then(() => {
            input?.select()
            list?.scrollIntoView({ block: 'nearest' })
        })
    }

    function close() {
        open = false
        query = ''
    }

    function choose(option: ComboboxOption) {
        if (option.disabled) {
            return
        }
        value = option.value
        onchange?.(option.value)
        close()
        input?.focus()
    }

    function clear() {
        value = ''
        onchange?.('')
        close()
        input?.focus()
    }

    function move(step: number) {
        if (!shown.length) {
            return
        }
        let index = active
        for (let i = 0; i < shown.length; i++) {
            index = (index + step + shown.length) % shown.length
            if (!shown[index]?.disabled) {
                active = index
                break
            }
        }
        tick().then(() =>
            list
                ?.querySelector('[data-active="true"]')
                ?.scrollIntoView({ block: 'nearest' }),
        )
    }

    function onkeydown(event: KeyboardEvent) {
        if (disabled) {
            return
        }
        switch (event.key) {
            case 'ArrowDown':
                event.preventDefault()
                if (open) {
                    move(1)
                } else {
                    openList()
                }
                break
            case 'ArrowUp':
                event.preventDefault()
                if (open) {
                    move(-1)
                } else {
                    openList()
                }
                break
            case 'Enter': {
                if (open) {
                    event.preventDefault()
                    const option = shown[active]
                    if (option) {
                        choose(option)
                    }
                }
                break
            }
            case 'Escape':
                if (open) {
                    // closes the list, not the dialog around it
                    event.preventDefault()
                    event.stopPropagation()
                    close()
                }
                break
            case 'Tab':
                close()
                break
        }
    }

    function oninput(event: Event) {
        query = (event.currentTarget as HTMLInputElement).value
        if (!open) {
            open = true
        }
        active = firstEnabled()
    }

    function onfocusout(event: FocusEvent) {
        const next = event.relatedTarget as Node | null
        if (!next || !(event.currentTarget as HTMLElement).contains(next)) {
            close()
        }
    }
</script>

<div class="wg-field {className}">
    {#if label}
        <label for={id}>
            {label}
            {#if required}
                <span class="wg-required" aria-hidden="true">*</span>
            {/if}
        </label>
    {/if}

    <div class="shell" {onfocusout}>
        <div
            class="control"
            class:invalid={isInvalid}
            class:disabled
            class:open
        >
            <input
                {id}
                bind:this={input}
                type="text"
                role="combobox"
                aria-expanded={open}
                aria-controls="{id}-list"
                aria-autocomplete="list"
                aria-activedescendant={open && shown[active]
                    ? `${id}-opt-${active}`
                    : undefined}
                aria-invalid={isInvalid || undefined}
                aria-describedby={describedBy}
                autocomplete="off"
                spellcheck="false"
                {disabled}
                placeholder={selected ? '' : placeholder}
                value={open ? query : (selected?.label ?? '')}
                {oninput}
                onfocus={openList}
                onclick={openList}
                {onkeydown}
            />
            {#if clearable && value && !disabled}
                <button
                    type="button"
                    class="clear"
                    aria-label="Clear selection"
                    onclick={clear}
                >
                    <Icon name="close" size={12} />
                </button>
            {/if}
            <svg
                class="arrow"
                viewBox="0 0 12 12"
                width="12"
                height="12"
                aria-hidden="true"
            >
                <path
                    d="M3 4.5L6 8l3-3.5"
                    fill="none"
                    stroke="currentColor"
                    stroke-width="1.5"
                    stroke-linecap="round"
                    stroke-linejoin="round"
                />
            </svg>
        </div>

        {#if open}
            <div
                class="panel"
                id="{id}-list"
                role="listbox"
                aria-label={label}
                bind:this={list}
            >
                {#if loading}
                    <div class="note" role="status">
                        <Spinner size={14} /> Loading…
                    </div>
                {:else if loadError}
                    <div class="note error" role="alert">{loadError}</div>
                {:else if !shown.length}
                    <div class="note">{emptyText}</div>
                {:else}
                    {#each shown as option, index (option.value)}
                        <div
                            role="option"
                            tabindex="-1"
                            id="{id}-opt-{index}"
                            class="option"
                            class:active={index === active}
                            class:disabled={option.disabled}
                            data-active={index === active}
                            aria-selected={option.value === value}
                            aria-disabled={option.disabled || undefined}
                            onmousedown={event => event.preventDefault()}
                            onmousemove={() => {
                                if (!option.disabled) {
                                    active = index
                                }
                            }}
                            onclick={() => choose(option)}
                            onkeydown={event => {
                                if (event.key === 'Enter' || event.key === ' ') {
                                    event.preventDefault()
                                    choose(option)
                                }
                            }}
                        >
                            <span class="text">
                                <span class="name">{option.label}</span>
                                {#if option.description}
                                    <span class="desc">{option.description}</span>
                                {/if}
                            </span>
                            {#if option.tag}
                                <span class="tag">{option.tag}</span>
                            {/if}
                            {#if option.value === value}
                                <Icon name="check" size={14} />
                            {/if}
                        </div>
                    {/each}
                    {#if matches.length > shown.length}
                        <div class="note">
                            Showing the first {MAX_SHOWN} of {matches.length}. Keep
                            typing to narrow it down.
                        </div>
                    {/if}
                {/if}
            </div>
        {/if}
    </div>

    {#if error}
        <p class="wg-field-error" id="{id}-error">{error}</p>
    {:else if hint}
        <p class="wg-field-hint" id="{id}-hint">{hint}</p>
    {/if}
</div>

<style>
    .wg-field {
        display: flex;
        flex-direction: column;
        gap: var(--wg-space-xs);
        min-width: 0;
    }

    label {
        font: var(--wg-text-body-md);
        color: var(--wg-text-muted);
    }

    .wg-required {
        color: var(--wg-error);
    }

    .shell {
        position: relative;
    }

    .control {
        display: flex;
        align-items: center;
        gap: var(--wg-space-xs);
        height: var(--wg-control-height);
        padding-right: var(--wg-space-sm);
        background: var(--wg-surface-sunken);
        border: var(--wg-border-width) solid var(--wg-border-strong);
        border-radius: var(--wg-radius-control);
        transition:
            border-color var(--wg-duration-fast) var(--wg-easing),
            box-shadow var(--wg-duration-fast) var(--wg-easing);
    }

    .control:hover:not(.open):not(.invalid):not(.disabled) {
        border-color: var(--wg-outline);
    }

    .control:focus-within {
        border-color: var(--wg-primary);
        box-shadow: 0 0 0 3px var(--wg-primary-tint);
    }

    .control.invalid {
        border-color: var(--wg-error);
    }

    .control.disabled {
        opacity: 0.45;
    }

    input {
        flex: 1 1 auto;
        min-width: 0;
        height: 100%;
        padding: 0 var(--wg-space-sm);
        border: 0;
        background: none;
        color: var(--wg-text);
        font: var(--wg-text-body-md);
    }

    input:focus {
        outline: none;
    }

    input:disabled {
        cursor: not-allowed;
    }

    input::placeholder {
        color: var(--wg-text-subtle);
    }

    .clear {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        flex: none;
        width: 1.25rem;
        height: 1.25rem;
        padding: 0;
        border: 0;
        border-radius: var(--wg-radius-control);
        background: none;
        color: var(--wg-text-muted);
        cursor: pointer;
        transition:
            background var(--wg-duration-fast) var(--wg-easing),
            color var(--wg-duration-fast) var(--wg-easing);
    }

    .clear:hover {
        background: var(--wg-surface-container-high);
        color: var(--wg-text);
    }

    .clear:focus-visible {
        outline: var(--wg-focus-ring);
        outline-offset: 1px;
    }

    .arrow {
        flex: none;
        color: var(--wg-text-muted);
        pointer-events: none;
        transition: transform var(--wg-duration-fast) var(--wg-easing);
    }

    .control.open .arrow {
        transform: rotate(180deg);
    }

    .panel {
        position: absolute;
        z-index: 5;
        top: calc(100% + 4px);
        left: 0;
        right: 0;
        max-height: 14rem;
        overflow-y: auto;
        padding: var(--wg-space-xs);
        background: var(--wg-surface-container-high);
        border: var(--wg-border-width) solid var(--wg-border-strong);
        border-radius: var(--wg-radius-control);
        box-shadow: var(--wg-shadow-overlay);
    }

    .option {
        display: flex;
        align-items: center;
        gap: var(--wg-space-sm);
        padding: var(--wg-space-xs) var(--wg-space-sm);
        border-radius: var(--wg-radius-control);
        color: var(--wg-text);
        font: var(--wg-text-body-md);
        cursor: pointer;
        transition: background var(--wg-duration-fast) var(--wg-easing);
    }

    .option.active {
        background: var(--wg-primary-tint);
    }

    .option.disabled {
        opacity: 0.45;
        cursor: not-allowed;
    }

    .text {
        display: flex;
        flex-direction: column;
        flex: 1 1 auto;
        min-width: 0;
    }

    .name {
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
    }

    .option[aria-selected='true'] .name {
        color: var(--wg-primary);
    }

    .desc {
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
        color: var(--wg-text-subtle);
        font: var(--wg-text-label-sm);
    }

    .tag {
        flex: none;
        padding: 0 var(--wg-space-xs);
        border: var(--wg-border-width) solid var(--wg-info);
        border-radius: var(--wg-radius-badge);
        background: var(--wg-info-tint);
        color: var(--wg-info);
        font: var(--wg-text-label-sm);
    }

    .note {
        display: flex;
        align-items: center;
        gap: var(--wg-space-sm);
        padding: var(--wg-space-sm);
        color: var(--wg-text-muted);
        font: var(--wg-text-body-md);
    }

    .note.error {
        color: var(--wg-error);
    }

    .wg-field-error,
    .wg-field-hint {
        margin: 0;
        font: var(--wg-text-label-sm);
    }

    .wg-field-error {
        color: var(--wg-error);
    }

    .wg-field-hint {
        color: var(--wg-text-subtle);
    }

    @media (prefers-reduced-motion: reduce) {
        .control,
        .arrow,
        .clear,
        .option {
            transition: none;
        }
    }
</style>
