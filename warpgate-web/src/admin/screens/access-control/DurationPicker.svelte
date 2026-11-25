<script lang="ts">
    /**
     * A length of time for an approval setting, in seconds: a few presets the way
     * people say them (5 minutes, 1 hour), or a custom number of minutes. With
     * `unsetLabel`, "not set" is a choice too, and means the server's own default.
     */
    import {
        APPROVAL_PRESETS,
        formatSeconds,
        MAX_APPROVAL_SECONDS,
    } from 'common/accessRules'
    import Input from 'ui/Input.svelte'
    import Select from 'ui/Select.svelte'

    interface Props {
        /** Seconds; `undefined` when not set. */
        value?: number
        label: string
        hint?: string
        /** Offer "not set" under this name. */
        unsetLabel?: string
        disabled?: boolean
    }

    let {
        value = $bindable(),
        label,
        hint,
        unsetLabel,
        disabled = false,
    }: Props = $props()

    const CUSTOM = 'custom'

    function choiceOf(seconds: number | undefined): string {
        if (seconds === undefined) {
            return ''
        }
        return APPROVAL_PRESETS.some(preset => preset.seconds === seconds)
            ? String(seconds)
            : CUSTOM
    }

    // svelte-ignore state_referenced_locally
    let choice = $state(choiceOf(value))
    // svelte-ignore state_referenced_locally
    let customMinutes = $state(String(Math.max(1, Math.round((value ?? 900) / 60))))

    const options = $derived([
        ...(unsetLabel ? [{ value: '', label: unsetLabel }] : []),
        ...APPROVAL_PRESETS.map(preset => ({
            value: String(preset.seconds),
            label: preset.label,
        })),
        { value: CUSTOM, label: 'Custom…' },
    ])

    const customSeconds = $derived(Math.round(Number(customMinutes) * 60))
    const customInvalid = $derived(
        choice === CUSTOM &&
            !(
                Number.isFinite(customSeconds) &&
                customSeconds >= 60 &&
                customSeconds <= MAX_APPROVAL_SECONDS
            ),
    )

    // Reads the choice from the event: the bound `choice` may not be updated yet when this runs.
    function choose(event: Event) {
        choice = (event.target as HTMLSelectElement).value
        if (choice === '') {
            value = undefined
        } else if (choice === CUSTOM) {
            applyCustom()
        } else {
            value = Number(choice)
        }
    }

    function applyCustom() {
        if (!customInvalid) {
            value = customSeconds
        }
    }
</script>

<div class="picker">
    <Select
        {label}
        {options}
        bind:value={choice}
        onchange={choose}
        {disabled}
        {hint}
    />
    {#if choice === CUSTOM}
        <Input
            label="Minutes"
            type="number"
            min={1}
            max={Math.floor(MAX_APPROVAL_SECONDS / 60)}
            inputmode="numeric"
            bind:value={customMinutes}
            oninput={applyCustom}
            {disabled}
            invalid={customInvalid}
            error={customInvalid
                ? 'Between 1 minute and 30 days (43200 minutes).'
                : undefined}
            hint={!customInvalid && value ? formatSeconds(value) : undefined}
        />
    {/if}
</div>

<style>
    .picker {
        display: flex;
        flex-direction: column;
        gap: var(--wg-space-sm);
        min-width: 0;
    }
</style>
