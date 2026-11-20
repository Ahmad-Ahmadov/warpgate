<script lang="ts" module>
    /** 16x16 outline icons, drawn as the shell's are (`shell/navItems.ts`). */
    export const RECORDING_ICONS = {
        play: 'M5 3.5v9l7.5-4.5z',
        log: 'M5.5 4h8M5.5 8h8M5.5 12h8M2.5 4h.01M2.5 8h.01M2.5 12h.01',
        download: 'M8 2.5v7.5M4.5 6.5 8 10l3.5-3.5M3 13.5h10',
    }
</script>

<script lang="ts">
    /**
     * A session's recording, at a glance and one click away: the session
     * list's Recording column, and the action beside a session's title.
     *
     *   watch       a link to the player: "Watch", or "Watch live" while the
     *               connection is still being recorded
     *   other       an API log to read or a traffic capture to download; no
     *               play action, as neither plays
     *   processing  finalized shortly after the connection closes
     *   expired     past the retention period
     *   none        nothing was recorded
     *
     * Inside a table row, the link keeps its keys and double-clicks to itself:
     * the row opens the session on Enter and on a double-click, and would
     * otherwise take both.
     */
    import { RecordingKind, RecordingState } from 'admin/lib/api'
    import {
        recordingHref,
        type SessionRecordingStatus,
    } from 'common/recordings'
    import StatusMarker from 'ui/StatusMarker.svelte'

    interface Props {
        status: SessionRecordingStatus
        /** The user session, for the player's way back. */
        session: string
        /** `compact` for a table row, `standard` beside a heading. */
        size?: 'compact' | 'standard'
        /** Whose session, for a screen reader telling one row's link from the next. */
        context?: string
        /** A traffic capture downloads at once, rather than opening its page. */
        download?: boolean
        /** "+2" for the session's other recordings; not on the session's own page. */
        showMore?: boolean
    }

    let {
        status,
        session,
        size = 'compact',
        context,
        download = false,
        showMore = true,
    }: Props = $props()

    const live = $derived(
        status.kind === 'watch' &&
            status.recording.state === RecordingState.Live,
    )

    // The capture's own endpoint, which checks the permission to view
    // recordings as every recording endpoint does.
    const captureUrl = $derived(
        download &&
            status.kind === 'other' &&
            status.recording.kind === RecordingKind.Traffic
            ? `/@warpgate/admin/api/recordings/${status.recording.id}/tcpdump`
            : undefined,
    )

    const verb = $derived.by(() => {
        if (status.kind === 'watch') {
            if (live) {
                return 'Watch live'
            }
            return size === 'compact' ? 'Watch' : 'Watch recording'
        }
        if (status.kind === 'other') {
            if (status.recording.kind === RecordingKind.Traffic) {
                return captureUrl ? 'Download' : 'Capture'
            }
            return 'View log'
        }
        return ''
    })

    const icon = $derived(
        status.kind === 'other'
            ? status.recording.kind === RecordingKind.Traffic
                ? RECORDING_ICONS.download
                : RECORDING_ICONS.log
            : RECORDING_ICONS.play,
    )

    const more = $derived(
        showMore && (status.kind === 'watch' || status.kind === 'other')
            ? status.more
            : 0,
    )
    const moreHint = $derived(
        `${more} more ${more === 1 ? 'recording' : 'recordings'} on the session's page`,
    )

    // Starts with the visible label, so a voice command naming the button
    // finds it, and goes on to say which session it is.
    const name = $derived(context ? `${verb}: ${context}` : verb)

    const hint = $derived(
        status.kind === 'watch'
            ? live
                ? 'Watch the recording as it is made'
                : 'Watch the recording'
            : captureUrl
              ? 'Download the traffic capture (pcap, for Wireshark)'
              : status.kind === 'other' &&
                  status.recording.kind === RecordingKind.Traffic
                ? 'Open the traffic capture'
                : 'Read the API log',
    )

    function keepToItself(event: Event) {
        event.stopPropagation()
    }
</script>

<span class="recording recording-{size}">
    {#if status.kind === 'watch' || status.kind === 'other'}
        <a
            class="action"
            class:action-primary={status.kind === 'watch'}
            href={captureUrl ?? recordingHref(status.recording.id, session)}
            download={captureUrl
                ? `recording-${status.recording.id}.pcap`
                : undefined}
            aria-label={name}
            title={hint}
            onkeydown={keepToItself}
            ondblclick={keepToItself}
        >
            {#if live}
                <span class="live-dot" aria-hidden="true"></span>
            {:else}
                <svg
                    viewBox="0 0 16 16"
                    width="12"
                    height="12"
                    aria-hidden="true"
                >
                    <path
                        d={icon}
                        fill={status.kind === 'watch' ? 'currentColor' : 'none'}
                        stroke="currentColor"
                        stroke-width="1.6"
                        stroke-linecap="round"
                        stroke-linejoin="round"
                    />
                </svg>
            {/if}
            <span>{verb}</span>
        </a>
        {#if more > 0}
            <span class="more" title={moreHint}>+{more}</span>
        {/if}
    {:else if status.kind === 'processing'}
        <StatusMarker kind="pending" bare label="Processing" />
    {:else if status.kind === 'expired'}
        <span
            title="Past the recording retention period; removed at the next cleanup"
        >
            <StatusMarker kind="ended" bare label="Expired" />
        </span>
    {:else}
        <span class="none">Not recorded</span>
    {/if}
</span>

<style>
    .recording {
        display: inline-flex;
        align-items: center;
        gap: var(--wg-space-sm);
        white-space: nowrap;
    }

    .action {
        display: inline-flex;
        align-items: center;
        gap: var(--wg-space-xs);
        height: var(--wg-control-height-compact);
        padding: 0 var(--wg-control-padding-x-compact);
        border: var(--wg-border-width) solid var(--wg-border-strong);
        border-radius: var(--wg-radius-control);
        background: var(--wg-surface-container);
        color: var(--wg-text);
        font: var(--wg-text-label-sm);
        text-decoration: none;
        transition:
            background var(--wg-duration-fast) var(--wg-easing),
            color var(--wg-duration-fast) var(--wg-easing);
    }

    .recording-standard .action {
        height: var(--wg-control-height);
        padding: 0 var(--wg-control-padding-x);
        font: var(--wg-text-label-md);
        gap: var(--wg-space-sm);
    }

    .action:hover {
        background: var(--wg-surface-container-high);
    }

    .action-primary {
        border-color: transparent;
        background: var(--wg-primary);
        color: var(--wg-on-primary);
        font-weight: 600;
    }

    .action-primary:hover {
        background: var(--wg-primary-container);
        color: var(--wg-on-primary-container);
    }

    .action:focus-visible {
        outline: var(--wg-focus-ring);
        outline-offset: var(--wg-focus-ring-offset);
    }

    /* The live marker's colour and pulse, on the button's own fill. */
    .live-dot {
        width: 7px;
        height: 7px;
        border-radius: var(--wg-radius-full);
        background: var(--wg-secondary);
        box-shadow: 0 0 0 2px var(--wg-on-primary);
        animation: live-pulse 1.6s var(--wg-easing) infinite;
    }

    @keyframes live-pulse {
        50% {
            opacity: 0.35;
        }
    }

    .more {
        color: var(--wg-text-subtle);
        font: var(--wg-text-code-sm);
        font-variant-numeric: tabular-nums;
    }

    .none {
        color: var(--wg-text-subtle);
        font: var(--wg-text-label-sm);
    }

    @media (prefers-reduced-motion: reduce) {
        .live-dot {
            animation: none;
        }

        .action {
            transition: none;
        }
    }
</style>
