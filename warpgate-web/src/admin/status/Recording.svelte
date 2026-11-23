<script lang="ts">
    /**
     * A recording, in the viewer for its kind: a terminal session or a desktop
     * plays back (live, while it is still being made), a Kubernetes API session
     * reads as a log, and a forwarded connection's traffic downloads as a
     * packet capture.
     *
     * Before any of that, the page asks for the recording's first byte. A file
     * that is gone (removed with its session once the retention period passed,
     * or deleted from storage) answers 404, and the players cannot say so:
     * they wait for data forever. The page says what happened instead. The
     * request goes through the same permission check as the players' own.
     *
     * `?session=<id>`, which the session screens add to their links, names the
     * user session the recording belongs to: the way back, and the session's
     * own account of the recording (its state, its target, its protocol). An
     * administrator who may view recordings but not sessions gets the way
     * back to the list, and the recording without that account.
     */
    import {
        api,
        type Recording,
        RecordingKind,
        RecordingState,
        type UserSessionSnapshot,
    } from 'admin/lib/api'
    import DesktopRecordingPlayer from 'admin/player/DesktopRecordingPlayer.svelte'
    import TerminalRecordingPlayer from 'admin/player/TerminalRecordingPlayer.svelte'
    import DelayedSpinner from 'common/DelayedSpinner.svelte'
    import { stringifyError } from 'common/errors'
    import {
        parseRecordingMetadata,
        RECORDING_KIND_ICONS,
        RECORDING_STATE_MARKERS,
        recordingDuration,
        recordingMetadataToFieldSet,
        recordingTitle,
    } from 'common/recordings'
    import { router } from 'svelte-spa-router'
    import Callout from 'ui/Callout.svelte'
    import RelativeDate from 'ui/RelativeDate.svelte'
    import StatusMarker from 'ui/StatusMarker.svelte'
    import { adminPermissions } from '../lib/store'
    import KubernetesRecording from './KubernetesRecording.svelte'

    interface Props {
        params: { id: string }
    }

    let { params = { id: '' } }: Props = $props()

    /** What the first byte said about the recording's file. */
    type Availability =
        | 'checking'
        | 'ready'
        | 'missing'
        | 'empty'
        | 'denied'
        | 'failed'

    let error: string | null = $state(null)
    // Typed through `$state<…>` rather than an annotation: an annotated `let`
    // initialised to null narrows to `null` for TypeScript, which never sees
    // the assignments made in `load()` and its callbacks, so `session?.…` in
    // the `$derived`s below would be typed `never`.
    let recording = $state<Recording | null>(null)
    let session = $state<UserSessionSnapshot | null>(null)
    let availability: Availability = $state('checking')
    let failure = $state('')

    const sessionId =
        new URLSearchParams(router.querystring ?? '').get('session') ??
        undefined
    const backHref = sessionId
        ? `#/status/sessions/${encodeURIComponent(sessionId)}`
        : '#/status/sessions'

    function fileUrl(r: Recording): string {
        const file = r.kind === RecordingKind.Traffic ? 'tcpdump' : 'data'
        return `/@warpgate/admin/api/recordings/${r.id}/${file}`
    }

    async function checkAvailability(r: Recording): Promise<Availability> {
        let response: Response
        try {
            response = await fetch(fileUrl(r), {
                headers: { Range: 'bytes=0-0' },
            })
        } catch (e) {
            failure = e instanceof Error ? e.message : String(e)
            return 'failed'
        }
        // Only the status matters: whatever came with it is left unread.
        response.body?.cancel().catch(() => {})
        if (response.ok) {
            return 'ready'
        }
        switch (response.status) {
            case 404:
                return 'missing'
            case 401:
            case 403:
                return 'denied'
            case 416:
                // Nothing in the file: a recording still being made has
                // nothing yet, and plays as it comes; a finished one never
                // got anything.
                return r.ended ? 'empty' : 'ready'
        }
        failure = `${response.status} ${response.statusText}`.trim()
        return 'failed'
    }

    async function load() {
        if (!$adminPermissions.recordingsView) {
            error = 'You do not have permission to view recordings.'
            return
        }
        const loaded = await api.getRecording(params)
        recording = loaded
        if (sessionId && $adminPermissions.sessionsView) {
            api.getSession({ id: sessionId })
                .then(s => {
                    session = s
                })
                .catch(() => {
                    // The recording plays without its session's account.
                })
        }
        availability = await checkAvailability(loaded)
    }

    load().catch(async e => {
        error = await stringifyError(e)
    })

    // The session's account of this recording, when the page has it.
    const snapshot = $derived(
        session?.recordings.find(r => r.id === recording?.id),
    )
    const connection = $derived(
        session?.targetSessions.find(t => t.id === recording?.sessionId),
    )
    const fields = $derived.by(() => {
        const metadata = recording ? parseRecordingMetadata(recording) : null
        return metadata ? recordingMetadataToFieldSet(metadata) : []
    })
</script>

<div class="head">
    <a class="back" href={backHref}>
        <svg viewBox="0 0 16 16" width="12" height="12" aria-hidden="true">
            <path
                d="M10 3.5 5.5 8l4.5 4.5"
                fill="none"
                stroke="currentColor"
                stroke-width="1.6"
                stroke-linecap="round"
                stroke-linejoin="round"
            />
        </svg>
        {sessionId ? 'Back to session' : 'Sessions'}
    </a>

    {#if recording}
        <div class="head-title">
            <span class="head-icon" aria-hidden="true">
                <svg
                    viewBox="0 0 16 16"
                    width="18"
                    height="18"
                    aria-hidden="true"
                >
                    <path
                        d={RECORDING_KIND_ICONS[recording.kind]}
                        fill="none"
                        stroke="currentColor"
                        stroke-width="1.3"
                        stroke-linecap="round"
                        stroke-linejoin="round"
                    />
                </svg>
            </span>
            <h1>{recordingTitle(recording, session?.protocol)}</h1>
            {#if snapshot}
                {@const marker = RECORDING_STATE_MARKERS[snapshot.state]}
                <StatusMarker kind={marker.kind} label={marker.label} />
            {/if}
        </div>

        <p class="head-meta">
            {#if session?.username}
                <span>{session.username}</span>
            {/if}
            {#if connection?.target}
                <span>
                    on <span class="wg-mono">{connection.target.name}</span>
                </span>
            {/if}
            <span>started <RelativeDate date={recording.started} /></span>
            <span>
                {#if snapshot?.state === RecordingState.Live}
                    recording now
                {:else}
                    {recordingDuration(recording, connection?.ended)}
                    long
                {/if}
            </span>
            {#each fields as [label, value] (label)}
                <span>{label} <span class="wg-mono">{value}</span></span>
            {/each}
        </p>
    {:else}
        <h1>Recording</h1>
    {/if}
</div>

{#if error}
    <Callout tone="danger" title="Could not open this recording">
        {error}
    </Callout>
{:else if !recording || availability === 'checking'}
    <DelayedSpinner />
{:else if availability === 'missing'}
    <Callout tone="warning" title="This recording is no longer available">
        Its file is gone. Recordings are removed with their session once the
        recording retention period has passed, and a file can also have been
        removed from storage.
    </Callout>
{:else if availability === 'empty'}
    <Callout title="Nothing was recorded">
        The connection ended before anything was captured.
    </Callout>
{:else if availability === 'denied'}
    <Callout tone="danger" title="No access to this recording">
        You do not have permission to view recordings.
    </Callout>
{:else if availability === 'failed'}
    <Callout tone="danger" title="Could not load this recording">
        {failure || 'The server did not answer.'}
    </Callout>
{:else}
    {#if snapshot?.state === RecordingState.Processing}
        <div class="notice">
            <Callout title="Still being finalized">
                The connection has just closed and this recording is being
                written out. What has been saved so far plays now; reload in a
                moment for the rest.
            </Callout>
        </div>
    {:else if snapshot?.state === RecordingState.Expired}
        <div class="notice">
            <Callout tone="warning" title="Past the retention period">
                This recording is removed with its session at the next cleanup.
            </Callout>
        </div>
    {/if}

    {#if recording.kind === RecordingKind.Traffic}
        <div class="capture">
            <p>
                The traffic of a forwarded connection, as a packet capture. Open
                it in Wireshark or tcpdump.
            </p>
            <a
                class="download"
                href={fileUrl(recording)}
                download="recording-{recording.id}.pcap"
            >
                <svg
                    viewBox="0 0 16 16"
                    width="13"
                    height="13"
                    aria-hidden="true"
                >
                    <path
                        d="M8 2.5v7.5M4.5 6.5 8 10l3.5-3.5M3 13.5h10"
                        fill="none"
                        stroke="currentColor"
                        stroke-width="1.6"
                        stroke-linecap="round"
                        stroke-linejoin="round"
                    />
                </svg>
                Download capture
            </a>
        </div>
    {:else if recording.kind === RecordingKind.Terminal}
        <TerminalRecordingPlayer {recording} />
    {:else if recording.kind === RecordingKind.Desktop}
        <DesktopRecordingPlayer {recording} />
    {:else if recording.kind === RecordingKind.Kubernetes}
        <KubernetesRecording {recording} />
    {/if}
{/if}

<style>
    .head {
        display: flex;
        flex-direction: column;
        gap: var(--wg-space-xs);
        margin-bottom: var(--wg-space-lg);
    }

    .back {
        display: inline-flex;
        align-items: center;
        gap: var(--wg-space-xs);
        align-self: flex-start;
        margin-bottom: var(--wg-space-sm);
        border-radius: var(--wg-radius-sm);
        color: var(--wg-text-muted);
        font: var(--wg-text-label-md);
        text-decoration: none;
    }

    .back:hover {
        color: var(--wg-text);
        text-decoration: underline;
    }

    .back:focus-visible {
        outline: var(--wg-focus-ring);
        outline-offset: var(--wg-focus-ring-offset);
    }

    .head-title {
        display: flex;
        align-items: center;
        flex-wrap: wrap;
        gap: var(--wg-space-md);
    }

    .head-icon {
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
    }

    h1 {
        margin: 0;
        font: var(--wg-text-headline-lg);
    }

    /* Each fact its own item, separated by a middle dot. */
    .head-meta {
        display: flex;
        flex-wrap: wrap;
        gap: 0 var(--wg-space-sm);
        margin: 0;
        color: var(--wg-text-muted);
        font: var(--wg-text-body-md);
    }

    .head-meta > span + span::before {
        content: "·";
        margin-right: var(--wg-space-sm);
        color: var(--wg-text-subtle);
    }

    .notice {
        margin-bottom: var(--wg-space-lg);
    }

    .capture {
        display: flex;
        flex-direction: column;
        align-items: flex-start;
        gap: var(--wg-space-md);
        padding: var(--wg-space-lg);
        border: var(--wg-border-width) solid var(--wg-border);
        border-radius: var(--wg-radius-panel);
        background: var(--wg-surface-container);
    }

    .capture p {
        margin: 0;
        color: var(--wg-text-muted);
    }

    .download {
        display: inline-flex;
        align-items: center;
        gap: var(--wg-space-sm);
        height: var(--wg-control-height);
        padding: 0 var(--wg-control-padding-x);
        border-radius: var(--wg-radius-control);
        background: var(--wg-primary);
        color: var(--wg-on-primary);
        font: var(--wg-text-label-md);
        font-weight: 600;
        text-decoration: none;
    }

    .download:hover {
        background: var(--wg-primary-container);
        color: var(--wg-on-primary-container);
    }

    .download:focus-visible {
        outline: var(--wg-focus-ring);
        outline-offset: var(--wg-focus-ring-offset);
    }

    @media (max-width: 640px) {
        h1 {
            font: var(--wg-text-headline-lg-mobile);
        }
    }
</style>
