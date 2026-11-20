<script lang="ts">
    /**
     * Session detail — screen 2.
     *
     * Three parts, each under a heading of its own: the timeline (connection,
     * authentication, approvals, target connections and disconnect, in the
     * order they happened), the session's recordings, and its log.
     *
     * Behaviour preserved from admin/status/Session.svelte:
     *   - 1s polling, so a live session's timeline grows while you watch
     *   - target sessions sorted newest-first
     *   - recordings matched to their target session by sessionId
     *   - recording links gated on recordingsView
     *   - close gated on PROTOCOL_PROPERTIES[...].sessionsCanBeClosed, which
     *     is why HTTP sessions have no close button
     *   - the embedded LogViewer, filtered to this session
     *
     * Recordings come with the session, each in its state, for an
     * administrator who may view them. They used to be a second request
     * every second, which the API refuses without that permission: the
     * refusal took the whole screen down for an administrator who may view
     * sessions but not recordings. A recording was a badge nested in the
     * timeline whose type ("Desktop session") was the link; it is now a row
     * with its duration, its state and an action that says what it does,
     * and the session's own "Watch recording" sits beside its title.
     *
     * Dropped: `getTargetAddress()`, which was defined and never called.
     */
    import {
        ApprovalRequestStatus,
        api,
        type RecordingSnapshot,
        RecordingState,
        type TargetSessionSnapshot,
        type UserSessionSnapshot,
    } from 'admin/lib/api'
    import { adminPermissions } from 'admin/lib/store'
    import TargetBadge from 'admin/log-viewer/TargetBadge.svelte'
    import UserBadge from 'admin/log-viewer/UserBadge.svelte'
    import { stringifyError } from 'common/errors'
    import { PROTOCOL_PROPERTIES } from 'common/protocols'
    import {
        canOpen,
        isReplayable,
        parseRecordingMetadata,
        RECORDING_KIND_ICONS,
        RECORDING_STATE_MARKERS,
        recordingDuration,
        recordingMetadataToFieldSet,
        recordingTitle,
        sessionRecordingStatus,
    } from 'common/recordings'
    import { formatDistanceStrict } from 'date-fns'
    import { onDestroy } from 'svelte'
    import firstBy from 'thenby'
    import Button from 'ui/Button.svelte'
    import Callout from 'ui/Callout.svelte'
    import ConfirmDialog from 'ui/ConfirmDialog.svelte'
    import RelativeDate from 'ui/RelativeDate.svelte'
    import SkeletonRow from 'ui/SkeletonRow.svelte'
    import StatusMarker from 'ui/StatusMarker.svelte'
    import { toast } from 'ui/toasts.svelte'
    import LogViewer from '../log-viewer/LogViewer.svelte'
    import RecordingAction from '../status/RecordingAction.svelte'

    interface Props {
        params: { id: string }
    }

    let { params = { id: '' } }: Props = $props()

    let error: string | null = $state(null)
    let session: UserSessionSnapshot | null = $state(null)
    let closeOpen = $state(false)

    const canViewRecordings = $derived($adminPermissions.recordingsView)

    async function load() {
        const loaded = await api.getSession(params)
        loaded.targetSessions.sort(firstBy(x => x.started, 'desc'))
        session = loaded
    }

    async function closeSession() {
        if (!session) {
            return
        }
        await api.closeSession(session)
        toast.success('Session closed')
        await load()
    }

    function recordingsFor(s: TargetSessionSnapshot): RecordingSnapshot[] {
        return (session?.recordings ?? [])
            .filter(x => x.targetSessionId === s.id)
            .sort(firstBy(x => x.started))
    }

    load().catch(async e => {
        error = await stringifyError(e)
    })

    const interval = setInterval(load, 1000)
    onDestroy(() => clearInterval(interval))

    // Bound to a local first: narrowing `session` inside a $derived expression
    // does not survive, and the chained access resolves to `never`.
    const canClose = $derived.by(() => {
        const s = session
        if (!s || s.ended) {
            return false
        }
        return !!PROTOCOL_PROPERTIES[s.protocol]?.sessionsCanBeClosed
    })

    // The session's recordings by target connection, newest connection first,
    // each connection's recordings in the order they started.
    const recordingGroups = $derived.by(() => {
        const s = session
        if (!s) {
            return []
        }
        return s.targetSessions
            .map(connection => ({
                connection,
                recordings: recordingsFor(connection),
            }))
            .filter(group => group.recordings.length > 0)
    })

    const recordingStatus = $derived.by(() => {
        const s = session
        return s
            ? sessionRecordingStatus(s.recordings, s.recordingCount)
            : ({ kind: 'none' } as const)
    })

    // Why there is nothing to show, in the words that fit the session.
    const noRecordingsReason = $derived.by(() => {
        const s = session
        if (!s) {
            return ''
        }
        if (PROTOCOL_PROPERTIES[s.protocol]?.sessionsAreRecorded === false) {
            return `${s.protocol} sessions are not recorded.`
        }
        if (!s.targetSessions.length) {
            return s.ended
                ? 'The session never reached a target, so there was nothing to record.'
                : 'Nothing to record yet: the session has not reached a target.'
        }
        return 'Nothing was recorded. Recording may be turned off, or the session ended before anything was captured.'
    })
</script>

{#snippet recordingAction(
    recording: RecordingSnapshot,
    sessionId: string,
    context: string,
)}
    {#if canOpen(recording)}
        <RecordingAction
            status={isReplayable(recording.kind)
                ? { kind: 'watch', recording, more: 0 }
                : { kind: 'other', recording, more: 0 }}
            session={sessionId}
            {context}
            download
        />
    {:else if recording.state === RecordingState.Processing}
        <span class="rec-note">Available shortly</span>
    {:else}
        <span class="rec-note">Removed at the next cleanup</span>
    {/if}
{/snippet}

{#if error}
    <Callout tone="danger" title="Something went wrong">{error}</Callout>
{:else if !session}
    <SkeletonRow rows={6} columns={[1, 4, 2]} />
{:else}
    <div class="head">
        <div class="head-main">
            <div class="head-title">
                <h1>{session.protocol} session</h1>
                {#if session.ended}
                    <StatusMarker kind="ended" label="Ended" />
                {:else}
                    <StatusMarker kind="live" />
                {/if}
            </div>

            <p class="head-meta">
                {#if session.ended}
                    {formatDistanceStrict(
                        new Date(session.started),
                        new Date(session.ended),
                    )}
                    long
                {/if}
                {#if session.nodeHostname}
                    <span class="wg-mono">· {session.nodeHostname}</span>
                {/if}
            </p>
        </div>

        {#if canViewRecordings && recordingStatus.kind !== 'none'}
            <div class="head-actions">
                <RecordingAction
                    status={recordingStatus}
                    session={session.id}
                    size="standard"
                    showMore={false}
                />
            </div>
        {/if}
    </div>

    <h2>Timeline</h2>
    <ol class="timeline">
        <li>
            <span class="tl-dot" aria-hidden="true"></span>
            <span class="tl-label">Connected from</span>
            <span class="wg-mono">{session.remoteAddress}</span>
            <span class="tl-time"><RelativeDate date={session.started} /></span>
        </li>

        <li>
            <span class="tl-dot" aria-hidden="true"></span>
            {#if session.username}
                <span class="tl-label">Authenticated as</span>
                <UserBadge id={session.userId} name={session.username} />
            {:else}
                <span class="tl-label">
                    {session.ended
                        ? 'Not authenticated'
                        : 'Not authenticated yet'}
                </span>
            {/if}
        </li>

        {#each session.adminApprovals as approval (approval)}
            <li>
                <StatusMarker
                    kind={approval.status === ApprovalRequestStatus.Pending
                        ? 'pending'
                        : approval.status === ApprovalRequestStatus.Approved
                          ? 'online'
                          : 'failed'}
                    label={approval.status === ApprovalRequestStatus.Pending
                        ? 'Awaiting approval'
                        : approval.status === ApprovalRequestStatus.Approved
                          ? 'Approved'
                          : approval.status === ApprovalRequestStatus.Rejected
                            ? 'Rejected'
                            : 'Timed out'}
                />
                <span class="tl-label">for</span>
                <TargetBadge id={approval.targetId} name={approval.target} />
                {#if approval.resolvedAt}
                    {#if approval.resolvedByUsername}
                        <span class="tl-label">by</span>
                        <UserBadge
                            id={approval.resolvedByUserId}
                            name={approval.resolvedByUsername}
                        />
                    {/if}
                    <span class="tl-time">
                        <RelativeDate date={approval.resolvedAt} />
                    </span>
                {/if}
            </li>
        {/each}

        {#each session.targetSessions as targetSession (targetSession.id)}
            {@const recorded = canViewRecordings
                ? recordingsFor(targetSession).length
                : 0}
            <li>
                <StatusMarker
                    kind={targetSession.ended ? 'ended' : 'live'}
                    label={targetSession.ended ? 'Closed' : 'Live'}
                />
                <span class="tl-label">on</span>
                {#if targetSession.target}
                    <TargetBadge
                        id={targetSession.targetId}
                        name={targetSession.target.name}
                    />
                {:else}
                    <span class="tl-label">a now deleted target</span>
                {/if}
                {#if recorded}
                    <span class="tl-recorded">
                        {recorded}
                        {recorded === 1 ? 'recording' : 'recordings'}
                    </span>
                {/if}
                {#if targetSession.nodeHostname}
                    <span class="tl-time wg-mono">
                        via {targetSession.nodeHostname}
                    </span>
                {/if}
            </li>
        {/each}

        {#if session.ended && session.protocol !== 'HTTP'}
            <li>
                <span class="tl-dot" aria-hidden="true"></span>
                <span class="tl-label">Disconnected</span>
                <span class="tl-time"
                    ><RelativeDate date={session.ended} /></span
                >
            </li>
        {/if}
    </ol>

    {#if canViewRecordings}
        <section class="recordings" aria-labelledby="recordings-heading">
            <h2 id="recordings-heading">
                Recordings
                {#if session.recordingCount}
                    <span class="h2-count">{session.recordingCount}</span>
                {/if}
            </h2>

            {#if !recordingGroups.length}
                <p class="rec-empty">{noRecordingsReason}</p>
            {:else}
                <div class="rec-scroll">
                    <table class="rec-table">
                        <caption class="wg-sr-only">
                            Recordings of this session, by target connection
                        </caption>
                        <thead>
                            <tr>
                                <th scope="col">Recording</th>
                                <th scope="col" class="rec-started">Started</th>
                                <th scope="col" class="rec-num">Duration</th>
                                <th scope="col">Status</th>
                                <th scope="col" class="rec-action">
                                    <span class="wg-sr-only">Action</span>
                                </th>
                            </tr>
                        </thead>
                        {#each recordingGroups as group (group.connection.id)}
                            {@const connection = group.connection}
                            {@const targetName =
                                connection.target?.name ??
                                'a now deleted target'}
                            <tbody>
                                <tr class="rec-group">
                                    <th scope="colgroup" colspan="5">
                                        <span class="rec-group-label">
                                            {#if connection.target}
                                                <TargetBadge
                                                    id={connection.targetId}
                                                    name={targetName}
                                                />
                                            {:else}
                                                <span class="tl-label"
                                                    >A now deleted target</span
                                                >
                                            {/if}
                                            <span class="rec-group-time">
                                                connected
                                                <RelativeDate
                                                    date={connection.started}
                                                />
                                            </span>
                                        </span>
                                    </th>
                                </tr>
                                {#each group.recordings as recording (recording.id)}
                                    {@const metadata =
                                        parseRecordingMetadata(recording)}
                                    {@const fields = metadata
                                        ? recordingMetadataToFieldSet(metadata)
                                        : []}
                                    {@const marker =
                                        RECORDING_STATE_MARKERS[
                                            recording.state
                                        ]}
                                    {@const title = recordingTitle(
                                        recording,
                                        session.protocol,
                                    )}
                                    <tr>
                                        <td>
                                            <span class="rec-name">
                                                <span
                                                    class="rec-icon"
                                                    aria-hidden="true"
                                                >
                                                    <svg
                                                        viewBox="0 0 16 16"
                                                        width="14"
                                                        height="14"
                                                        aria-hidden="true"
                                                    >
                                                        <path
                                                            d={RECORDING_KIND_ICONS[
                                                                recording.kind
                                                            ]}
                                                            fill="none"
                                                            stroke="currentColor"
                                                            stroke-width="1.4"
                                                            stroke-linecap="round"
                                                            stroke-linejoin="round"
                                                        />
                                                    </svg>
                                                </span>
                                                <span class="rec-title"
                                                    >{title}</span
                                                >
                                            </span>
                                            {#if fields.length}
                                                <span class="rec-fields">
                                                    {#each fields as [label, value] (label)}
                                                        <span class="rec-field">
                                                            <span
                                                                class="tl-label"
                                                                >{label}</span
                                                            >
                                                            <span
                                                                class="wg-mono"
                                                                >{value}</span
                                                            >
                                                        </span>
                                                    {/each}
                                                </span>
                                            {/if}
                                        </td>
                                        <td class="rec-started">
                                            <RelativeDate
                                                date={recording.started}
                                            />
                                        </td>
                                        <td class="rec-num">
                                            {recordingDuration(
                                                recording,
                                                connection.ended,
                                            )}
                                        </td>
                                        <td>
                                            <StatusMarker
                                                kind={marker.kind}
                                                label={marker.label}
                                                bare
                                            />
                                        </td>
                                        <td class="rec-action">
                                            {@render recordingAction(
                                                recording,
                                                session.id,
                                                `${title} on ${targetName}`,
                                            )}
                                        </td>
                                    </tr>
                                {/each}
                            </tbody>
                        {/each}
                    </table>
                </div>
            {/if}
        </section>
    {/if}

    <h2>Log</h2>
    <LogViewer filters={{ sessionId: session.id }} />

    {#if canClose}
        <div class="action-bar">
            <Button variant="destructive" onclick={() => (closeOpen = true)}>
                Close session now
            </Button>
        </div>
    {/if}
{/if}

<ConfirmDialog
    bind:open={closeOpen}
    title="Close this session?"
    confirmLabel="Close session"
    onconfirm={closeSession}
>
    <p>
        This disconnects the user immediately. Recordings already written are
        kept.
    </p>
</ConfirmDialog>

<style>
    .head {
        display: flex;
        align-items: flex-start;
        justify-content: space-between;
        gap: var(--wg-space-lg);
        flex-wrap: wrap;
        margin-bottom: var(--wg-space-lg);
    }

    .head-main {
        display: flex;
        flex-direction: column;
        gap: var(--wg-space-xs);
        min-width: 0;
    }

    .head-title {
        display: flex;
        align-items: center;
        gap: var(--wg-space-md);
    }

    .head-actions {
        display: flex;
        align-items: center;
        gap: var(--wg-space-sm);
    }

    h1 {
        margin: 0;
        font: var(--wg-text-headline-lg);
    }

    h2 {
        display: flex;
        align-items: baseline;
        gap: var(--wg-space-sm);
        margin: var(--wg-space-2xl) 0 var(--wg-space-md);
        font: var(--wg-text-headline-md);
    }

    .h2-count {
        color: var(--wg-text-subtle);
        font: var(--wg-text-code-md);
        font-variant-numeric: tabular-nums;
    }

    .head-meta {
        margin: 0;
        font: var(--wg-text-body-md);
        color: var(--wg-text-muted);
    }

    .timeline {
        list-style: none;
        margin: 0;
        padding: 0;
        border: var(--wg-border-width) solid var(--wg-border);
        border-radius: var(--wg-radius-panel);
        overflow: hidden;
    }

    .timeline li {
        display: flex;
        align-items: center;
        flex-wrap: wrap;
        gap: var(--wg-space-sm);
        min-height: var(--wg-row-height);
        padding: var(--wg-space-xs) var(--wg-space-md);
        border-bottom: var(--wg-border-width) solid var(--wg-border);
        font: var(--wg-text-body-md);
    }

    .timeline li:last-child {
        border-bottom: 0;
    }

    .tl-dot {
        flex: none;
        width: 6px;
        height: 6px;
        border-radius: var(--wg-radius-full);
        background: var(--wg-text-subtle);
    }

    .tl-label {
        color: var(--wg-text-muted);
    }

    .tl-time {
        margin-left: auto;
        font: var(--wg-text-label-sm);
        color: var(--wg-text-subtle);
    }

    .tl-recorded {
        color: var(--wg-text-subtle);
        font: var(--wg-text-label-sm);
    }

    /* ── Recordings ──────────────────────────────────────────────────── */

    .rec-empty {
        margin: 0;
        padding: var(--wg-space-lg);
        border: var(--wg-border-width) dashed var(--wg-border);
        border-radius: var(--wg-radius-panel);
        color: var(--wg-text-muted);
        font: var(--wg-text-body-md);
    }

    /* Only the table scrolls sideways; the page never does. */
    .rec-scroll {
        overflow-x: auto;
        border: var(--wg-border-width) solid var(--wg-border);
        border-radius: var(--wg-radius-panel);
    }

    .rec-table {
        width: 100%;
        border-collapse: separate;
        border-spacing: 0;
        font: var(--wg-text-body-md);
        color: var(--wg-text);
    }

    .rec-table thead th {
        height: var(--wg-row-height);
        padding: 0 var(--wg-space-md);
        background: var(--wg-surface-container);
        border-bottom: var(--wg-border-width) solid var(--wg-border);
        color: var(--wg-text-muted);
        font: var(--wg-text-label-md);
        text-align: left;
        white-space: nowrap;
    }

    .rec-table td {
        height: var(--wg-row-height);
        padding: var(--wg-space-xs) var(--wg-space-md);
        border-bottom: var(--wg-border-width) solid var(--wg-border);
        vertical-align: middle;
        font-variant-numeric: tabular-nums;
    }

    .rec-table tbody:last-child tr:last-child td {
        border-bottom: 0;
    }

    .rec-table tbody tr:not(.rec-group):hover {
        background: var(--wg-row-hover);
    }

    .rec-table .rec-group th {
        height: var(--wg-row-height-dense);
        padding: 0 var(--wg-space-md);
        background: var(--wg-surface-container-low);
        border-bottom: var(--wg-border-width) solid var(--wg-border);
        font: var(--wg-text-label-md);
        text-align: left;
    }

    .rec-group-label {
        display: inline-flex;
        align-items: center;
        gap: var(--wg-space-sm);
    }

    .rec-group-time {
        color: var(--wg-text-subtle);
        font: var(--wg-text-label-sm);
    }

    .rec-name {
        display: inline-flex;
        align-items: center;
        gap: var(--wg-space-sm);
        min-width: 0;
    }

    .rec-icon {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        flex: none;
        width: 1.5rem;
        height: 1.5rem;
        border: var(--wg-border-width) solid var(--wg-border);
        border-radius: var(--wg-radius);
        background: var(--wg-surface-container-high);
        color: var(--wg-text-muted);
    }

    .rec-title {
        font-weight: 500;
    }

    .rec-fields {
        display: flex;
        flex-wrap: wrap;
        gap: 0 var(--wg-space-md);
        margin-top: 2px;
        padding-left: calc(1.5rem + var(--wg-space-sm));
        font: var(--wg-text-label-sm);
    }

    .rec-field {
        display: inline-flex;
        gap: var(--wg-space-xs);
        min-width: 0;
    }

    .rec-num {
        text-align: right;
        white-space: nowrap;
    }

    .rec-started {
        white-space: nowrap;
    }

    .rec-action {
        width: 1%;
        text-align: right;
        white-space: nowrap;
    }

    .rec-note {
        color: var(--wg-text-subtle);
        font: var(--wg-text-label-sm);
    }

    .wg-sr-only {
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

    .action-bar {
        position: sticky;
        bottom: 0;
        display: flex;
        justify-content: flex-end;
        margin-top: var(--wg-space-xl);
        padding: var(--wg-space-md) 0;
        background: var(--wg-surface);
        border-top: var(--wg-border-width) solid var(--wg-border);
    }

    @media (max-width: 640px) {
        h1 {
            font: var(--wg-text-headline-lg-mobile);
        }

        /* When a recording started is in its row's group heading already. */
        .rec-started {
            display: none;
        }
    }
</style>
