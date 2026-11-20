import type { IconDefinition } from '@fortawesome/free-brands-svg-icons'
import {
    faArrowRightArrowLeft,
    faDesktop,
    faList,
    faSquare,
    faTerminal,
} from '@fortawesome/free-solid-svg-icons'
import {
    RecordingKind,
    type RecordingSnapshot,
    RecordingState,
} from 'admin/lib/api'
import { formatDistanceStrict } from 'date-fns'

/**
 * What the labels read from a recording: its metadata, the JSON its recorder
 * wrote. A `Recording` and a session's `RecordingSnapshot` both have it.
 */
export interface DescribedRecording {
    metadata: string
}

export type RecordingMetadata =
    | {
          type: 'kubernetes-exec'
          namespace: string
          pod: string
          // Absent when the client named no container: kubectl omits it for
          // single-container pods and lets the API server choose.
          container?: string | null
          // Stored either as argv or, in older recordings, as a single string.
          command: string | string[]
      }
    | {
          type: 'kubernetes-attach'
          namespace: string
          pod: string
          container?: string | null
      }
    | {
          type: 'kubernetes-api'
      }
    | {
          type: 'ssh-shell'
          channel: number
      }
    | {
          type: 'ssh-exec'
          channel: number
      }
    | {
          type: 'ssh-direct-tcpip'
          host: string
          port: number
      }
    | {
          type: 'ssh-direct-socket'
          path: string
      }
    | {
          type: 'ssh-forwarded-tcpip'
          host: string
          port: number
      }
    | {
          type: 'ssh-forwarded-socket'
          path: string
      }
    | {
          type: 'desktop'
          protocol: string
          target: string
      }

export function recordingMetadataToFieldSet(
    metadata: RecordingMetadata,
): [string, string][] {
    const fieldSets: [string, string][] = []

    switch (metadata.type) {
        case 'kubernetes-exec':
            fieldSets.push(['Namespace', metadata.namespace])
            fieldSets.push(['Pod', metadata.pod])
            if (metadata.container) {
                fieldSets.push(['Container', metadata.container])
            }
            fieldSets.push(['Command', [metadata.command].flat().join(' ')])
            break
        case 'kubernetes-attach':
            fieldSets.push(['Namespace', metadata.namespace])
            fieldSets.push(['Pod', metadata.pod])
            if (metadata.container) {
                fieldSets.push(['Container', metadata.container])
            }
            break
        case 'ssh-shell':
            fieldSets.push(['Channel', metadata.channel.toString()])
            break
        case 'ssh-exec':
            fieldSets.push(['Channel', metadata.channel.toString()])
            break
        case 'ssh-direct-tcpip':
        case 'ssh-forwarded-tcpip':
            fieldSets.push(['Host', metadata.host])
            fieldSets.push(['Port', metadata.port.toString()])
            break
        case 'ssh-direct-socket':
        case 'ssh-forwarded-socket':
            fieldSets.push(['Path', metadata.path])
            break
        case 'desktop':
            break
    }

    return fieldSets
}

/** A recording's metadata, or null when it is not the JSON it should be. */
export function parseRecordingMetadata(
    recording: DescribedRecording,
): RecordingMetadata | null {
    try {
        return JSON.parse(recording.metadata) as RecordingMetadata | null
    } catch {
        return null
    }
}

export function recordingTypeLabel(recording: DescribedRecording): string {
    const metadata = parseRecordingMetadata(recording)
    switch (metadata?.type) {
        case 'kubernetes-api':
            return 'API session'
        case 'kubernetes-exec':
            return 'Pod exec session'
        case 'kubernetes-attach':
            return 'Pod attach session'
        case 'ssh-shell':
            return 'Shell session'
        case 'ssh-exec':
            return 'SSH exec request'
        case 'ssh-direct-tcpip':
            return 'Local TCP forward'
        case 'ssh-direct-socket':
            return 'Local UNIX socket forward'
        case 'ssh-forwarded-tcpip':
            return 'Remote TCP forward'
        case 'ssh-forwarded-socket':
            return 'Remote UNIX socket forward'
        case 'desktop':
            return 'Desktop session'
    }

    return 'Unknown session type'
}

export function recordingTypeIcon(recording: DescribedRecording): IconDefinition {
    const metadata = parseRecordingMetadata(recording)
    switch (metadata?.type) {
        case 'kubernetes-api':
            return faList
        case 'kubernetes-exec':
            return faTerminal
        case 'kubernetes-attach':
            return faTerminal
        case 'ssh-shell':
            return faTerminal
        case 'ssh-exec':
            return faTerminal
        case 'ssh-direct-tcpip':
            return faArrowRightArrowLeft
        case 'ssh-direct-socket':
            return faArrowRightArrowLeft
        case 'ssh-forwarded-tcpip':
            return faArrowRightArrowLeft
        case 'ssh-forwarded-socket':
            return faArrowRightArrowLeft
        case 'desktop':
            return faDesktop
    }

    return faSquare
}

/** What opening a recording does with it. */
export type RecordingAction = 'watch' | 'view' | 'download'

/**
 * Terminal sessions and desktops play back in a player; a Kubernetes API
 * session is a log of requests to read, not to play; a forwarded connection's
 * traffic is a capture to download. Only the first gets a play action.
 */
const ACTIONS: Record<RecordingKind, RecordingAction> = {
    [RecordingKind.Terminal]: 'watch',
    [RecordingKind.Desktop]: 'watch',
    [RecordingKind.Kubernetes]: 'view',
    [RecordingKind.Traffic]: 'download',
}

export function recordingAction(kind: RecordingKind): RecordingAction {
    return ACTIONS[kind] ?? 'view'
}

export function isReplayable(kind: RecordingKind): boolean {
    return recordingAction(kind) === 'watch'
}

/** Whether a recording can be opened now: not past retention, and finished being written out. */
export function canOpen(recording: RecordingSnapshot): boolean {
    return (
        recording.state === RecordingState.Live ||
        recording.state === RecordingState.Available
    )
}

const STATE_ORDER: Record<RecordingState, number> = {
    [RecordingState.Live]: 0,
    [RecordingState.Available]: 1,
    [RecordingState.Processing]: 2,
    [RecordingState.Expired]: 3,
}

/** Someone at a desktop or a shell before a command run, a capture before nothing. */
function kindOrder(recording: RecordingSnapshot): number {
    switch (parseRecordingMetadata(recording)?.type) {
        case 'desktop':
            return 0
        case 'ssh-shell':
        case 'kubernetes-exec':
        case 'kubernetes-attach':
            return 1
    }
    switch (recording.kind) {
        case RecordingKind.Desktop:
            return 0
        case RecordingKind.Terminal:
            return 2
        case RecordingKind.Kubernetes:
            return 3
    }
    return 4
}

/**
 * The order the server keeps the session list's recordings in (`relevance` in
 * the admin API's sessions_list.rs): what can be watched first; then what is
 * being recorded now, then what is complete; then a desktop or a shell before
 * a command or a forwarded connection; then the earliest.
 */
export function compareRecordings(
    a: RecordingSnapshot,
    b: RecordingSnapshot,
): number {
    const key = (recording: RecordingSnapshot) => [
        isReplayable(recording.kind) ? 0 : 1,
        STATE_ORDER[recording.state],
        kindOrder(recording),
        recording.started.getTime(),
    ]
    const left = key(a)
    const right = key(b)
    for (let i = 0; i < left.length; i++) {
        const difference = (left[i] ?? 0) - (right[i] ?? 0)
        if (difference !== 0) {
            return difference
        }
    }
    return 0
}

/** The recording "Watch recording" opens: the most telling one that plays now. */
export function primaryRecording(
    recordings: RecordingSnapshot[],
): RecordingSnapshot | undefined {
    return recordings
        .filter(recording => isReplayable(recording.kind) && canOpen(recording))
        .sort(compareRecordings)[0]
}

/**
 * Where a session stands on recordings, for the session list's Recording
 * column and the session page's header:
 *
 *   watch       something plays now (live, or complete)
 *   processing  what would play is still being finalized
 *   other       only what reads or downloads, such as an API log or a capture
 *   expired     past the retention period, removed at the next cleanup
 *   none        nothing was recorded
 */
export type SessionRecordingStatus =
    | { kind: 'watch'; recording: RecordingSnapshot; more: number }
    | { kind: 'other'; recording: RecordingSnapshot; more: number }
    | { kind: 'processing'; count: number }
    | { kind: 'expired'; count: number }
    | { kind: 'none' }

export function sessionRecordingStatus(
    recordings: RecordingSnapshot[],
    count: number,
): SessionRecordingStatus {
    const total = Math.max(count, recordings.length)
    if (!total) {
        return { kind: 'none' }
    }
    const processing = (replayable: boolean) =>
        recordings.some(
            recording =>
                isReplayable(recording.kind) === replayable &&
                recording.state === RecordingState.Processing,
        )
    const watch = primaryRecording(recordings)
    if (watch) {
        return { kind: 'watch', recording: watch, more: total - 1 }
    }
    // What plays outranks a capture beside it, even while it is finalized.
    if (processing(true)) {
        return { kind: 'processing', count: total }
    }
    const other = recordings.filter(canOpen).sort(compareRecordings)[0]
    if (other) {
        return { kind: 'other', recording: other, more: total - 1 }
    }
    if (processing(false)) {
        return { kind: 'processing', count: total }
    }
    return { kind: 'expired', count: total }
}

/**
 * A recording's page. `session`, the user session it belongs to, gives the
 * page its way back to that session.
 */
export function recordingHref(recordingId: string, session?: string): string {
    const query = session ? `?session=${encodeURIComponent(session)}` : ''
    return `#/status/recordings/${recordingId}${query}`
}

/**
 * How long a recording ran: to its end, or for one never marked ended, to the
 * end of its connection, or for a live one, until now.
 */
export function recordingDuration(
    recording: { started: Date; ended?: Date },
    connectionEnded?: Date,
): string {
    const end = recording.ended ?? connectionEnded ?? new Date()
    return formatDistanceStrict(recording.started, end)
}

/** A recording's name for a person: what was recorded, a desktop by its protocol. */
export function recordingTitle(
    recording: DescribedRecording,
    protocol?: string,
): string {
    if (parseRecordingMetadata(recording)?.type === 'desktop' && protocol) {
        return `${protocol} desktop`
    }
    return recordingTypeLabel(recording)
}

/**
 * An outline icon per kind of recording, on a 16x16 viewBox and stroked in
 * the current colour, as the shell's own icons are: a desktop, a terminal, a
 * Kubernetes wheel, and traffic both ways.
 */
export const RECORDING_KIND_ICONS: Record<RecordingKind, string> = {
    [RecordingKind.Desktop]: 'M2 3h12v8H2zM6 14h4M8 11v3',
    [RecordingKind.Terminal]: 'M2 3h12v10H2zM4.5 6.5 6.5 8l-2 1.5M8 10h3',
    [RecordingKind.Kubernetes]:
        'M8 1.8l5.4 3.1v6.2L8 14.2l-5.4-3.1V4.9zM8 5.5v5M5.8 6.8l4.4 2.4M10.2 6.8 5.8 9.2',
    [RecordingKind.Traffic]: 'M2.5 5.5h10L10 3M13.5 10.5h-10L6 13',
}

/**
 * A recording's state as the marker shape and word every screen uses for it
 * (`ui/StatusMarker`): the live dot while it is made, the pending diamond
 * while it is finalized, the online ring once it plays, the ended ring once
 * it is past retention.
 */
export const RECORDING_STATE_MARKERS: Record<
    RecordingState,
    { kind: 'live' | 'pending' | 'online' | 'ended'; label: string }
> = {
    [RecordingState.Live]: { kind: 'live', label: 'Recording' },
    [RecordingState.Processing]: { kind: 'pending', label: 'Processing' },
    [RecordingState.Available]: { kind: 'online', label: 'Available' },
    [RecordingState.Expired]: { kind: 'ended', label: 'Expired' },
}
