/**
 * Access rules in the browser: building, describing and checking the weekly
 * schedule and approval settings that the server stores and enforces.
 *
 * Nothing here decides anything. The server evaluates every rule, in the rules'
 * own timezone, when a connection starts; this only helps an administrator write
 * them down and read them back. `validateRules` mirrors the server's checks so a
 * mistake shows before saving, but the server's answer is the one that counts.
 */
import {
    AccessRuleAction,
    type AccessRules,
    AccessRuleWeekday,
    type AccessRuleWindow,
} from 'admin/lib/api'

export const WEEKDAYS: { value: AccessRuleWeekday; short: string; long: string }[] = [
    { value: AccessRuleWeekday.Mon, short: 'Mon', long: 'Monday' },
    { value: AccessRuleWeekday.Tue, short: 'Tue', long: 'Tuesday' },
    { value: AccessRuleWeekday.Wed, short: 'Wed', long: 'Wednesday' },
    { value: AccessRuleWeekday.Thu, short: 'Thu', long: 'Thursday' },
    { value: AccessRuleWeekday.Fri, short: 'Fri', long: 'Friday' },
    { value: AccessRuleWeekday.Sat, short: 'Sat', long: 'Saturday' },
    { value: AccessRuleWeekday.Sun, short: 'Sun', long: 'Sunday' },
]

export const WEEKDAY_ORDER: AccessRuleWeekday[] = WEEKDAYS.map(day => day.value)

export const ACTION_LABELS: Record<AccessRuleAction, string> = {
    [AccessRuleAction.Allow]: 'Allow',
    [AccessRuleAction.RequireApproval]: 'Require approval',
    [AccessRuleAction.Deny]: 'Deny',
}

/** Minutes in a day: the largest end of a window (`24:00`). */
export const MINUTES_PER_DAY = 1440

/** The longest request expiry or approval validity the server accepts: 30 days. */
export const MAX_APPROVAL_SECONDS = 30 * 24 * 3600

/** The browser's own timezone, as an IANA name. */
export function browserTimezone(): string {
    try {
        return Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC'
    } catch {
        return 'UTC'
    }
}

const FALLBACK_TIMEZONES = [
    'UTC',
    'Europe/London',
    'Europe/Berlin',
    'Europe/Paris',
    'Europe/Istanbul',
    'Europe/Moscow',
    'Asia/Baku',
    'Asia/Dubai',
    'Asia/Kolkata',
    'Asia/Singapore',
    'Asia/Tokyo',
    'Australia/Sydney',
    'America/New_York',
    'America/Chicago',
    'America/Denver',
    'America/Los_Angeles',
    'America/Sao_Paulo',
]

/** Every IANA timezone the browser knows, UTC first; a short list where it cannot say. */
export function timezoneNames(): string[] {
    try {
        const supported = (
            Intl as unknown as {
                supportedValuesOf?: (key: string) => string[]
            }
        ).supportedValuesOf?.('timeZone')
        if (supported?.length) {
            return ['UTC', ...supported.filter(name => name !== 'UTC')]
        }
    } catch {
        // fall through to the short list
    }
    return FALLBACK_TIMEZONES
}

/** `HH:MM` to minutes since midnight; `24:00` only where `allowEndOfDay`. */
export function parseClock(text: string, allowEndOfDay = false): number | undefined {
    const match = /^(\d{2}):(\d{2})$/.exec(text)
    if (!match) {
        return undefined
    }
    const hours = Number(match[1])
    const minutes = Number(match[2])
    if (minutes > 59) {
        return undefined
    }
    if (hours === 24 && minutes === 0 && allowEndOfDay) {
        return MINUTES_PER_DAY
    }
    return hours <= 23 ? hours * 60 + minutes : undefined
}

/** A window that ends before it starts runs overnight, into the next morning. */
export function isOvernight(window: Pick<AccessRuleWindow, 'start' | 'end'>): boolean {
    const start = parseClock(window.start)
    const end = parseClock(window.end, true)
    return start !== undefined && end !== undefined && end < start
}

/** `Mon–Fri`, `Sat, Sun`, `Every day`. */
export function describeDays(days: AccessRuleWeekday[]): string {
    const present = WEEKDAY_ORDER.map(day => days.includes(day))
    if (present.every(Boolean)) {
        return 'Every day'
    }
    const parts: string[] = []
    let index = 0
    while (index < 7) {
        if (!present[index]) {
            index += 1
            continue
        }
        let end = index
        while (end + 1 < 7 && present[end + 1]) {
            end += 1
        }
        const first = WEEKDAYS[index]?.short ?? ''
        const last = WEEKDAYS[end]?.short ?? ''
        if (end - index === 0) {
            parts.push(first)
        } else if (end - index === 1) {
            parts.push(first, last)
        } else {
            parts.push(`${first}–${last}`)
        }
        index = end + 1
    }
    return parts.join(', ')
}

export function describeWindow(window: AccessRuleWindow): string {
    const overnight = isOvernight(window) ? ' (overnight)' : ''
    return `${describeDays(window.days)} ${window.start}–${window.end}${overnight}`
}

/** The rules in a sentence or two, for an administrator reading back what they wrote. */
export function describeRules(rules: AccessRules): string {
    const windows = rules.windows.filter(window => window.days.length)
    const parts = windows.map(
        window => `${describeWindow(window)}: ${ACTION_LABELS[window.action].toLowerCase()}`,
    )
    parts.push(
        windows.length
            ? `otherwise ${ACTION_LABELS[rules.outside].toLowerCase()}`
            : `always ${ACTION_LABELS[rules.outside].toLowerCase()}`,
    )
    return `${parts.join('; ')} (${rules.timezone})`
}

/** Office hours, with approval required outside them: the usual starting point. */
export function defaultRules(timezone = browserTimezone()): AccessRules {
    return {
        timezone,
        windows: [
            {
                days: WEEKDAY_ORDER.slice(0, 5),
                start: '09:00',
                end: '18:00',
                action: AccessRuleAction.Allow,
            },
        ],
        outside: AccessRuleAction.RequireApproval,
        approval: {
            requestExpirySeconds: 900,
            validForSeconds: 1800,
            approverUserIds: [],
            approverRoleIds: [],
        },
    }
}

/** A copy that shares nothing with `rules`. */
export function cloneRules(rules: AccessRules): AccessRules {
    return {
        timezone: rules.timezone,
        windows: rules.windows.map(window => ({ ...window, days: [...window.days] })),
        outside: rules.outside,
        approval: {
            requestExpirySeconds: rules.approval?.requestExpirySeconds,
            validForSeconds: rules.approval?.validForSeconds,
            approverUserIds: [...(rules.approval?.approverUserIds ?? [])],
            approverRoleIds: [...(rules.approval?.approverRoleIds ?? [])],
        },
    }
}

/** What the server will refuse, found before sending; `undefined` when it looks fine. */
export function validateRules(rules: AccessRules): string | undefined {
    if (!rules.timezone.trim()) {
        return 'Choose a timezone.'
    }
    for (const [index, window] of rules.windows.entries()) {
        const number = index + 1
        if (!window.days.length) {
            return `Window ${number}: choose at least one day.`
        }
        const start = parseClock(window.start)
        const end = parseClock(window.end, true)
        if (start === undefined || end === undefined) {
            return `Window ${number}: enter the times as HH:MM.`
        }
        if (start === end) {
            return `Window ${number}: the start and end must differ.`
        }
    }
    for (const [what, seconds] of [
        ['request expiry', rules.approval?.requestExpirySeconds],
        ['approval validity', rules.approval?.validForSeconds],
    ] as const) {
        if (seconds !== undefined && !(seconds >= 1 && seconds <= MAX_APPROVAL_SECONDS)) {
            return `The ${what} must be between one second and 30 days.`
        }
    }
    return undefined
}

// ---- durations (expiry "after 2 weeks", approval windows) ----

export type DurationUnit = 'minutes' | 'hours' | 'days' | 'weeks' | 'months'

export const DURATION_UNITS: { value: DurationUnit; label: string }[] = [
    { value: 'minutes', label: 'Minutes' },
    { value: 'hours', label: 'Hours' },
    { value: 'days', label: 'Days' },
    { value: 'weeks', label: 'Weeks' },
    { value: 'months', label: 'Months' },
]

/** `from` plus a calendar duration. Months are calendar months, not 30 days. */
export function addDuration(from: Date, amount: number, unit: DurationUnit): Date {
    const result = new Date(from.getTime())
    switch (unit) {
        case 'minutes':
            result.setMinutes(result.getMinutes() + amount)
            break
        case 'hours':
            result.setHours(result.getHours() + amount)
            break
        case 'days':
            result.setDate(result.getDate() + amount)
            break
        case 'weeks':
            result.setDate(result.getDate() + amount * 7)
            break
        case 'months':
            result.setMonth(result.getMonth() + amount)
            break
    }
    return result
}

/** `15 minutes`, `1 hour`, `2 days`: seconds in the largest whole unit. */
export function formatSeconds(seconds: number): string {
    const units: [number, string][] = [
        [86400, 'day'],
        [3600, 'hour'],
        [60, 'minute'],
        [1, 'second'],
    ]
    for (const [size, name] of units) {
        if (seconds >= size && seconds % size === 0) {
            const count = seconds / size
            return `${count} ${name}${count === 1 ? '' : 's'}`
        }
    }
    return `${seconds} seconds`
}

/** The presets offered for how long a request waits, or an approval stays good. */
export const APPROVAL_PRESETS: { seconds: number; label: string }[] = [
    { seconds: 300, label: '5 minutes' },
    { seconds: 900, label: '15 minutes' },
    { seconds: 1800, label: '30 minutes' },
    { seconds: 3600, label: '1 hour' },
]
