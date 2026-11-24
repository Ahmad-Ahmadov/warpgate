/**
 * The product's icon set: outline paths on a 16×16 viewBox, stroked in the
 * current colour at 1.4, round caps and joins (`ui/Icon.svelte` draws them).
 *
 * Inline paths rather than the FontAwesome packages, for the reason the shell
 * gave when it started this set: they render on every route, at one weight,
 * and cost nothing to import. Target-kind and recording-kind icons, drawn the
 * same way, live in `common/targetKinds.ts` and `common/recordings.ts`.
 */
export const ICONS = {
    // ---- navigation (the shell's original set) ----
    sessions: 'M2 4h12M2 8h12M2 12h8',
    requests: 'M8 2v6l4 2M8 14A6 6 0 108 2a6 6 0 000 12z',
    shield: 'M8 2l5 2v4c0 3-2 5.5-5 6-3-.5-5-3-5-6V4l5-2z',
    network: 'M8 2v4M8 10v4M3 8h10M4 5l8 6M12 5l-8 6',
    log: 'M4 2h8v12H4zM6 5h4M6 8h4M6 11h2',
    overview: 'M2 2h5v5H2zM9 2h5v3H9zM9 7h5v7H9zM2 9h5v5H2z',
    target: 'M8 2a6 6 0 100 12A6 6 0 008 2zm0 3a3 3 0 100 6 3 3 0 000-6z',
    group: 'M3 4h4v4H3zM9 4h4v4H9zM3 10h4v4H3zM9 10h4v4H9z',
    user: 'M8 8a3 3 0 100-6 3 3 0 000 6zM2 14c0-3 2.5-4.5 6-4.5S14 11 14 14',
    key: 'M10 2a4 4 0 00-3.5 6L2 12.5V14h2l.5-1.5H6V11h1.5l.5-.5A4 4 0 1010 2z',
    ticket: 'M2 5h12v2a1.5 1.5 0 000 3v2H2v-2a1.5 1.5 0 000-3z',
    sliders: 'M2 5h8M12 5h2M2 11h2M6 11h8M10 3v4M4 9v4',
    directory: 'M2 3h5l1 2h6v8H2z',
    vault: 'M2 3h12v10H2zM8 6a2 2 0 100 4 2 2 0 000-4zM8 8h3M4 13v1M12 13v1',

    // ---- access ----
    /** A shield with a check: who may connect (Access Control). */
    access: 'M8 2l5 2v4c0 3-2 5.5-5 6-3-.5-5-3-5-6V4l5-2zM5.8 8.2l1.6 1.6 3-3',
    /** Two people: a group of users. */
    users: 'M6 7.5a2.5 2.5 0 100-5 2.5 2.5 0 000 5zM1.5 13.5c0-2.5 2-3.8 4.5-3.8s4.5 1.3 4.5 3.8M11 7.5a2 2 0 100-4M12.5 9.9c1.3.4 2 1.6 2 3.6',
    /** A person with a padlock: a remote account on a target. */
    account:
        'M6 7a2.5 2.5 0 100-5 2.5 2.5 0 000 5zM1.5 13c0-2.4 2-3.7 4.5-3.7 1 0 1.8.2 2.5.5M10 10.5h4.5v3.5H10zM11 10.5V9.6a1.25 1.25 0 012.5 0v.9',
    /** A pulse: a live session. */
    activity: 'M1.5 8h3l1.5-4 3 8 1.5-4h4',

    // ---- actions ----
    plus: 'M8 3v10M3 8h10',
    edit: 'M10.5 2.5l3 3L6 13H3v-3zM9 4l3 3',
    trash: 'M3 4.5h10M6.5 4.5V3h3v1.5M4.5 4.5l.6 8.5h5.8l.6-8.5M7 7v4M9 7v4',
    /** Play: start a session. */
    connect: 'M5 3.5v9l7.5-4.5z',
    /** A strip of film: watch a recording. */
    recording:
        'M2 4h12v8H2zM5 4v8M11 4v8M2 6.5h3M11 6.5h3M2 9.5h3M11 9.5h3',
    /** An arrow out of a box: opens elsewhere. */
    external: 'M9 3h4v4M13 3 7.5 8.5M11 9.5V13H3V5h3.5',
    search: 'M7 12A5 5 0 107 2a5 5 0 000 10zM10.5 10.5 14 14',
    check: 'M3 8.5l3.5 3.5L13 5',
    close: 'M4 4l8 8M12 4l-8 8',
    /** An open tray: nothing here yet. */
    inbox: 'M2 9l2-6h8l2 6v4H2zM2 9h3.5l1 1.5h3l1-1.5H14',
} as const

export type IconName = keyof typeof ICONS
