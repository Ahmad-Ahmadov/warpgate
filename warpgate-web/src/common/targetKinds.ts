import { TargetKind } from 'gateway/lib/api'

export const TARGET_KIND_LABELS: Record<TargetKind, string> = {
    [TargetKind.Ssh]: 'SSH',
    [TargetKind.Http]: 'HTTP',
    [TargetKind.MySql]: 'MySQL',
    [TargetKind.Postgres]: 'PostgreSQL',
    [TargetKind.Kubernetes]: 'Kubernetes',
    [TargetKind.Vnc]: 'VNC',
    [TargetKind.Rdp]: 'RDP',
}

const DATABASE_ICON =
    'M3 4c0-1.1 2.2-2 5-2s5 .9 5 2v8c0 1.1-2.2 2-5 2s-5-.9-5-2zM3 4c0 1.1 2.2 2 5 2s5-.9 5-2M3 8c0 1.1 2.2 2 5 2s5-.9 5-2'
const DESKTOP_ICON = 'M2 3h12v8H2zM6 14h4M8 11v3'

/**
 * An outline icon for each kind of target, drawn on a 16x16 viewBox and
 * stroked in the current colour, as the shell's navigation icons are
 * (`shell/navItems.ts`): inline paths, not an icon font.
 */
export const TARGET_KIND_ICONS: Record<TargetKind, string> = {
    // A terminal window with a prompt
    [TargetKind.Ssh]: 'M2 3h12v10H2zM4.5 6.5 6.5 8l-2 1.5M8 10h3',
    // A globe
    [TargetKind.Http]:
        'M8 2a6 6 0 100 12A6 6 0 008 2zM2 8h12M8 2c1.8 1.7 2.6 3.7 2.6 6S9.8 12.3 8 14M8 2C6.2 3.7 5.4 5.7 5.4 8s.8 4.3 2.6 6',
    [TargetKind.MySql]: DATABASE_ICON,
    [TargetKind.Postgres]: DATABASE_ICON,
    // A hexagon with a wheel
    [TargetKind.Kubernetes]:
        'M8 1.8l5.4 3.1v6.2L8 14.2l-5.4-3.1V4.9zM8 5.5v5M5.8 6.8l4.4 2.4M10.2 6.8 5.8 9.2',
    [TargetKind.Vnc]: DESKTOP_ICON,
    [TargetKind.Rdp]: DESKTOP_ICON,
}

const PROTOCOL_KINDS: Record<string, TargetKind> = {
    ssh: TargetKind.Ssh,
    http: TargetKind.Http,
    mysql: TargetKind.MySql,
    postgres: TargetKind.Postgres,
    postgresql: TargetKind.Postgres,
    kubernetes: TargetKind.Kubernetes,
    vnc: TargetKind.Vnc,
    rdp: TargetKind.Rdp,
}

/**
 * The kind icon for a protocol as sessions and assignments name it ("SSH",
 * "rdp", "PostgreSQL"); `undefined` for one this does not know.
 */
export function protocolIcon(protocol: string): string | undefined {
    const kind = PROTOCOL_KINDS[protocol.trim().toLowerCase()]
    return kind ? TARGET_KIND_ICONS[kind] : undefined
}
