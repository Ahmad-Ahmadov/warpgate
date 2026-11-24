import type { AdminPermissionKey } from 'admin/lib/store'
import type { AdminPermissions } from 'gateway/lib/api'
import { ICONS } from 'ui/icons'

/**
 * Sidebar navigation, gated on the same ADMIN_PERMISSIONS keys the palette
 * uses. One list, one gate — a nav item the operator cannot reach is absent,
 * not disabled, for the same disclosure reason.
 *
 * `icon` is a path drawn on a 16×16 viewBox, from the shared set in
 * `ui/icons.ts`. Icons are inline paths rather than a FontAwesome import
 * because the collapsed rail renders them at every route and the existing
 * @fortawesome packages are only pulled in by screens that have not migrated
 * yet.
 */

export interface NavItem {
    id: string
    label: string
    href: string
    /** Route prefix that marks this item active. */
    match: string
    /**
     * Further route prefixes under this item: screens with no item of their
     * own that are reached from this one, such as a session's recordings.
     */
    alsoMatch?: string[]
    icon: string
    requires?: AdminPermissionKey
}

export interface NavSection {
    id: string
    label: string
    items: NavItem[]
}

export const NAV_SECTIONS: NavSection[] = [
    {
        id: 'status',
        label: 'Status',
        items: [
            {
                id: 'overview',
                label: 'Overview',
                href: '#/',
                match: '/',
                icon: ICONS.overview,
                requires: 'sessionsView',
            },
            {
                id: 'sessions',
                label: 'Sessions',
                href: '#/status/sessions',
                match: '/status/sessions',
                alsoMatch: ['/status/recordings'],
                icon: ICONS.sessions,
                requires: 'sessionsView',
            },
            {
                id: 'requests',
                label: 'Requests',
                href: '#/status/requests',
                match: '/status/requests',
                icon: ICONS.requests,
                requires: 'approveSessions',
            },
            {
                id: 'login-protection',
                label: 'Login protection',
                href: '#/status/login-protection',
                match: '/status/login-protection',
                icon: ICONS.shield,
                requires: 'configEdit',
            },
            {
                id: 'network',
                label: 'Network',
                href: '#/status/network',
                match: '/status/network',
                icon: ICONS.network,
                requires: 'configEdit',
            },
            {
                id: 'log',
                label: 'Audit log',
                href: '#/log',
                match: '/log',
                icon: ICONS.log,
                requires: 'sessionsView',
            },
        ],
    },
    {
        id: 'access',
        label: 'Access',
        items: [
            {
                id: 'targets',
                label: 'Targets',
                href: '#/config/targets',
                match: '/config/targets',
                icon: ICONS.target,
                requires: 'targetsEdit',
            },
            {
                id: 'target-groups',
                label: 'Target groups',
                href: '#/config/target-groups',
                match: '/config/target-groups',
                icon: ICONS.group,
                requires: 'targetsEdit',
            },
            {
                id: 'users',
                label: 'Users',
                href: '#/config/users',
                match: '/config/users',
                icon: ICONS.user,
                requires: 'usersEdit',
            },
            {
                // Assignments, access groups and the migration review: the one
                // place access is granted. Replaces "Access roles" and
                // "Account access"; their routes still lead here.
                id: 'access-control',
                label: 'Access control',
                href: '#/config/access-control',
                match: '/config/access-control',
                alsoMatch: ['/config/access-roles', '/config/account-access'],
                icon: ICONS.access,
                requires: 'accessRolesAssign',
            },
            {
                id: 'admin-roles',
                label: 'Admin roles',
                href: '#/config/admin-roles',
                match: '/config/admin-roles',
                icon: ICONS.shield,
                requires: 'adminRolesManage',
            },
            {
                id: 'tickets',
                label: 'Tickets',
                href: '#/config/tickets',
                match: '/config/tickets',
                icon: ICONS.ticket,
                requires: 'ticketsCreate',
            },
        ],
    },
    {
        id: 'configuration',
        label: 'Configuration',
        items: [
            {
                id: 'ssh',
                label: 'SSH keys',
                href: '#/config/ssh',
                match: '/config/ssh',
                icon: ICONS.key,
                requires: 'configEdit',
            },
            {
                id: 'policies',
                label: 'Policies',
                href: '#/config/policies',
                match: '/config/policies',
                icon: ICONS.shield,
                requires: 'configEdit',
            },
            {
                id: 'ldap',
                label: 'LDAP servers',
                href: '#/config/ldap-servers',
                match: '/config/ldap-servers',
                icon: ICONS.directory,
                requires: 'configEdit',
            },
            {
                id: 'secret-backends',
                label: 'Secret backends',
                href: '#/config/secret-backends',
                match: '/config/secret-backends',
                icon: ICONS.vault,
                requires: 'configEdit',
            },
            {
                id: 'parameters',
                label: 'Parameters',
                href: '#/config/parameters',
                match: '/config/parameters',
                icon: ICONS.sliders,
                requires: 'configEdit',
            },
        ],
    },
]

export function permittedSections(
    sections: NavSection[],
    permissions: AdminPermissions,
): NavSection[] {
    return sections
        .map(section => ({
            ...section,
            items: section.items.filter(
                item => !item.requires || permissions[item.requires] === true,
            ),
        }))
        .filter(section => section.items.length > 0)
}

/**
 * Longest-prefix match, so `/config/targets/abc` highlights Targets rather
 * than matching nothing, and `/config/target-groups` is not captured by
 * `/config/targets`.
 *
 * Overview's `match` is `/`, which is safe here rather than matching
 * everything: the child test is `path.startsWith(item.match + '/')`, so for
 * the root that asks whether the path starts with `//`, which no path does.
 * Overview therefore highlights on the exact root only.
 */
export function activeItemId(
    sections: NavSection[],
    path: string,
): string | undefined {
    let best: NavItem | undefined
    let bestLength = -1
    for (const section of sections) {
        for (const item of section.items) {
            for (const prefix of [item.match, ...(item.alsoMatch ?? [])]) {
                const exact = path === prefix
                const child = path.startsWith(`${prefix}/`)
                if ((exact || child) && prefix.length > bestLength) {
                    best = item
                    bestLength = prefix.length
                }
            }
        }
    }
    return best?.id
}
