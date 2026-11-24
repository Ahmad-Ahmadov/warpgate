import type { Crumb } from 'shell/Breadcrumbs.svelte'
import { NAV_SECTIONS } from 'shell/navItems'

/**
 * Derives the breadcrumb trail from the SPA path.
 *
 * Built from NAV_SECTIONS rather than a parallel table, so a renamed nav item
 * renames its crumb too. The leaf — a target name, a username — is not known
 * from the route, so screens pass it in and it is appended.
 */

const LEAF_LABELS: Record<string, string> = {
    create: 'New',
    users: 'Users',
    credentials: 'Credentials',
}

/**
 * The leaf of a screen reached under another item's crumb (a nav item's
 * `alsoMatch`): a recording sits under Sessions.
 */
const ALSO_MATCH_LEAVES: Record<string, string> = {
    '/status/recordings': 'Recording',
    '/config/access-roles': 'Access group',
}

export function crumbsFor(path: string, leaf?: Crumb): Crumb[] {
    const crumbs: Crumb[] = []
    let alsoMatchLeaf: string | undefined

    for (const section of NAV_SECTIONS) {
        for (const item of section.items) {
            if (path === item.match || path.startsWith(`${item.match}/`)) {
                crumbs.push({
                    label: item.label,
                    href: path === item.match ? undefined : item.href,
                })
            }
            for (const prefix of item.alsoMatch ?? []) {
                if (path === prefix || path.startsWith(`${prefix}/`)) {
                    crumbs.push({ label: item.label, href: item.href })
                    alsoMatchLeaf = ALSO_MATCH_LEAVES[prefix]
                }
            }
        }
    }

    // Longest match wins, same rule the sidebar highlight uses.
    if (crumbs.length > 1) {
        crumbs.splice(0, crumbs.length - 1)
    }

    if (leaf) {
        crumbs.push(leaf)
        return crumbs
    }

    if (alsoMatchLeaf && crumbs.length) {
        crumbs.push({ label: alsoMatchLeaf })
        return crumbs
    }

    // A trailing segment with a known label (…/create) becomes its own crumb.
    const tail = path.split('/').filter(Boolean).pop()
    if (tail && LEAF_LABELS[tail] && crumbs.length) {
        crumbs.push({ label: LEAF_LABELS[tail] })
    }

    return crumbs
}
