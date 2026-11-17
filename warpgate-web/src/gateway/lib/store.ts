import { autosave } from 'common/autosave'
import { logoUrl, preloadImage } from 'common/helpers'
import { derived, writable } from 'svelte/store'
import { api, type Info } from './api'

export const serverInfo = writable<Info | undefined>(undefined)

// The portal's collapsed target groups. Upstream #2860 moved this into
// ItemList's `storageKey` along with its customizable columns; this fork keeps
// its own ItemList (card grid, bindable `collapsedGroups`), so it keeps the
// store. Same storage key, so a collapsed group stays collapsed either way.
export const [collapsedTargetGroups] = autosave<string[]>(
    'target-list:collapsed-groups',
    [],
)

const [openTargetsInNewTabPreference] = autosave<boolean | null>(
    'target-list:open-in-new-tab',
    null,
)

export const openTargetsInNewTab = derived(
    [openTargetsInNewTabPreference, serverInfo],
    ([$preference, $serverInfo]) => {
        switch ($serverInfo?.openTargetsInNewTab) {
            case 'ForcedOn':
                return true
            case 'ForcedOff':
                return false
            case 'DefaultOff':
                return $preference ?? false
            default:
                return $preference ?? true
        }
    },
)

export const openTargetsInNewTabForced = derived(
    serverInfo,
    $serverInfo =>
        $serverInfo?.openTargetsInNewTab === 'ForcedOn' ||
        $serverInfo?.openTargetsInNewTab === 'ForcedOff',
)

export function setOpenTargetsInNewTab(value: boolean): void {
    openTargetsInNewTabPreference.set(value)
}

export async function reloadServerInfo(): Promise<void> {
    const info = await api.getInfo()
    if (info.logoEtag) {
        await preloadImage(logoUrl(info.logoEtag))
    }
    serverInfo.set(info)
}
