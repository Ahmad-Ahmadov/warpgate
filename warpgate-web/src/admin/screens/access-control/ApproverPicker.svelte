<script lang="ts">
    /**
     * Who may approve: named users and access groups, as removable chips. Empty
     * means "any administrator who is allowed to approve sessions", which is also
     * what the approvals screen offers. A person on the list still needs that
     * administrator permission to reach the approvals screen at all; the list only
     * narrows who among them may approve this request.
     */
    import type { Role, User } from 'admin/lib/api'
    import Combobox, { type ComboboxOption } from 'ui/Combobox.svelte'
    import Icon from 'ui/Icon.svelte'

    interface Props {
        userIds: string[]
        roleIds: string[]
        users: User[]
        roles: Role[]
        disabled?: boolean
    }

    let {
        userIds = $bindable(),
        roleIds = $bindable(),
        users,
        roles,
        disabled = false,
    }: Props = $props()

    let adding = $state('')

    const options = $derived<ComboboxOption[]>([
        ...users
            .filter(user => !userIds.includes(user.id))
            .map(user => ({
                value: `user:${user.id}`,
                label: user.username,
                description: user.description || 'User',
                keywords: 'user',
            })),
        ...roles
            .filter(role => !roleIds.includes(role.id))
            .map(role => ({
                value: `group:${role.id}`,
                label: role.name,
                description: 'Access group',
                keywords: 'group role',
            })),
    ])

    const chips = $derived([
        ...userIds.map(id => ({
            key: `user:${id}`,
            name: users.find(user => user.id === id)?.username ?? 'Deleted user',
            kind: 'User',
        })),
        ...roleIds.map(id => ({
            key: `group:${id}`,
            name: roles.find(role => role.id === id)?.name ?? 'Deleted group',
            kind: 'Group',
        })),
    ])

    function add(value: string) {
        if (value.startsWith('user:')) {
            userIds = [...userIds, value.slice(5)]
        } else if (value.startsWith('group:')) {
            roleIds = [...roleIds, value.slice(6)]
        }
        adding = ''
    }

    function remove(key: string) {
        if (key.startsWith('user:')) {
            userIds = userIds.filter(id => id !== key.slice(5))
        } else {
            roleIds = roleIds.filter(id => id !== key.slice(6))
        }
    }
</script>

<div class="approvers">
    <Combobox
        label="Approvers"
        bind:value={adding}
        {options}
        placeholder="Anyone allowed to approve sessions — add a user or group to narrow it"
        clearable={false}
        {disabled}
        onchange={add}
    />
    {#if chips.length}
        <ul class="chips" aria-label="Chosen approvers">
            {#each chips as chip (chip.key)}
                <li class="chip">
                    <span class="kind">{chip.kind}</span>
                    {chip.name}
                    <button
                        type="button"
                        aria-label="Remove {chip.name}"
                        {disabled}
                        onclick={() => remove(chip.key)}
                    >
                        <Icon name="close" size={12} />
                    </button>
                </li>
            {/each}
        </ul>
    {/if}
</div>

<style>
    .approvers {
        display: flex;
        flex-direction: column;
        gap: var(--wg-space-sm);
    }

    .chips {
        display: flex;
        flex-wrap: wrap;
        gap: var(--wg-space-xs);
        margin: 0;
        padding: 0;
        list-style: none;
    }

    .chip {
        display: inline-flex;
        align-items: center;
        gap: var(--wg-space-xs);
        height: var(--wg-control-height-compact);
        padding: 0 var(--wg-space-xs) 0 var(--wg-space-sm);
        border: var(--wg-border-width) solid var(--wg-primary);
        border-radius: var(--wg-radius-badge);
        background: var(--wg-primary-tint);
        color: var(--wg-text);
        font: var(--wg-text-label-md);
    }

    .kind {
        color: var(--wg-text-subtle);
        font: var(--wg-text-label-sm);
    }

    .chip button {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        width: 1.25rem;
        height: 1.25rem;
        padding: 0;
        border: 0;
        border-radius: 50%;
        background: none;
        color: var(--wg-text-muted);
        cursor: pointer;
        transition:
            background var(--wg-duration-fast) var(--wg-easing),
            color var(--wg-duration-fast) var(--wg-easing);
    }

    .chip button:hover:not(:disabled) {
        background: var(--wg-primary-tint-strong);
        color: var(--wg-text);
    }

    .chip button:focus-visible {
        outline: var(--wg-focus-ring);
        outline-offset: 1px;
    }
</style>
