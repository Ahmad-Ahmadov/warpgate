<script lang="ts">
    /**
     * A protocol name with its target-kind icon in front ("SSH", "RDP",
     * "PostgreSQL"…). The caller renders the text exactly as it did before;
     * this only adds the icon, and nothing when the protocol is unknown.
     */
    import type { Snippet } from 'svelte'
    import Icon from 'ui/Icon.svelte'
    import { protocolIcon } from './targetKinds'

    interface Props {
        protocol: string
        class?: string
        children?: Snippet
    }

    let { protocol, class: className = '', children }: Props = $props()

    const icon = $derived(protocolIcon(protocol))
</script>

<span class="wg-protocol {className}">
    {#if icon}
        <Icon path={icon} size={14} class="wg-protocol-icon" />
    {/if}
    {#if children}{@render children()}{:else}{protocol}{/if}
</span>

<style>
    .wg-protocol {
        display: inline-flex;
        align-items: center;
        gap: var(--wg-space-xs);
        white-space: nowrap;
    }

    .wg-protocol :global(.wg-protocol-icon) {
        color: var(--wg-primary);
    }
</style>
