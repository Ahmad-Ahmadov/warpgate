<script lang="ts">
    /**
     * One outline icon from `ui/icons.ts` (or a path of the same set, such as a
     * target kind's), at the product's single stroke weight. Decorative: the
     * text next to it carries the meaning, so it is hidden from assistive tech.
     */
    import { ICONS, type IconName } from './icons'

    interface Props {
        name?: IconName
        /** A path on the same 16×16 grid, for icons kept elsewhere. */
        path?: string
        size?: number
        class?: string
    }

    let { name, path, size = 16, class: className = '' }: Props = $props()

    const d = $derived(path ?? (name ? ICONS[name] : ''))
</script>

<svg
    class="wg-icon {className}"
    viewBox="0 0 16 16"
    width={size}
    height={size}
    aria-hidden="true"
    focusable="false"
>
    <path
        {d}
        fill="none"
        stroke="currentColor"
        stroke-width="1.4"
        stroke-linecap="round"
        stroke-linejoin="round"
    />
</svg>

<style>
    .wg-icon {
        flex: none;
        display: inline-block;
        vertical-align: -0.15em;
    }
</style>
