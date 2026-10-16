<script lang="ts">
    /**
     * Custom logo picker for the global parameters screen — upstream #2696.
     *
     * Upstream builds this on sveltestrap's Button, which this fork removed, so
     * it is redrawn on ui/Button with the same props and the same value
     * contract: `undefined` keeps the stored logo, `null` removes it, a data URL
     * replaces it. The validation (accepted types, 4 MB cap) is unchanged.
     *
     * One deliberate behaviour difference. Upstream opens the file chooser with
     * a `<label class="btn">` pointing at an `<input type="file" class="d-none">`.
     * A label is not focusable and a display:none input is not in the tab
     * order, so the chooser could not be reached from the keyboard at all
     * (WCAG 2.1.1). Here a real button calls `input.click()` instead, which is
     * focusable, announces as a button, and still opens the native chooser.
     */

    import HelpText from 'admin/lib/HelpText.svelte'
    import { logoUrl } from 'common/helpers'
    import Button from 'ui/Button.svelte'

    interface Props {
        etag?: string | null
        /**
         * Pending edit: undefined keeps the stored logo, null removes it and a
         * data URL replaces it.
         */
        value?: string | null
    }

    let { etag, value = $bindable() }: Props = $props()

    let error: string | undefined = $state()
    let input: HTMLInputElement | undefined = $state()

    const preview = $derived(
        value ?? (value === undefined && etag ? logoUrl(etag) : undefined),
    )

    async function load(file: File) {
        const dataUrl = await new Promise<string>((resolve, reject) => {
            const reader = new FileReader()
            reader.onload = () => resolve(reader.result as string)
            reader.onerror = () => reject(reader.error)
            reader.readAsDataURL(file)
        })
        if (
            !/^data:image\/(png|jpeg|gif|webp|svg\+xml);base64,/.test(dataUrl)
        ) {
            error = 'Unsupported image type'
        } else if (dataUrl.length > 4 * 1024 * 1024) {
            error = 'Image too large, keep it under 4 MB'
        } else {
            error = undefined
            value = dataUrl
        }
    }

    function remove() {
        value = null
        if (input) {
            input.value = ''
        }
    }
</script>

<div class="logo-input">
    {#if preview}
        <img src={preview} alt="Current logo" class="preview">
    {:else}
        <span class="empty">No image selected</span>
    {/if}

    <!-- Kept out of the tab order on purpose: the button below is the control
         a person reaches, and it forwards to this. -->
    <input
        bind:this={input}
        type="file"
        class="file"
        tabindex="-1"
        aria-hidden="true"
        aria-label="Logo image file"
        accept="image/png,image/jpeg,image/gif,image/webp,image/svg+xml"
        onchange={e => {
            const file = e.currentTarget.files?.[0]
            if (file) {
                load(file)
            }
        }}
    >

    <div class="actions">
        <Button size="compact" onclick={() => input?.click()}>
            {preview ? 'Change logo' : 'Choose logo'}
        </Button>
        {#if preview}
            <Button size="compact" variant="destructive" onclick={remove}>
                Clear
            </Button>
        {/if}
    </div>
</div>

<p class="error" aria-live="polite">{error ?? ''}</p>

<HelpText>
    Replaces the Warpgate logo in the header and on the login page. PNG, JPEG,
    GIF, WebP or SVG up to 4 MB.
</HelpText>

<style>
    .logo-input {
        display: flex;
        align-items: center;
        gap: var(--wg-space-md);
    }

    .preview {
        display: block;
        height: 32px;
        margin-right: auto;
    }

    .empty {
        margin-right: auto;
        color: var(--wg-text-muted);
        font: var(--wg-text-body-md);
    }

    .actions {
        display: flex;
        gap: var(--wg-space-sm);
    }

    /* display:none would also work, but visually hidden keeps `click()`
       reliable across browsers that refuse to open choosers for inputs that
       are not rendered. */
    .file {
        position: absolute;
        width: 1px;
        height: 1px;
        overflow: hidden;
        clip: rect(0 0 0 0);
        white-space: nowrap;
    }

    /* Rendered even when empty, so the live region is in the accessibility
       tree from the start and the first error is announced rather than missed.
       Hiding it with display:none while empty would undo exactly that. */
    .error {
        margin: var(--wg-space-xs) 0 0;
        color: var(--wg-error);
        font: var(--wg-text-label-sm);
    }

    .error:empty {
        margin: 0;
    }
</style>
