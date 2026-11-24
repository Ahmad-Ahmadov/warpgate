<script lang="ts">
    /**
     * MySQL and PostgreSQL target options — part of screen 4f.
     *
     * These were inline in the old Target.svelte rather than a component; the
     * two protocols share every field except the Postgres-only protocol
     * version and idle timeout, which live in the Advanced section on the
     * parent page.
     *
     * TlsConfiguration is reused from 4c, which is why this file is short.
     *
     * The database accounts Warpgate signs in as (a password or Vault
     * reference, or a cloud role) are the target's Accounts; who may use which
     * is Access Control.
     */
    import type {
        TargetOptionsTargetMySqlOptions,
        TargetOptionsTargetPostgresOptions,
    } from 'admin/lib/api'
    import Input from 'ui/Input.svelte'
    import { TlsMode } from 'admin/lib/api'
    import TlsConfiguration from '../TlsConfiguration.svelte'

    interface Props {
        options:
            | TargetOptionsTargetMySqlOptions
            | TargetOptionsTargetPostgresOptions
    }

    let { options = $bindable() }: Props = $props()
</script>

<h5>Connection</h5>

<div class="row">
    <Input label="Target host" mono bind:value={options.host} />
    <Input
        label="Target port"
        type="number"
        mono
        class="port"
        value={String(options.port)}
        oninput={e => {
            const v = Number.parseInt((e.target as HTMLInputElement).value, 10)
            if (!Number.isNaN(v)) {
                options.port = v
            }
        }}
    />
</div>

<h5>Transport</h5>

<TlsConfiguration bind:value={options.tls} subject="this database" />
{#if options.tls.mode === TlsMode.Preferred}
    <!-- Upstream 8b9daba4: "Preferred" no longer falls back to a plaintext password. -->
    <p class="tls-note">
        If the database offers no TLS, Warpgate will not send the password in
        plaintext and the sign-in fails. To allow plaintext deliberately, choose
        Disabled.
    </p>
{/if}

<style>
    h5 {
        margin: var(--wg-space-xl) 0 var(--wg-space-md);
        font: var(--wg-text-label-md);
        color: var(--wg-text-muted);
    }

    .tls-note {
        margin: calc(var(--wg-space-sm) * -1) 0 0;
        color: var(--wg-text-muted);
        font: var(--wg-text-body-md);
    }

    h5:first-child {
        margin-top: 0;
    }

    .row {
        display: flex;
        flex-wrap: wrap;
        gap: var(--wg-space-lg);
        margin-bottom: var(--wg-space-lg);
    }

    .row > :global(*) {
        flex: 1 1 12rem;
        min-width: 0;
    }

    .row > :global(.port) {
        flex: 0 1 8rem;
    }
</style>
