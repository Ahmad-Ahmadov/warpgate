<script lang="ts">
    /**
     * "Users sign in with their directory password" for an LDAP server.
     *
     * A Checkbox, not a Toggle: it is saved with the rest of the form.
     *
     * The server refuses the setting without TLS (a password is never sent
     * in the clear), so with TLS disabled the box is disabled while off, and
     * a box already on explains why saving will fail rather than silently
     * turning itself off. Certificate verification being off is allowed but
     * called out: it lets anyone on the path read the passwords.
     */
    import { type Tls, TlsMode } from 'admin/lib/api'
    import Callout from 'ui/Callout.svelte'
    import Checkbox from 'ui/Checkbox.svelte'

    interface Props {
        authenticateUsers: boolean
        tls: Tls
    }

    let { authenticateUsers = $bindable(), tls }: Props = $props()

    const tlsDisabled = $derived(tls.mode === TlsMode.Disabled)
</script>

<div class="field">
    <Checkbox
        label="Users sign in with their directory password"
        hint="Linked users log in with their LDAP username and password, checked by binding to this server at every login. Warpgate stores no password for them, and their local passwords stop working. Account restrictions in the directory — disabled, locked or expired accounts, expired passwords — apply."
        disabled={tlsDisabled && !authenticateUsers}
        bind:checked={authenticateUsers}
    />

    {#if tlsDisabled}
        <Callout
            tone={authenticateUsers ? 'danger' : 'info'}
            title="Needs an encrypted connection"
        >
            Passwords are only sent over LDAPS or StartTLS. Set TLS to
            Preferred or Required to use directory sign-in.
        </Callout>
    {:else if authenticateUsers && !tls.verify}
        <Callout tone="warning" title="Certificate verification is off">
            Anyone able to intercept the connection to this server could
            impersonate it and read users' passwords. Turn verification on
            unless the network path is trusted.
        </Callout>
    {/if}
</div>

<style>
    .field {
        display: flex;
        flex-direction: column;
        gap: var(--wg-space-md);
        margin-top: var(--wg-space-xl);
    }
</style>
