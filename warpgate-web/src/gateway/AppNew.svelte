<script lang="ts">
    /**
     * Portal shell for the redesigned UI — screen 12.
     *
     * ── Enumeration of gateway/App.svelte, asserted present ──────────────
     * State:   redirecting (reset on pageshow), serverInfoPromise,
     *          webAuthRequests, doNotShowAuthRequests.
     * Guards:  requireLogin — awaits serverInfo, pushes
     *          /login?next=<pathname>#<location>[?querystring] when there is
     *          no username, and forces /mfa-setup when needsMfaSetup and the
     *          route is not already /mfa-setup;
     *          requireMfaSetupPending — requireLogin first, then bounces to
     *          / when MFA setup is *not* pending.
     * Socket:  wss web-auth-requests stream, re-opened whenever the username
     *          changes and closed first, with reloadWebAuthRequests on every
     *          message and once on open.
     * Chrome:  BannerModal from serverInfo.banner; DelayedSpinner while
     *          redirecting; logo linking to /@warpgate; the Admin link, shown
     *          only with hasAdminAccess and not during MFA setup; AuthBar;
     *          RequestsButton and the pending web-auth request list, both
     *          hidden when the route sets doNotShowAuthRequests or MFA setup
     *          is pending.
     * Routes:  all eight, with their conditions and userData unchanged.
     *
     * ── No sidebar, deliberately ─────────────────────────────────────────
     * The portal mockups render the ADMIN navigation rail — Users, Roles,
     * Configuration, Cluster. That is a Stitch artifact, not a design: a
     * portal user is not an administrator and must not be shown a rail full
     * of destinations they cannot open. The existing centred layout is the
     * right shape for four destinations and is kept, restyled onto the token
     * layer.
     *
     * ── Top bar ──────────────────────────────────────────────────────────
     * A full-width bar with a bottom hairline, as the admin shell's: the
     * brand, the portal's own destinations (the target list, and ticket
     * requests where self-service is on, which was otherwise only reachable
     * through the profile hub), then Admin and the account menu. The target
     * list is a grid and takes the bar's full width; the profile pages and
     * forms keep the narrow column they were laid out for.
     */
    import { hasAdminAccess } from 'admin/lib/store'
    import AuthBar from 'common/AuthBar.svelte'
    import BannerModal from 'common/BannerModal.svelte'
    import Brand from 'common/Brand.svelte'
    import Loadable from 'common/Loadable.svelte'
    import RequestsButton from 'common/RequestsButton.svelte'
    import { reloadServerInfo, serverInfo } from 'gateway/lib/store'
    import { get } from 'svelte/store'
    import Router, {
        link,
        push,
        type RouteDetail,
        router,
    } from 'svelte-spa-router'
    import { wrap } from 'svelte-spa-router/wrap'
    import Spinner from 'ui/Spinner.svelte'
    import { type AuthStateResponseInternal, api } from './lib/api'

    let redirecting = $state(false)
    const serverInfoPromise = reloadServerInfo()
    let webAuthRequests: AuthStateResponseInternal[] = $state([])
    let doNotShowAuthRequests = $state(false)

    async function init() {
        await serverInfoPromise
    }

    function onPageResume() {
        redirecting = false
    }

    async function reloadWebAuthRequests() {
        webAuthRequests = await api.getWebAuthRequests()
    }

    async function requireLogin(detail: RouteDetail) {
        await serverInfoPromise
        if (!get(serverInfo)?.username) {
            let url = `${location.pathname}#${detail.location}`
            if (detail.querystring) {
                url += `?${detail.querystring}`
            }
            push(`/login?next=${encodeURIComponent(url)}`)
            return false
        }
        if (
            get(serverInfo)?.needsMfaSetup &&
            detail.location !== '/mfa-setup'
        ) {
            push('/mfa-setup')
            return false
        }
        return true
    }

    async function requireMfaSetupPending(detail: RouteDetail) {
        if (!(await requireLogin(detail))) {
            return false
        }
        if (!get(serverInfo)?.needsMfaSetup) {
            push('/')
            return false
        }
        return true
    }

    const routes = {
        '/': wrap({
            asyncComponent: () => import('./screens/Targets.svelte'),
            props: {
                // A plain callback prop. This was `'on:navigation'`, which in
                // Svelte 4 was an event listener and in Svelte 5 is a prop
                // whose name happens to contain a colon — nothing read it, so
                // the spinner below could never appear.
                onnavigate: () => (redirecting = true),
            },
            conditions: [requireLogin],
        }),
        '/profile': wrap({
            asyncComponent: () => import('./Profile.svelte'),
            conditions: [requireLogin],
        }),
        '/profile/api-tokens': wrap({
            asyncComponent: () => import('./ProfileApiTokens.svelte'),
            conditions: [requireLogin],
        }),
        '/profile/credentials': wrap({
            asyncComponent: () => import('./ProfileCredentials.svelte'),
            conditions: [requireLogin],
        }),
        '/ticket-requests': wrap({
            asyncComponent: () => import('./TicketRequests.svelte'),
            conditions: [requireLogin],
        }),
        '/mfa-setup': wrap({
            asyncComponent: () => import('./MfaSetup.svelte'),
            conditions: [requireMfaSetupPending],
        }),
        '/login': wrap({
            asyncComponent: () => import('./screens/Login.svelte'),
        }),
        '/login/:stateId': wrap({
            asyncComponent: () => import('./OutOfBandAuth.svelte'),
            conditions: [requireLogin],
            userData: {
                doNotShowAuthRequests: true,
            },
        }),
    }

    const initPromise = init()
    let socket: WebSocket | null = null

    $effect(() => {
        $serverInfo?.username // trigger effect on username change
        try {
            socket?.close()
        } catch {
            // ignore
        }
        socket = null
        if ($serverInfo?.username) {
            socket = new WebSocket(
                `wss://${location.host}/@warpgate/api/auth/web-auth-requests/stream`,
            )
            socket.addEventListener('message', () => {
                reloadWebAuthRequests()
            })
            reloadWebAuthRequests()
        }
    })

    function onRouteLoaded(detail: RouteDetail) {
        doNotShowAuthRequests = !!(
            detail.userData as { doNotShowAuthRequests?: boolean }
        )?.doNotShowAuthRequests
    }

    const path = $derived(router.location)
    const onTargets = $derived(path === '/' || path === '')
    const onTicketRequests = $derived(path.startsWith('/ticket-requests'))
    // The portal's own destinations are for a signed-in user past MFA setup;
    // before that, every route but the one they are on bounces back.
    const showNav = $derived(
        !!$serverInfo?.username && !$serverInfo?.needsMfaSetup,
    )
</script>

<svelte:window on:pageshow={onPageResume} />

<BannerModal banner={$serverInfo?.banner ?? ''} />

<div class="app">
    <Loadable promise={initPromise}>
        {#if redirecting}
            <div class="redirecting">
                <Spinner delay={1000} label="Opening your session" />
            </div>
        {:else}
            <header class="topbar">
                <div class="topbar-inner">
                    <a
                        class="logo"
                        href="/@warpgate"
                        aria-label="Warpgate home"
                    >
                        <Brand />
                    </a>

                    {#if showNav}
                        <nav class="nav" aria-label="Portal">
                            <a
                                class="nav-link"
                                class:nav-link-active={onTargets}
                                href="/"
                                use:link
                                aria-current={onTargets ? 'page' : undefined}
                            >
                                My targets
                            </a>
                            {#if $serverInfo?.ticketSelfServiceEnabled}
                                <a
                                    class="nav-link"
                                    class:nav-link-active={onTicketRequests}
                                    href="/ticket-requests"
                                    use:link
                                    aria-current={onTicketRequests
                                        ? 'page'
                                        : undefined}
                                >
                                    Ticket requests
                                </a>
                            {/if}
                        </nav>
                    {/if}

                    <div class="header-actions">
                        {#if $hasAdminAccess && !$serverInfo?.needsMfaSetup}
                            <a
                                class="admin-link"
                                href="/@warpgate/admin"
                                aria-label="Admin"
                            >
                                <svg
                                    viewBox="0 0 16 16"
                                    width="13"
                                    height="13"
                                    aria-hidden="true"
                                >
                                    <circle
                                        cx="8"
                                        cy="8"
                                        r="2.25"
                                        fill="none"
                                        stroke="currentColor"
                                        stroke-width="1.5"
                                    />
                                    <path
                                        d="M8 1.5v1.6M8 12.9v1.6M14.5 8h-1.6M3.1 8H1.5M12.6 3.4l-1.1 1.1M4.5 11.5l-1.1 1.1M12.6 12.6l-1.1-1.1M4.5 4.5L3.4 3.4"
                                        stroke="currentColor"
                                        stroke-width="1.4"
                                        stroke-linecap="round"
                                    />
                                </svg>
                                <span class="admin-link-text">Admin</span>
                            </a>
                        {/if}

                        <AuthBar />
                    </div>
                </div>
            </header>

            <div class="portal" class:portal-wide={onTargets}>
                {#if !doNotShowAuthRequests && !$serverInfo?.needsMfaSetup}
                    <div class="requests">
                        <RequestsButton />
                    </div>

                    {#each webAuthRequests as authRequest (authRequest.id)}
                        <button
                            type="button"
                            class="auth-request"
                            onclick={() => push(`/login/${authRequest.id}`)}
                        >
                            <span class="auth-request-body">
                                <strong>
                                    {authRequest.protocol}
                                    authentication request
                                </strong>
                                {#if authRequest.address}
                                    <span class="auth-request-from">
                                        From {authRequest.address}
                                    </span>
                                {/if}
                            </span>
                            <span class="auth-request-go" aria-hidden="true"
                                >→</span
                            >
                        </button>
                    {/each}
                {/if}

                <main>
                    <Router {routes} {onRouteLoaded} />
                </main>
            </div>
        {/if}
    </Loadable>
</div>

<style>
    /* Loadable's own error, when the server info cannot be had, in the
     * column the page would have used. */
    .app > :global(.wg-callout) {
        width: calc(100% - 2 * var(--wg-space-lg));
        max-width: 48rem;
        margin: var(--wg-space-3xl) auto;
    }

    /* The target list's grid width; the top bar's content keeps to it on
     * every page, so the brand and the account menu do not move. */
    .topbar,
    .portal {
        --portal-wide: 88rem;
    }

    .topbar {
        position: sticky;
        top: 0;
        z-index: 20;
        background: var(--wg-surface-container-low);
        border-bottom: var(--wg-border-width) solid var(--wg-border);
    }

    .topbar-inner {
        display: flex;
        flex-wrap: wrap;
        align-items: center;
        gap: var(--wg-space-sm) var(--wg-space-xl);
        max-width: var(--portal-wide);
        min-height: var(--wg-topbar-height);
        margin: 0 auto;
        padding: var(--wg-space-sm) var(--wg-space-xl);
    }

    .portal {
        width: 100%;
        max-width: 48rem;
        margin: 0 auto;
        padding: var(--wg-space-2xl) var(--wg-space-xl) var(--wg-space-3xl);
    }

    .portal-wide {
        max-width: var(--portal-wide);
    }

    .logo {
        display: inline-flex;
        align-items: center;
        flex: none;
        border-radius: var(--wg-radius-sm);
    }

    .logo:focus-visible,
    .nav-link:focus-visible,
    .admin-link:focus-visible,
    .auth-request:focus-visible {
        outline: var(--wg-focus-ring);
        outline-offset: var(--wg-focus-ring-offset);
    }

    .nav {
        display: flex;
        align-items: center;
        gap: var(--wg-space-xs);
        min-width: 0;
    }

    .nav-link {
        display: inline-flex;
        align-items: center;
        height: var(--wg-control-height-compact);
        padding: 0 var(--wg-space-sm);
        border-radius: var(--wg-radius-control);
        color: var(--wg-text-muted);
        font: var(--wg-text-label-md);
        text-decoration: none;
        white-space: nowrap;
        transition:
            background var(--wg-duration-fast) var(--wg-easing),
            color var(--wg-duration-fast) var(--wg-easing);
    }

    .nav-link:hover {
        background: var(--wg-surface-container-high);
        color: var(--wg-text);
    }

    /* Where you are: full ink and a primary rule under the label, not colour
     * alone. */
    .nav-link-active {
        color: var(--wg-text);
        box-shadow: inset 0 -2px 0 var(--wg-primary);
    }

    .header-actions {
        display: flex;
        align-items: center;
        gap: var(--wg-space-md);
        margin-left: auto;
        min-width: 0;
    }

    .admin-link {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        gap: var(--wg-space-xs);
        height: var(--wg-control-height-compact);
        padding: 0 var(--wg-space-sm);
        border: var(--wg-border-width) solid var(--wg-border-strong);
        border-radius: var(--wg-radius-control);
        color: var(--wg-text);
        font: var(--wg-text-label-md);
        text-decoration: none;
        white-space: nowrap;
        transition: background var(--wg-duration-fast) var(--wg-easing);
    }

    .admin-link:hover {
        background: var(--wg-surface-container-high);
    }

    @media (max-width: 640px) {
        .topbar-inner {
            padding: var(--wg-space-sm) var(--wg-space-lg);
            column-gap: var(--wg-space-md);
        }

        /* The destinations take a row of their own under the brand. */
        .nav {
            order: 3;
            width: 100%;
        }

        .portal {
            padding: var(--wg-space-xl) var(--wg-space-lg) var(--wg-space-3xl);
        }

        /* The button keeps "Admin" as its accessible name. */
        .admin-link-text {
            display: none;
        }

        .admin-link {
            width: var(--wg-control-height-compact);
            padding: 0;
        }
    }

    .redirecting {
        display: flex;
        justify-content: center;
        padding: var(--wg-space-3xl) 0;
    }

    .requests {
        margin-bottom: var(--wg-space-lg);
    }

    .auth-request {
        display: flex;
        align-items: center;
        gap: var(--wg-space-md);
        width: 100%;
        margin-bottom: var(--wg-space-lg);
        padding: var(--wg-space-lg);
        text-align: left;
        background: var(--wg-surface-container);
        border: var(--wg-border-width) solid var(--wg-border-strong);
        border-radius: var(--wg-radius-panel);
        color: var(--wg-text);
        cursor: pointer;
    }

    .auth-request:hover {
        background: var(--wg-surface-container-high);
    }

    .auth-request-body {
        display: flex;
        flex-direction: column;
        gap: 2px;
        min-width: 0;
    }

    .auth-request-from {
        color: var(--wg-text-muted);
        font: var(--wg-text-label-sm);
    }

    .auth-request-go {
        margin-left: auto;
        color: var(--wg-text-muted);
    }
</style>
