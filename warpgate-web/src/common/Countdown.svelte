<script lang="ts">
    /**
     * Time left until `until`, counting down: "12 min 30 s", or "expired". Only
     * a display: the server decides what has expired, and the answer it gives
     * wins when it differs from this clock.
     */
    import { onDestroy } from 'svelte'

    interface Props {
        until: Date
        /** What to say once the time is up. */
        expired?: string
    }

    let { until, expired = 'expired' }: Props = $props()

    let now = $state(Date.now())
    const timer = setInterval(() => {
        now = Date.now()
    }, 1000)
    onDestroy(() => clearInterval(timer))

    const text = $derived.by(() => {
        const seconds = Math.ceil((until.getTime() - now) / 1000)
        if (seconds <= 0) {
            return expired
        }
        const days = Math.floor(seconds / 86400)
        const hours = Math.floor((seconds % 86400) / 3600)
        const minutes = Math.floor((seconds % 3600) / 60)
        const rest = seconds % 60
        if (days) {
            return `${days} d ${hours} h`
        }
        if (hours) {
            return `${hours} h ${minutes} min`
        }
        if (minutes) {
            return `${minutes} min ${String(rest).padStart(2, '0')} s`
        }
        return `${rest} s`
    })
</script>

<span class="countdown" title={until.toLocaleString()}>{text}</span>

<style>
    .countdown {
        font-variant-numeric: tabular-nums;
    }
</style>
