<script lang="ts">
    /**
     * Grant Access / Edit Access: one dialog for giving a user access to a target
     * as an account, and for what limits that access.
     *
     * Four ideas, kept apart on purpose because they are enforced separately by
     * the server:
     *
     *   - the assignment's expiry: when the permission itself stops (and live
     *     sessions end);
     *   - the schedule: on which days and hours a connection may START (a window
     *     closing does not end a session that is already open);
     *   - the approval request's expiry: how long a request for out-of-hours
     *     access waits for an answer;
     *   - the approval's validity: how long an approval, once given, can be used
     *     to start one connection.
     *
     * The simple grant (a user, a target, an account) is three fields and a
     * button; the rest is behind switches. The server checks everything again.
     */
    import { untrack } from 'svelte'
    import {
        AccessAssignmentSource,
        type AccessAssignment,
        type AccessAssignmentOptions,
        AccessRuleAction,
        type AccessRules,
        api,
        type Role,
        type Target,
        TargetAccountAuthMethod,
        type User,
    } from 'admin/lib/api'
    import {
        addDuration,
        cloneRules,
        defaultRules,
        describeRules,
        DURATION_UNITS,
        type DurationUnit,
        formatSeconds,
        validateRules,
    } from 'common/accessRules'
    import { stringifyError } from 'common/errors'
    import Button from 'ui/Button.svelte'
    import Callout from 'ui/Callout.svelte'
    import Combobox, { type ComboboxOption } from 'ui/Combobox.svelte'
    import Icon from 'ui/Icon.svelte'
    import Input from 'ui/Input.svelte'
    import Modal from 'ui/Modal.svelte'
    import SegmentedControl from 'ui/SegmentedControl.svelte'
    import Select from 'ui/Select.svelte'
    import Textarea from 'ui/Textarea.svelte'
    import Toggle from 'ui/Toggle.svelte'
    import { toast } from 'ui/toasts.svelte'
    import ApproverPicker from './ApproverPicker.svelte'
    import DurationPicker from './DurationPicker.svelte'
    import ScheduleEditor from './ScheduleEditor.svelte'

    interface Props {
        open: boolean
        /** The direct assignment being edited; `null` to grant new access. */
        editing?: AccessAssignment | null
        users: User[]
        targets: Target[]
        /** Preselect these (from a filter, or the page the admin came from). */
        initialUser?: string
        initialTarget?: string
        onsaved: () => void
    }

    let {
        open = $bindable(),
        editing = null,
        users,
        targets,
        initialUser = '',
        initialTarget = '',
        onsaved,
    }: Props = $props()

    const METHOD_LABELS: Record<TargetAccountAuthMethod, string> = {
        [TargetAccountAuthMethod.StoredCredential]: 'Stored credential',
        [TargetAccountAuthMethod.TypedPassword]: 'Password typed when connecting',
        [TargetAccountAuthMethod.DirectoryPassword]: "User's own directory password",
    }

    // ---- the form ----
    let userId = $state('')
    let targetId = $state('')
    let accountId = $state('')
    let enabled = $state(true)
    let note = $state('')

    type ExpiryMode = 'never' | 'at' | 'after'
    let expiryMode = $state<ExpiryMode>('never')
    let expiresAtInput = $state('')
    let afterAmount = $state('1')
    let afterUnit = $state<DurationUnit>('days')

    let restrict = $state(false)
    let rules = $state<AccessRules>(defaultRules())
    let requestExpiry = $state<number | undefined>(900)
    let validFor = $state<number | undefined>(1800)
    let approverUserIds = $state<string[]>([])
    let approverRoleIds = $state<string[]>([])

    let roles = $state<Role[]>([])
    let rolesRequested = false

    let options = $state<AccessAssignmentOptions | null>(null)
    let optionsLoading = $state(false)
    let optionsError = $state<string | null>(null)
    let saving = $state(false)
    let saveError = $state<string | null>(null)

    function toLocalInput(date?: Date): string {
        if (!date) {
            return ''
        }
        const local = new Date(date.getTime() - date.getTimezoneOffset() * 60000)
        return local.toISOString().slice(0, 16)
    }

    function reset() {
        const existing = editing
        userId = existing?.userId ?? initialUser
        targetId = existing?.targetId ?? initialTarget
        accountId = existing?.accountId ?? ''
        enabled = existing?.enabled ?? true
        note = existing?.note ?? ''
        expiryMode = existing?.expiresAt ? 'at' : 'never'
        expiresAtInput = toLocalInput(existing?.expiresAt)
        afterAmount = '1'
        afterUnit = 'days'
        const saved = existing?.rules
        restrict = !!saved
        rules = saved ? cloneRules(saved) : defaultRules()
        requestExpiry = saved?.approval?.requestExpirySeconds ?? 900
        validFor = saved?.approval?.validForSeconds ?? 1800
        approverUserIds = [...(saved?.approval?.approverUserIds ?? [])]
        approverRoleIds = [...(saved?.approval?.approverRoleIds ?? [])]
        saveError = null
        saving = false
    }

    // Start from a clean form each time the dialog opens.
    $effect(() => {
        if (open) {
            untrack(reset)
        }
    })

    // Approvers are chosen among access groups: load them the first time they are wanted.
    $effect(() => {
        if (open && restrict && !rolesRequested) {
            rolesRequested = true
            api.getRoles()
                .then(loaded => {
                    roles = loaded
                })
                .catch(() => {
                    rolesRequested = false
                })
        }
    })

    // What can be granted depends on the user and the target: ask the server.
    $effect(() => {
        const user = userId
        const target = targetId
        options = null
        optionsError = null
        if (!open || !user || !target) {
            return
        }
        let cancelled = false
        optionsLoading = true
        api.getAccessAssignmentOptions({ userId: user, targetId: target })
            .then(loaded => {
                if (cancelled) {
                    return
                }
                options = loaded
                const usable = loaded.accounts.filter(a => !a.problem)
                const only = usable[0]
                if (!untrack(() => accountId) && usable.length === 1 && only) {
                    accountId = only.id
                }
            })
            .catch(async e => {
                if (!cancelled) {
                    optionsError = await stringifyError(e)
                }
            })
            .finally(() => {
                if (!cancelled) {
                    optionsLoading = false
                }
            })
        return () => {
            cancelled = true
        }
    })

    // ---- the pickers ----
    const userOptions = $derived<ComboboxOption[]>(
        [...users]
            .sort((a, b) => a.username.localeCompare(b.username))
            .map(user => ({
                value: user.id,
                label: user.username,
                description: user.description || undefined,
                tag: user.ldapServerId ? 'Directory' : undefined,
                keywords: user.ldapServerId ? 'ldap ad active directory linked' : '',
            })),
    )

    const targetOptions = $derived<ComboboxOption[]>(
        [...targets]
            .sort((a, b) => a.name.localeCompare(b.name))
            .map(target => ({
                value: target.id,
                label: target.name,
                description: target.description
                    ? `${target.options.kind}, ${target.description}`
                    : target.options.kind,
                keywords: target.options.kind,
            })),
    )

    const accountOptions = $derived<ComboboxOption[]>(
        (options?.accounts ?? []).map(account => ({
            value: account.id,
            label: account.signsInAs ?? account.account,
            description: account.problem ?? METHOD_LABELS[account.authMethod],
            keywords: account.account,
            disabled: !!account.problem && account.id !== editing?.accountId,
        })),
    )

    const chosenUser = $derived(users.find(user => user.id === userId))
    const chosenTarget = $derived(targets.find(target => target.id === targetId))
    const chosenAccount = $derived(
        options?.accounts.find(account => account.id === accountId),
    )
    const needsAccount = $derived(!!options?.usesAccounts)

    // ---- expiry ----
    const afterCount = $derived(Number(afterAmount))
    const afterValid = $derived(
        Number.isInteger(afterCount) && afterCount >= 1 && afterCount <= 10000,
    )

    function expiryDate(): Date | undefined {
        if (expiryMode === 'at') {
            return expiresAtInput ? new Date(expiresAtInput) : undefined
        }
        if (expiryMode === 'after' && afterValid) {
            return addDuration(new Date(), afterCount, afterUnit)
        }
        return undefined
    }

    // Follows the inputs it reads; the date itself is only worked out again when they change.
    const previewExpiry = $derived(expiryDate())

    const expiryProblem = $derived.by(() => {
        if (expiryMode === 'at') {
            if (!expiresAtInput) {
                return 'Choose when the access ends.'
            }
            if (new Date(expiresAtInput).getTime() <= Date.now()) {
                return 'Choose a time in the future.'
            }
        }
        if (expiryMode === 'after' && !afterValid) {
            return 'Enter a whole number of 1 or more.'
        }
        return undefined
    })

    const scheduleProblem = $derived(restrict ? validateRules(rules) : undefined)
    const asksForApproval = $derived(
        restrict && rules.outside === AccessRuleAction.RequireApproval,
    )

    const canSave = $derived(
        !!userId &&
            !!targetId &&
            !!options &&
            (!needsAccount || !!accountId) &&
            !expiryProblem &&
            !scheduleProblem &&
            !saving,
    )

    function when(date: Date): string {
        return date.toLocaleString(undefined, {
            weekday: 'short',
            year: 'numeric',
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
        })
    }

    // ---- the review ----
    const review = $derived.by(() => {
        const lines: string[] = []
        const who = chosenUser?.username ?? 'The user'
        const where = chosenTarget?.name ?? 'the target'
        const account = chosenAccount
            ? ` as ${chosenAccount.signsInAs ?? chosenAccount.account}`
            : ''
        lines.push(`${who} may connect to ${where}${account}.`)
        lines.push(enabled ? 'The access is on.' : 'The access starts switched off.')
        lines.push(
            previewExpiry
                ? `It ends ${when(previewExpiry)}.`
                : 'It does not expire.',
        )
        if (restrict) {
            lines.push(`Connections can start: ${describeRules(rules)}.`)
            if (asksForApproval) {
                lines.push(
                    `Otherwise the user asks for approval: the request waits ${
                        requestExpiry ? formatSeconds(requestExpiry) : 'the server default'
                    }, and an approval can start a connection for ${
                        validFor ? formatSeconds(validFor) : 'as long as the request waits'
                    }, once.`,
                )
            } else if (rules.outside === AccessRuleAction.Deny) {
                lines.push('Otherwise connections are refused.')
            }
        } else {
            lines.push('No time limits. Access policies, second factors and session limits still apply.')
        }
        return lines
    })

    async function save() {
        saving = true
        saveError = null
        const expires = expiryDate()
        const payload: AccessRules | undefined = restrict
            ? {
                  ...cloneRules(rules),
                  approval: {
                      requestExpirySeconds: requestExpiry,
                      validForSeconds: validFor,
                      approverUserIds,
                      approverRoleIds,
                  },
              }
            : undefined
        try {
            if (editing?.id) {
                await api.updateAccessAssignment({
                    id: editing.id,
                    updateAccessAssignmentRequest: {
                        accountId: accountId || undefined,
                        enabled,
                        expiresAt: expires,
                        note,
                        rules: payload,
                        removeRules: !restrict && !!editing.rules,
                    },
                })
                toast.success('Access updated')
            } else {
                await api.createAccessAssignment({
                    createAccessAssignmentRequest: {
                        userId,
                        targetId,
                        accountId: accountId || undefined,
                        enabled,
                        expiresAt: expires,
                        note,
                        rules: payload,
                    },
                })
                toast.success('Access granted')
            }
            open = false
            onsaved()
        } catch (e) {
            saveError = await stringifyError(e)
        } finally {
            saving = false
        }
    }
</script>

<Modal
    bind:open
    title={editing ? 'Edit Access' : 'Grant Access'}
    size="lg"
    class="wg-grant-modal"
>
    <form
        id="grant-access-form"
        class="form"
        onsubmit={event => {
            event.preventDefault()
            if (canSave) {
                save()
            }
        }}
    >
        <section class="section" aria-labelledby="grant-identity">
            <h3 id="grant-identity">Access</h3>
            <div class="pair">
                <Combobox
                    label="User"
                    placeholder="Search by username or name"
                    options={userOptions}
                    bind:value={userId}
                    disabled={!!editing}
                    required
                    emptyText="No user matches"
                    hint={chosenUser
                        ? chosenUser.ldapServerId
                            ? 'Linked to a directory: their own directory account can be granted.'
                            : 'Not linked to a directory.'
                        : undefined}
                />
                <Combobox
                    label="Target"
                    placeholder="Search targets"
                    options={targetOptions}
                    bind:value={targetId}
                    disabled={!!editing}
                    required
                    emptyText="No target matches"
                />
            </div>

            {#if optionsError}
                <Callout tone="danger" title="Could not load the target's accounts">
                    {optionsError}
                </Callout>
            {:else if options?.usesAccounts}
                {#if options.accounts.length}
                    <Combobox
                        label="Account"
                        placeholder="Choose the account to sign in as"
                        options={accountOptions}
                        bind:value={accountId}
                        loading={optionsLoading}
                        required
                        clearable={false}
                        emptyText="This target has no usable account"
                        hint="From the target's Accounts. A linked directory account signs each user in as themselves."
                    />
                {:else}
                    <Callout tone="warning" title="This target has no accounts yet">
                        Add one on
                        <a href="#/config/targets/{targetId}">the target's page</a>,
                        under Accounts.
                    </Callout>
                {/if}
            {:else if options}
                <p class="plain">
                    <Icon name="check" size={14} />
                    This protocol has no remote accounts: the grant is access to the
                    target itself.
                </p>
            {/if}
        </section>

        <section class="section" aria-labelledby="grant-validity">
            <h3 id="grant-validity">Validity</h3>

            <Toggle
                label="Access is on"
                checked={enabled}
                onchange={value => (enabled = value)}
                hint="Switch off to keep the grant without letting anyone use it."
            />

            <div class="block">
                <SegmentedControl
                    label="Access ends"
                    size="compact"
                    value={expiryMode}
                    onchange={value => (expiryMode = value)}
                    segments={[
                        { value: 'never', label: 'Never' },
                        { value: 'at', label: 'On a date' },
                        { value: 'after', label: 'After a while' },
                    ]}
                />
                {#if expiryMode === 'at'}
                    <Input
                        label="Ends at"
                        type="datetime-local"
                        bind:value={expiresAtInput}
                        error={expiryProblem}
                        hint="Your local time. The user loses access then, and live sessions end."
                    />
                {:else if expiryMode === 'after'}
                    <div class="after">
                        <Input
                            label="Ends after"
                            type="number"
                            min={1}
                            inputmode="numeric"
                            bind:value={afterAmount}
                            invalid={!afterValid}
                        />
                        <Select
                            label="Unit"
                            options={DURATION_UNITS}
                            bind:value={afterUnit}
                        />
                    </div>
                    <p class="hint" aria-live="polite">
                        {#if previewExpiry}
                            Ends {when(previewExpiry)}, counted from when you save.
                        {:else}
                            {expiryProblem}
                        {/if}
                    </p>
                {/if}
            </div>

            <div class="block">
                <Toggle
                    label="Limit when connections can start"
                    checked={restrict}
                    onchange={value => (restrict = value)}
                    hint="By day and hour, in a timezone. A connection that is already open is not ended when a window closes."
                />
                {#if restrict}
                    <div class="indent">
                        <ScheduleEditor bind:rules />

                        {#if asksForApproval}
                            <div class="approval">
                                <h4>Approval outside these hours</h4>
                                <div class="pair">
                                    <DurationPicker
                                        label="Request waits"
                                        bind:value={requestExpiry}
                                        unsetLabel="Server default"
                                        hint="How long an approver has to answer."
                                    />
                                    <DurationPicker
                                        label="Approval valid for"
                                        bind:value={validFor}
                                        unsetLabel="Same as the request"
                                        hint="How long an approval can start a connection. Used once."
                                    />
                                </div>
                                <ApproverPicker
                                    bind:userIds={approverUserIds}
                                    bind:roleIds={approverRoleIds}
                                    {users}
                                    {roles}
                                />
                            </div>
                        {/if}
                    </div>
                {/if}
            </div>
        </section>

        <section class="section" aria-labelledby="grant-details">
            <h3 id="grant-details">Details</h3>
            <Textarea
                label="Note"
                rows={2}
                resize="vertical"
                placeholder="Why, ticket number… (optional)"
                bind:value={note}
            />
        </section>

        {#if userId && targetId && options && (!needsAccount || chosenAccount)}
            <section class="review" aria-labelledby="grant-review">
                <h3 id="grant-review">Review</h3>
                <ul>
                    {#each review as line (line)}
                        <li>{line}</li>
                    {/each}
                </ul>
                {#if options.current.length && !editing}
                    <p class="muted">
                        Already there:
                        {options.current
                            .map(
                                current =>
                                    `${current.account ?? 'the target'} (${
                                        current.source === AccessAssignmentSource.Group
                                            ? `group ${current.groupName}`
                                            : 'direct'
                                    }, ${current.status})`,
                            )
                            .join('; ')}.
                    </p>
                {/if}
            </section>
        {/if}

        {#if saveError}
            <Callout tone="danger" title="Could not save">{saveError}</Callout>
        {/if}
    </form>

    {#snippet footer()}
        <Button variant="ghost" onclick={() => (open = false)}>Cancel</Button>
        <Button
            variant="primary"
            type="submit"
            form="grant-access-form"
            icon={editing ? 'check' : 'access'}
            disabled={!canSave}
        >
            {saving ? 'Saving…' : editing ? 'Save changes' : 'Grant Access'}
        </Button>
    {/snippet}
</Modal>

<style>
    .form {
        display: flex;
        flex-direction: column;
        gap: var(--wg-space-lg);
    }

    .section {
        display: flex;
        flex-direction: column;
        gap: var(--wg-space-md);
        padding-bottom: var(--wg-space-lg);
        border-bottom: var(--wg-border-width) solid var(--wg-border);
    }

    h3 {
        margin: 0;
        font: var(--wg-text-label-md);
        color: var(--wg-text);
    }

    h4 {
        margin: 0;
        font: var(--wg-text-label-md);
        color: var(--wg-text);
    }

    .pair {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: var(--wg-space-md);
    }

    @media (max-width: 640px) {
        .pair {
            grid-template-columns: 1fr;
        }
    }

    .block {
        display: flex;
        flex-direction: column;
        gap: var(--wg-space-sm);
    }

    .indent {
        display: flex;
        flex-direction: column;
        gap: var(--wg-space-md);
        padding-left: var(--wg-space-md);
        border-left: 2px solid var(--wg-primary-tint-strong);
    }

    .approval {
        display: flex;
        flex-direction: column;
        gap: var(--wg-space-md);
        padding: var(--wg-space-md);
        background: var(--wg-secondary-tint);
        border-radius: var(--wg-radius-panel);
    }

    .after {
        display: grid;
        grid-template-columns: 8rem 10rem;
        gap: var(--wg-space-md);
    }

    .hint {
        margin: 0;
        font: var(--wg-text-label-sm);
        color: var(--wg-text-subtle);
    }

    .plain {
        display: flex;
        align-items: center;
        gap: var(--wg-space-sm);
        margin: 0;
        color: var(--wg-text-muted);
        font: var(--wg-text-body-md);
    }

    .review {
        padding: var(--wg-space-md);
        background: var(--wg-primary-tint);
        border: var(--wg-border-width) solid var(--wg-primary);
        border-radius: var(--wg-radius-panel);
    }

    .review h3 {
        margin-bottom: var(--wg-space-xs);
    }

    .review ul {
        margin: 0;
        padding-left: var(--wg-space-lg);
        font: var(--wg-text-body-md);
    }

    .muted {
        margin: var(--wg-space-sm) 0 0;
        color: var(--wg-text-muted);
        font: var(--wg-text-label-md);
    }
</style>
