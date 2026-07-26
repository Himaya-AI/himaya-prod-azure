# DLP v2 Frontend Implementation Plan

## Document status

- **Purpose:** Replace the legacy DLP dashboard with a frontend for the greenfield DLP v2 control plane.
- **Frontend route:** `/dlp`
- **Backend API:** `/api/dlp/v2`
- **Current state:** Planning; implementation has not started.
- **Backend status:** The v2 runtime, control-plane APIs, and local allow/stop end-to-end test exist.
- **Legacy backend removal:** Deferred until v2 has been tested and deployed.

Related documents:

- [`DLP_V2_STATUS.md`](DLP_V2_STATUS.md) — current backend status and remaining work.
- [`DLP_BACKEND_IMPLEMENTATION_ROADMAP.md`](DLP_BACKEND_IMPLEMENTATION_ROADMAP.md) — broader backend roadmap.
- [`DLP_INGRESS_GATEWAY_PLAN.md`](DLP_INGRESS_GATEWAY_PLAN.md) — transport and gateway design.
- [`../backend/dlp/README.md`](../backend/dlp/README.md) — runtime ownership, APIs, migrations, and local verification.

---

## 1. Goal

Build an authenticated, tenant-scoped DLP administration experience that:

1. Shows gateway and worker health separately from tenant configuration.
2. Lets administrators enable DLP and select monitor or enforce mode.
3. Supports versioned policy editing through a draft-and-publish workflow.
4. Lists DLP messages and their decisions.
5. Lets authorized reviewers release or stop held messages.
6. Uses only `/api/dlp/v2/*`.
7. Preserves the existing `/dlp` route and enterprise navigation behavior.

The frontend must represent the v2 domain directly. It must not recreate the legacy API model or add a compatibility layer.

---

## 2. Current frontend

The existing DLP frontend is primarily one large file:

```text
frontend/src/app/(dashboard)/dlp/page.tsx
```

It contains its types, API calls, tabs, charts, forms, policy modal, provider sync buttons, setup flow, and review actions. It currently calls legacy endpoints under `/api/dlp/*`.

Current tabs:

- Overview
- Policies
- Queue
- Logs
- Settings

Current supporting files:

```text
frontend/src/components/layout/Sidebar.tsx  # /dlp navigation and enterprise visibility
frontend/src/lib/api.ts                     # Axios client and Bearer token interceptor
frontend/src/lib/auth.ts                    # getUser(), token/session helpers
frontend/src/lib/types.ts                   # User role, tier, and organization fields
frontend/src/lib/i18n.ts                    # DLP navigation label
```

There is currently no dedicated DLP API client, type package, hook, or component directory.

---

## 3. Legacy frontend behavior to remove

After the frontend cutover, the `/dlp` page must not call any of these legacy endpoints:

```text
GET    /api/dlp/stats
GET    /api/dlp/events
GET    /api/dlp/policies
POST   /api/dlp/policies
PATCH  /api/dlp/policies/{id}
DELETE /api/dlp/policies/{id}
POST   /api/dlp/policies/{id}/sync-m365
POST   /api/dlp/policies/{id}/sync-gsuite
GET    /api/dlp/queue
POST   /api/dlp/queue/{id}/release
POST   /api/dlp/queue/{id}/block
GET    /api/dlp/setup/status
POST   /api/dlp/setup/enable
POST   /api/dlp/setup/disable
PUT    /api/dlp/setup/config
GET    /api/dlp/engine/status
POST   /api/dlp/classify
```

Remove or replace these legacy UI concepts:

| Legacy concept | v2 replacement |
|---|---|
| Independent policy CRUD and enable toggles | One versioned policy document with draft and publish |
| Queue and event log as separate resources | One message list filtered by state and decision |
| Block action | Stop action |
| One-click setup and category action columns | Tenant settings plus a published policy |
| Provider policy synchronization | Not part of the current v2 API; hide until provider automation exists |
| Synthetic classify form | Not part of the v2 control plane; remove for this phase |
| Legacy engine endpoint | v2 status endpoint |

Delete unused `QuickSetupTab` and `GuideModal` code when the new page is active.

Do not change SaaS/DSPM DLP features during this work. `saas-security`, `saas_dlp_match`, and `cross_cloud_dlp` are separate concerns.

---

## 4. Target information architecture

Keep `/dlp` and use four primary tabs:

```text
/dlp
├── Overview
│   ├── Runtime health
│   ├── Tenant state
│   ├── Message counts
│   └── Recent messages
├── Settings
│   ├── Enabled
│   ├── Monitor / enforce
│   ├── Internal domains
│   ├── Lexicon version
│   └── Active policy version
├── Policy
│   ├── Published policy
│   ├── Draft status
│   ├── Rule editor
│   ├── Save draft
│   └── Publish
└── Messages
    ├── State filters
    ├── Cursor pagination
    ├── Message detail
    └── Release / stop review actions
```

Queue and Logs should not remain separate tabs. They are two views of the same v2 message resource.

---

## 5. Proposed frontend structure

Split the current monolithic page into a route shell, private route components, and a reusable typed client:

```text
frontend/src/
├── app/(dashboard)/dlp/
│   ├── page.tsx
│   └── _components/
│       ├── DlpOverviewTab.tsx
│       ├── DlpSettingsTab.tsx
│       ├── DlpPolicyTab.tsx
│       ├── DlpMessagesTab.tsx
│       ├── DlpMessageDetail.tsx
│       ├── DlpReviewActionDialog.tsx
│       ├── PolicyRuleEditor.tsx
│       └── DlpStatusBadge.tsx
└── lib/dlp/
    ├── types.ts
    ├── api.ts
    ├── policy-options.ts
    └── errors.ts
```

The `_components` directory makes it explicit that these files are private route components, not additional routes.

Do not introduce another HTTP client. `frontend/src/lib/dlp/api.ts` must use the existing Axios instance from `@/lib/api`, which already supplies the Bearer token and transient GET retries.

---

## 6. Authentication, tenant scope, tier, and role behavior

### Authentication

Use the existing `api` client:

```ts
import api from '@/lib/api'
```

The interceptor sends:

```text
Authorization: Bearer <sentinel_token>
```

Do not send a client-selected organization ID. The backend derives tenant scope from the authenticated user.

### Roles

Backend DLP mutations accept:

```text
admin
superadmin
super_admin
```

Reads are available to authenticated users. The frontend should calculate:

```ts
const canManageDlp = ['admin', 'superadmin', 'super_admin']
  .includes((user?.role ?? '').toLowerCase())
```

For users without mutation permission:

- Keep Overview, Policy, Settings, and Messages readable.
- Disable or hide Save, Publish, Release, and Stop controls.
- Display a concise “Administrator permission required” explanation.
- Still handle backend `403` responses; UI gating is not authorization.

### Enterprise tier

The existing Sidebar hides `/dlp` for users outside:

```text
enterprise
enterprise trial
```

The page should also check the locally stored user tier so direct navigation has an upgrade state.

However, DLP v2 endpoints currently authenticate users but do not enforce enterprise tier. Before production rollout, make one explicit product decision:

1. **Recommended:** add enterprise-tier authorization to the v2 backend; or
2. Make DLP v2 available to all authenticated tiers and remove enterprise-only frontend claims.

Do not rely on a `/status` `403` to identify non-enterprise tenants; the current endpoint does not implement that check.

---

## 7. Exact v2 API contracts

All paths below are relative to:

```text
/api/dlp/v2
```

### 7.1 Runtime status

```text
GET /status
```

Response:

```ts
interface DlpStatus {
  status: 'disabled' | 'ready'
  pipeline_enabled: boolean
  mode: 'monitor' | 'enforce'
  classifier_url_configured: boolean
  legacy_independent: boolean
  message_counts: Record<string, number>
  failed_outbox_commands: number
}
```

Important semantics:

- `pipeline_enabled`, `status`, and `classifier_url_configured` describe runtime/environment health.
- `status.mode` currently comes from environment defaults.
- It is not the authoritative tenant mode.
- Tenant enabled/mode must come from `GET /settings`.

The Overview page must load `/status` and `/settings` together.

### 7.2 Tenant settings

```text
GET /settings
PUT /settings
```

Response:

```ts
interface DlpTenantSettings {
  enabled: boolean
  mode: 'monitor' | 'enforce'
  domains: string[]
  lexicon_version: string
  active_policy_version: number | null
}
```

PUT request:

```ts
interface DlpTenantSettingsUpdate {
  enabled: boolean
  mode: 'monitor' | 'enforce'
  domains: string[]
  lexicon_version: string
}
```

`active_policy_version` is read-only and must not be sent in the PUT payload.

Frontend validation:

- Trim and lowercase domains before submission.
- Remove trailing dots.
- Reject values containing `@`, `/`, or whitespace.
- Deduplicate domains.
- Limit the list to 100 entries.
- Require a non-empty lexicon version, maximum 64 characters.
- Explain that monitor records intended actions but permits delivery.
- Show a confirmation before switching from monitor to enforce.

### 7.3 Published policy

```text
GET /policy
```

Returns the active tenant policy. If none has been published, it returns version `0`, status `builtin`, and the built-in policy document.

### 7.4 Policy draft

```text
GET /policy/draft
PUT /policy/draft
```

`GET /policy/draft` returns either a policy response or JSON `null`.

PUT request:

```ts
interface PolicyDraftRequest {
  document: PolicyDocument
}
```

### 7.5 Publish policy

```text
POST /policy/publish
```

No request body. It publishes the latest draft, archives the previous published version, and makes the draft active.

If no draft exists, the backend returns `404`.

Policy response:

```ts
interface PolicyVersion {
  id: string | null
  version: number
  status: 'builtin' | 'draft' | 'published' | 'archived'
  document: PolicyDocument
  created_at: string | null
  published_at: string | null
}
```

### 7.6 Policy document

```ts
type PolicyAction = 'allow' | 'hold' | 'stop'

interface PolicyDocument {
  default_action: PolicyAction
  rules: PolicyRule[]
}

interface PolicyRule {
  rule_id: string
  name: string
  action: PolicyAction
  conditions: RuleConditions
  priority: number
  enabled: boolean
}

interface RuleConditions {
  entity_types: string[]
  detectors: string[]
  min_confidence: number
  min_match_count: number
  llm_classifications: string[]
  llm_categories: string[]
  external_recipients_only: boolean
  recipient_domains: string[]
}
```

Validation:

- Maximum 500 rules.
- `rule_id`: required, unique, maximum 128 characters.
- `name`: required, maximum 255 characters.
- `priority`: integer from 0 through 10,000.
- `min_confidence`: 0 through 1.
- `min_match_count`: at least 1.
- Condition arrays may be empty.

Lower priority numbers win ties. The evaluator still applies action precedence: stop outranks hold, which outranks allow.

### 7.7 Message list

```text
GET /messages?state=<state>&before=<ISO datetime>&limit=<1..200>
```

Response:

```ts
interface DlpMessageList {
  items: DlpMessageSummary[]
  next_cursor: string | null
}

interface DlpMessageSummary {
  message_id: string
  envelope_from: string
  envelope_to: string[]
  state: string
  received_at: string
  intended_action: string | null
  effective_action: string | null
  explanation: string | null
}
```

Use `next_cursor` as the next request’s `before` parameter. Do not calculate offsets in the browser.

Known states include:

```text
received
decided
release_requested
stop_requested
```

The review API also accepts a held message whose state is `held`. The frontend must not infer reviewability from state alone.

### 7.8 Message detail

```text
GET /messages/{message_id}
```

The current endpoint returns the same `DlpMessageSummary` shape as the list. It does not yet include subject, content preview, findings, matched rules, extraction limitations, policy version, or review history.

This is a backend prerequisite for a complete reviewer experience. See section 9.

### 7.9 Release and stop

```text
POST /messages/{message_id}/release
POST /messages/{message_id}/stop
```

Request:

```ts
interface DlpReviewActionRequest {
  reason: string
  idempotency_key: string
}
```

Response:

```ts
interface DlpReviewActionResponse {
  message_id: string
  action: 'release' | 'stop'
  command_id: string
  status: 'queued' | 'already_queued'
}
```

Rules:

- Reason is required, 3 through 2,000 characters.
- Idempotency key is required, 8 through 255 characters.
- Use `crypto.randomUUID()`.
- Create one key per user action and retain it across retries.
- Do not create a different key because a request timed out.
- Only administrators may mutate.
- Only messages with an effective hold decision and valid state may be reviewed.
- A stale or invalid review attempt returns `409`.

---

## 8. Typed API client

Create thin wrappers in `frontend/src/lib/dlp/api.ts`:

```ts
getDlpStatus()
getDlpSettings()
updateDlpSettings(payload)
getActiveDlpPolicy()
getDlpPolicyDraft()
saveDlpPolicyDraft(document)
publishDlpPolicy()
listDlpMessages(params)
getDlpMessage(messageId)
releaseDlpMessage(messageId, payload)
stopDlpMessage(messageId, payload)
```

Requirements:

- Use the existing `api` Axios instance.
- Return typed response data, not full Axios responses.
- Keep endpoint strings in this client, not scattered through components.
- Convert unknown server errors into a consistent displayable error.
- Preserve backend `detail` messages for `400`, `403`, `404`, and `409`.
- Do not automatically retry mutations.
- Existing GET retry behavior may remain.

---

## 9. Backend prerequisites and decisions

These items must be resolved before calling the frontend complete.

### 9.1 Enterprise authorization

The backend currently does not enforce enterprise tier for v2 routes. Add a backend dependency or formally change the product entitlement.

This does not block development of the client and read-only tabs, but it blocks secure production entitlement.

### 9.2 Rich message detail

Release/stop review should not be performed from envelope data and one explanation string alone.

Add a safe tenant-scoped detail response containing at least:

```ts
interface DlpMessageDetail extends DlpMessageSummary {
  subject: string | null
  reviewable: boolean
  policy_version: string | null
  matched_rule_ids: string[]
  findings: Array<{
    detector: string
    entity_type: string
    confidence: number
    part_reference?: string
  }>
  extraction_limitations: Array<{
    code: string
    detail: string
  }>
  sanitized_preview?: string
  review_history: Array<{
    action: 'release' | 'stop'
    reason: string
    actor_user_id: string
    created_at: string
  }>
}
```

Security requirements:

- Never expose raw MIME or unrestricted attachment bytes through this endpoint.
- Redact sensitive values where possible; findings should reference type and location rather than repeat secrets.
- Bound preview size.
- Sanitize HTML before rendering, or return plain text only.
- Enforce organization scope on every lookup.

If this backend addition is deferred, ship Messages as an operational list and do not present the release/stop workflow as a complete review experience.

### 9.3 Policy metadata

The policy schema accepts strings, but a usable editor needs supported values.

Preferred endpoint:

```text
GET /api/dlp/v2/policy/metadata
```

Suggested response:

```ts
interface DlpPolicyMetadata {
  detectors: Array<{ value: string; label: string }>
  entity_types: Array<{ value: string; label: string; category?: string }>
  llm_classifications: Array<{ value: string; label: string }>
  llm_categories: Array<{ value: string; label: string }>
}
```

Until that endpoint exists, keep the supported values in `policy-options.ts`, derived from the classifier contract and covered by tests. Do not silently invent values in the UI.

Known built-in values include:

```text
detectors:
  credential
  lexicon

entity types:
  CREDIT_CARD
  IBAN_CODE
  US_BANK_NUMBER
  US_SSN
  US_PASSPORT
  US_DRIVER_LICENSE
  UK_NHS
  UK_NINO
  IN_AADHAAR
  IN_PAN

LLM classifications:
  SENSITIVE
  UNCERTAIN
```

This list is not necessarily exhaustive and must be reconciled with the deployed classifier.

### 9.4 Status semantics

The status endpoint currently mixes runtime settings with a `mode` field that may differ from tenant mode. The frontend can avoid confusion by treating:

- `/status` as infrastructure health.
- `/settings` as tenant behavior.

A later backend cleanup may rename or restructure the status response.

---

## 10. Tab behavior

### 10.1 Overview

Load in parallel:

```text
GET /status
GET /settings
GET /messages?limit=10
```

Display:

- Runtime pipeline ready/disabled.
- Tenant enabled/disabled.
- Tenant monitor/enforce mode.
- Classifier configured/not configured.
- Active policy version.
- Failed outbox command count.
- Message counts by state.
- Ten most recent messages.

Do not recreate the legacy risk/action charts unless a v2 analytics endpoint exists. Avoid calculating authoritative totals from one paginated page.

Provide clear warnings for:

- Runtime pipeline disabled.
- Tenant DLP disabled.
- Classifier URL missing.
- Failed outbox commands greater than zero.
- Enforce mode with no published tenant policy (built-in policy is active).

### 10.2 Settings

Fields:

- DLP enabled toggle.
- Mode selector: monitor or enforce.
- Internal domains list editor.
- Lexicon version.
- Active policy version, read-only.

Behavior:

- Load through `GET /settings`.
- Keep server values separate from editable form values.
- Track dirty state.
- Disable Save when unchanged, invalid, submitting, or unauthorized.
- Confirm monitor → enforce.
- On success, replace local state with the server response.
- On error, preserve unsaved values.
- Warn before navigation with unsaved changes if the application already has a standard pattern for this.

### 10.3 Policy

Load active policy and draft in parallel.

Initialization:

1. If a draft exists, edit its document.
2. If draft is `null`, clone the active/built-in document into local editor state.
3. Mark this clone as unsaved.
4. First Save calls `PUT /policy/draft`.
5. Publish remains disabled until a server-side draft exists.

Display:

- Active version and status.
- Draft version/status if present.
- Default action.
- Rules ordered by priority.
- Unsaved changes indicator.
- Last published timestamp.

Rule editor:

- Add a rule with a generated stable `rule_id`.
- Edit name, action, priority, enabled state, and conditions.
- Duplicate a rule with a new ID.
- Delete a draft rule with confirmation.
- Validate IDs are unique before submission.
- Use multi-select controls for detector/entity/LLM fields.
- Use a 0–1 numeric input or clearly labelled percentage conversion for confidence.
- Explain that external-only uses tenant domains from Settings.
- Do not mutate the active policy directly.

Save draft:

- Send the entire `PolicyDocument`.
- Preserve form state on validation/server failure.
- Replace local draft metadata with the response on success.

Publish:

- Require a saved draft.
- Show a summary confirmation: version, rule count, enabled rules, and default action.
- Explain that published policies are immutable.
- On success, refresh active policy, draft, and settings.
- Expect the draft endpoint to return `null` after publication.

### 10.4 Messages

Display columns:

- Received time.
- Envelope sender.
- Recipients.
- State.
- Intended action.
- Effective action.
- Explanation summary.
- Review status/action.

Filters:

- All states.
- Held/reviewable.
- Decided.
- Release requested.
- Stop requested.

Until `reviewable` is returned by the backend, identify a potential held row as:

```text
effective_action == "hold" AND state in {"decided", "held"}
```

The server remains authoritative and may return `409`.

Pagination:

- Store pages or append rows using `next_cursor`.
- Pass the cursor as `before`.
- Disable “Load more” when `next_cursor` is null.
- Deduplicate by `message_id` when appending.
- Reset rows/cursor when the state filter changes.

Detail:

- If only the current summary endpoint exists, show the available metadata and explain that content preview is unavailable.
- When rich detail exists, show matched rules, findings, limitations, bounded preview, and audit history.

Review:

- Release and Stop open a confirmation dialog.
- Require a reason.
- Create and retain one idempotency key for the submission.
- Disable duplicate clicks while pending.
- On `queued` or `already_queued`, close the dialog and refresh the row/list.
- On `409`, explain that the message is no longer reviewable and refresh.
- Never optimistically claim delivery or stopping succeeded; the API only confirms the command was queued.

---

## 11. Error, loading, and empty states

Each tab must have:

- Initial skeleton/loading state.
- Explicit empty state.
- Recoverable error state with Retry.
- Permission-denied state.
- Mutation progress state.
- Success feedback.

Minimum error mapping:

| Status | UI behavior |
|---|---|
| `400` / `422` | Show field or policy validation detail |
| `401` | Existing global auth behavior handles session expiration |
| `403` | Show insufficient role/tier message |
| `404` | Show missing resource; for publish, “Save a draft first” |
| `409` | Show stale/conflicting state and refresh relevant data |
| `429`, `502`, `503`, `504` | GET client retries; otherwise show temporary service error |

Do not discard unsaved settings or policy edits because a request failed.

---

## 12. Accessibility and safety

- All form controls require visible labels.
- Tabs and dialogs must support keyboard navigation.
- Dialog focus must be trapped and restored.
- Status must not be communicated by color alone.
- Destructive Stop and Publish actions need confirmation.
- Enforce-mode confirmation must explain that messages can be held or stopped.
- Recipient lists and explanations must wrap safely.
- Never render message HTML using `dangerouslySetInnerHTML`.
- Do not log message content, policy secrets, or auth tokens in browser console output.
- Use UTC timestamps from the API and render localized dates consistently.

---

## 13. Implementation phases

### Phase 0 — Resolve contracts and prerequisites

- Confirm enterprise entitlement behavior.
- Decide whether rich message detail is required for the first release.
- Reconcile supported detector/entity/LLM values with the classifier.
- Freeze TypeScript contracts against backend schemas.

Exit criteria:

- No unresolved API shape assumptions.
- Backend prerequisites have owners and are either completed or explicitly deferred.

### Phase 1 — Foundation

- Create `lib/dlp/types.ts`.
- Create the typed API client.
- Add consistent DLP error parsing.
- Replace the monolithic route with a tab shell.
- Preserve Sidebar navigation and enterprise visibility.
- Add role capability calculation.

Exit criteria:

- Route loads without calling legacy endpoints.
- API client has unit-testable typed wrappers.

### Phase 2 — Overview and Settings

- Implement Overview with status, settings, counts, and recent messages.
- Implement Settings with validation and admin-only Save.
- Confirm monitor → enforce.

Exit criteria:

- Settings round-trip correctly.
- Runtime health and tenant state are displayed separately.

### Phase 3 — Policy

- Implement active/draft loading.
- Implement null-draft cloning behavior.
- Build the rule editor.
- Save complete drafts.
- Publish with confirmation and refresh.

Exit criteria:

- Built-in policy can be cloned into a new draft.
- Draft survives reload.
- Publish updates active policy version.
- Duplicate IDs and invalid ranges are blocked.

### Phase 4 — Messages and review

- Implement filtered cursor list.
- Add message detail.
- Add Release/Stop dialogs.
- Handle idempotency and stale `409` responses.

Exit criteria:

- No duplicate rows during pagination.
- Held messages can be reviewed by admins.
- Non-admins cannot invoke mutations.
- UI accurately distinguishes queued commands from completed gateway actions.

### Phase 5 — Legacy UI cleanup

- Remove legacy types, API calls, tabs, modals, charts, provider sync, setup, and classify-test code.
- Ensure no `/api/dlp/*` call remains except `/api/dlp/v2/*`.
- Keep `/dlp` navigation and relevant i18n keys.

Exit criteria:

- Repository search finds no legacy endpoint references in the DLP page/client.
- The old frontend no longer depends on the legacy backend.

### Phase 6 — Verification and rollout

- Run lint and production build.
- Test all supported roles and tiers.
- Test against local compose and a deployed environment.
- Roll out with legacy enforcement disabled wherever v2 enforcement is enabled.

Exit criteria:

- Acceptance checklist passes.
- Network inspection shows only v2 DLP calls.
- No environment has both legacy and v2 enforcement acting on the same message.

---

## 14. Testing plan

### Static verification

From `frontend/`:

```bash
npm run lint
npm run build
```

### Client tests

Add tests if/when the frontend test runner is configured. At minimum cover:

- Correct endpoint and payload for every wrapper.
- Nullable draft response.
- Cursor parameter serialization.
- Review idempotency key reuse.
- Backend error detail extraction.

### Component behavior

Verify:

- Loading, error, empty, and success states.
- Direct `/dlp` navigation as non-enterprise user.
- Viewer/analyst reads with mutation controls unavailable.
- Admin settings save.
- Monitor → enforce confirmation.
- Draft absent → clone active → save.
- Draft save failure preserves edits.
- Publish without saved draft is disabled.
- Publish success updates active version.
- Message filter resets cursor.
- Cursor pages append without duplicates.
- Review reason validation.
- Release/Stop `409` refreshes stale data.
- Double click does not create duplicate review actions.

### API integration

Against the v2 backend:

1. Load status and settings.
2. Update settings in monitor mode.
3. Load built-in policy.
4. Create and reload a draft.
5. Publish the draft.
6. Verify `active_policy_version`.
7. List messages produced by local e2e.
8. Review a held message when a hold test fixture is available.

### Browser/network audit

Confirm:

- All DLP requests use `/api/dlp/v2`.
- Bearer auth is present.
- No organization identifier is selected or injected by the client.
- No sensitive message content is logged.
- No mutation is automatically retried by custom frontend code.

---

## 15. Acceptance checklist

### Navigation and access

- [ ] `/dlp` remains in the enterprise Sidebar.
- [ ] Direct navigation has an explicit tier state.
- [ ] Authenticated read-only users can view permitted data.
- [ ] Only DLP admins can Save, Publish, Release, or Stop.
- [ ] Backend entitlement decision is implemented before production rollout.

### Overview

- [ ] Runtime health and tenant settings are loaded separately.
- [ ] Pipeline, classifier, outbox failures, tenant enabled state, and tenant mode are visible.
- [ ] Message counts and recent messages render safely.
- [ ] No unsupported legacy analytics are presented as authoritative.

### Settings

- [ ] Settings GET/PUT round-trip.
- [ ] Domains are validated and deduplicated.
- [ ] Active policy version is read-only.
- [ ] Monitor → enforce requires confirmation.
- [ ] Failed saves preserve edits.

### Policy

- [ ] Active and draft policies are visually distinct.
- [ ] A null draft initializes from active/built-in policy.
- [ ] Full policy documents can be saved.
- [ ] Rules have unique IDs and valid ranges.
- [ ] Publish requires a saved draft and confirmation.
- [ ] Publish refreshes active policy/settings and clears draft state.

### Messages

- [ ] Messages support server cursor pagination.
- [ ] State filter changes reset pagination.
- [ ] Message IDs are deduplicated across pages.
- [ ] Detail limitations are honest until rich detail exists.
- [ ] Review actions require a reason.
- [ ] Idempotency keys are retained across retries.
- [ ] `409` stale actions refresh state.
- [ ] Queued is not presented as completed delivery.

### Cutover quality

- [ ] The DLP frontend makes no legacy API calls.
- [ ] Provider sync, legacy setup, and synthetic classify UI are removed.
- [ ] `npm run lint` passes.
- [ ] `npm run build` passes.
- [ ] Local and deployed smoke tests pass.
- [ ] Legacy enforcement is disabled wherever v2 enforcement runs.

---

## 16. Out of scope

This frontend phase does not include:

- Removing the legacy backend.
- Dropping legacy DLP tables.
- Provider transport-rule automation for Microsoft 365 or Google Workspace.
- Editing detector implementation details.
- Raw MIME or attachment download.
- SaaS/DSPM DLP redesign.
- Reworking DLP fields shown by Drafts, Message Trace, or Threats.
- Recreating legacy charts without a v2 analytics contract.

These may be separate follow-up projects.

---

## 17. Rollout and rollback

Recommended rollout:

1. Deploy backend prerequisites.
2. Deploy the v2 frontend behind the existing enterprise navigation gate.
3. Keep tenant mode at monitor initially.
4. Verify status, settings, draft/publish, message list, and review permissions.
5. Enable enforce mode for a controlled tenant.
6. Confirm legacy enforcement is disabled for that environment/tenant.
7. Observe outbox failures, message states, and gateway outcomes.
8. Expand rollout.
9. Remove the legacy backend only after the v2 deployment is accepted.

Frontend rollback:

- Roll back the frontend deployment if the v2 UI is unusable.
- Do not enable legacy enforcement automatically as part of a UI rollback.
- Enforcement ownership must remain an explicit operational decision to prevent double processing.

---

## 18. Definition of done

The DLP v2 frontend is complete when:

1. `/dlp` uses only `/api/dlp/v2`.
2. Runtime health, tenant settings, policy lifecycle, and messages are represented accurately.
3. Administrators can save settings and draft/publish policy.
4. Held-message review has sufficient safe context and supports idempotent Release/Stop.
5. Tier and role behavior is enforced consistently, including backend entitlement.
6. Lint, production build, local integration, and deployed smoke tests pass.
7. The frontend no longer requires legacy DLP routes.
8. Operational documentation clearly prevents simultaneous legacy and v2 enforcement.
