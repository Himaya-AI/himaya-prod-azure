# DLP v2 backend

`backend/dlp` is the control plane and application-worker boundary between
`dlp-gateway` and `dlp-classifier`.

For shipped-vs-remaining status and cutover notes, see
[`docs/DLP_V2_STATUS.md`](../../docs/DLP_V2_STATUS.md).

## Ownership

This module owns:

- capture-event consumption
- immutable MIME retrieval and extraction
- classifier HTTP orchestration
- tenant policy evaluation
- decision persistence and command outbox
- review, policy, status, and enablement APIs

It does not own:

- SMTP acceptance, durable gateway spool, or provider relay
- detector implementations
- legacy DLP compatibility or fallback behavior

## Runtime processes

- FastAPI mounts the authenticated `/api/dlp/v2` control-plane routes.
- Queue consumers run separately with `python -m backend.dlp.workers.main`
  once the worker is implemented.

## Contracts

Contracts in `contracts/` mirror the currently deployed service payloads:

- `CaptureEvent` from `dlp-gateway`
- `ClassifyRequest` / `ClassifyResponse` from `dlp-classifier`
- `GatewayCommand` consumed by `dlp-gateway`

Schema changes must be versioned and covered by cross-service contract tests.

## Database migrations

DLP v2 uses its own Alembic version table and never creates tables during API
startup.

```bash
python -m backend.dlp.migrate
```

Run this as a one-shot deployment task before starting updated API and worker
tasks. Do not run migrations independently in every API replica.

## Adapters

- Local: `FilesystemDlpMessageBus` uses the gateway's durable queue directory.
- Azure: `AzureServiceBusDlpMessageBus` uses dedicated capture and command
  queues.
- MIME: `AzureBlobMimeStore` validates the configured host/container, enforces
  the byte limit while streaming, and checks SHA-256 before returning content.

Production should use managed identity with `DLP_SERVICE_BUS_FULLY_QUALIFIED_NAMESPACE`
and `DLP_AZURE_STORAGE_ACCOUNT`; connection strings are for local development
or controlled migration only.

## MIME extraction

`SafeMimeExtractor` bounds MIME size, part count, per-part bytes, archive
expansion, extracted text, attachment memory, and attachment runtime. PDF,
Office, and RTF extraction runs in a child process. Unsupported, malformed,
encrypted, truncated, timed-out, and failed extraction is returned as a
structured limitation so policy can hold rather than silently allow.

## Classifier boundary

`ClassifierClient` is the only code that calls `POST /classify`. It validates
the exact v1 response, flattens detector matches into service-independent
findings, retries only transient failures, and opens a circuit breaker after
repeated outages. Timeout, transport, and contract failures remain distinct
from a valid no-findings response.

## Policy evaluation

Policy is deterministic and separate from classification. Rules match typed
entity findings, confidence, detector, LLM outcome, recipient scope, and
tenant domains. `STOP` outranks `HOLD`, which outranks `ALLOW`; priority breaks
ties. Every decision records the immutable policy version, all matching rule
IDs, non-sensitive finding references, intended action, effective action, and
explanation. Fatal extraction gaps and detector errors produce a system hold.
Monitor mode records what would happen while effectively allowing delivery.

## Worker

After migrations, run the data-processing worker separately from FastAPI:

```bash
python -m backend.dlp.workers.main
```

The worker consumes capture events idempotently, verifies and extracts MIME,
calls the classifier, evaluates policy, and commits the decision plus gateway
command in one database transaction. A separate loop publishes outbox rows.
If publication succeeds but the database update fails, the same deterministic
command ID is retried and the gateway safely deduplicates it. A hold creates no
delivery command, so the gateway keeps the message captured.

## Local end-to-end stack

The unified stack uses Postgres, Azurite, MailHog, the gateway, the backend
worker, and a contract-faithful classifier stub. No cloud credentials are
required.

```bash
docker compose -f docker-compose.dlp.yml up --build -d
$env:DLP_E2E="1"  # PowerShell
python -m pytest backend/tests/integration/test_dlp_local_e2e.py -q
docker compose -f docker-compose.dlp.yml down -v
```

The test proves both paths: a clean external email is relayed to MailHog, while
a high-confidence credit-card finding creates a stop decision and is not
relayed. The classifier stub exists only for local contract testing.

## Control-plane API

All routes are authenticated, enterprise-tier gated, and tenant-scoped under
`/api/dlp/v2`:

- `GET /status` (includes `reviewable_count`)
- `GET|PUT /settings`
- `GET /policy`, `GET|PUT /policy/draft`, `POST /policy/publish`
- `GET /messages` (`state`, `reviewable=true`, cursor via `before`)
- `GET /messages/{message_id}` (rich detail: findings, limitations, bounded preview)
- `POST /messages/{message_id}/release`
- `POST /messages/{message_id}/stop`

Settings, policy mutations, release, and stop require an administrator role.
Published policies are immutable. Review actions require an idempotency key
and atomically create an audit record plus outbox command. Message detail never
returns raw MIME or secret match text; preview download is best-effort and
bounded.

## Safety rules

1. Never read or write legacy DLP tables.
2. Never import legacy DLP routers or services.
3. Never treat classifier failure as a clean result.
4. Never publish a gateway command outside the transactional outbox.
5. Never run gateway auto-allow and the backend capture consumer together.
