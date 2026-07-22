# DLP v2 backend

`backend/dlp` is the control plane and application-worker boundary between
`dlp-gateway` and `dlp-classifier`.

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

## Safety rules

1. Never read or write legacy DLP tables.
2. Never import legacy DLP routers or services.
3. Never treat classifier failure as a clean result.
4. Never publish a gateway command outside the transactional outbox.
5. Never run gateway auto-allow and the backend capture consumer together.
