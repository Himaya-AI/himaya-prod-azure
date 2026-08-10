# DLP v2 — Implementation Status

Short handoff for the greenfield DLP stack. For architecture and module details, see the linked docs — this file tracks **what shipped**, **how to verify**, and **what is left**.

| Related doc | Role |
|---|---|
| [`backend/dlp/README.md`](../backend/dlp/README.md) | Module ownership, APIs, adapters, local e2e commands |
| [`docs/DLP_INGRESS_GATEWAY_PLAN.md`](DLP_INGRESS_GATEWAY_PLAN.md) | Gateway / transport design |
| [`docs/DLP_BACKEND_IMPLEMENTATION_ROADMAP.md`](DLP_BACKEND_IMPLEMENTATION_ROADMAP.md) | Broader backend roadmap (enablement, providers, rollout) |

**Branch:** `feature/DLP`  
**Backend vertical slice through:** `9475ed3` (`feat(dlp): add tenant control-plane APIs`)  
**Live local e2e:** proven with `docker-compose.dlp.yml` (allow + stop)

---

## What has been done

### Services

| Unit | Path | Role |
|---|---|---|
| Data plane | `dlp-gateway/` | SMTP accept, spool, blob capture, command consume, relay/stop |
| Control plane + workers | `backend/dlp/` | Capture consume → extract → classify → policy → outbox → APIs |
| Classifier | `dlp-classifier/` (+ local stub in compose) | `POST /classify` detectors |

### Pipeline

```text
SMTP → gateway capture → blob + capture event
  → backend.dlp worker → MIME extract → classifier → policy
  → decision + outbox command → gateway allow/stop/release
  → provider outcome → durable delivery event → backend state/retry outbox
```

### Control-plane APIs (`/api/dlp/v2`)

Authenticated, tenant-scoped:

- `GET /status`
- `GET|PUT /settings`
- `GET /policy`, `GET|PUT /policy/draft`, `POST /policy/publish`
- `GET /messages`, `GET /messages/{message_id}`
- `POST /messages/{message_id}/release`
- `POST /messages/{message_id}/stop`

### Persistence

Independent Alembic chain (`python -m backend.dlp.migrate`): messages, parts, classification, decisions, events, outbox, plus control-plane settings/policy tables. Does **not** use legacy DLP tables.

### Local stack and tests

- Compose: `docker-compose.dlp.yml` (Postgres, Azurite, MailHog, gateway, migrate, classifier stub, worker)
- Unit/integration: `backend/tests/test_dlp_v2_*.py`, `dlp-gateway/tests/`
- Delivery safety: spool-backed event outbox, partial/uncertain retry guards,
  bounded deferred retries, and interrupted-submit recovery
- Live e2e (gated): `DLP_E2E=1` + `backend/tests/integration/test_dlp_local_e2e.py`  
  - Clean mail → allow + relayed to MailHog  
  - Credit-card mail → stop + not relayed

### Key implementation commits

| Commit | Summary |
|---|---|
| `84f085a` | Skeleton, contracts, `/api/dlp/v2/status` |
| `8e0e7cd` | Schema + repositories |
| `d7e8e96` | Gateway command idempotency / recovery |
| `39c7f71` | Messaging + Blob MIME store |
| `f0ce118` | Bounded MIME extraction |
| `8e2ce16` | Classifier client |
| `ee093ee` | Policy evaluator |
| `f6672bc` | Capture worker + transactional outbox |
| `7421414` | Local compose + e2e test |
| `9475ed3` | Settings / policy / messages / release / stop APIs |

---

## Dual-stack warning (important)

Legacy DLP is **still present** beside v2:

- Routers: `backend/routers/dlp.py`, `dlp_webhook.py`
- Services: `backend/services/dlp_service.py`, `dlp_inline.py`
- Startup / loops: `run_outbound_dlp_loop` and related hooks
- UI: frontend `/dlp` still targets old `/api/dlp/*`
- Infra scripts: `infra/dlp/*`

**Rule while both exist:** in any environment where the gateway + `backend.dlp` worker enforce mail, **disable legacy enforcement** so both cannot act on the same message. Keep old `/api/dlp` only if needed for temporary UI or rollback — not as a second prevention path.

DSPM `cross_cloud_dlp` is **not** legacy email DLP; keep it. Only stop depending on `dlp_service` when that path is rewired.

---

## What is left to do

| Priority | Item | Notes |
|---|---|---|
| Next | **Frontend → v2** | Rewire or rebuild `/dlp` to `/api/dlp/v2` |
| Next | **Deploy / test with legacy enforcement off** | Gateway + migrate + API + worker; prove allow/hold/stop in target env |
| Next | **Provision delivery queue / staging matrix** | Create `dlp-delivery`; test accepted, deferred, failed, partial, uncertain, and duplicate-event paths |
| Later | **Remove legacy DLP** | Unmount/delete old routers, services, loops, `infra/dlp`, obsolete tests; rewire `drafts` / `saas_security` off `dlp_service` |
| Later | **Legacy table cleanup** | Drop/archive old `dlp_*` tables only after nothing needs that data |
| Optional | **Deeper e2e** | Monitor mode, failure/recovery, hold/release beyond the current allow/stop smoke test |
| Roadmap | **Enablement / providers** | Full “Enable DLP”, M365/Google automation — see implementation roadmap |

Legacy backend removal is **intentionally deferred** until after v2 is tested and deployed with legacy enforcement disabled.

---

## How to verify locally

```bash
docker compose -f docker-compose.dlp.yml up --build -d

# PowerShell
$env:DLP_E2E="1"
python -m pytest backend/tests/test_dlp_v2_*.py backend/tests/integration/test_dlp_local_e2e.py -q

# Gateway unit tests (run from dlp-gateway/)
cd dlp-gateway
python -m pytest tests -q
```

See [`backend/dlp/README.md`](../backend/dlp/README.md) for process ownership, migration rules, and safety constraints.

---

## Definition of done for cutover

1. UI and ops use `/api/dlp/v2` only.  
2. Deployed path is gateway + `backend.dlp` worker (no legacy enforcement).  
3. Legacy routers/services/loops/`infra/dlp` removed.  
4. Old DLP tables dropped or archived when no longer needed.
