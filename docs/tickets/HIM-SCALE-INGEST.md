# HIM-SCALE-INGEST — Fleet-scale ingestion: push notifications, project sharding, rate governor

**Type:** Epic / Architecture
**Priority:** High (blocks >~10-customer / >~10K-mailbox growth)
**Component:** Backend / Ingestion (delta-sync, quarantine, worker)
**Epic:** Scale readiness
**Estimate:** ~15–20 dev-days (L) across 3 workstreams

---

## Context

Ingestion currently uses a **polling** model: `backend/services/delta_sync.py` walks every connected mailbox on a fixed interval (~35s) and calls Gmail `history.list` / `messages.list` (and the Graph delta equivalent for M365) regardless of whether new mail exists. Correctness is solid — 429s retry with `Retry-After` backoff and a per-user catch-up cursor guarantees mail is never permanently missed — but the **cost model scales with mailbox count, not mail volume**, so idle mailboxes still burn API quota every cycle.

This is fine at today's tenant count. It breaks well before enterprise fleet scale.

### The math (why this is a hard ceiling, not a tuning knob)

| Scenario | Mailboxes | Mail volume | Verdict on current arch |
|---|---|---|---|
| 1 customer | 1,000 | 1M/mo (~0.38/s) | **Works comfortably** — polling ~29 list-calls/s (~145 units/s); processing ~6 units/s |
| ~10 customers | ~10,000 | ~10M/mo | **Mostly works**, quota bump advisable |
| 100 customers | 100,000 | 100M/mo (~38/s) | **Fails** — see below |

At **100K mailboxes**, polling alone is:

```
100,000 mailboxes / 35s  ≈ 2,860 list-calls/sec
2,860 * ~5 units/call     ≈ 14,000 quota units/sec
                          ≈ ~1.2 BILLION units/day — just to poll (mostly empty) mailboxes
```

That is at/over a single Gmail project's default daily quota **before processing a single real email**. Result: project-wide 429 storms driven by polling overhead, independent of threat volume. M365 has the analogous per-app throttling ceiling.

## Goal

Make ingestion cost scale with **actual mail volume**, not mailbox count, so the platform serves 100+ enterprise customers (100K+ mailboxes) within provider quotas — while preserving today's correctness guarantees (no lost mail, truthful quarantine status).

## In scope

- Gmail push (`users.watch` + Pub/Sub) and M365 Graph change-notifications, replacing steady-state polling.
- Polling retained only as a **reconciliation fallback** (low-frequency sweep + watch-renewal safety net).
- GCP/Graph project (app) sharding across customers/regions.
- A global rate governor (per-mailbox + per-project token buckets) in the worker.

## Out of scope

- Changes to the classification / auto-triage / quarantine *logic* (only how messages are discovered).
- Per-tenant retention policy on held captures (separate ticket).
- Multi-region data residency routing (separate ticket; sharding here is quota-driven, not residency-driven).

---

## Acceptance criteria

- [ ] **Push ingestion (Gmail):** new mail in a watched mailbox triggers processing via Pub/Sub within **≤10s** with **zero API calls for idle mailboxes**.
- [ ] **Push ingestion (M365):** Graph change-notification subscriptions drive processing; subscriptions auto-renew before expiry.
- [ ] **Watch lifecycle:** `users.watch` / Graph subscriptions are created on onboarding, renewed before expiry (Gmail ~7d, Graph varies), and torn down on disconnect; renewal failures alert, don't silently stop ingestion.
- [ ] **Reconciliation fallback:** a low-frequency sweep (e.g. every 15–30 min) catches anything push missed; the existing per-user catch-up cursor still guarantees no permanent loss.
- [ ] **Project sharding:** mailboxes are deterministically assigned to a GCP/Graph app shard; adding a shard rebalances without re-onboarding users; per-shard quota usage is observable.
- [ ] **Rate governor:** per-mailbox and per-project token buckets smooth bursts (onboarding backfills, mass quarantine) so sustained 429 rate stays near zero under a simulated 100K-mailbox load test.
- [ ] **Load test:** a synthetic 100K-mailbox / ~38 msg/sec simulation runs for ≥1h with p95 detection latency **≤30s** and **no dropped messages**.
- [ ] **Backward compatible:** existing tenants migrate from poll→push with no gap in coverage (dual-run during cutover).
- [ ] Feature-flagged rollout (`INGEST_PUSH_ENABLED`), poll-only fallback if push is disabled.

---

## Technical tasks

1. **Gmail push**
   - Pub/Sub topic + push subscription; grant `gmail-api-push@system.gserviceaccount.com` publish rights.
   - `users.watch` on onboarding (`backend/services/onboarding*`), store `historyId` + watch expiry per mailbox.
   - New webhook endpoint (`backend/routers/`) to receive Pub/Sub push, resolve mailbox, enqueue delta from stored `historyId`.
   - Renewal job (watches expire ~7d).
2. **M365 push**
   - Graph subscription create/renew on onboarding; validation-token handshake endpoint; map notification → mailbox → delta pull.
3. **Delta-sync refactor** (`backend/services/delta_sync.py`)
   - Split "discover new mail" (now push-driven) from "process message" (unchanged).
   - Demote polling to a reconciliation sweep + watch-renewal safety net.
4. **Project/app sharding**
   - Shard-assignment map (hash of org/mailbox → shard); per-shard credential resolution in token acquisition (`quarantine_service`, `baseline_ingestion`, `attachment_fetch`).
   - Provisioning docs for adding a shard.
5. **Rate governor**
   - Redis token-bucket per mailbox (per-user/sec) + per project (per-min); worker acquires before each provider call; integrates with existing `_request_with_retry` backoff.
6. **Observability**
   - Per-shard quota-usage counters, watch-health (active/expiring/failed), push→process latency histogram, 429 rate.
7. **Quota**
   - File Gmail/Graph quota-increase requests (verified-vendor); document current vs granted limits per shard.
8. **Load test harness**
   - Synthetic mailbox/message generator to validate the 100K-mailbox target.

---

## Config / env (defaults)

```
INGEST_PUSH_ENABLED=false            # poll-only until push validated
GMAIL_PUBSUB_TOPIC=
GMAIL_WATCH_RENEW_HOURS=144          # renew before ~7d expiry
GRAPH_SUB_RENEW_MINUTES=1440
INGEST_RECONCILE_INTERVAL_S=1800     # fallback sweep
INGEST_SHARD_COUNT=1                 # grow as tenants scale
RATE_GOV_PER_MAILBOX_QPS=200
RATE_GOV_PER_PROJECT_QPM=1000000
```

## Rollout

1. Ship with `INGEST_PUSH_ENABLED=false` (no behavior change).
2. Enable push for one pilot org, **dual-run** with polling; compare coverage + latency for ~1 week.
3. Cut pilot to push-primary, polling as reconciliation only.
4. Roll out fleet-wide; introduce sharding as mailbox count crosses per-project quota headroom.

## Risks / mitigations

- **Missed push notification** → reconciliation sweep + catch-up cursor guarantee eventual processing (delay, never loss).
- **Watch/subscription expiry** → proactive renewal job + expiry alerting; poll fallback covers gaps.
- **Webhook abuse / spoofing** → verify Pub/Sub JWT (Gmail) and Graph validation tokens; authN on webhook endpoints.
- **Shard rebalancing complexity** → deterministic hash assignment; rebalance is metadata-only (no re-onboarding).
- **Thundering herd on mass events** (onboarding backfill, mass quarantine) → rate governor smooths bursts.

## Notes

- Current correctness guarantees already hold at every scale; the failure mode of the *existing* system is **delay under throttle, never lost mail**. This epic addresses **cost/throughput ceilings**, not correctness.
- Related recent fixes this builds on: per-user catch-up cursor and `Retry-After` backoff in `delta_sync.py` / `quarantine_service.py` (commits `5dd24a5`, `b140052`).
