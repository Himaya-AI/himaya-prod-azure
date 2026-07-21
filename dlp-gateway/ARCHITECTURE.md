# DLP Gateway Architecture

## Style

Hexagonal (ports & adapters):

- **Domain** owns message lifecycle, outcomes, and pure rules.
- **Ports** are Protocol interfaces (spool, blob, queue, relay adapter, config cache).
- **Adapters** implement ports for local Docker and later Azure.
- **Workers** are application services orchestrating use cases.
- **Composition root** is `app/main.py` — wires adapters from settings.

## Platform place (three services)

```text
dlp-gateway        → SMTP data plane (this repo folder)
backend/dlp        → control plane, extraction, policy, APIs
dlp-classifier     → detectors / findings only
```

This service never calls the classifier. Backend does.

```text
capture event → backend/dlp → dlp-classifier → findings
                     → policy → allow|release|stop command → gateway relay
```

## Why not Postfix-first for local MVP

Production may front Postfix for HA SMTP. The acceptance contract is:

> `250` only after envelope + MIME are fsynced to durable spool.

A Python SMTP edge (`aiosmtpd`) makes that contract explicit and testable. Postfix can be introduced later behind the same spool/capture interfaces without changing capture/relay.

## Message lifecycle

```text
accepted_in_spool
  → captured
  → allow|hold|stop command   (from backend/dlp after classifier findings)
  → submitting
  → provider_accepted | deferred | failed | outcome_uncertain
```

## Local vs production adapters

| Port | Local | Production |
| --- | --- | --- |
| Blob MIME store | Azurite | Azure Blob |
| Event/command bus | Filesystem queue | Azure Service Bus |
| Relay adapter | SMTP to MailHog | Microsoft 365 / Google adapters |
| Tenant config | JSON file snapshot | Signed published snapshots |
| Decision source | `FORCE_ALLOW` auto-allow worker | `backend/dlp` policy worker (after `dlp-classifier` findings) |

## Non-goals (this service)

- Classification / LLM / detector packs (`dlp-classifier`)
- Policy evaluation (`backend/dlp`)
- Enable DLP admin APIs (`backend/dlp`)
- Direct-to-internet MX delivery
