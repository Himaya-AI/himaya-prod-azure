# Himaya DLP Gateway

SMTP data-plane service for outbound DLP.

Receives mail from Microsoft 365 / Google Workspace, durably stores the original MIME, publishes capture events, and relays allowed or released messages back through the provider return path.

Classification lives in `dlp-classifier/`; policy and APIs live in `backend/dlp/`. This gateway does **not** classify content on the SMTP hot path.

## Design references

- `docs/DLP_INGRESS_GATEWAY_PLAN.md`
- `docs/DLP_BACKEND_IMPLEMENTATION_ROADMAP.md`
- [`ARCHITECTURE.md`](./ARCHITECTURE.md) — patterns and module boundaries
- [`DEVELOPMENT.md`](./DEVELOPMENT.md) — step-by-step build log
- [`HANDOFF.md`](./HANDOFF.md) — three-service handoff for backend and classifier engineers

## Local quick start

```bash
cd dlp-gateway
docker compose up --build
```

Services:

| Service | Port | Purpose |
| --- | --- | --- |
| `gateway` | SMTP `2525`, health `8080` | Accept, spool, capture, auto-allow, relay |
| `mailhog` | UI `8025`, SMTP `1025` | Fake provider return sink |
| `azurite` | Blob `10000` | Local immutable MIME store |

Send a test message:

```bash
python scripts/send_test_mail.py
```

Open http://localhost:8025 to confirm the message arrived at the sink.

## Microsoft return (AWS staging)

Local default still relays to MailHog (`relay.adapter=local`).

To enable Exchange Online return:

1. Use `conf/tenants/staging-m365.json.example` as the tenant snapshot
2. Mount return client cert/key (see compose volumes `m365-client-*.pem`)
3. Set `relay.adapter=microsoft` and `mx_host` to the tenant MX
4. Keep intake STARTTLS cert separate from the return client cert

## Core principles

1. Return SMTP `250` only after durable spool `fsync`.
2. Never query Postgres during SMTP commands.
3. Keep original MIME immutable; relay from that copy.
4. Communicate with the control plane via events and commands only.
5. Local mode may auto-allow; production waits for backend commands.

## Layout

```text
app/
  domain/         # models, state machine, ports (interfaces)
  smtp/           # SMTP edge, trust, tenant resolve, headers
  spool/          # durable MTA spool
  capture/        # MIME → Blob + capture event
  config_cache/   # signed/local tenant snapshots
  relay/          # dispatcher + provider adapters
  commands/       # allow / release / stop / retry
  events/         # publishers + local bus adapters
  workers/        # capture, command, auto-allow, supervisor
  health/         # health HTTP endpoint
contracts/        # event/command/config schemas (shared with backend later)
```
