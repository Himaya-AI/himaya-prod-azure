# Deterministic Scoring

The Reputation Service uses deterministic scoring: the same normalized entity plus the same source signals always returns the same score and verdict.

## Score and verdict

| Range | Verdict | Notes |
|-------|---------|-------|
| 0–30 | benign | Unless a suspicious signal is present |
| 31–60 | suspicious | |
| 61–100 | malicious | |
| no useful signals | unknown | |

**Score formula:**

```text
score = sum(score_impact)
score = max(score, minimum_score)   # per-signal floor, if set
score = clamp(score, 0, 100)
```

## Signal sources

| Priority | Source | Type |
|----------|--------|------|
| 1 | IOC feeds | Redis threat feeds (URLhaus, OpenPhish, IP lists) |
| 2 | VirusTotal, AlienVault OTX, urlscan.io, MalwareBazaar | External TI APIs |
| 3 | DNS, WHOIS, heuristics, email auth | Supporting evidence |

Context signals (`email_auth`, `heuristic`) are applied on every request and are **not cached**.

## Signal impacts

### Email authentication (from caller `auth_results`)

| Signal | Impact |
|--------|-------:|
| `spf_fail` / `spf_softfail` | +15 |
| `spf_none` | +5 |
| `dkim_fail` | +15 |
| `dkim_none` | +5 |
| `dmarc_fail` | +20 |
| `dmarc_none` | +10 |

### IOC feeds

| Signal | Impact | Verdict |
|--------|-------:|---------|
| `ioc_feed_url_match:*` | +60 (min 60) | malicious |
| `ioc_feed_domain_match:*` | +40 | suspicious |
| `ioc_feed_ip_match:*` | +30 (min 30) | malicious |

Requires shared Redis with Helios `threat_feeds_service` data.

### VirusTotal

| Signal | Impact | Notes |
|--------|-------:|-------|
| `vt_malicious:N/T` (domain/url, ≥3) | +50 | malicious |
| `vt_malicious:N/T` (domain/url, 1–2) | +25 | suspicious |
| `vt_malicious:N/T` (file, ≥3) | +70, min 85 | malicious |
| `vt_malicious:N/T` (file, 1–2) | +40 | suspicious |
| `vt_suspicious:N/T` (≥2) | +15 | suspicious |
| `vt_trusted:N_harmless` | −10 | benign lean |
| `vt_reputation:N` | +20 | When VT reputation < −10 and harmless ratio guard passes |

WHOIS is skipped when VirusTotal returns HTTP 200 data for the domain.

### AlienVault OTX

| Signal | Impact |
|--------|-------:|
| `otx_pulse_match:N` (≥2) | +35 to +50 |

### urlscan.io

| Signal | Impact | Verdict |
|--------|-------:|---------|
| `urlscan_malicious:N` (≥3) | +50 | malicious |
| `urlscan_malicious:N` (1–2) | +25 | suspicious |
| `urlscan_search_malicious:N` | +25 / +50 | fallback when Malicious API unavailable |

Uses the Malicious Lookup API (`/api/v1/malicious/{type}/{value}`) with Search API fallback on 401/403.

### MalwareBazaar (abuse.ch)

| Signal | Impact | Verdict |
|--------|-------:|---------|
| `malwarebazaar_known_sample` | +75 (min 80) | malicious |
| `mb_signature:{family}` | (indicator) | — |

Requires `ABUSECH_API_KEY` (free at [auth.abuse.ch](https://auth.abuse.ch)). `file` entity only.

### DNS (domain only)

| Signal | Impact |
|--------|-------:|
| `no_mx_record` | +20 |
| `no_spf_record` | +10 |
| `no_dmarc_record` | +10 |

### WHOIS domain age

| Signal | Impact |
|--------|-------:|
| `whois_new_domain:Nd` (<30 days) | +40 |
| `whois_young_domain:Nd` (<90 days) | +20 |
| `whois_recent_domain:Nd` (<365 days) | +5 |
| `whois_established:Nd` (≥365 days) | −5 |
| `whois_no_creation_date` | +15 |

### Heuristics

| Signal | Impact |
|--------|-------:|
| `dangerous_attachment_extension:.ext` | +20 |
| `suspicious_url_*` (each) | +10, capped at +30 total |

URL heuristics include: long domain, many subdomains, digit prefix, suspicious TLD, login lure, verify-account lure, brand impersonation.

## Source correlation

| Level | Meaning |
|-------|---------|
| `strong` | Multiple sources agree, or priority-1 source is malicious |
| `partial` | One flagged source, or benign lean |
| `conflict` | Benign and malicious signals coexist |
| `none` | No actionable TI data |

## Confidence

Confidence (0.0–1.0) is separate from score. It rises with source agreement and high-confidence sources; it falls on conflict or source timeouts.
