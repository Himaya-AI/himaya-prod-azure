# Encrypted / Password-Protected Attachment Handling — Architecture

**Status:** Proposed
**Owner:** Platform / Threat Detection
**Author:** (drafted for engineering hand-off)
**Related ticket:** `docs/tickets/HIM-ENC-ATTACH.md`

---

## 1. Problem

Attackers routinely wrap malware in a **password-protected archive** (encrypted ZIP/7z/RAR) or an **encrypted Office/PDF** file, and put the password in the email body — often as plain text ("the password is `1234`"), in the subject, or embedded in an **image** to defeat text parsing.

This defeats Himaya's current attachment defenses because:

- **Hashing** (`backend/services/attachment_hashing.py`) hashes the *encrypted container*. The hash never matches a known-bad payload hash — the malicious bytes inside are unreachable.
- **Static extension/hash scan** (`backend/services/saas_malware_scanner.scan_uploaded_file`) sees a benign-looking `.zip` / `.7z` and cannot open it.
- **Detonation** (`backend/services/aci_sandbox_service.detonate_in_aci`) receives a file it cannot open without the password, so nothing meaningful executes.

Net effect: a password-protected malware ZIP with the password in the body currently scores **low** and can reach the user.

## 2. Goal

Detect encrypted attachments, **harvest the password from the surrounding email context**, safely **unlock and recursively extract** the contents in an isolated environment, and **re-feed the extracted files through the existing scan + detonation pipeline** so the real payload is analyzed and scored.

## 3. Non-Goals

- Cracking/brute-forcing strong passwords not present in the email (only a tiny bounded dictionary of email-derived + common defaults is tried).
- Breaking S/MIME / PGP *transport* encryption (that is a separate feature — see option 2 in the original scoping).
- Replacing the DLP container's YARA/ClamAV engines; we feed *into* them.

---

## 4. Where it fits in the pipeline

```
Inbound email (Gmail/M365 sync)
        │
        ▼
 email_processor.process_email()
        │  attachments[] (filename, mime, size, sha256)
        ▼
 ┌─────────────────────────────────────────────┐
 │  NEW: encrypted_attachment_service            │
 │  1. is_encrypted(file) ? ───────────────No──▶ existing scan path (unchanged)
 │                         │Yes                   │
 │  2. harvest_passwords(email_body, subject,     │
 │     inline_images[OCR], sender_domain)         │
 │  3. try_unlock(file, candidate_passwords)      │
 │  4. recursive_extract(unlocked, limits)        │
 │  5. for each extracted child:                  │
 │        - sha256 (attachment_hashing)           │
 │        - scan_uploaded_file()                  │
 │        - detonate_in_aci() (if risky)          │
 │  6. emit indicators + child findings           │
 └─────────────────────────────────────────────┘
        │
        ▼
 Risk scoring (email_processor / auto_triage_service)
        │
        ▼
 Threat record + quarantine + live-session evidence
```

Runs in the **worker** (`himaya-prod-worker`) via the existing async task path, not the synchronous request path, because unlock + detonation can take tens of seconds.

---

## 5. Components

### 5.1 `backend/services/encrypted_attachment_service.py` (new)

Public API:

```python
async def analyze_encrypted_attachment(
    *,
    org_id: str,
    threat_id: str | None,
    filename: str,
    raw_bytes: bytes,
    email_subject: str,
    email_body_text: str,
    email_body_html: str,
    inline_images: list[bytes] | None = None,
    sender_domain: str = "",
) -> EncryptedAttachmentResult
```

`EncryptedAttachmentResult` (dataclass):

| field | type | meaning |
|---|---|---|
| `is_encrypted` | bool | container required a password |
| `unlocked` | bool | we found a working password |
| `password_source` | str | `body` / `subject` / `image_ocr` / `default_dict` / `none` |
| `extracted_children` | list[ChildFile] | filename, sha256, size, mime, scan_result, detonation_verdict |
| `indicators` | list[str] | see §7 |
| `severity` | str | rolled up from children |
| `confidence` | float | |
| `blob_keys` | list[str] | Azure Blob keys of stored artifacts |

### 5.2 Encryption detection (`is_encrypted`)

Magic-byte + header inspection (no full decode):

- **ZIP:** central-directory general-purpose bit 0 set, or AES extra field (0x9901) → encrypted. `pyzipper`/`zipfile` raises `RuntimeError` on read.
- **7z / RAR:** header flags via `py7zr` / `rarfile`; 7z encrypted-header case → whole archive listing is locked.
- **Office (docx/xlsx/pptx):** file is an OLE compound doc with `EncryptedPackage` stream → detect via `msoffcrypto.OfficeFile.is_encrypted()`.
- **PDF:** `/Encrypt` in trailer → `pikepdf.open` raises `PasswordError`.

### 5.3 Password harvesting (`harvest_passwords`)

Ordered candidate list (bounded, deduped, capped at N=25):

1. **Body/subject regex** — patterns for EN + AR:
   - `password[:\s]+(\S+)`, `pass(?:word|code)?\s*(?:is|=|:)\s*(\S+)`, `pwd[:\s]+(\S+)`
   - `كلمة (?:المرور|السر)[:\s]+(\S+)`, `الرمز[:\s]+(\S+)`
   - Quoted tokens near the words above; also "unzip/open with `X`".
2. **Inline-image OCR** — run Tesseract on embedded/inline images, then re-run the regexes on OCR text (attackers screenshot the password). Gated behind `ENC_ATTACH_OCR_ENABLED`.
3. **Default dictionary** — small, configurable set of the most common lure passwords (`123`, `1234`, `12345`, `0000`, `password`, `infected`, `virus`, `malware`, sender domain, current year).

Each attempt is capped; we stop at first success.

### 5.4 Unlock + recursive extraction (`try_unlock`, `recursive_extract`)

- Libraries: `pyzipper` (AES ZIP), `py7zr`, `rarfile` (+ `unar`/`unrar` binary), `msoffcrypto-tool`, `pikepdf`/`qpdf`.
- **Runs inside the isolated sandbox/worker, never on the API host.**
- **Zip-bomb / resource guards (hard limits, configurable):**
  - Max extracted total size (`ENC_ATTACH_MAX_TOTAL_BYTES`, default 200 MB)
  - Max file count (`ENC_ATTACH_MAX_FILES`, default 500)
  - Max recursion depth (`ENC_ATTACH_MAX_DEPTH`, default 3 — archives-in-archives)
  - Per-op timeout (`ENC_ATTACH_TIMEOUT_S`, default 60)
  - Compression-ratio ceiling → emit `zip_bomb` and abort.
- Extracted children are **never executed here** — they are hashed and handed to the existing scanners/detonation.

### 5.5 Re-feed into existing pipeline

For each extracted child:
1. `attachment_hashing.sha256_hex()`
2. `saas_malware_scanner.scan_uploaded_file(filename, raw_bytes=...)`
3. If risky (dangerous ext, known-bad hash, macro-office) → `aci_sandbox_service.detonate_in_aci()`
4. Store artifact in Azure Blob via `storage_client.upload()` under `encrypted-attachments/{threat_id}/{sha256}/...`

---

## 6. Data model changes

New table `encrypted_attachment_scans`:

| column | type | notes |
|---|---|---|
| `id` | uuid pk | |
| `org_id` | uuid | |
| `threat_id` | uuid null | FK to the parent threat |
| `filename` | text | original container name |
| `container_sha256` | text | hash of the encrypted container |
| `is_encrypted` | bool | |
| `unlocked` | bool | |
| `password_source` | text | body/subject/image_ocr/default_dict/none |
| `child_count` | int | |
| `worst_child_severity` | text | |
| `indicators` | jsonb | |
| `blob_keys` | jsonb | |
| `created_at` | timestamptz | default now() |

Child findings can be denormalized into `indicators`/`blob_keys` for v1 (no separate child table needed initially).

Created idempotently at startup alongside the other bootstrap tables in `backend/main.py` (same pattern as `password_reset_tokens`).

---

## 7. Indicators emitted (feed scoring)

| indicator | severity contribution |
|---|---|
| `encrypted_attachment` | +low (context) |
| `password_in_body` / `password_in_subject` / `password_in_image` | +medium (classic evasion signal) |
| `unlocked_malware_inside` | +critical |
| `unlocked_dangerous_extension` | +high |
| `unlocked_macro_office` | +high |
| `nested_archive` | +low |
| `zip_bomb` | +high, abort |
| `unlock_failed` | +medium (still suspicious — encrypted + unopenable) |

Wire into `email_processor` score breakdown (`score_breakdown.encrypted_attachment`) and `auto_triage_service` so it influences verdict + quarantine, consistent with existing `suspicious_attachments` handling.

---

## 8. Security & isolation

- Unlock/extraction executes **only** in the sandbox image or the worker container, which have no VNet path to prod private resources (same isolation posture as `sandbox_session_service`).
- Contents are **never executed** during extraction; execution only happens inside the detonation ACI sandbox that is already isolated + auto-reaped.
- Strict resource ceilings (§5.4) to prevent zip-bomb / decompression DoS.
- Harvested passwords and extracted payloads are stored in Blob with short-lived SAS access, and are covered by the sandbox reaper / evidence retention policy.
- OCR is optional and off by default (`ENC_ATTACH_OCR_ENABLED=false`) to bound CPU.

---

## 9. Configuration (env vars)

| var | default | purpose |
|---|---|---|
| `ENC_ATTACH_ENABLED` | `true` | master switch |
| `ENC_ATTACH_OCR_ENABLED` | `false` | enable Tesseract OCR password harvesting |
| `ENC_ATTACH_MAX_TOTAL_BYTES` | `209715200` | 200 MB extracted cap |
| `ENC_ATTACH_MAX_FILES` | `500` | extracted file count cap |
| `ENC_ATTACH_MAX_DEPTH` | `3` | recursive archive depth |
| `ENC_ATTACH_TIMEOUT_S` | `60` | per-attachment processing timeout |
| `ENC_ATTACH_DEFAULT_PASSWORDS` | (built-in list) | comma-separated extra defaults |

Sandbox image already ships `p7zip-full` + `unzip`; add `unar`/`unrar`, `tesseract-ocr`, and the Python libs (`pyzipper`, `py7zr`, `rarfile`, `msoffcrypto-tool`, `pikepdf`) to `sandbox/Dockerfile` and/or backend `requirements.txt`.

---

## 10. Rollout

1. Ship behind `ENC_ATTACH_ENABLED=false`; enable for one pilot org first.
2. Log-only mode: emit indicators but do **not** change quarantine decisions, to measure false positives.
3. Flip to enforcing after reviewing pilot metrics (unlock rate, child-malware hit rate, timeouts).

## 11. Observability

- Structured logs per attachment: `is_encrypted`, `password_source`, `child_count`, `worst_child_severity`, elapsed ms.
- Metrics/counters: encrypted-seen, unlocked-ok, unlock-failed, zip-bomb-aborted, malware-found-inside.

## 12. Test plan (summary)

- Unit: detection for AES-ZIP, legacy-ZIP, 7z encrypted-header, encrypted docx/xlsx, encrypted PDF.
- Unit: password regex across EN/AR phrasings; OCR path with a fixture image.
- Unit: zip-bomb + depth/size/count guards abort correctly.
- Integration: encrypted ZIP with EICAR inside + password in body → child flagged malware, threat scored critical, artifacts in Blob.
- Integration: wrong/absent password → `unlock_failed` indicator, still elevated.
