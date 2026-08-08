# HIM-ENC-ATTACH — Detect & unlock encrypted/password-protected attachments

**Type:** Feature
**Priority:** High
**Component:** Backend / Threat Detection pipeline
**Epic:** Attachment threat coverage
**Estimate:** ~8–10 dev-days (M)
**Architecture:** `docs/ENCRYPTED_ATTACHMENT_HANDLING.md`

---

## Context

Malware is commonly delivered inside a **password-protected archive** (encrypted ZIP/7z/RAR) or **encrypted Office/PDF**, with the password written in the email body/subject or embedded in an image. Our current defenses hash and statically scan the *encrypted container*, so the real payload is invisible and the email scores low.

Prove it locally: an encrypted ZIP containing EICAR, password `1234` in the body, currently sails through with a low score.

## Goal

When an inbound attachment is encrypted, harvest the password from the email context, unlock + recursively extract in isolation, and re-feed the extracted files through our existing hash → static scan → detonation pipeline so the true payload is analyzed and scored.

## In scope

- Encryption detection for ZIP (legacy + AES), 7z, RAR, Office (docx/xlsx/pptx), PDF.
- Password harvesting from body + subject (EN + AR regex), optional image OCR, small default-password dictionary.
- Safe unlock + recursive extraction with strict zip-bomb/resource limits.
- Re-feeding children into `scan_uploaded_file` + `detonate_in_aci`.
- New indicators + score integration + new `encrypted_attachment_scans` table.
- Feature-flagged rollout (log-only → enforcing).

## Out of scope

- Brute-forcing passwords not derivable from the email.
- S/MIME / PGP transport decryption (separate ticket).
- New YARA/ClamAV engines (we feed the existing ones).

---

## Acceptance criteria

- [ ] Encrypted ZIP (AES + legacy), 7z, encrypted docx/xlsx, and encrypted PDF are correctly detected as encrypted.
- [ ] Password is harvested from: body ("password is X"), subject, and (when `ENC_ATTACH_OCR_ENABLED=true`) an image; EN and AR phrasings covered.
- [ ] Given the correct password, the archive is unlocked and all children (incl. one nested archive level) are extracted within limits.
- [ ] Each extracted child is SHA-256 hashed, run through `saas_malware_scanner.scan_uploaded_file`, and detonated via `aci_sandbox_service.detonate_in_aci` when risky.
- [ ] Encrypted ZIP containing **EICAR** + password in body → child flagged malware, parent threat scored **critical**, artifacts stored in Azure Blob.
- [ ] Wrong/missing password → `unlock_failed` indicator emitted and threat severity elevated (encrypted + unopenable is itself suspicious).
- [ ] Zip-bomb / oversized / too-deep archives are aborted with a `zip_bomb` indicator; no OOM, no runaway CPU.
- [ ] All processing runs in the worker/sandbox, never on the API request host; contents are never executed during extraction.
- [ ] Feature is behind `ENC_ATTACH_ENABLED` and ships defaulted to log-only for pilot.
- [ ] Indicators surface in the threat UI alongside existing `suspicious_attachments`.

---

## Technical tasks

1. **New service** `backend/services/encrypted_attachment_service.py`
   - `is_encrypted()`, `harvest_passwords()`, `try_unlock()`, `recursive_extract()`, `analyze_encrypted_attachment()`.
   - `EncryptedAttachmentResult` + `ChildFile` dataclasses.
2. **Dependencies**
   - Backend `requirements.txt`: `pyzipper`, `py7zr`, `rarfile`, `msoffcrypto-tool`, `pikepdf`, `pytesseract` (OCR optional).
   - `sandbox/Dockerfile`: add `unar`/`unrar`, `tesseract-ocr` (p7zip-full/unzip already present).
3. **Pipeline integration**
   - Hook into `backend/services/email_processor.py` where attachments are processed (see `all_attachments` handling ~lines 604–740). When an attachment is encrypted and `ENC_ATTACH_ENABLED`, dispatch `analyze_encrypted_attachment` on the worker path.
   - Merge returned indicators into `risk_result["score_breakdown"]` and combined indicators; feed severity into `auto_triage_service`.
4. **Storage**
   - Persist container + extracted children via `backend/services/storage_client.upload()` under `encrypted-attachments/{threat_id}/{sha256}/...`; generate SAS via `generate_download_url` for evidence/live-session display.
5. **Data model**
   - Create `encrypted_attachment_scans` (see architecture §6) idempotently at startup in `backend/main.py` (mirror the `password_reset_tokens` bootstrap pattern).
6. **Config**
   - Add env vars from architecture §9 to `backend/config.py` + `infra/azure/provision.sh` + container app settings.
7. **Guards**
   - Implement total-size/file-count/depth/timeout/compression-ratio limits with unit coverage.
8. **Observability**
   - Structured per-attachment logs + counters (encrypted-seen, unlocked-ok, unlock-failed, zip-bomb, malware-inside).
9. **Tests**
   - Unit + integration per architecture §12, including an EICAR-in-encrypted-ZIP fixture.
10. **Docs**
    - Update `docs/SANDBOX_SETUP.md` / threat-detection docs with the new indicators and flags.

---

## Config / env (defaults)

```
ENC_ATTACH_ENABLED=false          # pilot log-only first, then true
ENC_ATTACH_OCR_ENABLED=false
ENC_ATTACH_MAX_TOTAL_BYTES=209715200
ENC_ATTACH_MAX_FILES=500
ENC_ATTACH_MAX_DEPTH=3
ENC_ATTACH_TIMEOUT_S=60
ENC_ATTACH_DEFAULT_PASSWORDS=123,1234,12345,0000,password,infected,virus,malware
```

## Rollout

1. Deploy with `ENC_ATTACH_ENABLED=false`.
2. Enable log-only for one pilot org; review unlock rate + false positives for ~1 week.
3. Flip to enforcing (affects quarantine decisions) after sign-off.

## Risks / mitigations

- **Decompression DoS (zip bomb)** → hard size/ratio/depth/time limits, abort + indicator.
- **False positives from default-password dictionary** → keep dictionary tiny; log-only pilot; passwords tried are bounded and email-derived first.
- **CPU from OCR** → off by default, only on inline images, per-op timeout.
- **Library CVEs (archive parsers)** → pin versions, run only in isolated worker/sandbox, never execute contents.
