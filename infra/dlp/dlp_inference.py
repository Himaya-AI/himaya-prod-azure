"""
Helios DLP — DeepSeek-R1-Distill-Qwen-7B Inference Server
Runs on a g4dn.xlarge EC2 spot instance (T4 GPU, 16GB VRAM).
Port: 8001

Endpoints:
  POST /classify  — classify email for DLP violations
  GET  /health    — liveness check + model status

Falls back to regex-only classification if GPU OOM or model not loaded.
"""
from __future__ import annotations

import json
import logging
import os
import re
from typing import Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

app = FastAPI(title="Helios DLP Inference", version="1.0.0")

MODEL_ID = os.getenv("DEEPSEEK_MODEL_ID", "deepseek-ai/DeepSeek-R1-Distill-Qwen-7B")
_llm = None       # Lazy-loaded on first /classify request
_llm_loaded = False
_llm_error: Optional[str] = None


# ── Regex fallback patterns ───────────────────────────────────────────────────

class _Pattern:
    def __init__(self, pattern: str, severity: str, category: str):
        self.regex = re.compile(pattern)
        self.severity = severity
        self.category = category

    def match(self, text: str) -> bool:
        return bool(self.regex.search(text))


REGEX_PATTERNS: list[_Pattern] = [
    # PII
    _Pattern(r'\b\d{3}-\d{2}-\d{4}\b',                                                   "critical", "pii_ssn"),
    _Pattern(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b',
                                                                                           "critical", "pii_credit_card"),
    _Pattern(r'\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]?){0,16}\b',                   "high",     "pii_iban"),
    _Pattern(r'\b[A-Z]{1,2}\d{6,9}\b',                                                    "medium",   "pii_passport"),
    _Pattern(r'\b\d{8,12}\b',                                                              "medium",   "pii_national_id"),  # generic national ID

    # Financial
    _Pattern(r'\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b',                        "high",     "financial_swift"),
    _Pattern(r'\b(?:0[0-9]|1[0-2]|2[1-9]|3[0-2])\d{7}\b',                               "high",     "financial_routing"),
    _Pattern(r'(?i)(?:account\s*(?:number|no|#)\s*[:=]?\s*\d{8,18})',                     "high",     "financial_account"),
    _Pattern(r'(?i)wire\s*transfer\s*(?:amount|to|instructions)',                          "high",     "financial_wire"),

    # Credentials
    _Pattern(r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----',                            "critical", "credential_private_key"),
    _Pattern(r'AKIA[0-9A-Z]{16}',                                                          "critical", "credential_aws_key"),
    _Pattern(r'(?i)(?:api[_\-]?key|secret[_\-]?key|access[_\-]?token)\s*[:=]\s*[\'"]?([A-Za-z0-9_\-]{20,})',
                                                                                           "critical", "credential_api_key"),
    _Pattern(r'(?i)(?:^|\s)password\s*[:=]\s*\S+',                                        "high",     "credential_password"),
    _Pattern(r'(?i)(?:bearer|oauth)\s+[A-Za-z0-9_\-\.]{20,}',                            "high",     "credential_token"),
    _Pattern(r'ghp_[A-Za-z0-9]{36}',                                                      "critical", "credential_github_pat"),
    _Pattern(r'sk-[A-Za-z0-9]{48}',                                                       "critical", "credential_openai_key"),

    # ITAR / Export-controlled
    _Pattern(r'(?i)\b(?:ITAR|International Traffic in Arms)\b',                           "high",     "itar"),
    _Pattern(r'(?i)\b(?:EAR|Export Administration Regulations)\b',                        "high",     "itar_ear"),
    _Pattern(r'(?i)\b(?:ECCN\s+[0-9][A-Z][0-9]{3})\b',                                  "high",     "itar_eccn"),
    _Pattern(r'(?i)\b(?:munitions|defense.?article|technical.?data.?subject.?to)\b',      "high",     "itar_munitions"),
    _Pattern(r'(?i)\b(?:export.?controlled|controlled.?technology|dual.?use)\b',          "medium",   "itar_export_controlled"),

    # Bulk exfiltration signals
    _Pattern(r'(?i)(?:bcc:|cc:)(?:[^,\n]+,\s*){19,}',                                    "high",     "bulk_exfil_bcc"),
    _Pattern(r'(?i)(?:to:)(?:[^,\n]+,\s*){29,}',                                         "high",     "bulk_exfil_to"),
]

_SEV_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
_ACT_MAP = {"low": "ALLOW", "medium": "WARN", "high": "HOLD", "critical": "BLOCK"}


def regex_classify(text: str) -> dict:
    """Fast regex-only classification. Always runs before (or instead of) LLM."""
    categories: list[str] = []
    matched: list[str] = []
    max_sev = "low"

    for p in REGEX_PATTERNS:
        if p.match(text):
            if p.category not in categories:
                categories.append(p.category)
            matched.append(p.category)
            if _SEV_ORDER[p.severity] > _SEV_ORDER[max_sev]:
                max_sev = p.severity

    return {
        "risk_level": max_sev,
        "action": _ACT_MAP[max_sev],
        "categories": categories,
        "confidence": 0.80 if categories else 0.55,
        "matched_patterns": matched,
        "explanation": (
            f"Regex patterns matched: {', '.join(set(matched))}"
            if matched
            else "No sensitive patterns detected by regex scan."
        ),
        "method": "regex",
    }


# ── LLM prompt ────────────────────────────────────────────────────────────────

_DLP_PROMPT_TPL = """<|User|>
You are a Data Loss Prevention (DLP) classifier for enterprise email security. Your job is to detect sensitive information that should not leave the organization.

Analyze the following email and respond ONLY with a valid JSON object.

Detect these categories:
- pii_ssn: US Social Security Numbers (XXX-XX-XXXX)
- pii_credit_card: Credit card numbers (Visa, Mastercard, Amex, Discover)
- pii_iban: International Bank Account Numbers
- pii_passport: Passport numbers
- pii_national_id: National ID numbers
- financial_swift: SWIFT/BIC codes
- financial_routing: Bank routing numbers
- financial_account: Bank account numbers
- financial_wire: Wire transfer instructions
- credential_private_key: PEM private keys
- credential_api_key: API keys, secret keys, access tokens
- credential_password: Plaintext passwords
- credential_token: Bearer/OAuth tokens, GitHub PATs, OpenAI keys
- itar: ITAR/EAR/ECCN export-controlled content
- bulk_exfil: Email sent to 20+ external recipients (data exfiltration signal)

Email Subject: {subject}
Recipient Domains: {recipient_domains}

Email Body (truncated to 3000 chars):
{body}
{attachments_section}

Respond with ONLY this JSON (no markdown, no explanation outside JSON):
{{
  "risk_level": "low|medium|high|critical",
  "action": "ALLOW|WARN|HOLD|BLOCK",
  "categories": ["category1", "category2"],
  "confidence": 0.0,
  "matched_patterns": ["description of what was found"],
  "explanation": "one sentence explanation"
}}

Action guide:
- ALLOW: No sensitive content (confidence ≥ 0.85)
- WARN: Possibly sensitive, needs user awareness
- HOLD: Likely sensitive — needs security team review before delivery
- BLOCK: Clear PII, credentials, or ITAR data — do not deliver
<|Assistant|>
"""


def _build_prompt(req_dict: dict) -> str:
    attachments = req_dict.get("attachments", [])
    att_section = (
        f"\nAttachment filenames: {', '.join(attachments)}"
        if attachments
        else ""
    )
    return _DLP_PROMPT_TPL.format(
        subject=req_dict.get("subject", "")[:200],
        recipient_domains=", ".join(req_dict.get("recipient_domains", [])) or "unknown",
        body=req_dict.get("email_body", "")[:3000],
        attachments_section=att_section,
    )


def _load_llm():
    """Load vLLM engine. Called lazily on first request."""
    global _llm, _llm_loaded, _llm_error
    if _llm_loaded or _llm_error:
        return
    try:
        from vllm import LLM
        logger.info(f"Loading {MODEL_ID} via vLLM (may take 30-60s)...")
        _llm = LLM(
            model=MODEL_ID,
            max_model_len=4096,
            gpu_memory_utilization=0.85,
            dtype="float16",
        )
        _llm_loaded = True
        logger.info("DeepSeek model loaded successfully")
    except Exception as exc:
        _llm_error = str(exc)
        logger.warning(f"vLLM load failed (using regex fallback): {exc}")


def _llm_classify(req_dict: dict) -> Optional[dict]:
    """Run LLM inference. Returns None on any failure."""
    global _llm, _llm_error

    if _llm_error or _llm is None:
        return None

    try:
        from vllm import SamplingParams
        prompt = _build_prompt(req_dict)
        params = SamplingParams(temperature=0.05, max_tokens=512, stop=["<|User|>"])
        outputs = _llm.generate([prompt], params)
        raw = outputs[0].outputs[0].text.strip()

        match = re.search(r'\{.*\}', raw, re.DOTALL)
        if not match:
            logger.warning("LLM response had no JSON block")
            return None

        result = json.loads(match.group())
        result["method"] = "deepseek"
        return result

    except Exception as exc:
        err = str(exc)
        if "out of memory" in err.lower() or "CUDA out of memory" in err:
            logger.error("GPU OOM — switching to regex-only mode")
            _llm_error = "GPU OOM"
        else:
            logger.error(f"LLM inference error: {exc}")
        return None


# ── Request/Response models ───────────────────────────────────────────────────

class ClassifyRequest(BaseModel):
    email_body: str
    subject: str = ""
    attachments: list[str] = []
    recipient_domains: list[str] = []
    org_id: str = ""


class ClassifyResponse(BaseModel):
    risk_level: str          # low | medium | high | critical
    action: str              # ALLOW | WARN | HOLD | BLOCK
    categories: list[str]
    confidence: float
    matched_patterns: list[str]
    explanation: str
    method: str = "regex"    # regex | deepseek


# ── Routes ────────────────────────────────────────────────────────────────────

@app.post("/classify", response_model=ClassifyResponse)
async def classify(req: ClassifyRequest):
    """Classify an email for DLP violations."""
    body_text = f"Subject: {req.subject}\n\n{req.email_body}"
    if req.attachments:
        body_text += "\n\nAttachment filenames: " + ", ".join(req.attachments)

    # Step 1: regex (always, fast deterministic baseline)
    regex_result = regex_classify(body_text)

    # Step 2: short-circuit if regex found critical — LLM won't make it more critical
    if regex_result["risk_level"] == "critical":
        return ClassifyResponse(**regex_result)

    # Step 3: Try to load LLM (no-op if already loaded/failed)
    _load_llm()

    # Step 4: LLM classification for nuanced detection
    req_dict = req.model_dump()
    llm_result = _llm_classify(req_dict)

    if llm_result is None:
        # LLM unavailable — return regex result
        return ClassifyResponse(**regex_result)

    # Step 5: Merge regex + LLM results (take more severe)
    all_categories = list(set(
        regex_result["categories"] + llm_result.get("categories", [])
    ))
    all_patterns = list(set(
        regex_result["matched_patterns"] + llm_result.get("matched_patterns", [])
    ))

    # Use more severe action
    regex_sev = _SEV_ORDER.get(regex_result["risk_level"], 0)
    llm_sev = _SEV_ORDER.get(llm_result.get("risk_level", "low"), 0)

    if regex_sev >= llm_sev:
        final = {**llm_result, **regex_result}
    else:
        final = {**regex_result, **llm_result}

    final["categories"] = all_categories
    final["matched_patterns"] = all_patterns
    final["method"] = "deepseek"

    return ClassifyResponse(**final)


@app.get("/health")
async def health():
    """Liveness + model readiness check."""
    model_status = "not_loaded"
    if _llm_loaded:
        model_status = "loaded"
    elif _llm_error:
        model_status = f"error: {_llm_error}"

    return {
        "status": "ok",
        "model": MODEL_ID,
        "llm_status": model_status,
        "fallback": "regex" if not _llm_loaded else "none",
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001, log_level="info")
