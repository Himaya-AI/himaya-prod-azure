"""
Helios DLP — DeepSeek-R1-Distill-Qwen-7B Inference Server (v2)
Port: 8001

Fixed prompt template for Qwen-based model.
DeepSeek-R1-Distill models use Qwen's chat template, not DeepSeek's.

Endpoints:
  POST /classify  — classify email for DLP violations
  GET  /health    — liveness check + model status
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import threading
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

MODEL_ID = os.getenv("DEEPSEEK_MODEL_ID", "deepseek-ai/DeepSeek-R1-Distill-Qwen-7B")
_llm = None
_llm_loaded = False
_llm_loading = False
_llm_error: Optional[str] = None
_llm_lock = threading.Lock()


# ── Regex supplementary patterns ─────────────────────────────────────────────

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
    # Financial
    _Pattern(r'\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b',                        "high",     "financial_swift"),
    _Pattern(r'(?i)wire\s*transfer',                                                       "high",     "financial_wire"),
    # Credentials
    _Pattern(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',                  "critical", "credential_private_key"),
    _Pattern(r'AKIA[0-9A-Z]{16}',                                                          "critical", "credential_aws_key"),
    _Pattern(r'(?i)(?:api[_\-]?key|secret[_\-]?key)\s*[:=]\s*[\'"]?([A-Za-z0-9_\-]{20,})',
                                                                                           "critical", "credential_api_key"),
    _Pattern(r'ghp_[A-Za-z0-9]{36}',                                                      "critical", "credential_github_pat"),
    # Bulk exfiltration
    _Pattern(r'(?i)(?:bcc:|cc:)(?:[^,\n]+,\s*){19,}',                                    "high",     "bulk_exfil_bcc"),
    # ITAR
    _Pattern(r'(?i)\b(?:ITAR|EAR|ECCN)\b',                                               "high",     "itar"),
]

_SEV_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
_ACT_MAP = {"low": "ALLOW", "medium": "WARN", "high": "HOLD", "critical": "BLOCK"}


def regex_classify(text: str) -> dict:
    """Fast regex supplementary scan."""
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
            f"Regex patterns matched: {', '.join(set(matched))}" if matched
            else "No sensitive patterns detected by regex scan."
        ),
        "method": "regex",
    }


# ── LLM prompt — using Qwen/ChatML format ─────────────────────────────────────
# DeepSeek-R1-Distill-Qwen models use Qwen's ChatML template:
# <|im_start|>system\n...<|im_end|>\n<|im_start|>user\n...<|im_end|>\n<|im_start|>assistant\n

# For DeepSeek-R1-Distill models, we use a more direct prompt that asks for
# JSON output immediately. The model may still think internally but should
# conclude with JSON.
_SYSTEM_PROMPT = """You are a DLP (Data Loss Prevention) classifier. Analyze emails and output JSON.

Categories: pii_ssn, pii_credit_card, pii_iban, pii_passport, financial_wire, financial_account, credential_private_key, credential_api_key, credential_password, credential_token, financial_unreleased, employee_data, ip_source_code, legal_privileged, customer_data, insider_exfil, bulk_exfil, itar

Risk levels: low (ALLOW), medium (WARN), high (HOLD), critical (BLOCK)

You MUST end your response with a JSON object in this exact format:
{"risk_level": "...", "action": "...", "categories": [...], "confidence": 0.0, "matched_patterns": [...], "explanation": "..."}"""


def _build_prompt(req_dict: dict) -> str:
    """Build ChatML-formatted prompt for Qwen-based model."""
    attachments = req_dict.get("attachments", [])
    att_line = f"\nAttachments: {', '.join(attachments)}" if attachments else ""
    
    user_msg = f"""Classify this email for DLP violations.

Subject: {req_dict.get("subject", "")[:200]}
Recipients: {", ".join(req_dict.get("recipient_domains", [])) or "internal"}
{att_line}

Body:
{req_dict.get("email_body", "")[:3500]}

Return only the JSON classification:"""

    # ChatML format for Qwen
    prompt = (
        f"<|im_start|>system\n{_SYSTEM_PROMPT}<|im_end|>\n"
        f"<|im_start|>user\n{user_msg}<|im_end|>\n"
        f"<|im_start|>assistant\n"
    )
    return prompt


# ── Model loading — runs in background thread at startup ─────────────────────

def _load_llm_bg():
    """Load vLLM engine in a background thread."""
    global _llm, _llm_loaded, _llm_loading, _llm_error
    with _llm_lock:
        if _llm_loaded or _llm_error:
            return
        _llm_loading = True
    try:
        from vllm import LLM
        logger.info(f"[startup] Loading {MODEL_ID} via vLLM...")
        llm = LLM(
            model=MODEL_ID,
            max_model_len=8192,
            gpu_memory_utilization=0.92,
            dtype="float16",
            quantization="bitsandbytes",
            load_format="bitsandbytes",
        )
        with _llm_lock:
            _llm = llm
            _llm_loaded = True
            _llm_loading = False
        logger.info("[startup] DeepSeek model loaded successfully")
    except Exception as exc:
        with _llm_lock:
            _llm_error = str(exc)
            _llm_loading = False
        logger.error(f"[startup] vLLM load failed: {exc}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Start model loading in background at startup."""
    t = threading.Thread(target=_load_llm_bg, daemon=True, name="vllm-loader")
    t.start()
    logger.info("[startup] Model loading started in background")
    yield
    logger.info("[shutdown] DLP inference shutting down")


app = FastAPI(title="Helios DLP Inference", version="2.0.0", lifespan=lifespan)


def _extract_json(raw: str) -> Optional[dict]:
    """Extract JSON from model output, handling chain-of-thought reasoning."""
    # DeepSeek-R1-Distill models output reasoning text then JSON at the end
    text = raw.strip()
    
    # Find the LAST JSON object in the response (model thinks, then outputs JSON)
    # Look for JSON that contains our expected fields
    all_json_matches = list(re.finditer(r'\{[^{}]*"risk_level"[^{}]*"action"[^{}]*\}', text, re.DOTALL))
    if all_json_matches:
        # Take the last match (after reasoning)
        try:
            return json.loads(all_json_matches[-1].group())
        except json.JSONDecodeError:
            pass
    
    # Try finding any JSON with risk_level
    all_json_matches = list(re.finditer(r'\{[^{}]*"risk_level"[^{}]*\}', text, re.DOTALL))
    if all_json_matches:
        try:
            return json.loads(all_json_matches[-1].group())
        except json.JSONDecodeError:
            pass
    
    # Last resort: find any well-formed JSON object at the end
    # Search from the end of the string
    for i in range(len(text) - 1, -1, -1):
        if text[i] == '}':
            # Find matching opening brace
            depth = 1
            for j in range(i - 1, -1, -1):
                if text[j] == '}':
                    depth += 1
                elif text[j] == '{':
                    depth -= 1
                    if depth == 0:
                        try:
                            candidate = text[j:i+1]
                            result = json.loads(candidate)
                            if isinstance(result, dict) and "risk_level" in result:
                                return result
                        except json.JSONDecodeError:
                            pass
                        break
            break
    
    logger.warning(f"Could not extract JSON from response (len={len(text)}): {text[:300]}...")
    return None


def _llm_classify(req_dict: dict) -> Optional[dict]:
    """Run LLM inference. Returns None on any failure."""
    global _llm, _llm_error
    with _llm_lock:
        llm = _llm
        err = _llm_error

    if err or llm is None:
        return None

    try:
        from vllm import SamplingParams
        prompt = _build_prompt(req_dict)
        # DeepSeek-R1-Distill outputs reasoning then JSON. Need more tokens.
        # Stop at end of assistant turn.
        params = SamplingParams(
            temperature=0.1,
            max_tokens=1024,  # Increased for chain-of-thought + JSON
            stop=["<|im_end|>", "<|im_start|>"],
        )
        outputs = llm.generate([prompt], params)
        raw = outputs[0].outputs[0].text.strip()
        
        logger.debug(f"Raw LLM output: {raw[:500]}")
        
        result = _extract_json(raw)
        if result:
            # Validate required fields
            if "risk_level" not in result or "action" not in result:
                logger.warning(f"JSON missing required fields: {result}")
                return None
            result["method"] = "deepseek"
            return result
        
        return None

    except Exception as exc:
        err_str = str(exc)
        if "out of memory" in err_str.lower() or "CUDA" in err_str:
            logger.error(f"GPU error: {exc}")
            with _llm_lock:
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
    risk_level: str
    action: str
    categories: list[str]
    confidence: float
    matched_patterns: list[str]
    explanation: str
    method: str = "deepseek"
    score: Optional[int] = None


# ── Routes ────────────────────────────────────────────────────────────────────

@app.post("/classify", response_model=ClassifyResponse)
async def classify(req: ClassifyRequest):
    """Classify email for DLP violations."""
    with _llm_lock:
        loading = _llm_loading
        loaded = _llm_loaded
        err = _llm_error

    if loading and not loaded:
        raise HTTPException(
            status_code=503,
            detail="DLP model is still loading. Retry in 60-90 seconds."
        )

    if err and not loaded:
        raise HTTPException(
            status_code=503,
            detail=f"DLP model failed to load: {err}"
        )

    # Run LLM inference in thread pool
    loop = asyncio.get_running_loop()
    req_dict = req.model_dump()
    llm_result = await loop.run_in_executor(None, _llm_classify, req_dict)

    # Regex supplementary scan
    body_text = f"Subject: {req.subject}\n\n{req.email_body}"
    if req.attachments:
        body_text += "\n\nAttachments: " + ", ".join(req.attachments)
    regex_result = regex_classify(body_text)

    if llm_result is None:
        logger.warning("LLM inference failed — using regex fallback")
        return ClassifyResponse(**regex_result)

    # Merge: take more severe across DeepSeek + regex
    all_cats = list(set(llm_result.get("categories", []) + regex_result["categories"]))
    all_pats = list(set(llm_result.get("matched_patterns", []) + regex_result["matched_patterns"]))

    ds_sev = _SEV_ORDER.get(llm_result.get("risk_level", "low"), 0)
    rx_sev = _SEV_ORDER.get(regex_result["risk_level"], 0)

    if rx_sev > ds_sev:
        final = {**llm_result}
        final["risk_level"] = regex_result["risk_level"]
        final["action"] = regex_result["action"]
        final["explanation"] = (
            f"{llm_result.get('explanation','')} "
            f"[Regex elevated: {regex_result.get('explanation','')}]"
        )
    else:
        final = {**llm_result}

    final["categories"] = all_cats
    final["matched_patterns"] = all_pats
    final["method"] = "deepseek"

    # Numeric score
    sev_scores = {"low": 5, "medium": 45, "high": 75, "critical": 95}
    base = sev_scores.get(final.get("risk_level", "low"), 5)
    conf = float(final.get("confidence") or 0.5)
    final["score"] = min(100, max(0, int(base + (conf - 0.5) * 20)))

    return ClassifyResponse(**final)


@app.get("/health")
async def health():
    """Liveness + model readiness check."""
    with _llm_lock:
        loaded = _llm_loaded
        loading = _llm_loading
        err = _llm_error

    if loaded:
        status = "loaded"
    elif loading:
        status = "loading"
    elif err:
        status = f"error: {err}"
    else:
        status = "not_started"

    return {
        "status": "ok",
        "model": MODEL_ID,
        "llm_status": status,
        "ready": loaded,
        "version": "2.0.0",
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001, log_level="info", workers=1)
