from __future__ import annotations

import asyncio
import json
import logging
import os
import re

from config.aws import bedrock_runtime

logger = logging.getLogger(__name__)

_MODEL_ID = os.getenv(
    "GRAPH_LLM_MODEL_ID",
    "minimax.minimax-m2.5",
)

_SYSTEM = """\
You are a graph-signal trust analyst for an email security system.
You receive structured behavioural data about an email sender and must reason about trust.

Rules:
- Reason only from graph signals provided. Never infer from email content.
- Output a single JSON object. No prose, no markdown fences.
- trust_score must be an integer between 0 and 100.
- reasoning must be under 80 words.
"""

_OUTPUT_SCHEMA = (
    '{"trust_score": <int 0..100>, "reasoning": "<str ≤80 words>", '
    '"key_signals": ["<str>", ...], "confidence": <float 0.0-1.0>}'
)


def apply_llm(rule: dict, llm: dict) -> dict:
    return {
        **rule,
        "trust_score":    llm["llm_trust_score"],
        "trust_method":   rule["trust_method"] + "+llm",
        "reasoning":      rule["reasoning"] + f" | LLM: {llm['llm_reasoning']}",
        "indicators":     rule["indicators"] + llm["llm_key_signals"],
        "llm_adjustment": llm["llm_trust_score"] - rule["trust_score"],
        "llm_reasoning":  llm["llm_reasoning"],
        "llm_confidence": llm["llm_confidence"],
        "llm_model":      llm["llm_model"],
    }


def should_invoke(rule_verdict: dict) -> bool:
    method = rule_verdict.get("trust_method", "")
    score  = rule_verdict.get("trust_score", 50)

    if method == "block":
        return False                     # hard fact — never override

    if method == "insufficient_history":
        return True                      # rules can't score; LLM can reason forward

    if 35 <= score <= 55:
        return True                      # deterministic ambiguous zone

    return False


async def analyze_trust(
    graph_data: dict,
    rule_verdict: dict,
    content_hint: str | None = None,
    reputation_hint: dict | None = None,
) -> dict | None:
    prompt = _build_prompt(graph_data, rule_verdict, content_hint, reputation_hint)
    try:
        raw = await asyncio.to_thread(_invoke, prompt)
        llm_score = max(0, min(100, int(raw["trust_score"])))

        logger.info(
            "Graph LLM | trust_score=%d conf=%.2f method=%s",
            llm_score,
            raw.get("confidence", 0),
            rule_verdict.get("trust_method"),
        )

        return {
            "llm_trust_score": llm_score,
            "llm_reasoning":   raw.get("reasoning", ""),
            "llm_key_signals": raw.get("key_signals", []),
            "llm_confidence":  float(raw.get("confidence", 0.5)),
            "llm_model":       _MODEL_ID,
        }

    except Exception as exc:
        logger.warning("Graph LLM failed (non-fatal): %s", exc)
        return None


def _invoke(prompt: str) -> dict:
    body = json.dumps({
        "model": _MODEL_ID,
        "max_tokens": 1000,
        "messages": [
            {"role": "system", "content": _SYSTEM},
            {"role": "user",   "content": prompt},
        ],
        "temperature": 0.3,
    })
    response = bedrock_runtime.invoke_model(
        modelId=_MODEL_ID,
        contentType="application/json",
        accept="application/json",
        body=body,
    )
    raw = response["body"].read()
    logger.info("llm_analyst._invoke | raw_bytes=%d", len(raw))

    try:
        response_body = json.loads(raw)
    except json.JSONDecodeError:
        logger.warning("llm_analyst._invoke | response body is not JSON: %r", raw[:500])
        raise

    logger.info("llm_analyst._invoke | response_body keys=%s", list(response_body.keys()))

    text = response_body["choices"][0]["message"]["content"].strip()
    logger.info("llm_analyst._invoke | raw content=%r", text)

    stripped = re.sub(r"<reasoning>.*?</reasoning>", "", text, flags=re.DOTALL).strip()
    search_in = stripped if stripped else text

    match = re.search(r"\{.*\}", search_in, re.DOTALL)
    if not match:
        logger.warning("llm_analyst._invoke | no JSON object found. full content=%r", text)
        raise ValueError("no JSON object in model output")

    text = match.group()
    logger.info("llm_analyst._invoke | extracted JSON=%r", text[:300])

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        logger.warning("llm_analyst._invoke | model output is not valid JSON: %r", text[:300])
        raise


def _build_prompt(
    graph_data: dict,
    rule_verdict: dict,
    content_hint: str | None,
    reputation_hint: dict | None,
) -> str:
    s     = graph_data.get("sender", {})
    d     = graph_data.get("domain", {})
    rel   = graph_data.get("relationship", {})
    intel = graph_data.get("intel", {})

    hint_line = f"\nUpstream content classifier: {content_hint}" if content_hint else ""

    rep_section = ""
    if reputation_hint:
        auth_parts = []
        if reputation_hint.get("spf_pass") is not None:
            auth_parts.append(f"spf={'pass' if reputation_hint['spf_pass'] else 'fail'}")
        if reputation_hint.get("dkim_pass") is not None:
            auth_parts.append(f"dkim={'pass' if reputation_hint['dkim_pass'] else 'fail'}")
        if reputation_hint.get("dmarc_pass") is not None:
            auth_parts.append(f"dmarc={'pass' if reputation_hint['dmarc_pass'] else 'fail'}")
        rep_section = f"""
EXTERNAL REPUTATION  (from threat-intel sources)
  reputation_score: {reputation_hint.get('reputation_score', 0)}/100  (higher = more malicious)
  auth:             {', '.join(auth_parts) if auth_parts else 'unknown'}
  indicators:       {reputation_hint.get('indicators', [])}
"""

    return f"""\
Evaluate sender trust from graph signals only.{hint_line}

SENDER
  emails_sent:        {s.get('email_count', 0)}
  flagged_as_threats: {s.get('threat_count', 0)}
  reputation:         {s.get('reputation_score', 0)}/100
  threat_types_seen:  {s.get('historical_threat_types', [])}
  first_seen:         {s.get('first_seen', 'unknown')}

DOMAIN
  total_emails:  {d.get('total_emails', 0)}
  flagged:       {d.get('flagged_emails', 0)}  ({d.get('flagged_email_rate', 0):.4%})
  total_senders: {d.get('total_senders', 0)}
  orgs_targeted: {d.get('orgs_targeted', 0)}

RELATIONSHIP  (with this recipient)
  prior_emails: {rel.get('prior_emails_to_recipient', 0)}
  last_contact: {rel.get('last_contact', 'never')}

INTEL
  reported_by_other_orgs: {intel.get('reported_by_other_orgs', 0)}
  similar_threat_senders: {intel.get('similar_threat_senders', [])}
{rep_section}
RULE ENGINE
  trust_score:  {rule_verdict.get('trust_score')}/100
  trust_method: {rule_verdict.get('trust_method')}
  indicators:   {rule_verdict.get('indicators', [])}

Provide a trust score (0-100) for this sender. 0 = no trust, 100 = fully trusted.
Output schema (JSON only, no fences): {_OUTPUT_SCHEMA}
"""
