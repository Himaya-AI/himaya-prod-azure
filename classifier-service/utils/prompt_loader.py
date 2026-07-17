from __future__ import annotations

import json
import logging
import threading
from typing import Any

from config.aws import PROMPT_BUCKET, s3_client

logger = logging.getLogger(__name__)

_cache: dict[str, Any] = {}
_lock = threading.Lock()

_SYSTEM_PROMPT_KEY = "system_prompt.txt"
_FEW_SHOTS_KEY = "few_shots.json"


def _fetch_system_prompt() -> str:
    logger.info(f"Fetching {_SYSTEM_PROMPT_KEY} from s3://{PROMPT_BUCKET}")
    try:
        response = s3_client.get_object(Bucket=PROMPT_BUCKET, Key=_SYSTEM_PROMPT_KEY)
        logger.info(f"S3 get_object succeeded for {_SYSTEM_PROMPT_KEY}, reading body...")
        content = response["Body"].read().decode("utf-8")
        logger.info(f"Loaded {_SYSTEM_PROMPT_KEY}: {len(content)} chars")
        return content
    except Exception as e:
        logger.error(f"Failed to fetch {_SYSTEM_PROMPT_KEY} from s3://{PROMPT_BUCKET}: {type(e).__name__}: {e}", exc_info=True)
        raise


def _fetch_few_shot_examples() -> list[dict[str, str]]:
    logger.info(f"Fetching {_FEW_SHOTS_KEY} from s3://{PROMPT_BUCKET}")
    try:
        response = s3_client.get_object(Bucket=PROMPT_BUCKET, Key=_FEW_SHOTS_KEY)
        logger.info(f"S3 get_object succeeded for {_FEW_SHOTS_KEY}, reading body...")
        content = response["Body"].read().decode("utf-8")
        logger.info(f"Loaded {_FEW_SHOTS_KEY}: {len(content)} chars, parsing JSON...")
        data = json.loads(content)
        logger.info(f"Parsed {_FEW_SHOTS_KEY}: {len(data)} examples")
        return data
    except Exception as e:
        logger.error(f"Failed to fetch {_FEW_SHOTS_KEY} from s3://{PROMPT_BUCKET}: {type(e).__name__}: {e}", exc_info=True)
        raise


def get_system_prompt() -> str:
    if _SYSTEM_PROMPT_KEY not in _cache:
        with _lock:
            if _SYSTEM_PROMPT_KEY not in _cache:
                _cache[_SYSTEM_PROMPT_KEY] = _fetch_system_prompt()
    return _cache[_SYSTEM_PROMPT_KEY]


def get_few_shot_examples() -> list[dict[str, str]]:
    if _FEW_SHOTS_KEY not in _cache:
        with _lock:
            if _FEW_SHOTS_KEY not in _cache:
                _cache[_FEW_SHOTS_KEY] = _fetch_few_shot_examples()
    return _cache[_FEW_SHOTS_KEY]


def build_classification_prompt(
    sender: str,
    recipient: str,
    subject: str,
    body: str,
    attachments: list[str] | None = None,
    headers: dict[str, str] | None = None,
    email_verify: dict[str, Any] | None = None,
) -> str:
    parts = [f"Analyze this email:\nFROM: {sender}\nTO: {recipient}\nSUBJECT: {subject}"]

    if headers:
        parts.append("HEADERS:")
        for k, v in headers.items():
            parts.append(f"  {k}: {v}")

    if email_verify:
        parts.append("EMAIL_VERIFY:")
        parts.append(json.dumps(email_verify, indent=2, sort_keys=True, ensure_ascii=False))

    if attachments:
        parts.append(f"ATTACHMENTS: {', '.join(attachments)}")

    parts.append(f"BODY:\n{body}")

    return "\n".join(parts)


def get_messages_for_classification(
    sender: str,
    recipient: str,
    subject: str,
    body: str,
    attachments: list[str] | None = None,
    headers: dict[str, str] | None = None,
    email_verify: dict[str, Any] | None = None,
    include_few_shot: bool = True,
) -> list[dict[str, str]]:
    messages: list[dict[str, str]] = []

    if include_few_shot:
        messages.extend(get_few_shot_examples())

    messages.append({
        "role": "user",
        "content": build_classification_prompt(
            sender=sender,
            recipient=recipient,
            subject=subject,
            body=body,
            attachments=attachments,
            headers=headers,
            email_verify=email_verify,
        ),
    })

    return messages


def reload_prompts() -> None:
    """Clear the cache and re-fetch both prompts from S3."""
    _cache.clear()
    get_system_prompt()
    get_few_shot_examples()
    logger.info("Prompt cache reloaded from S3.")
