"""
Himaya Helios - MODEL-002: A/B Testing Framework
Compares Claude vs GPT-4o classifications for accuracy, latency, and cost analysis.
Results stored in SQLite for offline analysis.
"""

from __future__ import annotations

import asyncio
import json
import logging
import sqlite3
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from models.content_classifier.classifier import ContentClassifier, _parse_llm_response, CLAUDE_MODEL, OPENAI_MODEL
from models.content_classifier.prompts import SYSTEM_PROMPT, get_messages_for_classification
from models.shared.config import LLM_TEMPERATURE, LLM_MAX_TOKENS, LLM_TIMEOUT_SECONDS
from models.shared.schemas import ContentClassificationResult, ThreatClassification

logger = logging.getLogger(__name__)

DEFAULT_DB_PATH = "/tmp/sentinel-ab-testing.db"


@dataclass
class ModelResult:
    """Result from a single model call in A/B test."""
    model: str
    classification: str
    confidence: float
    latency_ms: float
    input_tokens: int
    output_tokens: int
    cost_usd: float
    error: str | None = None
    raw_response: str | None = None


@dataclass
class ABTestRecord:
    """Complete A/B test record for one email."""
    email_id: str
    timestamp: str
    sender: str
    recipient: str
    subject_preview: str  # First 100 chars
    claude_result: ModelResult | None = None
    openai_result: ModelResult | None = None
    agreement: bool = False
    ground_truth: str | None = None  # If known

    @property
    def models_agree(self) -> bool:
        """Check if both models produced same classification."""
        if self.claude_result and self.openai_result:
            return self.claude_result.classification == self.openai_result.classification
        return False


class ABTestingDB:
    """
    SQLite database for storing A/B test results.
    """

    CREATE_TABLE_SQL = """
    CREATE TABLE IF NOT EXISTS ab_test_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email_id TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        sender TEXT,
        recipient TEXT,
        subject_preview TEXT,
        claude_classification TEXT,
        claude_confidence REAL,
        claude_latency_ms REAL,
        claude_input_tokens INTEGER,
        claude_output_tokens INTEGER,
        claude_cost_usd REAL,
        claude_error TEXT,
        openai_classification TEXT,
        openai_confidence REAL,
        openai_latency_ms REAL,
        openai_input_tokens INTEGER,
        openai_output_tokens INTEGER,
        openai_cost_usd REAL,
        openai_error TEXT,
        agreement INTEGER,
        ground_truth TEXT
    )
    """

    def __init__(self, db_path: str = DEFAULT_DB_PATH) -> None:
        self.db_path = db_path
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(self.CREATE_TABLE_SQL)
            conn.commit()

    def insert_record(self, record: ABTestRecord) -> int:
        """Insert a test record and return the row ID."""
        def _get(r: ModelResult | None, attr: str, default: Any = None) -> Any:
            return getattr(r, attr, default) if r else default

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                """INSERT INTO ab_test_results (
                    email_id, timestamp, sender, recipient, subject_preview,
                    claude_classification, claude_confidence, claude_latency_ms,
                    claude_input_tokens, claude_output_tokens, claude_cost_usd, claude_error,
                    openai_classification, openai_confidence, openai_latency_ms,
                    openai_input_tokens, openai_output_tokens, openai_cost_usd, openai_error,
                    agreement, ground_truth
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    record.email_id,
                    record.timestamp,
                    record.sender,
                    record.recipient,
                    record.subject_preview,
                    _get(record.claude_result, "classification"),
                    _get(record.claude_result, "confidence"),
                    _get(record.claude_result, "latency_ms"),
                    _get(record.claude_result, "input_tokens"),
                    _get(record.claude_result, "output_tokens"),
                    _get(record.claude_result, "cost_usd"),
                    _get(record.claude_result, "error"),
                    _get(record.openai_result, "classification"),
                    _get(record.openai_result, "confidence"),
                    _get(record.openai_result, "latency_ms"),
                    _get(record.openai_result, "input_tokens"),
                    _get(record.openai_result, "output_tokens"),
                    _get(record.openai_result, "cost_usd"),
                    _get(record.openai_result, "error"),
                    int(record.models_agree),
                    record.ground_truth,
                ),
            )
            conn.commit()
            return cursor.lastrowid

    def get_summary_stats(self) -> dict[str, Any]:
        """Compute summary statistics across all A/B tests."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            total = conn.execute("SELECT COUNT(*) as n FROM ab_test_results").fetchone()["n"]
            if total == 0:
                return {"total": 0}

            agree = conn.execute("SELECT COUNT(*) as n FROM ab_test_results WHERE agreement=1").fetchone()["n"]

            claude_stats = conn.execute("""
                SELECT
                    AVG(claude_latency_ms) as avg_latency,
                    SUM(claude_cost_usd) as total_cost,
                    AVG(claude_confidence) as avg_confidence,
                    COUNT(claude_error) as error_count
                FROM ab_test_results WHERE claude_classification IS NOT NULL
            """).fetchone()

            openai_stats = conn.execute("""
                SELECT
                    AVG(openai_latency_ms) as avg_latency,
                    SUM(openai_cost_usd) as total_cost,
                    AVG(openai_confidence) as avg_confidence,
                    COUNT(openai_error) as error_count
                FROM ab_test_results WHERE openai_classification IS NOT NULL
            """).fetchone()

            # Classification distribution
            claude_dist = conn.execute("""
                SELECT claude_classification as cls, COUNT(*) as n
                FROM ab_test_results
                WHERE claude_classification IS NOT NULL
                GROUP BY claude_classification
            """).fetchall()

            openai_dist = conn.execute("""
                SELECT openai_classification as cls, COUNT(*) as n
                FROM ab_test_results
                WHERE openai_classification IS NOT NULL
                GROUP BY openai_classification
            """).fetchall()

        return {
            "total_tests": total,
            "agreement_rate": round(agree / total, 3) if total > 0 else 0,
            "agreement_count": agree,
            "claude": {
                "avg_latency_ms": round(claude_stats["avg_latency"] or 0, 1),
                "total_cost_usd": round(claude_stats["total_cost"] or 0, 4),
                "avg_confidence": round(claude_stats["avg_confidence"] or 0, 3),
                "error_count": claude_stats["error_count"] or 0,
                "classification_distribution": {row["cls"]: row["n"] for row in claude_dist},
            },
            "openai": {
                "avg_latency_ms": round(openai_stats["avg_latency"] or 0, 1),
                "total_cost_usd": round(openai_stats["total_cost"] or 0, 4),
                "avg_confidence": round(openai_stats["avg_confidence"] or 0, 3),
                "error_count": openai_stats["error_count"] or 0,
                "classification_distribution": {row["cls"]: row["n"] for row in openai_dist},
            },
        }


class ABTester:
    """
    Runs both Claude and GPT-4o on the same email and records comparison results.

    Use this to:
    - Track model agreement rate over time
    - Compare accuracy when ground truth is available
    - Monitor cost efficiency per classification
    - Identify cases where models disagree (review queue)
    """

    def __init__(
        self,
        classifier: ContentClassifier | None = None,
        db_path: str = DEFAULT_DB_PATH,
        timeout_seconds: float = LLM_TIMEOUT_SECONDS,
    ) -> None:
        self.classifier = classifier or ContentClassifier(timeout_seconds=timeout_seconds)
        self.db = ABTestingDB(db_path=db_path)

    async def _call_single_model(
        self,
        messages: list[dict[str, str]],
        model: str,
    ) -> ModelResult:
        """Call a single model and return structured result."""
        t0 = time.time()
        try:
            if "claude" in model.lower():
                raw, in_tok, out_tok = await self.classifier._call_claude(messages)
            else:
                raw, in_tok, out_tok = await self.classifier._call_openai(messages)

            result = _parse_llm_response(raw, model)
            latency = (time.time() - t0) * 1000
            cost = self.classifier._compute_cost(in_tok, out_tok, model)

            return ModelResult(
                model=model,
                classification=result.classification.value,
                confidence=result.confidence,
                latency_ms=latency,
                input_tokens=in_tok,
                output_tokens=out_tok,
                cost_usd=cost,
                raw_response=raw[:500],  # truncate for storage
            )

        except asyncio.TimeoutError:
            return ModelResult(
                model=model,
                classification="UNCERTAIN",
                confidence=0.0,
                latency_ms=(time.time() - t0) * 1000,
                input_tokens=0,
                output_tokens=0,
                cost_usd=0.0,
                error="timeout",
            )
        except Exception as e:
            return ModelResult(
                model=model,
                classification="UNCERTAIN",
                confidence=0.0,
                latency_ms=(time.time() - t0) * 1000,
                input_tokens=0,
                output_tokens=0,
                cost_usd=0.0,
                error=str(e)[:200],
            )

    async def run_test(
        self,
        email_id: str,
        sender: str,
        recipient: str,
        subject: str,
        body: str,
        attachments: list[str] | None = None,
        headers: dict[str, str] | None = None,
        ground_truth: str | None = None,
    ) -> ABTestRecord:
        """
        Run both models on the same email and record results.

        Args:
            email_id: Unique identifier for this email
            sender: Sender email address
            recipient: Recipient email address
            subject: Email subject
            body: Email body
            attachments: Attachment filenames
            headers: Email headers
            ground_truth: Known correct classification (optional)

        Returns:
            ABTestRecord with both model results
        """
        messages = get_messages_for_classification(
            sender=sender,
            recipient=recipient,
            subject=subject,
            body=body,
            attachments=attachments,
            headers=headers,
            include_few_shot=self.classifier.include_few_shot,
        )

        # Run both models in parallel
        claude_task = self._call_single_model(messages, CLAUDE_MODEL)
        openai_task = self._call_single_model(messages, OPENAI_MODEL)
        claude_result, openai_result = await asyncio.gather(claude_task, openai_task)

        record = ABTestRecord(
            email_id=email_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            sender=sender,
            recipient=recipient,
            subject_preview=subject[:100],
            claude_result=claude_result,
            openai_result=openai_result,
            ground_truth=ground_truth,
        )

        # Persist to database
        row_id = self.db.insert_record(record)
        logger.info(
            f"A/B test [{email_id}]: Claude={claude_result.classification} "
            f"OpenAI={openai_result.classification} "
            f"Agreement={'✓' if record.models_agree else '✗'} "
            f"DB row={row_id}"
        )

        return record

    async def run_batch_test(
        self,
        emails: list[dict[str, Any]],
        concurrency: int = 3,
    ) -> list[ABTestRecord]:
        """
        Run A/B tests on multiple emails concurrently.

        Args:
            emails: List of dicts with email data + optional ground_truth
            concurrency: Max concurrent test pairs

        Returns:
            List of ABTestRecord results
        """
        semaphore = asyncio.Semaphore(concurrency)

        async def run_with_sem(email: dict[str, Any]) -> ABTestRecord:
            async with semaphore:
                return await self.run_test(
                    email_id=email.get("email_id", str(time.time())),
                    sender=email["sender"],
                    recipient=email["recipient"],
                    subject=email["subject"],
                    body=email["body"],
                    attachments=email.get("attachments"),
                    headers=email.get("headers"),
                    ground_truth=email.get("ground_truth"),
                )

        return await asyncio.gather(*[run_with_sem(e) for e in emails])

    def print_summary(self) -> None:
        """Print formatted summary statistics to stdout."""
        stats = self.db.get_summary_stats()
        if stats.get("total_tests", 0) == 0:
            print("No A/B test data available.")
            return

        print("\n" + "=" * 60)
        print("SENTINEL MAIL — A/B TEST SUMMARY")
        print("=" * 60)
        print(f"Total tests: {stats['total_tests']}")
        print(f"Agreement rate: {stats['agreement_rate']:.1%} ({stats['agreement_count']} / {stats['total_tests']})")

        for model_name, model_key in [("Claude", "claude"), ("GPT-4o", "openai")]:
            ms = stats[model_key]
            print(f"\n{model_name}:")
            print(f"  Avg latency:   {ms['avg_latency_ms']:.0f}ms")
            print(f"  Total cost:    ${ms['total_cost_usd']:.4f}")
            print(f"  Avg confidence:{ms['avg_confidence']:.2f}")
            print(f"  Errors:        {ms['error_count']}")
            print(f"  Classifications:")
            for cls, count in sorted(ms['classification_distribution'].items()):
                print(f"    {cls}: {count}")

        print("=" * 60 + "\n")
