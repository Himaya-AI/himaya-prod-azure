"""
Active learning feedback loop.

When an org admin confirms/dismisses a threat in the UI:
  1. Store the labeled sample in S3 (himaya-evidence bucket, feedback/ prefix)
  2. Update the threat record in DB with analyst verdict
  3. Accumulate samples until threshold → trigger SageMaker retraining job
  4. Update model performance metrics per-org for accuracy tracking

Label schema:
  confirmed_malicious  → True Positive  (model was right, also catches FN if admin escalates clean email)
  false_positive       → False Positive (model wrong, email was benign)
  confirmed_benign     → True Negative  (baseline, email was clean, model correctly low-scored)
"""

import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Literal, Optional

import boto3
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

S3_CLIENT = boto3.client("s3", region_name=os.getenv("AWS_REGION", "uaenorth"))
SAGEMAKER_CLIENT = boto3.client("sagemaker", region_name=os.getenv("AWS_REGION", "uaenorth"))

EVIDENCE_BUCKET = os.getenv("S3_EVIDENCE_BUCKET", "himaya-evidence")
MODELS_BUCKET = os.getenv("S3_MODELS_BUCKET", "himaya-models-prod")

# Minimum samples before triggering a retraining job
RETRAIN_THRESHOLD = int(os.getenv("RETRAIN_THRESHOLD", "50"))

FeedbackLabel = Literal["confirmed_malicious", "false_positive", "confirmed_benign"]


async def record_analyst_feedback(
    threat_id: str,
    org_id: str,
    analyst_email: str,
    label: FeedbackLabel,
    notes: Optional[str],
    threat_snapshot: dict,
    db: AsyncSession,
) -> dict:
    """
    Main entry point. Call this when admin clicks Confirm/Dismiss on a threat.

    threat_snapshot should include:
      - threat_type, risk_score, score_breakdown
      - sender, sender_domain, subject_hash
      - ai_explanation_en, threat_indicators
      - original email body snippet (if available and policy allows)
    """
    feedback_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    # 1. Persist to S3 for training dataset
    sample = {
        "feedback_id": feedback_id,
        "threat_id": threat_id,
        "org_id": org_id,
        "analyst": analyst_email,
        "label": label,
        "notes": notes,
        "timestamp": now,
        "model_prediction": {
            "threat_type": threat_snapshot.get("threat_type"),
            "risk_score": threat_snapshot.get("risk_score"),
            "score_breakdown": threat_snapshot.get("score_breakdown"),
            "indicators": threat_snapshot.get("threat_indicators"),
        },
        "features": {
            "sender_domain": threat_snapshot.get("sender_domain"),
            "subject_hash": threat_snapshot.get("subject_hash"),
            "content_score": threat_snapshot.get("content_score"),
            "graph_score": threat_snapshot.get("graph_score"),
            "reputation_score": threat_snapshot.get("reputation_score"),
            "ai_explanation": threat_snapshot.get("ai_explanation_en"),
        },
    }

    s3_key = f"feedback/{org_id}/{label}/{feedback_id}.json"
    try:
        S3_CLIENT.put_object(
            Bucket=EVIDENCE_BUCKET,
            Key=s3_key,
            Body=json.dumps(sample),
            ContentType="application/json",
            Metadata={
                "org_id": org_id,
                "label": label,
                "feedback_id": feedback_id,
            },
        )
        logger.info(f"Feedback sample stored: s3://{EVIDENCE_BUCKET}/{s3_key}")
    except Exception as e:
        logger.error(f"Failed to store feedback to S3: {e}")

    # 2. Update threat record in DB
    try:
        from backend.models.db_models import Threat
        verdict_map = {
            "confirmed_malicious": "confirmed",
            "false_positive": "false_positive",
            "confirmed_benign": "benign",
        }
        await db.execute(
            update(Threat)
            .where(Threat.id == uuid.UUID(threat_id))
            .values(
                status=verdict_map.get(label, "reviewed"),
                analyst_verdict=label,
                analyst_email=analyst_email,
                reviewed_at=datetime.now(timezone.utc),
                analyst_notes=notes,
            )
        )
        await db.flush()
    except Exception as e:
        logger.error(f"Failed to update threat verdict in DB: {e}")

    # 3. Check if we should trigger retraining
    retrain_triggered = await _maybe_trigger_retraining(org_id)

    # 4. Update org-level accuracy metrics
    await _update_accuracy_metrics(org_id, label, db)

    return {
        "feedback_id": feedback_id,
        "s3_key": s3_key,
        "retrain_triggered": retrain_triggered,
        "message": _feedback_message(label),
    }


def _feedback_message(label: FeedbackLabel) -> str:
    return {
        "confirmed_malicious": "Confirmed. This sample will strengthen threat detection.",
        "false_positive": "Noted. This false positive will improve model precision.",
        "confirmed_benign": "Acknowledged. Sample added to training baseline.",
    }.get(label, "Feedback recorded.")


async def _maybe_trigger_retraining(org_id: str) -> bool:
    """
    Count accumulated feedback samples for this org in S3.
    If we've hit the threshold, kick off a SageMaker training job.
    """
    try:
        # Count objects in this org's feedback prefix
        paginator = S3_CLIENT.get_paginator("list_objects_v2")
        count = 0
        for page in paginator.paginate(
            Bucket=EVIDENCE_BUCKET,
            Prefix=f"feedback/{org_id}/",
        ):
            count += page.get("KeyCount", 0)

        logger.info(f"Org {org_id} has {count} feedback samples (threshold: {RETRAIN_THRESHOLD})")

        if count > 0 and count % RETRAIN_THRESHOLD == 0:
            return await _trigger_sagemaker_retraining(org_id, count)

    except Exception as e:
        logger.warning(f"Could not check feedback count for retraining: {e}")

    return False


async def _trigger_sagemaker_retraining(org_id: str, sample_count: int) -> bool:
    """
    Launch a SageMaker training job using the accumulated feedback data.
    Uses the content_classifier training script.
    """
    job_name = f"sentinel-retrain-{org_id[:8]}-{int(datetime.now().timestamp())}"

    training_config = {
        "job_name": job_name,
        "org_id": org_id,
        "sample_count": sample_count,
        "triggered_at": datetime.now(timezone.utc).isoformat(),
        "input_data": f"s3://{EVIDENCE_BUCKET}/feedback/{org_id}/",
        "output_model": f"s3://{MODELS_BUCKET}/retrained/{org_id}/{job_name}/",
    }

    # Store job config so we can monitor it
    S3_CLIENT.put_object(
        Bucket=MODELS_BUCKET,
        Key=f"retrain-jobs/{job_name}.json",
        Body=json.dumps(training_config),
        ContentType="application/json",
    )

    try:
        SAGEMAKER_CLIENT.create_training_job(
            TrainingJobName=job_name,
            AlgorithmSpecification={
                "TrainingImage": f"__AZURE_ACCT__.dkr.ecr.uaenorth.amazonaws.com/himaya-backend:latest",
                "TrainingInputMode": "File",
            },
            RoleArn=f"arn:aws:iam::__AZURE_ACCT__:role/himaya-ecs-task-role",
            InputDataConfig=[
                {
                    "ChannelName": "feedback",
                    "DataSource": {
                        "S3DataSource": {
                            "S3DataType": "S3Prefix",
                            "S3Uri": f"s3://{EVIDENCE_BUCKET}/feedback/{org_id}/",
                            "S3DataDistributionType": "FullyReplicated",
                        }
                    },
                    "ContentType": "application/json",
                }
            ],
            OutputDataConfig={
                "S3OutputPath": f"s3://{MODELS_BUCKET}/retrained/{org_id}/",
            },
            ResourceConfig={
                "InstanceType": "ml.m5.large",
                "InstanceCount": 1,
                "VolumeSizeInGB": 10,
            },
            StoppingCondition={"MaxRuntimeInSeconds": 3600},
            HyperParameters={
                "org_id": org_id,
                "mode": "fine_tune",
                "base_model": f"s3://{MODELS_BUCKET}/content_classifier/latest/",
            },
        )
        logger.info(f"SageMaker retraining job launched: {job_name}")
        return True
    except Exception as e:
        # SageMaker might not have a training image yet — log and continue
        logger.warning(f"SageMaker retraining launch failed (non-fatal): {e}")
        logger.info(f"Training config saved to S3 for manual trigger: {job_name}")
        return False


async def _update_accuracy_metrics(org_id: str, label: FeedbackLabel, db: AsyncSession):
    """
    Update running accuracy metrics for the org.
    Stored in the org_metrics table (or org settings JSON for now).
    """
    try:
        from sqlalchemy import text
        # Increment the appropriate counter
        counter_col = {
            "confirmed_malicious": "feedback_tp",
            "false_positive": "feedback_fp",
            "confirmed_benign": "feedback_tn",
        }.get(label)

        if counter_col:
            await db.execute(
                text(f"""
                    INSERT INTO org_metrics (org_id, {counter_col}, updated_at)
                    VALUES (:org_id, 1, now())
                    ON CONFLICT (org_id) DO UPDATE
                    SET {counter_col} = COALESCE(org_metrics.{counter_col}, 0) + 1,
                        updated_at = now()
                """),
                {"org_id": org_id},
            )
            await db.flush()
    except Exception as e:
        logger.warning(f"Could not update accuracy metrics: {e}")
