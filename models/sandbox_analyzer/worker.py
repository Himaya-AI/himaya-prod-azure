"""
SQS worker that consumes sandbox jobs and runs analysis.
Runs as a separate ECS task or standalone process.
"""
import asyncio
import boto3
import json
import logging
import os
from models.sandbox_analyzer.orchestrator import SandboxOrchestrator, SandboxJob

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

SQS = boto3.client("sqs", region_name="us-west-2")
JOBS_QUEUE_URL = SQS.get_queue_url(QueueName="himaya-sandbox-jobs")["QueueUrl"]
RESULTS_QUEUE_URL = SQS.get_queue_url(QueueName="himaya-sandbox-results")["QueueUrl"]

orchestrator = SandboxOrchestrator()


async def process_job(message: dict):
    """Process a single sandbox job from SQS"""
    try:
        body = json.loads(message["Body"])
        job = SandboxJob(**body)

        logger.info(f"Processing sandbox job {job.job_id} for org {job.org_id}")
        report = await orchestrator.analyze(job)

        # Send results back via SQS
        SQS.send_message(
            QueueUrl=RESULTS_QUEUE_URL,
            MessageBody=json.dumps({
                "job_id": job.job_id,
                "threat_id": job.threat_id,
                "org_id": job.org_id,
                "verdict": report.verdict,
                "risk_score": report.risk_score,
                "confidence": report.confidence,
                "behavior_summary_en": report.behavior_summary_en,
                "behavior_summary_ar": report.behavior_summary_ar,
                "iocs": report.iocs,
                "mitre_techniques": report.mitre_techniques,
                "network_activity": report.network_activity,
                "persistence_attempted": report.persistence_attempted,
                "data_exfiltration_attempted": report.data_exfiltration_attempted,
                "analyzed_at": report.analyzed_at
            })
        )
        logger.info(f"Job {job.job_id} complete: {report.verdict} (score: {report.risk_score})")

    except Exception as e:
        logger.error(f"Job processing failed: {e}")


async def run_worker():
    """Main SQS polling loop"""
    logger.info("Himaya Helios Sandbox Worker started")
    while True:
        try:
            response = SQS.receive_message(
                QueueUrl=JOBS_QUEUE_URL,
                MaxNumberOfMessages=1,
                WaitTimeSeconds=20,     # Long polling
                VisibilityTimeout=900   # 15 min
            )
            messages = response.get("Messages", [])
            for message in messages:
                await process_job(message)
                SQS.delete_message(
                    QueueUrl=JOBS_QUEUE_URL,
                    ReceiptHandle=message["ReceiptHandle"]
                )
        except Exception as e:
            logger.error(f"Worker error: {e}")
            await asyncio.sleep(10)


if __name__ == "__main__":
    asyncio.run(run_worker())
