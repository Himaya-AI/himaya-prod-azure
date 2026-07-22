import os

import boto3
from botocore.config import Config
from dotenv import load_dotenv

load_dotenv()

KIMI_MODEL_ID = os.getenv("KIMI_MODEL_ID", "moonshotai.kimi-k2.5")
CLASSIFICATION_MODEL = KIMI_MODEL_ID
LLM_TIMEOUT_SECONDS = float(os.getenv("LLM_TIMEOUT_SECONDS", "30"))
LLM_TEMPERATURE = float(os.getenv("LLM_TEMPERATURE", "0.1"))
LLM_MAX_TOKENS = int(os.getenv("LLM_MAX_TOKENS", "2000"))

bedrock_runtime = boto3.client(
    service_name="bedrock-runtime",
    region_name=os.getenv("AWS_REGION", "us-east-1"),  # fallback to us-east-1
    config=Config(retries={"max_attempts": 10, "mode": "standard"}),
)

PROMPT_BUCKET = os.getenv("PROMPT_BUCKET", "classify-prompts-439055361147")

s3_client = boto3.client(
    service_name="s3",
    region_name="us-east-1",
    config=Config(retries={"max_attempts": 3, "mode": "standard"}),
)