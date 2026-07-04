import os
from pathlib import Path
from pydantic_settings import BaseSettings
from dotenv import load_dotenv

# Load .env from himaya-helios/ root (parent of backend/)
_root = Path(__file__).parent.parent
load_dotenv(_root / ".env")


class Settings(BaseSettings):
    DATABASE_URL: str = "postgresql+asyncpg://sentinel:sentinel_dev_password@localhost:5432/sentinel_mail"
    REDIS_URL: str = "redis://localhost:6379"
    NEO4J_URL: str = "bolt://10.0.3.166:7687"
    NEO4J_USER: str = "neo4j"
    NEO4J_PASSWORD: str = "sentinel_dev_password"
    ANTHROPIC_API_KEY: str = ""
    OPENAI_API_KEY: str = ""
    HIBP_API_KEY: str = ""
    WHOISXML_API_KEY: str = ""
    # Azure primary settings
    AZURE_STORAGE_ACCOUNT: str = ""
    AZURE_SERVICE_BUS_NAMESPACE: str = ""
    AZURE_REGION: str = "uaenorth"
    AZURE_CLIENT_ID: str = ""

    # AWS fallback settings (keep during migration; SES still uses AWS us-east-1)
    AWS_REGION: str = "us-east-1"
    AWS_SQS_EMAIL_QUEUE: str = "himaya-email-events"
    JWT_SECRET: str = "dev-secret-change-in-prod"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 720  # 12 hours
    VENDOR_ADMIN_API_KEY: str = ""  # Required: set via env var
    VENDOR_ADMIN_EMAIL: str = "adnan@himaya.ai"
    VENDOR_ADMIN_PASSWORD: str = ""  # Required: set via env var

    class Config:
        env_file = str(_root / ".env")


settings = Settings()
