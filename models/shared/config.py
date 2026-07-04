"""
Himaya Helios - Shared Configuration
AWS Region: us-west-2
"""

# AWS Configuration
AWS_REGION = "us-west-2"
SAGEMAKER_GRAPH_ENDPOINT = "sentinel-graph-analyzer"
SAGEMAKER_REPUTATION_ENDPOINT = "sentinel-sender-reputation"
S3_MODELS_BUCKET = "sentinel-models-prod"

# Redis
REDIS_URL = "redis://localhost:6379"
REDIS_TTL_SECONDS = 86400  # 24 hours

# Risk Score Thresholds
RISK_SCORE_THRESHOLDS = {
    "deliver": (0, 30),
    "banner": (31, 50),
    "hold": (51, 70),
    "quarantine": (71, 89),
    "block": (90, 100),
}

# Model ensemble weights
ENSEMBLE_WEIGHTS = {
    "graph_score": 0.30,
    "content_score": 0.40,
    "reputation_score": 0.30,
}

# LLM Configuration
CLAUDE_MODEL = "claude-opus-4-5-20251101"  # Opus for all primary classification
OPENAI_MODEL = "gpt-4o"
LLM_TIMEOUT_SECONDS = 30
LLM_TEMPERATURE = 0.1
LLM_MAX_TOKENS = 2000

# Graph Analyzer
GRAPH_ANOMALY_THRESHOLD = 70.0  # Score above this = anomalous
GRAPH_EMBEDDING_DIM = 64
GRAPH_HIDDEN_DIM = 128
GRAPH_NUM_LAYERS = 2

# Sender Reputation
HIBP_API_BASE = "https://haveibeenpwned.com/api/v3"
REPUTATION_LOOKALIKE_THRESHOLD = 2  # Levenshtein distance

# SageMaker
SAGEMAKER_INSTANCE_TYPE = "ml.t2.medium"
SAGEMAKER_CONTAINER_IMAGE = "python:3.12-slim"

# Model storage paths
MODEL_SAVE_DIR = "/tmp/sentinel-models"
GRAPH_MODEL_PATH = f"{MODEL_SAVE_DIR}/graph_analyzer.pkl"
REPUTATION_MODEL_PATH = f"{MODEL_SAVE_DIR}/reputation_classifier.pkl"
