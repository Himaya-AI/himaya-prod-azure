"""
Himaya Helios - Sender Reputation SageMaker Deployment
Deploys trained XGBoost model to AWS SageMaker (uaenorth).
"""

from __future__ import annotations

import json
import logging
import os
import tarfile
import tempfile

import boto3
import sagemaker
from sagemaker.model import Model
from sagemaker.predictor import Predictor
from sagemaker.serializers import JSONSerializer
from sagemaker.deserializers import JSONDeserializer
from sagemaker.xgboost import XGBoostModel

from models.shared.config import (
    AWS_REGION,
    S3_MODELS_BUCKET,
    SAGEMAKER_REPUTATION_ENDPOINT,
    SAGEMAKER_INSTANCE_TYPE,
    REPUTATION_MODEL_PATH,
)

logger = logging.getLogger(__name__)


# Inference script for SageMaker container
INFERENCE_SCRIPT = '''
"""SageMaker inference handler for Himaya Helios Sender Reputation."""

import json
import logging
import os
import pickle

import numpy as np

logger = logging.getLogger(__name__)


def model_fn(model_dir: str):
    """Load model from the model directory."""
    model_path = os.path.join(model_dir, "reputation_classifier.pkl")
    
    with open(model_path, "rb") as f:
        data = pickle.load(f)
    
    model = data["model"]
    logger.info("Sender reputation model loaded successfully")
    return model


def input_fn(request_body: str, content_type: str = "application/json") -> dict:
    """Parse input data."""
    if content_type == "application/json":
        return json.loads(request_body)
    raise ValueError(f"Unsupported content type: {content_type}")


def predict_fn(input_data: dict, model) -> dict:
    """
    Run prediction.
    
    Expected input (pre-computed features):
    {
        "features": [0.5, 1, 1, 1, 0, 0, 1.0, 0, 0.1, 1, 0.3]  # 11 features
    }
    
    Or raw signals for server-side feature computation:
    {
        "domain": "example.com",
        "signals": {
            "domain_age_days": 1000,
            "has_dmarc": true,
            ...
        }
    }
    """
    if "features" in input_data:
        # Pre-computed features
        features = np.array(input_data["features"], dtype=np.float32).reshape(1, -1)
    else:
        # Need to compute features from signals (requires full package)
        raise ValueError("Server-side feature computation not implemented. Send pre-computed features.")
    
    # Get prediction
    proba = model.predict_proba(features)[0, 1]
    prediction = int(proba > 0.5)
    
    return {
        "malicious_probability": float(proba),
        "final_score": round(float(proba) * 100, 2),
        "prediction": prediction,
        "prediction_label": "MALICIOUS" if prediction else "BENIGN",
    }


def output_fn(prediction: dict, accept: str = "application/json") -> str:
    """Serialize prediction output."""
    return json.dumps(prediction)
'''


class ReputationModelDeployer:
    """
    Deploys the Himaya Helios Sender Reputation model to AWS SageMaker.
    Region: uaenorth
    """

    def __init__(
        self,
        region: str = AWS_REGION,
        s3_bucket: str = S3_MODELS_BUCKET,
        endpoint_name: str = SAGEMAKER_REPUTATION_ENDPOINT,
        instance_type: str = SAGEMAKER_INSTANCE_TYPE,
        role_arn: str | None = None,
    ) -> None:
        self.region = region
        self.s3_bucket = s3_bucket
        self.endpoint_name = endpoint_name
        self.instance_type = instance_type

        self.session = boto3.Session(region_name=region)
        self.sm_session = sagemaker.Session(boto_session=self.session)
        self.role_arn = role_arn or sagemaker.get_execution_role(self.sm_session)

    def package_model(self, model_path: str, output_dir: str | None = None) -> str:
        """
        Package model and inference code into model.tar.gz.

        Args:
            model_path: Local path to .pkl model file
            output_dir: Output directory (defaults to temp)

        Returns:
            Path to model.tar.gz
        """
        output_dir = output_dir or tempfile.mkdtemp()
        tar_path = os.path.join(output_dir, "model.tar.gz")

        with tarfile.open(tar_path, "w:gz") as tar:
            # Add model file
            tar.add(model_path, arcname="reputation_classifier.pkl")

            # Add inference script
            script_path = os.path.join(output_dir, "inference.py")
            with open(script_path, "w") as f:
                f.write(INFERENCE_SCRIPT)
            tar.add(script_path, arcname="code/inference.py")

        logger.info(f"Model packaged to {tar_path}")
        return tar_path

    def upload_to_s3(self, local_path: str, s3_key: str | None = None) -> str:
        """Upload model artifact to S3."""
        s3_key = s3_key or "models/sender_reputation/model.tar.gz"
        s3_uri = f"s3://{self.s3_bucket}/{s3_key}"

        s3 = self.session.client("s3")
        s3.upload_file(local_path, self.s3_bucket, s3_key)
        logger.info(f"Model uploaded to {s3_uri}")
        return s3_uri

    def deploy(
        self,
        model_path: str = REPUTATION_MODEL_PATH,
        initial_instance_count: int = 1,
    ) -> Predictor:
        """
        Full deployment: package → upload → create endpoint.

        Args:
            model_path: Local path to trained .pkl model
            initial_instance_count: Number of inference instances

        Returns:
            SageMaker Predictor
        """
        logger.info(f"Deploying Sender Reputation model to SageMaker ({self.region})...")

        # Package and upload
        tar_path = self.package_model(model_path)
        s3_uri = self.upload_to_s3(tar_path)

        # Get XGBoost container image
        image_uri = sagemaker.image_uris.retrieve(
            framework="xgboost",
            region=self.region,
            version="1.7-1",
            py_version="py3",
            instance_type=self.instance_type,
        )
        logger.info(f"Using XGBoost container: {image_uri}")

        # Create model
        xgb_model = XGBoostModel(
            model_data=s3_uri,
            role=self.role_arn,
            framework_version="1.7-1",
            py_version="py3",
            entry_point="inference.py",
            source_dir=os.path.dirname(tar_path),
            sagemaker_session=self.sm_session,
        )

        # Deploy
        predictor = xgb_model.deploy(
            initial_instance_count=initial_instance_count,
            instance_type=self.instance_type,
            endpoint_name=self.endpoint_name,
            serializer=JSONSerializer(),
            deserializer=JSONDeserializer(),
        )

        logger.info(f"Endpoint '{self.endpoint_name}' deployed successfully!")
        return predictor

    def delete_endpoint(self) -> None:
        """Delete endpoint to stop billing."""
        sm = self.session.client("sagemaker")
        sm.delete_endpoint(EndpointName=self.endpoint_name)
        logger.info(f"Endpoint '{self.endpoint_name}' deleted")

    def test_endpoint(self, predictor: Predictor) -> dict:
        """Test endpoint with sample payload."""
        # Sample feature vector: old domain, all auth present, no risk signals
        test_payload = {
            "features": [
                0.8,   # domain_age_days (normalized)
                1,     # has_dmarc
                1,     # has_spf
                1,     # has_dkim
                0,     # is_breached
                0,     # is_lookalike
                1.0,   # lookalike_distance (max = not lookalike)
                0,     # is_new_to_org
                0.1,   # tld_risk_score (.com)
                1,     # mx_valid
                0.3,   # domain_entropy (normalized)
            ]
        }

        result = predictor.predict(test_payload)
        logger.info(f"Test prediction: {result}")
        return result


if __name__ == "__main__":
    import argparse

    logging.basicConfig(level=logging.INFO)

    parser = argparse.ArgumentParser(description="Deploy Sender Reputation model to SageMaker")
    parser.add_argument("--model-path", default=REPUTATION_MODEL_PATH, help="Path to trained model")
    parser.add_argument("--role-arn", help="SageMaker execution role ARN")
    parser.add_argument("--delete", action="store_true", help="Delete existing endpoint")
    args = parser.parse_args()

    deployer = ReputationModelDeployer(role_arn=args.role_arn)

    if args.delete:
        deployer.delete_endpoint()
    else:
        predictor = deployer.deploy(model_path=args.model_path)
        deployer.test_endpoint(predictor)
