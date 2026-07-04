"""
Himaya Helios - Graph Analyzer SageMaker Deployment
Deploys trained model to AWS SageMaker inference endpoint (us-west-2).
"""

from __future__ import annotations

import json
import logging
import os
import pickle
import tarfile
import tempfile
from pathlib import Path

import boto3
import sagemaker
from sagemaker.model import Model
from sagemaker.predictor import Predictor
from sagemaker.serializers import JSONSerializer
from sagemaker.deserializers import JSONDeserializer

from models.shared.config import (
    AWS_REGION,
    S3_MODELS_BUCKET,
    SAGEMAKER_GRAPH_ENDPOINT,
    SAGEMAKER_INSTANCE_TYPE,
)

logger = logging.getLogger(__name__)

# --- Dockerfile content for custom container ---
DOCKERFILE = """
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \\
    build-essential \\
    curl \\
    git \\
    && rm -rf /var/lib/apt/lists/*

# Install PyTorch CPU (lighter for inference)
RUN pip install --no-cache-dir \\
    torch==2.2.0+cpu \\
    torchvision==0.17.0+cpu \\
    --index-url https://download.pytorch.org/whl/cpu

# Install PyG for CPU
RUN pip install --no-cache-dir \\
    torch_geometric \\
    pyg_lib \\
    torch_scatter \\
    torch_sparse \\
    torch_cluster \\
    torch_spline_conv \\
    -f https://data.pyg.org/whl/torch-2.2.0+cpu.html

RUN pip install --no-cache-dir \\
    numpy scipy \\
    pydantic>=2.0 \\
    sagemaker-inference \\
    boto3

# SageMaker serving
ENV PYTHONUNBUFFERED=1
ENV SAGEMAKER_PROGRAM=serve.py

WORKDIR /opt/ml/code

COPY serve.py .
COPY models/ ./models/

CMD ["python", "serve.py"]
"""

# --- SageMaker inference script ---
SERVE_SCRIPT = '''
"""SageMaker inference handler for Himaya Helios Graph Analyzer."""

import json
import logging
import os
import pickle
import sys
import time

import flask
import torch
from flask import Flask, Request, Response

sys.path.insert(0, "/opt/ml/code")

from models.graph_analyzer.inference import GraphInferenceEngine
from models.shared.config import GRAPH_MODEL_PATH

logger = logging.getLogger(__name__)
app = Flask(__name__)

# Global inference engine
engine: GraphInferenceEngine | None = None


def model_fn(model_dir: str):
    """Load model. Called once by SageMaker."""
    global engine
    model_path = os.path.join(model_dir, "graph_analyzer.pkl")
    engine = GraphInferenceEngine(model_path=model_path)
    engine.load()
    logger.info("Graph inference engine loaded successfully")
    return engine


def predict_fn(input_data: dict, model: GraphInferenceEngine) -> dict:
    """
    Run inference.
    
    Expected input:
    {
        "sender": "user@company.com",
        "recipient": "cfo@company.com",
        "direction": "inbound"
    }
    """
    sender = input_data["sender"]
    recipient = input_data["recipient"]
    direction = input_data.get("direction", "inbound")

    result = model.score_edge(sender, recipient, direction)

    return {
        "anomaly_score": result.anomaly_score,
        "is_anomalous": result.is_anomalous,
        "mahalanobis_distance": result.mahalanobis_distance,
        "latency_ms": result.latency_ms,
        "model_version": result.model_version,
    }


def input_fn(request_body: str, content_type: str = "application/json") -> dict:
    return json.loads(request_body)


def output_fn(prediction: dict, accept: str = "application/json") -> str:
    return json.dumps(prediction)


# Health check endpoint
@app.route("/ping", methods=["GET"])
def ping() -> Response:
    health = "Healthy" if engine is not None else "Unhealthy"
    status = 200 if engine is not None else 503
    return Response(response=json.dumps({"status": health}), status=status, mimetype="application/json")


@app.route("/invocations", methods=["POST"])
def invocations() -> Response:
    try:
        data = json.loads(flask.request.data.decode("utf-8"))
        result = predict_fn(data, engine)
        return Response(response=json.dumps(result), status=200, mimetype="application/json")
    except Exception as e:
        logger.exception("Prediction error")
        return Response(response=json.dumps({"error": str(e)}), status=500, mimetype="application/json")


if __name__ == "__main__":
    # Load model at startup
    model_fn(os.environ.get("SM_MODEL_DIR", "/opt/ml/model"))
    app.run(host="0.0.0.0", port=8080)
'''


class GraphAnalyzerDeployer:
    """
    Deploys the Himaya Helios Graph Analyzer to AWS SageMaker (us-west-2).
    """

    def __init__(
        self,
        region: str = AWS_REGION,
        s3_bucket: str = S3_MODELS_BUCKET,
        endpoint_name: str = SAGEMAKER_GRAPH_ENDPOINT,
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
        Package trained model into a tar.gz for S3 upload.

        Args:
            model_path: Local path to .pkl model file
            output_dir: Directory for output tar.gz (defaults to temp dir)

        Returns:
            Local path to model.tar.gz
        """
        output_dir = output_dir or tempfile.mkdtemp()
        tar_path = os.path.join(output_dir, "model.tar.gz")

        with tarfile.open(tar_path, "w:gz") as tar:
            tar.add(model_path, arcname="graph_analyzer.pkl")

            # Add inference code
            serve_path = os.path.join(output_dir, "serve.py")
            with open(serve_path, "w") as f:
                f.write(SERVE_SCRIPT)
            tar.add(serve_path, arcname="code/serve.py")

        logger.info(f"Model packaged to {tar_path}")
        return tar_path

    def upload_to_s3(self, local_path: str, s3_key: str | None = None) -> str:
        """
        Upload model artifact to S3.

        Returns:
            S3 URI
        """
        s3_key = s3_key or f"models/graph_analyzer/model.tar.gz"
        s3_uri = f"s3://{self.s3_bucket}/{s3_key}"

        s3 = self.session.client("s3")
        s3.upload_file(local_path, self.s3_bucket, s3_key)
        logger.info(f"Model uploaded to {s3_uri}")
        return s3_uri

    def build_and_push_docker(self, image_name: str = "sentinel-graph-analyzer") -> str:
        """
        Build and push Docker image to ECR.

        Returns:
            ECR image URI
        """
        account_id = self.session.client("sts").get_caller_identity()["Account"]
        ecr_uri = f"{account_id}.dkr.ecr.{self.region}.amazonaws.com/{image_name}:latest"

        # Write Dockerfile
        with tempfile.TemporaryDirectory() as tmpdir:
            dockerfile_path = os.path.join(tmpdir, "Dockerfile")
            with open(dockerfile_path, "w") as f:
                f.write(DOCKERFILE)

            logger.info(f"Build and push with: docker build -t {ecr_uri} {tmpdir} && docker push {ecr_uri}")
            logger.info("Ensure ECR repo exists and you're authenticated: aws ecr get-login-password | docker login")

        return ecr_uri

    def deploy(
        self,
        model_path: str,
        ecr_image_uri: str | None = None,
        initial_instance_count: int = 1,
    ) -> Predictor:
        """
        Full deployment pipeline: package → upload → deploy endpoint.

        Args:
            model_path: Local path to trained .pkl model
            ecr_image_uri: ECR image URI (build manually with build_and_push_docker)
            initial_instance_count: Number of instances

        Returns:
            SageMaker Predictor for making inference calls
        """
        logger.info(f"Deploying Graph Analyzer to SageMaker ({self.region})...")

        # Package and upload model
        tar_path = self.package_model(model_path)
        s3_uri = self.upload_to_s3(tar_path)

        # Use prebuilt PyTorch image if no custom ECR image provided
        if ecr_image_uri is None:
            # AWS Deep Learning Container for PyTorch
            ecr_image_uri = sagemaker.image_uris.retrieve(
                framework="pytorch",
                region=self.region,
                version="2.1",
                py_version="py310",
                instance_type=self.instance_type,
                image_scope="inference",
            )
            logger.info(f"Using DLC image: {ecr_image_uri}")

        # Create SageMaker model
        sm_model = Model(
            image_uri=ecr_image_uri,
            model_data=s3_uri,
            role=self.role_arn,
            sagemaker_session=self.sm_session,
            predictor_cls=Predictor,
            env={
                "SAGEMAKER_PROGRAM": "serve.py",
                "AWS_DEFAULT_REGION": self.region,
            },
        )

        # Deploy endpoint
        predictor = sm_model.deploy(
            initial_instance_count=initial_instance_count,
            instance_type=self.instance_type,
            endpoint_name=self.endpoint_name,
            serializer=JSONSerializer(),
            deserializer=JSONDeserializer(),
        )

        logger.info(f"Endpoint '{self.endpoint_name}' deployed successfully!")
        logger.info(f"Region: {self.region}, Instance: {self.instance_type}")
        return predictor

    def delete_endpoint(self) -> None:
        """Delete the SageMaker endpoint to stop billing."""
        sm = self.session.client("sagemaker")
        sm.delete_endpoint(EndpointName=self.endpoint_name)
        logger.info(f"Endpoint '{self.endpoint_name}' deleted")

    def test_endpoint(self, predictor: Predictor) -> dict:
        """
        Test the deployed endpoint with a sample payload.

        Returns:
            Prediction result dict
        """
        test_payload = {
            "sender": "ceo@company.com",
            "recipient": "finance@company.com",
            "direction": "outbound",
        }
        result = predictor.predict(test_payload)
        logger.info(f"Test prediction: {result}")
        return result


if __name__ == "__main__":
    import argparse

    logging.basicConfig(level=logging.INFO)

    parser = argparse.ArgumentParser(description="Deploy Graph Analyzer to SageMaker")
    parser.add_argument("--model-path", required=True, help="Path to trained .pkl model")
    parser.add_argument("--ecr-image", help="ECR image URI (optional)")
    parser.add_argument("--role-arn", help="SageMaker execution role ARN")
    args = parser.parse_args()

    deployer = GraphAnalyzerDeployer(role_arn=args.role_arn)
    predictor = deployer.deploy(
        model_path=args.model_path,
        ecr_image_uri=args.ecr_image,
    )
    deployer.test_endpoint(predictor)
