"""
Himaya Helios - Graph Analyzer Inference
Load trained model and score new email edges in <100ms.
"""

from __future__ import annotations

import logging
import time
from typing import Any

import torch

from models.graph_analyzer.model import GraphSAGEAnomalyDetector
from models.graph_analyzer.data_pipeline import EmailGraphPipeline
from models.graph_analyzer.trainer import GraphSAGETrainer
from models.shared.config import GRAPH_MODEL_PATH, GRAPH_ANOMALY_THRESHOLD
from models.shared.schemas import GraphAnalysisResult

logger = logging.getLogger(__name__)


class GraphInferenceEngine:
    """
    Production inference engine for the Communication Graph Analyzer.

    Maintains a loaded model and cached graph state for fast inference.
    Target latency: <100ms per edge scoring request.
    """

    def __init__(self, model_path: str = GRAPH_MODEL_PATH) -> None:
        self.model_path = model_path
        self.model: GraphSAGEAnomalyDetector | None = None
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self._loaded = False

        # Cached graph data for inference
        self._graph_data: Any = None
        self._pipeline: EmailGraphPipeline | None = None

    def load(self) -> None:
        """Load model from disk. Called once at startup."""
        t0 = time.time()
        _, self.model = GraphSAGETrainer.load(self.model_path)
        self.model = self.model.to(self.device)
        self.model.eval()
        self._loaded = True
        logger.info(f"Graph inference engine loaded in {(time.time()-t0)*1000:.1f}ms")

    def load_graph(self, email_records: list[dict[str, Any]], org_domain: str = "") -> None:
        """
        Build and cache the graph from historical email records.
        Call this when the model is first loaded with historical data.

        Args:
            email_records: Historical email metadata list
            org_domain: Organization domain for external detection
        """
        self._pipeline = EmailGraphPipeline(org_domain=org_domain)
        self._graph_data = self._pipeline.build(email_records)
        logger.info(
            f"Graph loaded: {self._graph_data.num_nodes} nodes, "
            f"{self._graph_data.edge_index.shape[1]} edges"
        )

    def score_edge(
        self,
        sender: str,
        recipient: str,
        direction: str = "inbound",
    ) -> GraphAnalysisResult:
        """
        Score a new email edge (sender → recipient) for anomaly.

        Args:
            sender: Sender email address
            recipient: Recipient email address
            direction: Email direction

        Returns:
            GraphAnalysisResult with anomaly_score 0-100
        """
        if not self._loaded or self.model is None:
            raise RuntimeError("Model not loaded. Call load() first.")
        if self._graph_data is None:
            raise RuntimeError("Graph not loaded. Call load_graph() first.")

        t0 = time.time()

        # Extend graph with new edge if nodes are unknown
        src_idx, dst_idx, edge_attr = self._pipeline.build_new_edge_features(
            self._graph_data, sender, recipient, direction
        )

        x = self._graph_data.x.to(self.device)
        edge_index = self._graph_data.edge_index.to(self.device)
        existing_edge_attr = (
            self._graph_data.edge_attr.to(self.device)
            if hasattr(self._graph_data, "edge_attr") and self._graph_data.edge_attr is not None
            else None
        )

        with torch.no_grad():
            # Get embeddings for all nodes
            z = self.model.encode(x, edge_index, existing_edge_attr)

            # If new nodes were added, we need to handle them
            # For new nodes, use zero embeddings (worst-case anomaly)
            if src_idx >= len(z) or dst_idx >= len(z):
                # Pad embeddings with zeros for new nodes
                num_new = max(src_idx, dst_idx) + 1 - len(z)
                padding = torch.zeros(num_new, z.shape[1], device=self.device)
                z = torch.cat([z, padding], dim=0)

            # Compute anomaly score
            anomaly_score = self.model.edge_anomaly_score(z, src_idx, dst_idx)

            # Get Mahalanobis distance for both nodes
            z_src = z[src_idx].unsqueeze(0)
            z_dst = z[dst_idx].unsqueeze(0)
            maha_src = self.model.mahalanobis_distance(z_src).item()
            maha_dst = self.model.mahalanobis_distance(z_dst).item()
            maha_combined = (maha_src + maha_dst) / 2.0

            # Get edge embedding (concatenation of node embeddings)
            edge_embedding = torch.cat([z_src, z_dst], dim=-1).cpu().numpy().tolist()[0]

        latency_ms = (time.time() - t0) * 1000.0

        result = GraphAnalysisResult(
            anomaly_score=round(anomaly_score, 2),
            edge_embedding=edge_embedding,
            is_anomalous=anomaly_score >= GRAPH_ANOMALY_THRESHOLD,
            mahalanobis_distance=round(maha_combined, 4),
            latency_ms=round(latency_ms, 2),
            sender_node_score=round(self.model.edge_anomaly_score(z, src_idx, src_idx), 2),
            recipient_node_score=round(self.model.edge_anomaly_score(z, dst_idx, dst_idx), 2),
        )

        if latency_ms > 100:
            logger.warning(f"Graph inference latency {latency_ms:.1f}ms exceeded 100ms target")

        return result

    def score_edge_from_graph_data(
        self,
        graph_x: torch.Tensor,
        graph_edge_index: torch.Tensor,
        src_idx: int,
        dst_idx: int,
        graph_edge_attr: torch.Tensor | None = None,
    ) -> float:
        """
        Low-level scoring method for use in SageMaker endpoint.

        Returns:
            Anomaly score 0-100
        """
        if not self._loaded or self.model is None:
            raise RuntimeError("Model not loaded.")

        x = graph_x.to(self.device)
        edge_index = graph_edge_index.to(self.device)
        edge_attr = graph_edge_attr.to(self.device) if graph_edge_attr is not None else None

        with torch.no_grad():
            z = self.model.encode(x, edge_index, edge_attr)
            score = self.model.edge_anomaly_score(z, src_idx, dst_idx)

        return score
