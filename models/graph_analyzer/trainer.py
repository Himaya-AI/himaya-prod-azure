"""
Himaya Helios - Graph Analyzer Trainer
Unsupervised training of GraphSAGE via reconstruction loss.
Target: precision >0.85, recall >0.80 on BEC patterns.
"""

from __future__ import annotations

import logging
import os
import pickle
import time
from datetime import datetime, timezone
from typing import Any

import numpy as np
import torch
import torch.optim as optim

from models.graph_analyzer.model import GraphSAGEAnomalyDetector
from models.shared.config import (
    GRAPH_EMBEDDING_DIM,
    GRAPH_HIDDEN_DIM,
    GRAPH_NUM_LAYERS,
    GRAPH_MODEL_PATH,
    MODEL_SAVE_DIR,
)

try:
    from torch_geometric.data import Data, DataLoader
    HAS_PYG = True
except ImportError:
    HAS_PYG = False
    from torch.utils.data import DataLoader  # type: ignore

logger = logging.getLogger(__name__)


class GraphSAGETrainer:
    """
    Trains the GraphSAGE anomaly detector using unsupervised reconstruction loss.

    Training approach:
    1. Build graph from historical email data
    2. Encode nodes to embeddings
    3. Decode embeddings back to node features
    4. Minimize reconstruction loss (MSE)
    5. After training, fit Mahalanobis baseline distribution

    The model learns what "normal" communication looks like.
    At inference, new edges far from the baseline are flagged as anomalous.
    """

    def __init__(
        self,
        embedding_dim: int = GRAPH_EMBEDDING_DIM,
        hidden_dim: int = GRAPH_HIDDEN_DIM,
        num_layers: int = GRAPH_NUM_LAYERS,
        learning_rate: float = 1e-3,
        weight_decay: float = 1e-4,
        num_epochs: int = 100,
        patience: int = 10,
        device: str | None = None,
    ) -> None:
        self.embedding_dim = embedding_dim
        self.hidden_dim = hidden_dim
        self.num_layers = num_layers
        self.lr = learning_rate
        self.weight_decay = weight_decay
        self.num_epochs = num_epochs
        self.patience = patience
        self.device = torch.device(device or ("cuda" if torch.cuda.is_available() else "cpu"))

        self.model: GraphSAGEAnomalyDetector | None = None
        self.training_history: list[dict[str, float]] = []

    def _init_model(self, node_feature_dim: int = 4) -> GraphSAGEAnomalyDetector:
        model = GraphSAGEAnomalyDetector(
            node_feature_dim=node_feature_dim,
            hidden_dim=self.hidden_dim,
            embedding_dim=self.embedding_dim,
            num_layers=self.num_layers,
            dropout=0.2,
        )
        return model.to(self.device)

    def train(self, pyg_data: Any) -> GraphSAGEAnomalyDetector:
        """
        Train the GraphSAGE encoder on the provided graph data.

        Args:
            pyg_data: PyG Data object with x, edge_index, edge_attr

        Returns:
            Trained model
        """
        node_feature_dim = pyg_data.x.shape[1]
        self.model = self._init_model(node_feature_dim)

        x = pyg_data.x.to(self.device)
        edge_index = pyg_data.edge_index.to(self.device)
        edge_attr = pyg_data.edge_attr.to(self.device) if hasattr(pyg_data, "edge_attr") and pyg_data.edge_attr is not None else None

        optimizer = optim.Adam(
            self.model.parameters(),
            lr=self.lr,
            weight_decay=self.weight_decay,
        )
        scheduler = optim.lr_scheduler.ReduceLROnPlateau(
            optimizer, mode="min", factor=0.5, patience=5
        )

        best_loss = float("inf")
        best_state = None
        no_improve = 0

        logger.info(
            f"Training GraphSAGE: {pyg_data.num_nodes} nodes, "
            f"{edge_index.shape[1]} edges, device={self.device}"
        )

        self.model.train()
        t0 = time.time()

        for epoch in range(1, self.num_epochs + 1):
            optimizer.zero_grad()
            z, x_hat, loss = self.model(x, edge_index, edge_attr)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(self.model.parameters(), max_norm=1.0)
            optimizer.step()
            scheduler.step(loss)

            loss_val = loss.item()
            self.training_history.append({"epoch": epoch, "loss": loss_val})

            if loss_val < best_loss:
                best_loss = loss_val
                best_state = {k: v.clone() for k, v in self.model.state_dict().items()}
                no_improve = 0
            else:
                no_improve += 1

            if epoch % 10 == 0:
                elapsed = time.time() - t0
                logger.info(f"Epoch {epoch:4d}/{self.num_epochs} | Loss: {loss_val:.6f} | Elapsed: {elapsed:.1f}s")

            if no_improve >= self.patience:
                logger.info(f"Early stopping at epoch {epoch} (no improvement for {self.patience} epochs)")
                break

        # Restore best weights
        if best_state is not None:
            self.model.load_state_dict(best_state)

        # Fit baseline distribution
        logger.info("Fitting baseline embedding distribution for anomaly scoring...")
        self.model.eval()
        with torch.no_grad():
            z_baseline = self.model.encode(x, edge_index, edge_attr)
            self.model.fit_baseline(z_baseline)

        logger.info(f"Training complete. Best loss: {best_loss:.6f}")
        return self.model

    def evaluate_bec_detection(
        self,
        pyg_data: Any,
        bec_edges: list[tuple[int, int]],
        normal_edges: list[tuple[int, int]],
        threshold: float = 70.0,
    ) -> dict[str, float]:
        """
        Evaluate precision/recall on BEC edge detection.

        Args:
            pyg_data: Graph data
            bec_edges: List of (src_idx, dst_idx) known BEC edges
            normal_edges: List of (src_idx, dst_idx) known normal edges
            threshold: Score threshold for flagging as anomalous

        Returns:
            Dict with precision, recall, f1
        """
        if self.model is None:
            raise RuntimeError("Model not trained. Call train() first.")

        self.model.eval()
        x = pyg_data.x.to(self.device)
        edge_index = pyg_data.edge_index.to(self.device)
        edge_attr = pyg_data.edge_attr.to(self.device) if hasattr(pyg_data, "edge_attr") and pyg_data.edge_attr is not None else None

        with torch.no_grad():
            z = self.model.encode(x, edge_index, edge_attr)

        tp = fp = fn = tn = 0

        for src, dst in bec_edges:
            score = self.model.edge_anomaly_score(z, src, dst)
            if score >= threshold:
                tp += 1
            else:
                fn += 1

        for src, dst in normal_edges:
            score = self.model.edge_anomaly_score(z, src, dst)
            if score >= threshold:
                fp += 1
            else:
                tn += 1

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

        return {"precision": precision, "recall": recall, "f1": f1, "tp": tp, "fp": fp, "fn": fn, "tn": tn}

    def save(self, path: str = GRAPH_MODEL_PATH) -> None:
        """Save trained model and metadata to disk as .pkl."""
        if self.model is None:
            raise RuntimeError("No model to save. Train first.")

        os.makedirs(os.path.dirname(path), exist_ok=True)

        payload = {
            "model_state_dict": self.model.state_dict(),
            "model_config": {
                "embedding_dim": self.embedding_dim,
                "hidden_dim": self.hidden_dim,
                "num_layers": self.num_layers,
            },
            "baseline_mean": self.model.baseline_mean.cpu().numpy(),
            "baseline_cov_inv": self.model.baseline_cov_inv.cpu().numpy(),
            "baseline_fitted": self.model._baseline_fitted,
            "training_history": self.training_history,
            "saved_at": datetime.now(timezone.utc).isoformat(),
            "model_version": "1.0.0",
        }

        with open(path, "wb") as f:
            pickle.dump(payload, f)

        logger.info(f"Model saved to {path}")

    @classmethod
    def load(cls, path: str = GRAPH_MODEL_PATH) -> tuple["GraphSAGETrainer", GraphSAGEAnomalyDetector]:
        """Load a previously saved trainer+model from disk."""
        with open(path, "rb") as f:
            payload = pickle.load(f)

        config = payload["model_config"]
        trainer = cls(
            embedding_dim=config["embedding_dim"],
            hidden_dim=config["hidden_dim"],
            num_layers=config["num_layers"],
        )
        trainer.training_history = payload.get("training_history", [])

        model = GraphSAGEAnomalyDetector(
            embedding_dim=config["embedding_dim"],
            hidden_dim=config["hidden_dim"],
            num_layers=config["num_layers"],
        )
        model.load_state_dict(payload["model_state_dict"])

        # Restore baseline distribution
        model.baseline_mean = torch.tensor(payload["baseline_mean"])
        model.baseline_cov_inv = torch.tensor(payload["baseline_cov_inv"])
        model._baseline_fitted = payload.get("baseline_fitted", False)

        model.eval()
        trainer.model = model
        logger.info(f"Model loaded from {path} (saved at {payload.get('saved_at')})")
        return trainer, model
