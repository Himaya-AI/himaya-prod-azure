"""
Himaya Helios - MODEL-001: Communication Graph Analyzer
GraphSAGE-based unsupervised anomaly detection on email communication graphs.

Architecture:
- GraphSAGE with mean aggregation (2 layers)
- Unsupervised: encoder → embedding → reconstruction loss
- Output: anomaly score 0-100 per new sender→recipient edge
"""

from __future__ import annotations

import torch
import torch.nn as nn
import torch.nn.functional as F

try:
    from torch_geometric.nn import SAGEConv
    from torch_geometric.data import Data
    HAS_PYG = True
except ImportError:
    HAS_PYG = False
    # Fallback stubs for environments without PyG installed
    class SAGEConv(nn.Module):  # type: ignore
        def __init__(self, in_channels: int, out_channels: int):
            super().__init__()
            self.lin = nn.Linear(in_channels, out_channels)
        def forward(self, x: torch.Tensor, edge_index: torch.Tensor) -> torch.Tensor:
            return self.lin(x)

    class Data:  # type: ignore
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)


class GraphSAGEEncoder(nn.Module):
    """
    GraphSAGE encoder for email communication graphs.

    Node features (4-dim):
        - email_volume: normalized count of emails sent/received
        - external_ratio: fraction of emails with external parties
        - role_encoding: 0=employee, 1=manager, 2=exec
        - dept_encoding: integer encoding of department

    Edge features (3-dim):
        - frequency: normalized communication frequency
        - recency_days: days since last communication (normalized)
        - direction: 0=inbound, 1=outbound, 2=both
    """

    NODE_FEATURE_DIM = 4
    EDGE_FEATURE_DIM = 3

    def __init__(
        self,
        in_channels: int = NODE_FEATURE_DIM,
        hidden_channels: int = 128,
        out_channels: int = 64,
        num_layers: int = 2,
        dropout: float = 0.2,
    ) -> None:
        super().__init__()
        self.dropout = dropout
        self.convs = nn.ModuleList()

        # Input layer
        self.convs.append(SAGEConv(in_channels, hidden_channels))

        # Hidden layers
        for _ in range(num_layers - 2):
            self.convs.append(SAGEConv(hidden_channels, hidden_channels))

        # Output layer
        self.convs.append(SAGEConv(hidden_channels, out_channels))

        # Batch normalization layers
        self.bns = nn.ModuleList([
            nn.BatchNorm1d(hidden_channels) for _ in range(num_layers - 1)
        ])

        # Edge MLP (projects edge features to node feature space for conditioning)
        self.edge_mlp = nn.Sequential(
            nn.Linear(self.EDGE_FEATURE_DIM, 16),
            nn.ReLU(),
            nn.Linear(16, in_channels),
        )

    def forward(
        self,
        x: torch.Tensor,
        edge_index: torch.Tensor,
        edge_attr: torch.Tensor | None = None,
    ) -> torch.Tensor:
        """
        Forward pass through GraphSAGE encoder.

        Args:
            x: Node feature matrix [num_nodes, in_channels]
            edge_index: Graph connectivity [2, num_edges]
            edge_attr: Edge feature matrix [num_edges, edge_feature_dim]

        Returns:
            Node embeddings [num_nodes, out_channels]
        """
        # Optionally condition on edge features
        if edge_attr is not None:
            edge_context = self.edge_mlp(edge_attr)  # [num_edges, in_channels]
            # Aggregate edge context to source nodes
            src_nodes = edge_index[0]
            edge_agg = torch.zeros_like(x)
            edge_agg.scatter_add_(0, src_nodes.unsqueeze(1).expand_as(edge_context), edge_context)
            x = x + 0.1 * edge_agg

        for i, conv in enumerate(self.convs[:-1]):
            x = conv(x, edge_index)
            x = self.bns[i](x)
            x = F.relu(x)
            x = F.dropout(x, p=self.dropout, training=self.training)

        x = self.convs[-1](x, edge_index)
        return x  # [num_nodes, out_channels]


class GraphSAGEDecoder(nn.Module):
    """
    Decoder for reconstruction-based unsupervised training.
    Reconstructs node features from embeddings.
    """

    def __init__(self, in_channels: int = 64, hidden_channels: int = 128, out_channels: int = 4) -> None:
        super().__init__()
        self.mlp = nn.Sequential(
            nn.Linear(in_channels, hidden_channels),
            nn.ReLU(),
            nn.BatchNorm1d(hidden_channels),
            nn.Linear(hidden_channels, out_channels),
        )

    def forward(self, z: torch.Tensor) -> torch.Tensor:
        return self.mlp(z)


class EdgeAnomalyPredictor(nn.Module):
    """
    Predicts anomaly score for a new edge (sender → recipient).
    Combines node embeddings of both endpoints.
    """

    def __init__(self, embedding_dim: int = 64) -> None:
        super().__init__()
        self.mlp = nn.Sequential(
            nn.Linear(embedding_dim * 2, 128),
            nn.ReLU(),
            nn.Linear(128, 64),
            nn.ReLU(),
            nn.Linear(64, 1),
            nn.Sigmoid(),
        )

    def forward(self, z_src: torch.Tensor, z_dst: torch.Tensor) -> torch.Tensor:
        """
        Compute raw anomaly probability for src→dst edge.

        Args:
            z_src: Source node embedding [batch, embedding_dim]
            z_dst: Destination node embedding [batch, embedding_dim]

        Returns:
            Anomaly probability [batch, 1]
        """
        combined = torch.cat([z_src, z_dst], dim=-1)
        return self.mlp(combined)


class GraphSAGEAnomalyDetector(nn.Module):
    """
    Full GraphSAGE-based unsupervised anomaly detector for email graphs.

    Training: reconstruction loss (autoencoder-style) on node features.
    Inference: Mahalanobis distance from learned embedding distribution.
    """

    def __init__(
        self,
        node_feature_dim: int = 4,
        hidden_dim: int = 128,
        embedding_dim: int = 64,
        num_layers: int = 2,
        dropout: float = 0.2,
    ) -> None:
        super().__init__()
        self.embedding_dim = embedding_dim

        self.encoder = GraphSAGEEncoder(
            in_channels=node_feature_dim,
            hidden_channels=hidden_dim,
            out_channels=embedding_dim,
            num_layers=num_layers,
            dropout=dropout,
        )

        self.decoder = GraphSAGEDecoder(
            in_channels=embedding_dim,
            hidden_channels=hidden_dim,
            out_channels=node_feature_dim,
        )

        self.edge_predictor = EdgeAnomalyPredictor(embedding_dim=embedding_dim)

        # Baseline distribution parameters (set during training)
        self.register_buffer("baseline_mean", torch.zeros(embedding_dim))
        self.register_buffer("baseline_cov_inv", torch.eye(embedding_dim))
        self._baseline_fitted = False

    def encode(
        self,
        x: torch.Tensor,
        edge_index: torch.Tensor,
        edge_attr: torch.Tensor | None = None,
    ) -> torch.Tensor:
        """Encode graph to node embeddings."""
        return self.encoder(x, edge_index, edge_attr)

    def decode(self, z: torch.Tensor) -> torch.Tensor:
        """Reconstruct node features from embeddings."""
        return self.decoder(z)

    def reconstruction_loss(
        self,
        x: torch.Tensor,
        x_hat: torch.Tensor,
    ) -> torch.Tensor:
        """MSE reconstruction loss between original and reconstructed features."""
        return F.mse_loss(x_hat, x)

    def forward(
        self,
        x: torch.Tensor,
        edge_index: torch.Tensor,
        edge_attr: torch.Tensor | None = None,
    ) -> tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        """
        Full forward pass for training.

        Returns:
            (z, x_hat, loss) tuple
        """
        z = self.encode(x, edge_index, edge_attr)
        x_hat = self.decode(z)
        loss = self.reconstruction_loss(x, x_hat)
        return z, x_hat, loss

    def fit_baseline(self, embeddings: torch.Tensor) -> None:
        """
        Fit baseline distribution (mean + inverse covariance) from training embeddings.
        Used for Mahalanobis distance computation at inference time.

        Args:
            embeddings: Node embeddings from training data [N, embedding_dim]
        """
        with torch.no_grad():
            mean = embeddings.mean(dim=0)
            centered = embeddings - mean
            cov = (centered.T @ centered) / (embeddings.shape[0] - 1)

            # Add regularization for numerical stability
            cov += torch.eye(self.embedding_dim, device=cov.device) * 1e-6

            try:
                cov_inv = torch.linalg.inv(cov)
            except torch.linalg.LinAlgError:
                cov_inv = torch.eye(self.embedding_dim, device=cov.device)

            self.baseline_mean.copy_(mean)
            self.baseline_cov_inv.copy_(cov_inv)
            self._baseline_fitted = True

    def mahalanobis_distance(self, z: torch.Tensor) -> torch.Tensor:
        """
        Compute Mahalanobis distance from baseline distribution.

        Args:
            z: Embeddings to score [N, embedding_dim]

        Returns:
            Distances [N]
        """
        diff = z - self.baseline_mean.unsqueeze(0)
        # d² = (x-μ)ᵀ Σ⁻¹ (x-μ)
        maha_sq = (diff @ self.baseline_cov_inv * diff).sum(dim=-1)
        return torch.sqrt(torch.clamp(maha_sq, min=0.0))

    def cosine_anomaly_score(self, z: torch.Tensor) -> torch.Tensor:
        """
        Cosine distance from baseline mean embedding.
        Complementary to Mahalanobis for directional anomalies.

        Args:
            z: Embeddings [N, embedding_dim]

        Returns:
            Cosine distances [N] in [0, 1]
        """
        z_norm = F.normalize(z, dim=-1)
        mean_norm = F.normalize(self.baseline_mean.unsqueeze(0), dim=-1)
        cosine_sim = (z_norm * mean_norm).sum(dim=-1)
        return (1 - cosine_sim) / 2.0  # Map to [0, 1]

    def edge_anomaly_score(
        self,
        z: torch.Tensor,
        src_idx: int,
        dst_idx: int,
    ) -> float:
        """
        Compute combined anomaly score 0-100 for a specific edge.

        Args:
            z: Full node embedding matrix [N, embedding_dim]
            src_idx: Source node index
            dst_idx: Destination node index

        Returns:
            Anomaly score in [0, 100]
        """
        z_src = z[src_idx].unsqueeze(0)
        z_dst = z[dst_idx].unsqueeze(0)

        # Mahalanobis distance for both nodes
        maha_src = self.mahalanobis_distance(z_src).item()
        maha_dst = self.mahalanobis_distance(z_dst).item()
        maha_combined = (maha_src + maha_dst) / 2.0

        # Cosine distance
        cosine_src = self.cosine_anomaly_score(z_src).item()
        cosine_dst = self.cosine_anomaly_score(z_dst).item()
        cosine_combined = (cosine_src + cosine_dst) / 2.0

        # Edge-level predictor
        edge_prob = self.edge_predictor(z_src, z_dst).item()

        # Normalize Mahalanobis (typical range 0-20, clamp at 20)
        maha_normalized = min(maha_combined / 20.0, 1.0)

        # Weighted combination → score in [0, 1]
        raw_score = (
            0.45 * maha_normalized +
            0.25 * cosine_combined +
            0.30 * edge_prob
        )

        return float(raw_score * 100.0)
