"""
Himaya Helios - Graph Analyzer Data Pipeline
Transforms raw email metadata into PyTorch Geometric Data objects.
"""

from __future__ import annotations

import math
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

import numpy as np
import scipy.sparse as sp

try:
    import torch
    from torch_geometric.data import Data
    HAS_PYG = True
except ImportError:
    HAS_PYG = False
    import torch  # type: ignore

    class Data:  # type: ignore
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)


class EmailGraphPipeline:
    """
    Converts a list of email metadata records into a PyTorch Geometric Data object.

    Node features (per email address):
        - email_volume: log-normalized count of emails
        - external_ratio: fraction of emails to/from external domains
        - role_encoding: 0=employee, 1=manager, 2=exec (provided externally or inferred)
        - dept_encoding: integer department ID (provided externally or 0)

    Edge features (per sender→recipient pair):
        - frequency: normalized communication count
        - recency_days: normalized days since most recent email
        - direction: 0=inbound, 1=outbound, 2=both
    """

    DIRECTION_MAP = {"inbound": 0, "outbound": 1, "both": 2}

    def __init__(
        self,
        org_domain: str = "",
        user_roles: dict[str, int] | None = None,
        user_depts: dict[str, int] | None = None,
        reference_time: datetime | None = None,
    ) -> None:
        """
        Args:
            org_domain: Primary organization domain (e.g. "company.com") for external detection.
            user_roles: Map of email → role_encoding (0/1/2).
            user_depts: Map of email → dept_encoding integer.
            reference_time: Time reference for recency calculation. Defaults to now.
        """
        self.org_domain = org_domain
        self.user_roles = user_roles or {}
        self.user_depts = user_depts or {}
        self.reference_time = reference_time or datetime.now(timezone.utc)

    def _extract_domain(self, email: str) -> str:
        return email.split("@")[-1].lower() if "@" in email else email

    def _is_external(self, email: str) -> bool:
        if not self.org_domain:
            return False
        return self._extract_domain(email) != self.org_domain

    def build(self, email_records: list[dict[str, Any]]) -> Data:
        """
        Build a PyG Data object from a list of email metadata dicts.

        Expected dict keys:
            - sender (str): Sender email
            - recipient (str): Recipient email
            - timestamp (datetime | str): Email timestamp
            - direction (str): "inbound" | "outbound" | "both"

        Returns:
            PyG Data object with x, edge_index, edge_attr attributes.
        """
        if not email_records:
            raise ValueError("email_records must not be empty")

        # --- Node indexing ---
        node_set: set[str] = set()
        for rec in email_records:
            node_set.add(rec["sender"].lower())
            node_set.add(rec["recipient"].lower())

        node_list = sorted(node_set)
        node_idx: dict[str, int] = {n: i for i, n in enumerate(node_list)}
        num_nodes = len(node_list)

        # --- Accumulators ---
        node_email_count: dict[str, int] = defaultdict(int)
        node_external_count: dict[str, int] = defaultdict(int)

        # edge key: (src_idx, dst_idx) → {count, timestamps, direction}
        edge_data: dict[tuple[int, int], dict[str, Any]] = defaultdict(
            lambda: {"count": 0, "timestamps": [], "directions": set()}
        )

        for rec in email_records:
            sender = rec["sender"].lower()
            recipient = rec["recipient"].lower()
            direction = rec.get("direction", "outbound").lower()

            ts = rec["timestamp"]
            if isinstance(ts, str):
                ts = datetime.fromisoformat(ts)
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)

            # Count emails per node
            node_email_count[sender] += 1
            node_email_count[recipient] += 1

            # Count external interactions
            if self._is_external(sender):
                node_external_count[recipient] += 1
            if self._is_external(recipient):
                node_external_count[sender] += 1

            # Edge accumulation
            src_i = node_idx[sender]
            dst_i = node_idx[recipient]
            ekey = (src_i, dst_i)
            edge_data[ekey]["count"] += 1
            edge_data[ekey]["timestamps"].append(ts)
            edge_data[ekey]["directions"].add(direction)

        # --- Compute node features ---
        max_count = max(node_email_count.values()) if node_email_count else 1

        node_features = np.zeros((num_nodes, 4), dtype=np.float32)
        for node_name, node_i in node_idx.items():
            count = node_email_count.get(node_name, 0)
            external = node_external_count.get(node_name, 0)

            # email_volume: log-normalized
            node_features[node_i, 0] = math.log1p(count) / math.log1p(max_count)
            # external_ratio
            node_features[node_i, 1] = external / count if count > 0 else 0.0
            # role_encoding (normalized to 0-1 for NN stability)
            role = self.user_roles.get(node_name, 0)
            node_features[node_i, 2] = role / 2.0
            # dept_encoding (normalized, assuming max 20 depts)
            dept = self.user_depts.get(node_name, 0)
            node_features[node_i, 3] = min(dept / 20.0, 1.0)

        # --- Compute edge features ---
        max_edge_count = max((v["count"] for v in edge_data.values()), default=1)
        ref_ts = self.reference_time

        edge_indices: list[list[int]] = [[], []]
        edge_attrs: list[list[float]] = []

        for (src_i, dst_i), einfo in sorted(edge_data.items()):
            edge_indices[0].append(src_i)
            edge_indices[1].append(dst_i)

            # frequency (normalized)
            freq = einfo["count"] / max_edge_count

            # recency_days (normalized, max 365 days → 0)
            latest_ts = max(einfo["timestamps"])
            days_ago = (ref_ts - latest_ts).total_seconds() / 86400.0
            recency = 1.0 - min(days_ago / 365.0, 1.0)

            # direction encoding
            dirs = einfo["directions"]
            if len(dirs) > 1 or "both" in dirs:
                dir_enc = 2.0
            elif "outbound" in dirs:
                dir_enc = 1.0
            else:
                dir_enc = 0.0
            dir_enc /= 2.0  # normalize to [0, 1]

            edge_attrs.append([freq, recency, dir_enc])

        # --- Adjacency matrix (scipy sparse, for reference) ---
        row = edge_indices[0]
        col = edge_indices[1]
        data_vals = [ea[0] for ea in edge_attrs]  # frequency as weight
        adjacency = sp.csr_matrix(
            (data_vals, (row, col)),
            shape=(num_nodes, num_nodes),
        )

        # --- Build PyG Data ---
        x = torch.tensor(node_features, dtype=torch.float32)
        edge_index_t = torch.tensor(edge_indices, dtype=torch.long)
        edge_attr_t = torch.tensor(edge_attrs, dtype=torch.float32)

        pyg_data = Data(
            x=x,
            edge_index=edge_index_t,
            edge_attr=edge_attr_t,
            num_nodes=num_nodes,
        )

        # Attach metadata for downstream use
        pyg_data.node_names = node_list
        pyg_data.node_idx = node_idx
        pyg_data.adjacency = adjacency

        return pyg_data

    def build_new_edge_features(
        self,
        existing_data: Data,
        sender: str,
        recipient: str,
        direction: str = "inbound",
    ) -> tuple[int, int, torch.Tensor]:
        """
        Given an existing graph Data object and a new edge, return
        (src_idx, dst_idx, edge_attr_tensor) for inference.

        If sender or recipient are unknown nodes, they are assigned
        the nearest existing node's features (fallback).

        Returns:
            (src_idx, dst_idx, edge_attr) for use in inference
        """
        sender = sender.lower()
        recipient = recipient.lower()

        node_idx: dict[str, int] = existing_data.node_idx
        num_existing = existing_data.num_nodes

        # Add unknown nodes if necessary
        new_features = []
        final_idx = dict(node_idx)

        for email in [sender, recipient]:
            if email not in final_idx:
                # New node: assign default features (unknown entity = high risk profile)
                new_i = num_existing + len(new_features)
                final_idx[email] = new_i
                # email_volume=0, external_ratio=1, role=employee, dept=unknown
                new_features.append([0.0, 1.0, 0.0, 0.0])

        src_idx = final_idx[sender]
        dst_idx = final_idx[recipient]

        # Edge feature for a *new* (first-time) edge: freq=0, recency=1 (just now), direction
        dir_val = {"inbound": 0.0, "outbound": 0.5, "both": 1.0}.get(direction.lower(), 0.0)
        edge_attr = torch.tensor([[0.0, 1.0, dir_val]], dtype=torch.float32)

        # Extend node feature matrix if new nodes were added
        if new_features:
            new_x = torch.tensor(new_features, dtype=torch.float32)
            existing_data.x = torch.cat([existing_data.x, new_x], dim=0)

        return src_idx, dst_idx, edge_attr
