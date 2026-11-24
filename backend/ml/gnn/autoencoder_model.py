from __future__ import annotations
from dataclasses import dataclass, field
import torch
import torch.nn as nn
from graph_encoder import EDGE_FEATURE_DIM, FEATURE_DIM, NUMERIC_PROPS
from layers import SAGEConvLayer
NUMERIC_FEATURE_OFFSET = FEATURE_DIM - len(NUMERIC_PROPS)

@dataclass
class ReconstructionOutput:
    edge_existence_logits: torch.Tensor
    edge_type_logits: torch.Tensor
    node_feature_recon: torch.Tensor
    node_embeddings: torch.Tensor = field(repr=False, default=None)

class GraphAutoencoder(nn.Module):

    def __init__(self, in_dim: int=FEATURE_DIM, hidden_dim: int=FEATURE_DIM, embedding_dim: int=FEATURE_DIM // 2, num_layers: int=2, dropout: float=0.0) -> None:
        super().__init__()
        dims = [in_dim] + [hidden_dim] * num_layers
        self.convs = nn.ModuleList([SAGEConvLayer(dims[i], dims[i + 1]) for i in range(num_layers)])
        self.dropout = nn.Dropout(dropout)
        self.hidden_dim = hidden_dim
        self.embedding_dim = embedding_dim
        self.edge_type_decoder = nn.Linear(hidden_dim * 2, EDGE_FEATURE_DIM)
        self.node_feature_decoder = nn.Linear(hidden_dim, len(NUMERIC_PROPS))
        self.bottleneck = nn.Linear(hidden_dim, embedding_dim)

    def encode_nodes(self, x: torch.Tensor, edge_index: torch.Tensor) -> torch.Tensor:
        h = x
        for conv in self.convs:
            h = self.dropout(conv(h, edge_index))
        return h

    def pooled_embedding(self, h: torch.Tensor) -> torch.Tensor:
        pooled = h.mean(dim=0, keepdim=True) if h.shape[0] > 0 else torch.zeros((1, self.hidden_dim))
        return torch.tanh(self.bottleneck(pooled)).squeeze(0)

    def reconstruct(self, h: torch.Tensor) -> ReconstructionOutput:
        n = h.shape[0]
        edge_existence_logits = h @ h.T
        h_i = h.unsqueeze(1).expand(n, n, self.hidden_dim)
        h_j = h.unsqueeze(0).expand(n, n, self.hidden_dim)
        pair_repr = torch.cat([h_i, h_j], dim=-1)
        edge_type_logits = self.edge_type_decoder(pair_repr)
        node_feature_recon = self.node_feature_decoder(h)
        return ReconstructionOutput(edge_existence_logits=edge_existence_logits, edge_type_logits=edge_type_logits, node_feature_recon=node_feature_recon, node_embeddings=h)

    def forward(self, x: torch.Tensor, edge_index: torch.Tensor) -> ReconstructionOutput:
        h = self.encode_nodes(x, edge_index)
        return self.reconstruct(h)

    def embed_graph(self, x: torch.Tensor, edge_index: torch.Tensor) -> torch.Tensor:
        with torch.no_grad():
            h = self.encode_nodes(x, edge_index)
            return self.pooled_embedding(h)