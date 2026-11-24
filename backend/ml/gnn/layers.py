from __future__ import annotations
import torch
import torch.nn as nn
import torch.nn.functional as F

class SAGEConvLayer(nn.Module):

    def __init__(self, in_dim: int, out_dim: int) -> None:
        super().__init__()
        self.self_lin = nn.Linear(in_dim, out_dim)
        self.neigh_lin = nn.Linear(in_dim, out_dim)

    def forward(self, x: torch.Tensor, edge_index: torch.Tensor) -> torch.Tensor:
        num_nodes = x.shape[0]
        if edge_index.shape[1] == 0:
            neigh_mean = torch.zeros_like(x)
        else:
            src, dst = (edge_index[0], edge_index[1])
            neigh_sum = torch.zeros_like(x).index_add_(0, dst, x[src])
            counts = torch.zeros(num_nodes, device=x.device, dtype=x.dtype)
            counts = counts.index_add_(0, dst, torch.ones(src.shape[0], device=x.device, dtype=x.dtype))
            neigh_mean = neigh_sum / counts.clamp(min=1.0).unsqueeze(1)
        return F.relu(self.self_lin(x) + self.neigh_lin(neigh_mean))