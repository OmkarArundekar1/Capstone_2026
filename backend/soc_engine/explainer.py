from __future__ import annotations
import logging
from typing import Any
import numpy as np
import torch
logger = logging.getLogger(__name__)

class FeatureExplainer:

    def __init__(self, feature_names: list[str] | None=None, top_k: int=5) -> None:
        self.feature_names = feature_names
        self.top_k = top_k

    def explain(self, model: 'torch.nn.Module', x: np.ndarray | torch.Tensor) -> list[dict[str, Any]]:
        if isinstance(x, np.ndarray):
            x_tensor = torch.tensor(x, dtype=torch.float32)
        else:
            x_tensor = x.float()
        device = next(model.parameters()).device
        x_tensor = x_tensor.to(device)
        per_feat_err = model.per_feature_errors(x_tensor).cpu().numpy()
        results = []
        for i in range(per_feat_err.shape[0]):
            results.append(self._top_features(per_feat_err[i]))
        return results

    def explain_single(self, model: 'torch.nn.Module', x: np.ndarray | torch.Tensor) -> dict[str, Any]:
        if isinstance(x, np.ndarray):
            x = x.ravel()[np.newaxis, :]
        else:
            x = x.view(1, -1)
        return self.explain(model, x)[0]

    def _top_features(self, per_feat_err: np.ndarray) -> dict[str, Any]:
        total_err = float(per_feat_err.sum()) + 1e-09
        top_indices = np.argsort(per_feat_err)[::-1][:self.top_k]
        top_features = []
        for idx in top_indices:
            name = self.feature_names[idx] if self.feature_names and idx < len(self.feature_names) else f'feature_{idx}'
            attribution = float(per_feat_err[idx])
            top_features.append({'feature_index': int(idx), 'feature_name': name, 'attribution': round(attribution, 6), 'contribution_pct': round(100.0 * attribution / total_err, 2)})
        return {'top_features': top_features}

def explain_from_per_feature_errors(per_feat_errors: np.ndarray, feature_names: list[str] | None=None, top_k: int=5) -> list[dict[str, Any]]:
    explainer = FeatureExplainer(feature_names=feature_names, top_k=top_k)
    results = []
    for i in range(per_feat_errors.shape[0]):
        results.append(explainer._top_features(per_feat_errors[i]))
    return results