from __future__ import annotations
import os
from pathlib import Path
from typing import Any
import numpy as np
_ML_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_MODEL_DIR = os.path.join(_ML_DIR, 'models')
DEFAULT_WINDOW_FEATURES_PATH = os.path.join(_ML_DIR, 'artifacts', 'window_features.npy')

class SSFTRuntimeTransformer:

    def __init__(self, model_dir: str=DEFAULT_MODEL_DIR) -> None:
        import joblib
        import torch
        from soc_engine.model import Autoencoder
        model_dir_path = Path(model_dir)
        model_path = model_dir_path / 'autoencoder_best.pth'
        scaler_path = model_dir_path / 'ssl_scaler.pkl'
        if not model_path.exists():
            raise FileNotFoundError(f'No trained SSL autoencoder at {model_path}. Run ml/ssl_pipeline.py (train_ssl_autoencoder) first — SSFT transforms data through an already-trained self-supervised model, it does not train one.')
        self._scaler = joblib.load(scaler_path)
        self._model = Autoencoder(input_dim=self._scaler.n_features_in_)
        self._model.load_state_dict(torch.load(model_path, map_location='cpu', weights_only=True))
        self._model.eval()

    @property
    def input_dim(self) -> int:
        return int(self._scaler.n_features_in_)

    def transform(self, windows: np.ndarray) -> dict[str, Any]:
        import torch
        arr = np.asarray(windows, dtype=np.float64)
        single = arr.ndim == 1
        arr = np.atleast_2d(arr)
        if arr.shape[1] != self.input_dim:
            raise ValueError(f'SSFTRuntimeTransformer expects {self.input_dim}-dimensional window features (the shape ssl_scaler.pkl was fit on), got {arr.shape[1]}.')
        arr = np.nan_to_num(arr, nan=0.0, posinf=0.0, neginf=0.0)
        scaled = self._scaler.transform(arr).astype(np.float32)
        x = torch.tensor(scaled, dtype=torch.float32)
        with torch.no_grad():
            latent = self._model.encode(x).numpy()
        errors = self._model.reconstruction_errors(x).numpy()
        if single:
            return {'latent': latent[0], 'reconstruction_error': float(errors[0])}
        return {'latent': latent, 'reconstruction_error': errors}

def transform_to_ssft_dataset(window_features_path: str=DEFAULT_WINDOW_FEATURES_PATH, model_dir: str=DEFAULT_MODEL_DIR, output_path: str | None=None) -> str:
    model_dir_path = Path(model_dir)
    transformer = SSFTRuntimeTransformer(model_dir_path)
    raw = np.load(window_features_path)
    result = transformer.transform(raw)
    output_path = output_path or str(model_dir_path.parent / 'artifacts' / 'ssft_dataset.npz')
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(output_path, latent=result['latent'], reconstruction_error=result['reconstruction_error'])
    return output_path
if __name__ == '__main__':
    path = transform_to_ssft_dataset()
    print(f'SSFT dataset written to {path}')