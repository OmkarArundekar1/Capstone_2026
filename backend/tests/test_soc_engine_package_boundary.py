import subprocess
import sys
from pathlib import Path
BACKEND_DIR = Path(__file__).resolve().parent.parent

def test_soc_engine_package_does_not_reexport_generation1_only_helpers():
    import soc_engine
    assert not hasattr(soc_engine, 'FeatureExplainer')
    assert not hasattr(soc_engine, 'TemporalSmoother')
    assert 'FeatureExplainer' not in soc_engine.__all__
    assert 'TemporalSmoother' not in soc_engine.__all__

def test_soc_engine_reusable_generation2_primitives_still_reexported():
    import soc_engine
    assert soc_engine.Autoencoder is not None
    assert soc_engine.load_autoencoder is not None
    assert soc_engine.SeverityScorer is not None
    assert soc_engine.compute_scores is not None
    assert soc_engine.AdaptiveThreshold is not None
    assert soc_engine.AutoencoderTrainer is not None

def test_explainer_and_temporal_engine_remain_directly_importable():
    from soc_engine.explainer import FeatureExplainer
    from soc_engine.temporal_engine import TemporalSmoother, apply_temporal_smoothing
    assert FeatureExplainer is not None
    assert TemporalSmoother is not None
    assert apply_temporal_smoothing is not None

def test_generation2_import_path_no_longer_pulls_in_generation1_only_modules():
    code = "import sys\nfrom tests._production_safety import install_child_guards\ninstall_child_guards()\nfrom soc_engine.model import Autoencoder\nassert 'soc_engine.explainer' not in sys.modules, 'explainer.py must not be eagerly imported via soc_engine.model'\nassert 'soc_engine.temporal_engine' not in sys.modules, 'temporal_engine.py must not be eagerly imported via soc_engine.model'\nprint('OK')\n"
    result = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, cwd=str(BACKEND_DIR))
    assert result.returncode == 0, result.stderr
    assert 'OK' in result.stdout