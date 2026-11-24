from __future__ import annotations
import platform
import sys
_SAFE_SCALAR_FIELDS = ['NEO4J_URI', 'MISP_URL', 'VERIFY_MISP_SSL', 'GNN_ENABLED', 'GNN_MODEL_PATH', 'CAMPAIGN_TIMEOUT', 'OPERATION_TIMEOUT', 'DEDUP_WINDOW', 'ENABLE_DUPLICATE_BUFFER', 'LOG_LEVEL']

def get_safe_config_snapshot() -> dict:
    import config
    snapshot: dict = {}
    for field in _SAFE_SCALAR_FIELDS:
        if hasattr(config, field):
            snapshot[field] = getattr(config, field)
    snapshot['misp_credential_configured'] = bool(getattr(config, 'MISP_API_KEY', ''))
    snapshot['shuffle_webhook_configured'] = bool(getattr(config, 'SHUFFLE_WEBHOOK', ''))
    snapshot['shuffle_api_configured'] = bool(getattr(config, 'SHUFFLE_BASE_URL', '') and getattr(config, 'SHUFFLE_API_KEY', ''))
    snapshot['software_versions'] = get_software_versions()
    return snapshot

def get_software_versions() -> dict:
    versions = {'python': sys.version.split()[0], 'platform': platform.platform()}

    def _pkg_version(module_name: str) -> str | None:
        try:
            import importlib.metadata
            return importlib.metadata.version(module_name)
        except Exception:
            return None
    for pkg in ['flask', 'neo4j', 'torch', 'xgboost', 'scikit-learn', 'requests']:
        versions[pkg] = _pkg_version(pkg)
    return versions