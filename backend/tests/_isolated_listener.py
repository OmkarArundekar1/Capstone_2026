from __future__ import annotations
import os
import subprocess
import sys
import textwrap
BACKEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
LISTENER_DIR = os.path.join(BACKEND_DIR, 'listener')
_PRELUDE = f"""\nimport logging, os, sys, types\nsys.path.insert(0, {LISTENER_DIR!r})\nsys.path.insert(0, {BACKEND_DIR!r})\n\nfrom tests._production_safety import install_child_guards\ninstall_child_guards()\n\n# The real realtime_socgraph calls basicConfig at import. Keep that side effect,\n# because the listener's logging setup is written around it.\nlogging.basicConfig(level=logging.INFO)\n\nclass _Forbidden:\n    def __getattr__(self, name):\n        raise AssertionError(f"isolated listener reached stubbed dependency: {{name}}")\n\ndef _forbidden(*args, **kwargs):\n    raise AssertionError("isolated listener reached stubbed Neo4j")\n\ndef _stub(name, **attributes):\n    module = types.ModuleType(name)\n    module.__dict__.update(attributes)\n    sys.modules[name] = module\n\nprocessed = []\n\ndef _process_alert(alert):\n    processed.append(alert)\n    return True\n\n_stub("realtime_socgraph", process_alert=_process_alert)\n_stub("neo4j_client", batch_update_duplicates=_forbidden, find_recent_duplicate=_forbidden)\n_stub("campaign_manager", campaign_manager=_Forbidden())\n_stub("operation_manager", operation_manager=_Forbidden())\n\nimport wazuh_listener as wl\n\nwl.ALERT_FILE = os.path.join(os.getcwd(), "alerts.json")\nwl.__file__ = os.path.join(os.getcwd(), "wazuh_listener.py")\n"""

def run_isolated_listener(code: str, cwd: str, timeout: float=30) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, '-c', _PRELUDE + '\n' + textwrap.dedent(code)], capture_output=True, text=True, cwd=cwd, timeout=timeout)

def real_offset_state():
    from tests._production_safety import REAL_OFFSET_FILE
    try:
        status = os.stat(REAL_OFFSET_FILE)
    except FileNotFoundError:
        return None
    return (status.st_size, status.st_mtime_ns)