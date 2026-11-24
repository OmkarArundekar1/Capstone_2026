import os
import signal
import sys
import pytest
BACKEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)
from tests._production_safety import DELIBERATE_NETWORK, REAL_LISTENER_LOG, UnsafeConfiguration, activate, verify_disposable_marker, verify_resolved_settings
_UNSAFE_CONFIGURATION = None
try:
    SAFETY = activate()
except UnsafeConfiguration as error:
    SAFETY = None
    _UNSAFE_CONFIGURATION = error

def pytest_configure(config):
    if _UNSAFE_CONFIGURATION is not None:
        raise pytest.UsageError(str(_UNSAFE_CONFIGURATION))

def pytest_sessionstart(session):
    import config as backend_config
    try:
        verify_resolved_settings(backend_config, SAFETY.config)
    except UnsafeConfiguration as error:
        raise pytest.UsageError(str(error))

def _redirect_dashboard_listener_log():
    dashboard_api = sys.modules.get('dashboard_api')
    if dashboard_api is not None and dashboard_api.LISTENER_LOG_PATH == REAL_LISTENER_LOG:
        dashboard_api.LISTENER_LOG_PATH = os.path.join(SAFETY.scratch_dir, 'no_listener_log.log')

def pytest_collection_finish(session):
    _redirect_dashboard_listener_log()

def pytest_terminal_summary(terminalreporter):
    if SAFETY is None:
        return
    records = SAFETY.network.records
    if records:
        terminalreporter.section('network attempts blocked by the test guard')
        lines = {f"{('deliberate' if r['deliberate'] else 'UNEXPECTED')} {r['operation']} {r['destination']} <- {r['test']}" for r in records}
        for line in sorted(lines):
            terminalreporter.line(line)
    if SAFETY.paths.violations:
        terminalreporter.section('protected resources refused by the test guard')
        for violation in SAFETY.paths.violations:
            terminalreporter.line(violation)

@pytest.fixture(autouse=True)
def _production_safety_checks():
    _redirect_dashboard_listener_log()
    handlers = (signal.getsignal(signal.SIGINT), signal.getsignal(signal.SIGTERM))
    violations_before = len(SAFETY.paths.violations)
    yield
    new_violations = SAFETY.paths.violations[violations_before:]
    assert not new_violations, f'test reached protected resources: {new_violations}'
    assert (signal.getsignal(signal.SIGINT), signal.getsignal(signal.SIGTERM)) == handlers, "test replaced this process's signal handlers"

@pytest.fixture
def deliberate_network(monkeypatch):
    monkeypatch.setenv(DELIBERATE_NETWORK, '1')

@pytest.fixture
def live_neo4j():
    if SAFETY.config.live_uri is None:
        pytest.skip(SAFETY.config.live_skip_reason)
    from neo4j_client import driver
    try:
        verify_disposable_marker(driver, SAFETY.config.live_marker)
    except UnsafeConfiguration as error:
        pytest.fail(str(error), pytrace=False)

@pytest.fixture(autouse=True)
def _reset_gnn_inference_singleton():
    from ml.gnn.inference import gnn_inference_service
    gnn_inference_service._loaded = False
    gnn_inference_service._model = None
    gnn_inference_service._metadata = None
    gnn_inference_service._embedding_cache.clear()
    yield
    gnn_inference_service._loaded = False
    gnn_inference_service._model = None
    gnn_inference_service._metadata = None
    gnn_inference_service._embedding_cache.clear()