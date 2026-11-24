from __future__ import annotations
import os
import subprocess
import sys
import textwrap
import pytest
from tests._isolated_listener import real_offset_state, run_isolated_listener
BACKEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
LISTENER_DIR = os.path.join(BACKEND_DIR, 'listener')
_PATH_PRELUDE = f'\nimport sys\nsys.path.insert(0, {LISTENER_DIR!r})\nsys.path.insert(0, {BACKEND_DIR!r})\nfrom tests._production_safety import install_child_guards\ninstall_child_guards()\n'

def _run(code: str, cwd: str, timeout: float=30) -> subprocess.CompletedProcess:
    full_code = _PATH_PRELUDE + '\n' + textwrap.dedent(code)
    return subprocess.run([sys.executable, '-c', full_code], capture_output=True, text=True, cwd=cwd, timeout=timeout)

def _log_path(cwd: str) -> str:
    return os.path.join(cwd, 'logs', 'prerana_listener.log')

def test_audit_event_is_actually_written_to_the_log_file(tmp_path):
    result = _run('\n        import wazuh_listener as wl\n        wl.logger.info("AUDIT_EVENT_BASIC_PERSISTENCE_CHECK")\n        ', cwd=str(tmp_path))
    assert result.returncode == 0, result.stderr
    log_path = _log_path(str(tmp_path))
    assert os.path.exists(log_path), 'logging setup must create the log file'
    content = open(log_path, encoding='utf-8').read()
    assert 'AUDIT_EVENT_BASIC_PERSISTENCE_CHECK' in content
    assert ' | INFO | ' in content

def test_stdout_logging_still_works_alongside_file_logging(tmp_path):
    result = _run('\n        import wazuh_listener as wl\n        wl.logger.info("AUDIT_EVENT_STDOUT_CHECK")\n        ', cwd=str(tmp_path))
    assert result.returncode == 0, result.stderr
    console_output = result.stdout + result.stderr
    assert 'AUDIT_EVENT_STDOUT_CHECK' in console_output
    log_path = _log_path(str(tmp_path))
    assert 'AUDIT_EVENT_STDOUT_CHECK' in open(log_path, encoding='utf-8').read()

def test_repeated_configure_logging_does_not_duplicate_handlers_or_lines(tmp_path):
    result = _run('\n        import logging\n        import wazuh_listener as wl\n\n        handler_counts = [len(logging.getLogger().handlers)]\n        for _ in range(4):\n            wl._configure_logging()\n            handler_counts.append(len(logging.getLogger().handlers))\n\n        assert len(set(handler_counts)) == 1, (\n            f"handler count changed across repeated _configure_logging() calls: {handler_counts}"\n        )\n\n        file_handlers = [h for h in logging.getLogger().handlers if isinstance(h, logging.FileHandler)]\n        assert len(file_handlers) == 1, f"expected exactly one FileHandler, found {len(file_handlers)}"\n\n        wl.logger.info("AUDIT_EVENT_DUPLICATE_INIT_CHECK")\n        ', cwd=str(tmp_path))
    assert result.returncode == 0, result.stderr
    content = open(_log_path(str(tmp_path)), encoding='utf-8').read()
    assert content.count('AUDIT_EVENT_DUPLICATE_INIT_CHECK') == 1, f"expected exactly one occurrence, got {content.count('AUDIT_EVENT_DUPLICATE_INIT_CHECK')}:\n{content}"

def test_reimporting_via_fresh_interpreter_does_not_duplicate_prior_content(tmp_path):
    first = _run('\n        import wazuh_listener as wl\n        wl.logger.info("AUDIT_EVENT_FIRST_PROCESS")\n        ', cwd=str(tmp_path))
    assert first.returncode == 0, first.stderr
    second = _run('\n        import wazuh_listener as wl\n        wl.logger.info("AUDIT_EVENT_SECOND_PROCESS")\n        ', cwd=str(tmp_path))
    assert second.returncode == 0, second.stderr
    content = open(_log_path(str(tmp_path)), encoding='utf-8').read()
    assert content.count('AUDIT_EVENT_FIRST_PROCESS') == 1
    assert content.count('AUDIT_EVENT_SECOND_PROCESS') == 1

def test_events_persist_across_the_real_start_listener_shutdown_lifecycle(tmp_path):
    offset_before = real_offset_state()
    result = run_isolated_listener('\n        import threading, time\n\n        def trigger_stop():\n            time.sleep(1.5)\n            wl.stop_event.set()\n\n        threading.Thread(target=trigger_stop, daemon=True).start()\n        wl.start_listener()\n        print("START_LISTENER_RETURNED", flush=True)\n        ', cwd=str(tmp_path), timeout=20)
    assert real_offset_state() == offset_before
    assert result.returncode == 0, result.stderr
    assert 'START_LISTENER_RETURNED' in result.stdout, 'start_listener() must return once stop_event is set, not hang'
    content = open(_log_path(str(tmp_path)), encoding='utf-8').read()
    assert 'Prerana Listener initialized.' in content
    assert 'Queue worker started.' in content
    assert 'Listener stopped.' in content, "the shutdown path's own log line must reach the file, not just startup lines"

def test_real_listener_startup_path_produces_audit_events_that_reach_the_file(tmp_path):
    offset_before = real_offset_state()
    result = run_isolated_listener('\n        import threading, time\n\n        def trigger_stop():\n            time.sleep(1.0)\n            wl.stop_event.set()\n\n        threading.Thread(target=trigger_stop, daemon=True).start()\n        wl.start_listener()\n        ', cwd=str(tmp_path), timeout=20)
    assert real_offset_state() == offset_before
    assert result.returncode == 0, result.stderr
    content = open(_log_path(str(tmp_path)), encoding='utf-8').read()
    expected_lines = ['Prerana Listener initialized.', 'Watching :', 'Initial offset =', 'Queue worker started.', 'Maintenance worker started.', 'Polling started.', 'Waiting for new Wazuh alerts...']
    missing = [line for line in expected_lines if line not in content]
    assert not missing, f'expected real lifecycle audit lines missing from file: {missing}\ngot:\n{content}'