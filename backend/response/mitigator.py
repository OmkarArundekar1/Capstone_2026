from __future__ import annotations
import logging
import subprocess
from typing import Any
logger = logging.getLogger(__name__)

class Mitigator:

    def __init__(self, dry_run: bool=True) -> None:
        self.dry_run = dry_run
        self._action_log: list[dict[str, Any]] = []

    def execute_playbook(self, playbook: dict[str, Any]) -> dict[str, Any]:
        results = []
        for action in playbook.get('actions', []):
            result = self._execute_action(action)
            results.append(result)
        executed = sum((1 for r in results if r['status'] == 'executed'))
        skipped = sum((1 for r in results if r['status'] == 'skipped'))
        logged = sum((1 for r in results if r['status'] == 'logged_dry_run'))
        report = {'playbook_id': playbook.get('playbook_id'), 'dry_run': self.dry_run, 'total_actions': len(results), 'executed': executed, 'skipped': skipped, 'logged_dry_run': logged, 'results': results}
        self._action_log.append(report)
        return report

    def _execute_action(self, action: dict[str, Any]) -> dict[str, Any]:
        action_id = action.get('action_id', 'UNKNOWN')
        auto = action.get('auto_execute', False)
        command = action.get('command')
        if not auto:
            logger.info('[SKIPPED] %s — requires manual approval', action_id)
            return {'action_id': action_id, 'status': 'skipped', 'reason': 'manual_approval_required'}
        if self.dry_run:
            logger.info('[DRY-RUN] Would execute: %s — %s', action_id, action.get('description'))
            if command:
                logger.info('           Command: %s', command)
            return {'action_id': action_id, 'status': 'logged_dry_run', 'command': command}
        if command:
            try:
                result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    logger.warning('[EXECUTED] %s — success', action_id)
                    return {'action_id': action_id, 'status': 'executed', 'output': result.stdout}
                else:
                    logger.error('[FAILED] %s — %s', action_id, result.stderr)
                    return {'action_id': action_id, 'status': 'failed', 'error': result.stderr}
            except Exception as e:
                return {'action_id': action_id, 'status': 'error', 'error': str(e)}
        else:
            logger.info('[EXECUTED] %s — no command (notification/alert)', action_id)
            return {'action_id': action_id, 'status': 'executed', 'output': 'Notification sent'}

    @property
    def action_log(self) -> list[dict[str, Any]]:
        return list(self._action_log)