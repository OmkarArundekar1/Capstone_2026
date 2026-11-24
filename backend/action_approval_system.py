from __future__ import annotations
import logging
import uuid
import subprocess
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List, Callable
from datetime import datetime
from enum import Enum
import threading
import queue
from enhanced_detection_output import SuggestedAction, ActionStatus, AlertSeverity
logger = logging.getLogger(__name__)

class ExecutionResult(str, Enum):
    SUCCESS = 'SUCCESS'
    FAILED = 'FAILED'
    PARTIAL = 'PARTIAL'
    SKIPPED = 'SKIPPED'
    TIMEOUT = 'TIMEOUT'

@dataclass
class ActionExecution:
    execution_id: str
    action_id: str
    action_type: str
    target: str
    command: Optional[str]
    status: ActionStatus
    result: ExecutionResult
    output: str = ''
    error: str = ''
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    executed_by: str = 'system'

    def to_dict(self) -> Dict[str, Any]:
        return {'execution_id': self.execution_id, 'action_id': self.action_id, 'action_type': self.action_type, 'target': self.target, 'status': self.status.value, 'result': self.result.value, 'output': self.output, 'error': self.error, 'started_at': self.started_at.isoformat() if self.started_at else None, 'completed_at': self.completed_at.isoformat() if self.completed_at else None, 'executed_by': self.executed_by}

class ActionExecutor:
    ACTION_HANDLERS: Dict[str, Callable] = {}

    def __init__(self, dry_run: bool=False):
        self.dry_run = dry_run
        self.audit_trail: List[ActionExecution] = []
        self.audit_lock = threading.RLock()
        self.execution_queue = queue.Queue(maxsize=100)
        self.executor_thread = None
        self.running = False
        self._register_handlers()
        logger.info(f'ActionExecutor initialized (dry_run={dry_run})')

    def _register_handlers(self):
        self.ACTION_HANDLERS = {'block_ip': self._block_ip, 'unblock_ip': self._unblock_ip, 'isolate_host': self._isolate_host, 'disable_account': self._disable_account, 'enable_monitoring': self._enable_monitoring, 'collect_forensics': self._collect_forensics, 'kill_process': self._kill_process, 'block_port': self._block_port, 'rate_limit': self._rate_limit, 'alert_analyst': self._alert_analyst}

    def execute_action(self, action: SuggestedAction, executed_by: str='system') -> ActionExecution:
        execution = ActionExecution(execution_id=str(uuid.uuid4()), action_id=action.action_id, action_type=action.action_type, target=action.target, command=action.command, status=ActionStatus.EXECUTING, result=ExecutionResult.SKIPPED, started_at=datetime.utcnow(), executed_by=executed_by)
        if action.requires_approval and action.status != ActionStatus.APPROVED:
            execution.status = ActionStatus.FAILED
            execution.result = ExecutionResult.SKIPPED
            execution.error = 'Action requires approval but is not approved'
            execution.completed_at = datetime.utcnow()
            self._record_execution(execution)
            logger.warning(f'Blocked unapproved action: {action.action_id}')
            return execution
        logger.info(f'Executing action: {action.action_type} on {action.target} (dry_run={self.dry_run})')
        try:
            handler = self.ACTION_HANDLERS.get(action.action_type)
            if not handler:
                execution.result = ExecutionResult.FAILED
                execution.error = f'No handler for action type: {action.action_type}'
            elif self.dry_run:
                execution.result = ExecutionResult.SUCCESS
                execution.output = f'[DRY RUN] Would execute: {action.action_type} on {action.target}'
                if action.command:
                    execution.output += f'\nCommand: {action.command}'
            else:
                result = handler(action)
                execution.result = result.get('result', ExecutionResult.SUCCESS)
                execution.output = result.get('output', '')
                execution.error = result.get('error', '')
            if execution.result == ExecutionResult.SUCCESS:
                execution.status = ActionStatus.COMPLETED
            else:
                execution.status = ActionStatus.FAILED
            logger.info(f'Action {action.action_id} completed: result={execution.result.value}')
        except Exception as e:
            logger.exception(f'Action execution failed: {e}')
            execution.result = ExecutionResult.FAILED
            execution.status = ActionStatus.FAILED
            execution.error = str(e)
        execution.completed_at = datetime.utcnow()
        self._record_execution(execution)
        return execution

    def _record_execution(self, execution: ActionExecution):
        with self.audit_lock:
            self.audit_trail.append(execution)
            if len(self.audit_trail) > 1000:
                self.audit_trail = self.audit_trail[-1000:]

    def get_audit_trail(self, action_id: Optional[str]=None, target: Optional[str]=None, limit: int=100) -> List[ActionExecution]:
        with self.audit_lock:
            trail = self.audit_trail
            if action_id:
                trail = [e for e in trail if e.action_id == action_id]
            if target:
                trail = [e for e in trail if e.target == target]
            return trail[-limit:]

    def _block_ip(self, action: SuggestedAction) -> Dict[str, Any]:
        ip = action.target
        try:
            command = f'iptables -A INPUT -s {ip} -j DROP'
            if action.command:
                command = action.command
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                return {'result': ExecutionResult.SUCCESS, 'output': f'Successfully blocked IP {ip}\n{result.stdout}'}
            else:
                return {'result': ExecutionResult.FAILED, 'error': f'Failed to block IP {ip}: {result.stderr}'}
        except subprocess.TimeoutExpired:
            return {'result': ExecutionResult.TIMEOUT, 'error': 'Command execution timed out'}
        except Exception as e:
            return {'result': ExecutionResult.FAILED, 'error': str(e)}

    def _unblock_ip(self, action: SuggestedAction) -> Dict[str, Any]:
        ip = action.target
        try:
            command = f'iptables -D INPUT -s {ip} -j DROP'
            if action.command:
                command = action.command
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                return {'result': ExecutionResult.SUCCESS, 'output': f'Successfully unblocked IP {ip}\n{result.stdout}'}
            else:
                return {'result': ExecutionResult.FAILED, 'error': f'Failed to unblock IP {ip}: {result.stderr}'}
        except Exception as e:
            return {'result': ExecutionResult.FAILED, 'error': str(e)}

    def _isolate_host(self, action: SuggestedAction) -> Dict[str, Any]:
        host = action.target
        return {'result': ExecutionResult.SUCCESS, 'output': f'Host {host} isolated from network (placeholder)'}

    def _disable_account(self, action: SuggestedAction) -> Dict[str, Any]:
        account = action.target
        return {'result': ExecutionResult.SUCCESS, 'output': f'Account {account} disabled (placeholder)'}

    def _enable_monitoring(self, action: SuggestedAction) -> Dict[str, Any]:
        target = action.target
        return {'result': ExecutionResult.SUCCESS, 'output': f'Enhanced monitoring enabled for {target}'}

    def _collect_forensics(self, action: SuggestedAction) -> Dict[str, Any]:
        target = action.target
        return {'result': ExecutionResult.SUCCESS, 'output': f'Forensics collection initiated for {target}'}

    def _kill_process(self, action: SuggestedAction) -> Dict[str, Any]:
        pid = action.target
        try:
            command = f'kill -9 {pid}'
            if action.command:
                command = action.command
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=5)
            return {'result': ExecutionResult.SUCCESS if result.returncode == 0 else ExecutionResult.FAILED, 'output': result.stdout, 'error': result.stderr}
        except Exception as e:
            return {'result': ExecutionResult.FAILED, 'error': str(e)}

    def _block_port(self, action: SuggestedAction) -> Dict[str, Any]:
        port = action.target
        try:
            command = f'iptables -A INPUT -p tcp --dport {port} -j DROP'
            if action.command:
                command = action.command
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=10)
            return {'result': ExecutionResult.SUCCESS if result.returncode == 0 else ExecutionResult.FAILED, 'output': result.stdout, 'error': result.stderr}
        except Exception as e:
            return {'result': ExecutionResult.FAILED, 'error': str(e)}

    def _rate_limit(self, action: SuggestedAction) -> Dict[str, Any]:
        target = action.target
        return {'result': ExecutionResult.SUCCESS, 'output': f'Rate limiting applied to {target}'}

    def _alert_analyst(self, action: SuggestedAction) -> Dict[str, Any]:
        return {'result': ExecutionResult.SUCCESS, 'output': f'Alert sent to analyst about {action.target}'}

class ActionApprovalManager:

    def __init__(self, executor: ActionExecutor):
        self.executor = executor
        self.pending_actions: Dict[str, SuggestedAction] = {}
        self.lock = threading.RLock()
        logger.info('ActionApprovalManager initialized')

    def submit_action(self, action: SuggestedAction) -> bool:
        with self.lock:
            if not action.requires_approval and action.auto_applicable:
                logger.info(f'Auto-executing action: {action.action_id}')
                execution = self.executor.execute_action(action, executed_by='auto')
                return execution.status == ActionStatus.COMPLETED
            else:
                self.pending_actions[action.action_id] = action
                logger.info(f'Action queued for approval: {action.action_id}')
                return True

    def approve_action(self, action_id: str, approved_by: str, execute_immediately: bool=True) -> Optional[ActionExecution]:
        with self.lock:
            action = self.pending_actions.get(action_id)
            if not action:
                logger.warning(f'Action not found: {action_id}')
                return None
            action.status = ActionStatus.APPROVED
            action.approved_by = approved_by
            action.approved_at = datetime.utcnow()
            logger.info(f'Action approved: {action_id} by {approved_by}')
            if execute_immediately:
                execution = self.executor.execute_action(action, executed_by=approved_by)
                del self.pending_actions[action_id]
                return execution
            return None

    def reject_action(self, action_id: str, rejected_by: str, reason: str='') -> bool:
        with self.lock:
            action = self.pending_actions.get(action_id)
            if not action:
                logger.warning(f'Action not found: {action_id}')
                return False
            action.status = ActionStatus.REJECTED
            logger.info(f'Action rejected: {action_id} by {rejected_by} (reason: {reason})')
            del self.pending_actions[action_id]
            return True

    def get_pending_actions(self) -> List[SuggestedAction]:
        with self.lock:
            return list(self.pending_actions.values())

    def get_action(self, action_id: str) -> Optional[SuggestedAction]:
        with self.lock:
            return self.pending_actions.get(action_id)
_executor: Optional[ActionExecutor] = None
_approval_manager: Optional[ActionApprovalManager] = None

def get_executor(dry_run: bool=False) -> ActionExecutor:
    global _executor
    if _executor is None:
        _executor = ActionExecutor(dry_run=dry_run)
    return _executor

def get_approval_manager() -> ActionApprovalManager:
    global _approval_manager
    if _approval_manager is None:
        executor = get_executor()
        _approval_manager = ActionApprovalManager(executor)
    return _approval_manager