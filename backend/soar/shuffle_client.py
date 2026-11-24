from __future__ import annotations
import logging
from dataclasses import dataclass
from enum import Enum
from typing import Any
import requests
logger = logging.getLogger(__name__)

class ShuffleTriggerOutcome(str, Enum):
    TRIGGERED = 'triggered'
    SYNCHRONOUS_RESULT = 'synchronous_result'
    NOT_CONFIGURED = 'not_configured'
    AUTH_FAILED = 'auth_failed'
    TIMEOUT = 'timeout'
    ERROR = 'error'

@dataclass
class ShuffleTriggerResult:
    outcome: ShuffleTriggerOutcome
    http_status: int | None = None
    shuffle_execution_id: str | None = None
    output: dict[str, Any] | str | None = None
    error: str | None = None

@dataclass
class ShuffleStatusResult:
    outcome: str
    raw: dict[str, Any] | None = None
    error: str | None = None

class ShuffleClient:

    def __init__(self, webhook_url: str, base_url: str='', api_key: str='', timeout: int=30):
        self.webhook_url = webhook_url
        self.base_url = base_url.rstrip('/') if base_url else ''
        self.api_key = api_key
        self.timeout = timeout

    def trigger(self, payload: dict[str, Any]) -> ShuffleTriggerResult:
        if not self.webhook_url:
            return ShuffleTriggerResult(outcome=ShuffleTriggerOutcome.NOT_CONFIGURED)
        try:
            response = requests.post(self.webhook_url, json=payload, timeout=self.timeout)
        except requests.exceptions.Timeout:
            return ShuffleTriggerResult(outcome=ShuffleTriggerOutcome.TIMEOUT)
        except requests.exceptions.RequestException as e:
            return ShuffleTriggerResult(outcome=ShuffleTriggerOutcome.ERROR, error=str(e))
        if response.status_code in (401, 403):
            return ShuffleTriggerResult(outcome=ShuffleTriggerOutcome.AUTH_FAILED, http_status=response.status_code)
        if response.status_code >= 400:
            return ShuffleTriggerResult(outcome=ShuffleTriggerOutcome.ERROR, http_status=response.status_code, error=f'Shuffle returned HTTP {response.status_code}')
        body: dict[str, Any] | str
        try:
            body = response.json()
        except ValueError:
            body = response.text
        shuffle_execution_id = body.get('execution_id') if isinstance(body, dict) else None
        if isinstance(body, dict) and any((k not in ('execution_id', 'success') for k in body)):
            return ShuffleTriggerResult(outcome=ShuffleTriggerOutcome.SYNCHRONOUS_RESULT, http_status=response.status_code, shuffle_execution_id=shuffle_execution_id, output=body)
        return ShuffleTriggerResult(outcome=ShuffleTriggerOutcome.TRIGGERED, http_status=response.status_code, shuffle_execution_id=shuffle_execution_id, output=body)

    def get_execution_status(self, workflow_id: str, execution_id: str) -> ShuffleStatusResult:
        if not self.base_url or not self.api_key:
            return ShuffleStatusResult(outcome='not_configured')
        url = f'{self.base_url}/api/v1/workflows/{workflow_id}/executions/{execution_id}'
        try:
            response = requests.get(url, headers={'Authorization': f'Bearer {self.api_key}'}, timeout=self.timeout)
        except requests.exceptions.RequestException as e:
            return ShuffleStatusResult(outcome='error', error=str(e))
        if response.status_code in (401, 403):
            return ShuffleStatusResult(outcome='error', error='Authentication failed')
        if response.status_code >= 400:
            return ShuffleStatusResult(outcome='error', error=f'HTTP {response.status_code}')
        try:
            data = response.json()
        except ValueError:
            return ShuffleStatusResult(outcome='error', error='Non-JSON response from Shuffle')
        shuffle_status = str(data.get('status', '')).upper()
        if shuffle_status in ('FINISHED', 'SUCCESS'):
            outcome = 'success'
        elif shuffle_status in ('EXECUTING', 'RUNNING', 'WAITING'):
            outcome = 'running'
        elif shuffle_status:
            outcome = 'failed'
        else:
            outcome = 'error'
        return ShuffleStatusResult(outcome=outcome, raw=data)

    def health_check(self) -> bool:
        if not self.base_url:
            return False
        try:
            response = requests.get(f'{self.base_url}/api/v1/ping', timeout=5)
            return response.status_code < 400
        except requests.exceptions.RequestException:
            return False

def build_default_client() -> ShuffleClient:
    import config
    return ShuffleClient(webhook_url=config.SHUFFLE_WEBHOOK, base_url=config.SHUFFLE_BASE_URL, api_key=config.SHUFFLE_API_KEY)