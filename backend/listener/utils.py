import hashlib
import re
from dataclasses import dataclass
from typing import Any, Optional
from urllib.parse import quote
KEY_VERSION = 'cyukti.v1'
SOURCE_KIND = 'wazuh'
VALID = 'VALID'
MISSING_ID = 'MISSING_ID'
EMPTY_ID = 'EMPTY_ID'
MALFORMED_ID = 'MALFORMED_ID'
MISSING_MANAGER = 'MISSING_MANAGER'
MALFORMED_MANAGER = 'MALFORMED_MANAGER'
_WAZUH_ID = re.compile('[0-9]+\\.[0-9]+')
_MAX_ID_LENGTH = 64
_MAX_ENCODED_MANAGER_LENGTH = 200
_OPERATION = re.compile('[A-Za-z0-9_.-]+')

@dataclass(frozen=True)
class SourceIdentity:
    status: str
    manager: Optional[str] = None
    source_id: Optional[str] = None

    @property
    def valid(self) -> bool:
        return self.status == VALID

    @property
    def source_key(self) -> Optional[str]:
        if not self.valid:
            return None
        return f"{SOURCE_KIND}:{quote(self.manager, safe='-._~')}/{self.source_id}"

    def as_dict(self) -> dict:
        return {'status': self.status, 'manager': self.manager, 'id': self.source_id, 'source_key': self.source_key}

def extract_source_identity(alert: Any) -> SourceIdentity:
    source_id = alert.get('id')
    if source_id is None:
        return SourceIdentity(MISSING_ID)
    if type(source_id) is not str:
        return SourceIdentity(MALFORMED_ID)
    if not source_id:
        return SourceIdentity(EMPTY_ID)
    if len(source_id) > _MAX_ID_LENGTH or not _WAZUH_ID.fullmatch(source_id):
        return SourceIdentity(MALFORMED_ID)
    manager_block = alert.get('manager')
    if manager_block is None:
        return SourceIdentity(MISSING_MANAGER)
    if type(manager_block) is not dict:
        return SourceIdentity(MALFORMED_MANAGER)
    manager = manager_block.get('name')
    if manager is None or manager == '':
        return SourceIdentity(MISSING_MANAGER)
    if type(manager) is not str:
        return SourceIdentity(MALFORMED_MANAGER)
    try:
        encoded = quote(manager, safe='-._~')
    except UnicodeEncodeError:
        return SourceIdentity(MALFORMED_MANAGER)
    if len(encoded) > _MAX_ENCODED_MANAGER_LENGTH:
        return SourceIdentity(MALFORMED_MANAGER)
    return SourceIdentity(VALID, manager, source_id)

def assign_source_identity(alert: dict) -> SourceIdentity:
    identity = extract_source_identity(alert)
    alert['source_identity'] = identity.as_dict()
    alert['alert_id'] = identity.source_key
    return identity

def request_key(source_key: str, operation: str) -> str:
    if type(source_key) is not str or not source_key.startswith(f'{SOURCE_KIND}:'):
        raise ValueError('a request key needs a source key')
    if type(operation) is not str or not _OPERATION.fullmatch(operation):
        raise ValueError('operation must be a plain name')
    return f'{KEY_VERSION}|{source_key}|{operation}'

def source_ref(alert: dict) -> str:
    key = alert.get('alert_id')
    return hashlib.sha256(key.encode('utf-8')).hexdigest()[:12] if key else 'no-identity'

def _first(*values: Any) -> Any:
    for value in values:
        if value:
            return value
    return None

def network_endpoints(alert: dict) -> tuple[Any, Any, bool]:
    data = alert.get('data')
    data = data if isinstance(data, dict) else {}
    source = (data.get('src_ip'), data.get('srcip'), alert.get('src_ip'), alert.get('srcip'))
    destination = (data.get('dest_ip'), data.get('dstip'), alert.get('dest_ip'), alert.get('dstip'))
    conflict = any((len({str(value) for value in group if value}) > 1 for group in (source, destination)))
    return (_first(*source), _first(*destination), conflict)

def content_fingerprint(alert: dict) -> str:
    rule = alert.get('rule')
    agent = alert.get('agent')
    source, destination, _ = network_endpoints(alert)
    raw = '|'.join((str(value) for value in (alert.get('timestamp', ''), rule.get('id', '') if isinstance(rule, dict) else '', agent.get('id', '') if isinstance(agent, dict) else '', source or '', destination or '', alert.get('location', ''))))
    return hashlib.sha256(raw.encode('utf-8', 'surrogatepass')).hexdigest()