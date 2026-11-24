from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum

class ResponseState(str, Enum):
    OBSERVE = 'OBSERVE'
    INVESTIGATE = 'INVESTIGATE'
    RECOMMEND = 'RECOMMEND'
    CONTAIN = 'CONTAIN'
    VERIFY = 'VERIFY'
    VERIFIED = 'VERIFIED'
    FAILED = 'FAILED'
    ROLLED_BACK = 'ROLLED_BACK'
    EXPIRED = 'EXPIRED'
_VALID_TRANSITIONS: dict[ResponseState, frozenset[ResponseState]] = {ResponseState.OBSERVE: frozenset({ResponseState.INVESTIGATE}), ResponseState.INVESTIGATE: frozenset({ResponseState.RECOMMEND, ResponseState.OBSERVE}), ResponseState.RECOMMEND: frozenset({ResponseState.CONTAIN, ResponseState.OBSERVE}), ResponseState.CONTAIN: frozenset({ResponseState.VERIFY, ResponseState.FAILED}), ResponseState.VERIFY: frozenset({ResponseState.VERIFIED, ResponseState.FAILED}), ResponseState.VERIFIED: frozenset({ResponseState.ROLLED_BACK, ResponseState.EXPIRED}), ResponseState.FAILED: frozenset(), ResponseState.ROLLED_BACK: frozenset(), ResponseState.EXPIRED: frozenset()}

class InvalidStateTransition(Exception):

    def __init__(self, current: ResponseState, target: ResponseState):
        super().__init__(f'Illegal response-state transition {current.value} -> {target.value}. Valid targets from {current.value}: {sorted((s.value for s in _VALID_TRANSITIONS.get(current, frozenset())))}')
        self.current = current
        self.target = target

@dataclass
class StateTransitionRecord:
    from_state: ResponseState
    to_state: ResponseState
    timestamp: str
    evidence: str = ''

    def to_dict(self) -> dict:
        return {'from_state': self.from_state.value, 'to_state': self.to_state.value, 'timestamp': self.timestamp, 'evidence': self.evidence}

@dataclass
class ResponseStateMachine:
    current_state: ResponseState = ResponseState.OBSERVE
    history: list[StateTransitionRecord] = field(default_factory=list)

    def transition(self, target: ResponseState, evidence: str='') -> StateTransitionRecord:
        allowed = _VALID_TRANSITIONS.get(self.current_state, frozenset())
        if target not in allowed:
            raise InvalidStateTransition(self.current_state, target)
        if target in (ResponseState.VERIFY, ResponseState.VERIFIED) and (not evidence):
            raise ValueError(f'Transition to {target.value} requires non-empty evidence -- a state change into verification territory can never be evidence-free.')
        record = StateTransitionRecord(from_state=self.current_state, to_state=target, timestamp=datetime.now(timezone.utc).isoformat(), evidence=evidence)
        self.history.append(record)
        self.current_state = target
        return record

    def is_terminal(self) -> bool:
        return not _VALID_TRANSITIONS.get(self.current_state, frozenset())