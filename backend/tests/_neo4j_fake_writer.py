from __future__ import annotations
import enum
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

class FakeOutcome(enum.Enum):
    COMMITTED = 'COMMITTED'
    NOT_COMMITTED = 'NOT_COMMITTED'
    AMBIGUOUS = 'AMBIGUOUS'

@dataclass(frozen=True)
class FakeWriteResult:
    operation: str
    outcome: Any
    attempts: int
    duration_seconds: float = 0.0
    counters: Optional[dict] = None
    exception_type: Optional[str] = None
    exception_code: Optional[str] = None
    diagnostic: str = ''
    exception: Optional[Exception] = field(default=None, repr=False, compare=False)
    records: Optional[list] = field(default=None, repr=False, compare=False)

class Script:
    COMMIT = 'commit'
    NOT_EXECUTED = 'not_executed'
    FAILED_BEFORE_COMMIT = 'failed_before_commit'
    AMBIGUOUS_APPLIED = 'ambiguous_applied'
    AMBIGUOUS_NOT_APPLIED = 'ambiguous_not_applied'
    RAISES = 'raises'
    RAISES_AFTER_APPLYING = 'raises_after_applying'
    INTERRUPTED = 'interrupted'
    UNKNOWN_OUTCOME = 'unknown_outcome'
    NO_OUTCOME = 'no_outcome'

class FakeWriter:

    def __init__(self, *script: str, default: str=Script.COMMIT, during: Optional[Callable[[], None]]=None, effect: Optional[Callable[[str, Any], None]]=None) -> None:
        self.script = list(script)
        self.default = default
        self.during = during
        self.effect = effect
        self.calls: list = []
        self.effects: list = []

    def _apply(self, operation: str, statements: Any) -> None:
        self.effects.append((operation, statements))
        if self.effect is not None:
            self.effect(operation, statements)

    def __call__(self, operation: str, statements: Any, *, limits: Any) -> FakeWriteResult:
        self.calls.append((operation, statements, limits))
        step = self.script.pop(0) if self.script else self.default
        if self.during is not None:
            self.during()
        if step == Script.COMMIT:
            self._apply(operation, statements)
            return FakeWriteResult(operation, FakeOutcome.COMMITTED, 1, counters={'nodes_created': 1})
        if step == Script.NOT_EXECUTED:
            return FakeWriteResult(operation, FakeOutcome.NOT_COMMITTED, 0, exception_type='ServiceUnavailable', diagnostic='ServiceUnavailable: failure before any query was submitted', exception=RuntimeError('SECRET-CANARY exception text'))
        if step == Script.FAILED_BEFORE_COMMIT:
            return FakeWriteResult(operation, FakeOutcome.NOT_COMMITTED, 1, exception_type='TransientError', exception_code='Neo.TransientError.Test', diagnostic='TransientError: failure before commit', exception=RuntimeError('SECRET-CANARY exception text'))
        if step in (Script.AMBIGUOUS_APPLIED, Script.AMBIGUOUS_NOT_APPLIED):
            if step == Script.AMBIGUOUS_APPLIED:
                self._apply(operation, statements)
            return FakeWriteResult(operation, FakeOutcome.AMBIGUOUS, 1, exception_type='IncompleteCommit', diagnostic='IncompleteCommit: connection lost during commit', exception=RuntimeError('SECRET-CANARY exception text'))
        if step == Script.RAISES:
            raise RuntimeError('SECRET-CANARY writer failed')
        if step == Script.RAISES_AFTER_APPLYING:
            self._apply(operation, statements)
            raise RuntimeError('SECRET-CANARY writer failed after applying')
        if step == Script.INTERRUPTED:
            raise KeyboardInterrupt()
        if step == Script.UNKNOWN_OUTCOME:
            return FakeWriteResult(operation, type('Odd', (), {'value': 'PROBABLY_FINE'})(), 1)
        if step == Script.NO_OUTCOME:
            return None
        raise AssertionError(f'unknown script step {step}')