from __future__ import annotations
import json
import os
from dataclasses import asdict, dataclass, field
_REGISTRY_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'scenarios.json')

@dataclass
class AttackScenario:
    scenario_id: str
    scenario_name: str
    attacker: str
    victim: str
    attack_family: str
    expected_techniques: list[str]
    expected_threat_status: str
    benign_or_malicious: str
    provenance: str
    evidence_sources: list[str] = field(default_factory=list)
    expected_attribution: str | None = None
    expected_prediction_transition: str | None = None
    execution_command_reference: str | None = None
    notes: str = ''

    def to_dict(self) -> dict:
        return asdict(self)

def load_registry() -> list[AttackScenario]:
    if not os.path.exists(_REGISTRY_PATH):
        return []
    with open(_REGISTRY_PATH) as f:
        raw = json.load(f)
    return [AttackScenario(**s) for s in raw]

def get_scenario(scenario_id: str) -> AttackScenario | None:
    for s in load_registry():
        if s.scenario_id == scenario_id:
            return s
    return None