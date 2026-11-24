from __future__ import annotations
import json
from dataclasses import dataclass, field
from config import TPS_MAP
from mitre_mapper import MITRE_TO_STAGE
from neo4j_client import driver

def _tps_for(attack_id: str) -> tuple[str, int]:
    stage = MITRE_TO_STAGE.get(attack_id, 'Unknown')
    return (stage, TPS_MAP.get(stage, 0))

@dataclass
class EventDelta:
    event_id: str
    campaign_id: str
    attack_id: str
    occurrences: int
    old_stage: str
    new_stage: str
    old_tps: int
    new_tps: int

@dataclass
class CampaignDelta:
    campaign_id: str
    old_risk_score: float
    new_risk_score: float
    events: list[EventDelta] = field(default_factory=list)

def compute_deltas() -> list[CampaignDelta]:
    with driver.session() as session:
        rows = session.run('\n            MATCH (c:Campaign)-[:HAS_EVENT]->(e:AttackEvent)\n            RETURN c.campaign_id AS campaign_id, c.risk_score AS old_campaign_risk,\n                   e.event_id AS event_id, e.attack_id AS attack_id,\n                   e.occurrences AS occurrences, e.stage AS old_stage, e.tps AS old_tps\n            ORDER BY c.campaign_id\n            ').data()
    by_campaign: dict[str, CampaignDelta] = {}
    for row in rows:
        cid = row['campaign_id']
        if cid not in by_campaign:
            by_campaign[cid] = CampaignDelta(campaign_id=cid, old_risk_score=row['old_campaign_risk'] or 0.0, new_risk_score=0.0)
        occurrences = row['occurrences'] or 0
        new_stage, tps_per_occurrence = _tps_for(row['attack_id'])
        new_event_tps = tps_per_occurrence * occurrences
        by_campaign[cid].events.append(EventDelta(event_id=row['event_id'], campaign_id=cid, attack_id=row['attack_id'], occurrences=occurrences, old_stage=row['old_stage'], new_stage=new_stage, old_tps=row['old_tps'] or 0, new_tps=new_event_tps))
    for delta in by_campaign.values():
        delta.new_risk_score = sum((e.new_tps for e in delta.events))
    return sorted(by_campaign.values(), key=lambda d: d.campaign_id)

def backup_current_values(path: str) -> None:
    with driver.session() as session:
        events = session.run('MATCH (e:AttackEvent) RETURN e.event_id AS event_id, e.stage AS stage, e.tps AS tps').data()
        campaigns = session.run('MATCH (c:Campaign) RETURN c.campaign_id AS campaign_id, c.risk_score AS risk_score, c.total_tps AS total_tps').data()
        techniques = session.run('MATCH (t:Technique) WHERE t.total_tps IS NOT NULL RETURN t.attack_id AS attack_id, t.total_tps AS total_tps').data()
    with open(path, 'w') as f:
        json.dump({'events': events, 'campaigns': campaigns, 'techniques': techniques}, f, indent=2)

def apply_recalculation(deltas: list[CampaignDelta]) -> None:
    with driver.session() as session:
        for delta in deltas:
            for e in delta.events:
                session.run('MATCH (ev:AttackEvent {event_id: $event_id}) SET ev.stage = $stage, ev.tps = $tps', event_id=e.event_id, stage=e.new_stage, tps=e.new_tps)
            session.run('MATCH (c:Campaign {campaign_id: $campaign_id}) SET c.risk_score = $risk_score, c.total_tps = $risk_score', campaign_id=delta.campaign_id, risk_score=delta.new_risk_score)
        session.run('\n            MATCH (t:Technique)<-[:MATCHES]-(e:AttackEvent)\n            WITH t, sum(e.tps) AS corrected_total\n            SET t.total_tps = corrected_total\n            ')