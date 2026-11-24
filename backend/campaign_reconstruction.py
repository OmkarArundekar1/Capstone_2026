from __future__ import annotations
from dataclasses import dataclass, field
from neo4j_client import driver
from risk_recalculation import _tps_for

@dataclass
class OrphanCampaignPlan:
    campaign_id: str
    attacker_ip: str
    victim_ip: str
    event_ids: list[str] = field(default_factory=list)
    first_seen: object = None
    last_seen: object = None
    last_technique: str = ''
    risk_score: float = 0.0

def find_orphan_campaign_ids() -> list[str]:
    with driver.session() as session:
        rows = session.run('\n            MATCH (e:AttackEvent)\n            WHERE NOT EXISTS { MATCH (:Campaign)-[:HAS_EVENT]->(e) }\n            RETURN DISTINCT e.campaign_id AS campaign_id\n            ').data()
    return [r['campaign_id'] for r in rows]

def plan_reconstruction(campaign_id: str) -> OrphanCampaignPlan | None:
    with driver.session() as session:
        existing = session.run('MATCH (c:Campaign {campaign_id: $cid}) RETURN c', cid=campaign_id).single()
        if existing is not None:
            return None
        rows = session.run('\n            MATCH (e:AttackEvent {campaign_id: $cid})\n            WHERE NOT EXISTS { MATCH (:Campaign)-[:HAS_EVENT]->(e) }\n            RETURN e.event_id AS event_id, e.attacker_ip AS attacker_ip,\n                   e.victim_ip AS victim_ip, e.attack_id AS attack_id,\n                   e.occurrences AS occurrences, e.first_seen AS first_seen,\n                   e.last_seen AS last_seen\n            ORDER BY e.first_seen\n            ', cid=campaign_id).data()
    if not rows:
        return None
    attackers = {r['attacker_ip'] for r in rows}
    victims = {r['victim_ip'] for r in rows}
    if len(attackers) != 1 or len(victims) != 1:
        raise ValueError(f"{campaign_id}: orphaned events don't share a single attacker/victim pair (attackers={attackers}, victims={victims}) — refusing to guess, needs manual review")
    total_risk = sum((_tps_for(r['attack_id'])[1] * (r['occurrences'] or 0) for r in rows))
    return OrphanCampaignPlan(campaign_id=campaign_id, attacker_ip=attackers.pop(), victim_ip=victims.pop(), event_ids=[r['event_id'] for r in rows], first_seen=rows[0]['first_seen'], last_seen=rows[-1]['last_seen'], last_technique=rows[-1]['attack_id'], risk_score=total_risk)

def apply_reconstruction(plan: OrphanCampaignPlan) -> None:
    with driver.session() as session:
        session.run("\n            MERGE (c:Campaign {campaign_id: $campaign_id})\n            ON CREATE SET\n                c.attacker_ip = $attacker_ip,\n                c.victim_ip = $victim_ip,\n                c.status = 'INACTIVE',\n                c.first_seen = $first_seen,\n                c.last_seen = $last_seen,\n                c.last_technique = $last_technique,\n                c.occurrences = size($event_ids),\n                c.total_tps = $risk_score,\n                c.risk_score = $risk_score,\n                c.reconstructed = true,\n                c.reconstructed_at = datetime()\n\n            WITH c\n            MERGE (a:Attacker {ip: $attacker_ip})\n            MERGE (h:Host {ip: $victim_ip})\n            MERGE (a)-[:LAUNCHED]->(c)\n            MERGE (c)-[:TARGETS]->(h)\n\n            WITH c\n            UNWIND $event_ids AS eid\n            MATCH (e:AttackEvent {event_id: eid})\n            MERGE (c)-[:HAS_EVENT]->(e)\n            ", campaign_id=plan.campaign_id, attacker_ip=plan.attacker_ip, victim_ip=plan.victim_ip, first_seen=plan.first_seen, last_seen=plan.last_seen, last_technique=plan.last_technique, event_ids=plan.event_ids, risk_score=plan.risk_score)

@dataclass
class IntegrityReport:
    total_events: int
    linked_events: int
    orphaned_events: int
    orphan_campaign_ids: list[str]

    @property
    def is_clean(self) -> bool:
        return self.orphaned_events == 0

def check_integrity() -> IntegrityReport:
    with driver.session() as session:
        total = session.run('MATCH (e:AttackEvent) RETURN count(e) AS n').single()['n']
        linked = session.run('MATCH (:Campaign)-[:HAS_EVENT]->(e:AttackEvent) RETURN count(DISTINCT e) AS n').single()['n']
        orphan_ids = [r['campaign_id'] for r in session.run('MATCH (e:AttackEvent) WHERE NOT EXISTS { MATCH (:Campaign)-[:HAS_EVENT]->(e) } RETURN DISTINCT e.campaign_id AS campaign_id')]
    return IntegrityReport(total_events=total, linked_events=linked, orphaned_events=total - linked, orphan_campaign_ids=orphan_ids)

def reconstruct_all_orphans() -> list[OrphanCampaignPlan]:
    applied = []
    for campaign_id in find_orphan_campaign_ids():
        plan = plan_reconstruction(campaign_id)
        if plan is None:
            continue
        apply_reconstruction(plan)
        applied.append(plan)
    return applied