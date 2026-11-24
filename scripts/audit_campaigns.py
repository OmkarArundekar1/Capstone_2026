import os
import sys
from collections import Counter
BACKEND = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'backend')
sys.path.insert(0, BACKEND)
os.chdir(BACKEND)
from neo4j_client import driver

def main():
    with driver.session() as s:
        campaigns = s.run('\n            MATCH (c:Campaign)\n            OPTIONAL MATCH (a:Attacker)-[:LAUNCHED]->(c)\n            OPTIONAL MATCH (c)-[:TARGETS]->(h:Host)\n            OPTIONAL MATCH (c)-[:HAS_EVENT]->(e:AttackEvent)\n            OPTIONAL MATCH (e)-[:MATCHES]->(t:Technique)\n            WITH c, a, h, count(DISTINCT e) AS event_count,\n                 collect(DISTINCT t.attack_id) AS techniques\n            RETURN c.campaign_id AS campaign_id, c.status AS status,\n                   c.risk_score AS risk_score, c.first_seen AS first_seen,\n                   c.last_seen AS last_seen, a.ip AS attacker, h.ip AS victim,\n                   event_count, techniques\n            ORDER BY c.first_seen\n        ').data()
        print(f'=== {len(campaigns)} campaigns ===\n')
        event_counts = []
        technique_counts = []
        all_techniques = Counter()
        durations = []
        risk_scores = []
        attackers = Counter()
        victims = Counter()
        statuses = Counter()
        zero_event_campaigns = []
        zero_technique_campaigns = []
        for c in campaigns:
            n_events = c['event_count'] or 0
            techs = [t for t in c['techniques'] or [] if t]
            n_techs = len(techs)
            event_counts.append(n_events)
            technique_counts.append(n_techs)
            all_techniques.update(techs)
            risk_scores.append(c['risk_score'] or 0.0)
            attackers[c['attacker']] += 1
            victims[c['victim']] += 1
            statuses[c['status']] += 1
            if c['first_seen'] and c['last_seen']:
                duration_s = (c['last_seen'].to_native() - c['first_seen'].to_native()).total_seconds()
                durations.append(duration_s)
            else:
                duration_s = None
            if n_events == 0:
                zero_event_campaigns.append(c['campaign_id'])
            if n_techs == 0:
                zero_technique_campaigns.append(c['campaign_id'])
            print(f"{c['campaign_id']:16s} status={c['status']:9s} risk={c['risk_score']:6.1f} events={n_events:3d} techniques={n_techs:2d} duration={(duration_s if duration_s is not None else '?'):>8} attacker={c['attacker']} victim={c['victim']}")
        print('\n=== Aggregate stats ===')
        print(f'Campaign statuses: {dict(statuses)}')
        print(f'Distinct attackers: {len(attackers)} -> {dict(attackers)}')
        print(f'Distinct victims: {len(victims)} -> {dict(victims)}')
        print(f'Events per campaign: min={min(event_counts)}, max={max(event_counts)}, mean={sum(event_counts) / len(event_counts):.1f}')
        print(f'Techniques per campaign: min={min(technique_counts)}, max={max(technique_counts)}, mean={sum(technique_counts) / len(technique_counts):.1f}')
        print(f'Campaigns with 0 events: {len(zero_event_campaigns)} -> {zero_event_campaigns}')
        print(f'Campaigns with 0 techniques: {len(zero_technique_campaigns)} -> {zero_technique_campaigns}')
        print(f'Risk score range: min={min(risk_scores):.1f}, max={max(risk_scores):.1f}, mean={sum(risk_scores) / len(risk_scores):.1f}')
        if durations:
            print(f'Duration (s): min={min(durations):.1f}, max={max(durations):.1f}, mean={sum(durations) / len(durations):.1f}')
        print(f'\nUnique techniques observed across all campaigns: {len(all_techniques)}')
        print(f'Technique frequency (all): {dict(all_techniques.most_common())}')
        print('\n=== Label availability ===')
        has_attribution = s.run('\n            MATCH (c:Campaign)-[:RESEMBLES]->(other) RETURN count(DISTINCT c) AS n\n        ').single()['n']
        print(f'Campaigns with a stored RESEMBLES (attribution) relationship: {has_attribution} / {len(campaigns)}')
        has_prediction = s.run('\n            MATCH (c:Campaign)-[:LIKELY_NEXT]->(t) RETURN count(DISTINCT c) AS n\n        ').single()['n']
        print(f'Campaigns with a stored LIKELY_NEXT prediction: {has_prediction} / {len(campaigns)}')
        print("No stored 'severity' *label* field exists on Campaign — severity/malicious labels are not ground truth, they'd have to be derived from risk_score or assigned manually.")
if __name__ == '__main__':
    main()