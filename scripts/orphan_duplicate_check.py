import os
import sys
BACKEND = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'backend')
sys.path.insert(0, BACKEND)
os.chdir(BACKEND)
from neo4j_client import driver
with driver.session() as s:
    print('=== Do any orphan fingerprints ALSO appear on a linked (real-campaign) event? ===')
    rows = s.run('\n        MATCH (orphan:AttackEvent)\n        WHERE NOT EXISTS { MATCH (:Campaign)-[:HAS_EVENT]->(orphan) }\n        WITH DISTINCT orphan.fingerprint AS fp\n        MATCH (linked:AttackEvent {fingerprint: fp})\n        WHERE EXISTS { MATCH (:Campaign)-[:HAS_EVENT]->(linked) }\n        RETURN fp, linked.event_id AS linked_event_id, linked.campaign_id AS linked_campaign_id,\n               linked.first_seen AS linked_first_seen, linked.occurrences AS linked_occurrences\n        ').data()
    print(f'orphan fingerprints that ALSO exist on a linked event: {len(rows)}')
    for r in rows:
        print(r)
    print('\n=== Total distinct orphan fingerprints ===')
    n = s.run('\n        MATCH (orphan:AttackEvent)\n        WHERE NOT EXISTS { MATCH (:Campaign)-[:HAS_EVENT]->(orphan) }\n        RETURN count(DISTINCT orphan.fingerprint) AS n\n        ').single()['n']
    print('distinct orphan fingerprints:', n)
    print('\n=== Does attacker 192.168.56.106 -> pes1ug23cs411-VirtualBox have ANY linked/real campaign at all? ===')
    rows2 = s.run("\n        MATCH (c:Campaign {attacker_ip: '192.168.56.106', victim_ip: 'pes1ug23cs411-VirtualBox'})\n        RETURN c.campaign_id AS campaign_id, c.first_seen AS first_seen, c.last_seen AS last_seen,\n               c.status AS status\n        ORDER BY c.first_seen\n        ").data()
    for r in rows2:
        print(r)