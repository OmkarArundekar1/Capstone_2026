from neo4j import GraphDatabase
import json
import os
from dotenv import load_dotenv

load_dotenv()
driver = GraphDatabase.driver(
    os.getenv('NEO4J_URI'),
    auth=(os.getenv('NEO4J_USERNAME'), os.getenv('NEO4J_PASSWORD'))
)

scenarios = {
    'SESSION-BOUNDARY-001': [
        'CAMP_23FB320A', 'CAMP_1429ADB4', 'CAMP_F91A7652', 'CAMP_066240B7'
    ],
    'SCN-NMAP-001': [
        'CAMP_7331E223', 'CAMP_9669CA33', 'CAMP_B39F5C0A', 'CAMP_947A7084',
        'CAMP_67FCB361', 'CAMP_427A075C', 'CAMP_99EE7A64', 'CAMP_5D691192',
        'CAMP_0CCD0071', 'CAMP_77263583', 'CAMP_BB19A996', 'CAMP_8FF3B37F',
        'CAMP_B3CDBFA1', 'CAMP_86D5837D', 'CAMP_15E98B82', 'CAMP_B177634A',
        'CAMP_1B8E9033'
    ],
    'SESSION-BOUNDARY-002': [
        'CAMP_5DD3F083', 'CAMP_A93237FD', 'CAMP_B12C16D4', 'CAMP_1627943B',
        'CAMP_BB9A0F28', 'CAMP_0E9C0284', 'CAMP_C6E494CF', 'CAMP_75FBEEBC',
        'CAMP_DDBFC6D9', 'CAMP_10407C1A', 'CAMP_D8605E81', 'CAMP_DAE35509',
        'CAMP_E449E81D', 'CAMP_6371D7E5', 'CAMP_436330B7', 'CAMP_F51E9C79',
        'CAMP_38EBD436', 'CAMP_71320238', 'CAMP_2845679C', 'CAMP_835F5335',
        'CAMP_BB680773', 'CAMP_F4E63855', 'CAMP_E8E9F042', 'CAMP_6988F109',
        'CAMP_5A4539E8'
    ]
}

all_campaign_ids = []
for ids in scenarios.values():
    all_campaign_ids.extend(ids)

print(f"Querying {len(all_campaign_ids)} campaigns across 3 scenarios...")

with driver.session() as s:
    result = s.run('''
        MATCH (c:Campaign)-[:HAS_EVENT]->(e:AttackEvent)
        WHERE c.campaign_id IN $ids
        RETURN
            c.campaign_id as campaign_id,
            e.event_id as event_id,
            e.first_seen as first_seen,
            e.attack_id as attack_id,
            e.attacker_ip as attacker_ip,
            e.victim_ip as victim_ip,
            e.investigation_payload as payload
        ORDER BY e.first_seen, e.event_id
