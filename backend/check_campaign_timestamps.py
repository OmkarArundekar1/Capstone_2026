from neo4j import GraphDatabase
import os
from dotenv import load_dotenv

load_dotenv()
driver = GraphDatabase.driver(
    os.getenv('NEO4J_URI'),
    auth=(os.getenv('NEO4J_USERNAME'), os.getenv('NEO4J_PASSWORD'))
)

campaign_ids = [
    'CAMP_7331E223', 'CAMP_436330B7', 'CAMP_1429ADB4',
    'CAMP_77263583', 'CAMP_BB19A996',
    'CAMP_5DD3F083', 'CAMP_A93237FD'
]

with driver.session() as s:
    result = s.run('''
        MATCH (c:Campaign)
        WHERE c.campaign_id IN $ids
        RETURN c.campaign_id, c.first_seen, c.last_seen, c.attacker_ip, c.victim_ip
        ORDER BY c.first_seen
