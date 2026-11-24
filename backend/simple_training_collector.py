import numpy as np
import logging
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Tuple
from neo4j import GraphDatabase
import sys

sys.path.append(str(Path(__file__).parent))

from config import NEO4J_URI, NEO4J_USERNAME, NEO4J_PASSWORD

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class SimpleTrainingCollector:
    def __init__(self):
        self.driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USERNAME, NEO4J_PASSWORD))

    def close(self):
        self.driver.close()

    def get_campaigns(self, limit: int = 200) -> List[str]:
        query = """
        MATCH (c:Campaign)
        WHERE c.status IN ['INACTIVE', 'CLOSED']
        RETURN c.campaign_id as campaign_id
        ORDER BY c.first_seen DESC
        LIMIT $limit
        MATCH (c1:Campaign {campaign_id: $id1})
        MATCH (c2:Campaign {campaign_id: $id2})

        OPTIONAL MATCH (c1)-[:HAS_TECHNIQUE]->(t1:Technique)
        WITH c1, c2, collect(DISTINCT t1.attack_id) as techniques1

        OPTIONAL MATCH (c2)-[:HAS_TECHNIQUE]->(t2:Technique)
        WITH c1, c2, techniques1, collect(DISTINCT t2.attack_id) as techniques2

        WITH c1, c2, techniques1, techniques2,
             [t IN techniques1 WHERE t IN techniques2] as common_techniques

        WITH c1, c2, techniques1, techniques2, common_techniques,
             CASE
                WHEN size(techniques1) + size(techniques2) > 0
                THEN toFloat(size(common_techniques) * 2) / (size(techniques1) + size(techniques2))
                ELSE 0.0
             END as ioc_overlap

        WITH c1, c2, ioc_overlap,
             abs(c1.first_seen.epochSeconds - c2.last_seen.epochSeconds) as time_gap_seconds

        WITH c1, c2, ioc_overlap, time_gap_seconds,
             CASE
                WHEN time_gap_seconds < 3600 THEN 1.0
                WHEN time_gap_seconds < 86400 THEN 0.5
                ELSE 0.1
             END as temporal_overlap

        OPTIONAL MATCH (c1)-[:HAS_IP]->(ip:IP)<-[:HAS_IP]-(c2)
        WITH c1, c2, ioc_overlap, temporal_overlap, count(DISTINCT ip) as shared_ips

        WITH c1, c2, ioc_overlap, temporal_overlap,
             CASE
                WHEN shared_ips > 0 THEN 1.0
                WHEN c1.attacker_ip = c2.attacker_ip THEN 0.8
                ELSE 0.0
             END as attacker_overlap

        RETURN c1.campaign_id as id1,
               c2.campaign_id as id2,
               ioc_overlap,
               temporal_overlap,
               attacker_overlap,
               c1.risk_score as risk1,
               c2.risk_score as risk2,
               c1.occurrences as occ1,
               c2.occurrences as occ2
        MATCH (c1:Campaign {campaign_id: $id1})
        MATCH (c2:Campaign {campaign_id: $id2})

        WITH c1, c2,
             c1.attacker_ip = c2.attacker_ip as same_attacker,
             c1.victim_ip = c2.victim_ip as same_victim

        OPTIONAL MATCH (c1)-[:HAS_TECHNIQUE]->(t:Technique)<-[:HAS_TECHNIQUE]-(c2)
        WITH c1, c2, same_attacker, same_victim, count(t) as shared_techniques

        OPTIONAL MATCH (c1)-[:ATTRIBUTED_TO]->(:ThreatActor)<-[:ATTRIBUTED_TO]-(c2)
        WITH c1, c2, same_attacker, same_victim, shared_techniques, count(*) as same_actor

        OPTIONAL MATCH (c1)-[:CORRELATED_WITH]-(c2)
        WITH same_attacker, same_victim, shared_techniques, same_actor, count(*) as explicit_corr

        RETURN same_attacker, same_victim, shared_techniques, same_actor, explicit_corr
