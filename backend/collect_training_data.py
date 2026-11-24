import numpy as np
import logging
from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Dict, Tuple
from neo4j import GraphDatabase
from dataclasses import asdict
import sys

sys.path.append(str(Path(__file__).parent))

from config import NEO4J_URI, NEO4J_USERNAME, NEO4J_PASSWORD
from campaign_feature_engine import CampaignFeatureEngine
from campaign_decision_engine import CampaignDecisionEngine

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class TrainingDataCollector:
    def __init__(self):
        self.driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USERNAME, NEO4J_PASSWORD))
        self.feature_engine = CampaignFeatureEngine()
        self.decision_engine = CampaignDecisionEngine()

    def close(self):
        self.driver.close()

    def get_historical_campaigns(self, limit: int = 1000) -> List[Dict]:
        query = """
        MATCH (c:Campaign)
        WHERE c.status IN ['INACTIVE', 'CLOSED']
        RETURN c.campaign_id as campaign_id,
               c.first_seen as first_seen,
               c.last_seen as last_seen,
               c.status as status
        ORDER BY c.first_seen DESC
        LIMIT $limit
        MATCH (c:Campaign {campaign_id: $campaign_id})
        WITH c,
             c.status as status,
             c.last_technique as last_technique,
             c.attacker_ip as attacker_ip,
             c.victim_ip as victim_ip,
             c.risk_level as risk_level
        OPTIONAL MATCH (c)-[:CORRELATED_WITH]->(related:Campaign)
        WITH c, status, last_technique, attacker_ip, victim_ip, risk_level,
             count(related) as correlation_count
        OPTIONAL MATCH (c)-[:ATTRIBUTED_TO]->(actor:ThreatActor)
        RETURN status, last_technique, attacker_ip, victim_ip, risk_level,
               correlation_count,
               actor.name as attributed_actor
        MATCH (c1:Campaign {campaign_id: $id1})
        MATCH (c2:Campaign {campaign_id: $id2})
        RETURN exists((c1)-[:CORRELATED_WITH]-(c2)) as correlated
        MATCH (c1:Campaign {campaign_id: $id1})-[:ATTRIBUTED_TO]->(actor:ThreatActor)
        MATCH (c2:Campaign {campaign_id: $id2})-[:ATTRIBUTED_TO]->(actor)
        RETURN count(actor) as count
