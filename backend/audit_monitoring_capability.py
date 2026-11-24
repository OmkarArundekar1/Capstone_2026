import os
import sys
from dotenv import load_dotenv
from neo4j import GraphDatabase
import json

load_dotenv()

driver = GraphDatabase.driver(
    os.getenv('NEO4J_URI'),
    auth=(os.getenv('NEO4J_USERNAME'), os.getenv('NEO4J_PASSWORD'))
)

print("=" * 80)
print("PHASE B.2 MONITORING CAPABILITY AUDIT")
print("=" * 80)
print()

print("1. CAMPAIGN NODE PROPERTIES (sample from 3 campaigns)")
print("-" * 80)
with driver.session() as s:
    result = s.run('''
        MATCH (c:Campaign)
        RETURN c
        LIMIT 3
        MATCH (e:AttackEvent)
        RETURN e
        LIMIT 3
        MATCH (c:Campaign)
        OPTIONAL MATCH (c)-[:HAS_EVENT]->(e:AttackEvent)
        WITH c, count(e) as event_count
        RETURN
            count(c) as total_campaigns,
            count(DISTINCT c.attacker_ip + '→' + c.victim_ip) as unique_pairs,
            sum(event_count) as total_events,
            avg(event_count) as avg_events_per_campaign,
            min(event_count) as min_events,
            max(event_count) as max_events,
            count(CASE WHEN c.status = 'ACTIVE' THEN 1 END) as active_campaigns,
            count(CASE WHEN c.status = 'INACTIVE' THEN 1 END) as inactive_campaigns,
            count(CASE WHEN c.reopened_count > 0 THEN 1 END) as reopened_campaigns,
            avg(c.reopened_count) as avg_reopened_count
        MATCH (c:Campaign)
        WITH c.attacker_ip as attacker, c.victim_ip as victim, count(c) as campaign_count
        WHERE campaign_count > 1
        RETURN attacker, victim, campaign_count
        ORDER BY campaign_count DESC
        LIMIT 10
        MATCH (c:Campaign)
        WHERE c.first_seen IS NOT NULL AND c.last_seen IS NOT NULL
        WITH c,
             duration.between(c.first_seen, c.last_seen) as duration
        RETURN
            min(c.first_seen) as earliest_campaign,
            max(c.last_seen) as latest_campaign,
            avg(duration.seconds) as avg_duration_seconds,
            min(duration.seconds) as min_duration_seconds,
            max(duration.seconds) as max_duration_seconds
        MATCH (e:AttackEvent)
        RETURN
            count(e) as total_events,
            count(e.investigation_payload) as events_with_payload,
            count(CASE WHEN e.investigation_payload IS NOT NULL AND size(e.investigation_payload) > 100 THEN 1 END) as events_with_substantial_payload
            MATCH (e:AttackEvent)
            WHERE e.investigation_payload IS NOT NULL
            RETURN e.investigation_payload as payload
            LIMIT 1
