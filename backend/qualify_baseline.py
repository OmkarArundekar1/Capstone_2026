import os
import sys
from dotenv import load_dotenv
from neo4j import GraphDatabase
import json
from datetime import datetime, timezone
from collections import defaultdict

load_dotenv()

driver = GraphDatabase.driver(
    os.getenv('NEO4J_URI'),
    auth=(os.getenv('NEO4J_USERNAME'), os.getenv('NEO4J_PASSWORD'))
)

print("=" * 80)
print("BASELINE QUALIFICATION ANALYSIS")
print("=" * 80)
print()

print("1. CAMPAIGN CREATION TIMELINE")
print("-" * 80)
with driver.session() as s:
    result = s.run('''
        MATCH (c:Campaign)
        WHERE c.first_seen IS NOT NULL
        RETURN
            min(c.first_seen) as earliest,
            max(c.first_seen) as latest,
            count(c) as total_campaigns
        MATCH (c:Campaign)
        WHERE c.first_seen IS NOT NULL
        WITH date(c.first_seen) as creation_date
        WITH date.truncate('month', creation_date) as month,
             count(*) as campaign_count
        RETURN month, campaign_count
        ORDER BY month
        MATCH (c:Campaign)
        WHERE c.first_seen IS NOT NULL
        WITH c,
             CASE
                 WHEN c.first_seen < $fix_date THEN 'PRE_FIX'
                 ELSE 'POST_FIX'
             END as period
        RETURN
            period,
            count(c) as campaign_count,
            min(c.first_seen) as earliest,
            max(c.first_seen) as latest
        ORDER BY period
        MATCH (c:Campaign)
        RETURN
            c.attacker_ip as attacker,
            c.victim_ip as victim,
            count(*) as campaign_count
        ORDER BY campaign_count DESC
        LIMIT 20
        MATCH (c:Campaign)
        WHERE c.first_seen IS NOT NULL
        RETURN max(c.first_seen) as latest
            MATCH (c:Campaign)
            WHERE c.first_seen >= $cutoff
            RETURN count(c) as recent_campaigns
        MATCH (c:Campaign)
        RETURN max(c.first_seen) as latest
            MATCH (c:Campaign)
            WHERE c.first_seen >= $fix_date
            RETURN count(c) as count
        MATCH (c:Campaign)
        WHERE c.first_seen IS NOT NULL
        WITH CASE
                 WHEN c.first_seen < $fix_date THEN 'PRE_FIX'
                 ELSE 'POST_FIX'
             END as period,
             count(c) as count
        RETURN period, count
