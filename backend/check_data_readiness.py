from neo4j import GraphDatabase
from config import NEO4J_URI, NEO4J_USERNAME, NEO4J_PASSWORD
from datetime import datetime, timedelta
driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USERNAME, NEO4J_PASSWORD))
cutoff_7days = int((datetime.now() - timedelta(days=7)).timestamp())
cutoff_1day = int((datetime.now() - timedelta(days=1)).timestamp())
with driver.session() as session:
    total = session.run('MATCH (c:Campaign) RETURN count(c) as count').single()['count']
    old = session.run('MATCH (c:Campaign) WHERE c.first_seen < $cutoff RETURN count(c) as count', cutoff=cutoff_7days).single()['count']
    recent = session.run('MATCH (c:Campaign) WHERE c.first_seen >= $cutoff RETURN count(c) as count', cutoff=cutoff_1day).single()['count']
    with_outcome = session.run('MATCH (c:Campaign) WHERE c.final_outcome IS NOT NULL RETURN count(c) as count').single()['count']
    with_corr = session.run('MATCH (c:Campaign)-[:CORRELATED_WITH]->() RETURN count(DISTINCT c) as count').single()['count']
print('=' * 60)
print('DATA READINESS CHECK')
print('=' * 60)
print(f'Total campaigns: {total}')
print(f'Campaigns >7 days old: {old}')
print(f'Recent campaigns (<1 day): {recent}')
print(f'Campaigns with final_outcome: {with_outcome}')
print(f'Campaigns with CORRELATED_WITH: {with_corr}')
print('=' * 60)
if old >= 10:
    print('✓ READY: Sufficient historical data for training')
    print(f'  Can collect ~{old * 10} to {old * 20} pairs')
elif total >= 10:
    print('⚠ WAIT: Need campaigns to age (currently {old}/10)')
    print(f'  Wait {7 - (datetime.now() - datetime.fromtimestamp(cutoff_7days)).days} more days')
else:
    print('✗ NOT READY: Insufficient campaigns')
    print(f'  Need {10 - total} more campaigns')
driver.close()