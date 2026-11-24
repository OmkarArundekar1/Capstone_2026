from neo4j import GraphDatabase
from config import NEO4J_URI, NEO4J_USERNAME, NEO4J_PASSWORD
from datetime import datetime

driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USERNAME, NEO4J_PASSWORD))

with driver.session() as session:
    total = session.run("MATCH (c:Campaign) RETURN count(c) as count").single()["count"]

    closed = session.run(
        "MATCH (c:Campaign) WHERE c.status IN ['INACTIVE', 'CLOSED'] RETURN count(c) as count"
    ).single()["count"]

    with_risk = session.run(
        "MATCH (c:Campaign) WHERE c.risk_score IS NOT NULL RETURN count(c) as count"
    ).single()["count"]

    result = session.run("""
        MATCH (c:Campaign)
        WHERE c.first_seen IS NOT NULL
        WITH c
        ORDER BY c.first_seen
        LIMIT 1
        RETURN c.first_seen as earliest
        MATCH (c:Campaign)
        WHERE c.last_seen IS NOT NULL
        WITH c
        ORDER BY c.last_seen DESC
        LIMIT 1
        RETURN c.last_seen as latest
        MATCH (c1:Campaign), (c2:Campaign)
        WHERE id(c1) < id(c2)
        RETURN count(*) as count
        LIMIT 10000
