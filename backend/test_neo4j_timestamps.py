from neo4j_client import driver

with driver.session() as session:
    result = session.run("""
        MATCH (c:Campaign)
        RETURN c.campaign_id as id, c.first_seen as first, c.last_seen as last
        LIMIT 1
