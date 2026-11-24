from neo4j_client import driver

print("=" * 80)
print("Neo4j Schema Inspection")
print("=" * 80)

with driver.session() as session:
    print("\n1. All Relationship Types in Database:")
    print("-" * 80)
    result = session.run("CALL db.relationshipTypes()")
    rel_types = [record[0] for record in result]
    for rel in sorted(rel_types):
        print(f"  - {rel}")

    print("\n2. Campaign Node Properties:")
    print("-" * 80)
    result = session.run("""
        MATCH (c:Campaign)
        WITH keys(c) as props
        RETURN DISTINCT props
        LIMIT 1
        MATCH (e:AttackEvent)
        WITH keys(e) as props
        RETURN DISTINCT props
        LIMIT 1
        MATCH (c:Campaign)-[r]->(e:AttackEvent)
        RETURN type(r) as rel_type, count(*) as count
        MATCH (e:AttackEvent)-[r]->(c:Campaign)
        RETURN type(r) as rel_type, count(*) as count
        MATCH (c:Campaign)
        OPTIONAL MATCH (c)-[r1]->(e:AttackEvent)
        OPTIONAL MATCH (e2:AttackEvent)-[r2]->(c)
        WITH c, count(DISTINCT e) as outgoing_count, count(DISTINCT e2) as incoming_count,
             type(r1) as out_rel, type(r2) as in_rel
        WHERE outgoing_count > 0 OR incoming_count > 0
        RETURN c.campaign_id as id, outgoing_count, incoming_count,
               out_rel, in_rel
        LIMIT 1
        MATCH (c:Campaign {campaign_id: 'CAMP_427A075C'})
        OPTIONAL MATCH path = (c)-[*1..2]-(e:AttackEvent)
        RETURN count(DISTINCT e) as related_events,
               [rel in relationships(path) | type(rel)] as rel_types
        LIMIT 1
