from neo4j_client import driver
with driver.session() as session:
    result = session.run('\n        MATCH (c:Campaign)-[r]->(o:Operation)\n        RETURN type(r) as rel_type, count(*) as count\n    ')
    print('Campaign-Operation Relationships:')
    for record in result:
        print(f"  {record['rel_type']}: {record['count']}")