from neo4j_client import driver
with driver.session() as session:
    result = session.run('\n        MATCH (ae:AttackEvent)-[r]->()\n        RETURN type(r) as rel_type, count(*) as count\n    ')
    print('AttackEvent Outgoing Relationships:')
    for record in result:
        print(f"  {record['rel_type']}: {record['count']}")
    result = session.run('\n        MATCH (ae:AttackEvent)\n        WHERE ae.campaign_id IS NOT NULL\n        RETURN count(ae) as count\n    ').single()
    print(f"\nAttackEvents with campaign_id property: {result['count']}")
    result = session.run('\n        MATCH (ae:AttackEvent)\n        WHERE ae.campaign_id IS NOT NULL\n        RETURN ae.campaign_id as campaign_id\n        LIMIT 5\n    ')
    print('\nSample campaign_id values:')
    for record in result:
        print(f"  {record['campaign_id']}")