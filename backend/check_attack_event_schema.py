from neo4j_client import driver
with driver.session() as session:
    result = session.run('\n        MATCH (ae:AttackEvent)\n        RETURN ae LIMIT 1\n    ')
    record = result.single()
    if record:
        ae = record['ae']
        print('AttackEvent properties:')
        for key in sorted(ae.keys()):
            print(f'  {key}: {ae[key]}')
    result = session.run('\n        MATCH (ae:AttackEvent)-[r]->(t)\n        RETURN type(r) as rel_type, labels(t) as target_labels, count(*) as count\n    ')
    print('\nAttackEvent relationships:')
    for record in result:
        print(f"  -{record['rel_type']}-> {record['target_labels']}: {record['count']}")
    result = session.run('\n        MATCH (ae:AttackEvent)\n        RETURN ae.rule_id as rule_id, count(*) as count\n        ORDER BY count DESC\n        LIMIT 15\n    ')
    print('\nTop rule_ids by frequency:')
    for record in result:
        print(f"  {record['rule_id']}: {record['count']}")