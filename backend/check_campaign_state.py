from neo4j_client import driver
with driver.session() as session:
    result = session.run('MATCH (c:Campaign) RETURN count(c) as count, c.status as status')
    print('Campaign Status:')
    for record in result:
        print(f"  {record['status']}: {record['count']}")
    result = session.run('\n        MATCH (c:Campaign)\n        RETURN c.attacker_ip as attacker, c.victim_ip as victim,\n               c.status as status, count(*) as count\n        ORDER BY count DESC\n        LIMIT 10\n    ')
    print('\nTop Campaign Host Pairs:')
    for record in result:
        print(f"  {record['attacker']} → {record['victim']}: {record['count']} ({record['status']})")
    result = session.run('MATCH (ae:AttackEvent) RETURN count(ae) as count').single()
    print(f"\nTotal AttackEvents: {result['count']}")
    result = session.run('MATCH (o:Operation) RETURN count(o) as count, o.status as status')
    print('\nOperation Status:')
    for record in result:
        print(f"  {record['status']}: {record['count']}")
    result = session.run('\n        MATCH ()-[r:NEXT_TECHNIQUE]->()\n        RETURN count(r) as total,\n               sum(r.count) as observations\n    ').single()
    print(f"\nTransition Edges: {result['total']} (total observations: {result['observations']})")
    result = session.run('\n        MATCH (a:Technique)-[r:NEXT_TECHNIQUE]->(b:Technique)\n        RETURN a.attack_id as src, b.attack_id as dst,\n               r.count as count, r.confidence as confidence\n        ORDER BY r.count DESC\n        LIMIT 10\n    ')
    print('\nTop Transitions:')
    for record in result:
        print(f"  {record['src']} → {record['dst']}: count={record['count']}, confidence={record['confidence']:.2f}")