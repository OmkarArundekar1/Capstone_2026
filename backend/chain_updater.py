from neo4j_client import driver

def update_attack_chain(campaign_id, current_technique, transition):
    if transition is None:
        raise ValueError('update_attack_chain() requires the TransitionContext returned by CampaignManager.get_or_create_campaign_with_transition(); the previous technique cannot be recovered from Campaign.last_technique.')
    if transition.campaign_id != campaign_id or transition.current_technique != current_technique:
        raise ValueError(f'TransitionContext mismatch: got campaign={transition.campaign_id!r} technique={transition.current_technique!r}, expected campaign={campaign_id!r} technique={current_technique!r}')
    previous = transition.previous_technique
    print('\n========== CHAIN DEBUG ==========')
    print(f'Campaign : {campaign_id}')
    print(f'Previous : {previous}')
    print(f'Current  : {current_technique}')
    print(f"Segment  : {('start' if transition.segment_start else 'continuation')}")
    print('=================================\n')
    if transition.segment_start:
        print('[CHAIN] New/Reopened campaign. Skipping first transition.')
        return None
    if previous is None:
        print(f'[CHAIN] Starting new attack chain with {current_technique}')
        return None
    if previous == current_technique:
        print(f'[CHAIN] Duplicate technique ignored: {current_technique}')
        return None
    try:
        with driver.session() as session:
            print(f'[CHAIN] Learning {previous} -> {current_technique}')
            session.run('\n                MATCH (a:Technique {attack_id: $src})\n                MATCH (b:Technique {attack_id: $dst})\n\n                MERGE (a)-[r:NEXT_TECHNIQUE]->(b)\n\n                ON CREATE SET\n                    r.count = 1,\n                    r.created_at = datetime(),\n                    r.last_seen = datetime(),\n                    r.confidence = 1.0\n\n                ON MATCH SET\n                    r.count = r.count + 1,\n                    r.last_seen = datetime()\n                ', src=previous, dst=current_technique)
            session.run('\n                MATCH (a:Technique {attack_id: $src})-[r:NEXT_TECHNIQUE]->()\n\n                WITH collect(r) AS rels,\n                     sum(r.count) AS total\n\n                UNWIND rels AS rel\n\n                SET rel.confidence =\n                    CASE\n                        WHEN total = 0 THEN 0.0\n                        ELSE toFloat(rel.count) / total\n                    END\n                ', src=previous)
            transition_row = session.run('\n                MATCH (a:Technique {attack_id: $src})\n                      -[r:NEXT_TECHNIQUE]->\n                      (b:Technique {attack_id: $dst})\n\n                RETURN\n                    r.count AS count,\n                    r.confidence AS confidence,\n                    r.created_at AS created_at,\n                    r.last_seen AS last_seen\n                ', src=previous, dst=current_technique).single()
            if transition_row is None:
                print(f'[CHAIN WARNING] {previous} -> {current_technique} not stored: a Technique node is missing.')
                return None
            print('\n========== TRANSITION LEARNED ==========')
            print(f'Source      : {previous}')
            print(f'Destination : {current_technique}')
            print(f"Count       : {transition_row['count']}")
            print(f"Confidence  : {transition_row['confidence']:.2f}")
            print(f"Created     : {transition_row['created_at']}")
            print(f"Last Seen   : {transition_row['last_seen']}")
            print('========================================')
            return (previous, current_technique)
    except Exception as e:
        print(f'[CHAIN ERROR] {e}')
        return None