import json
from collections import Counter, defaultdict
from datetime import datetime
from neo4j_client import driver

def collect_dataset_inventory():
    with driver.session() as session:
        result = session.run('\n            MATCH (ae:AttackEvent)\n            RETURN ae.event_id as event_id,\n                   ae.campaign_id as campaign_id,\n                   ae.rule_id as rule_id,\n                   ae.attack_id as attack_id,\n                   ae.attacker_ip as attacker_ip,\n                   ae.victim_ip as victim_ip,\n                   ae.first_seen as first_seen,\n                   ae.investigation_payload as payload\n            ORDER BY ae.first_seen\n        ')
        events = []
        rule_counts = Counter()
        technique_counts = Counter()
        host_pairs = set()
        attackers = set()
        victims = set()
        unknown_count = 0
        timestamps = []
        for record in result:
            event = {'event_id': record['event_id'], 'campaign_id': record['campaign_id'], 'rule_id': record['rule_id'], 'attack_id': record['attack_id'], 'attacker_ip': record['attacker_ip'], 'victim_ip': record['victim_ip'], 'first_seen': record['first_seen']}
            events.append(event)
            rule_counts[record['rule_id']] += 1
            if record['attack_id']:
                technique_counts[record['attack_id']] += 1
            else:
                unknown_count += 1
            host_pairs.add((record['attacker_ip'], record['victim_ip']))
            attackers.add(record['attacker_ip'])
            victims.add(record['victim_ip'])
            if record['first_seen']:
                timestamps.append(record['first_seen'])
        result = session.run('\n            MATCH (c:Campaign)\n            RETURN c.campaign_id as campaign_id,\n                   c.status as status,\n                   c.attacker_ip as attacker_ip,\n                   c.victim_ip as victim_ip,\n                   c.first_seen as first_seen,\n                   c.last_seen as last_seen,\n                   c.reopened_count as reopened_count\n            ORDER BY c.first_seen\n        ')
        campaigns = []
        campaign_status = Counter()
        campaign_host_pairs = Counter()
        campaign_sizes = []
        for record in result:
            campaign = {'campaign_id': record['campaign_id'], 'status': record['status'], 'attacker_ip': record['attacker_ip'], 'victim_ip': record['victim_ip'], 'first_seen': record['first_seen'], 'last_seen': record['last_seen'], 'reopened_count': record['reopened_count'] or 0}
            campaigns.append(campaign)
            campaign_status[record['status']] += 1
            campaign_host_pairs[record['attacker_ip'], record['victim_ip']] += 1
        result = session.run('\n            MATCH (ae:AttackEvent)\n            WITH ae.campaign_id as campaign_id, count(*) as size\n            RETURN campaign_id, size\n            ORDER BY size DESC\n        ')
        for record in result:
            campaign_sizes.append(record['size'])
        result = session.run('\n            MATCH (o:Operation)\n            RETURN o.operation_id as operation_id,\n                   o.status as status\n        ')
        operations = []
        operation_status = Counter()
        for record in result:
            operations.append({'operation_id': record['operation_id'], 'status': record['status']})
            operation_status[record['status']] += 1
        result = session.run('\n            MATCH (c:Campaign)-[r]->(o:Operation)\n            RETURN o.operation_id as operation_id, count(c) as campaign_count\n            ORDER BY campaign_count DESC\n        ')
        operation_campaign_counts = []
        for record in result:
            operation_campaign_counts.append({'operation_id': record['operation_id'], 'campaign_count': record['campaign_count']})
        result = session.run('\n            MATCH ()-[r:NEXT_TECHNIQUE]->()\n            RETURN count(r) as edge_count, sum(r.count) as total_observations\n        ').single()
        transition_edges = result['edge_count']
        transition_observations = result['total_observations']
        time_range = None
        if timestamps:
            timestamps_sorted = sorted([t for t in timestamps if t])
            if timestamps_sorted:
                time_range = {'start': timestamps_sorted[0].isoformat(), 'end': timestamps_sorted[-1].isoformat(), 'duration_hours': (timestamps_sorted[-1] - timestamps_sorted[0]).days * 24 + (timestamps_sorted[-1] - timestamps_sorted[0]).seconds / 3600}
        return {'dataset_id': 'neo4j_308_events', 'collection_timestamp': datetime.now().isoformat(), 'events': {'total': len(events), 'unique_rules': len(rule_counts), 'unique_techniques': len(technique_counts), 'unknown_techniques': unknown_count, 'unique_host_pairs': len(host_pairs), 'unique_attackers': len(attackers), 'unique_victims': len(victims), 'top_rules': rule_counts.most_common(10), 'top_techniques': technique_counts.most_common(10)}, 'campaigns': {'total': len(campaigns), 'by_status': dict(campaign_status), 'unique_host_pairs': len(campaign_host_pairs), 'singleton_count': sum((1 for s in campaign_sizes if s == 1)), 'size_distribution': {'min': min(campaign_sizes) if campaign_sizes else 0, 'max': max(campaign_sizes) if campaign_sizes else 0, 'mean': sum(campaign_sizes) / len(campaign_sizes) if campaign_sizes else 0, 'median': sorted(campaign_sizes)[len(campaign_sizes) // 2] if campaign_sizes else 0, 'sizes': campaign_sizes[:20]}}, 'operations': {'total': len(operations), 'by_status': dict(operation_status), 'campaigns_per_operation': operation_campaign_counts[:10]}, 'transitions': {'edges': transition_edges, 'observations': transition_observations}, 'temporal': time_range, 'provenance': {'source': 'Neo4j AttackEvents and Campaigns', 'independent_ground_truth': False, 'reproducible': True, 'notes': 'Campaign membership is observed CYUKTI output, not independent labels'}}

def print_inventory(inventory):
    print('=' * 80)
    print('R2 DATASET INVENTORY')
    print('=' * 80)
    print(f"Dataset ID: {inventory['dataset_id']}")
    print(f"Collected: {inventory['collection_timestamp']}")
    print()
    events = inventory['events']
    print('ATTACKEVENTS')
    print('-' * 80)
    print(f"Total Events:          {events['total']}")
    print(f"Unique Rules:          {events['unique_rules']}")
    print(f"Unique Techniques:     {events['unique_techniques']}")
    print(f"UNKNOWN Techniques:    {events['unknown_techniques']} ({events['unknown_techniques'] / events['total'] * 100:.1f}%)")
    print(f"Unique Host Pairs:     {events['unique_host_pairs']}")
    print(f"Unique Attackers:      {events['unique_attackers']}")
    print(f"Unique Victims:        {events['unique_victims']}")
    print()
    campaigns = inventory['campaigns']
    print('CAMPAIGNS')
    print('-' * 80)
    print(f"Total Campaigns:       {campaigns['total']}")
    print(f"Status Distribution:   {campaigns['by_status']}")
    print(f"Unique Host Pairs:     {campaigns['unique_host_pairs']}")
    print(f"Singleton Campaigns:   {campaigns['singleton_count']} ({campaigns['singleton_count'] / campaigns['total'] * 100:.1f}%)")
    dist = campaigns['size_distribution']
    print(f"Campaign Size:         min={dist['min']}, max={dist['max']}, mean={dist['mean']:.1f}, median={dist['median']}")
    print()
    ops = inventory['operations']
    print('OPERATIONS')
    print('-' * 80)
    print(f"Total Operations:      {ops['total']}")
    print(f"Status Distribution:   {ops['by_status']}")
    if ops['campaigns_per_operation']:
        print(f"Top Operation Size:    {ops['campaigns_per_operation'][0]['campaign_count']} campaigns")
    print()
    trans = inventory['transitions']
    print('TRANSITIONS')
    print('-' * 80)
    print(f"Edge Count:            {trans['edges']}")
    print(f"Total Observations:    {trans['observations']}")
    print()
    if inventory['temporal']:
        temp = inventory['temporal']
        print('TEMPORAL RANGE')
        print('-' * 80)
        print(f"Start:                 {temp['start']}")
        print(f"End:                   {temp['end']}")
        print(f"Duration:              {temp['duration_hours']:.1f} hours")
        print()
    prov = inventory['provenance']
    print('PROVENANCE')
    print('-' * 80)
    print(f"Source:                {prov['source']}")
    print(f"Independent GT:        {prov['independent_ground_truth']}")
    print(f"Reproducible:          {prov['reproducible']}")
    print(f"Notes:                 {prov['notes']}")
    print('=' * 80)
if __name__ == '__main__':
    inventory = collect_dataset_inventory()
    print_inventory(inventory)
    output_file = 'r2_dataset_inventory.json'
    with open(output_file, 'w') as f:
        json.dump(inventory, f, indent=2)
    print(f'\nInventory saved to: {output_file}')