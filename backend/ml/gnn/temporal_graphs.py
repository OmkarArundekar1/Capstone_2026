from __future__ import annotations
from dataclasses import dataclass
from graph_encoder import EncodedGraph, encode_graph
_SNAPSHOT_QUERY = '\nMATCH (c:Campaign {campaign_id:$campaign_id})\nOPTIONAL MATCH (a:Attacker)-[r1:LAUNCHED]->(c)\nOPTIONAL MATCH (c)-[r2:HAS_EVENT]->(e:AttackEvent)\nWHERE e.first_seen <= $cutoff\nOPTIONAL MATCH (e)-[r3:MATCHES]->(t:Technique)\nOPTIONAL MATCH (c)-[r4:TARGETS]->(h:Host)\n\nWITH\n    collect(DISTINCT a) +\n    collect(DISTINCT c) +\n    collect(DISTINCT e) +\n    collect(DISTINCT t) +\n    collect(DISTINCT h) AS nodes,\n\n    collect(DISTINCT r1) +\n    collect(DISTINCT r2) +\n    collect(DISTINCT r3) +\n    collect(DISTINCT r4) AS rels\n\nRETURN nodes, rels\n'

@dataclass
class TemporalSnapshot:
    campaign_id: str
    snapshot_index: int
    cutoff_timestamp: str
    graph: EncodedGraph
    num_distinct_timestamps_included: int

def list_temporal_campaign_ids() -> list[str]:
    from neo4j_client import driver
    with driver.session() as session:
        result = session.run('\n            MATCH (c:Campaign)-[:HAS_EVENT]->(e:AttackEvent)\n            WITH c, collect(DISTINCT e.first_seen) AS ts\n            WHERE size(ts) >= 2\n            RETURN c.campaign_id AS id\n            ORDER BY id\n        ')
        return [record['id'] for record in result]

def _distinct_event_timestamps(campaign_id: str) -> list:
    from neo4j_client import driver
    with driver.session() as session:
        result = session.run('\n            MATCH (:Campaign {campaign_id:$campaign_id})-[:HAS_EVENT]->(e:AttackEvent)\n            RETURN DISTINCT e.first_seen AS ts\n            ORDER BY ts\n        ', campaign_id=campaign_id)
        return [record['ts'] for record in result]

def _build_snapshot_graph(campaign_id: str, cutoff):
    from graph_feature_engine import GraphBuilder, GraphSnapshot
    from neo4j_client import driver
    snapshot = GraphSnapshot()
    with driver.session() as session:
        record = session.run(_SNAPSHOT_QUERY, campaign_id=campaign_id, cutoff=cutoff).single()
        if record is not None:
            for node in record['nodes']:
                if node is None:
                    continue
                snapshot.nodes.append({'id': node.element_id, 'labels': list(node.labels), 'properties': dict(node)})
            for rel in record['rels']:
                if rel is None:
                    continue
                snapshot.relationships.append({'id': rel.element_id, 'type': rel.type, 'start': rel.start_node.element_id, 'end': rel.end_node.element_id, 'properties': dict(rel)})
    return GraphBuilder().build(snapshot)

def build_temporal_snapshots(campaign_id: str) -> list[TemporalSnapshot]:
    timestamps = _distinct_event_timestamps(campaign_id)
    if len(timestamps) < 2:
        return []
    snapshots = []
    for index, cutoff in enumerate(timestamps):
        graph = _build_snapshot_graph(campaign_id, cutoff)
        encoded = encode_graph(graph)
        snapshots.append(TemporalSnapshot(campaign_id=campaign_id, snapshot_index=index, cutoff_timestamp=str(cutoff), graph=encoded, num_distinct_timestamps_included=index + 1))
    return snapshots

def build_all_temporal_snapshots() -> dict[str, list[TemporalSnapshot]]:
    return {cid: build_temporal_snapshots(cid) for cid in list_temporal_campaign_ids()}
if __name__ == '__main__':
    import json
    all_snapshots = build_all_temporal_snapshots()
    print(json.dumps({'campaigns_with_temporal_data': len(all_snapshots), 'snapshots_per_campaign': {cid: len(snaps) for cid, snaps in all_snapshots.items()}}, indent=2))