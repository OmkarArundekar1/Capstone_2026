from __future__ import annotations
from typing import Any
try:
    import networkx as nx
    _HAS_NX = True
except ImportError:
    _HAS_NX = False

class AttackGraphBuilder:

    def build(self, events: list[dict[str, Any]], src_ip: str='unknown') -> dict[str, Any]:
        if not events:
            return self._empty_graph(src_ip)
        if not _HAS_NX:
            return self._heuristic_graph(events, src_ip)
        G = nx.DiGraph()
        prev_node = None
        for ev in events:
            phase = ev.get('kill_chain_phase', 'Unknown')
            port = ev.get('dst_port') or 0
            label = ev.get('attack_label', 'Unknown')
            node_id = f'{phase}:{port}'
            G.add_node(node_id, phase=phase, label=label, port=port)
            if prev_node and prev_node != node_id:
                if G.has_edge(prev_node, node_id):
                    G[prev_node][node_id]['weight'] += 1
                else:
                    G.add_edge(prev_node, node_id, weight=1)
            prev_node = node_id
        phases = [ev.get('kill_chain_phase', 'Unknown') for ev in events]
        unique_phases = list(dict.fromkeys(phases))
        return {'src_ip': src_ip, 'num_nodes': G.number_of_nodes(), 'num_edges': G.number_of_edges(), 'unique_phases': unique_phases, 'nodes': [{'id': n, **G.nodes[n]} for n in G.nodes()], 'edges': [{'from': u, 'to': v, 'weight': d['weight']} for u, v, d in G.edges(data=True)], 'is_multi_stage': len(unique_phases) > 1}

    def _heuristic_graph(self, events: list[dict], src_ip: str) -> dict[str, Any]:
        phases = [ev.get('kill_chain_phase', 'Unknown') for ev in events]
        unique_phases = list(dict.fromkeys(phases))
        return {'src_ip': src_ip, 'num_nodes': len(unique_phases), 'num_edges': max(0, len(unique_phases) - 1), 'unique_phases': unique_phases, 'nodes': [{'id': p, 'phase': p} for p in unique_phases], 'edges': [{'from': unique_phases[i], 'to': unique_phases[i + 1], 'weight': 1} for i in range(len(unique_phases) - 1)], 'is_multi_stage': len(unique_phases) > 1}

    @staticmethod
    def _empty_graph(src_ip: str) -> dict[str, Any]:
        return {'src_ip': src_ip, 'num_nodes': 0, 'num_edges': 0, 'unique_phases': [], 'nodes': [], 'edges': [], 'is_multi_stage': False}