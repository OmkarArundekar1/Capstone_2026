from flask import Flask, jsonify, request
from flask_cors import CORS
from neo4j_client import driver
import prediction_engine
import recommendation_engine
import datetime
import json
import os
import logging
import types
from neo4j.exceptions import Neo4jError, ServiceUnavailable
from werkzeug.exceptions import HTTPException
from campaign_context import CampaignContext
from investigation.loop import default_action_executor, default_model_predictor, run_investigation
from rag.mitre_retriever import mitre_retriever
from risk_scoring import TPS_CEILING, normalize_risk_score, risk_level_from_score, severity_from_tps
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
app = Flask(__name__)
CORS(app)
LISTENER_LOG_PATH = os.path.join(os.path.dirname(__file__), 'logs', 'prerana_listener.log')
import config as _startup_config
if _startup_config.GNN_ENABLED:
    try:
        from ml.gnn.inference import gnn_inference_service as _gnn_prewarm
        _gnn_prewarm.available
    except Exception:
        logger.exception('GNN pre-warm failed at startup -- GNN inference may be unavailable this session.')
from soar.api import soar_bp
app.register_blueprint(soar_bp)
from containment_api import containment_bp
app.register_blueprint(containment_bp)
from websocket_events import initialize_socketio
socketio = initialize_socketio(app, cors_allowed_origins='*')

@app.errorhandler(ServiceUnavailable)
def handle_neo4j_unavailable(e):
    logger.error('Neo4j unreachable handling %s %s: %s', request.method, request.path, e)
    return (jsonify({'error': f'Database unavailable: {e}'}), 503)

@app.errorhandler(Neo4jError)
def handle_neo4j_error(e):
    logger.error('Neo4j query error handling %s %s: %s', request.method, request.path, e)
    return (jsonify({'error': f'Database query error: {e}'}), 500)

@app.errorhandler(HTTPException)
def handle_http_exception(e):
    return (jsonify({'error': e.description or e.name}), e.code)

@app.errorhandler(Exception)
def handle_unexpected_error(e):
    logger.exception('Unhandled exception handling %s %s', request.method, request.path)
    return (jsonify({'error': 'Internal server error'}), 500)

def neo4j_datetime_to_iso(val):
    if val is None:
        return None
    if hasattr(val, 'iso_format'):
        return val.iso_format()
    return str(val)

def format_campaign_label(campaign_id, index=None):
    if index is not None:
        return f'Campaign #{index}'
    if campaign_id and len(campaign_id) > 24:
        return f'Campaign …{campaign_id[-8:]}'
    return campaign_id or 'Campaign'

def format_node_label(node_type, props, campaign_index=None):
    if node_type == 'Campaign':
        return format_campaign_label(props.get('campaign_id'), campaign_index)
    if node_type == 'Technique':
        return props.get('name') or props.get('attack_id') or 'Technique'
    if node_type == 'Attacker':
        return props.get('ip') or 'Attacker'
    if node_type == 'Host':
        return props.get('ip') or 'Host'
    if node_type == 'AttackEvent':
        return props.get('technique') or props.get('attack_id') or 'Event'
    return props.get('name') or props.get('attack_id') or props.get('ip') or node_type

@app.route('/api/health')
def health():
    try:
        driver.verify_connectivity()
        return jsonify({'status': 'healthy', 'neo4j': 'connected', 'timestamp': datetime.datetime.now().isoformat()})
    except Exception as e:
        return (jsonify({'status': 'degraded', 'neo4j': 'disconnected', 'timestamp': datetime.datetime.now().isoformat()}), 500)

def get_time_where_clause(time_range, entity_alias, timestamp_field='last_seen'):
    if not time_range or time_range == 'all':
        return ''
    ranges = {'15m': 'datetime() - duration({minutes: 15})', '1h': 'datetime() - duration({hours: 1})', '24h': 'datetime() - duration({hours: 24})', '7d': 'datetime() - duration({days: 7})'}
    if time_range in ranges:
        return f'{entity_alias}.{timestamp_field} >= {ranges[time_range]}'
    return ''

@app.route('/api/overview')
def overview():
    time_range = request.args.get('time_range', 'all')
    time_filter = get_time_where_clause(time_range, 'e')
    where_clause = f'WHERE {time_filter}' if time_filter else ''
    with driver.session() as session:
        result = session.run(f'\n            MATCH (e:AttackEvent) {where_clause} WITH count(e) as total_events\n            OPTIONAL MATCH (c:Campaign) WITH total_events, count(c) as active_campaigns\n            OPTIONAL MATCH (a:Attacker) WITH total_events, active_campaigns, count(a) as unique_attackers\n            OPTIONAL MATCH (t:Technique) WITH total_events, active_campaigns, unique_attackers, count(t) as techniques_detected\n            OPTIONAL MATCH ()-[r:NEXT_TECHNIQUE]->() WITH total_events, active_campaigns, unique_attackers, techniques_detected, count(r) as learned_transitions\n            OPTIONAL MATCH (h:Host) WITH total_events, active_campaigns, unique_attackers, techniques_detected, learned_transitions, count(h) as total_hosts\n            RETURN total_events, active_campaigns, unique_attackers, techniques_detected, learned_transitions, total_hosts\n        ').single()
        return jsonify({'total_events': result['total_events'] or 0, 'active_campaigns': result['active_campaigns'] or 0, 'unique_attackers': result['unique_attackers'] or 0, 'techniques_detected': result['techniques_detected'] or 0, 'learned_transitions': result['learned_transitions'] or 0, 'total_hosts': result['total_hosts'] or 0, 'timestamp': datetime.datetime.now().isoformat()})

@app.route('/api/events')
def events():
    page = int(request.args.get('page', 1))
    page_size = int(request.args.get('page_size', 50))
    campaign = request.args.get('campaign')
    attacker = request.args.get('attacker')
    technique = request.args.get('technique')
    time_range = request.args.get('time_range', 'all')
    skip = (page - 1) * page_size
    match_clause = 'MATCH (c:Campaign)-[:HAS_EVENT]->(e:AttackEvent)-[:MATCHES]->(t:Technique), (a:Attacker)-[:LAUNCHED]->(c), (c)-[:TARGETS]->(h:Host)'
    where_clauses = []
    params = {}
    time_filter = get_time_where_clause(time_range, 'e')
    if time_filter:
        where_clauses.append(time_filter)
    if campaign:
        where_clauses.append('c.campaign_id = $campaign')
        params['campaign'] = campaign
    if attacker:
        where_clauses.append('a.ip = $attacker')
        params['attacker'] = attacker
    if technique:
        where_clauses.append('t.attack_id = $technique')
        params['technique'] = technique
    where_str = ' WHERE ' + ' AND '.join(where_clauses) if where_clauses else ''
    with driver.session() as session:
        count_res = session.run(f'{match_clause}{where_str} RETURN count(e) as total', **params).single()
        total = count_res['total'] if count_res else 0
        query = f'\n            {match_clause}{where_str}\n            RETURN elementId(e) as id, e.last_seen as timestamp, e.first_seen as first_seen,\n                   e.occurrences as occurrences, e.tps as tps,\n                   a.ip as attacker_ip, h.ip as victim_ip,\n                   t.attack_id as technique_id, t.name as technique_name, e.stage as stage, \n                   c.campaign_id as campaign_id\n            ORDER BY e.last_seen DESC SKIP $skip LIMIT $limit\n        '
        params['skip'] = skip
        params['limit'] = page_size
        res = session.run(query, **params)
        events_list = []
        for record in res:
            tps = record.get('tps') or 0
            events_list.append({'id': record['id'], 'timestamp': neo4j_datetime_to_iso(record['timestamp']), 'attacker_ip': record['attacker_ip'], 'victim_ip': record['victim_ip'], 'technique_id': record['technique_id'], 'technique_name': record['technique_name'], 'stage': record['stage'], 'severity': severity_from_tps(tps), 'occurrences': record.get('occurrences') or 1, 'campaign_id': record['campaign_id']})
        return jsonify({'events': events_list, 'total': total, 'page': page, 'page_size': page_size, 'total_pages': (total + page_size - 1) // page_size if total > 0 else 0})

@app.route('/api/events/<event_id>')
def event_detail(event_id):
    with driver.session() as session:
        query = '\n            MATCH (c:Campaign)-[:HAS_EVENT]->(e:AttackEvent)-[:MATCHES]->(t:Technique),\n                  (a:Attacker)-[:LAUNCHED]->(c), (c)-[:TARGETS]->(h:Host)\n            WHERE elementId(e) = $event_id\n            RETURN e.last_seen as timestamp, e.first_seen as first_seen, e.occurrences as occurrences, e.tps as tps,\n                   a.ip as attacker_ip, h.ip as victim_ip,\n                   t.attack_id as technique_id, t.name as technique_name, e.stage as stage, \n                   c.campaign_id as campaign_id, e.investigation_payload as investigation_payload\n        '
        record = session.run(query, event_id=event_id).single()
        if not record:
            return (jsonify({'error': 'Not found'}), 404)
        pred = None
        likely = session.run('\n            MATCH (c:Campaign {campaign_id: $campaign_id})-[r:LIKELY_NEXT]->(pt:Technique)\n            RETURN pt.attack_id AS predicted, r.confidence AS confidence, r.generated_at AS generated_at\n        ', campaign_id=record['campaign_id']).single()
        if likely and likely['predicted']:
            pred = {'predicted': likely['predicted'], 'confidence': likely['confidence'], 'generated_at': neo4j_datetime_to_iso(likely['generated_at'])}
        else:
            engine_pred = prediction_engine.predict_next_readonly(record['technique_id'])
            if engine_pred:
                pred = engine_pred
        recs = recommendation_engine.get_recommendations(record['technique_id'])
        payload = {}
        if record.get('investigation_payload'):
            try:
                payload = json.loads(record['investigation_payload'])
            except Exception:
                pass
        detail = {'id': event_id, 'timestamp': neo4j_datetime_to_iso(record['timestamp']), 'first_seen': neo4j_datetime_to_iso(record['first_seen']), 'occurrences': record['occurrences'], 'attacker_ip': record['attacker_ip'], 'victim_ip': record['victim_ip'], 'technique_id': record['technique_id'], 'technique_name': record['technique_name'], 'stage': record['stage'], 'severity': severity_from_tps(record.get('tps')), 'campaign_id': record['campaign_id'], 'mitre_tactic': record['stage'], 'predicted_next_attack': pred['predicted'] if pred else None, 'prediction_confidence': pred['confidence'] if pred else None, 'prediction_generated_at': pred.get('generated_at') if pred else None, 'recommendations': recs, 'investigation_payload': payload, 'raw_wazuh_event': payload}
        return jsonify(detail)

@app.route('/api/campaigns')
def campaigns():
    time_range = request.args.get('time_range', 'all')
    attacker_filter = request.args.get('attacker')
    time_filter = get_time_where_clause(time_range, 'c')
    where_parts = []
    params = {}
    if time_filter:
        where_parts.append(time_filter)
    if attacker_filter:
        where_parts.append('a.ip = $attacker')
        params['attacker'] = attacker_filter
    where_clause = f"WHERE {' AND '.join(where_parts)}" if where_parts else ''
    with driver.session() as session:
        res = session.run(f'\n            MATCH (a:Attacker)-[:LAUNCHED]->(c:Campaign)\n            OPTIONAL MATCH (c)-[:TARGETS]->(h:Host)\n            OPTIONAL MATCH (c)-[:HAS_EVENT]->(e:AttackEvent)-[:MATCHES]->(t:Technique)\n            OPTIONAL MATCH (c)-[ln:LIKELY_NEXT]->(pt:Technique)\n            {where_clause}\n            WITH c, a, h, collect(DISTINCT t) as techniques, count(DISTINCT e) as event_count,\n                 head(collect(DISTINCT pt.attack_id)) AS predicted_technique,\n                 head(collect(DISTINCT ln.confidence)) AS prediction_confidence\n            RETURN c.campaign_id as campaign_id, a.ip as attacker_ip, h.ip as victim_ip,\n                   c.first_seen as first_seen, c.last_seen as last_seen, event_count,\n                   c.tps as raw_tps, c.last_technique as latest_technique,\n                   predicted_technique, prediction_confidence\n            ORDER BY c.last_seen DESC\n        ', **params)
        campaigns_list = []
        for idx, r in enumerate(res, start=1):
            raw_tps = r['raw_tps'] or 0
            risk_score = normalize_risk_score(raw_tps)
            campaigns_list.append({'campaign_id': r['campaign_id'], 'campaign_label': format_campaign_label(r['campaign_id'], idx), 'attacker_ip': r['attacker_ip'], 'victim_ip': r['victim_ip'] or 'Unknown', 'first_seen': neo4j_datetime_to_iso(r['first_seen']), 'last_seen': neo4j_datetime_to_iso(r['last_seen']), 'event_count': r['event_count'], 'risk_score': risk_score, 'raw_tps': raw_tps, 'risk_level': risk_level_from_score(risk_score), 'latest_technique': r['latest_technique'], 'predicted_technique': r['predicted_technique'], 'prediction_confidence': r['prediction_confidence']})
        return jsonify({'campaigns': campaigns_list, 'count': len(campaigns_list)})

@app.route('/api/operations')
def operations():
    with driver.session() as session:
        res = session.run('\n            MATCH (o:Operation)\n            OPTIONAL MATCH (o)-[:HAS_CAMPAIGN]->(c:Campaign)\n            WITH o, collect(DISTINCT c.campaign_id) AS campaign_ids\n            RETURN o.operation_id AS operation_id,\n                   o.primary_attacker AS primary_attacker,\n                   o.primary_target AS primary_target,\n                   o.status AS status,\n                   o.created_at AS created_at,\n                   o.last_seen AS last_seen,\n                   o.closed_at AS closed_at,\n                   o.confidence AS confidence,\n                   o.correlation_score AS correlation_score,\n                   o.predicted_goal AS predicted_goal,\n                   campaign_ids\n            ORDER BY o.last_seen DESC\n        ')
        operations_list = []
        for r in res:
            campaign_ids = [cid for cid in r['campaign_ids'] if cid is not None]
            operations_list.append({'operation_id': r['operation_id'], 'primary_attacker': r['primary_attacker'], 'primary_target': r['primary_target'], 'status': r['status'], 'created_at': neo4j_datetime_to_iso(r['created_at']), 'last_seen': neo4j_datetime_to_iso(r['last_seen']), 'closed_at': neo4j_datetime_to_iso(r['closed_at']), 'confidence': float(r['confidence']) if r['confidence'] is not None else None, 'correlation_score': float(r['correlation_score']) if r['correlation_score'] is not None else None, 'predicted_goal': r['predicted_goal'] or None, 'campaign_ids': campaign_ids, 'campaign_count': len(campaign_ids)})
        return jsonify({'operations': operations_list, 'count': len(operations_list)})

@app.route('/api/correlation/campaigns/<campaign_id>')
def correlation_campaigns(campaign_id):
    with driver.session() as session:
        query = "\n        MATCH (c1:Campaign {campaign_id: $campaign_id})\n        MATCH (c2:Campaign)\n        WHERE c1 <> c2\n\n        // Techniques\n        OPTIONAL MATCH (c1)-[:HAS_EVENT]->(:AttackEvent)-[:MATCHES]->(t1:Technique)\n        WITH c1, c2, collect(DISTINCT t1) AS c1_techs\n        OPTIONAL MATCH (c2)-[:HAS_EVENT]->(:AttackEvent)-[:MATCHES]->(t2:Technique)\n        WITH c1, c2, c1_techs, collect(DISTINCT t2) AS c2_techs\n        WITH c1, c2, c1_techs, c2_techs, [t IN c1_techs WHERE t IN c2_techs] AS shared_t\n        WITH c1, c2, size(shared_t) AS shared_tech_count,\n             size(c1_techs) + size(c2_techs) - size(shared_t) AS total_tech_count,\n             [t IN shared_t | coalesce(t.name, t.attack_id)] AS shared_techniques,\n             [t IN shared_t | coalesce(t.stage, 'Unknown')] AS shared_tactics_raw\n\n        // Attacker\n        OPTIONAL MATCH (a1:Attacker)-[:LAUNCHED]->(c1)\n        WITH c1, c2, shared_tech_count, total_tech_count, shared_techniques, shared_tactics_raw, collect(DISTINCT a1.ip) AS c1_a\n        OPTIONAL MATCH (a2:Attacker)-[:LAUNCHED]->(c2)\n        WITH c1, c2, shared_tech_count, total_tech_count, shared_techniques, shared_tactics_raw, c1_a, collect(DISTINCT a2.ip) AS c2_a\n        WITH c1, c2, shared_tech_count, total_tech_count, shared_techniques, shared_tactics_raw, [a IN c1_a WHERE a IN c2_a] AS shared_a\n\n        // Host\n        OPTIONAL MATCH (c1)-[:TARGETS]->(h1:Host)\n        WITH c1, c2, shared_tech_count, total_tech_count, shared_techniques, shared_tactics_raw, shared_a, collect(DISTINCT h1.ip) AS c1_h\n        OPTIONAL MATCH (c2)-[:TARGETS]->(h2:Host)\n        WITH c1, c2, shared_tech_count, total_tech_count, shared_techniques, shared_tactics_raw, shared_a, c1_h, collect(DISTINCT h2.ip) AS c2_h\n        WITH c1, c2, shared_tech_count, total_tech_count, shared_techniques, shared_tactics_raw, shared_a, [h IN c1_h WHERE h IN c2_h] AS shared_h\n\n        // Calculation\n        WITH c2, shared_techniques, shared_tactics_raw, shared_a, shared_h,\n             (CASE WHEN total_tech_count = 0 THEN 0.0 ELSE toFloat(shared_tech_count) / total_tech_count END * 60.0) +\n             (CASE WHEN size(shared_a) > 0 THEN 20.0 ELSE 0.0 END) +\n             (CASE WHEN size(shared_h) > 0 THEN 20.0 ELSE 0.0 END) AS similarity_score\n        WHERE similarity_score > 0\n        RETURN c2.campaign_id AS campaign_id,\n               c2.tps AS raw_tps,\n               round(similarity_score) AS similarity_score,\n               shared_techniques,\n               shared_tactics_raw,\n               shared_a AS shared_attackers,\n               shared_h AS shared_hosts\n        ORDER BY similarity_score DESC LIMIT 10\n        "
        logger.info(f'Executing Cypher Query: Correlation for campaign {campaign_id}\n{query}')
        res = session.run(query, campaign_id=campaign_id)
        similar_campaigns = []
        for idx, r in enumerate(res, start=1):
            tactics_set = list(set(r['shared_tactics_raw']))
            similar_campaigns.append({'campaign_id': r['campaign_id'], 'campaign_label': format_campaign_label(r['campaign_id'], None), 'similarity_score': r['similarity_score'], 'shared_techniques': r['shared_techniques'], 'shared_tactics': tactics_set, 'shared_attackers': r['shared_attackers'], 'shared_hosts': r['shared_hosts'], 'gnn_topology_similarity': _gnn_topology_similarity_for_dashboard(campaign_id, r['campaign_id'])})
        return jsonify({'campaign_id': campaign_id, 'similar_campaigns': similar_campaigns})

def _gnn_topology_similarity_for_dashboard(campaign_id_a: str, campaign_id_b: str) -> float | None:
    try:
        from ml.gnn.topology_similarity import gnn_topology_similarity_between_campaigns
        return gnn_topology_similarity_between_campaigns(campaign_id_a, campaign_id_b)
    except Exception:
        logger.exception('GNN topology similarity computation failed for dashboard correlation (%s vs %s) -- continuing without it.', campaign_id_a, campaign_id_b)
        return None

@app.route('/api/attribution/actors/<campaign_id>')
def attribution_actors(campaign_id):
    with driver.session() as session:
        query = '\n        MATCH (c:Campaign {campaign_id: $campaign_id})-[:HAS_EVENT]->(:AttackEvent)-[:MATCHES]->(t:Technique)\n        WITH c, collect(DISTINCT t) AS c_techs\n        MATCH (ta:ThreatActor)-[:USES]->(ta_t:Technique)\n        WITH c, c_techs, ta, collect(DISTINCT ta_t) AS ta_techs\n        WITH c, ta, c_techs, ta_techs, [t IN c_techs WHERE t IN ta_techs] AS shared_t\n        WITH c, ta, size(shared_t) AS shared_tech_count,\n             size(c_techs) + size(ta_techs) - size(shared_t) AS total_tech_count,\n             [t IN shared_t | coalesce(t.name, t.attack_id)] AS shared_techniques\n        WHERE shared_tech_count > 0\n        \n        OPTIONAL MATCH (ta)-[:USES]->(m:Malware)\n        WITH c, ta, shared_tech_count, total_tech_count, shared_techniques, collect(DISTINCT m.name) AS ta_malware\n        \n        OPTIONAL MATCH (ta)-[:USES]->(tool:Tool)\n        WITH c, ta, shared_tech_count, total_tech_count, shared_techniques, ta_malware, collect(DISTINCT tool.name) AS ta_tools\n        \n        WITH ta.name AS actor_name,\n             ta.description AS description,\n             // total_tech_count is guaranteed > 0 here: the preceding\n             // `WHERE shared_tech_count > 0` means total_tech_count (which\n             // is always >= shared_tech_count, being a union-minus-overlap\n             // count) can never be 0. max(x, y) over two scalars is not\n             // valid Cypher (max() is an aggregate function) -- this\n             // previously raised Neo.ClientError.Statement.SyntaxError on\n             // every real call, live-confirmed this session; the division\n             // guard it was attempting is unneeded, not just invalid.\n             (toFloat(shared_tech_count) / total_tech_count) * 100 AS base_confidence,\n             shared_tech_count,\n             shared_techniques,\n             ta_malware,\n             ta_tools\n             \n        // Boost confidence slightly if they match many techniques absolutely\n        WITH actor_name, description, \n             CASE WHEN base_confidence + (shared_tech_count * 2) > 99 THEN 99.0 \n                  ELSE base_confidence + (shared_tech_count * 2) END AS confidence,\n             shared_techniques, ta_malware, ta_tools\n             \n        RETURN actor_name, round(confidence) AS confidence, description,\n               shared_techniques, ta_malware, ta_tools\n        ORDER BY confidence DESC LIMIT 5\n        '
        logger.info(f'Executing Cypher Query: Attribution for campaign {campaign_id}\n{query}')
        res = session.run(query, campaign_id=campaign_id)
        actors = []
        for r in res:
            actors.append({'actor_name': r['actor_name'], 'confidence': r['confidence'], 'description': r['description'], 'shared_techniques': r['shared_techniques'], 'malware': r['ta_malware'][:5], 'tools': r['ta_tools'][:5]})
        return jsonify({'campaign_id': campaign_id, 'attribution': actors})

@app.route('/api/risk/propagation/<campaign_id>')
def risk_propagation(campaign_id):
    with driver.session() as session:
        query = "\n        MATCH (c:Campaign {campaign_id: $campaign_id})\n        OPTIONAL MATCH (a:Attacker)-[:LAUNCHED]->(c)\n        OPTIONAL MATCH (c)-[:HAS_EVENT]->(e:AttackEvent)-[:MATCHES]->(t:Technique)\n        OPTIONAL MATCH (c)-[:TARGETS]->(h:Host)\n        \n        WITH c, a, h, t, e.tps AS e_tps\n        \n        WITH c,\n             a.ip AS attacker_ip, \n             h.ip AS host_ip,\n             collect(DISTINCT {id: coalesce(t.attack_id, 'Unknown'), name: coalesce(t.name, 'Unknown'), score: coalesce(e_tps, 0)}) AS techniques\n             \n        RETURN c.campaign_id AS campaign_id,\n               c.tps AS campaign_tps,\n               attacker_ip,\n               host_ip,\n               techniques\n        "
        logger.info(f'Executing Cypher Query: Risk Propagation for campaign {campaign_id}\n{query}')
        res = session.run(query, campaign_id=campaign_id).single()
        if not res:
            return (jsonify({'error': 'Campaign not found'}), 404)
        c_tps = res['campaign_tps'] or 0
        c_risk = normalize_risk_score(c_tps)
        tech_contributions = {}
        total_tech_score = 0
        for tech in res['techniques']:
            t_id = tech['id']
            if t_id == 'Unknown':
                continue
            tech_contributions[t_id] = tech_contributions.get(t_id, 0) + tech['score']
            total_tech_score += tech['score']
        tech_list = []
        for t_id, score in tech_contributions.items():
            name = next((t['name'] for t in res['techniques'] if t['id'] == t_id), t_id)
            percent = round(score / max(total_tech_score, 1) * 100)
            tech_list.append({'node_id': t_id, 'node_name': name, 'node_type': 'Technique', 'risk_score': normalize_risk_score(score), 'contribution_percent': percent})
        tech_list.sort(key=lambda x: x['contribution_percent'], reverse=True)
        nodes = []
        if res['attacker_ip']:
            nodes.append({'node_id': res['attacker_ip'], 'node_name': res['attacker_ip'], 'node_type': 'Attacker', 'risk_score': c_risk, 'contribution_percent': 100})
        nodes.append({'node_id': res['campaign_id'], 'node_name': format_campaign_label(res['campaign_id'], None), 'node_type': 'Campaign', 'risk_score': c_risk, 'contribution_percent': 100})
        nodes.extend(tech_list[:5])
        if res['host_ip']:
            nodes.append({'node_id': res['host_ip'], 'node_name': res['host_ip'], 'node_type': 'Host', 'risk_score': c_risk, 'contribution_percent': 100})
        return jsonify({'campaign_id': campaign_id, 'propagation': nodes})

@app.route('/api/campaigns/<campaign_id>/timeline')
def campaign_timeline(campaign_id):
    with driver.session() as session:
        query = '\n        MATCH (c:Campaign {campaign_id: $campaign_id})-[:HAS_EVENT]->(e:AttackEvent)-[:MATCHES]->(t:Technique)\n        RETURN elementId(e) as id, e.first_seen as first_seen, e.last_seen as last_seen, e.occurrences as occurrences,\n               t.attack_id as technique_id, t.name as technique_name, e.stage as stage\n        ORDER BY e.first_seen ASC\n        '
        res = session.run(query, campaign_id=campaign_id)
        events = []
        for r in res:
            events.append({'id': r['id'], 'technique_id': r['technique_id'], 'technique_name': r['technique_name'], 'stage': r['stage'], 'first_seen': r['first_seen'].iso_format() if hasattr(r['first_seen'], 'iso_format') else str(r['first_seen']), 'last_seen': r['last_seen'].iso_format() if hasattr(r['last_seen'], 'iso_format') else str(r['last_seen']), 'occurrences': r['occurrences'] or 1})
        return jsonify({'events': events, 'campaign_id': campaign_id})

@app.route('/api/attackers')
def attackers():
    with driver.session() as session:
        res = session.run('\n            MATCH (a:Attacker)-[:LAUNCHED]->(c:Campaign)\n            OPTIONAL MATCH (c)-[:HAS_EVENT]->(e:AttackEvent)-[:MATCHES]->(t:Technique)\n            OPTIONAL MATCH (c)-[ln:LIKELY_NEXT]->(pt:Technique)\n            WITH a, count(DISTINCT c) AS campaign_count,\n                 count(DISTINCT e) AS event_count,\n                 sum(coalesce(c.tps, 0)) AS raw_tps,\n                 min(c.first_seen) AS first_seen,\n                 max(c.last_seen) AS last_seen,\n                 collect(DISTINCT t.attack_id) AS techniques,\n                 head(collect(pt.attack_id)) AS predicted_technique\n            RETURN a.ip AS attacker_ip, campaign_count, event_count, raw_tps,\n                   first_seen, last_seen, techniques, predicted_technique\n            ORDER BY raw_tps DESC, event_count DESC\n        ')
        attackers_list = []
        for r in res:
            raw_tps = r['raw_tps'] or 0
            risk_score = normalize_risk_score(raw_tps)
            attackers_list.append({'attacker_ip': r['attacker_ip'], 'campaign_count': r['campaign_count'], 'event_count': r['event_count'], 'risk_score': risk_score, 'raw_tps': raw_tps, 'risk_level': risk_level_from_score(risk_score), 'first_seen': neo4j_datetime_to_iso(r['first_seen']), 'last_seen': neo4j_datetime_to_iso(r['last_seen']), 'techniques_observed': [t for t in r['techniques'] or [] if t], 'predicted_technique': r['predicted_technique']})
        return jsonify({'attackers': attackers_list, 'count': len(attackers_list)})

@app.route('/api/graph/expand')
def expand_graph():
    node_id = request.args.get('node_id')
    depth = int(request.args.get('depth', 1))
    if not node_id:
        return (jsonify({'error': 'Missing node_id parameter'}), 400)
    with driver.session() as session:
        start = session.run('\n            MATCH (start) WHERE elementId(start) = $node_id\n            RETURN labels(start)[0] AS node_type, start.attack_id AS attack_id\n        ', node_id=node_id).single()
        if not start:
            return jsonify({'nodes': [], 'links': []})
        if start['node_type'] == 'Technique':
            query = f"\n            MATCH (t:Technique) WHERE elementId(t) = $node_id\n            MATCH path = (t)-[*1..{depth}]-(m)\n            WHERE any(label IN labels(m) WHERE label IN ['ThreatActor', 'Malware', 'Tool', 'Mitigation', 'Tactic', 'Technique'])\n            UNWIND nodes(path) AS n\n            UNWIND relationships(path) AS r\n            WITH collect(DISTINCT n) AS all_nodes, collect(DISTINCT r) AS all_rels\n            RETURN all_nodes, all_rels\n            "
        else:
            query = f"\n            MATCH (start) WHERE elementId(start) = $node_id\n            MATCH path = (start)-[*1..{depth}]-(m)\n            WHERE any(label IN labels(m) WHERE label IN ['ThreatActor', 'Malware', 'Tool', 'Mitigation', 'Tactic', 'Campaign', 'Technique', 'Attacker', 'Host'])\n            UNWIND nodes(path) AS n\n            UNWIND relationships(path) AS r\n            WITH collect(DISTINCT n) AS all_nodes, collect(DISTINCT r) AS all_rels\n            RETURN all_nodes, all_rels\n            "
        res = session.run(query, node_id=node_id).single()
        if not res or not res['all_nodes']:
            return jsonify({'nodes': [], 'links': []})
        nodes = []
        for n in res['all_nodes']:
            n_id = n.element_id
            n_type = list(n.labels)[0] if n.labels else 'Unknown'
            n_props = dict(n)
            nodes.append({'id': n_id, 'type': n_type, 'label': format_node_label(n_type, n_props), 'attack_id': n_props.get('attack_id'), 'campaign_id': n_props.get('campaign_id'), 'full_label': n_props.get('campaign_id') or n_props.get('name') or n_props.get('attack_id')})
        links = []
        for r in res['all_rels']:
            links.append({'source': r.start_node.element_id, 'target': r.end_node.element_id, 'label': r.type})
        return jsonify({'nodes': nodes, 'links': links})

@app.route('/api/graph/paths')
def graph_paths():
    campaign_id = request.args.get('campaign_id')
    timeframe = request.args.get('timeframe')
    with driver.session() as session:
        time_filter = ''
        if timeframe == '24h':
            time_filter = "AND e.first_seen >= datetime() - duration('PT24H')"
        elif timeframe == '7d':
            time_filter = "AND e.first_seen >= datetime() - duration('P7D')"
        elif timeframe == '30d':
            time_filter = "AND e.first_seen >= datetime() - duration('P30D')"
        campaign_filter = ''
        if campaign_id:
            campaign_filter = 'AND c.campaign_id = $campaign_id'
        query = f"\n        // Get all techniques involved\n        OPTIONAL MATCH (c:Campaign)-[:HAS_EVENT]->(e:AttackEvent)-[:MATCHES]->(t:Technique)\n        WHERE 1=1 {time_filter} {campaign_filter}\n        WITH collect(DISTINCT t) AS event_techs\n        \n        OPTIONAL MATCH (c:Campaign)-[:LIKELY_NEXT]->(t:Technique)\n        WHERE 1=1 {campaign_filter}\n        WITH event_techs, collect(DISTINCT t) AS likely_techs\n        \n        WITH [x IN (event_techs + likely_techs) WHERE x IS NOT NULL] AS all_techs\n        UNWIND all_techs AS t\n        WITH DISTINCT t\n        \n        // Calculate global frequency and max TPS for node sizing\n        OPTIONAL MATCH (c2:Campaign)-[:HAS_EVENT]->(e2:AttackEvent)-[:MATCHES]->(t)\n        WHERE 1=1 {time_filter} {campaign_filter}\n        WITH t, count(DISTINCT c2) AS campaign_count, sum(e2.occurrences) AS frequency, max(e2.tps) AS max_tps\n        \n        // Return nodes\n        RETURN elementId(t) AS id, 'Technique' AS type, t.attack_id AS attack_id, coalesce(t.name, t.attack_id) AS name,\n               t.description AS description, t.stage AS stage,\n               frequency, campaign_count, max_tps\n        "
        logger.info(f'Executing Cypher Query: Path Graph Nodes\n{query}')
        nodes_res = session.run(query, campaign_id=campaign_id)
        nodes = []
        node_ids = set()
        for r in nodes_res:
            n_id = r['id']
            node_ids.add(n_id)
            nodes.append({'id': n_id, 'type': 'Technique', 'label': r['name'], 'attack_id': r['attack_id'], 'description': r['description'], 'stage': r['stage'], 'frequency': r['frequency'] or 0, 'campaign_count': r['campaign_count'] or 0, 'max_tps': r['max_tps'] or 0})
        links_query = f"\n        // NEXT_TECHNIQUE edges\n        OPTIONAL MATCH (c:Campaign)-[:HAS_EVENT]->(e:AttackEvent)-[:MATCHES]->(t1:Technique)\n        WHERE 1=1 {time_filter} {campaign_filter}\n        WITH collect(DISTINCT t1) AS event_techs\n        \n        OPTIONAL MATCH (c:Campaign)-[:LIKELY_NEXT]->(t2:Technique)\n        WHERE 1=1 {campaign_filter}\n        WITH event_techs, collect(DISTINCT t2) AS likely_techs\n        \n        WITH [x IN (event_techs + likely_techs) WHERE x IS NOT NULL] AS all_techs\n        \n        OPTIONAL MATCH (t1:Technique)-[r:NEXT_TECHNIQUE]->(t2:Technique)\n        WHERE t1 IN all_techs AND t2 IN all_techs\n        WITH all_techs, collect(DISTINCT {{source: elementId(t1), target: elementId(t2), label: 'NEXT_TECHNIQUE', count: coalesce(r.count, 1), confidence: null}}) AS next_links\n        \n        // LIKELY_NEXT edges\n        OPTIONAL MATCH (c:Campaign)-[r:LIKELY_NEXT]->(t:Technique)\n        WHERE 1=1 {campaign_filter}\n        OPTIONAL MATCH (c)-[:HAS_EVENT]->(e:AttackEvent)-[:MATCHES]->(t_src:Technique)\n        WITH next_links, collect(DISTINCT {{source: elementId(t_src), target: elementId(t), label: 'LIKELY_NEXT', count: null, confidence: coalesce(r.confidence, 0)}}) AS likely_links\n        \n        RETURN next_links, likely_links\n        "
        logger.info(f'Executing Cypher Query: Path Graph Edges\n{links_query}')
        links_res = session.run(links_query, campaign_id=campaign_id).single()
        links = []
        if links_res:
            next_links = links_res['next_links'] or []
            likely_links = links_res['likely_links'] or []
            for l in next_links:
                if l['source'] and l['target'] and (l['source'] in node_ids) and (l['target'] in node_ids):
                    links.append(l)
            for l in likely_links:
                if l['source'] and l['target'] and (l['source'] in node_ids) and (l['target'] in node_ids):
                    if l['source'] != l['target']:
                        links.append(l)
        for node in nodes:
            mitig_query = '\n            MATCH (t:Technique {attack_id: $attack_id})-[:MITIGATED_BY]->(m:Mitigation)\n            RETURN m.name AS name, m.description AS description LIMIT 3\n            '
            try:
                m_res = session.run(mitig_query, attack_id=node['attack_id'])
                node['mitigations'] = [{'name': mr['name'], 'description': mr['description']} for mr in m_res]
            except:
                node['mitigations'] = []
        return jsonify({'nodes': nodes, 'links': links})
import re

@app.route('/api/query', methods=['POST'])
def execute_query():
    data = request.json
    if not data or 'query' not in data:
        return (jsonify({'error': 'Missing query parameter'}), 400)
    query = data['query'].strip()
    forbidden_keywords = ['\\bCREATE\\b', '\\bMERGE\\b', '\\bDELETE\\b', '\\bDETACH\\b', '\\bSET\\b', '\\bREMOVE\\b', '\\bDROP\\b', '\\bLOAD CSV\\b']
    upper_query = query.upper()
    for pattern in forbidden_keywords:
        if re.search(pattern, upper_query):
            return (jsonify({'error': 'Query validation failed: Mutating commands (CREATE, MERGE, DELETE, etc.) are strictly forbidden in the console.'}), 403)

    def _execute_read(tx, cypher):
        result = tx.run(cypher)
        records = []
        columns = result.keys()
        nodes = []
        node_ids = set()
        links = []

        def _process_node(n):
            if n.element_id not in node_ids:
                node_ids.add(n.element_id)
                props = dict(n)
                nodes.append({'id': n.element_id, 'type': list(n.labels)[0] if n.labels else 'Unknown', 'label': props.get('name') or props.get('attack_id') or props.get('ip') or props.get('campaign_id') or n.element_id, 'props': props})

        def _process_rel(r):
            links.append({'source': r.start_node.element_id, 'target': r.end_node.element_id, 'label': r.type, 'props': dict(r)})
        for record in result:
            row_dict = {}
            for col in columns:
                val = record[col]
                row_dict[col] = str(val) if not isinstance(val, (int, float, bool, type(None))) else val
                if hasattr(val, 'labels'):
                    _process_node(val)
                elif hasattr(val, 'start_node'):
                    _process_rel(val)
                    _process_node(val.start_node)
                    _process_node(val.end_node)
                elif hasattr(val, 'nodes') and hasattr(val, 'relationships'):
                    for n in val.nodes:
                        _process_node(n)
                    for r in val.relationships:
                        _process_rel(r)
            records.append(row_dict)
        return {'columns': columns, 'records': records, 'count': len(records), 'graph': {'nodes': nodes, 'links': links}}
    try:
        with driver.session() as session:
            payload = session.execute_read(_execute_read, query)
            return jsonify(payload)
    except Exception as e:
        return (jsonify({'error': str(e)}), 400)

def _build_graph_response(session, layer, campaign_filter=None, attacker_filter=None):
    campaign_clause = ''
    attacker_clause = ''
    params = {}
    if campaign_filter:
        campaign_clause = 'AND c.campaign_id = $campaign_id'
        params['campaign_id'] = campaign_filter
    if attacker_filter:
        attacker_clause = 'AND a.ip = $attacker_ip'
        params['attacker_ip'] = attacker_filter
    combined_filter = f'{campaign_clause} {attacker_clause}'
    campaign_index_map = {}
    idx_res = session.run('MATCH (c:Campaign) RETURN c.campaign_id AS id ORDER BY c.first_seen ASC')
    for i, row in enumerate(idx_res, start=1):
        campaign_index_map[row['id']] = i
    node_list_query = ''
    links_queries = []
    if layer == 'investigation':
        node_list_query = f"\n        MATCH (c:Campaign)\n        WHERE true {campaign_clause.replace('AND a.ip', 'AND a.ip')}\n        MATCH (c)-[:HAS_EVENT]->(e:AttackEvent)-[:MATCHES]->(t:Technique)\n        OPTIONAL MATCH (t)-[:NEXT_TECHNIQUE]->(n_t:Technique)\n        OPTIONAL MATCH (c)-[:LIKELY_NEXT]->(l_t:Technique)\n        WITH collect(DISTINCT c) + collect(DISTINCT e) + collect(DISTINCT t) + collect(DISTINCT n_t) + collect(DISTINCT l_t) AS node_list\n        UNWIND node_list AS n WITH DISTINCT n WHERE n IS NOT NULL\n        RETURN elementId(n) AS id, labels(n)[0] AS type, properties(n) AS props\n        "
        links_queries.append(f"\n        MATCH (c:Campaign)-[:HAS_EVENT]->(e:AttackEvent)-[:MATCHES]->(t:Technique)\n        WHERE true {campaign_clause}\n        RETURN elementId(c) AS s, elementId(e) AS t, 'HAS_EVENT' AS label, null AS confidence, null AS count, null AS props\n        UNION\n        MATCH (c:Campaign)-[:HAS_EVENT]->(e:AttackEvent)-[:MATCHES]->(t:Technique)\n        WHERE true {campaign_clause}\n        RETURN elementId(e) AS s, elementId(t) AS t, 'MATCHES' AS label, null AS confidence, null AS count, null AS props\n        ")
    elif layer == 'threat_intel':
        node_list_query = f'\n        MATCH (c:Campaign)\n        WHERE true {campaign_clause}\n        OPTIONAL MATCH (c)-[:SIMILAR_TO]->(c2:Campaign)\n        OPTIONAL MATCH (c)-[:RESEMBLES]->(ta:ThreatActor)\n        OPTIONAL MATCH (ta)-[:USES]->(t:Technique)\n        WITH collect(DISTINCT c) + collect(DISTINCT c2) + collect(DISTINCT ta) + collect(DISTINCT t) AS node_list\n        UNWIND node_list AS n WITH DISTINCT n WHERE n IS NOT NULL\n        RETURN elementId(n) AS id, labels(n)[0] AS type, properties(n) AS props\n        '
        links_queries.append(f"\n        MATCH (c:Campaign)-[r:SIMILAR_TO]->(c2:Campaign)\n        WHERE true {campaign_clause}\n        RETURN elementId(c) AS s, elementId(c2) AS t, 'SIMILAR_TO' AS label, r.score AS confidence, null AS count, r AS props\n        UNION\n        MATCH (c:Campaign)-[r:RESEMBLES]->(ta:ThreatActor)\n        WHERE true {campaign_clause}\n        RETURN elementId(c) AS s, elementId(ta) AS t, 'RESEMBLES' AS label, r.confidence AS confidence, null AS count, r AS props\n        UNION\n        MATCH (c:Campaign)-[:RESEMBLES]->(ta:ThreatActor)-[r:USES]->(t:Technique)\n        WHERE true {campaign_clause}\n        RETURN elementId(ta) AS s, elementId(t) AS t, 'USES' AS label, null AS confidence, null AS count, null AS props\n        ")
    else:
        node_list_query = f'\n        MATCH (a:Attacker)-[:LAUNCHED]->(c:Campaign)\n        WHERE true {combined_filter}\n        OPTIONAL MATCH (c)-[:TARGETS]->(h:Host)\n        OPTIONAL MATCH (c)-[:HAS_EVENT]->(:AttackEvent)-[:MATCHES]->(t:Technique)\n        WITH collect(DISTINCT a) + collect(DISTINCT c) + collect(DISTINCT h) + collect(DISTINCT t) AS node_list\n        UNWIND node_list AS n WITH DISTINCT n WHERE n IS NOT NULL\n        RETURN elementId(n) AS id, labels(n)[0] AS type, properties(n) AS props\n        '
        links_queries.append(f"\n        MATCH (a:Attacker)-[:LAUNCHED]->(c:Campaign)\n        WHERE true {combined_filter}\n        RETURN elementId(a) AS s, elementId(c) AS t, 'LAUNCHED' AS label, null AS confidence, null AS count, null AS props\n        UNION\n        MATCH (a:Attacker)-[:LAUNCHED]->(c:Campaign)-[:TARGETS]->(h:Host)\n        WHERE true {combined_filter}\n        RETURN elementId(c) AS s, elementId(h) AS t, 'TARGETS' AS label, null AS confidence, null AS count, null AS props\n        UNION\n        MATCH (a:Attacker)-[:LAUNCHED]->(c:Campaign)-[:HAS_EVENT]->(:AttackEvent)-[:MATCHES]->(t:Technique)\n        WHERE true {combined_filter}\n        RETURN elementId(c) AS s, elementId(t) AS t, 'USES_TECHNIQUE' AS label, null AS confidence, null AS count, null AS props\n        ")
    nodes = []
    node_ids = set()
    for r in session.run(node_list_query, **params):
        props = dict(r['props'] or {})
        n_type = r['type']
        campaign_idx = campaign_index_map.get(props.get('campaign_id')) if n_type == 'Campaign' else None
        nodes.append({'id': r['id'], 'type': n_type, 'label': format_node_label(n_type, props, campaign_idx), 'full_label': props.get('campaign_id') or props.get('name') or props.get('attack_id') or props.get('ip'), 'attack_id': props.get('attack_id'), 'campaign_id': props.get('campaign_id'), 'tps': props.get('tps'), 'description': props.get('description')})
        node_ids.add(r['id'])
    links = []
    for q in links_queries:
        for r in session.run(q, **params):
            if r['s'] in node_ids and r['t'] in node_ids:
                links.append({'source': r['s'], 'target': r['t'], 'label': r['label'], 'confidence': r['confidence'], 'count': r['count'], 'edge_props': dict(r['props'] or {})})
    if layer == 'investigation':
        nt_query = "\n        MATCH (t1:Technique)-[r:NEXT_TECHNIQUE]->(t2:Technique)\n        RETURN elementId(t1) AS s, elementId(t2) AS t, 'NEXT_TECHNIQUE' AS label, null AS confidence, r.count AS count\n        "
        for r in session.run(nt_query):
            if r['s'] in node_ids and r['t'] in node_ids:
                links.append({'source': r['s'], 'target': r['t'], 'label': 'NEXT_TECHNIQUE', 'confidence': r['confidence'], 'count': r['count'], 'edge_props': {}})
        likely_query = f"\n        MATCH (c:Campaign)-[r:LIKELY_NEXT]->(t:Technique)\n        WHERE true {campaign_clause}\n        RETURN elementId(c) AS s, elementId(t) AS t, 'LIKELY_NEXT' AS label, r.confidence AS confidence, null AS count, null AS props\n        "
        for r in session.run(likely_query, **params):
            if r['s'] in node_ids and r['t'] in node_ids:
                links.append({'source': r['s'], 'target': r['t'], 'label': r['label'], 'confidence': r['confidence'], 'count': r['count'], 'edge_props': dict(r['props'] or {})})
    return {'nodes': nodes, 'links': links}

@app.route('/api/analytics/paths')
def analytics_paths():
    with driver.session() as session:
        query = '\n        MATCH (c:Campaign)-[:HAS_EVENT]->(e:AttackEvent)-[:MATCHES]->(t:Technique)\n        WITH c, e, t ORDER BY e.first_seen ASC\n        WITH c, collect(t.attack_id) AS attack_path, collect(coalesce(t.name, t.attack_id)) as attack_path_names\n        WHERE size(attack_path) > 1\n        RETURN attack_path, \n               attack_path_names,\n               count(c) AS frequency, \n               max(c.tps) AS max_raw_tps,\n               collect(c.campaign_id)[0..3] AS example_campaigns\n        ORDER BY frequency DESC, max_raw_tps DESC\n        LIMIT 20\n        '
        logger.info(f'Executing Cypher Query: Analytics Paths\n{query}')
        res = session.run(query)
        paths = []
        for r in res:
            raw_tps = r['max_raw_tps'] or 0
            risk_score = normalize_risk_score(raw_tps)
            paths.append({'path': r['attack_path'], 'path_names': r['attack_path_names'], 'frequency': r['frequency'], 'risk_score': risk_score, 'risk_level': risk_level_from_score(risk_score), 'example_campaigns': r['example_campaigns']})
        return jsonify({'paths': paths})

@app.route('/api/attack-chain')
def attack_chain():
    campaign = request.args.get('campaign')
    with driver.session() as session:
        if campaign:
            result = session.run('\n                MATCH (c:Campaign {campaign_id: $campaign_id})-[:HAS_EVENT]->(e:AttackEvent)-[:MATCHES]->(t:Technique)\n                RETURN t.attack_id AS technique_id, t.name AS name, e.stage AS stage,\n                       e.occurrences AS detection_count, e.tps AS tps, e.first_seen AS first_seen\n                ORDER BY e.first_seen ASC\n            ', campaign_id=campaign)
            chain = []
            for r in result:
                chain.append({'technique_id': r['technique_id'], 'name': r['name'], 'stage': r['stage'], 'detection_count': r['detection_count'], 'tps': r['tps'], 'first_seen': neo4j_datetime_to_iso(r['first_seen'])})
            return jsonify({'campaign_id': campaign, 'chain': chain})
        result = session.run('\n            MATCH (t1:Technique)-[r:NEXT_TECHNIQUE]->(t2:Technique)\n            RETURN t1.attack_id AS from_id, t1.name AS from_name,\n                   t2.attack_id AS to_id, t2.name AS to_name,\n                   r.count AS count\n            ORDER BY r.count DESC LIMIT 50\n        ')
        transitions = []
        total_count = 0
        for r in result:
            c = r['count'] or 0
            total_count += c
            transitions.append({'from': r['from_id'], 'from_name': r['from_name'], 'from_stage': 'Unknown', 'to': r['to_id'], 'to_name': r['to_name'], 'to_stage': 'Unknown', 'count': c, 'confidence': 0.0})
        for t in transitions:
            t['confidence'] = round(t['count'] / max(total_count, 1), 4)
        return jsonify({'transitions': transitions, 'chain': []})

@app.route('/api/predictions')
def predictions():
    with driver.session() as session:
        likely_res = session.run('\n            MATCH (c:Campaign)-[r:LIKELY_NEXT]->(pt:Technique)\n            OPTIONAL MATCH (c)-[:HAS_EVENT]->(e:AttackEvent)-[:MATCHES]->(ct:Technique)\n            WITH c, r, pt, collect(DISTINCT ct)[-1] AS current\n            RETURN c.campaign_id AS campaign_id,\n                   current.attack_id AS current_technique,\n                   current.name AS current_name,\n                   current.stage AS stage,\n                   pt.attack_id AS predicted_technique,\n                   pt.name AS predicted_name,\n                   r.confidence AS confidence,\n                   r.generated_at AS generated_at\n            ORDER BY r.confidence DESC\n        ')
        preds = []
        seen = set()
        for r in likely_res:
            conf = r['confidence'] or 0
            preds.append({'campaign_id': r['campaign_id'], 'current_technique': r['current_technique'] or r['predicted_technique'], 'predicted_technique': r['predicted_technique'], 'confidence': conf, 'risk_level': risk_level_from_score(conf), 'stage': r['stage'], 'generated_at': neo4j_datetime_to_iso(r['generated_at']) or datetime.datetime.now().isoformat(), 'source': 'LIKELY_NEXT'})
            seen.add(r['campaign_id'])
        fallback = session.run('\n            MATCH (c:Campaign)-[:HAS_EVENT]->(e:AttackEvent)-[:MATCHES]->(t:Technique)\n            WITH c, t ORDER BY e.last_seen ASC\n            WITH c, collect(t)[-1] AS latest\n            WHERE NOT c.campaign_id IN $seen\n            RETURN c.campaign_id AS campaign_id, latest.attack_id AS technique_id, latest.stage AS stage\n        ', seen=list(seen))
        for r in fallback:
            pred = prediction_engine.predict_next_readonly(r['technique_id'])
            if pred:
                conf = pred.get('confidence', 0)
                preds.append({'campaign_id': r['campaign_id'], 'current_technique': r['technique_id'], 'predicted_technique': pred.get('predicted', 'UNKNOWN'), 'confidence': conf, 'risk_level': risk_level_from_score(conf), 'stage': r['stage'], 'generated_at': datetime.datetime.now().isoformat(), 'source': 'NEXT_TECHNIQUE'})
        return jsonify({'predictions': preds, 'count': len(preds)})

@app.route('/api/recommendations')
def recommendations():
    tech = request.args.get('technique')
    if tech:
        recs = recommendation_engine.get_recommendations(tech)
        return jsonify({'technique': tech, 'recommendations': recs})
    else:
        with driver.session() as session:
            res = session.run('MATCH (t:Technique) RETURN t.attack_id as t_id LIMIT 10')
            all_recs = []
            for r in res:
                mit = recommendation_engine.get_recommendations(r['t_id'])
                if mit:
                    all_recs.append({'technique_id': r['t_id'], 'recommendations': mit})
            return jsonify({'recommendations': all_recs})

@app.route('/api/predict', methods=['POST'])
def predict():
    data = request.get_json()
    if not data or 'current_technique' not in data:
        return (jsonify({'error': 'Missing current_technique parameter'}), 400)
    technique = data['current_technique']
    result = prediction_engine.predict_next_readonly(technique)
    if result:
        return jsonify(result)
    return jsonify({'current': technique, 'predicted': None, 'confidence': 0})

@app.route('/api/graph')
def graph():
    view_mode = request.args.get('view_mode', 'campaign')
    campaign_filter = request.args.get('campaign')
    attacker_filter = request.args.get('attacker')
    with driver.session() as session:
        return jsonify(_build_graph_response(session, view_mode, campaign_filter, attacker_filter))

def _load_campaign_context(session, campaign_id):
    record = session.run('\n        MATCH (c:Campaign {campaign_id: $campaign_id})\n        OPTIONAL MATCH (a:Attacker)-[:LAUNCHED]->(c)\n        OPTIONAL MATCH (c)-[:TARGETS]->(h:Host)\n        OPTIONAL MATCH (c)-[:HAS_EVENT]->(:AttackEvent)-[:MATCHES]->(t:Technique)\n        OPTIONAL MATCH (c)-[pred:LIKELY_NEXT]->(pt:Technique)\n        WITH c, a, h, collect(DISTINCT t.attack_id) AS techniques,\n             pt.attack_id AS predicted_next, pred.confidence AS prediction_confidence\n        RETURN c, a.ip AS attacker_ip, h.ip AS victim_ip, techniques,\n               predicted_next, prediction_confidence\n        LIMIT 1\n        ', campaign_id=campaign_id).single()
    if record is None or record['c'] is None:
        return None
    c = record['c']
    context = CampaignContext(campaign_id=campaign_id, attacker_ip=record['attacker_ip'] or '', victim_ip=record['victim_ip'] or '', risk_score=c.get('risk_score', 0.0) or 0.0, last_technique=c.get('last_technique'), first_seen=c.get('first_seen').to_native() if c.get('first_seen') else None, last_seen=c.get('last_seen').to_native() if c.get('last_seen') else None, predicted_next=record['predicted_next'], prediction_confidence=record['prediction_confidence'] or 0.0)
    context.techniques = set(record['techniques'] or [])
    context.attack_chain = list(context.techniques)
    return context

def _try_load_campaign_context(campaign_id):
    try:
        with driver.session() as session:
            return (_load_campaign_context(session, campaign_id), None)
    except (ServiceUnavailable, Neo4jError) as e:
        logger.error('Neo4j unavailable while loading campaign %s: %s', campaign_id, e)
        return (None, (jsonify({'error': f'Database unavailable: {e}'}), 503))

@app.route('/api/investigate/<campaign_id>', methods=['POST'])
def investigate_campaign(campaign_id):
    body = request.get_json(silent=True) or {}
    context, error_response = _try_load_campaign_context(campaign_id)
    if error_response:
        return error_response
    if context is None:
        return (jsonify({'error': f'Campaign {campaign_id} not found'}), 404)
    attack_id = body.get('attack_id') or context.last_technique
    if not attack_id:
        return (jsonify({'error': 'No attack_id provided and campaign has no last_technique recorded'}), 400)
    event_id = body.get('event_id', '')
    executor = default_action_executor(context, attack_id, event_id)
    model_predictor = default_model_predictor(context, attack_id, event_id)
    try:
        record = run_investigation(executor, model_predictor=model_predictor, confidence_threshold=float(body.get('confidence_threshold', 0.75)), max_uncertainty=float(body.get('max_uncertainty', 0.4)), max_steps=int(body.get('max_steps', 8)))
    except Exception as e:
        logger.exception('Investigation failed for campaign %s', campaign_id)
        return (jsonify({'error': str(e)}), 500)
    payload = record.to_dict()
    payload['campaign_id'] = campaign_id
    payload['evidence'] = [e.to_dict() for e in record.evidence_store.all()]
    return jsonify(payload)

@app.route('/api/rag/mitre/search', methods=['POST'])
def rag_mitre_search():
    body = request.get_json(silent=True) or {}
    query_text = body.get('query')
    if not query_text:
        return (jsonify({'error': 'Missing query parameter'}), 400)
    top_k = int(body.get('top_k', 5))
    try:
        results = mitre_retriever.query(query_text, top_k=top_k)
    except FileNotFoundError as e:
        return (jsonify({'error': f'MITRE corpus unavailable: {e}'}), 503)
    return jsonify({'query': query_text, 'results': [e.to_dict() for e in results]})

@app.route('/api/gnn/status')
def gnn_status():
    from ml.gnn.inference import gnn_inference_service
    available = gnn_inference_service.available
    metadata = gnn_inference_service.metadata
    return jsonify({'gnn_available': available, 'gnn_model_version': metadata.model_version if metadata else None, 'gnn_metadata': metadata.to_dict() if metadata else None})

@app.route('/api/gnn/topology/<campaign_id>')
def gnn_topology(campaign_id):
    top_k = int(request.args.get('top_k', 5))
    context, error_response = _try_load_campaign_context(campaign_id)
    if error_response:
        return error_response
    if context is None:
        return (jsonify({'error': f'Campaign {campaign_id} not found'}), 404)
    from ml.gnn.inference import gnn_inference_service
    if not gnn_inference_service.available:
        return jsonify({'campaign_id': campaign_id, 'gnn_available': False, 'topology_neighbors': []})
    from rag.gnn_topology_retriever import GNNTopologyRetriever
    try:
        results = GNNTopologyRetriever().query(campaign_id, top_k=top_k)
    except Exception as e:
        logger.exception('GNN topology retrieval failed for campaign %s', campaign_id)
        return (jsonify({'error': str(e)}), 500)
    return jsonify({'campaign_id': campaign_id, 'gnn_available': True, 'gnn_model_version': gnn_inference_service.metadata.model_version, 'topology_neighbors': [e.to_dict() for e in results]})

@app.route('/api/rag/search', methods=['POST'])
def rag_search():
    body = request.get_json(silent=True) or {}
    query_text = body.get('query')
    campaign_id = body.get('campaign_id')
    top_k = int(body.get('top_k', 5))
    if not query_text and (not campaign_id):
        return (jsonify({'error': 'Provide at least one of: query, campaign_id'}), 400)
    sources = {}
    if query_text:
        try:
            mitre_results = mitre_retriever.query(query_text, top_k=top_k)
            sources['mitre_knowledge'] = [e.to_dict() for e in mitre_results]
        except Exception as e:
            logger.exception('rag_search: MITRE retrieval failed')
            sources['mitre_knowledge'] = {'error': str(e)}
        try:
            from rag.campaign_retriever import CampaignNarrativeRetriever
            narrative_results = CampaignNarrativeRetriever().query(query_text, top_k=top_k)
            sources['campaign_history'] = [e.to_dict() for e in narrative_results]
        except Exception as e:
            logger.exception('rag_search: campaign narrative retrieval failed')
            sources['campaign_history'] = {'error': str(e)}
    if campaign_id:
        from ml.gnn.inference import gnn_inference_service
        if not gnn_inference_service.available:
            sources['gnn_topology'] = {'gnn_available': False, 'results': []}
        else:
            try:
                from rag.gnn_topology_retriever import GNNTopologyRetriever
                gnn_results = GNNTopologyRetriever().query(campaign_id, top_k=top_k)
                sources['gnn_topology'] = {'gnn_available': True, 'results': [e.to_dict() for e in gnn_results]}
            except Exception as e:
                logger.exception('rag_search: GNN topology retrieval failed')
                sources['gnn_topology'] = {'error': str(e)}
    return jsonify({'query': query_text, 'campaign_id': campaign_id, 'sources': sources})

@app.route('/api/misp/status')
def misp_status():
    import config
    credential_configured = bool(config.MISP_API_KEY)
    result = {'misp_url': config.MISP_URL, 'credential_configured': credential_configured, 'authenticated': False, 'cached_campaigns': 0, 'campaign_event_map': {}}
    if not credential_configured:
        result['status_message'] = 'MISP publication requires configured authentication (MISP_API_KEY is not set).'
        return jsonify(result)
    try:
        from cti_publisher import CTIPublisher
        from misp_cache import cache as misp_cache
        publisher = CTIPublisher(config.MISP_URL, config.MISP_API_KEY, verify_ssl=config.VERIFY_MISP_SSL)
        result['authenticated'] = publisher.health_check()
        stats = misp_cache.all()
        result['cached_campaigns'] = len(stats)
        result['campaign_event_map'] = stats
        result['status_message'] = 'Connected' if result['authenticated'] else 'Credential configured but MISP is unreachable or rejected the request.'
    except Exception as e:
        logger.exception('MISP status check failed')
        result['status_message'] = f'MISP status check failed: {e}'
    return jsonify(result)

@app.route('/api/system/health')
def system_health():
    import config
    subsystems = {}
    try:
        driver.verify_connectivity()
        subsystems['neo4j'] = {'status': 'connected'}
    except Exception as e:
        subsystems['neo4j'] = {'status': 'disconnected', 'detail': str(e)}
    xgb_path = os.path.join(os.path.dirname(__file__), 'ml', 'models', 'xgb_severity.json')
    if os.path.exists(xgb_path):
        subsystems['xgboost_severity'] = {'status': 'available', 'model_path': xgb_path, 'modified': datetime.datetime.fromtimestamp(os.path.getmtime(xgb_path), tz=datetime.timezone.utc).isoformat()}
    else:
        subsystems['xgboost_severity'] = {'status': 'not_trained'}
    try:
        from ml.gnn.inference import gnn_inference_service
        if config.GNN_ENABLED:
            available = gnn_inference_service.available
            subsystems['gnn'] = {'status': 'available' if available else 'enabled_but_unavailable', 'model_version': gnn_inference_service.metadata.model_version if available else None}
        else:
            subsystems['gnn'] = {'status': 'disabled'}
    except Exception as e:
        subsystems['gnn'] = {'status': 'error', 'detail': str(e)}
    credential_configured = bool(config.MISP_API_KEY)
    subsystems['misp'] = {'status': 'credential_configured' if credential_configured else 'credential_missing'}
    if os.path.exists(LISTENER_LOG_PATH):
        age_seconds = datetime.datetime.now().timestamp() - os.path.getmtime(LISTENER_LOG_PATH)
        subsystems['wazuh_listener'] = {'status': 'recently_active' if age_seconds < 300 else 'idle', 'log_last_modified_seconds_ago': round(age_seconds, 1)}
    else:
        subsystems['wazuh_listener'] = {'status': 'no_log_found'}
    overall_ok = subsystems['neo4j']['status'] == 'connected'
    return jsonify({'status': 'healthy' if overall_ok else 'degraded', 'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'subsystems': subsystems})

@app.route('/api/system/config-snapshot')
def system_config_snapshot():
    from config_snapshot import get_safe_config_snapshot
    return jsonify(get_safe_config_snapshot())

@app.route('/api/audit/logs')
def audit_logs():
    limit = min(int(request.args.get('limit', 200)), 2000)
    log_path = LISTENER_LOG_PATH
    if not os.path.exists(log_path):
        return jsonify({'entries': [], 'total_lines': 0, 'log_path': log_path})
    with open(log_path, 'r', errors='replace') as f:
        lines = f.readlines()
    total_lines = len(lines)
    tail = lines[-limit:]
    entries = []
    for line in tail:
        line = line.rstrip('\n')
        if not line:
            continue
        parts = line.split(' | ', 2)
        if len(parts) == 3:
            entries.append({'timestamp': parts[0], 'level': parts[1], 'message': parts[2]})
        else:
            entries.append({'timestamp': None, 'level': None, 'message': line})
    return jsonify({'entries': entries, 'total_lines': total_lines, 'log_path': log_path})

def _build_threat_qualification(campaign_id, context, session):
    row = session.run('MATCH (c:Campaign {campaign_id: $id}) RETURN c.cti_score AS score, c.cti_publish AS publish', id=campaign_id).single()
    from cti_confidence_engine import NOT_THREAT_THRESHOLD, PUBLISH_THRESHOLD
    from threat_qualification import engine as qualification_engine, NOT_THREAT, SUSPICIOUS, QUALIFIED_THREAT
    incident_like = types.SimpleNamespace(campaign_id=campaign_id, attacker_ip=context.attacker_ip, technique=context.last_technique, timestamp=context.last_seen.isoformat() if context.last_seen else None, cti=None)
    score = row['score'] if row else None
    if score is not None:
        if score >= PUBLISH_THRESHOLD:
            classification = QUALIFIED_THREAT
        elif score >= NOT_THREAT_THRESHOLD:
            classification = SUSPICIOUS
        else:
            classification = NOT_THREAT
        incident_like.cti = types.SimpleNamespace(threat_classification=classification, score=score)
    return qualification_engine.qualify(incident_like)

@app.route('/api/threat-qualification/<campaign_id>')
def threat_qualification_view(campaign_id):
    context, error_response = _try_load_campaign_context(campaign_id)
    if error_response:
        return error_response
    if context is None:
        return (jsonify({'error': f'Campaign {campaign_id} not found'}), 404)
    try:
        with driver.session() as session:
            result = _build_threat_qualification(campaign_id, context, session)
    except (ServiceUnavailable, Neo4jError) as e:
        return (jsonify({'error': f'Database unavailable: {e}'}), 503)
    return jsonify(result.to_dict())

def _discover_campaign_selection_candidates(campaign_id, session):
    rows = session.run('\n        MATCH (c1:Campaign {campaign_id: $campaign_id})\n        MATCH (c2:Campaign) WHERE c1 <> c2\n        OPTIONAL MATCH (c1)-[:HAS_EVENT]->(:AttackEvent)-[:MATCHES]->(t1:Technique)\n        OPTIONAL MATCH (c2)-[:HAS_EVENT]->(:AttackEvent)-[:MATCHES]->(t2:Technique)\n        OPTIONAL MATCH (a1:Attacker)-[:LAUNCHED]->(c1)\n        OPTIONAL MATCH (a2:Attacker)-[:LAUNCHED]->(c2)\n        WITH c2, collect(DISTINCT t1.attack_id) AS t1s, collect(DISTINCT t2.attack_id) AS t2s,\n             collect(DISTINCT a1.ip) AS a1s, collect(DISTINCT a2.ip) AS a2s\n        WHERE any(t IN t1s WHERE t IN t2s) OR any(a IN a1s WHERE a IN a2s)\n        RETURN DISTINCT c2.campaign_id AS campaign_id LIMIT 10\n        ', campaign_id=campaign_id)
    return [r['campaign_id'] for r in rows]

def _build_campaign_selection(campaign_id, context, session):
    from campaign_selection import selector, build_candidates_from_campaigns
    from soar.memory import memory_store
    candidate_ids = _discover_campaign_selection_candidates(campaign_id, session)
    candidates = build_candidates_from_campaigns(context, candidate_ids, session, memory_store=memory_store)
    return selector.select(candidates)

@app.route('/api/campaign-selection/<campaign_id>')
def campaign_selection_view(campaign_id):
    context, error_response = _try_load_campaign_context(campaign_id)
    if error_response:
        return error_response
    if context is None:
        return (jsonify({'error': f'Campaign {campaign_id} not found'}), 404)
    try:
        with driver.session() as session:
            result = _build_campaign_selection(campaign_id, context, session)
    except (ServiceUnavailable, Neo4jError) as e:
        return (jsonify({'error': f'Database unavailable: {e}'}), 503)
    return jsonify({'campaign_id': campaign_id, **result.to_dict()})

@app.route('/api/incidents/<campaign_id>/overview')
def incident_overview(campaign_id):
    context, error_response = _try_load_campaign_context(campaign_id)
    if error_response:
        return error_response
    if context is None:
        return (jsonify({'error': f'Campaign {campaign_id} not found'}), 404)
    from risk_scoring import severity_from_tps
    from mitre_resolver import enrich_technique_metadata, MitreResolution
    try:
        with driver.session() as session:
            operation_row = session.run('MATCH (o:Operation)-[:HAS_CAMPAIGN]->(c:Campaign {campaign_id: $id}) RETURN o.operation_id AS operation_id', id=campaign_id).single()
            threat_qualification = _build_threat_qualification(campaign_id, context, session)
            campaign_selection = _build_campaign_selection(campaign_id, context, session)
    except (ServiceUnavailable, Neo4jError) as e:
        return (jsonify({'error': f'Database unavailable: {e}'}), 503)
    techniques = sorted(context.techniques) if context.techniques else [context.last_technique] if context.last_technique else []
    mitre_resolution = MitreResolution(technique_ids=tuple(techniques), provenance='AGGREGATED_FROM_CAMPAIGN_RECORD', confidence='N/A', reason="Techniques observed across this campaign's real, already-resolved events.")
    mitre = enrich_technique_metadata(mitre_resolution) if techniques else []
    from soar.memory import memory_store
    playbooks = [p.to_dict() for p in memory_store.list_playbooks() if p.source_campaign_id == campaign_id]
    executions = [e.to_dict() for e in memory_store.executions_for_campaign(campaign_id)]
    try:
        from ml.gnn.inference import gnn_inference_service
        gnn_status = {'gnn_available': gnn_inference_service.available, 'gnn_model_version': gnn_inference_service.metadata.model_version if gnn_inference_service.available else None}
    except Exception:
        gnn_status = {'gnn_available': False, 'gnn_model_version': None}
    return jsonify({'campaign': {'campaign_id': context.campaign_id, 'attacker_ip': context.attacker_ip, 'victim_ip': context.victim_ip, 'status': context.status, 'first_seen': context.first_seen.isoformat() if context.first_seen else None, 'last_seen': context.last_seen.isoformat() if context.last_seen else None, 'last_technique': context.last_technique, 'techniques': techniques, 'risk_score': context.risk_score, 'predicted_next': context.predicted_next, 'prediction_confidence': context.prediction_confidence}, 'operation_id': operation_row['operation_id'] if operation_row else None, 'mitre': mitre, 'severity': {'label': severity_from_tps(context.risk_score), 'risk_score': context.risk_score}, 'threat_qualification': threat_qualification.to_dict(), 'campaign_selection': campaign_selection.to_dict(), 'gnn': gnn_status, 'soar': {'playbooks': playbooks, 'executions': executions}, 'investigation_available': True, 'rag_available': True})

@app.route('/api/incidents/<campaign_id>/response-plan')
def incident_response_plan(campaign_id):
    context, error_response = _try_load_campaign_context(campaign_id)
    if error_response:
        return error_response
    if context is None:
        return (jsonify({'error': f'Campaign {campaign_id} not found'}), 404)
    from soar.generator import PlaybookGenerator
    from soar.memory import memory_store
    from soar.response_plan import response_plan_generator
    try:
        with driver.session() as session:
            qualification = _build_threat_qualification(campaign_id, context, session)
            selection = _build_campaign_selection(campaign_id, context, session)
    except (ServiceUnavailable, Neo4jError) as e:
        return (jsonify({'error': f'Database unavailable: {e}'}), 503)
    existing = [p for p in memory_store.list_playbooks() if p.source_campaign_id == campaign_id]
    playbook = existing[0] if existing else PlaybookGenerator().generate(context)
    plan = response_plan_generator.generate(context, playbook=playbook, qualification=qualification, selection=selection)
    return jsonify(plan.to_dict())

@app.route('/api/ml/predict/severity', methods=['POST'])
def ml_predict_severity():
    body = request.get_json(silent=True) or {}
    campaign_id = body.get('campaign_id')
    if not campaign_id:
        return (jsonify({'error': 'Missing campaign_id parameter'}), 400)
    model_path = os.path.join(os.path.dirname(__file__), 'ml', 'models', 'xgb_severity.json')
    if not os.path.exists(model_path):
        return (jsonify({'error': 'No trained severity model available yet. The XGBoost classifier trains on real resolved-campaign records (ml.dataset_builder) — see ml/train_xgboost.py.'}), 503)
    context, error_response = _try_load_campaign_context(campaign_id)
    if error_response:
        return error_response
    if context is None:
        return (jsonify({'error': f'Campaign {campaign_id} not found'}), 404)
    attack_id = body.get('attack_id') or context.last_technique
    if not attack_id:
        return (jsonify({'error': 'No attack_id provided and campaign has no last_technique recorded'}), 400)
    try:
        from ml.runtime_predictor import RuntimeCampaignPredictor
        predictor = RuntimeCampaignPredictor.from_model_path(model_path)
        result = predictor.predict_for_campaign(context, attack_id, body.get('event_id', ''))
    except Exception as e:
        logger.exception('Severity prediction failed for campaign %s', campaign_id)
        return (jsonify({'error': str(e)}), 500)
    return jsonify({'campaign_id': campaign_id, **result})
if __name__ == '__main__':
    if socketio is not None:
        logger.info('Starting CYUKTI dashboard with WebSocket support on port 5002')
        socketio.run(app, host='0.0.0.0', port=5002, allow_unsafe_werkzeug=True)
    else:
        logger.warning('SocketIO not initialized, starting without WebSocket support')
        app.run(host='0.0.0.0', port=5002, threaded=True)