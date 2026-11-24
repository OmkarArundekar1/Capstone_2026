import logging
from flask import Blueprint, jsonify, request
from datetime import datetime
from typing import Optional, Dict, Any
logger = logging.getLogger(__name__)
containment_bp = Blueprint('containment', __name__, url_prefix='/api/containment')
PROTECTED_IPS = {'127.0.0.1', 'localhost'}
AUTO_BLOCK_ENABLED = False
AUTO_BLOCK_MIN_CONFIDENCE = 95.0
AUTO_BLOCK_MIN_SEVERITY = 'HIGH'
AUTO_BLOCK_TTL_SECONDS = 3600
AUTO_BLOCK_REQUIRE_VALIDATED_ATTACK = True

def is_ip_protected(ip: str) -> bool:
    return ip in PROTECTED_IPS or ip.startswith('127.') or ip == '0.0.0.0'

def validate_ip_address(ip: str) -> bool:
    import ipaddress
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ValueError:
        return False

def get_event_from_neo4j(event_id: str) -> Optional[Dict[str, Any]]:
    from neo4j_client import driver
    try:
        with driver.session() as session:
            result = session.run('\n                MATCH (ae:AttackEvent)\n                WHERE elementId(ae) = $event_id\n                OPTIONAL MATCH (a:Attacker)-[:LAUNCHED]->(c:Campaign)-[:HAS_EVENT]->(ae)\n                OPTIONAL MATCH (c)-[:TARGETS]->(h:Host)\n                RETURN \n                    ae.event_id as event_id,\n                    a.ip as attacker_ip,\n                    h.ip as victim_ip,\n                    ae.tps as tps,\n                    ae.stage as stage,\n                    c.campaign_id as campaign_id\n            ', event_id=event_id)
            record = result.single()
            if not record:
                return None
            return {'event_id': record['event_id'], 'attacker_ip': record['attacker_ip'], 'victim_ip': record['victim_ip'], 'tps': record.get('tps', 0), 'stage': record.get('stage'), 'campaign_id': record.get('campaign_id')}
    except Exception as e:
        logger.error(f'Failed to retrieve event {event_id}: {e}')
        return None

@containment_bp.route('/block', methods=['POST'])
def request_block():
    try:
        data = request.get_json()
        if not data:
            return (jsonify({'error': 'Request body required'}), 400)
        event_id = data.get('event_id')
        if not event_id:
            return (jsonify({'error': 'event_id required'}), 400)
        operator = data.get('operator', 'unknown')
        reason = data.get('reason', 'manual')
        ttl_seconds = data.get('ttl_seconds', AUTO_BLOCK_TTL_SECONDS)
        event = get_event_from_neo4j(event_id)
        if not event:
            return (jsonify({'error': f'Event {event_id} not found', 'status': 'REJECTED'}), 404)
        attacker_ip = event['attacker_ip']
        if not attacker_ip:
            return (jsonify({'error': 'Event has no attacker IP', 'status': 'REJECTED'}), 400)
        if not validate_ip_address(attacker_ip):
            return (jsonify({'error': f'Invalid IP address: {attacker_ip}', 'status': 'REJECTED'}), 400)
        if is_ip_protected(attacker_ip):
            logger.warning(f'Rejected containment request for protected IP {attacker_ip}')
            return (jsonify({'error': f'IP {attacker_ip} is protected and cannot be blocked', 'status': 'REJECTED', 'reason': 'protected_infrastructure'}), 403)
        correlation_id = event.get('campaign_id') or event_id
        try:
            from active_response.integration import initiate_containment_for_campaign
            from active_response.containment_actions import ContainmentAction
            result = initiate_containment_for_campaign(correlation_id=correlation_id, target_ip=attacker_ip, action=ContainmentAction.BLOCK_SOURCE_IP, trigger='manual', operator=operator, ttl_seconds=ttl_seconds)
            success = result.containment_status == 'EXECUTED'
            status = result.containment_status
            verified = result.independently_reconfirmed
            try:
                from websocket_events import emit_response_status_update
                emit_response_status_update(event_id=event_id, attacker_ip=attacker_ip, response_status='BLOCKED' if success else 'FAILED', response_action='block_ip', operator=operator, verified=verified, timestamp=datetime.utcnow().isoformat())
            except Exception as ws_error:
                logger.error(f'WebSocket emission failed: {ws_error}')
            return (jsonify({'success': success, 'event_id': event_id, 'attacker_ip': attacker_ip, 'status': status, 'verification': 'confirmed' if verified else 'not_verified', 'rule_reference': result.rule_reference, 'timestamp': result.executed_at, 'expires_at': result.expires_at}), 200 if success else 500)
        except Exception as e:
            logger.exception(f'Containment execution failed for {attacker_ip}: {e}')
            return (jsonify({'error': str(e), 'status': 'FAILED', 'event_id': event_id, 'attacker_ip': attacker_ip}), 500)
    except Exception as e:
        logger.exception('Block request handler failed')
        return (jsonify({'error': 'Internal server error'}), 500)

@containment_bp.route('/unblock', methods=['POST'])
def request_unblock():
    try:
        data = request.get_json()
        if not data:
            return (jsonify({'error': 'Request body required'}), 400)
        attacker_ip = data.get('attacker_ip')
        if not attacker_ip:
            return (jsonify({'error': 'attacker_ip required'}), 400)
        operator = data.get('operator', 'unknown')
        if not validate_ip_address(attacker_ip):
            return (jsonify({'error': f'Invalid IP: {attacker_ip}'}), 400)
        try:
            from active_response.rollback import rollback_containment
            result = rollback_containment(target_ip=attacker_ip, operator=operator)
            success = result.get('success', False)
            try:
                from websocket_events import emit_response_status_update
                emit_response_status_update(event_id='rollback', attacker_ip=attacker_ip, response_status='UNBLOCKED' if success else 'FAILED', response_action='unblock_ip', operator=operator, timestamp=datetime.utcnow().isoformat())
            except Exception as ws_error:
                logger.error(f'WebSocket emission failed: {ws_error}')
            return (jsonify({'success': success, 'attacker_ip': attacker_ip, 'status': 'UNBLOCKED' if success else 'FAILED', 'timestamp': datetime.utcnow().isoformat()}), 200 if success else 500)
        except Exception as e:
            logger.exception(f'Unblock execution failed for {attacker_ip}: {e}')
            return (jsonify({'error': str(e), 'status': 'FAILED', 'attacker_ip': attacker_ip}), 500)
    except Exception as e:
        logger.exception('Unblock request handler failed')
        return (jsonify({'error': 'Internal server error'}), 500)

@containment_bp.route('/status/<event_id>', methods=['GET'])
def containment_status(event_id: str):
    try:
        event = get_event_from_neo4j(event_id)
        if not event:
            return (jsonify({'error': 'Event not found'}), 404)
        campaign_id = event.get('campaign_id')
        if not campaign_id:
            return jsonify({'event_id': event_id, 'status': 'NOT_REQUESTED', 'audit_trail': []})
        try:
            from active_response.audit import audit_trail_for_correlation
            events = audit_trail_for_correlation(campaign_id)
            if not events:
                status = 'NOT_REQUESTED'
            elif any((e['event_type'] == 'CONTAINMENT_EXECUTED' for e in events)):
                if any((e['event_type'] == 'ROLLBACK_VERIFIED' for e in events)):
                    status = 'UNBLOCKED'
                else:
                    status = 'BLOCKED'
            elif any((e['event_type'] == 'CONTAINMENT_FAILED' for e in events)):
                status = 'FAILED'
            else:
                status = 'PENDING'
            return jsonify({'event_id': event_id, 'attacker_ip': event['attacker_ip'], 'status': status, 'audit_trail': events})
        except Exception as e:
            logger.error(f'Failed to retrieve audit trail: {e}')
            return (jsonify({'event_id': event_id, 'status': 'UNKNOWN', 'error': str(e)}), 500)
    except Exception as e:
        logger.exception('Status lookup failed')
        return (jsonify({'error': 'Internal server error'}), 500)