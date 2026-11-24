import logging
import json
from datetime import datetime
from threading import Lock
from collections import OrderedDict
from typing import Optional, Dict, Any
logger = logging.getLogger(__name__)
socketio = None
_emitted_events = OrderedDict()
_emitted_events_lock = Lock()
MAX_EMITTED_CACHE = 1000

def initialize_socketio(app, cors_allowed_origins='*'):
    global socketio
    if socketio is not None:
        logger.warning('SocketIO already initialized')
        return socketio
    try:
        from flask_socketio import SocketIO
        from flask import request as flask_request
        socketio = SocketIO(app, cors_allowed_origins=cors_allowed_origins, logger=False, engineio_logger=False, ping_timeout=60, ping_interval=25)

        @socketio.on('connect')
        def handle_connect():
            try:
                sid = flask_request.sid if hasattr(flask_request, 'sid') else 'unknown'
                logger.info(f'Client connected: {sid}')
            except:
                logger.info('Client connected')

        @socketio.on('disconnect')
        def handle_disconnect():
            try:
                sid = flask_request.sid if hasattr(flask_request, 'sid') else 'unknown'
                logger.info(f'Client disconnected: {sid}')
            except:
                logger.info('Client disconnected')

        @socketio.on('subscribe_events')
        def handle_subscribe(data):
            client_id = data.get('client', 'unknown')
            logger.info(f'Client subscribed to events: {client_id}')
            return {'status': 'subscribed', 'timestamp': datetime.utcnow().isoformat()}
        logger.info('SocketIO initialized successfully')
        return socketio
    except Exception as e:
        logger.exception(f'Failed to initialize SocketIO: {e}')
        return None

def emit_attack_event(event_id: str, campaign_id: Optional[str], attacker_ip: str, victim_ip: str, technique_id: Optional[str], technique_name: Optional[str], rule_id: str, severity: str, stage: Optional[str], timestamp: str, agent_name: Optional[str]=None, confidence: Optional[float]=None, operation_id: Optional[str]=None, risk_score: Optional[float]=None, **kwargs):
    global socketio
    if socketio is None:
        logger.debug('SocketIO not initialized, skipping event emission')
        return False
    with _emitted_events_lock:
        if event_id in _emitted_events:
            logger.debug(f'Event {event_id} already emitted, skipping duplicate')
            return True
        _emitted_events[event_id] = datetime.utcnow()
        if len(_emitted_events) > MAX_EMITTED_CACHE:
            _emitted_events.popitem(last=False)
    try:
        payload = {'id': event_id, 'event_type': 'attack_detected', 'timestamp': timestamp, 'attacker_ip': attacker_ip, 'victim_ip': victim_ip, 'technique_id': technique_id or 'UNKNOWN', 'technique_name': technique_name or 'Unknown Technique', 'rule_id': rule_id, 'severity': severity, 'stage': stage or 'Unknown', 'campaign_id': campaign_id, 'operation_id': operation_id, 'agent_name': agent_name, 'confidence': confidence, 'risk_score': risk_score, 'response_status': 'NOT_REQUESTED'}
        if kwargs:
            payload['metadata'] = kwargs
        socketio.emit('new_events', {'events': [payload]}, namespace='/')
        logger.debug(f'Emitted attack event {event_id} to WebSocket clients')
        return True
    except Exception as e:
        logger.error(f'Failed to emit event {event_id}: {e}', exc_info=True)
        return False

def emit_response_status_update(event_id: str, attacker_ip: str, response_status: str, response_action: Optional[str]=None, timestamp: Optional[str]=None, **kwargs):
    global socketio
    if socketio is None:
        logger.debug('SocketIO not initialized, skipping status update')
        return False
    try:
        payload = {'event_id': event_id, 'event_type': 'response_status_update', 'attacker_ip': attacker_ip, 'response_status': response_status, 'response_action': response_action, 'timestamp': timestamp or datetime.utcnow().isoformat()}
        if kwargs:
            payload.update(kwargs)
        socketio.emit('response_status_update', payload, namespace='/')
        logger.info(f'Emitted response status update for {event_id}: {response_status}')
        return True
    except Exception as e:
        logger.error(f'Failed to emit response status for {event_id}: {e}', exc_info=True)
        return False

def get_connection_count() -> int:
    global socketio
    if socketio is None:
        return 0
    try:
        return -1
    except:
        return 0