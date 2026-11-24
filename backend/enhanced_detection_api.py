from __future__ import annotations
import logging
from flask import Blueprint, jsonify, request
from intelligent_detection_system import get_detection_system
from hybrid_threat_enrichment import get_enricher
from threat_enrichment_integration import enrich_and_update_attacker, get_attacker_enrichment, bulk_enrich_attackers, generate_threat_report, enrichment_health_check
from action_approval_system import get_approval_manager
logger = logging.getLogger(__name__)
enhanced_detection_bp = Blueprint('enhanced_detection', __name__, url_prefix='/api/enhanced')

@enhanced_detection_bp.route('/health', methods=['GET'])
def health():
    try:
        detection_system = get_detection_system()
        health_status = detection_system.health_check()
        return jsonify({'status': 'healthy', 'components': health_status})
    except Exception as e:
        logger.exception(f'Health check failed: {e}')
        return (jsonify({'status': 'unhealthy', 'error': str(e)}), 500)

@enhanced_detection_bp.route('/enrich/ip/<ip>', methods=['POST'])
def enrich_ip(ip: str):
    try:
        async_mode = request.args.get('async', 'false').lower() == 'true'
        enriched = enrich_and_update_attacker(ip, async_mode=async_mode)
        if async_mode:
            return jsonify({'success': True, 'message': f'Enrichment queued for {ip}', 'async': True})
        else:
            return jsonify({'success': True, 'ip': ip, 'enrichment': enriched.to_dict() if enriched else None})
    except Exception as e:
        logger.exception(f'Enrichment failed for {ip}: {e}')
        return (jsonify({'success': False, 'error': str(e)}), 500)

@enhanced_detection_bp.route('/enrich/ip/<ip>', methods=['GET'])
def get_enrichment(ip: str):
    try:
        enrichment = get_attacker_enrichment(ip)
        if not enrichment:
            return (jsonify({'success': False, 'error': f'No enrichment data found for {ip}'}), 404)
        return jsonify({'success': True, 'enrichment': enrichment})
    except Exception as e:
        logger.exception(f'Failed to get enrichment for {ip}: {e}')
        return (jsonify({'success': False, 'error': str(e)}), 500)

@enhanced_detection_bp.route('/enrich/bulk', methods=['POST'])
def bulk_enrich():
    try:
        body = request.get_json() or {}
        limit = body.get('limit', 100)
        stats = bulk_enrich_attackers(limit=limit)
        return jsonify({'success': True, 'stats': stats})
    except Exception as e:
        logger.exception(f'Bulk enrichment failed: {e}')
        return (jsonify({'success': False, 'error': str(e)}), 500)

@enhanced_detection_bp.route('/threat-report/<ip>', methods=['GET'])
def threat_report(ip: str):
    try:
        report = generate_threat_report(ip)
        return jsonify({'success': True, 'report': report})
    except Exception as e:
        logger.exception(f'Failed to generate threat report for {ip}: {e}')
        return (jsonify({'success': False, 'error': str(e)}), 500)

@enhanced_detection_bp.route('/actions/pending', methods=['GET'])
def pending_actions():
    try:
        approval_manager = get_approval_manager()
        actions = approval_manager.get_pending_actions()
        return jsonify({'success': True, 'count': len(actions), 'actions': [a.to_dict() for a in actions]})
    except Exception as e:
        logger.exception(f'Failed to get pending actions: {e}')
        return (jsonify({'success': False, 'error': str(e)}), 500)

@enhanced_detection_bp.route('/actions/<action_id>/approve', methods=['POST'])
def approve_action(action_id: str):
    try:
        body = request.get_json() or {}
        approved_by = body.get('approved_by', 'api_user')
        execute_immediately = body.get('execute_immediately', True)
        approval_manager = get_approval_manager()
        execution = approval_manager.approve_action(action_id, approved_by=approved_by, execute_immediately=execute_immediately)
        if not execution and (not execute_immediately):
            return jsonify({'success': True, 'message': 'Action approved but not executed yet'})
        if not execution:
            return (jsonify({'success': False, 'error': f'Action {action_id} not found'}), 404)
        return jsonify({'success': True, 'execution': execution.to_dict()})
    except Exception as e:
        logger.exception(f'Failed to approve action {action_id}: {e}')
        return (jsonify({'success': False, 'error': str(e)}), 500)

@enhanced_detection_bp.route('/actions/<action_id>/reject', methods=['POST'])
def reject_action(action_id: str):
    try:
        body = request.get_json() or {}
        rejected_by = body.get('rejected_by', 'api_user')
        reason = body.get('reason', '')
        approval_manager = get_approval_manager()
        success = approval_manager.reject_action(action_id, rejected_by=rejected_by, reason=reason)
        if not success:
            return (jsonify({'success': False, 'error': f'Action {action_id} not found'}), 404)
        return jsonify({'success': True, 'message': f'Action {action_id} rejected'})
    except Exception as e:
        logger.exception(f'Failed to reject action {action_id}: {e}')
        return (jsonify({'success': False, 'error': str(e)}), 500)

@enhanced_detection_bp.route('/execution-history', methods=['GET'])
def execution_history():
    try:
        target = request.args.get('target')
        limit = int(request.args.get('limit', 100))
        detection_system = get_detection_system()
        history = detection_system.get_execution_history(target=target, limit=limit)
        return jsonify({'success': True, 'count': len(history), 'history': [e.to_dict() for e in history]})
    except Exception as e:
        logger.exception(f'Failed to get execution history: {e}')
        return (jsonify({'success': False, 'error': str(e)}), 500)

@enhanced_detection_bp.route('/cache/stats', methods=['GET'])
def cache_stats():
    try:
        enricher = get_enricher()
        stats = enricher.cache.stats()
        return jsonify({'success': True, 'cache_stats': stats})
    except Exception as e:
        logger.exception(f'Failed to get cache stats: {e}')
        return (jsonify({'success': False, 'error': str(e)}), 500)

@enhanced_detection_bp.route('/cache/clear', methods=['POST'])
def clear_cache():
    try:
        enricher = get_enricher()
        enricher.cache.clear()
        return jsonify({'success': True, 'message': 'Cache cleared'})
    except Exception as e:
        logger.exception(f'Failed to clear cache: {e}')
        return (jsonify({'success': False, 'error': str(e)}), 500)

@enhanced_detection_bp.route('/config', methods=['GET'])
def get_config():
    try:
        detection_system = get_detection_system()
        return jsonify({'success': True, 'config': {'auto_enrich': detection_system.auto_enrich, 'auto_execute_safe_actions': detection_system.auto_execute_safe_actions, 'dry_run': detection_system.dry_run}})
    except Exception as e:
        logger.exception(f'Failed to get config: {e}')
        return (jsonify({'success': False, 'error': str(e)}), 500)