"""
from transition_learner import learner as transition_learner
from wazuh_rule_mapper import get_technique_for_alert
"""
'\n        # Existing code:\n        resolution = resolve_mitre(alert)\n        \n        # ADD THIS:\n        # If Wazuh didn\'t provide ATT&CK label, try our mapping\n        if resolution.provenance == PROVENANCE_UNKNOWN:\n            mapped_technique = get_technique_for_alert(alert)\n            if mapped_technique:\n                logger.info(\n                    f"[MAPPER] Mapped rule {rule_id} -> {mapped_technique} "\n                    f"(was UNKNOWN)"\n                )\n                # Re-resolve with mapped technique\n                # Note: This is a simplified example - actual integration\n                # would need to construct proper resolution object\n                # For now, continue with UNKNOWN but log the mapping\n                logger.info(\n                    f"[MAPPER] Would map to {mapped_technique} - "\n                    f"full integration requires resolver updates"\n                )\n'
'\n        # Existing code:\n        transition = campaign_manager.get_or_create_campaign_with_transition(\n            attacker_ip,\n            victim_ip,\n            mitre_id,\n            event_time=event_time.value\n        )\n        campaign_id = transition.campaign_id\n        \n        # ADD THIS IMMEDIATELY AFTER:\n        # Record attacker activity for cross-campaign transition learning\n        # This runs regardless of whether campaign continued or split\n        if mitre_id != "UNKNOWN":\n            transition_learner.record_attacker_activity(\n                attacker_ip=attacker_ip,\n                technique=mitre_id,\n                event_time=event_time.value\n            )\n            logger.debug(\n                f"[LEARNER] Recorded {attacker_ip} -> {mitre_id} for learning"\n            )\n'
'\nimport threading\nimport time\n\ndef transition_learner_cleanup_task():\n    """\n    Background task to periodically clean up stale attacker cache entries.\n    Run this in a separate thread.\n    """\n    while True:\n        try:\n            time.sleep(300)  # 5 minutes\n            transition_learner.cleanup_cache()\n            logger.info("[LEARNER] Cleaned up stale attacker cache entries")\n        except Exception as e:\n            logger.exception(f"[LEARNER] Cleanup task error: {e}")\n\n# Start cleanup thread (add this to main() or at module level)\ncleanup_thread = threading.Thread(\n    target=transition_learner_cleanup_task,\n    daemon=True\n)\ncleanup_thread.start()\nlogger.info("[LEARNER] Started transition learner cleanup task")\n'

def integration_example():
    from transition_learner import learner as transition_learner
    from wazuh_rule_mapper import get_technique_for_alert

    def process_alert_snippet_1(alert, rule_id, resolution):
        if resolution.provenance == 'UNKNOWN':
            mapped_technique = get_technique_for_alert(alert)
            if mapped_technique:
                print(f'[MAPPER] Rule {rule_id} -> {mapped_technique}')

    def process_alert_snippet_2(attacker_ip, mitre_id, event_time, transition):
        campaign_id = transition.campaign_id
        if mitre_id != 'UNKNOWN':
            learned = transition_learner.record_attacker_activity(attacker_ip=attacker_ip, technique=mitre_id, event_time=event_time.value)
            if learned:
                print(f'[LEARNER] Learned new transition from {attacker_ip}')

def test_integration():
    from transition_learner import learner
    from datetime import datetime, timezone
    attacker = '192.168.1.100'
    learner.record_attacker_activity(attacker_ip=attacker, technique='T1595', event_time=datetime.now(timezone.utc))
    import time
    time.sleep(1)
    learned = learner.record_attacker_activity(attacker_ip=attacker, technique='T1110', event_time=datetime.now(timezone.utc))
    assert learned, 'Should have learned transition T1595 -> T1110'
    from neo4j_client import driver
    with driver.session() as session:
        result = session.run("\n            MATCH (:Technique {attack_id: 'T1595'})\n                  -[r:NEXT_TECHNIQUE]->\n                  (:Technique {attack_id: 'T1110'})\n            RETURN r.count AS count, r.learned_from_splits AS learned_from_splits\n            ").single()
        assert result is not None, 'Transition should exist in Neo4j'
        print(f"✓ Transition learned: count={result['count']}")
        print(f"✓ Learned from splits: {result['learned_from_splits']}")
    print('\n✓ All integration tests passed!')
if __name__ == '__main__':
    print(__doc__)
    print('\nThis file documents the integration points.')
    print('Copy the relevant code sections to realtime_socgraph.py')
    print('\nTo test after integration, run:')
    print('  python integration_patch.py')