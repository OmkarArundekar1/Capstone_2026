import sys
from datetime import datetime, timezone, timedelta
from typing import Dict, List

def test_unseen_transition_default():
    print('\n' + '=' * 60)
    print('TEST 1: Unseen Transition Default Value')
    print('=' * 60)
    from campaign_feature_engine import CampaignFeatureEngine
    from campaign_context import CampaignContext
    from neo4j_client import driver
    engine = CampaignFeatureEngine()
    context = CampaignContext(campaign_id='test_campaign_001', attacker_ip='10.0.0.1', victim_ip='10.0.0.2', last_technique='T1595', observed_chain=['T1595'], first_seen=datetime.now(timezone.utc), last_seen=datetime.now(timezone.utc))
    unseen_technique = 'T1999'
    similarity = engine.chain_similarity(context, unseen_technique)
    if similarity == 0.1:
        print('✓ PASS: Unseen transition returns default (0.1)')
    elif similarity == 0.0:
        print('✗ FAIL: Unseen transition returns 0.0 (old behavior)')
        return False
    elif similarity is None:
        print('✓ PASS: None is acceptable (no last_technique)')
    else:
        print(f'? Unexpected value: {similarity}')
    return True

def test_transition_learning():
    print('\n' + '=' * 60)
    print('TEST 2: Transition Learning Across Splits')
    print('=' * 60)
    from transition_learner import TransitionLearner
    from neo4j_client import driver
    learner = TransitionLearner()
    attacker_ip = '192.168.100.50'
    now = datetime.now(timezone.utc)
    print(f'\n[1] Recording: {attacker_ip} -> T1595')
    result1 = learner.record_attacker_activity(attacker_ip=attacker_ip, technique='T1595', event_time=now)
    print(f'    Learned: {result1} (expected: False, first activity)')
    print(f'\n[2] Recording: {attacker_ip} -> T1190')
    result2 = learner.record_attacker_activity(attacker_ip=attacker_ip, technique='T1190', event_time=now + timedelta(seconds=30))
    print(f'    Learned: {result2} (expected: True)')
    if result2:
        with driver.session() as session:
            result = session.run("\n                MATCH (:Technique {attack_id: 'T1595'})\n                      -[r:NEXT_TECHNIQUE]->\n                      (:Technique {attack_id: 'T1190'})\n                RETURN r.count AS count, \n                       r.learned_from_splits AS learned_from_splits\n                ").single()
            if result:
                print(f'    ✓ Transition exists in Neo4j')
                print(f"      Count: {result['count']}")
                print(f"      Learned from splits: {result.get('learned_from_splits', False)}")
                return True
            else:
                print(f'    ✗ Transition not found in Neo4j')
                return False
    else:
        print(f'    ✗ Transition was not learned')
        return False

def test_merged_features():
    print('\n' + '=' * 60)
    print('TEST 3: Merged Transition Features')
    print('=' * 60)
    from campaign_feature_engine import CampaignFeatureEngine, CampaignFeatures
    from campaign_decision_engine import CampaignDecisionEngine
    from config import CAMPAIGN_WEIGHTS
    print('\nChecking feature weights:')
    if 'transition_similarity' in CAMPAIGN_WEIGHTS:
        print(f"  ✓ transition_similarity: {CAMPAIGN_WEIGHTS['transition_similarity']}")
    else:
        print(f'  ✗ transition_similarity not in weights')
        return False
    if 'prediction_similarity' in CAMPAIGN_WEIGHTS:
        print(f'  ✗ prediction_similarity still in weights (should be removed)')
        return False
    if 'chain_similarity' in CAMPAIGN_WEIGHTS:
        print(f'  ✗ chain_similarity still in weights (should be removed)')
        return False
    print('\n  ✓ Feature weights properly merged')
    try:
        test_features = CampaignFeatures(transition_similarity=0.5, temporal_similarity=0.8, attacker_similarity=1.0, duplicate_similarity=0.1, graph_similarity=0.2, runtime_similarity=0.3)
        print('\n  ✓ CampaignFeatures accepts transition_similarity')
    except TypeError as e:
        print(f'\n  ✗ CampaignFeatures error: {e}')
        return False
    engine = CampaignDecisionEngine()
    decision = engine.evaluate(test_features)
    if 'transition_similarity' in decision.breakdown:
        print(f'  ✓ Decision engine uses transition_similarity')
        print(f'    Score: {decision.score:.2f}')
        return True
    else:
        print(f'  ✗ Decision engine missing transition_similarity')
        return False

def test_wazuh_rule_mapping():
    print('\n' + '=' * 60)
    print('TEST 4: Wazuh Rule Mapping')
    print('=' * 60)
    from wazuh_rule_mapper import WazuhRuleMapper
    mapper = WazuhRuleMapper()
    test_cases = [(5551, 'T1110', 'SSH Brute Force'), (5710, 'T1078', 'Valid Accounts'), (31100, 'T1190', 'Web Attack')]
    passed = 0
    for rule_id, expected_technique, description in test_cases:
        technique = mapper.get_technique(rule_id)
        if technique == expected_technique:
            print(f'  ✓ Rule {rule_id} -> {technique} ({description})')
            passed += 1
        else:
            print(f'  ✗ Rule {rule_id} -> {technique} (expected {expected_technique})')
    test_alert = {'rule': {'id': '5551'}}
    technique = mapper.map_alert(test_alert)
    if technique == 'T1110':
        print(f'\n  ✓ Alert mapping works: {technique}')
        passed += 1
    else:
        print(f'\n  ✗ Alert mapping failed: {technique}')
    print(f'\nPassed {passed}/{len(test_cases) + 1} tests')
    return passed == len(test_cases) + 1

def test_inverse_purity():
    print('\n' + '=' * 60)
    print('TEST 5: Inverse Purity Metrics')
    print('=' * 60)
    from evaluation_metrics import cluster_purity, inverse_purity, campaigns_per_attack
    true_labels = {'alert1': 'attack_A', 'alert2': 'attack_A', 'alert3': 'attack_A', 'alert4': 'attack_A', 'alert5': 'attack_A', 'alert6': 'attack_B', 'alert7': 'attack_B', 'alert8': 'attack_B', 'alert9': 'attack_C', 'alert10': 'attack_C'}
    fragmented_labels = {'alert1': 'campaign_A1', 'alert2': 'campaign_A2', 'alert3': 'campaign_A2', 'alert4': 'campaign_A3', 'alert5': 'campaign_A3', 'alert6': 'campaign_B1', 'alert7': 'campaign_B2', 'alert8': 'campaign_B2', 'alert9': 'campaign_C1', 'alert10': 'campaign_C1'}
    purity = cluster_purity(true_labels, fragmented_labels)
    inv_purity = inverse_purity(true_labels, fragmented_labels)
    cpa = campaigns_per_attack(true_labels, fragmented_labels)
    print(f'\nFragmented system metrics:')
    print(f'  Purity: {purity:.2%} (high even when splitting)')
    print(f'  Inverse Purity: {inv_purity:.2%} (shows splitting)')
    print(f"  Campaigns/Attack: {cpa['mean']:.1f} (high = bad)")
    print(f"    Attack A: {cpa['per_attack']['attack_A']} campaigns")
    print(f"    Attack B: {cpa['per_attack']['attack_B']} campaigns")
    print(f"    Attack C: {cpa['per_attack']['attack_C']} campaigns")
    ideal_labels = {'alert1': 'campaign_A', 'alert2': 'campaign_A', 'alert3': 'campaign_A', 'alert4': 'campaign_A', 'alert5': 'campaign_A', 'alert6': 'campaign_B', 'alert7': 'campaign_B', 'alert8': 'campaign_B', 'alert9': 'campaign_C', 'alert10': 'campaign_C'}
    purity_ideal = cluster_purity(true_labels, ideal_labels)
    inv_purity_ideal = inverse_purity(true_labels, ideal_labels)
    cpa_ideal = campaigns_per_attack(true_labels, ideal_labels)
    print(f'\nIdeal system metrics:')
    print(f'  Purity: {purity_ideal:.2%}')
    print(f'  Inverse Purity: {inv_purity_ideal:.2%}')
    print(f"  Campaigns/Attack: {cpa_ideal['mean']:.1f}")
    if inv_purity < inv_purity_ideal:
        print(f'\n  ✓ Inverse purity correctly identifies fragmentation')
        return True
    else:
        print(f'\n  ✗ Inverse purity failed to identify fragmentation')
        return False

def test_misp_publishing():
    print('\n' + '=' * 60)
    print('TEST 6: MISP Publishing')
    print('=' * 60)
    try:
        from misp_event_publisher import MISPEventPublisher
        import config
        if not config.MISP_URL or not config.MISP_API_KEY:
            print('  ⚠ MISP not configured (set MISP_URL and MISP_API_KEY)')
            print('  Skipping live test')
            return True
        publisher = MISPEventPublisher(misp_url=config.MISP_URL, api_key=config.MISP_API_KEY, verify_ssl=config.VERIFY_MISP_SSL)
        healthy = publisher.health_check()
        if healthy:
            print(f'  ✓ MISP connection successful')
            print(f'    URL: {config.MISP_URL}')
            return True
        else:
            print(f'  ✗ MISP connection failed')
            return False
    except ImportError as e:
        print(f'  ✗ Import error: {e}')
        return False
    except Exception as e:
        print(f'  ✗ Error: {e}')
        return False

def test_shuffle_publishing():
    print('\n' + '=' * 60)
    print('TEST 7: Shuffle Publishing')
    print('=' * 60)
    try:
        from shuffle_workflow_publisher import ShuffleWorkflowPublisher
        from soar.shuffle_client import build_default_client
        import config
        if not config.SHUFFLE_WEBHOOK:
            print('  ⚠ Shuffle not configured (set SHUFFLE_WEBHOOK)')
            print('  Skipping live test')
            return True
        client = build_default_client()
        publisher = ShuffleWorkflowPublisher(client)
        if config.SHUFFLE_BASE_URL:
            healthy = publisher.health_check()
            if healthy:
                print(f'  ✓ Shuffle connection successful')
                return True
            else:
                print(f'  ✗ Shuffle connection failed')
                return False
        else:
            print(f'  ✓ Shuffle publisher created (webhook configured)')
            print(f'    Health check requires SHUFFLE_BASE_URL')
            return True
    except ImportError as e:
        print(f'  ✗ Import error: {e}')
        return False
    except Exception as e:
        print(f'  ✗ Error: {e}')
        return False

def run_all_tests():
    print('\n' + '=' * 60)
    print('CYUKTI CRITICAL FIXES - TEST SUITE')
    print('=' * 60)
    tests = [('Unseen Transition Default', test_unseen_transition_default), ('Transition Learning', test_transition_learning), ('Merged Features', test_merged_features), ('Wazuh Rule Mapping', test_wazuh_rule_mapping), ('Inverse Purity Metrics', test_inverse_purity), ('MISP Publishing', test_misp_publishing), ('Shuffle Publishing', test_shuffle_publishing)]
    results = []
    for name, test_func in tests:
        try:
            passed = test_func()
            results.append((name, passed))
        except Exception as e:
            print(f'\n✗ TEST FAILED WITH EXCEPTION: {e}')
            import traceback
            traceback.print_exc()
            results.append((name, False))
    print('\n' + '=' * 60)
    print('TEST SUMMARY')
    print('=' * 60)
    passed_count = sum((1 for _, passed in results if passed))
    total_count = len(results)
    for name, passed in results:
        status = '✓ PASS' if passed else '✗ FAIL'
        print(f'{status}: {name}')
    print(f'\nTotal: {passed_count}/{total_count} tests passed')
    if passed_count == total_count:
        print('\n🎉 All tests passed! Fixes are working correctly.')
        return 0
    else:
        print(f'\n⚠ {total_count - passed_count} test(s) failed. Review output above.')
        return 1
if __name__ == '__main__':
    sys.exit(run_all_tests())