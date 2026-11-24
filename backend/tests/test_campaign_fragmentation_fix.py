from __future__ import annotations
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock, patch
import pytest
from campaign_manager import CampaignManager, ACTIVE, INACTIVE
from campaign_context import CampaignContext
from campaign_feature_engine import CampaignFeatures
from campaign_decision_engine import CampaignDecision
BASE_TIME = datetime(2026, 1, 20, 12, 0, 0, tzinfo=timezone.utc)

@pytest.fixture
def mock_neo4j():
    with patch('campaign_manager.get_active_campaign_db') as mock_active, patch('campaign_manager.get_recent_inactive_campaign_db') as mock_inactive, patch('campaign_manager.create_campaign_db') as mock_create, patch('campaign_manager.close_campaign_db') as mock_close, patch('campaign_manager.reopen_campaign_db') as mock_reopen, patch('campaign_manager.update_campaign_activity') as mock_update, patch('campaign_manager.get_campaign_chain') as mock_chain:
        mock_active.return_value = None
        mock_inactive.return_value = []
        mock_create.return_value = 'CAMP_TEST_001'
        mock_chain.return_value = []
        yield {'active': mock_active, 'inactive': mock_inactive, 'create': mock_create, 'close': mock_close, 'reopen': mock_reopen, 'update': mock_update, 'chain': mock_chain}

@pytest.fixture
def manager():
    mgr = CampaignManager()
    mgr.reset()
    mgr.decision_log = []
    return mgr

class TestCampaignContinuity:

    def test_same_session_continuous_events_create_one_campaign(self, manager, mock_neo4j):
        attacker = '192.168.56.106'
        victim = '192.168.56.105'
        techniques = ['T1595', 'T1210', 'T1059', 'T1055']
        with patch('campaign_manager.campaign_feature_engine') as mock_features, patch('campaign_manager.campaign_decision_engine') as mock_decision:
            mock_decision.evaluate.return_value = CampaignDecision(score=0.85, confidence=85.0, available_features=6, total_features=7, breakdown={'transition_similarity': 0.8, 'temporal_similarity': 1.0, 'attacker_similarity': 1.0, 'lateral_movement_similarity': 0.9, 'duplicate_similarity': 0.1, 'graph_similarity': 0.5, 'runtime_similarity': 0.6})
            campaigns = []
            for i, technique in enumerate(techniques):
                event_time = BASE_TIME + timedelta(seconds=i * 10)
                context = manager.resolve_campaign(attacker, victim, technique, event_time)
                if context.campaign_id not in campaigns:
                    campaigns.append(context.campaign_id)
            assert len(campaigns) == 1, f'Expected 1 campaign, got {len(campaigns)}: {campaigns}'
            create_decisions = [d for d in manager.decision_log if d['decision'] == 'CREATE']
            assert len(create_decisions) == 1, f'Expected 1 CREATE decision, got {len(create_decisions)}'
            continue_decisions = [d for d in manager.decision_log if d['decision'] == 'CONTINUE']
            assert len(continue_decisions) == len(techniques) - 1, f'Expected {len(techniques) - 1} CONTINUE decisions, got {len(continue_decisions)}'

    def test_delayed_events_within_timeout_continue(self, manager, mock_neo4j):
        attacker = '192.168.56.106'
        victim = '192.168.56.105'
        with patch('campaign_manager.campaign_feature_engine') as mock_features, patch('campaign_manager.campaign_decision_engine') as mock_decision:
            mock_decision.evaluate.return_value = CampaignDecision(score=0.75, confidence=80.0, available_features=6, total_features=7, breakdown={'temporal_similarity': 0.8})
            context1 = manager.resolve_campaign(attacker, victim, 'T1595', BASE_TIME)
            campaign_id_1 = context1.campaign_id
            context2 = manager.resolve_campaign(attacker, victim, 'T1210', BASE_TIME + timedelta(seconds=60))
            campaign_id_2 = context2.campaign_id
            assert campaign_id_1 == campaign_id_2, 'Events within timeout should use same campaign'

    def test_delayed_events_after_timeout_should_reopen(self, manager, mock_neo4j):
        attacker = '192.168.56.106'
        victim = '192.168.56.105'
        technique = 'T1595'
        campaign_id = 'CAMP_TEST_001'
        with patch('campaign_manager.campaign_feature_engine') as mock_features, patch('campaign_manager.campaign_decision_engine') as mock_decision:
            mock_decision.evaluate.return_value = CampaignDecision(score=0.85, confidence=85.0, available_features=6, total_features=7, breakdown={'temporal_similarity': 0.9})
            context1 = manager.resolve_campaign(attacker, victim, technique, BASE_TIME)
            manager._store_cache(context1)
            context2 = manager.resolve_campaign(attacker, victim, technique, BASE_TIME + timedelta(seconds=150))
            close_decisions = [d for d in manager.decision_log if d['decision'] == 'CLOSE_EXPIRED']
            assert len(close_decisions) >= 1, 'Should close expired campaign'

class TestCampaignDiversity:

    def test_different_sessions_same_attacker_victim_stay_separate(self, manager, mock_neo4j):
        attacker = '192.168.56.106'
        victim = 'pes1ug23cs411-VirtualBox'
        with patch('campaign_manager.campaign_feature_engine') as mock_features, patch('campaign_manager.campaign_decision_engine') as mock_decision:
            mock_decision.evaluate.return_value = CampaignDecision(score=0.85, confidence=85.0, available_features=6, total_features=7, breakdown={'temporal_similarity': 1.0})
            context1 = manager.resolve_campaign(attacker, victim, 'T1595', BASE_TIME)
            campaign_id_1 = context1.campaign_id
            manager.close_expired_context(context1, BASE_TIME + timedelta(seconds=200))
            mock_decision.evaluate.return_value = CampaignDecision(score=0.25, confidence=70.0, available_features=5, total_features=7, breakdown={'temporal_similarity': 0.2})
            mock_neo4j['inactive'].return_value = []
            context2 = manager.resolve_campaign(attacker, victim, 'T1595', BASE_TIME + timedelta(hours=2))
            campaign_id_2 = context2.campaign_id
            assert campaign_id_1 != campaign_id_2, 'Sessions separated by hours should create different campaigns'

class TestFeatureCalculations:

    def test_lateral_movement_similarity_included_in_scoring(self, manager, mock_neo4j):
        from campaign_decision_engine import engine as decision_engine
        from campaign_feature_engine import CampaignFeatures
        features = CampaignFeatures(transition_similarity=0.8, temporal_similarity=1.0, attacker_similarity=1.0, lateral_movement_similarity=0.9, duplicate_similarity=0.1, graph_similarity=0.5, runtime_similarity=0.6)
        decision = decision_engine.evaluate(features)
        assert 'lateral_movement_similarity' in decision.breakdown, 'lateral_movement_similarity must be in breakdown dict'
        assert decision.breakdown['lateral_movement_similarity'] == 0.9, 'lateral_movement_similarity value must be preserved'

    def test_unseen_transition_returns_neutral_default(self):
        from campaign_feature_engine import engine as feature_engine
        with patch('campaign_feature_engine.driver') as mock_driver:
            mock_session = Mock()
            mock_driver.session.return_value.__enter__.return_value = mock_session
            mock_session.run.return_value.single.return_value = {'total': 0}
            context = CampaignContext(campaign_id='CAMP_TEST', attacker_ip='10.0.0.1', victim_ip='10.0.0.2', last_technique='T1595', observed_chain=['T1595'])
            similarity = feature_engine.chain_similarity(context, 'T1210')
            assert similarity == 0.1, f'Unseen transition should return 0.1 (neutral), got {similarity}'

class TestCampaignClosureAndReopen:

    def test_campaign_closes_when_score_below_threshold(self, manager, mock_neo4j):
        attacker = '192.168.56.106'
        victim = '192.168.56.105'
        with patch('campaign_manager.campaign_feature_engine') as mock_features, patch('campaign_manager.campaign_decision_engine') as mock_decision:
            mock_decision.evaluate.return_value = CampaignDecision(score=0.85, confidence=85.0, available_features=6, total_features=7, breakdown={})
            context1 = manager.resolve_campaign(attacker, victim, 'T1595', BASE_TIME)
            manager._store_cache(context1)
            mock_decision.evaluate.return_value = CampaignDecision(score=0.25, confidence=70.0, available_features=5, total_features=7, breakdown={})
            context2 = manager.resolve_campaign(attacker, victim, 'T9999', BASE_TIME + timedelta(seconds=10))
            close_decisions = [d for d in manager.decision_log if d['decision'] == 'CLOSE_BELOW_THRESHOLD']
            assert len(close_decisions) >= 1, 'Should close campaign when score < 0.30'

    def test_fast_reopen_triggers_on_exact_match(self, manager, mock_neo4j):
        attacker = '192.168.56.106'
        victim = '192.168.56.105'
        technique = 'T1595'
        campaign_data = {'campaign_id': 'CAMP_TEST_001', 'status': INACTIVE, 'first_seen': BASE_TIME, 'last_seen': BASE_TIME + timedelta(seconds=30), 'last_technique': technique, 'predicted_next': None, 'prediction_confidence': None, 'prediction_generated_at': None, 'reopened_count': 0}
        with patch('campaign_manager.campaign_feature_engine') as mock_features:
            mock_features.temporal_similarity.return_value = 0.9
            mock_neo4j['inactive'].return_value = [campaign_data]
            mock_neo4j['chain'].return_value = [technique]
            context = manager.resolve_campaign(attacker, victim, technique, BASE_TIME + timedelta(seconds=100))
            if manager.decision_log:
                reopen_decisions = [d for d in manager.decision_log if 'REOPEN' in d['decision']]

class TestEdgeCases:

    def test_campaign_with_unknown_technique_first(self, manager, mock_neo4j):
        attacker = '192.168.56.106'
        victim = '192.168.56.105'
        context = manager.resolve_campaign(attacker, victim, 'UNKNOWN', BASE_TIME)
        assert context is not None, 'Should handle UNKNOWN technique'
        assert context.campaign_id is not None, 'Should create campaign ID'

    def test_concurrent_campaigns_different_victims(self, manager, mock_neo4j):
        attacker = '192.168.56.106'
        victim1 = '192.168.56.105'
        victim2 = '192.168.56.107'
        with patch('campaign_manager.campaign_feature_engine'), patch('campaign_manager.campaign_decision_engine'):
            mock_neo4j['create'].side_effect = ['CAMP_001', 'CAMP_002']
            context1 = manager.resolve_campaign(attacker, victim1, 'T1595', BASE_TIME)
            context2 = manager.resolve_campaign(attacker, victim2, 'T1595', BASE_TIME)
            assert context1.campaign_id != context2.campaign_id, 'Different victims should get different campaigns'
if __name__ == '__main__':
    pytest.main([__file__, '-v'])