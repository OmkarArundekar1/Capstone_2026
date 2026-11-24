import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

def test_gnn_availability():
    print('=' * 60)
    print('TEST 1: GNN Availability')
    print('=' * 60)
    try:
        from ml.gnn.inference import gnn_inference_service
        available = gnn_inference_service.available
        metadata = gnn_inference_service.metadata
        print(f'✅ GNN Available: {available}')
        if metadata:
            print(f'✅ Model Type: {metadata.model_type}')
            print(f'✅ Architecture: {metadata.architecture}')
            print(f'✅ Embedding Dim: {metadata.embedding_dim}')
            print(f'✅ Hidden Dim: {metadata.hidden_dim}')
            print(f'✅ Num Layers: {metadata.num_layers}')
            print(f'✅ Model Version: {metadata.model_version}')
        else:
            print('⚠️  No metadata available')
        return available
    except Exception as e:
        print(f'❌ GNN Availability Check Failed: {e}')
        import traceback
        traceback.print_exc()
        return False

def test_campaign_feature_engine():
    print('\n' + '=' * 60)
    print('TEST 2: Campaign Feature Engine GNN Method')
    print('=' * 60)
    try:
        from campaign_feature_engine import engine as feature_engine
        has_method = hasattr(feature_engine, 'gnn_topology_similarity')
        print(f'✅ gnn_topology_similarity method exists: {has_method}')
        if has_method:
            import inspect
            sig = inspect.signature(feature_engine.gnn_topology_similarity)
            print(f'✅ Method signature: {sig}')
        return has_method
    except Exception as e:
        print(f'❌ Feature Engine Check Failed: {e}')
        import traceback
        traceback.print_exc()
        return False

def test_campaign_features_dataclass():
    print('\n' + '=' * 60)
    print('TEST 3: CampaignFeatures Dataclass')
    print('=' * 60)
    try:
        from campaign_feature_engine import CampaignFeatures
        import dataclasses
        fields = {f.name: f.type for f in dataclasses.fields(CampaignFeatures)}
        print('✅ CampaignFeatures fields:')
        for field_name, field_type in fields.items():
            print(f'   - {field_name}: {field_type}')
        has_gnn = 'gnn_topology_similarity' in fields
        print(f"\n{('✅' if has_gnn else '❌')} gnn_topology_similarity field exists: {has_gnn}")
        return has_gnn
    except Exception as e:
        print(f'❌ CampaignFeatures Check Failed: {e}')
        import traceback
        traceback.print_exc()
        return False

def test_campaign_weights():
    print('\n' + '=' * 60)
    print('TEST 4: Campaign Weights Configuration')
    print('=' * 60)
    try:
        from config import CAMPAIGN_WEIGHTS
        print('✅ CAMPAIGN_WEIGHTS:')
        total_weight = 0.0
        for feature, weight in sorted(CAMPAIGN_WEIGHTS.items(), key=lambda x: x[1], reverse=True):
            print(f'   {feature:<30}: {weight:.2f}')
            total_weight += weight
        print(f'\n✅ Total weight: {total_weight:.2f}')
        has_gnn = 'gnn_topology_similarity' in CAMPAIGN_WEIGHTS
        print(f"{('✅' if has_gnn else '❌')} gnn_topology_similarity in weights: {has_gnn}")
        if has_gnn:
            gnn_weight = CAMPAIGN_WEIGHTS['gnn_topology_similarity']
            print(f'✅ GNN weight: {gnn_weight:.2f} ({gnn_weight * 100:.0f}%)')
        return has_gnn and abs(total_weight - 1.0) < 0.01
    except Exception as e:
        print(f'❌ Campaign Weights Check Failed: {e}')
        import traceback
        traceback.print_exc()
        return False

def test_decision_engine():
    print('\n' + '=' * 60)
    print('TEST 5: Campaign Decision Engine')
    print('=' * 60)
    try:
        from campaign_decision_engine import engine as decision_engine
        from campaign_feature_engine import CampaignFeatures
        test_features = CampaignFeatures(transition_similarity=0.75, temporal_similarity=0.8, attacker_similarity=1.0, lateral_movement_similarity=0.85, duplicate_similarity=0.0, graph_similarity=0.45, runtime_similarity=0.6, gnn_topology_similarity=0.78)
        decision = decision_engine.evaluate(test_features)
        print('✅ Decision Engine Evaluation:')
        print(f'   Score: {decision.score:.4f}')
        print(f'   Confidence: {decision.confidence:.2f}%')
        print(f'   Available Features: {decision.available_features}/{decision.total_features}')
        print('\n✅ Breakdown:')
        for feature, value in decision.breakdown.items():
            if value is not None:
                print(f'   {feature:<30}: {value:.2f}')
        has_gnn = 'gnn_topology_similarity' in decision.breakdown
        gnn_value = decision.breakdown.get('gnn_topology_similarity')
        print(f"\n{('✅' if has_gnn else '❌')} gnn_topology_similarity in breakdown: {has_gnn}")
        print(f"{('✅' if gnn_value == 0.78 else '❌')} GNN value preserved: {gnn_value}")
        return has_gnn and gnn_value == 0.78
    except Exception as e:
        print(f'❌ Decision Engine Check Failed: {e}')
        import traceback
        traceback.print_exc()
        return False

def main():
    print('\n' + '=' * 60)
    print('GNN INTEGRATION VERIFICATION')
    print('=' * 60)
    results = {'GNN Availability': test_gnn_availability(), 'Feature Engine Method': test_campaign_feature_engine(), 'CampaignFeatures Dataclass': test_campaign_features_dataclass(), 'Campaign Weights Config': test_campaign_weights(), 'Decision Engine': test_decision_engine()}
    print('\n' + '=' * 60)
    print('TEST SUMMARY')
    print('=' * 60)
    passed = sum((1 for v in results.values() if v))
    total = len(results)
    for test_name, result in results.items():
        status = '✅ PASS' if result else '❌ FAIL'
        print(f'{test_name:<30}: {status}')
    print('\n' + '=' * 60)
    print(f'OVERALL: {passed}/{total} tests passed')
    if passed == total:
        print('✅ GNN INTEGRATION VERIFIED - ALL SYSTEMS OPERATIONAL')
    else:
        print(f'⚠️  {total - passed} test(s) failed - review errors above')
    print('=' * 60)
    return passed == total
if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)