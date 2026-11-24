import itertools
from evidence.schema import Evidence, EvidenceSource, EvidenceType
from evidence.store import EvidenceStore
from investigation.actions import ACTION_METADATA, InvestigationAction
from investigation.next_best_evidence import W_COST, W_GAIN, W_LATENCY, W_NOVELTY, W_RELIABILITY, W_REDUNDANCY, W_UNCERTAINTY_REDUCTION, score_action

def _full_value_from_components(av) -> float:
    return W_GAIN * av.expected_gain + W_RELIABILITY * av.reliability + W_NOVELTY * av.novelty + W_UNCERTAINTY_REDUCTION * av.uncertainty_reduction - W_COST * av.cost - W_LATENCY * av.latency - W_REDUNDANCY * av.redundancy_penalty

def _rank_of(scores: dict) -> dict:
    ordered = sorted(scores.items(), key=lambda kv: (-kv[1], kv[0]))
    return {action: i + 1 for i, (action, _) in enumerate(ordered)}

def _pairwise_swaps(rank_a: list[int], rank_b: list[int]) -> int:
    return sum((1 for x, y in itertools.combinations(range(len(rank_a)), 2) if (rank_a[x] - rank_a[y]) * (rank_b[x] - rank_b[y]) < 0))

def test_ablation_a_reproduces_real_score_action_value_empty_store():
    store = EvidenceStore()
    for action in ACTION_METADATA:
        av = score_action(action, store, current_uncertainty=1.0, taken_actions=frozenset())
        assert abs(_full_value_from_components(av) - av.value) < 1e-09

def test_ablation_a_reproduces_real_score_action_value_with_evidence_and_dependency():
    store = EvidenceStore()
    store.add(Evidence(source=EvidenceSource.CAMPAIGN_HISTORY, source_id='c1', timestamp='t', type=EvidenceType.HISTORICAL_MATCH, content={}, confidence=0.9, relevance=0.7))
    taken = frozenset({InvestigationAction.CAMPAIGN_HISTORY})
    for action in ACTION_METADATA:
        av = score_action(action, store, current_uncertainty=0.42, taken_actions=taken)
        assert abs(_full_value_from_components(av) - av.value) < 1e-09

def test_ablation_a_reproduction_holds_across_varied_uncertainty_values():
    store = EvidenceStore()
    for current_uncertainty in (0.0, 0.25, 0.5, 0.75, 1.0):
        av = score_action(InvestigationAction.XGBOOST_PREDICTION, store, current_uncertainty=current_uncertainty, taken_actions=frozenset())
        assert abs(_full_value_from_components(av) - av.value) < 1e-09
        assert av.uncertainty_reduction == current_uncertainty

def test_rank_of_orders_descending_by_score():
    scores = {'a': 1.5, 'b': 3.0, 'c': 2.0}
    ranks = _rank_of(scores)
    assert ranks == {'b': 1, 'c': 2, 'a': 3}

def test_pairwise_swap_counter_detects_a_known_swap():
    rank_a = [1, 2, 3]
    rank_b = [1, 3, 2]
    assert _pairwise_swaps(rank_a, rank_b) == 1

def test_pairwise_swap_counter_returns_zero_for_identical_rankings():
    rank_a = [1, 2, 3, 4]
    assert _pairwise_swaps(rank_a, list(rank_a)) == 0

def test_pairwise_swap_counter_detects_full_reversal():
    rank_a = [1, 2, 3, 4]
    rank_b = [4, 3, 2, 1]
    assert _pairwise_swaps(rank_a, rank_b) == 6

def test_score_action_actually_produces_different_scores_for_different_novelty_state():
    store_before = EvidenceStore()
    store_after = EvidenceStore()
    store_after.add(Evidence(source=EvidenceSource.MITRE, source_id='T1000', timestamp='t', type=EvidenceType.TECHNIQUE_KNOWLEDGE, content={}, confidence=1.0, relevance=0.9))
    av_before = score_action(InvestigationAction.MITRE_SEMANTIC_SEARCH, store_before, taken_actions=frozenset())
    av_after = score_action(InvestigationAction.MITRE_SEMANTIC_SEARCH, store_after, taken_actions=frozenset())
    assert av_before.value != av_after.value
    assert _full_value_from_components(av_before) != _full_value_from_components(av_after)