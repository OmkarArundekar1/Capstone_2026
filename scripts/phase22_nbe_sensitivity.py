import itertools
import json
import os
import sys
BACKEND = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'backend')
sys.path.insert(0, BACKEND)
os.chdir(BACKEND)
from scipy.stats import kendalltau, spearmanr
from campaign_context import CampaignContext
from neo4j_client import driver
from investigation.loop import default_action_executor, default_model_predictor, run_investigation
sys.path.insert(0, os.path.join(BACKEND, '..', 'scripts'))
from run_real_investigations import CAMPAIGN_IDS, load_context
import investigation.next_best_evidence as nbe
W_GAIN = nbe.W_GAIN
W_RELIABILITY = nbe.W_RELIABILITY
W_NOVELTY = nbe.W_NOVELTY
W_UNCERTAINTY_REDUCTION = nbe.W_UNCERTAINTY_REDUCTION
W_COST = nbe.W_COST
W_LATENCY = nbe.W_LATENCY
W_REDUNDANCY = nbe.W_REDUNDANCY
assert (W_GAIN, W_RELIABILITY, W_NOVELTY, W_UNCERTAINTY_REDUCTION, W_COST, W_LATENCY, W_REDUNDANCY) == (1.0, 0.3, 0.5, 0.6, 0.4, 0.2, 0.5), 'Ablation weights have drifted from investigation/next_best_evidence.py -- update this script, do not silently diverge.'

def full_value(c):
    return W_GAIN * c['expected_gain'] + W_RELIABILITY * c['reliability'] + W_NOVELTY * c['novelty'] + W_UNCERTAINTY_REDUCTION * c['uncertainty_reduction'] - W_COST * c['cost'] - W_LATENCY * c['latency'] - W_REDUNDANCY * c['redundancy_penalty']

def no_uncertainty_reduction(c):
    return W_GAIN * c['expected_gain'] + W_RELIABILITY * c['reliability'] + W_NOVELTY * c['novelty'] - W_COST * c['cost'] - W_LATENCY * c['latency'] - W_REDUNDANCY * c['redundancy_penalty']

def no_model_probability(c):
    return no_uncertainty_reduction(c)

def no_dependency(c):
    return W_GAIN * c['expected_gain'] + W_RELIABILITY * c['reliability'] + W_NOVELTY * c['novelty'] + W_UNCERTAINTY_REDUCTION * c['uncertainty_reduction'] - W_COST * c['cost'] - W_LATENCY * c['latency']

def static_base_only(c):
    return W_RELIABILITY * c['reliability'] - W_COST * c['cost'] - W_LATENCY * c['latency']

def base_plus_gain_only(c):
    return static_base_only(c) + W_GAIN * c['expected_gain']

def base_plus_uncertainty_only(c):
    return static_base_only(c) + W_UNCERTAINTY_REDUCTION * c['uncertainty_reduction']

def base_plus_redundancy_only(c):
    return static_base_only(c) - W_REDUNDANCY * c['redundancy_penalty']
ABLATIONS = {'A_full_current_policy': full_value, 'B_no_uncertainty_reduction': no_uncertainty_reduction, 'C_no_model_probability': no_model_probability, 'D_no_dependency': no_dependency, 'E_static_base_only': static_base_only, 'F1_base_plus_gain_only': base_plus_gain_only, 'F2_base_plus_uncertainty_only': base_plus_uncertainty_only, 'F3_base_plus_redundancy_only': base_plus_redundancy_only}

def rank_of(scores: dict) -> dict:
    ordered = sorted(scores.items(), key=lambda kv: (-kv[1], kv[0]))
    return {action: i + 1 for i, (action, _) in enumerate(ordered)}

def main():
    campaigns_raw = {}
    for campaign_id in CAMPAIGN_IDS:
        with driver.session() as session:
            context, event_id = load_context(session, campaign_id)
        current_attack_id = context.last_technique or (sorted(context.techniques)[0] if context.techniques else None)
        if not current_attack_id:
            print(f'SKIPPED {campaign_id}: no technique available')
            continue
        executor = default_action_executor(context, current_attack_id, event_id)
        model_predictor = default_model_predictor(context, current_attack_id, event_id or '')
        record = run_investigation(executor, model_predictor=model_predictor, confidence_threshold=0.75, max_steps=8)
        campaigns_raw[campaign_id] = record.to_dict()
        print(f"{campaign_id}: {len(record.steps)} steps, final_confidence={record.to_dict()['final_confidence']}")
    max_repro_error = 0.0
    for cid, rec in campaigns_raw.items():
        for step in rec['steps']:
            for c in step['action_scores']:
                recomputed = round(full_value(c), 4)
                max_repro_error = max(max_repro_error, abs(recomputed - c['value']))
    print(f'\nAblation-A reproduction max abs error vs. real recorded value: {max_repro_error}')
    assert max_repro_error < 1e-06, 'Ablation A does not reproduce the real score_action() value -- weights or formula drifted.'
    results = {'campaigns': list(campaigns_raw.keys()), 'steps': []}
    n_steps = min((len(rec['steps']) for rec in campaigns_raw.values()))
    for step_idx in range(n_steps):
        step_result = {'step_index': step_idx + 1, 'ablations': {}}
        candidate_sets = [frozenset(rec['steps'][step_idx]['candidate_actions']) for rec in campaigns_raw.values()]
        same_candidate_set = len(set(candidate_sets)) == 1
        step_result['same_candidate_set_across_campaigns'] = same_candidate_set
        if not same_candidate_set:
            step_result['note'] = 'candidate sets differ across campaigns at this step index; skipping ranking comparison'
            results['steps'].append(step_result)
            continue
        for ablation_name, fn in ABLATIONS.items():
            per_campaign_scores = {}
            per_campaign_ranks = {}
            for cid, rec in campaigns_raw.items():
                comps = {c['action']: c for c in rec['steps'][step_idx]['action_scores']}
                scores = {action: round(fn(c), 4) for action, c in comps.items()}
                per_campaign_scores[cid] = scores
                per_campaign_ranks[cid] = rank_of(scores)
            cids = list(per_campaign_scores.keys())
            actions_sorted = sorted(next(iter(per_campaign_scores.values())).keys())
            pair_stats = []
            for a, b in itertools.combinations(cids, 2):
                sa = [per_campaign_scores[a][act] for act in actions_sorted]
                sb = [per_campaign_scores[b][act] for act in actions_sorted]
                ra = [per_campaign_ranks[a][act] for act in actions_sorted]
                rb = [per_campaign_ranks[b][act] for act in actions_sorted]
                tau, tau_p = kendalltau(ra, rb)
                rho, rho_p = spearmanr(ra, rb)
                pairwise_swaps = sum((1 for x, y in itertools.combinations(range(len(actions_sorted)), 2) if (ra[x] - ra[y]) * (rb[x] - rb[y]) < 0))
                top1_agree = min(per_campaign_ranks[a], key=per_campaign_ranks[a].get) == min(per_campaign_ranks[b], key=per_campaign_ranks[b].get)
                k = min(3, len(actions_sorted))
                topk_a = {act for act, r in per_campaign_ranks[a].items() if r <= k}
                topk_b = {act for act, r in per_campaign_ranks[b].items() if r <= k}
                topk_overlap = len(topk_a & topk_b) / k
                pair_stats.append({'pair': [a, b], 'kendall_tau': None if tau != tau else round(float(tau), 4), 'spearman_rho': None if rho != rho else round(float(rho), 4), 'pairwise_rank_swaps': pairwise_swaps, 'total_pairs': len(actions_sorted) * (len(actions_sorted) - 1) // 2, 'top1_agree': top1_agree, 'top3_overlap_fraction': round(topk_overlap, 4), 'identical_scores': sa == sb, 'identical_rankings': ra == rb})
            component_variance = {}
            for act in actions_sorted:
                vals = [per_campaign_scores[cid][act] for cid in cids]
                mean = sum(vals) / len(vals)
                var = sum(((v - mean) ** 2 for v in vals)) / len(vals)
                component_variance[act] = {'mean': round(mean, 4), 'variance': round(var, 6)}
            step_result['ablations'][ablation_name] = {'per_campaign_scores': per_campaign_scores, 'per_campaign_ranks': per_campaign_ranks, 'pairwise_comparisons': pair_stats, 'score_variance_by_action': component_variance, 'all_pairs_identical_rankings': all((p['identical_rankings'] for p in pair_stats))}
        results['steps'].append(step_result)
    with open(os.path.join(BACKEND, '..', 'review', 'phase22_nbe_sensitivity_raw.json'), 'w') as f:
        json.dump({'campaign_traces': campaigns_raw, 'ablation_analysis': results}, f, indent=2)
    print('\nWrote review/phase22_nbe_sensitivity_raw.json')
    print('\n=== HEADLINE: step-1 (full 8-candidate set) ranking agreement per ablation ===')
    step1 = results['steps'][0]
    for name, data in step1['ablations'].items():
        identical = data['all_pairs_identical_rankings']
        taus = [p['kendall_tau'] for p in data['pairwise_comparisons']]
        swaps = [p['pairwise_rank_swaps'] for p in data['pairwise_comparisons']]
        print(f'  {name:32s} all_pairs_identical_rankings={identical!s:5s} kendall_tau={taus} pairwise_swaps={swaps}')
if __name__ == '__main__':
    main()