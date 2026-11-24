import argparse
import json
import sys
from pathlib import Path
from typing import Dict, Any, Optional, List

def load_metrics(filepath: Path) -> Dict[str, Any]:
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f'ERROR: File not found: {filepath}', file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f'ERROR: Invalid JSON in {filepath}: {e}', file=sys.stderr)
        sys.exit(1)

def safe_divide(numerator: float, denominator: float) -> Optional[float]:
    if denominator == 0:
        return None
    return numerator / denominator

def calculate_percent_change(baseline: float, observation: float) -> Optional[float]:
    if baseline == 0:
        if observation == 0:
            return 0.0
        return None
    return (observation - baseline) / baseline * 100

def compare_campaigns_per_pair(baseline: Dict, observation: Dict) -> Dict[str, Any]:
    comparison = {'metric': 'campaigns_per_pair', 'interpretation': 'Lower values indicate better correlation (fewer fragments)', 'by_identity_category': {}}
    baseline_data = baseline.get('campaigns_per_pair', {}).get('by_identity_category', {})
    observation_data = observation.get('campaigns_per_pair', {}).get('by_identity_category', {})
    for category in ['ip_to_ip', 'hostname_based', 'self_to_self']:
        if category not in baseline_data and category not in observation_data:
            continue
        baseline_avg = baseline_data.get(category, {}).get('avg_campaigns_per_pair', 0)
        observation_avg = observation_data.get(category, {}).get('avg_campaigns_per_pair', 0)
        percent_change = calculate_percent_change(baseline_avg, observation_avg)
        comparison['by_identity_category'][category] = {'baseline_avg': baseline_avg, 'observation_avg': observation_avg, 'absolute_change': observation_avg - baseline_avg, 'percent_change': percent_change, 'interpretation': _interpret_campaigns_per_pair_change(percent_change, category)}
    return comparison

def _interpret_campaigns_per_pair_change(percent_change: Optional[float], category: str) -> str:
    if percent_change is None:
        return 'Cannot calculate (baseline zero)'
    if category == 'self_to_self':
        return 'Self-to-self excluded from evaluation (not lateral movement)'
    if percent_change < -5:
        return 'PROMISING: Fewer campaigns per pair (better correlation)'
    elif percent_change > 15:
        return 'CONCERNING: More campaigns per pair (worse fragmentation)'
    else:
        return 'STABLE: Minimal change'

def compare_singleton_rate(baseline: Dict, observation: Dict) -> Dict[str, Any]:
    comparison = {'metric': 'singleton_rate', 'interpretation': 'Lower values MAY indicate better correlation (but attack patterns confound)', 'by_identity_category': {}}
    baseline_data = baseline.get('singleton_rate', {}).get('by_identity_category', {})
    observation_data = observation.get('singleton_rate', {}).get('by_identity_category', {})
    for category in ['ip_to_ip', 'hostname_based', 'self_to_self']:
        if category not in baseline_data and category not in observation_data:
            continue
        baseline_rate = baseline_data.get(category, {}).get('singleton_rate', 0)
        observation_rate = observation_data.get(category, {}).get('singleton_rate', 0)
        percent_change = calculate_percent_change(baseline_rate, observation_rate)
        comparison['by_identity_category'][category] = {'baseline_rate': baseline_rate, 'observation_rate': observation_rate, 'absolute_change': observation_rate - baseline_rate, 'percent_change': percent_change, 'interpretation': _interpret_singleton_rate_change(percent_change, category)}
    return comparison

def _interpret_singleton_rate_change(percent_change: Optional[float], category: str) -> str:
    if percent_change is None:
        return 'Cannot calculate (baseline zero)'
    if category == 'self_to_self':
        return 'Self-to-self excluded from evaluation'
    if percent_change < -10:
        return 'PROMISING: Fewer singletons (but check if attack patterns changed)'
    elif percent_change > 10:
        return 'CONCERNING: More singletons (but may reflect attack behavior)'
    else:
        return 'STABLE: Minimal change'

def compare_temporal_gaps(baseline: Dict, observation: Dict) -> Dict[str, Any]:
    comparison = {'metric': 'temporal_gaps', 'interpretation': 'Short gaps (<120s) indicate potential fragmentation'}
    baseline_data = baseline.get('temporal_gaps', {})
    observation_data = observation.get('temporal_gaps', {})
    baseline_total = baseline_data.get('total_gaps', 0)
    observation_total = observation_data.get('total_gaps', 0)
    if baseline_total == 0 or observation_total == 0:
        comparison['note'] = 'Insufficient gap data for comparison'
        return comparison
    baseline_frag = baseline_data.get('fragmentation_indicator', {})
    observation_frag = observation_data.get('fragmentation_indicator', {})
    baseline_short_rate = baseline_frag.get('rate', 0)
    observation_short_rate = observation_frag.get('rate', 0)
    percent_change = calculate_percent_change(baseline_short_rate, observation_short_rate)
    comparison['short_gaps_under_120s'] = {'baseline_rate': baseline_short_rate, 'observation_rate': observation_short_rate, 'absolute_change': observation_short_rate - baseline_short_rate, 'percent_change': percent_change, 'interpretation': _interpret_gap_change(percent_change)}
    baseline_overlap = baseline_data.get('gap_distribution', {}).get('overlapping_campaigns', 0)
    observation_overlap = observation_data.get('gap_distribution', {}).get('overlapping_campaigns', 0)
    comparison['overlapping_campaigns'] = {'baseline_count': baseline_overlap, 'observation_count': observation_overlap, 'interpretation': 'Overlaps indicate fragmentation failure' if observation_overlap > baseline_overlap else 'Stable or improved'}
    return comparison

def _interpret_gap_change(percent_change: Optional[float]) -> str:
    if percent_change is None:
        return 'Cannot calculate'
    if percent_change < -20:
        return 'PROMISING: Fewer short gaps (less fragmentation)'
    elif percent_change > 20:
        return 'CONCERNING: More short gaps (more fragmentation)'
    else:
        return 'STABLE: Minimal change'

def compare_duration_stats(baseline: Dict, observation: Dict) -> Dict[str, Any]:
    comparison = {'metric': 'campaign_duration', 'interpretation': 'Very long durations (>24h) may indicate over-merging'}
    baseline_data = baseline.get('duration_stats', {})
    observation_data = observation.get('duration_stats', {})
    baseline_median = baseline_data.get('median_duration_seconds', 0)
    observation_median = observation_data.get('median_duration_seconds', 0)
    percent_change = calculate_percent_change(baseline_median, observation_median)
    comparison['median_duration'] = {'baseline_seconds': baseline_median, 'observation_seconds': observation_median, 'absolute_change': observation_median - baseline_median, 'percent_change': percent_change, 'interpretation': 'Median provides robust central tendency'}
    baseline_over_24h = baseline_data.get('duration_distribution', {}).get('over_24h', 0)
    observation_over_24h = observation_data.get('duration_distribution', {}).get('over_24h', 0)
    baseline_total = baseline_data.get('total_campaigns', 1)
    observation_total = observation_data.get('total_campaigns', 1)
    baseline_over_24h_rate = baseline_over_24h / baseline_total if baseline_total > 0 else 0
    observation_over_24h_rate = observation_over_24h / observation_total if observation_total > 0 else 0
    comparison['campaigns_over_24h'] = {'baseline_rate': baseline_over_24h_rate, 'observation_rate': observation_over_24h_rate, 'interpretation': 'High rate suggests potential over-merging' if observation_over_24h_rate > 0.05 else 'Acceptable'}
    return comparison

def compare_reopen_stats(baseline: Dict, observation: Dict) -> Dict[str, Any]:
    comparison = {'metric': 'reopen_frequency', 'interpretation': 'AMBIGUOUS: Could indicate better correlation OR worse fragmentation'}
    baseline_data = baseline.get('reopen_stats', {})
    observation_data = observation.get('reopen_stats', {})
    baseline_avg = baseline_data.get('avg_reopens_per_campaign', 0)
    observation_avg = observation_data.get('avg_reopens_per_campaign', 0)
    percent_change = calculate_percent_change(baseline_avg, observation_avg)
    comparison['avg_reopens_per_campaign'] = {'baseline_avg': baseline_avg, 'observation_avg': observation_avg, 'absolute_change': observation_avg - baseline_avg, 'percent_change': percent_change, 'interpretation': 'Requires human review to interpret - direction unclear'}
    return comparison

def compare_events_per_campaign(baseline: Dict, observation: Dict) -> Dict[str, Any]:
    comparison = {'metric': 'events_per_campaign', 'interpretation': 'Higher values suggest better correlation'}
    baseline_data = baseline.get('events_per_campaign', {})
    observation_data = observation.get('events_per_campaign', {})
    baseline_median = baseline_data.get('median_events_per_campaign', 0)
    observation_median = observation_data.get('median_events_per_campaign', 0)
    percent_change = calculate_percent_change(baseline_median, observation_median)
    comparison['median_events_per_campaign'] = {'baseline_median': baseline_median, 'observation_median': observation_median, 'absolute_change': observation_median - baseline_median, 'percent_change': percent_change, 'interpretation': _interpret_events_change(percent_change)}
    return comparison

def _interpret_events_change(percent_change: Optional[float]) -> str:
    if percent_change is None:
        return 'Cannot calculate'
    if percent_change > 10:
        return 'PROMISING: More events per campaign (better correlation)'
    elif percent_change < -10:
        return 'CONCERNING: Fewer events per campaign (worse fragmentation)'
    else:
        return 'STABLE: Minimal change'

def compare_overlapping_campaigns(baseline: Dict, observation: Dict) -> Dict[str, Any]:
    comparison = {'metric': 'overlapping_campaigns', 'interpretation': 'ANY overlap indicates fragmentation failure'}
    baseline_count = baseline.get('overlapping_campaigns', {}).get('overlapping_pair_count', 0)
    observation_count = observation.get('overlapping_campaigns', {}).get('overlapping_pair_count', 0)
    comparison['overlapping_pair_count'] = {'baseline_count': baseline_count, 'observation_count': observation_count, 'interpretation': _interpret_overlap_change(baseline_count, observation_count)}
    return comparison

def _interpret_overlap_change(baseline_count: int, observation_count: int) -> str:
    if observation_count == 0:
        return 'EXCELLENT: No overlaps detected'
    elif observation_count < baseline_count:
        return 'PROMISING: Fewer overlaps than baseline'
    elif observation_count > baseline_count:
        return 'CONCERNING: More overlaps than baseline'
    else:
        return 'STABLE: Same overlap count'

def compare_assignment_coverage(baseline: Dict, observation: Dict) -> Dict[str, Any]:
    comparison = {'metric': 'assignment_coverage', 'interpretation': 'Should be ~100%'}
    baseline_data = baseline.get('assignment_coverage', {})
    observation_data = observation.get('assignment_coverage', {})
    baseline_rate = baseline_data.get('coverage_rate', 0)
    observation_rate = observation_data.get('coverage_rate', 0)
    comparison['coverage_rate'] = {'baseline_rate': baseline_rate, 'observation_rate': observation_rate, 'absolute_change': observation_rate - baseline_rate, 'interpretation': _interpret_coverage_change(observation_rate)}
    return comparison

def _interpret_coverage_change(coverage_rate: float) -> str:
    if coverage_rate >= 0.95:
        return 'GOOD: High coverage'
    elif coverage_rate >= 0.9:
        return 'ACCEPTABLE: Minor gaps'
    else:
        return 'CONCERNING: Low coverage indicates correlation failures'

def determine_outcome(comparisons: Dict[str, Dict]) -> Dict[str, Any]:
    improved = 0
    degraded = 0
    stable = 0
    for metric_name, metric_data in comparisons.items():
        if metric_name in ['metadata']:
            continue
        interpretation = _extract_interpretation(metric_data)
        if 'PROMISING' in interpretation or 'EXCELLENT' in interpretation:
            improved += 1
        elif 'CONCERNING' in interpretation:
            degraded += 1
        elif 'STABLE' in interpretation or 'ACCEPTABLE' in interpretation:
            stable += 1
    total_metrics = improved + degraded + stable
    if total_metrics == 0:
        return {'outcome': 'INCONCLUSIVE', 'reason': 'Insufficient metrics available', 'confidence': 'none'}
    if improved >= 3 and degraded == 0:
        return {'outcome': 'PROMISING', 'reason': f'{improved} metrics improved, {degraded} degraded, {stable} stable', 'confidence': 'moderate' if improved >= 5 else 'low', 'recommendation': 'Fix shows positive evidence. Continue monitoring.'}
    if degraded >= 2 and improved == 0:
        return {'outcome': 'CONCERNING', 'reason': f'{improved} metrics improved, {degraded} degraded, {stable} stable', 'confidence': 'moderate', 'recommendation': 'Fix may be harmful. Investigate implementation.'}
    if improved > 0 and degraded > 0:
        return {'outcome': 'INCONCLUSIVE', 'reason': f'Conflicting signals: {improved} improved, {degraded} degraded, {stable} stable', 'confidence': 'low', 'recommendation': 'Mixed results. Extend observation period or conduct human review.'}
    return {'outcome': 'INCONCLUSIVE', 'reason': f'Minimal change detected: {improved} improved, {degraded} degraded, {stable} stable', 'confidence': 'low', 'recommendation': 'No clear pattern. May need longer observation period.'}

def _extract_interpretation(metric_data: Dict) -> str:
    interpretations = []
    for key, value in metric_data.items():
        if isinstance(value, dict) and 'interpretation' in value:
            interpretations.append(value['interpretation'])
        elif key == 'interpretation' and isinstance(value, str):
            interpretations.append(value)
    return ' '.join(interpretations)

def generate_comparison_report(baseline: Dict, observation: Dict) -> Dict[str, Any]:
    comparisons = {'metadata': {'baseline_period': {'start': baseline.get('metadata', {}).get('observation_start'), 'end': baseline.get('metadata', {}).get('observation_end')}, 'observation_period': {'start': observation.get('metadata', {}).get('observation_start'), 'end': observation.get('metadata', {}).get('observation_end')}, 'comparison_timestamp': observation.get('metadata', {}).get('collection_timestamp')}, 'campaigns_per_pair': compare_campaigns_per_pair(baseline, observation), 'singleton_rate': compare_singleton_rate(baseline, observation), 'temporal_gaps': compare_temporal_gaps(baseline, observation), 'duration_stats': compare_duration_stats(baseline, observation), 'reopen_stats': compare_reopen_stats(baseline, observation), 'events_per_campaign': compare_events_per_campaign(baseline, observation), 'overlapping_campaigns': compare_overlapping_campaigns(baseline, observation), 'assignment_coverage': compare_assignment_coverage(baseline, observation)}
    outcome = determine_outcome(comparisons)
    comparisons['outcome'] = outcome
    return comparisons

def parse_args():
    parser = argparse.ArgumentParser(description='Compare baseline vs. observation period campaign correlation metrics')
    parser.add_argument('--baseline', required=True, help='Path to baseline metrics JSON file')
    parser.add_argument('--observation', required=True, help='Path to observation period metrics JSON file')
    parser.add_argument('--output', required=True, help='Output comparison report JSON file path')
    return parser.parse_args()

def main():
    args = parse_args()
    baseline = load_metrics(Path(args.baseline))
    observation = load_metrics(Path(args.observation))
    comparison_report = generate_comparison_report(baseline, observation)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'w') as f:
        json.dump(comparison_report, f, indent=2, default=str)
    print(f'✅ Comparison report generated successfully')
    print(f'📊 Output written to: {output_path}')
    outcome = comparison_report.get('outcome', {})
    print(f"\n{'=' * 60}")
    print(f"OUTCOME: {outcome.get('outcome', 'UNKNOWN')}")
    print(f"{'=' * 60}")
    print(f"Reason: {outcome.get('reason', 'N/A')}")
    print(f"Confidence: {outcome.get('confidence', 'N/A')}")
    if 'recommendation' in outcome:
        print(f"Recommendation: {outcome.get('recommendation')}")
    print(f"{'=' * 60}\n")
if __name__ == '__main__':
    main()