from __future__ import annotations
import json
import csv
from dataclasses import dataclass
from typing import Dict, List, Set, Optional
from pathlib import Path
from datetime import datetime
import evaluation_metrics as metrics


@dataclass
class GroundTruthAttack:
    attack_id: str
    scenario_name: str
    start_time: datetime
    end_time: datetime
    techniques: List[str]
    source_ip: str
    target_ips: List[str]
    description: str


@dataclass
class CampaignCorrelationResult:
    dataset_name: str
    true_attacks: int
    predicted_campaigns: int

    inverse_purity: float
    cluster_purity: float
    campaigns_per_attack_mean: float
    campaigns_per_attack_max: int

    pairwise_precision: float
    pairwise_recall: float
    pairwise_f1: float

    campaigns_per_attack_detail: Dict[str, int]
    fragmentation_cases: List[Dict]

    meets_targets: bool
    issues: List[str]


class AITDatasetValidator:
    TARGET_INVERSE_PURITY = 0.80
    TARGET_CLUSTER_PURITY = 0.90
    TARGET_CAMPAIGNS_PER_ATTACK_MEAN = 2.0
    TARGET_CAMPAIGNS_PER_ATTACK_MAX = 5

    def __init__(self, ground_truth_path: str, cyukti_output_path: str):
        self.ground_truth_path = Path(ground_truth_path)
        self.cyukti_output_path = Path(cyukti_output_path)

        self.ground_truth: Dict[str, GroundTruthAttack] = {}
        self.cyukti_campaigns: Dict[str, str] = {}
        self.alert_to_attack: Dict[str, str] = {}

    def load_ground_truth(self) -> int:
        if not self.ground_truth_path.exists():
            raise FileNotFoundError(f"Ground truth file not found: {self.ground_truth_path}")

        with open(self.ground_truth_path, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                attack = GroundTruthAttack(
                    attack_id=row['attack_id'],
                    scenario_name=row['scenario'],
                    start_time=datetime.fromisoformat(row['start_time']),
                    end_time=datetime.fromisoformat(row['end_time']),
                    techniques=row['techniques'].split('|') if row['techniques'] else [],
                    source_ip=row['source_ip'],
                    target_ips=row['target_ips'].split('|') if row['target_ips'] else [],
                    description=row['description']
                )
                self.ground_truth[attack.attack_id] = attack

        return len(self.ground_truth)

    def load_cyukti_output(self) -> int:
        if not self.cyukti_output_path.exists():
            raise FileNotFoundError(f"CYUKTI output not found: {self.cyukti_output_path}")

        with open(self.cyukti_output_path, 'r') as f:
            data = json.load(f)

        for alert_id, alert_data in data.items():
            self.cyukti_campaigns[alert_id] = alert_data['campaign_id']
            if 'attack_id' in alert_data:
                self.alert_to_attack[alert_id] = alert_data['attack_id']

        return len(self.cyukti_campaigns)

    def build_clustering_mappings(self) -> tuple[Dict[str, str], Dict[str, str]]:
        true_clusters = {}
        pred_clusters = {}

        for alert_id in self.cyukti_campaigns:
            if alert_id in self.alert_to_attack:
                true_clusters[alert_id] = self.alert_to_attack[alert_id]
                pred_clusters[alert_id] = self.cyukti_campaigns[alert_id]

        return true_clusters, pred_clusters

    def evaluate(self) -> CampaignCorrelationResult:
        n_attacks = self.load_ground_truth()
        n_alerts = self.load_cyukti_output()

        if n_attacks == 0:
            raise ValueError("No ground truth attacks loaded")
        if n_alerts == 0:
            raise ValueError("No CYUKTI alerts loaded")

        true_clusters, pred_clusters = self.build_clustering_mappings()

        if not true_clusters:
            raise ValueError("No alerts with ground truth attack_id found")

        inv_purity = metrics.inverse_purity(true_clusters, pred_clusters)
        clus_purity = metrics.cluster_purity(true_clusters, pred_clusters)

        campaigns_stats = metrics.campaigns_per_attack(true_clusters, pred_clusters)

        pairwise = metrics.pairwise_precision_recall_f1(true_clusters, pred_clusters)

        fragmentation_cases = []
        for attack_id, campaign_count in campaigns_stats['per_attack'].items():
            if campaign_count > self.TARGET_CAMPAIGNS_PER_ATTACK_MAX:
                attack_info = self.ground_truth.get(attack_id)
                fragmentation_cases.append({
                    'attack_id': attack_id,
                    'scenario': attack_info.scenario_name if attack_info else 'Unknown',
                    'campaign_count': campaign_count,
                    'description': attack_info.description if attack_info else ''
                })

        issues = []
        if inv_purity < self.TARGET_INVERSE_PURITY:
            issues.append(f"Inverse purity {inv_purity:.3f} < target {self.TARGET_INVERSE_PURITY}")
        if clus_purity < self.TARGET_CLUSTER_PURITY:
            issues.append(f"Cluster purity {clus_purity:.3f} < target {self.TARGET_CLUSTER_PURITY}")
        if campaigns_stats['mean'] > self.TARGET_CAMPAIGNS_PER_ATTACK_MEAN:
            issues.append(f"Campaigns per attack {campaigns_stats['mean']:.2f} > target {self.TARGET_CAMPAIGNS_PER_ATTACK_MEAN}")
        if campaigns_stats['max'] > self.TARGET_CAMPAIGNS_PER_ATTACK_MAX:
            issues.append(f"Max campaigns per attack {campaigns_stats['max']} > target {self.TARGET_CAMPAIGNS_PER_ATTACK_MAX}")

        return CampaignCorrelationResult(
            dataset_name=self.ground_truth_path.stem,
            true_attacks=n_attacks,
            predicted_campaigns=len(set(pred_clusters.values())),
            inverse_purity=inv_purity,
            cluster_purity=clus_purity,
            campaigns_per_attack_mean=campaigns_stats['mean'],
            campaigns_per_attack_max=campaigns_stats['max'],
            pairwise_precision=pairwise['precision'],
            pairwise_recall=pairwise['recall'],
            pairwise_f1=pairwise['f1'],
            campaigns_per_attack_detail=campaigns_stats['per_attack'],
            fragmentation_cases=fragmentation_cases,
            meets_targets=len(issues) == 0,
            issues=issues
        )

    def print_report(self, result: CampaignCorrelationResult):
        print("\n" + "="*70)
        print(f"CAMPAIGN CORRELATION EVALUATION: {result.dataset_name}")
        print("="*70)

        print(f"\nDataset Overview:")
        print(f"  True Attacks          : {result.true_attacks}")
        print(f"  Predicted Campaigns   : {result.predicted_campaigns}")

        print(f"\nPrimary Metrics:")
        status = "✅" if result.inverse_purity >= self.TARGET_INVERSE_PURITY else "❌"
        print(f"  {status} Inverse Purity      : {result.inverse_purity:.3f} (target: {self.TARGET_INVERSE_PURITY})")

        status = "✅" if result.cluster_purity >= self.TARGET_CLUSTER_PURITY else "❌"
        print(f"  {status} Cluster Purity      : {result.cluster_purity:.3f} (target: {self.TARGET_CLUSTER_PURITY})")

        status = "✅" if result.campaigns_per_attack_mean <= self.TARGET_CAMPAIGNS_PER_ATTACK_MEAN else "❌"
        print(f"  {status} Campaigns/Attack    : {result.campaigns_per_attack_mean:.2f} (target: <{self.TARGET_CAMPAIGNS_PER_ATTACK_MEAN})")

        status = "✅" if result.campaigns_per_attack_max <= self.TARGET_CAMPAIGNS_PER_ATTACK_MAX else "❌"
        print(f"  {status} Max Fragmentation   : {result.campaigns_per_attack_max} campaigns (target: <{self.TARGET_CAMPAIGNS_PER_ATTACK_MAX})")

        print(f"\nPairwise Correlation:")
        print(f"  Precision             : {result.pairwise_precision:.3f}")
        print(f"  Recall                : {result.pairwise_recall:.3f}")
        print(f"  F1 Score              : {result.pairwise_f1:.3f}")

        if result.fragmentation_cases:
            print(f"\nFragmentation Cases (>{self.TARGET_CAMPAIGNS_PER_ATTACK_MAX} campaigns):")
            for case in result.fragmentation_cases[:5]:
                print(f"  - {case['attack_id']} ({case['scenario']}): {case['campaign_count']} campaigns")
                if case['description']:
                    print(f"    {case['description'][:60]}...")

        print(f"\n{'='*70}")
        if result.meets_targets:
            print("✅ ALL TARGETS MET - Phase 3 validation successful!")
        else:
            print("⚠️  ISSUES FOUND:")
            for issue in result.issues:
                print(f"  - {issue}")
        print("="*70 + "\n")


def create_sample_ground_truth(output_path: str):
    sample_data = [
        {
            'attack_id': 'ATK_001',
            'scenario': 'SSH Brute Force + Lateral Movement',
            'start_time': '2024-01-15T10:00:00',
            'end_time': '2024-01-15T10:15:00',
            'techniques': 'T1110.001|T1021.004|T1082',
            'source_ip': '203.0.113.50',
            'target_ips': '192.168.1.100|192.168.1.200',
            'description': 'SSH brute force followed by lateral movement'
        },
        {
            'attack_id': 'ATK_002',
            'scenario': 'Web Exploitation',
            'start_time': '2024-01-15T11:00:00',
            'end_time': '2024-01-15T11:10:00',
            'techniques': 'T1190|T1505.003|T1059.004',
            'source_ip': '198.51.100.75',
            'target_ips': '192.168.1.50',
            'description': 'SQL injection leading to web shell'
        }
    ]

    with open(output_path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=sample_data[0].keys())
        writer.writeheader()
        writer.writerows(sample_data)

    print(f"Sample ground truth created: {output_path}")


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 3:
        print("Usage:")
        print("
        print("  python3 ait_dataset_validator.py --create-sample ground_truth.csv")
        print()
        print("
        print("  python3 ait_dataset_validator.py ground_truth.csv cyukti_output.json")
        sys.exit(1)

    if sys.argv[1] == '--create-sample':
        create_sample_ground_truth(sys.argv[2])
    else:
        ground_truth_path = sys.argv[1]
        cyukti_output_path = sys.argv[2]

        validator = AITDatasetValidator(ground_truth_path, cyukti_output_path)
        result = validator.evaluate()
        validator.print_report(result)

        sys.exit(0 if result.meets_targets else 1)
