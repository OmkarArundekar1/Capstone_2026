from __future__ import annotations
import os
import random
import sys
_ML_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if _ML_DIR not in sys.path:
    sys.path.insert(0, _ML_DIR)
from dataset_utils import FEATURE_COLUMNS
from feature_schema import CampaignDatasetRecord
_SEVERITIES = ['Low', 'Medium', 'High', 'Critical']

def _severity_from_risk(risk_score: float, structural_risk: float, threat_actor_reputation: float) -> str:
    composite = 0.5 * risk_score + 0.3 * structural_risk + 0.2 * threat_actor_reputation
    composite += random.gauss(0, 8)
    if composite >= 70:
        return 'Critical'
    if composite >= 45:
        return 'High'
    if composite >= 20:
        return 'Medium'
    return 'Low'

def generate_synthetic_records(n: int, seed: int=42) -> list[CampaignDatasetRecord]:
    rng = random.Random(seed)
    records = []
    for i in range(n):
        risk_score = rng.uniform(0, 100)
        structural_risk = rng.uniform(0, 40)
        threat_actor_reputation = rng.uniform(0, 100)
        severity = _severity_from_risk(risk_score, structural_risk, threat_actor_reputation)
        values = {}
        for name in FEATURE_COLUMNS:
            if name == 'risk_score':
                values[name] = risk_score
            elif name == 'structural_risk':
                values[name] = structural_risk
            elif name == 'threat_actor_reputation':
                values[name] = threat_actor_reputation
            elif name.endswith('_count') or name.endswith('_degree') or name in ('campaign_size', 'unique_techniques', 'node_count', 'edge_count', 'graph_diameter', 'attack_chain_depth', 'wazuh_level'):
                values[name] = rng.randint(0, 20)
            else:
                values[name] = round(rng.uniform(0, 1) if 'similarity' in name or 'confidence' in name or 'reputation' in name else rng.uniform(0, 50), 4)
        records.append(CampaignDatasetRecord(campaign_id=f'synthetic-{i}', attacker_ip=f'10.0.{i % 255}.{i * 7 % 255}', victim_ip=f'10.1.{i % 255}.{i * 3 % 255}', severity=severity, attributed_actor=rng.choice(['unknown', 'actor-A', 'actor-B']), prediction_correct=rng.randint(0, 1), attribution_correct=rng.randint(0, 1), next_technique=rng.choice(['T1110', 'T1078', 'T1059', '']), risk_score=risk_score, **values))
    return records
if __name__ == '__main__':
    from dataset_writer import DatasetWriter
    writer = DatasetWriter(dataset_directory='../datasets_synthetic')
    for record in generate_synthetic_records(300):
        writer.append(record)
    print(f'Wrote {writer.size()} synthetic rows to {writer.csv_file}')