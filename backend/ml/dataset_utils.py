from __future__ import annotations
from dataclasses import fields
import pandas as pd
from feature_schema import CampaignDatasetRecord
IDENTIFIER_COLUMNS = ['campaign_id', 'attacker_ip', 'victim_ip']
LABEL_COLUMNS = ['severity', 'attributed_actor', 'prediction_correct', 'attribution_correct', 'next_technique']
LEAKAGE_COLUMNS = ['risk_score']
FEATURE_COLUMNS = [f.name for f in fields(CampaignDatasetRecord) if f.name not in IDENTIFIER_COLUMNS and f.name not in LABEL_COLUMNS and (f.name not in LEAKAGE_COLUMNS)]
FEATURE_SCHEMA_VERSION = 'campaign_dataset_v1'
MIN_TRAINING_ROWS = 30

def load_dataset():
    from ml.dataset_writer import writer
    return writer.load()

def validate_dataset_size(df: pd.DataFrame, min_rows: int=MIN_TRAINING_ROWS) -> None:
    if df.empty or len(df) < min_rows:
        raise ValueError(f'Not enough labeled campaign records to train a meaningful model: found {len(df)}, need at least {min_rows}. This dataset accumulates from real investigations via ml.dataset_builder.builder.build(...) as campaigns resolve — it cannot be backfilled without live data. For pipeline development/testing use ml/data_prep/generate_synthetic_dataset.py to produce a clearly-labeled synthetic fixture instead.')