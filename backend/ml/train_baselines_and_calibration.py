import argparse
import json
import logging
import sys
from pathlib import Path
import numpy as np
sys.path.insert(0, str(Path(__file__).parent.parent))
from ml.baselines.nbe_baseline import NaiveBayesEnsemble
from ml.confidence_calibration import ConfidenceCalibrator
from ml.dynamic_weights import DynamicWeightLearner
from ml.dynamic_thresholds import DynamicThresholdLearner
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def load_data(data_path: str):
    data = np.load(data_path, allow_pickle=True)
    features = data['features']
    labels = data['labels']
    scores = data['scores']
    correctness = data['correctness']
    n_features = features.shape[1]
    feature_names = ['ioc_overlap_score', 'transition_similarity', 'temporal_overlap', 'graph_similarity', 'persistence_indicator', 'feature_availability_score', 'trajectory_similarity', 'gnn_topology_similarity'][:n_features]
    logger.info(f'Loaded {len(features)} campaign pairs')
    logger.info(f'Positive pairs: {np.sum(labels == 1)}')
    logger.info(f'Negative pairs: {np.sum(labels == 0)}')
    logger.info(f'Features: {n_features}')
    return (features, labels, scores, correctness, feature_names)

def train_nbe_baseline(features, labels, feature_names, output_dir):
    logger.info('\n' + '=' * 60)
    logger.info('TRAINING NBE BASELINE')
    logger.info('=' * 60)
    nbe = NaiveBayesEnsemble()
    nbe.fit(features, labels, feature_names)
    nbe_path = Path(output_dir) / 'baselines' / 'nbe_baseline.pkl'
    nbe.save(str(nbe_path))
    logger.info(f'NBE baseline saved to {nbe_path}')
    return nbe

def train_confidence_calibrator(scores, correctness, output_dir):
    logger.info('\n' + '=' * 60)
    logger.info('TRAINING CONFIDENCE CALIBRATION')
    logger.info('=' * 60)
    best_calibrator = None
    best_ece = float('inf')
    for method in ['platt', 'isotonic', 'temperature']:
        logger.info(f'\nTrying method: {method}')
        calibrator = ConfidenceCalibrator(method=method)
        metrics = calibrator.fit(scores, correctness)
        logger.info(f"  ECE: {metrics['ece']:.4f}")
        if metrics['ece'] < best_ece:
            best_ece = metrics['ece']
            best_calibrator = calibrator
            logger.info(f'  ^ Best so far')
    calibrator_path = Path(output_dir) / 'confidence_calibrator.pkl'
    best_calibrator.save(str(calibrator_path))
    logger.info(f'\nBest calibrator: {best_calibrator.method}')
    logger.info(f'Saved to {calibrator_path}')
    return best_calibrator

def train_dynamic_weights(features, labels, feature_names, output_dir):
    logger.info('\n' + '=' * 60)
    logger.info('TRAINING DYNAMIC WEIGHTS')
    logger.info('=' * 60)
    best_learner = None
    best_score = 0.0
    for method in ['logistic', 'random_forest', 'gradient_boosting']:
        logger.info(f'\nTrying method: {method}')
        learner = DynamicWeightLearner(method=method)
        result = learner.fit(features, labels, feature_names)
        logger.info(f"  Validation accuracy: {result['validation_accuracy']:.4f}")
        if result['validation_accuracy'] > best_score:
            best_score = result['validation_accuracy']
            best_learner = learner
            logger.info(f'  ^ Best so far')
    learner_path = Path(output_dir) / 'weight_learner.pkl'
    best_learner.save(str(learner_path))
    logger.info(f'\nBest learner: {best_learner.method}')
    logger.info(f'Learned weights:')
    for name, weight in best_learner.learned_weights.items():
        logger.info(f'  {name}: {weight:.4f}')
    logger.info(f'Saved to {learner_path}')
    return best_learner

def train_dynamic_thresholds(scores, labels, output_dir):
    logger.info('\n' + '=' * 60)
    logger.info('TRAINING DYNAMIC THRESHOLDS')
    logger.info('=' * 60)
    threshold_learner = DynamicThresholdLearner(objective='f1')
    continue_result = threshold_learner.fit_continue_threshold(scores, labels)
    logger.info(f"Continue threshold: {continue_result['continue_threshold']:.3f}")
    logger.info(f"  F1 score: {continue_result['metric_value']:.4f}")
    reopen_result = threshold_learner.fit_reopen_threshold(scores, labels)
    logger.info(f"Reopen threshold: {reopen_result['reopen_threshold']:.3f}")
    logger.info(f"  F1 score: {reopen_result['metric_value']:.4f}")
    threshold_path = Path(output_dir) / 'threshold_learner.pkl'
    threshold_learner.save(str(threshold_path))
    logger.info(f'Saved to {threshold_path}')
    return threshold_learner

def save_report(output_dir, nbe, calibrator, weight_learner, threshold_learner, features, labels, scores, correctness):
    report = {'nbe_baseline': {'method': 'naive_bayes_ensemble', 'num_classifiers': len(nbe.classifiers)}, 'confidence_calibration': {'method': calibrator.method, 'metrics': calibrator.compute_metrics(scores, correctness)}, 'dynamic_weights': {'method': weight_learner.method, 'weights': weight_learner.learned_weights}, 'dynamic_thresholds': {'continue_threshold': threshold_learner.continue_threshold, 'reopen_threshold': threshold_learner.reopen_threshold}, 'dataset': {'num_pairs': len(features), 'num_positive': int(np.sum(labels == 1)), 'num_negative': int(np.sum(labels == 0)), 'baseline_accuracy': float(np.mean(correctness))}}
    report_path = Path(output_dir) / 'training_report.json'
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)
    logger.info(f'\nTraining report saved to {report_path}')

def main():
    parser = argparse.ArgumentParser(description='Train baselines and calibration models')
    parser.add_argument('--data', type=str, required=True, help='Path to campaign_pairs.npz')
    parser.add_argument('--output-dir', type=str, default='ml/models', help='Output directory')
    args = parser.parse_args()
    Path(args.output_dir).mkdir(parents=True, exist_ok=True)
    features, labels, scores, correctness, feature_names = load_data(args.data)
    nbe = train_nbe_baseline(features, labels, feature_names, args.output_dir)
    calibrator = train_confidence_calibrator(scores, correctness, args.output_dir)
    weight_learner = train_dynamic_weights(features, labels, feature_names, args.output_dir)
    threshold_learner = train_dynamic_thresholds(scores, labels, args.output_dir)
    save_report(args.output_dir, nbe, calibrator, weight_learner, threshold_learner, features, labels, scores, correctness)
    logger.info('\n' + '=' * 60)
    logger.info('TRAINING COMPLETE')
    logger.info('=' * 60)
if __name__ == '__main__':
    main()