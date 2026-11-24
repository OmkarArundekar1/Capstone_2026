from dataclasses import dataclass, field

@dataclass
class _FakeCampaignContext:
    risk_score: float
    attack_chain: list = field(default_factory=list)

def test_label_generator_normalizes_before_thresholding():
    from ml.label_generator import generator
    low = generator.generate(_FakeCampaignContext(risk_score=90), ['T1110'], 'T1110', 'unknown')
    medium = generator.generate(_FakeCampaignContext(risk_score=630), ['T1110'], 'T1110', 'unknown')
    critical = generator.generate(_FakeCampaignContext(risk_score=8330), ['T1110'], 'T1110', 'unknown')
    assert low.severity == 'Low'
    assert medium.severity == 'Medium'
    assert critical.severity == 'Critical'

def test_single_event_campaign_yields_not_applicable(monkeypatch):
    from ml import label_generator

    def _should_not_be_called(_current):
        raise AssertionError('predict_next_readonly must not be called with < 2 techniques')
    monkeypatch.setattr(label_generator, 'predict_next_readonly', _should_not_be_called)
    ctx = _FakeCampaignContext(risk_score=0)
    labels = label_generator.generator.generate(ctx, ['T1595'], 'T1595', 'unknown')
    assert labels.next_technique == ''
    assert labels.prediction_correct is None

def test_no_learned_transition_yields_not_applicable(monkeypatch):
    from ml import label_generator
    monkeypatch.setattr(label_generator, 'predict_next_readonly', lambda current: None)
    ctx = _FakeCampaignContext(risk_score=0)
    labels = label_generator.generator.generate(ctx, ['T1595', 'T1595'], 'T1595', 'unknown')
    assert labels.next_technique == 'T1595'
    assert labels.prediction_correct is None

def test_correct_prediction_recomputed_from_second_to_last_technique(monkeypatch):
    from ml import label_generator
    calls = []

    def _fake_predict(current):
        calls.append(current)
        return {'predicted': 'T1110', 'confidence': 100.0}
    monkeypatch.setattr(label_generator, 'predict_next_readonly', _fake_predict)
    ctx = _FakeCampaignContext(risk_score=0)
    labels = label_generator.generator.generate(ctx, ['T1110.001', 'T1110'], 'T1110', 'unknown')
    assert calls == ['T1110.001']
    assert labels.next_technique == 'T1110'
    assert labels.prediction_correct == 1

def test_incorrect_prediction_recomputed_from_second_to_last_technique(monkeypatch):
    from ml import label_generator
    monkeypatch.setattr(label_generator, 'predict_next_readonly', lambda current: {'predicted': 'T1078', 'confidence': 100.0})
    ctx = _FakeCampaignContext(risk_score=0)
    labels = label_generator.generator.generate(ctx, ['T1110.001', 'T1110'], 'T1110', 'unknown')
    assert labels.next_technique == 'T1110'
    assert labels.prediction_correct == 0

def test_longer_sequence_only_evaluates_the_final_transition(monkeypatch):
    from ml import label_generator
    calls = []

    def _fake_predict(current):
        calls.append(current)
        return {'predicted': 'T1078', 'confidence': 100.0}
    monkeypatch.setattr(label_generator, 'predict_next_readonly', _fake_predict)
    ctx = _FakeCampaignContext(risk_score=0)
    labels = label_generator.generator.generate(ctx, ['T1110.001', 'T1110', 'T1078'], 'T1078', 'unknown')
    assert calls == ['T1110']
    assert labels.prediction_correct == 1