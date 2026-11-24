from cti_confidence_engine import CTIConfidenceEngine, PUBLISH_THRESHOLD, NOT_THREAT_THRESHOLD, THREAT_CLASSIFICATION_NOT_THREAT, THREAT_CLASSIFICATION_SUSPICIOUS, THREAT_CLASSIFICATION_QUALIFIED_THREAT
engine = CTIConfidenceEngine()

def test_classification_is_qualified_threat_at_or_above_publish_threshold():
    result = engine.calculate(100, 100, 100, 100, 100)
    assert result.score >= PUBLISH_THRESHOLD
    assert result.threat_classification == THREAT_CLASSIFICATION_QUALIFIED_THREAT
    assert result.publish is True

def test_classification_is_not_threat_for_all_zero_signals():
    result = engine.calculate(0, 0, 0, 0, 0)
    assert result.score < NOT_THREAT_THRESHOLD
    assert result.threat_classification == THREAT_CLASSIFICATION_NOT_THREAT
    assert result.publish is False

def test_classification_is_suspicious_in_the_gap_between_thresholds():
    result = engine.calculate(detection_confidence=50, risk_score=50, threat_confidence=0, campaign_confidence=0, prediction_confidence=0)
    assert NOT_THREAT_THRESHOLD <= result.score < PUBLISH_THRESHOLD
    assert result.threat_classification == THREAT_CLASSIFICATION_SUSPICIOUS
    assert result.publish is False

def test_publish_boolean_condition_is_unchanged_by_the_new_field():
    for args in [(0, 0, 0, 0, 0), (50, 50, 0, 0, 0), (100, 100, 100, 100, 100), (39, 0, 0, 0, 0)]:
        result = engine.calculate(*args)
        assert result.publish == (result.score >= PUBLISH_THRESHOLD)