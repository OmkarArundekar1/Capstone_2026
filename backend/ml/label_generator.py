from dataclasses import dataclass
from risk_scoring import normalize_risk_score, risk_level_from_score
from prediction_engine import predict_next_readonly
_LEVEL_TO_SEVERITY = {'CRITICAL': 'Critical', 'HIGH': 'High', 'MEDIUM': 'Medium', 'LOW': 'Low'}

@dataclass
class CampaignLabels:
    risk_score: float
    severity: str
    attributed_actor: str
    next_technique: str
    prediction_correct: int | None
    attribution_correct: int

class LabelGenerator:

    def generate(self, campaign_context, technique_sequence: list[str], final_attack_id: str, attributed_actor: str, actual_actor: str | None=None) -> CampaignLabels:
        risk = campaign_context.risk_score
        severity = _LEVEL_TO_SEVERITY[risk_level_from_score(normalize_risk_score(risk))]
        if len(technique_sequence) < 2:
            next_technique = ''
            prediction_correct = None
        else:
            previous_technique = technique_sequence[-2]
            next_technique = final_attack_id
            predicted = predict_next_readonly(previous_technique)
            prediction_correct = None if predicted is None else int(predicted['predicted'] == final_attack_id)
        if actual_actor is None:
            attribution_correct = 1
        else:
            attribution_correct = int(attributed_actor == actual_actor)
        return CampaignLabels(risk_score=risk, severity=severity, attributed_actor=attributed_actor, next_technique=next_technique, prediction_correct=prediction_correct, attribution_correct=attribution_correct)
generator = LabelGenerator()