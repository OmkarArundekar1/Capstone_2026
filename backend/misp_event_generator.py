from dataclasses import dataclass
from datetime import datetime, timezone

@dataclass
class MISPEvent:
    info: str
    distribution: int
    threat_level_id: int
    analysis: int
    published: bool
    attributes: list
    tags: list

@dataclass
class IncidentContext:
    campaign_id: str
    operation_id: str
    attacker_ip: str
    victim_ip: str
    event_id: str
    technique: str
    stage: str
    prediction: str
    prediction_confidence: float
    detection: object
    threat: object
    dynamic_risk: object
    cti: object
    recommendations: list
    investigation_payload: str
    timestamp: str
    attribution: object = None

class MISPEventGenerator:

    def _risk_to_threat_level(self, risk):
        if risk >= 70:
            return 1
        elif risk >= 40:
            return 2
        return 3

    def generate(self, incident: IncidentContext):
        attributes = [{'type': 'ip-src', 'category': 'Network activity', 'value': incident.attacker_ip}, {'type': 'comment', 'category': 'Other', 'value': f'Victim : {incident.victim_ip}'}, {'type': 'text', 'category': 'Other', 'value': f'Campaign : {incident.campaign_id}'}, {'type': 'text', 'category': 'Other', 'value': f'Operation : {incident.operation_id}'}, {'type': 'text', 'category': 'Other', 'value': f'Technique : {incident.technique}'}, {'type': 'text', 'category': 'Other', 'value': f'Predicted : {incident.prediction}'}, {'type': 'text', 'category': 'Other', 'value': f'Prediction Confidence : {incident.prediction_confidence}'}, {'type': 'text', 'category': 'Other', 'value': f'Dynamic Risk : {incident.dynamic_risk.risk_score}'}, {'type': 'text', 'category': 'Other', 'value': f'CTI Confidence : {incident.cti.score}'}, {'type': 'text', 'category': 'Other', 'value': f'Attack Event : {incident.event_id}'}]
        if incident.attribution and incident.attribution.actors:
            best = incident.attribution.actors[0]
            attributes.extend([{'type': 'text', 'category': 'Other', 'value': f'Threat Actor : {best.actor}'}, {'type': 'text', 'category': 'Other', 'value': f'Attribution Confidence : {best.total_score:.2f}'}, {'type': 'text', 'category': 'Other', 'value': f'Coverage : {best.coverage:.2f}'}, {'type': 'text', 'category': 'Other', 'value': f'Precision : {best.precision:.2f}'}, {'type': 'text', 'category': 'Other', 'value': f'Chain Similarity : {best.chain_similarity:.2f}'}])
            for evidence in best.evidence:
                attributes.append({'type': 'comment', 'category': 'Other', 'value': evidence})
        for recommendation in incident.recommendations:
            text = recommendation['recommendation'] if isinstance(recommendation, dict) else recommendation
            attributes.append({'type': 'comment', 'category': 'Other', 'value': text})
        tags = [f'mitre:{incident.technique}', f'stage:{incident.stage}', f'campaign:{incident.campaign_id}', f'operation:{incident.operation_id}', f'prediction:{incident.prediction}', f'cti:{incident.cti.level}', f'risk:{incident.dynamic_risk.risk_level}']
        if incident.attribution and incident.attribution.actors:
            best = incident.attribution.actors[0]
            tags.extend([f'actor:{best.actor}', f'attribution:{int(best.total_score)}'])
        event = MISPEvent(info=f'CYUKTI Campaign {incident.campaign_id}', distribution=0, threat_level_id=self._risk_to_threat_level(incident.dynamic_risk.risk_score), analysis=2, published=False, attributes=attributes, tags=tags)
        summary = f'\n        ================ CYUKTI INCIDENT REPORT ================\n        \n        Campaign ID          : {incident.campaign_id}\n        Operation ID         : {incident.operation_id}\n        Attack Event         : {incident.event_id}\n        \n        Timestamp            : {incident.timestamp}\n        \n        Attacker             : {incident.attacker_ip}\n        Victim               : {incident.victim_ip}\n        \n        Current Technique    : {incident.technique}\n        Current Stage        : {incident.stage}\n        \n        Prediction           : {incident.prediction}\n        Prediction Confidence: {incident.prediction_confidence:.2f}\n        \n        ========================================================\n        '
        detection_section = f"\n        ================ DETECTION =================\n        \n        Detection Confidence : {incident.detection.confidence:.2f}\n        Detection Level      : {incident.detection.level}\n        \n        Wazuh Score          : {incident.detection.breakdown['Wazuh']}\n        Suricata Score       : {incident.detection.breakdown['Suricata']}\n        Zeek Score           : {incident.detection.breakdown['Zeek']}\n        Sigma Score          : {incident.detection.breakdown['Sigma']}\n        YARA Score           : {incident.detection.breakdown['YARA']}\n        \n        ===========================================\n        "
        risk_section = f'\n        ================ DYNAMIC RISK =================\n        \n        Risk Score      : {incident.dynamic_risk.risk_score:.2f}\n        Risk Level      : {incident.dynamic_risk.risk_level}\n        \n        Confidence      : {incident.dynamic_risk.confidence:.2f}\n        \n        ===============================================\n        '
        cti_section = f'\n        ================ CTI =================\n        \n        CTI Score       : {incident.cti.score:.2f}\n        \n        CTI Level       : {incident.cti.level}\n        \n        Publish         : {incident.cti.publish}\n        \n        ======================================\n        '
        attribution_section = ''
        if incident.attribution and incident.attribution.actors:
            best = incident.attribution.actors[0]
            attribution_section = f"\n        =============== THREAT ATTRIBUTION ===============\n        \n        Likely Actor      : {best.actor}\n        Confidence        : {best.total_score:.2f}\n        Coverage          : {best.coverage:.2f}\n        Precision         : {best.precision:.2f}\n        Chain Similarity  : {best.chain_similarity:.2f}\n        \n        Evidence:\n        {chr(10).join(('- ' + e for e in best.evidence))}\n        \n        ==============================================\n        "
        recommendation_text = '\n'.join((f'- {r}' for r in incident.recommendations))
        incident_report = summary + detection_section + risk_section + cti_section + attribution_section + '\nRecommendations\n' + recommendation_text
        return {'Event': {'info': event.info, 'distribution': event.distribution, 'threat_level_id': event.threat_level_id, 'analysis': event.analysis, 'published': event.published, 'date': datetime.now(timezone.utc).strftime('%Y-%m-%d'), 'Attribute': event.attributes, 'Tag': [{'name': tag} for tag in event.tags]}}
engine = MISPEventGenerator()