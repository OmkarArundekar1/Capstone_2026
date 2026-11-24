import json
import os
import sys
BACKEND = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'backend')
sys.path.insert(0, BACKEND)
os.chdir(BACKEND)
from campaign_context import CampaignContext
from neo4j_client import driver
from investigation.loop import default_action_executor, default_model_predictor, run_investigation
CAMPAIGN_IDS = ['CAMP_427A075C', 'CAMP_1429ADB4', 'CAMP_D8605E81']

def load_context(session, campaign_id):
    record = session.run('\n        MATCH (c:Campaign {campaign_id: $campaign_id})\n        OPTIONAL MATCH (a:Attacker)-[:LAUNCHED]->(c)\n        OPTIONAL MATCH (c)-[:TARGETS]->(h:Host)\n        OPTIONAL MATCH (c)-[:HAS_EVENT]->(e:AttackEvent)-[:MATCHES]->(t:Technique)\n        OPTIONAL MATCH (c)-[pred:LIKELY_NEXT]->(pt:Technique)\n        WITH c, a, h, collect(DISTINCT t.attack_id) AS techniques,\n             collect(DISTINCT e.event_id)[0] AS sample_event_id,\n             pt.attack_id AS predicted_next, pred.confidence AS prediction_confidence\n        RETURN c, a.ip AS attacker_ip, h.ip AS victim_ip, techniques, sample_event_id,\n               predicted_next, prediction_confidence\n        ', campaign_id=campaign_id).single()
    c = record['c']
    context = CampaignContext(campaign_id=campaign_id, attacker_ip=record['attacker_ip'] or '', victim_ip=record['victim_ip'] or '', risk_score=c.get('risk_score', 0.0) or 0.0, last_technique=c.get('last_technique'), first_seen=c.get('first_seen').to_native() if c.get('first_seen') else None, last_seen=c.get('last_seen').to_native() if c.get('last_seen') else None, predicted_next=record['predicted_next'], prediction_confidence=record['prediction_confidence'] or 0.0)
    techniques = [t for t in record['techniques'] or [] if t]
    context.techniques = set(techniques)
    context.attack_chain = techniques
    return (context, record['sample_event_id'])

def main():
    for campaign_id in CAMPAIGN_IDS:
        print(f"\n{'=' * 70}\nCAMPAIGN: {campaign_id}\n{'=' * 70}")
        with driver.session() as session:
            context, event_id = load_context(session, campaign_id)
        print(f'attacker={context.attacker_ip} victim={context.victim_ip} techniques={sorted(context.techniques)} last_technique={context.last_technique} risk_score={context.risk_score}')
        current_attack_id = context.last_technique or (sorted(context.techniques)[0] if context.techniques else None)
        if not current_attack_id:
            print('SKIPPED: no technique available to investigate from')
            continue
        executor = default_action_executor(context, current_attack_id, event_id)
        model_predictor = default_model_predictor(context, current_attack_id, event_id or '')
        print(f'model_predictor available: {model_predictor is not None}')
        try:
            record = run_investigation(executor, model_predictor=model_predictor, confidence_threshold=0.75, max_steps=8)
        except Exception as e:
            print(f'INVESTIGATION FAILED: {type(e).__name__}: {e}')
            import traceback
            traceback.print_exc()
            continue
        fc = record.final_confidence
        print(f'\nFinal investigation_confidence: {(fc.investigation_confidence if fc else None)}')
        print(f'Final uncertainty: {(fc.uncertainty if fc else None)}')
        print(f'Final model_probabilities: {(fc.model_probabilities if fc else None)}')
        print(f'Final model_uncertainty: {(fc.model_uncertainty if fc else None)}')
        print(f'Final evidence_reliability: {(fc.evidence_reliability if fc else None)}')
        print(f'Final evidence_coverage: {(fc.evidence_coverage if fc else None)}')
        print(f'Stopping reason: {record.stopping_reason}')
        print(f'Total evidence gathered: {len(record.evidence_store)}')
        for step in record.steps:
            ca = step.confidence_after
            print(f'\n  step {step.step_index}: action={step.action_taken.value} selection_value={step.action_value.value} (reliability={step.action_value.reliability}, novelty={step.action_value.novelty}, uncertainty_reduction={step.action_value.uncertainty_reduction}, cost={step.action_value.cost}, latency={step.action_value.latency}) evidence_added={step.evidence_added}')
            print(f'    model_probabilities={ca.model_probabilities} model_confidence={ca.model_confidence} model_uncertainty={ca.model_uncertainty}')
            print(f'    evidence_reliability={ca.evidence_reliability} evidence_coverage={ca.evidence_coverage} investigation_confidence={ca.investigation_confidence} uncertainty={ca.uncertainty} conflicts={ca.conflict_count}')
        print('\n  Evidence collected:')
        for e in record.evidence_store.all():
            print(f'    [{e.source.value}/{e.type.value}] id={e.source_id} conf={e.confidence:.2f} rel={e.relevance:.2f} provenance={e.provenance}')
if __name__ == '__main__':
    main()