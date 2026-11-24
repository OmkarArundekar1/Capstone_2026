from neo4j_client import driver
from campaign_manager import campaign_manager
from config import MIN_PREDICTION_CONFIDENCE, MIN_TRANSITION_OBSERVATIONS

def predict_next_readonly(current_technique):
    try:
        with driver.session() as session:
            result = session.run('\n                MATCH (t:Technique {attack_id: $current})\n                      -[r:NEXT_TECHNIQUE]->\n                      (n:Technique)\n\n                RETURN\n                    n.attack_id AS next,\n                    r.count AS count\n\n                ORDER BY r.count DESC\n                ', current=current_technique)
            rows = list(result)
            if not rows:
                print(f'[PREDICTION] No learned transitions for {current_technique}')
                return None
            total = sum((row['count'] for row in rows))
            if total < MIN_TRANSITION_OBSERVATIONS:
                print(f'[PREDICTION] Insufficient observations ({total} < {MIN_TRANSITION_OBSERVATIONS})')
                return None
            best = rows[0]
            confidence = round(best['count'] / total * 100, 2)
            if confidence < MIN_PREDICTION_CONFIDENCE:
                print(f'[PREDICTION] Confidence below threshold ({confidence}% < {MIN_PREDICTION_CONFIDENCE}%)')
                return None
            return {'current': current_technique, 'predicted': best['next'], 'confidence': confidence, 'transition_count': best['count'], 'total_transitions': total}
    except Exception as e:
        print(f'[PREDICTION ERROR] {e}')
        return None

def predict_next(campaign_id, current_technique):
    result = predict_next_readonly(current_technique)
    if result is None:
        return None
    campaign_manager.update_prediction(campaign_id, result['predicted'], result['confidence'])
    print('\n[PREDICTION]')
    print(f"Current      : {result['current']}")
    print(f"Predicted    : {result['predicted']}")
    print(f"Transitions  : {result['transition_count']}")
    print(f"Total Seen   : {result['total_transitions']}")
    print(f"Confidence   : {result['confidence']}%")
    return result