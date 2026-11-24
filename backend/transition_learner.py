from datetime import datetime, timezone, timedelta
from neo4j_client import driver
from config import CAMPAIGN_TIMEOUT
LEARNING_TIME_WINDOW = CAMPAIGN_TIMEOUT * 2

class TransitionLearner:

    def __init__(self):
        self.attacker_cache = {}

    def record_attacker_activity(self, attacker_ip: str, technique: str, event_time: datetime=None):
        if event_time is None:
            event_time = datetime.now(timezone.utc)
        if attacker_ip not in self.attacker_cache:
            self.attacker_cache[attacker_ip] = (technique, event_time)
            return False
        previous_technique, previous_time = self.attacker_cache[attacker_ip]
        self.attacker_cache[attacker_ip] = (technique, event_time)
        if previous_technique == technique:
            print(f'[LEARNER] Skipping self-transition: {technique}')
            return False
        time_gap = (event_time - previous_time).total_seconds()
        if time_gap > LEARNING_TIME_WINDOW:
            print(f'[LEARNER] Time gap too large: {time_gap:.1f}s > {LEARNING_TIME_WINDOW}s')
            return False
        return self._learn_transition(previous_technique, technique, attacker_ip, time_gap)

    def _learn_transition(self, previous: str, current: str, attacker_ip: str, time_gap: float) -> bool:
        try:
            with driver.session() as session:
                existing = session.run('\n                    MATCH (a:Technique {attack_id: $src})\n                          -[r:NEXT_TECHNIQUE]->\n                          (b:Technique {attack_id: $dst})\n                    RETURN r.count AS count\n                    ', src=previous, dst=current).single()
                if existing and existing['count'] > 0:
                    print(f'[LEARNER] Transition already known: {previous} -> {current}')
                    return False
                print(f'\n[LEARNER] Learning new transition from attacker behavior')
                print(f'  Attacker : {attacker_ip}')
                print(f'  Transition: {previous} -> {current}')
                print(f'  Time gap : {time_gap:.1f}s')
                session.run('\n                    MATCH (a:Technique {attack_id: $src})\n                    MATCH (b:Technique {attack_id: $dst})\n                    \n                    MERGE (a)-[r:NEXT_TECHNIQUE]->(b)\n                    \n                    ON CREATE SET\n                        r.count = 1,\n                        r.created_at = datetime(),\n                        r.last_seen = datetime(),\n                        r.confidence = 1.0,\n                        r.learned_from_splits = true\n                    \n                    ON MATCH SET\n                        r.count = r.count + 1,\n                        r.last_seen = datetime(),\n                        r.learned_from_splits = coalesce(r.learned_from_splits, false)\n                    ', src=previous, dst=current)
                session.run('\n                    MATCH (a:Technique {attack_id: $src})-[r:NEXT_TECHNIQUE]->()\n                    \n                    WITH collect(r) AS rels,\n                         sum(r.count) AS total\n                    \n                    UNWIND rels AS rel\n                    \n                    SET rel.confidence =\n                        CASE\n                            WHEN total = 0 THEN 0.0\n                            ELSE toFloat(rel.count) / total\n                        END\n                    ', src=previous)
                print(f'[LEARNER] Successfully learned transition\n')
                return True
        except Exception as e:
            print(f'[LEARNER ERROR] Failed to learn transition: {e}')
            return False

    def cleanup_cache(self, older_than_seconds: float=None):
        if older_than_seconds is None:
            older_than_seconds = LEARNING_TIME_WINDOW
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=older_than_seconds)
        stale_attackers = [ip for ip, (_, last_seen) in self.attacker_cache.items() if last_seen < cutoff]
        for ip in stale_attackers:
            del self.attacker_cache[ip]
        if stale_attackers:
            print(f'[LEARNER] Cleaned up {len(stale_attackers)} stale attacker entries')
learner = TransitionLearner()