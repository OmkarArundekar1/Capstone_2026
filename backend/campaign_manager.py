from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from threading import Lock
from config import CAMPAIGN_TIMEOUT, TPS_MAP
from mitre_mapper import MITRE_TO_STAGE

def _tps_for_technique(technique_id):
    stage = MITRE_TO_STAGE.get(technique_id, 'Unknown')
    return TPS_MAP.get(stage, 0)
from neo4j_client import get_active_campaign_db, get_recent_inactive_campaign_db, reopen_campaign_db, create_campaign_db, update_campaign_activity, close_campaign_db, store_prediction, archive_campaign_db, get_campaign_chain, expire_stale_campaigns_db, create_operation_db, attach_campaign_to_operation, update_operation_activity
from campaign_context import CampaignContext, TransitionContext
from campaign_feature_engine import engine as campaign_feature_engine
from campaign_decision_engine import engine as campaign_decision_engine
from campaign_correlation_engine import engine
from datetime_utils import normalize_datetime

def _log_gnn_nearest_topology_neighbor(campaign_id: str) -> None:
    try:
        import config
        if not config.GNN_ENABLED:
            return
        from rag.gnn_topology_retriever import GNNTopologyRetriever
        matches = GNNTopologyRetriever().query(campaign_id, top_k=1)
        if matches:
            content = matches[0].content
            print(f"{'GNN Topology':<15}: nearest={content['campaign_id']} similarity={content['topology_similarity']:.2f}")
        else:
            print(f"{'GNN Topology':<15}: N/A (no comparable historical campaign)")
    except Exception:
        import logging
        logging.getLogger(__name__).exception('GNN topology diagnostic failed for campaign %s -- continuing without it.', campaign_id)
ACTIVE = 'ACTIVE'
INACTIVE = 'INACTIVE'
REOPENED = 'REOPENED'
ARCHIVED = 'ARCHIVED'
ACTIVE_CONTINUE_THRESHOLD = 0.35
REOPEN_THRESHOLD = 0.7
CAMPAIGN_THRESHOLD = 50
PREDICTION_SCORE = 40
CHAIN_SCORE = 30
ACTIVE_SCORE = 20
HOST_SCORE = 20
REOPEN_PENALTY = 5

def _reference_time(event_time):
    return event_time if event_time is not None else datetime.now(timezone.utc)

def _later(current, candidate):
    if current is None:
        return candidate
    return candidate if candidate > current else current
DECISION_CREATE = 'CREATE'
DECISION_CONTINUE = 'CONTINUE'
DECISION_CLOSE_SCORE = 'CLOSE_BELOW_THRESHOLD'
DECISION_CLOSE_EXPIRED = 'CLOSE_EXPIRED'
DECISION_FAST_REOPEN = 'FAST_REOPEN'
DECISION_REOPEN = 'REOPEN'
DECISION_MAINTENANCE_EXPIRE = 'MAINTENANCE_EXPIRE'

class CampaignManager:

    def __init__(self):
        self.cache = {}
        self.lock = Lock()
        self.decision_log = None

    def _record(self, decision, context=None, event_time=None, **fields):
        if self.decision_log is None:
            return
        entry = {'decision': decision, 'campaign_id': getattr(context, 'campaign_id', None), 'attacker_ip': getattr(context, 'attacker_ip', None), 'victim_ip': getattr(context, 'victim_ip', None), 'event_time': event_time.isoformat() if event_time is not None else None}
        entry.update(fields)
        self.decision_log.append(entry)

    def reset(self):
        with self.lock:
            self.cache.clear()

    def _key(self, attacker_ip, victim_ip):
        return (attacker_ip, victim_ip)

    def _get_cached_campaign(self, attacker_ip, victim_ip):
        return self.cache.get(self._key(attacker_ip, victim_ip))

    def _store_cache(self, context):
        self.cache[self._key(context.attacker_ip, context.victim_ip)] = context

    def _remove_cache(self, attacker_ip, victim_ip):
        self.cache.pop(self._key(attacker_ip, victim_ip), None)

    def is_expired(self, context, reference_time=None):
        delta = _reference_time(reference_time) - context.last_seen
        return delta.total_seconds() > CAMPAIGN_TIMEOUT

    def close_expired_context(self, context, reference_time=None):
        closed_at = context.last_seen + timedelta(seconds=CAMPAIGN_TIMEOUT) if reference_time is not None else None
        close_campaign_db(context.campaign_id, closed_at=closed_at)
        context.status = INACTIVE
        self._store_cache(context)
        self._record(DECISION_CLOSE_EXPIRED, context, reference_time)

    def resolve_active_context_at(self, attacker_ip, victim_ip, event_time=None):
        context = self.resolve_campaign_context(attacker_ip, victim_ip)
        if context is not None and context.status == ACTIVE and self.is_expired(context, event_time):
            self.close_expired_context(context, event_time)
            return None
        return context

    def prediction_matches(self, context, current_technique):
        return context.predicted_next is not None and context.predicted_next == current_technique

    def update_prediction(self, campaign_id, predicted, confidence):
        store_prediction(campaign_id, predicted, confidence)
        for context in self.cache.values():
            if context.campaign_id == campaign_id:
                context.predicted_next = predicted
                context.prediction_confidence = confidence
                context.prediction_generated_at = datetime.now(timezone.utc)
                print('\n[PREDICTION STORED]')
                print(f'Campaign   : {campaign_id}')
                print(f'Next       : {predicted}')
                print(f'Confidence : {confidence}%')
                break

    def append_technique(self, context, technique, event_time=None):
        context.last_seen = _later(context.last_seen, _reference_time(event_time))
        context.last_technique = technique
        context.observed_chain.append(technique)
        context.risk_score += _tps_for_technique(technique)

    def load_from_database(self, attacker_ip, victim_ip, include_inactive=False):
        if include_inactive:
            data = get_recent_inactive_campaign_db(attacker_ip, victim_ip)
        else:
            data = get_active_campaign_db(attacker_ip, victim_ip)
        if data is None:
            return None
        last_seen = normalize_datetime(data['last_seen'])
        if last_seen.tzinfo is None:
            last_seen = last_seen.replace(tzinfo=timezone.utc)
        chain = get_campaign_chain(data['campaign_id'])
        risk_score = sum((_tps_for_technique(t) for t in chain))
        first_seen = normalize_datetime(data['first_seen'])
        if first_seen.tzinfo is None:
            first_seen = first_seen.replace(tzinfo=timezone.utc)
        context = CampaignContext(campaign_id=data['campaign_id'], attacker_ip=attacker_ip, victim_ip=victim_ip, status=data['status'], first_seen=first_seen, last_seen=last_seen, last_technique=data['last_technique'], observed_chain=chain, predicted_next=data['predicted_next'], prediction_confidence=data['prediction_confidence'], prediction_generated_at=data['prediction_generated_at'], reopened_count=data['reopened_count'], risk_score=risk_score)
        self._store_cache(context)
        return context

    def load_inactive_campaigns(self, attacker_ip, victim_ip):
        campaigns = get_recent_inactive_campaign_db(attacker_ip, victim_ip)
        contexts = []
        for data in campaigns:
            last_seen = normalize_datetime(data['last_seen'])
            if last_seen.tzinfo is None:
                last_seen = last_seen.replace(tzinfo=timezone.utc)
            chain = get_campaign_chain(data['campaign_id'])
            risk_score = sum((_tps_for_technique(t) for t in chain))
            first_seen = normalize_datetime(data['first_seen'])
            if first_seen.tzinfo is None:
                first_seen = first_seen.replace(tzinfo=timezone.utc)
            contexts.append(CampaignContext(campaign_id=data['campaign_id'], attacker_ip=attacker_ip, victim_ip=victim_ip, status=data['status'], first_seen=first_seen, last_seen=last_seen, last_technique=chain[-1] if chain else None, observed_chain=chain, predicted_next=data['predicted_next'], prediction_confidence=data['prediction_confidence'], prediction_generated_at=data['prediction_generated_at'], reopened_count=data['reopened_count'], risk_score=risk_score))
        return contexts

    def resolve_campaign_context(self, attacker_ip, victim_ip, include_inactive=False):
        with self.lock:
            context = self._get_cached_campaign(attacker_ip, victim_ip)
            if context:
                if include_inactive or context.status == ACTIVE:
                    return context
            context = self.load_from_database(attacker_ip, victim_ip, include_inactive)
            return context

    def create_campaign_context(self, attacker_ip, victim_ip, current_technique, event_time=None):
        print('\n################################')
        print('CREATE_CAMPAIGN_CONTEXT CALLED')
        print(f'Attacker : {attacker_ip}')
        print(f'Victim   : {victim_ip}')
        print('################################')
        campaign_id = create_campaign_db(attacker_ip, victim_ip, event_time=event_time)
        print(f'Created Campaign : {campaign_id}')
        now = _reference_time(event_time)
        context = CampaignContext(campaign_id=campaign_id, attacker_ip=attacker_ip, victim_ip=victim_ip, last_technique=current_technique, observed_chain=[current_technique], first_seen=now, last_seen=now)
        context.skip_next_chain_update = True
        self._store_cache(context)
        self._record(DECISION_CREATE, context, event_time, technique=current_technique)
        return context

    def expire_active_campaigns(self, reference_time=None):
        now = _reference_time(reference_time)
        for context in list(self.cache.values()):
            if context.status != ACTIVE:
                continue
            age = (now - context.last_seen).total_seconds()
            if age > CAMPAIGN_TIMEOUT:
                print(f'[CACHE EXPIRED] {context.campaign_id}')
                close_campaign_db(context.campaign_id, closed_at=context.last_seen + timedelta(seconds=CAMPAIGN_TIMEOUT) if reference_time is not None else None)
                context.status = INACTIVE
                self._store_cache(context)
                self._record(DECISION_MAINTENANCE_EXPIRE, context, reference_time, source='cache')
        expired = expire_stale_campaigns_db(CAMPAIGN_TIMEOUT, reference_time=reference_time)
        for campaign_id in expired:
            print(f'[DB EXPIRED] {campaign_id}')
            context = self.get_context_by_campaign_id(campaign_id)
            if context:
                context.status = INACTIVE
                self._store_cache(context)
                self._record(DECISION_MAINTENANCE_EXPIRE, context, reference_time, source='db')

    def resolve_campaign(self, attacker_ip, victim_ip, current_technique, event_time=None):
        context = self.resolve_campaign_context(attacker_ip, victim_ip)
        if context:
            if self.is_expired(context, event_time):
                self.close_expired_context(context, event_time)
            else:
                features = campaign_feature_engine.extract(context, current_technique, attacker_ip, reference_time=event_time)
                decision = campaign_decision_engine.evaluate(features)
                print('\n========== CAMPAIGN FEATURES ==========\n')
                feature_labels = {'transition_similarity': 'Transition', 'temporal_similarity': 'Temporal', 'attacker_similarity': 'Attacker', 'duplicate_similarity': 'Duplicate', 'graph_similarity': 'Graph', 'runtime_similarity': 'Runtime'}
                for key, label in feature_labels.items():
                    value = decision.breakdown.get(key)
                    display = f'{value:.2f}' if value is not None else 'N/A'
                    print(f'{label:<15}: {display}')
                _log_gnn_nearest_topology_neighbor(context.campaign_id)
                print('\n--------------------------------------')
                print(f"{'Score':<15}: {decision.score:.2f}")
                print(f"{'Confidence':<15}: {decision.confidence:.2f}% ({decision.available_features}/{decision.total_features})")
                print('\n======================================')
                if decision.score >= ACTIVE_CONTINUE_THRESHOLD:
                    print(f'[CAMPAIGN] Continuing active campaign ({decision.score:.2f})')
                    self._record(DECISION_CONTINUE, context, event_time, technique=current_technique, score=round(decision.score, 6))
                    return context
                print(f'[CAMPAIGN] Closing campaign ({decision.score:.2f})')
                close_campaign_db(context.campaign_id, closed_at=event_time)
                context.status = INACTIVE
                self._store_cache(context)
                self._record(DECISION_CLOSE_SCORE, context, event_time, technique=current_technique, score=round(decision.score, 6))
        inactive_campaigns = self.load_inactive_campaigns(attacker_ip, victim_ip)
        best = None
        best_score = -1.0
        matching_campaigns = []
        for context in inactive_campaigns:
            print('\n===== INACTIVE CANDIDATE =====')
            print(f'Campaign : {context.campaign_id}')
            first_technique = context.observed_chain[0] if context.observed_chain else None
            temporal = campaign_feature_engine.temporal_similarity(context, event_time)
            if first_technique == current_technique and temporal >= 0.8 and (context.attacker_ip == attacker_ip) and (context.victim_ip == victim_ip):
                print('\n==============================')
                print('[FAST CAMPAIGN REOPEN]')
                print(f'Campaign : {context.campaign_id}')
                print(f'Technique: {current_technique}')
                print('==============================')
                reopen_campaign_db(context.campaign_id, event_time=event_time)
                context.status = ACTIVE
                context.last_seen = _later(context.last_seen, _reference_time(event_time))
                context.last_technique = current_technique
                context.reopened_count += 1
                context.skip_next_chain_update = True
                self._store_cache(context)
                self._record(DECISION_FAST_REOPEN, context, event_time, technique=current_technique)
                return context
            features = campaign_feature_engine.extract(context, current_technique, attacker_ip, reference_time=event_time)
            decision = campaign_decision_engine.evaluate(features)
            for key, value in decision.breakdown.items():
                print(f'{key:<25}: {value}')
            print(f'Score                    : {decision.score:.2f}')
            print(f'Threshold                : {REOPEN_THRESHOLD}')
            print('==============================')
            if decision.score >= REOPEN_THRESHOLD:
                matching_campaigns.append((context, decision.score))
            if decision.score > best_score or (decision.score == best_score and (best is None or context.last_seen > best.last_seen)):
                best = context
                best_score = decision.score
        if len(matching_campaigns) > 1:
            print('\n========== REOPEN AMBIGUITY ==========')
            matching_campaigns.sort(key=lambda x: x[1], reverse=True)
            for ctx, score in matching_campaigns:
                print(f'{ctx.campaign_id} ({score:.2f})')
            print('======================================')
        if best and best_score >= REOPEN_THRESHOLD:
            reopen_campaign_db(best.campaign_id, event_time=event_time)
            best.status = ACTIVE
            best.last_seen = _later(best.last_seen, _reference_time(event_time))
            best.last_technique = current_technique
            best.reopened_count += 1
            best.skip_next_chain_update = True
            self._store_cache(best)
            print('\n==============================')
            print('[CAMPAIGN REOPENED]')
            print(f'Campaign : {best.campaign_id}')
            print(f'Score    : {best_score:.2f}')
            print(f'Technique: {current_technique}')
            print('==============================')
            self._record(DECISION_REOPEN, best, event_time, technique=current_technique, score=round(best_score, 6))
            return best
        self._remove_cache(attacker_ip, victim_ip)
        return self.create_campaign_context(attacker_ip, victim_ip, current_technique, event_time=event_time)

    def activate_campaign(self, context, technique, event_time=None):
        return self.activate_campaign_with_transition(context, technique, event_time=event_time).campaign_id

    def activate_campaign_with_transition(self, context, technique, event_time=None):
        segment_start = bool(context.skip_next_chain_update)
        transition = TransitionContext(campaign_id=context.campaign_id, current_technique=technique, previous_technique=None if segment_start else context.last_technique or None, segment_start=segment_start)
        context.skip_next_chain_update = False
        context.status = ACTIVE
        context.last_seen = _later(context.last_seen, _reference_time(event_time))
        context.predicted_next = None
        context.prediction_confidence = 0.0
        self.append_technique(context, technique, event_time=event_time)
        update_campaign_activity(context.campaign_id, technique, event_time=event_time)
        print(f'[CAMPAIGN] {context.campaign_id} ACTIVE')
        return transition

    def get_or_create_campaign(self, attacker_ip, victim_ip, current_technique, event_time=None):
        return self.get_or_create_campaign_with_transition(attacker_ip, victim_ip, current_technique, event_time=event_time).campaign_id

    def get_or_create_campaign_with_transition(self, attacker_ip, victim_ip, current_technique, event_time=None):
        context = self.resolve_campaign(attacker_ip, victim_ip, current_technique, event_time=event_time)
        return self.activate_campaign_with_transition(context, current_technique, event_time=event_time)

    def is_chain_continuation(self, previous_technique, current_technique):
        if previous_technique is None:
            return False
        from neo4j_client import driver
        with driver.session() as session:
            try:
                result = session.run('\n                    MATCH (:Technique {attack_id:$previous})\n                          -[:NEXT_TECHNIQUE]->\n                          (:Technique {attack_id:$current})\n\n                    RETURN COUNT(*) AS cnt\n                    ', previous=previous_technique, current=current_technique)
                record = result.single()
                return record['cnt'] > 0
            except Exception as e:
                print(f'[CHAIN LOOKUP ERROR] {e}')
                return False

    def archive_old_campaigns(self):
        expired = []
        for key, context in self.cache.items():
            if context.status == INACTIVE and self.is_expired(context):
                context.status = ARCHIVED
                context.last_technique = None
                context.predicted_next = None
                context.prediction_confidence = 0.0
                archive_campaign_db(context.campaign_id)
                expired.append(key)
        for key in expired:
            del self.cache[key]

    def get_context_by_campaign_id(self, campaign_id):
        for context in self.cache.values():
            if context.campaign_id == campaign_id:
                return context
        return None

    def cleanup_cache(self):
        self.archive_old_campaigns()
campaign_manager = CampaignManager()