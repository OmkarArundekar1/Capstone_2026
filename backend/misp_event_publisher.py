from __future__ import annotations
import logging
from datetime import datetime
from typing import Optional, Dict, List, Any
from dataclasses import dataclass
from cti_publisher import CTIPublisher
from neo4j_client import driver
logger = logging.getLogger(__name__)

@dataclass
class CampaignIntelligence:
    campaign_id: str
    attacker_ip: str
    victim_ip: str
    techniques: List[str]
    first_seen: datetime
    last_seen: datetime
    status: str
    risk_score: float
    severity: str
    alert_count: int
    operation_id: Optional[str] = None
    operation_name: Optional[str] = None
    attack_chain: List[str] = None

    def __post_init__(self):
        if self.attack_chain is None:
            self.attack_chain = []

class MISPEventPublisher:

    def __init__(self, misp_url: str, api_key: str, verify_ssl: bool=False):
        self.publisher = CTIPublisher(misp_url, api_key, verify_ssl)
        logger.info(f'Initialized MISPEventPublisher for {misp_url}')

    def get_campaign_intelligence(self, campaign_id: str) -> Optional[CampaignIntelligence]:
        try:
            with driver.session() as session:
                result = session.run('\n                    MATCH (c:Campaign {campaign_id: $campaign_id})\n                    OPTIONAL MATCH (c)-[:IN_OPERATION]->(o:Operation)\n                    OPTIONAL MATCH (c)-[:OBSERVED_TECHNIQUE]->(t:Technique)\n                    \n                    RETURN \n                        c.campaign_id AS campaign_id,\n                        c.attacker_ip AS attacker_ip,\n                        c.victim_ip AS victim_ip,\n                        c.first_seen AS first_seen,\n                        c.last_seen AS last_seen,\n                        c.status AS status,\n                        c.risk_score AS risk_score,\n                        c.severity AS severity,\n                        c.alert_count AS alert_count,\n                        o.operation_id AS operation_id,\n                        o.name AS operation_name,\n                        collect(DISTINCT t.attack_id) AS techniques\n                    ', campaign_id=campaign_id).single()
                if not result:
                    logger.warning(f'Campaign {campaign_id} not found in database')
                    return None
                chain_result = session.run('\n                    MATCH (c:Campaign {campaign_id: $campaign_id})\n                          -[:HAS_EVENT]->(e:AttackEvent)\n                          -[:REPRESENTS_TECHNIQUE]->(t:Technique)\n                    RETURN t.attack_id AS technique\n                    ORDER BY e.timestamp\n                    ', campaign_id=campaign_id)
                attack_chain = [r['technique'] for r in chain_result if r['technique']]
                return CampaignIntelligence(campaign_id=result['campaign_id'], attacker_ip=result['attacker_ip'], victim_ip=result['victim_ip'], techniques=result['techniques'] or [], first_seen=result['first_seen'], last_seen=result['last_seen'], status=result['status'], risk_score=result['risk_score'] or 0.0, severity=result['severity'] or 'UNKNOWN', alert_count=result['alert_count'] or 0, operation_id=result['operation_id'], operation_name=result['operation_name'], attack_chain=attack_chain)
        except Exception as e:
            logger.exception(f'Failed to extract campaign {campaign_id}: {e}')
            return None

    def build_misp_event(self, intel: CampaignIntelligence) -> Dict[str, Any]:
        threat_level_map = {'CRITICAL': '1', 'HIGH': '2', 'MEDIUM': '3', 'LOW': '4', 'UNKNOWN': '4'}
        threat_level = threat_level_map.get(intel.severity, '4')
        event_info = f'CYUKTI Campaign {intel.campaign_id}'
        if intel.operation_name:
            event_info += f' (Operation: {intel.operation_name})'
        tags = [{'name': f'cyukti:campaign-id="{intel.campaign_id}"'}, {'name': f'cyukti:severity="{intel.severity}"'}, {'name': f'cyukti:status="{intel.status}"'}]
        if intel.operation_id:
            tags.append({'name': f'cyukti:operation-id="{intel.operation_id}"'})
        for technique in intel.techniques:
            tags.append({'name': f'misp-galaxy:mitre-attack-pattern="{technique}"'})
        attributes = []
        attributes.append({'type': 'ip-src', 'category': 'Network activity', 'value': intel.attacker_ip, 'comment': 'Attacker source IP', 'to_ids': True})
        attributes.append({'type': 'ip-dst', 'category': 'Network activity', 'value': intel.victim_ip, 'comment': 'Target victim IP', 'to_ids': False})
        attributes.append({'type': 'text', 'category': 'Other', 'value': f'Risk Score: {intel.risk_score:.2f}', 'comment': 'CYUKTI computed risk score', 'to_ids': False})
        attributes.append({'type': 'counter', 'category': 'Other', 'value': str(intel.alert_count), 'comment': 'Number of alerts in campaign', 'to_ids': False})
        if intel.attack_chain:
            chain_str = ' -> '.join(intel.attack_chain)
            attributes.append({'type': 'text', 'category': 'Other', 'value': f'Attack Chain: {chain_str}', 'comment': 'Observed ATT&CK technique sequence', 'to_ids': False})
        attributes.append({'type': 'datetime', 'category': 'Other', 'value': intel.first_seen.isoformat() if isinstance(intel.first_seen, datetime) else str(intel.first_seen), 'comment': 'Campaign first seen', 'to_ids': False})
        attributes.append({'type': 'datetime', 'category': 'Other', 'value': intel.last_seen.isoformat() if isinstance(intel.last_seen, datetime) else str(intel.last_seen), 'comment': 'Campaign last seen', 'to_ids': False})
        event = {'Event': {'info': event_info, 'threat_level_id': threat_level, 'analysis': '2' if intel.status == 'ACTIVE' else '1', 'distribution': '3', 'published': False, 'Attribute': attributes, 'Tag': tags}}
        return event

    def publish_campaign(self, campaign_id: str, update: bool=False) -> Dict[str, Any]:
        try:
            intel = self.get_campaign_intelligence(campaign_id)
            if not intel:
                return {'success': False, 'error': f'Campaign {campaign_id} not found'}
            event = self.build_misp_event(intel)
            existing_event_id = self.publisher.search_campaign(campaign_id)
            if existing_event_id and update:
                result = self.publisher.update_event(existing_event_id, event)
                result['event_id'] = existing_event_id
                logger.info(f'Updated MISP event {existing_event_id} for campaign {campaign_id}')
            elif existing_event_id and (not update):
                return {'success': False, 'event_id': existing_event_id, 'error': 'Event already exists (use update=True to update)'}
            else:
                result = self.publisher.create_event(event)
                logger.info(f"Created MISP event {result.get('event_id')} for campaign {campaign_id}")
            return result
        except Exception as e:
            logger.exception(f'Failed to publish campaign {campaign_id}')
            return {'success': False, 'error': str(e)}

    def publish_operation(self, operation_id: str) -> Dict[str, Any]:
        try:
            with driver.session() as session:
                result = session.run('\n                    MATCH (o:Operation {operation_id: $operation_id})\n                          <-[:IN_OPERATION]-(c:Campaign)\n                    RETURN collect(c.campaign_id) AS campaigns\n                    ', operation_id=operation_id).single()
                if not result or not result['campaigns']:
                    return {'success': False, 'error': f'Operation {operation_id} not found or has no campaigns'}
                campaigns = result['campaigns']
                results = {}
                for campaign_id in campaigns:
                    results[campaign_id] = self.publish_campaign(campaign_id, update=True)
                success_count = sum((1 for r in results.values() if r.get('success')))
                logger.info(f'Published operation {operation_id}: {success_count}/{len(campaigns)} campaigns successful')
                return {'success': success_count == len(campaigns), 'operation_id': operation_id, 'campaigns': results, 'success_count': success_count, 'total_count': len(campaigns)}
        except Exception as e:
            logger.exception(f'Failed to publish operation {operation_id}')
            return {'success': False, 'error': str(e)}

    def health_check(self) -> bool:
        return self.publisher.health_check()

def create_publisher_from_config() -> MISPEventPublisher:
    import config
    return MISPEventPublisher(misp_url=config.MISP_URL, api_key=config.MISP_API_KEY, verify_ssl=config.VERIFY_MISP_SSL)