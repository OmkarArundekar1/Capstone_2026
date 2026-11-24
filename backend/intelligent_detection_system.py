from __future__ import annotations

import logging
import uuid
from typing import Dict, Any, List, Optional
from datetime import datetime

from hybrid_threat_enrichment import get_enricher, EnrichedIOC
from threat_enrichment_integration import (
    enrich_and_update_attacker,
    get_attacker_enrichment,
    generate_threat_report
)
from enhanced_detection_output import (
    DetectionAlert,
    AttackerProfile,
    SuggestedAction,
    AlertSeverity,
    ActionStatus,
    EnhancedOutputFormatter
)
from action_approval_system import (
    get_approval_manager,
    get_executor
)
from neo4j_client import driver

logger = logging.getLogger(__name__)


class IntelligentDetectionSystem:
    def __init__(
        self,
        auto_enrich: bool = True,
        auto_execute_safe_actions: bool = True,
        dry_run: bool = False
    ):
        self.auto_enrich = auto_enrich
        self.auto_execute_safe_actions = auto_execute_safe_actions
        self.dry_run = dry_run

        self.enricher = get_enricher()
        self.approval_manager = get_approval_manager()
        self.executor = get_executor(dry_run=dry_run)
        self.formatter = EnhancedOutputFormatter()

        logger.info(
            f"IntelligentDetectionSystem initialized: "
            f"auto_enrich={auto_enrich}, "
            f"auto_execute={auto_execute_safe_actions}, "
            f"dry_run={dry_run}"
        )

    def process_alert(
        self,
        campaign_id: str,
        attacker_ip: str,
        victim_ip: str,
        technique_id: str,
        technique_name: str,
        stage: str,
        rule_id: str,
        rule_description: str,
        rule_level: int,
        event_count: int = 1,
        output_format: str = "full"
    ) -> DetectionAlert:
        logger.info(
            f"Processing alert: {technique_id} from {attacker_ip} → {victim_ip}"
        )

        attacker_profile = self._get_attacker_profile(attacker_ip)

        threat_assessment = self._generate_threat_assessment(
            attacker_profile, technique_id, stage, rule_level
        )

        suggested_actions = self._generate_suggestions(
            attacker_profile, technique_id, stage, campaign_id,
            attacker_ip, victim_ip
        )

        alert = DetectionAlert(
            alert_id=str(uuid.uuid4()),
            timestamp=datetime.utcnow(),
            severity=attacker_profile.get_severity(),
            campaign_id=campaign_id,
            attacker=attacker_profile,
            victim_ip=victim_ip,
            technique_id=technique_id,
            technique_name=technique_name,
            stage=stage,
            is_new_attacker=attacker_profile.total_campaigns <= 1,
            is_known_malicious=attacker_profile.is_known_malicious,
            threat_assessment=threat_assessment,
            suggested_actions=suggested_actions,
            rule_id=rule_id,
            rule_description=rule_description,
            rule_level=rule_level,
            event_count=event_count
        )

        if self.auto_execute_safe_actions:
            for action in suggested_actions:
                self.approval_manager.submit_action(action)

        self._output_alert(alert, output_format)

        return alert

    def _get_attacker_profile(self, attacker_ip: str) -> AttackerProfile:
        enrichment = get_attacker_enrichment(attacker_ip)

        if not enrichment or self.auto_enrich:
            enriched = enrich_and_update_attacker(
                attacker_ip,
                async_mode=not self.auto_enrich
            )
            if enriched:
                enrichment = {
                    "overall_score": enriched.overall_score,
                    "threat_level": enriched.threat_level.value,
                    "is_malicious": enriched.is_malicious,
                    "is_known_attacker": enriched.is_known_attacker,
                    "confidence": enriched.confidence,
                    "tags": enriched.aggregated_tags,
                    "sources": [s.source.value for s in enriched.sources]
                }

        activity = self._get_attacker_activity(attacker_ip)

        return AttackerProfile(
            ip=attacker_ip,
            threat_score=enrichment.get("overall_score", 0.0) if enrichment else 0.0,
            threat_level=enrichment.get("threat_level", "UNKNOWN") if enrichment else "UNKNOWN",
            is_known_malicious=enrichment.get("is_malicious", False) if enrichment else False,
            first_seen=activity.get("first_seen"),
            last_seen=activity.get("last_seen"),
            total_campaigns=activity.get("total_campaigns", 0),
            active_campaigns=activity.get("active_campaigns", 0),
            total_events=activity.get("total_events", 0),
            techniques_used=activity.get("techniques", []),
            threat_tags=enrichment.get("tags", []) if enrichment else [],
            enrichment_sources=enrichment.get("sources", []) if enrichment else [],
            confidence=enrichment.get("confidence", 0.0) if enrichment else 0.0
        )

    def _get_attacker_activity(self, attacker_ip: str) -> Dict[str, Any]:
        try:
            with driver.session() as session:
                query = """
                MATCH (a:Attacker {ip: $ip})
                OPTIONAL MATCH (a)-[:LAUNCHED]->(c:Campaign)
                OPTIONAL MATCH (c)-[:HAS_EVENT]->(e:AttackEvent)
                OPTIONAL MATCH (e)-[:MATCHES]->(t:Technique)

                RETURN
                    a.first_seen as first_seen,
                    a.last_seen as last_seen,
                    count(DISTINCT c) as total_campaigns,
                    count(DISTINCT CASE WHEN c.status = 'ACTIVE' THEN c END) as active_campaigns,
                    count(DISTINCT e) as total_events,
                    collect(DISTINCT t.attack_id) as techniques
        assessments = []

        if profile.is_known_malicious:
            assessments.append("⚠️ CONFIRMED MALICIOUS ACTOR")
        elif profile.threat_score >= 70:
            assessments.append("🔴 HIGH THREAT ACTOR")
        elif profile.threat_score >= 40:
            assessments.append("🟡 SUSPICIOUS ACTOR")
        else:
            assessments.append("⚪ UNKNOWN THREAT LEVEL")

        if profile.total_campaigns > 5:
            assessments.append(f"Persistent attacker ({profile.total_campaigns} campaigns)")
        elif profile.active_campaigns > 0:
            assessments.append(f"Active campaign in progress")

        if technique_id in ["T1110", "T1110.001", "T1110.002", "T1110.003"]:
            assessments.append("Brute force attack detected")
        elif technique_id in ["T1059", "T1059.001", "T1059.004"]:
            assessments.append("Command execution detected")
        elif technique_id in ["T1041", "T1048"]:
            assessments.append("⚠️ DATA EXFILTRATION ATTEMPT")

        if stage in ["Exfiltration", "Impact"]:
            assessments.append("⚠️ LATE-STAGE ATTACK")

        if rule_level >= 10:
            assessments.append("Critical alert triggered")

        return " | ".join(assessments) if assessments else "New threat detected"

    def _generate_suggestions(
        self,
        profile: AttackerProfile,
        technique_id: str,
        stage: str,
        campaign_id: str,
        attacker_ip: str,
        victim_ip: str
    ) -> List[SuggestedAction]:
        suggestions = []

        if profile.threat_score >= 70 or profile.is_known_malicious:
            suggestions.append(SuggestedAction(
                action_id=str(uuid.uuid4()),
                action_type="block_ip",
                description=f"Block malicious IP {attacker_ip} at firewall",
                priority=AlertSeverity.CRITICAL,
                auto_applicable=False,
                requires_approval=True,
                target=attacker_ip,
                command=f"iptables -A INPUT -s {attacker_ip} -j DROP",
                estimated_impact="High",
                reversible=True
            ))

            suggestions.append(SuggestedAction(
                action_id=str(uuid.uuid4()),
                action_type="isolate_host",
                description=f"Isolate compromised host {victim_ip}",
                priority=AlertSeverity.HIGH,
                auto_applicable=False,
                requires_approval=True,
                target=victim_ip,
                estimated_impact="High",
                reversible=True
            ))

            suggestions.append(SuggestedAction(
                action_id=str(uuid.uuid4()),
                action_type="collect_forensics",
                description="Collect forensic evidence from affected systems",
                priority=AlertSeverity.HIGH,
                auto_applicable=True,
                requires_approval=False,
                target=victim_ip,
                estimated_impact="Low",
                reversible=False
            ))

        if technique_id in ["T1110", "T1110.001", "T1110.002", "T1110.003"]:
            suggestions.append(SuggestedAction(
                action_id=str(uuid.uuid4()),
                action_type="block_ip",
                description=f"Block brute force source {attacker_ip}",
                priority=AlertSeverity.HIGH,
                auto_applicable=False,
                requires_approval=True,
                target=attacker_ip,
                estimated_impact="Medium",
                reversible=True
            ))

            suggestions.append(SuggestedAction(
                action_id=str(uuid.uuid4()),
                action_type="rate_limit",
                description="Enable rate limiting for authentication attempts",
                priority=AlertSeverity.MEDIUM,
                auto_applicable=True,
                requires_approval=False,
                target=attacker_ip,
                estimated_impact="Low",
                reversible=True
            ))

        elif technique_id in ["T1059", "T1059.001", "T1059.004"]:
            suggestions.append(SuggestedAction(
                action_id=str(uuid.uuid4()),
                action_type="isolate_host",
                description=f"Isolate host {victim_ip} running malicious commands",
                priority=AlertSeverity.HIGH,
                auto_applicable=False,
                requires_approval=True,
                target=victim_ip,
                estimated_impact="High",
                reversible=True
            ))

        elif technique_id in ["T1041", "T1048"]:
            suggestions.append(SuggestedAction(
                action_id=str(uuid.uuid4()),
                action_type="block_ip",
                description=f"⚠️ Block data exfiltration to {attacker_ip}",
                priority=AlertSeverity.CRITICAL,
                auto_applicable=False,
                requires_approval=True,
                target=attacker_ip,
                estimated_impact="High",
                reversible=True
            ))

            suggestions.append(SuggestedAction(
                action_id=str(uuid.uuid4()),
                action_type="collect_forensics",
                description="Collect evidence of data exfiltration",
                priority=AlertSeverity.CRITICAL,
                auto_applicable=True,
                requires_approval=False,
                target=victim_ip,
                estimated_impact="Low",
                reversible=False
            ))

        if 40 <= profile.threat_score < 70:
            suggestions.append(SuggestedAction(
                action_id=str(uuid.uuid4()),
                action_type="enable_monitoring",
                description=f"Enable enhanced monitoring for {attacker_ip}",
                priority=AlertSeverity.MEDIUM,
                auto_applicable=True,
                requires_approval=False,
                target=attacker_ip,
                estimated_impact="Low",
                reversible=True
            ))

        if profile.threat_score >= 70 or stage in ["Exfiltration", "Impact"]:
            suggestions.append(SuggestedAction(
                action_id=str(uuid.uuid4()),
                action_type="alert_analyst",
                description="Notify security analyst",
                priority=AlertSeverity.HIGH,
                auto_applicable=True,
                requires_approval=False,
                target=campaign_id,
                estimated_impact="None",
                reversible=False
            ))

        return suggestions

    def _output_alert(self, alert: DetectionAlert, format: str = "full"):
        if format == "full":
            self.formatter.print_detection_alert(alert, use_colors=True)
        elif format == "compact":
            self.formatter.print_compact_alert(alert, use_colors=True)
        elif format == "json":
            import json
            print(json.dumps(alert.to_dict(), indent=2, default=str))

    def approve_action(
        self,
        alert_id: str,
        action_id: str,
        approved_by: str = "analyst"
    ):
        execution = self.approval_manager.approve_action(
            action_id,
            approved_by=approved_by,
            execute_immediately=True
        )

        if execution:
            print(f"\n✅ Action approved and executed:")
            print(f"   Result: {execution.result.value}")
            print(f"   Output: {execution.output}")
            if execution.error:
                print(f"   Error: {execution.error}")

        return execution

    def reject_action(
        self,
        alert_id: str,
        action_id: str,
        rejected_by: str = "analyst",
        reason: str = ""
    ):
        success = self.approval_manager.reject_action(
            action_id,
            rejected_by=rejected_by,
            reason=reason
        )

        if success:
            print(f"\n❌ Action rejected: {reason}")

        return success

    def get_pending_actions(self) -> List[SuggestedAction]:
        return self.approval_manager.get_pending_actions()

    def get_execution_history(
        self,
        target: Optional[str] = None,
        limit: int = 100
    ):
        return self.executor.get_audit_trail(target=target, limit=limit)

    def generate_threat_report(self, attacker_ip: str) -> Dict[str, Any]:
        return generate_threat_report(attacker_ip)

    def health_check(self) -> Dict[str, Any]:
        return {
            "enrichment": self.enricher.health_check(),
            "pending_actions": len(self.approval_manager.get_pending_actions()),
            "execution_history": len(self.executor.audit_trail),
            "dry_run": self.dry_run,
            "auto_enrich": self.auto_enrich,
            "auto_execute": self.auto_execute_safe_actions
        }


_detection_system: Optional[IntelligentDetectionSystem] = None


def get_detection_system(
    auto_enrich: bool = True,
    auto_execute_safe_actions: bool = True,
    dry_run: bool = False
) -> IntelligentDetectionSystem:
    global _detection_system
    if _detection_system is None:
        _detection_system = IntelligentDetectionSystem(
            auto_enrich=auto_enrich,
            auto_execute_safe_actions=auto_execute_safe_actions,
            dry_run=dry_run
        )
    return _detection_system
