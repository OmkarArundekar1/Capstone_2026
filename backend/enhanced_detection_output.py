from __future__ import annotations
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime
from enum import Enum
import json
logger = logging.getLogger(__name__)

class AlertSeverity(str, Enum):
    CRITICAL = 'CRITICAL'
    HIGH = 'HIGH'
    MEDIUM = 'MEDIUM'
    LOW = 'LOW'
    INFO = 'INFO'

class ActionStatus(str, Enum):
    PENDING = 'PENDING'
    APPROVED = 'APPROVED'
    REJECTED = 'REJECTED'
    EXECUTING = 'EXECUTING'
    COMPLETED = 'COMPLETED'
    FAILED = 'FAILED'

@dataclass
class SuggestedAction:
    action_id: str
    action_type: str
    description: str
    priority: AlertSeverity
    auto_applicable: bool
    requires_approval: bool
    target: str
    command: Optional[str] = None
    estimated_impact: str = ''
    reversible: bool = True
    status: ActionStatus = ActionStatus.PENDING
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None
    executed_at: Optional[datetime] = None
    result: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {'action_id': self.action_id, 'action_type': self.action_type, 'description': self.description, 'priority': self.priority.value, 'auto_applicable': self.auto_applicable, 'requires_approval': self.requires_approval, 'target': self.target, 'command': self.command, 'estimated_impact': self.estimated_impact, 'reversible': self.reversible, 'status': self.status.value, 'approved_by': self.approved_by, 'approved_at': self.approved_at.isoformat() if self.approved_at else None, 'executed_at': self.executed_at.isoformat() if self.executed_at else None, 'result': self.result}

@dataclass
class AttackerProfile:
    ip: str
    threat_score: float
    threat_level: str
    is_known_malicious: bool
    first_seen: Optional[str]
    last_seen: Optional[str]
    total_campaigns: int
    active_campaigns: int
    total_events: int
    techniques_used: List[str]
    threat_tags: List[str]
    enrichment_sources: List[str]
    confidence: float

    def get_severity(self) -> AlertSeverity:
        if self.threat_score >= 90:
            return AlertSeverity.CRITICAL
        elif self.threat_score >= 70:
            return AlertSeverity.HIGH
        elif self.threat_score >= 40:
            return AlertSeverity.MEDIUM
        elif self.threat_score >= 10:
            return AlertSeverity.LOW
        else:
            return AlertSeverity.INFO

@dataclass
class DetectionAlert:
    alert_id: str
    timestamp: datetime
    severity: AlertSeverity
    campaign_id: str
    attacker: AttackerProfile
    victim_ip: str
    technique_id: str
    technique_name: str
    stage: str
    is_new_attacker: bool
    is_known_malicious: bool
    threat_assessment: str
    suggested_actions: List[SuggestedAction]
    rule_id: str
    rule_description: str
    rule_level: int
    event_count: int

    def to_dict(self) -> Dict[str, Any]:
        return {'alert_id': self.alert_id, 'timestamp': self.timestamp.isoformat(), 'severity': self.severity.value, 'campaign_id': self.campaign_id, 'attacker': {'ip': self.attacker.ip, 'threat_score': self.attacker.threat_score, 'threat_level': self.attacker.threat_level, 'is_known_malicious': self.attacker.is_known_malicious, 'confidence': self.attacker.confidence, 'tags': self.attacker.threat_tags}, 'victim_ip': self.victim_ip, 'technique': {'id': self.technique_id, 'name': self.technique_name, 'stage': self.stage}, 'threat_assessment': self.threat_assessment, 'suggested_actions': [a.to_dict() for a in self.suggested_actions], 'rule': {'id': self.rule_id, 'description': self.rule_description, 'level': self.rule_level}, 'event_count': self.event_count}

class EnhancedOutputFormatter:
    COLORS = {'CRITICAL': '\x1b[91m', 'HIGH': '\x1b[31m', 'MEDIUM': '\x1b[33m', 'LOW': '\x1b[36m', 'INFO': '\x1b[37m', 'SUCCESS': '\x1b[92m', 'RESET': '\x1b[0m', 'BOLD': '\x1b[1m', 'DIM': '\x1b[2m'}

    @classmethod
    def print_detection_alert(cls, alert: DetectionAlert, use_colors: bool=True):
        cls._print_header(alert, use_colors)
        cls._print_threat_summary(alert, use_colors)
        cls._print_attack_details(alert, use_colors)
        if alert.suggested_actions:
            cls._print_suggested_actions(alert, use_colors)
        cls._print_footer(use_colors)

    @classmethod
    def _print_header(cls, alert: DetectionAlert, use_colors: bool):
        color = cls.COLORS.get(alert.severity.value, '') if use_colors else ''
        reset = cls.COLORS['RESET'] if use_colors else ''
        bold = cls.COLORS['BOLD'] if use_colors else ''
        print(f"\n{'=' * 80}")
        print(f'{bold}{color}🚨 SECURITY ALERT - {alert.severity.value}{reset}')
        print(f"{'=' * 80}")
        print(f'{bold}Alert ID:{reset} {alert.alert_id}')
        print(f"{bold}Timestamp:{reset} {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        print(f'{bold}Campaign:{reset} {alert.campaign_id}')
        print()

    @classmethod
    def _print_threat_summary(cls, alert: DetectionAlert, use_colors: bool):
        bold = cls.COLORS['BOLD'] if use_colors else ''
        reset = cls.COLORS['RESET'] if use_colors else ''
        attacker = alert.attacker
        threat_color = cls.COLORS.get(attacker.get_severity().value, '') if use_colors else ''
        print(f'{bold}📊 THREAT SUMMARY{reset}')
        print(f"{'─' * 80}")
        print(f'  {bold}Threat Level:{reset} {threat_color}{attacker.threat_level}{reset}')
        print(f'  {bold}Threat Score:{reset} {threat_color}{attacker.threat_score:.1f}/100{reset}')
        print(f'  {bold}Confidence:{reset} {attacker.confidence:.1f}%')
        print(f"  {bold}Known Malicious:{reset} {('🔴 YES' if attacker.is_known_malicious else '🟡 NO')}")
        print(f'  {bold}Assessment:{reset} {alert.threat_assessment}')
        if attacker.threat_tags:
            tags_str = ', '.join(attacker.threat_tags[:5])
            if len(attacker.threat_tags) > 5:
                tags_str += f' (+{len(attacker.threat_tags) - 5} more)'
            print(f'  {bold}Threat Tags:{reset} {tags_str}')
        print()

    @classmethod
    def _print_attack_details(cls, alert: DetectionAlert, use_colors: bool):
        bold = cls.COLORS['BOLD'] if use_colors else ''
        reset = cls.COLORS['RESET'] if use_colors else ''
        attacker = alert.attacker
        print(f'{bold}🎯 ATTACK DETAILS{reset}')
        print(f"{'─' * 80}")
        print(f'  {bold}Attacker IP:{reset} {attacker.ip}')
        print(f'  {bold}Victim IP:{reset} {alert.victim_ip}')
        print(f'  {bold}Technique:{reset} {alert.technique_id} - {alert.technique_name}')
        print(f'  {bold}Stage:{reset} {alert.stage}')
        print(f'  {bold}Rule:{reset} {alert.rule_id} - {alert.rule_description} (Level {alert.rule_level})')
        print()
        print(f'{bold}📈 ACTIVITY HISTORY{reset}')
        print(f"{'─' * 80}")
        print(f"  {bold}First Seen:{reset} {attacker.first_seen or 'Just now'}")
        print(f"  {bold}Last Seen:{reset} {attacker.last_seen or 'Just now'}")
        print(f'  {bold}Total Campaigns:{reset} {attacker.total_campaigns}')
        print(f'  {bold}Active Campaigns:{reset} {attacker.active_campaigns}')
        print(f'  {bold}Total Events:{reset} {attacker.total_events}')
        if attacker.techniques_used:
            techniques_str = ', '.join(attacker.techniques_used[:5])
            if len(attacker.techniques_used) > 5:
                techniques_str += f' (+{len(attacker.techniques_used) - 5} more)'
            print(f'  {bold}Techniques Used:{reset} {techniques_str}')
        print()

    @classmethod
    def _print_suggested_actions(cls, alert: DetectionAlert, use_colors: bool):
        bold = cls.COLORS['BOLD'] if use_colors else ''
        reset = cls.COLORS['RESET'] if use_colors else ''
        success_color = cls.COLORS['SUCCESS'] if use_colors else ''
        print(f'{bold}💡 SUGGESTED ACTIONS{reset}')
        print(f"{'─' * 80}")
        critical_actions = [a for a in alert.suggested_actions if a.priority == AlertSeverity.CRITICAL]
        high_actions = [a for a in alert.suggested_actions if a.priority == AlertSeverity.HIGH]
        medium_actions = [a for a in alert.suggested_actions if a.priority == AlertSeverity.MEDIUM]
        low_actions = [a for a in alert.suggested_actions if a.priority == AlertSeverity.LOW]
        for priority, actions in [('CRITICAL', critical_actions), ('HIGH', high_actions), ('MEDIUM', medium_actions), ('LOW', low_actions)]:
            if not actions:
                continue
            priority_color = cls.COLORS.get(priority, '') if use_colors else ''
            print(f'  {priority_color}{bold}[{priority}]{reset}')
            for action in actions:
                auto_icon = '🤖' if action.auto_applicable else '👤'
                approval_icon = '⚠️' if action.requires_approval else '✅'
                print(f'    {auto_icon} {approval_icon} {action.description}')
                print(f'       {bold}Action:{reset} {action.action_type}')
                print(f'       {bold}Target:{reset} {action.target}')
                print(f"       {bold}Impact:{reset} {action.estimated_impact} | {bold}Reversible:{reset} {('Yes' if action.reversible else 'No')}")
                if action.command:
                    print(f"       {bold}Command:{reset} {(cls.COLORS['DIM'] if use_colors else '')}{action.command}{reset}")
                if action.status == ActionStatus.APPROVED:
                    print(f'       {success_color}✓ APPROVED{reset} by {action.approved_by}')
                elif action.status == ActionStatus.PENDING and action.requires_approval:
                    print(f'       ⏳ PENDING APPROVAL')
                print()
        pending_approval = [a for a in alert.suggested_actions if a.requires_approval and a.status == ActionStatus.PENDING]
        if pending_approval:
            print(f'  {bold}To approve actions:{reset}')
            print(f"    approve_action(alert_id='{alert.alert_id}', action_id='<action_id>')")
            print()

    @classmethod
    def _print_footer(cls, use_colors: bool):
        print(f"{'=' * 80}\n")

    @classmethod
    def print_compact_alert(cls, alert: DetectionAlert, use_colors: bool=True):
        color = cls.COLORS.get(alert.severity.value, '') if use_colors else ''
        reset = cls.COLORS['RESET'] if use_colors else ''
        bold = cls.COLORS['BOLD'] if use_colors else ''
        time_str = alert.timestamp.strftime('%H:%M:%S')
        threat_indicator = '🔴' if alert.attacker.is_known_malicious else '🟡'
        print(f'{bold}{color}[{alert.severity.value:8}]{reset} {time_str} | {threat_indicator} {alert.attacker.ip:15} → {alert.victim_ip:15} | {alert.technique_id:10} | Score: {alert.attacker.threat_score:5.1f}/100 | {len(alert.suggested_actions)} actions')

    @classmethod
    def print_summary_report(cls, alerts: List[DetectionAlert], use_colors: bool=True):
        bold = cls.COLORS['BOLD'] if use_colors else ''
        reset = cls.COLORS['RESET'] if use_colors else ''
        print(f"\n{'=' * 80}")
        print(f'{bold}📋 DETECTION SUMMARY REPORT{reset}')
        print(f"{'=' * 80}\n")
        total = len(alerts)
        by_severity = {}
        for alert in alerts:
            by_severity[alert.severity] = by_severity.get(alert.severity, 0) + 1
        unique_attackers = len(set((a.attacker.ip for a in alerts)))
        known_malicious = sum((1 for a in alerts if a.attacker.is_known_malicious))
        print(f'{bold}Statistics:{reset}')
        print(f'  Total Alerts: {total}')
        print(f'  Unique Attackers: {unique_attackers}')
        print(f'  Known Malicious: {known_malicious}')
        print()
        print(f'{bold}By Severity:{reset}')
        for severity in [AlertSeverity.CRITICAL, AlertSeverity.HIGH, AlertSeverity.MEDIUM, AlertSeverity.LOW]:
            count = by_severity.get(severity, 0)
            if count > 0:
                color = cls.COLORS.get(severity.value, '') if use_colors else ''
                print(f'  {color}{severity.value:8}{reset}: {count}')
        print(f"\n{'=' * 80}\n")

def format_json_output(alert: DetectionAlert) -> str:
    return json.dumps(alert.to_dict(), indent=2, default=str)

def format_syslog_output(alert: DetectionAlert) -> str:
    return f'CYUKTI_ALERT severity={alert.severity.value} campaign={alert.campaign_id} attacker={alert.attacker.ip} victim={alert.victim_ip} technique={alert.technique_id} threat_score={alert.attacker.threat_score:.1f} actions={len(alert.suggested_actions)}'