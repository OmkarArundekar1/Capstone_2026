from __future__ import annotations
from typing import Any

class PlaybookGenerator:

    def generate(self, threat_report: dict[str, Any]) -> dict[str, Any]:
        severity = threat_report.get('severity_label', 'NORMAL')
        attack = threat_report.get('attack_label', 'BENIGN')
        phase = threat_report.get('kill_chain_phase', 'None')
        priority = threat_report.get('recommended_priority', 'P4_LOW')
        attacker_ip = threat_report.get('attacker_ip', 'unknown')
        actions = []
        actions.append({'action_id': 'LOG_EVENT', 'description': 'Log threat event to SIEM / Elasticsearch', 'priority': 1, 'target': 'siem', 'auto_execute': True})
        if severity in ('LOW', 'MEDIUM', 'HIGH'):
            actions.append({'action_id': 'ALERT_SOC', 'description': 'Send alert to SOC dashboard', 'priority': 2, 'target': 'soc_dashboard', 'auto_execute': True})
        if phase == 'Reconnaissance' or attack == 'PortScan':
            actions.append({'action_id': 'RATE_LIMIT_IP', 'description': 'Apply rate limiting to scanning source', 'priority': 3, 'target': 'firewall', 'command': f'iptables -A INPUT -s {attacker_ip} -m limit --limit 10/min -j ACCEPT', 'auto_execute': False})
        if attack == 'BruteForce':
            actions += [{'action_id': 'BLOCK_IP_TEMP', 'description': 'Temporarily block brute-force source IP (10 min)', 'priority': 2, 'target': 'firewall', 'command': f'iptables -A INPUT -s {attacker_ip} -j DROP', 'auto_execute': False}, {'action_id': 'FORCE_MFA', 'description': 'Force MFA re-auth for affected accounts', 'priority': 3, 'target': 'identity_provider', 'auto_execute': False}]
        if attack in ('DDoS', 'DoS'):
            actions += [{'action_id': 'ENABLE_RATE_LIMITING', 'description': 'Enable DDoS rate limiting on ingress', 'priority': 1, 'target': 'load_balancer', 'auto_execute': False}, {'action_id': 'BLOCK_IP_PERM', 'description': 'Permanently block DDoS source IP', 'priority': 2, 'target': 'firewall', 'command': f'iptables -I INPUT -s {attacker_ip} -j DROP', 'auto_execute': False}]
        if severity == 'HIGH' or priority in ('P1_CRITICAL', 'P2_HIGH'):
            actions.append({'action_id': 'ISOLATE_HOST', 'description': 'Isolate affected host from network', 'priority': 1, 'target': 'network_switch', 'command': 'iptables -P INPUT DROP && iptables -P OUTPUT DROP', 'auto_execute': False})
            actions.append({'action_id': 'NOTIFY_IR_TEAM', 'description': 'Page incident response team (PagerDuty / Slack)', 'priority': 1, 'target': 'notification_system', 'auto_execute': True})
        actions.sort(key=lambda a: a['priority'])
        return {'playbook_id': f'PB-{attack}-{severity}', 'severity_label': severity, 'attack_label': attack, 'kill_chain_phase': phase, 'recommended_priority': priority, 'total_actions': len(actions), 'actions': actions}