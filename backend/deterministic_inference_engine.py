from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Set
from collections import defaultdict
import re

@dataclass
class InferenceRule:
    name: str
    technique_id: str
    conditions: Dict
    confidence: float
    rationale: str

@dataclass
class InferenceResult:
    technique_id: str
    confidence: float
    rule_name: str
    matched_conditions: Dict
    rationale: str

class DeterministicInferenceEngine:

    def __init__(self):
        self.rules = self._load_rules()
        self.event_cache: Dict[str, List[Dict]] = defaultdict(list)
        self.cache_ttl = 600

    def _load_rules(self) -> List[InferenceRule]:
        return [InferenceRule(name='ssh_brute_force', technique_id='T1110.001', conditions={'rule_ids': ['5710', '5712', '5720'], 'min_frequency': 10, 'time_window_seconds': 300, 'source_ip_required': True}, confidence=0.95, rationale='10+ SSH auth failures from same IP in 5min = brute force attempt'), InferenceRule(name='ftp_brute_force', technique_id='T1110.001', conditions={'rule_ids': ['11151', '11154'], 'min_frequency': 8, 'time_window_seconds': 300, 'source_ip_required': True}, confidence=0.9, rationale='8+ FTP auth failures from same IP in 5min = brute force'), InferenceRule(name='sudo_password_guessing', technique_id='T1110.001', conditions={'rule_ids': ['5401'], 'min_frequency': 5, 'time_window_seconds': 180}, confidence=0.85, rationale='5+ sudo failures in 3min suggests password guessing'), InferenceRule(name='sudo_abuse', technique_id='T1548.003', conditions={'rule_ids': ['5402', '5403'], 'process_patterns': ['sudo', '/usr/bin/sudo']}, confidence=0.9, rationale='Successful sudo elevation detected'), InferenceRule(name='setuid_execution', technique_id='T1548.001', conditions={'rule_ids': ['2830'], 'process_patterns': ['setuid', 'setgid']}, confidence=0.85, rationale='Setuid/setgid binary execution'), InferenceRule(name='ssh_key_persistence', technique_id='T1098.004', conditions={'rule_ids': ['550', '554'], 'file_patterns': ['\\.ssh/authorized_keys', '/root/\\.ssh/authorized_keys']}, confidence=0.9, rationale='Modification to SSH authorized_keys = persistence mechanism'), InferenceRule(name='cron_persistence', technique_id='T1053.003', conditions={'rule_ids': ['2932', '533'], 'file_patterns': ['/etc/crontab', '/var/spool/cron', 'crontab']}, confidence=0.85, rationale='Cron configuration change = scheduled task persistence'), InferenceRule(name='systemd_service_persistence', technique_id='T1543.002', conditions={'rule_ids': ['550', '554'], 'file_patterns': ['/etc/systemd/system/.*\\.service', '/lib/systemd/system/.*\\.service']}, confidence=0.85, rationale='Systemd service file creation/modification'), InferenceRule(name='log_file_deletion', technique_id='T1070.002', conditions={'rule_ids': ['591', '592', '593'], 'file_patterns': ['/var/log/.*', '\\.log$']}, confidence=0.9, rationale='Log file deletion = anti-forensics'), InferenceRule(name='auditd_disabled', technique_id='T1562.001', conditions={'rule_ids': ['2905', '2906'], 'process_patterns': ['auditd', 'systemctl.*stop.*auditd']}, confidence=0.95, rationale='Auditd service stopped = defense evasion'), InferenceRule(name='firewall_rule_modification', technique_id='T1562.004', conditions={'rule_ids': ['534', '535'], 'process_patterns': ['iptables', 'ufw', 'firewall-cmd']}, confidence=0.85, rationale='Firewall rule modification detected'), InferenceRule(name='ssh_lateral_movement', technique_id='T1021.004', conditions={'rule_ids': ['5715', '5716'], 'internal_to_internal': True}, confidence=0.8, rationale='SSH login between internal hosts suggests lateral movement'), InferenceRule(name='reverse_shell_indicators', technique_id='T1059.004', conditions={'rule_ids': ['2901', '2902'], 'process_patterns': ['nc.*-e', 'bash.*-i', '/dev/tcp/', 'python.*socket', 'perl.*socket']}, confidence=0.9, rationale='Reverse shell command patterns detected'), InferenceRule(name='network_scanning', technique_id='T1046', conditions={'rule_ids': ['40704'], 'min_frequency': 20, 'time_window_seconds': 60, 'unique_ports_required': 5}, confidence=0.85, rationale='High frequency port scanning detected'), InferenceRule(name='system_enumeration', technique_id='T1082', conditions={'rule_ids': ['2902'], 'process_patterns': ['uname', 'hostname', 'cat /etc/.*-release', 'lsb_release']}, confidence=0.75, rationale='System enumeration commands executed'), InferenceRule(name='data_staging', technique_id='T1074.001', conditions={'rule_ids': ['550', '554'], 'file_patterns': ['/tmp/.*\\.tar', '/tmp/.*\\.zip', '/tmp/.*\\.gz']}, confidence=0.7, rationale='Archive creation in /tmp suggests data staging'), InferenceRule(name='curl_wget_exfiltration', technique_id='T1048.003', conditions={'rule_ids': ['2902'], 'process_patterns': ['curl.*--data', 'wget.*--post-data', 'curl.*-X POST', 'wget.*-O.*http']}, confidence=0.8, rationale='Curl/wget with POST/data upload = exfiltration indicator')]

    def infer_technique(self, alert: Dict, attacker_ip: Optional[str]=None, timestamp: Optional[datetime]=None) -> Optional[InferenceResult]:
        rule_id = str(alert.get('rule', {}).get('id', ''))
        full_log = alert.get('full_log', '')
        file_path = alert.get('syscheck', {}).get('path', '')
        if attacker_ip and timestamp:
            cache_key = f'{attacker_ip}:{rule_id}'
            self.event_cache[cache_key].append({'timestamp': timestamp, 'alert': alert})
            self._cleanup_cache(cache_key, timestamp)
        for rule in self.rules:
            if self._rule_matches(rule, alert, rule_id, full_log, file_path, attacker_ip, timestamp):
                matched_conditions = self._get_matched_conditions(rule, alert, rule_id, full_log, file_path, attacker_ip, timestamp)
                return InferenceResult(technique_id=rule.technique_id, confidence=rule.confidence, rule_name=rule.name, matched_conditions=matched_conditions, rationale=rule.rationale)
        return None

    def _rule_matches(self, rule: InferenceRule, alert: Dict, rule_id: str, full_log: str, file_path: str, attacker_ip: Optional[str], timestamp: Optional[datetime]) -> bool:
        conditions = rule.conditions
        if 'rule_ids' in conditions:
            if rule_id not in conditions['rule_ids']:
                return False
        if 'process_patterns' in conditions:
            if not any((re.search(pattern, full_log, re.IGNORECASE) for pattern in conditions['process_patterns'])):
                return False
        if 'file_patterns' in conditions:
            combined_paths = f'{file_path} {full_log}'
            if not any((re.search(pattern, combined_paths, re.IGNORECASE) for pattern in conditions['file_patterns'])):
                return False
        if 'min_frequency' in conditions:
            if not attacker_ip or not timestamp:
                return False
            cache_key = f'{attacker_ip}:{rule_id}'
            time_window = conditions.get('time_window_seconds', 300)
            recent_events = [e for e in self.event_cache[cache_key] if (timestamp - e['timestamp']).total_seconds() <= time_window]
            if len(recent_events) < conditions['min_frequency']:
                return False
            if 'unique_ports_required' in conditions:
                unique_ports = set()
                for event in recent_events:
                    port_match = re.search('port[:\\s]+(\\d+)', event['alert'].get('full_log', ''))
                    if port_match:
                        unique_ports.add(port_match.group(1))
                if len(unique_ports) < conditions['unique_ports_required']:
                    return False
        if conditions.get('source_ip_required', False):
            if not attacker_ip:
                return False
        if conditions.get('internal_to_internal', False):
            src_ip = alert.get('data', {}).get('srcip', '')
            dst_ip = alert.get('data', {}).get('dstip', '')
            if not (self._is_internal_ip(src_ip) and self._is_internal_ip(dst_ip)):
                return False
        return True

    def _get_matched_conditions(self, rule: InferenceRule, alert: Dict, rule_id: str, full_log: str, file_path: str, attacker_ip: Optional[str], timestamp: Optional[datetime]) -> Dict:
        matched = {'rule_id': rule_id}
        conditions = rule.conditions
        if 'process_patterns' in conditions:
            matched_patterns = [pattern for pattern in conditions['process_patterns'] if re.search(pattern, full_log, re.IGNORECASE)]
            if matched_patterns:
                matched['process_patterns'] = matched_patterns
        if 'file_patterns' in conditions:
            combined_paths = f'{file_path} {full_log}'
            matched_patterns = [pattern for pattern in conditions['file_patterns'] if re.search(pattern, combined_paths, re.IGNORECASE)]
            if matched_patterns:
                matched['file_patterns'] = matched_patterns
        if 'min_frequency' in conditions and attacker_ip and timestamp:
            cache_key = f'{attacker_ip}:{rule_id}'
            time_window = conditions.get('time_window_seconds', 300)
            recent_events = [e for e in self.event_cache[cache_key] if (timestamp - e['timestamp']).total_seconds() <= time_window]
            matched['frequency'] = len(recent_events)
            matched['time_window'] = time_window
        return matched

    def _cleanup_cache(self, cache_key: str, current_time: datetime):
        cutoff = current_time - timedelta(seconds=self.cache_ttl)
        self.event_cache[cache_key] = [e for e in self.event_cache[cache_key] if e['timestamp'] >= cutoff]

    def _is_internal_ip(self, ip: str) -> bool:
        if not ip:
            return False
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        try:
            first = int(parts[0])
            second = int(parts[1])
            if first == 10:
                return True
            if first == 172 and 16 <= second <= 31:
                return True
            if first == 192 and second == 168:
                return True
        except ValueError:
            return False
        return False

    def get_rule_summary(self) -> List[Dict]:
        return [{'name': rule.name, 'technique_id': rule.technique_id, 'confidence': rule.confidence, 'rationale': rule.rationale, 'conditions': rule.conditions} for rule in self.rules]
engine = DeterministicInferenceEngine()
if __name__ == '__main__':
    print('Deterministic Inference Engine - Loaded Rules\n')
    print(f'Total rules: {len(engine.rules)}\n')
    for i, rule in enumerate(engine.rules, 1):
        print(f'{i}. {rule.name}')
        print(f'   Technique: {rule.technique_id}')
        print(f'   Confidence: {rule.confidence}')
        print(f'   Rationale: {rule.rationale}')
        print(f'   Conditions: {rule.conditions}')
        print()