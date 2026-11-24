from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Set, Optional, Tuple
from collections import defaultdict
import re


@dataclass
class LateralMovementHop:
    timestamp: datetime
    source_ip: str
    target_ip: str
    technique_id: Optional[str]
    rule_id: str
    alert_id: str
    hop_number: int
    is_internal_to_internal: bool


@dataclass
class LateralMovementChain:
    chain_id: str
    campaign_id: str
    initial_attacker: str
    initial_victim: str
    hops: List[LateralMovementHop] = field(default_factory=list)
    compromised_hosts: Set[str] = field(default_factory=set)
    max_depth: int = 0
    last_updated: Optional[datetime] = None


@dataclass
class LateralMovementIndicators:
    has_lateral_movement: bool
    hop_count: int
    compromised_host_count: int
    max_propagation_depth: int
    chains: List[LateralMovementChain]
    lateral_techniques: Set[str]


class LateralMovementTracker:
    LATERAL_MOVEMENT_TECHNIQUES = {
        "T1021.001",
        "T1021.002",
        "T1021.004",
        "T1021.006",
        "T1080",
        "T1534",
        "T1563.002",
        "T1570",
    }

    def __init__(self):
        self.chains: Dict[str, List[LateralMovementChain]] = defaultdict(list)

        self.compromised_hosts: Dict[str, Set[str]] = defaultdict(set)

        self.initial_attackers: Dict[str, str] = {}

    def process_alert(
        self,
        campaign_id: str,
        alert: Dict,
        attacker_ip: str,
        technique_id: Optional[str] = None,
        timestamp: Optional[datetime] = None
    ) -> Optional[LateralMovementHop]:
        if not timestamp:
            timestamp = datetime.now()

        target_ip = self._extract_target_ip(alert)
        if not target_ip:
            return None

        rule_id = str(alert.get("rule", {}).get("id", ""))
        alert_id = alert.get("id", "")

        is_external_source = not self._is_internal_ip(attacker_ip)
        is_internal_target = self._is_internal_ip(target_ip)
        is_internal_to_internal = self._is_internal_ip(attacker_ip) and is_internal_target

        if is_external_source and is_internal_target:
            if campaign_id not in self.initial_attackers:
                self.initial_attackers[campaign_id] = attacker_ip

            self.compromised_hosts[campaign_id].add(target_ip)

            hop = LateralMovementHop(
                timestamp=timestamp,
                source_ip=attacker_ip,
                target_ip=target_ip,
                technique_id=technique_id,
                rule_id=rule_id,
                alert_id=alert_id,
                hop_number=0,
                is_internal_to_internal=False
            )

            self._add_to_chain(campaign_id, hop)
            return hop

        if is_internal_to_internal:
            if attacker_ip in self.compromised_hosts[campaign_id]:
                self.compromised_hosts[campaign_id].add(target_ip)

                hop_number = self._calculate_hop_number(campaign_id, attacker_ip, target_ip)

                hop = LateralMovementHop(
                    timestamp=timestamp,
                    source_ip=attacker_ip,
                    target_ip=target_ip,
                    technique_id=technique_id,
                    rule_id=rule_id,
                    alert_id=alert_id,
                    hop_number=hop_number,
                    is_internal_to_internal=True
                )

                self._add_to_chain(campaign_id, hop)
                return hop

        return None

    def get_campaign_indicators(self, campaign_id: str) -> LateralMovementIndicators:
        chains = self.chains.get(campaign_id, [])
        compromised = self.compromised_hosts.get(campaign_id, set())

        if not chains:
            return LateralMovementIndicators(
                has_lateral_movement=False,
                hop_count=0,
                compromised_host_count=0,
                max_propagation_depth=0,
                chains=[],
                lateral_techniques=set()
            )

        total_hops = sum(len(chain.hops) for chain in chains)
        max_depth = max((chain.max_depth for chain in chains), default=0)

        lateral_techniques = set()
        for chain in chains:
            for hop in chain.hops:
                if hop.technique_id and hop.technique_id in self.LATERAL_MOVEMENT_TECHNIQUES:
                    lateral_techniques.add(hop.technique_id)

        return LateralMovementIndicators(
            has_lateral_movement=True,
            hop_count=total_hops,
            compromised_host_count=len(compromised),
            max_propagation_depth=max_depth,
            chains=chains,
            lateral_techniques=lateral_techniques
        )

    def is_likely_same_campaign(
        self,
        campaign_id: str,
        new_attacker_ip: str,
        new_target_ip: Optional[str] = None
    ) -> Tuple[bool, float, str]:
        if campaign_id not in self.compromised_hosts:
            return (False, 0.0, "No lateral movement context")

        if new_attacker_ip in self.compromised_hosts[campaign_id]:
            if new_target_ip and self._is_internal_ip(new_target_ip):
                return (
                    True,
                    0.95,
                    f"Source {new_attacker_ip} is compromised host from campaign, "
                    f"targeting internal {new_target_ip} = lateral movement continuation"
                )
            else:
                return (
                    True,
                    0.85,
                    f"Source {new_attacker_ip} is compromised host from campaign"
                )

        if campaign_id in self.initial_attackers:
            if new_attacker_ip == self.initial_attackers[campaign_id]:
                return (
                    True,
                    0.90,
                    f"Same external attacker {new_attacker_ip} continuing campaign"
                )

        return (False, 0.0, "No lateral movement link detected")

    def _add_to_chain(self, campaign_id: str, hop: LateralMovementHop):
        chains = self.chains[campaign_id]

        for chain in chains:
            if self._hop_continues_chain(chain, hop):
                chain.hops.append(hop)
                chain.compromised_hosts.add(hop.target_ip)
                chain.max_depth = max(chain.max_depth, hop.hop_number)
                chain.last_updated = hop.timestamp
                return

        initial_attacker = self.initial_attackers.get(campaign_id, hop.source_ip)
        new_chain = LateralMovementChain(
            chain_id=f"{campaign_id}_chain_{len(chains)}",
            campaign_id=campaign_id,
            initial_attacker=initial_attacker,
            initial_victim=hop.target_ip if hop.hop_number == 0 else hop.source_ip,
            hops=[hop],
            compromised_hosts={hop.target_ip},
            max_depth=hop.hop_number,
            last_updated=hop.timestamp
        )
        chains.append(new_chain)

    def _hop_continues_chain(self, chain: LateralMovementChain, hop: LateralMovementHop) -> bool:
        if not chain.hops:
            return False

        if hop.source_ip in chain.compromised_hosts:
            return True

        if hop.hop_number == 0 and hop.source_ip == chain.initial_attacker:
            return True

        return False

    def _calculate_hop_number(
        self,
        campaign_id: str,
        source_ip: str,
        target_ip: str
    ) -> int:
        chains = self.chains.get(campaign_id, [])

        for chain in chains:
            for i, hop in enumerate(chain.hops):
                if hop.target_ip == source_ip:
                    return hop.hop_number + 1

        return 1

    def _extract_target_ip(self, alert: Dict) -> Optional[str]:
        data = alert.get("data", {})

        target = (
            data.get("dstip") or
            data.get("dest_ip") or
            data.get("destination_ip") or
            data.get("target_ip")
        )

        if target and self._is_valid_ip(target):
            return target

        full_log = alert.get("full_log", "")

        patterns = [
            r"dst[:\s]+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
            r"destination[:\s]+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
            r"to[:\s]+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
            r"->.*?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
        ]

        for pattern in patterns:
            match = re.search(pattern, full_log, re.IGNORECASE)
            if match:
                ip = match.group(1)
                if self._is_valid_ip(ip):
                    return ip

        return None

    def _is_internal_ip(self, ip: str) -> bool:
        if not ip:
            return False

        parts = ip.split(".")
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

    def _is_valid_ip(self, ip: str) -> bool:
        parts = ip.split(".")
        if len(parts) != 4:
            return False

        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except ValueError:
            return False

    def clear_campaign(self, campaign_id: str):
        self.chains.pop(campaign_id, None)
        self.compromised_hosts.pop(campaign_id, None)
        self.initial_attackers.pop(campaign_id, None)

    def get_statistics(self) -> Dict:
        total_chains = sum(len(chains) for chains in self.chains.values())
        total_hops = sum(
            len(hop.hops)
            for chains in self.chains.values()
            for hop in chains
        )
        campaigns_with_lateral = len([
            cid for cid in self.chains
            if any(hop.hop_number > 0 for chain in self.chains[cid] for hop in chain.hops)
        ])

        max_depth = max(
            (chain.max_depth
             for chains in self.chains.values()
             for chain in chains),
            default=0
        )

        return {
            "total_campaigns_tracked": len(self.chains),
            "campaigns_with_lateral_movement": campaigns_with_lateral,
            "total_chains": total_chains,
            "total_hops": total_hops,
            "max_propagation_depth": max_depth,
            "total_compromised_hosts": sum(
                len(hosts) for hosts in self.compromised_hosts.values()
            )
        }


tracker = LateralMovementTracker()


if __name__ == "__main__":
    from datetime import datetime, timedelta

    print("Lateral Movement Tracker - Test Scenario\n")

    campaign_id = "CAMP_TEST_001"
    base_time = datetime.now()

    alert1 = {
        "id": "alert_001",
        "rule": {"id": "5715"},
        "data": {"dstip": "192.168.1.100"},
        "full_log": "SSH login from external IP"
    }

    hop1 = tracker.process_alert(
        campaign_id,
        alert1,
        attacker_ip="203.0.113.50",
        technique_id="T1021.004",
        timestamp=base_time
    )

    print(f"Hop 1: {hop1.source_ip} -> {hop1.target_ip} (Hop 1)")
    print(f"  Initial Compromise: External attacker compromises web server\n")

    alert2 = {
        "id": "alert_002",
        "rule": {"id": "5715"},
        "data": {"dstip": "192.168.1.200"},
        "full_log": "SSH connection to database server"
    }

    hop2 = tracker.process_alert(
        campaign_id,
        alert2,
        attacker_ip="192.168.1.100",
        technique_id="T1021.004",
        timestamp=base_time + timedelta(minutes=5)
    )

    if hop2:
        print(f"Hop 2: {hop2.source_ip} -> {hop2.target_ip} (Hop")
        print(f"  Lateral Movement: Compromised web server pivots to database\n")

    indicators = tracker.get_campaign_indicators(campaign_id)
    print("Campaign Lateral Movement Summary:")
    print(f"  Has Lateral Movement: {indicators.has_lateral_movement}")
    print(f"  Total Hops: {indicators.hop_count}")
    print(f"  Compromised Hosts: {indicators.compromised_host_count}")
    print(f"  Max Depth: {indicators.max_propagation_depth}")
    print(f"  Lateral Techniques: {indicators.lateral_techniques}")

    print("\n--- Campaign Continuity Check ---")
    is_same, confidence, reason = tracker.is_likely_same_campaign(
        campaign_id,
        new_attacker_ip="192.168.1.100",
        new_target_ip="192.168.1.201"
    )
    print(f"Is same campaign: {is_same} (confidence: {confidence:.2f})")
    print(f"Reason: {reason}")
