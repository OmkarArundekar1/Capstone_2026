from __future__ import annotations

import logging
from typing import Dict, Any, Optional
from datetime import datetime

from hybrid_threat_enrichment import (
    get_enricher,
    EnrichedIOC,
    ThreatLevel,
    EnrichmentSource
)
from neo4j_client import driver

logger = logging.getLogger(__name__)


def update_attacker_threat_intel(attacker_ip: str, enriched: EnrichedIOC) -> bool:
    try:
        with driver.session() as session:
            query = """
            MERGE (a:Attacker {ip: $ip})
            SET
                a.vt_reputation = $vt_reputation,
                a.threat_actor_reputation = $threat_actor_reputation,
                a.malware_confidence = $malware_confidence,
                a.tool_confidence = $tool_confidence,
                a.misp_confidence = $misp_confidence,
                a.ioc_confidence = $ioc_confidence,
                a.overall_threat_score = $overall_score,
                a.threat_level = $threat_level,
                a.enrichment_confidence = $confidence,
                a.is_known_malicious = $is_malicious,
                a.is_known_attacker = $is_known_attacker,
                a.threat_tags = $tags,
                a.enrichment_sources = $sources,
                a.last_enriched = datetime()
            RETURN a.ip as ip
    Enrich an attacker IP and update Neo4j.

    Args:
        attacker_ip: IP to enrich
        async_mode: If True, enrich asynchronously

    Returns:
        EnrichedIOC if sync mode, None if async
    Get enriched threat intelligence for an attacker from Neo4j.

    Args:
        attacker_ip: Attacker IP

    Returns:
        Dict with enrichment data or None
            MATCH (a:Attacker {ip: $ip})
            RETURN
                a.ip as ip,
                a.overall_threat_score as overall_score,
                a.threat_level as threat_level,
                a.enrichment_confidence as confidence,
                a.is_known_malicious as is_malicious,
                a.is_known_attacker as is_known_attacker,
                a.threat_tags as tags,
                a.enrichment_sources as sources,
                a.vt_reputation as vt_score,
                a.misp_confidence as misp_score,
                a.malware_confidence as malware_score,
                a.threat_actor_reputation as threat_actor_score,
                a.last_enriched as last_enriched
    Enrich all attackers in Neo4j that haven't been enriched recently.

    Args:
        limit: Max number of attackers to enrich

    Returns:
        Statistics dict
            MATCH (a:Attacker)
            WHERE a.last_enriched IS NULL
               OR datetime() - a.last_enriched > duration({hours: 24})
            RETURN a.ip as ip
            ORDER BY a.last_seen DESC
            LIMIT $limit
    Generate comprehensive threat intelligence report for an attacker.

    Args:
        attacker_ip: Attacker IP

    Returns:
        Threat intelligence report dict
            MATCH (a:Attacker {ip: $ip})-[:LAUNCHED]->(c:Campaign)
            OPTIONAL MATCH (c)-[:HAS_EVENT]->(e:AttackEvent)-[:MATCHES]->(t:Technique)
            RETURN
                c.campaign_id as campaign_id,
                c.status as status,
                c.severity as severity,
                c.first_seen as first_seen,
                c.last_seen as last_seen,
                count(DISTINCT e) as event_count,
                collect(DISTINCT t.attack_id) as techniques
            ORDER BY c.last_seen DESC
            LIMIT 10
    threat_level = enrichment.get("threat_level", "UNKNOWN")
    overall_score = enrichment.get("overall_score", 0)
    is_malicious = enrichment.get("is_malicious", False)

    active_campaigns = sum(1 for c in campaigns if c.get("status") == "ACTIVE")
    total_events = sum(c.get("event_count", 0) for c in campaigns)

    assessment = {
        "threat_level": threat_level,
        "overall_score": overall_score,
        "is_confirmed_malicious": is_malicious,
        "active_campaigns": active_campaigns,
        "total_campaigns": len(campaigns),
        "total_attack_events": total_events,
        "confidence": enrichment.get("confidence", 0)
    }

    if overall_score >= 90:
        assessment["description"] = "CRITICAL THREAT: Confirmed malicious actor with high threat score"
    elif overall_score >= 70:
        assessment["description"] = "HIGH THREAT: Known malicious activity detected"
    elif overall_score >= 40:
        assessment["description"] = "MEDIUM THREAT: Suspicious activity detected"
    elif overall_score >= 10:
        assessment["description"] = "LOW THREAT: Minor suspicious indicators"
    else:
        assessment["description"] = "CLEAN: No significant threat indicators"

    return assessment


def _generate_recommendations(enrichment: Dict[str, Any], campaigns: list) -> list:
    recommendations = []

    overall_score = enrichment.get("overall_score", 0)
    is_malicious = enrichment.get("is_malicious", False)
    tags = enrichment.get("tags", [])
    active_campaigns = sum(1 for c in campaigns if c.get("status") == "ACTIVE")

    if overall_score >= 70 or is_malicious:
        recommendations.append({
            "priority": "CRITICAL",
            "action": "block_ip",
            "description": "Block this IP at firewall immediately",
            "auto_applicable": True
        })
        recommendations.append({
            "priority": "HIGH",
            "action": "isolate_affected_hosts",
            "description": "Isolate all hosts that communicated with this IP",
            "auto_applicable": False
        })
        recommendations.append({
            "priority": "HIGH",
            "action": "collect_forensics",
            "description": "Collect forensic evidence from affected systems",
            "auto_applicable": False
        })

    if active_campaigns > 0:
        recommendations.append({
            "priority": "HIGH",
            "action": "investigate_campaigns",
            "description": f"Investigate {active_campaigns} active campaign(s)",
            "auto_applicable": False
        })

    if any(tag in ["brute-force", "ssh-brute-force"] for tag in tags):
        recommendations.append({
            "priority": "MEDIUM",
            "action": "disable_ssh_access",
            "description": "Review and restrict SSH access from this IP",
            "auto_applicable": True
        })

    if any(tag in ["ddos", "dos"] for tag in tags):
        recommendations.append({
            "priority": "MEDIUM",
            "action": "enable_rate_limiting",
            "description": "Enable rate limiting for this IP",
            "auto_applicable": True
        })

    if any(tag in ["malware", "c2", "botnet"] for tag in tags):
        recommendations.append({
            "priority": "HIGH",
            "action": "scan_all_systems",
            "description": "Scan all systems for malware/C2 beacons",
            "auto_applicable": False
        })

    if 40 <= overall_score < 70:
        recommendations.append({
            "priority": "MEDIUM",
            "action": "monitor_closely",
            "description": "Enable enhanced monitoring for this IP",
            "auto_applicable": True
        })
        recommendations.append({
            "priority": "LOW",
            "action": "add_to_watchlist",
            "description": "Add to security watchlist",
            "auto_applicable": True
        })

    recommendations.append({
        "priority": "LOW",
        "action": "update_threat_intel",
        "description": "Keep threat intelligence updated",
        "auto_applicable": True
    })

    return recommendations


def enrichment_health_check() -> Dict[str, Any]:
    enricher = get_enricher()
    return enricher.health_check()
