from __future__ import annotations
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Any
from enum import Enum
import threading
import queue
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
logger = logging.getLogger(__name__)

class ThreatLevel(str, Enum):
    CRITICAL = 'CRITICAL'
    HIGH = 'HIGH'
    MEDIUM = 'MEDIUM'
    LOW = 'LOW'
    CLEAN = 'CLEAN'
    UNKNOWN = 'UNKNOWN'

class EnrichmentSource(str, Enum):
    MISP = 'MISP'
    VIRUSTOTAL = 'VirusTotal'
    ABUSEIPDB = 'AbuseIPDB'
    ALIENVAULT = 'AlienVault OTX'
    SHODAN = 'Shodan'
    GREYNOISE = 'GreyNoise'
    CACHE = 'Cache'
    INTERNAL = 'Internal'

@dataclass
class ThreatScore:
    source: EnrichmentSource
    score: float
    confidence: float
    tags: List[str] = field(default_factory=list)
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    description: Optional[str] = None
    raw_data: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.utcnow)

@dataclass
class EnrichedIOC:
    ioc: str
    ioc_type: str
    overall_score: float
    threat_level: ThreatLevel
    confidence: float
    sources: List[ThreatScore]
    aggregated_tags: List[str]
    is_malicious: bool
    is_known_attacker: bool
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    enriched_at: datetime = field(default_factory=datetime.utcnow)
    reputation_score: float = 0.0
    malware_score: float = 0.0
    threat_actor_score: float = 0.0
    botnet_score: float = 0.0
    c2_score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {'ioc': self.ioc, 'ioc_type': self.ioc_type, 'overall_score': round(self.overall_score, 2), 'threat_level': self.threat_level.value, 'confidence': round(self.confidence, 2), 'is_malicious': self.is_malicious, 'is_known_attacker': self.is_known_attacker, 'sources': [{'source': s.source.value, 'score': round(s.score, 2), 'confidence': round(s.confidence, 2), 'tags': s.tags} for s in self.sources], 'tags': self.aggregated_tags, 'reputation_score': round(self.reputation_score, 2), 'malware_score': round(self.malware_score, 2), 'threat_actor_score': round(self.threat_actor_score, 2), 'botnet_score': round(self.botnet_score, 2), 'c2_score': round(self.c2_score, 2), 'first_seen': self.first_seen, 'last_seen': self.last_seen, 'enriched_at': self.enriched_at.isoformat()}

class EnrichmentCache:

    def __init__(self, ttl_seconds: int=3600):
        self.cache: Dict[str, tuple[EnrichedIOC, float]] = {}
        self.lock = threading.RLock()
        self.ttl = ttl_seconds

    def get(self, ioc: str) -> Optional[EnrichedIOC]:
        with self.lock:
            if ioc in self.cache:
                enriched, timestamp = self.cache[ioc]
                if time.time() - timestamp < self.ttl:
                    logger.debug(f'Cache HIT for {ioc}')
                    return enriched
                else:
                    logger.debug(f'Cache EXPIRED for {ioc}')
                    del self.cache[ioc]
            return None

    def set(self, ioc: str, enriched: EnrichedIOC):
        with self.lock:
            self.cache[ioc] = (enriched, time.time())
            logger.debug(f'Cached enrichment for {ioc}')

    def clear(self):
        with self.lock:
            self.cache.clear()
            logger.info('Enrichment cache cleared')

    def stats(self) -> Dict[str, Any]:
        with self.lock:
            total = len(self.cache)
            expired = sum((1 for _, (_, ts) in self.cache.items() if time.time() - ts >= self.ttl))
            return {'total_cached': total, 'valid': total - expired, 'expired': expired, 'ttl_seconds': self.ttl}

class MISPEnricher:

    def __init__(self, misp_url: str, api_key: str, verify_ssl: bool=False):
        self.url = misp_url.rstrip('/')
        self.api_key = api_key
        self.verify_ssl = verify_ssl
        self.session = self._create_session()

    def _create_session(self) -> requests.Session:
        session = requests.Session()
        retries = Retry(total=1, backoff_factor=0.3, status_forcelist=[429, 500, 502, 503, 504])
        session.mount('http://', HTTPAdapter(max_retries=retries))
        session.mount('https://', HTTPAdapter(max_retries=retries))
        return session

    def _headers(self) -> Dict[str, str]:
        return {'Authorization': self.api_key, 'Accept': 'application/json', 'Content-Type': 'application/json'}

    def _is_valid_ip(self, value: str) -> bool:
        import ipaddress
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    def enrich_ip(self, ip: str) -> Optional[ThreatScore]:
        if not self._is_valid_ip(ip):
            logger.debug(f'Skipping MISP enrichment for hostname: {ip}')
            return None
        try:
            payload = {'returnFormat': 'json', 'type': 'ip-src', 'value': ip, 'limit': 10, 'published': True}
            response = self.session.post(f'{self.url}/attributes/restSearch', json=payload, headers=self._headers(), timeout=10, verify=self.verify_ssl)
            if not response.ok:
                logger.warning(f'MISP query failed for {ip}: HTTP {response.status_code}')
                return None
            data = response.json()
            attributes = data.get('response', {}).get('Attribute', [])
            if not attributes:
                logger.debug(f'No MISP data found for {ip}')
                return None
            tags = []
            malicious_count = 0
            total_sightings = 0
            for attr in attributes:
                event = attr.get('Event', {})
                threat_level = event.get('threat_level_id', 4)
                if threat_level <= 2:
                    malicious_count += 1
                for tag in event.get('Tag', []):
                    tag_name = tag.get('name', '')
                    if tag_name and tag_name not in tags:
                        tags.append(tag_name)
                sightings = attr.get('Sighting', [])
                total_sightings += len(sightings)
            base_score = min(malicious_count / len(attributes) * 100, 100)
            sighting_bonus = min(total_sightings * 5, 30)
            score = min(base_score + sighting_bonus, 100)
            confidence = min(len(attributes) / 10 * 100, 100)
            return ThreatScore(source=EnrichmentSource.MISP, score=score, confidence=confidence, tags=tags[:10], description=f'Found in {len(attributes)} MISP events with {total_sightings} sightings')
        except Exception as e:
            logger.exception(f'MISP enrichment failed for {ip}: {e}')
            return None

class VirusTotalEnricher:

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.session = requests.Session()

    def enrich_ip(self, ip: str) -> Optional[ThreatScore]:
        if not self.api_key:
            return None
        try:
            headers = {'x-apikey': self.api_key}
            response = self.session.get(f'https://www.virustotal.com/api/v3/ip_addresses/{ip}', headers=headers, timeout=5)
            if response.status_code == 404:
                logger.debug(f'IP {ip} not found in VirusTotal')
                return None
            if not response.ok:
                logger.warning(f'VirusTotal query failed for {ip}: HTTP {response.status_code}')
                return None
            data = response.json().get('data', {})
            attributes = data.get('attributes', {})
            stats = attributes.get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            harmless = stats.get('harmless', 0)
            undetected = stats.get('undetected', 0)
            total = malicious + suspicious + harmless + undetected
            if total == 0:
                return None
            score = (malicious * 100 + suspicious * 50) / total
            confidence = min(total / 80 * 100, 100)
            tags = []
            for tag in attributes.get('tags', [])[:10]:
                tags.append(tag)
            return ThreatScore(source=EnrichmentSource.VIRUSTOTAL, score=score, confidence=confidence, tags=tags, description=f'{malicious}/{total} engines flagged as malicious', raw_data={'malicious': malicious, 'suspicious': suspicious, 'total': total})
        except Exception as e:
            logger.exception(f'VirusTotal enrichment failed for {ip}: {e}')
            return None

class AbuseIPDBEnricher:

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.session = requests.Session()

    def enrich_ip(self, ip: str) -> Optional[ThreatScore]:
        if not self.api_key:
            return None
        try:
            headers = {'Key': self.api_key, 'Accept': 'application/json'}
            params = {'ipAddress': ip, 'maxAgeInDays': 90}
            response = self.session.get('https://api.abuseipdb.com/api/v2/check', headers=headers, params=params, timeout=5)
            if not response.ok:
                logger.warning(f'AbuseIPDB query failed for {ip}: HTTP {response.status_code}')
                return None
            data = response.json().get('data', {})
            abuse_score = data.get('abuseConfidenceScore', 0)
            total_reports = data.get('totalReports', 0)
            if total_reports == 0:
                logger.debug(f'No AbuseIPDB reports for {ip}')
                return None
            confidence = min(total_reports / 50 * 100, 100)
            tags = []
            for category in data.get('categories', []):
                category_map = {3: 'fraud', 4: 'ddos', 14: 'port-scan', 15: 'hacking', 18: 'brute-force', 19: 'bad-web-bot', 20: 'exploited-host', 21: 'web-app-attack', 22: 'ssh-brute-force'}
                if category in category_map:
                    tags.append(category_map[category])
            return ThreatScore(source=EnrichmentSource.ABUSEIPDB, score=float(abuse_score), confidence=confidence, tags=tags, description=f'{total_reports} abuse reports in last 90 days', raw_data={'total_reports': total_reports, 'abuse_score': abuse_score})
        except Exception as e:
            logger.exception(f'AbuseIPDB enrichment failed for {ip}: {e}')
            return None

class HybridThreatEnricher:

    def __init__(self, misp_url: str, misp_api_key: str, virustotal_api_key: str='', abuseipdb_api_key: str='', verify_misp_ssl: bool=False, cache_ttl: int=3600):
        self.misp = MISPEnricher(misp_url, misp_api_key, verify_misp_ssl) if misp_api_key else None
        self.virustotal = VirusTotalEnricher(virustotal_api_key) if virustotal_api_key else None
        self.abuseipdb = AbuseIPDBEnricher(abuseipdb_api_key) if abuseipdb_api_key else None
        self.cache = EnrichmentCache(ttl_seconds=cache_ttl)
        self.enrichment_queue = queue.Queue(maxsize=1000)
        self.enrichment_thread = None
        self.running = False
        logger.info(f"HybridThreatEnricher initialized: MISP={('✓' if self.misp else '✗')}, VT={('✓' if self.virustotal else '✗')}, AbuseIPDB={('✓' if self.abuseipdb else '✗')}")

    def enrich_ip(self, ip: str, use_cache: bool=True) -> EnrichedIOC:
        if use_cache:
            cached = self.cache.get(ip)
            if cached:
                return cached
        logger.info(f'Enriching IP: {ip}')
        sources: List[ThreatScore] = []
        if self.misp:
            misp_score = self.misp.enrich_ip(ip)
            if misp_score:
                sources.append(misp_score)
        if self.virustotal:
            vt_score = self.virustotal.enrich_ip(ip)
            if vt_score:
                sources.append(vt_score)
        if self.abuseipdb:
            abuse_score = self.abuseipdb.enrich_ip(ip)
            if abuse_score:
                sources.append(abuse_score)
        enriched = self._aggregate_scores(ip, 'ip', sources)
        self.cache.set(ip, enriched)
        return enriched

    def _aggregate_scores(self, ioc: str, ioc_type: str, sources: List[ThreatScore]) -> EnrichedIOC:
        if not sources:
            return EnrichedIOC(ioc=ioc, ioc_type=ioc_type, overall_score=0.0, threat_level=ThreatLevel.UNKNOWN, confidence=0.0, sources=[], aggregated_tags=[], is_malicious=False, is_known_attacker=False)
        total_weighted_score = 0.0
        total_weight = 0.0
        for source in sources:
            weight = source.confidence / 100.0
            total_weighted_score += source.score * weight
            total_weight += weight
        overall_score = total_weighted_score / total_weight if total_weight > 0 else 0.0
        avg_confidence = sum((s.confidence for s in sources)) / len(sources)
        if overall_score >= 90:
            threat_level = ThreatLevel.CRITICAL
        elif overall_score >= 70:
            threat_level = ThreatLevel.HIGH
        elif overall_score >= 40:
            threat_level = ThreatLevel.MEDIUM
        elif overall_score >= 10:
            threat_level = ThreatLevel.LOW
        else:
            threat_level = ThreatLevel.CLEAN
        all_tags = []
        for source in sources:
            all_tags.extend(source.tags)
        unique_tags = list(set(all_tags))[:20]
        is_malicious = overall_score >= 70
        is_known_attacker = overall_score >= 50
        reputation_score = overall_score
        malware_score = self._calculate_category_score(sources, ['malware', 'trojan', 'ransomware'])
        threat_actor_score = self._calculate_category_score(sources, ['apt', 'threat-actor', 'targeted-attack'])
        botnet_score = self._calculate_category_score(sources, ['botnet', 'c2', 'command-and-control'])
        c2_score = self._calculate_category_score(sources, ['c2', 'command-and-control', 'cnc'])
        return EnrichedIOC(ioc=ioc, ioc_type=ioc_type, overall_score=overall_score, threat_level=threat_level, confidence=avg_confidence, sources=sources, aggregated_tags=unique_tags, is_malicious=is_malicious, is_known_attacker=is_known_attacker, reputation_score=reputation_score, malware_score=malware_score, threat_actor_score=threat_actor_score, botnet_score=botnet_score, c2_score=c2_score)

    def _calculate_category_score(self, sources: List[ThreatScore], keywords: List[str]) -> float:
        matching_sources = [s for s in sources if any((keyword in tag.lower() for tag in s.tags for keyword in keywords))]
        if not matching_sources:
            return 0.0
        return sum((s.score for s in matching_sources)) / len(matching_sources)

    def enrich_async(self, ip: str, callback=None):
        try:
            self.enrichment_queue.put_nowait((ip, callback))
        except queue.Full:
            logger.warning(f'Enrichment queue full, dropping {ip}')

    def _enrichment_worker(self):
        while self.running:
            try:
                ip, callback = self.enrichment_queue.get(timeout=1)
                enriched = self.enrich_ip(ip)
                if callback:
                    callback(enriched)
            except queue.Empty:
                continue
            except Exception as e:
                logger.exception(f'Enrichment worker error: {e}')

    def start_async_worker(self):
        if self.running:
            logger.warning('Enrichment worker already running')
            return
        self.running = True
        self.enrichment_thread = threading.Thread(target=self._enrichment_worker, daemon=True, name='ThreatEnrichmentWorker')
        self.enrichment_thread.start()
        logger.info('Async enrichment worker started')

    def stop_async_worker(self):
        self.running = False
        if self.enrichment_thread:
            self.enrichment_thread.join(timeout=5)
        logger.info('Async enrichment worker stopped')

    def health_check(self) -> Dict[str, Any]:
        health = {'misp': False, 'virustotal': bool(self.virustotal and self.virustotal.api_key), 'abuseipdb': bool(self.abuseipdb and self.abuseipdb.api_key), 'cache': self.cache.stats(), 'queue_size': self.enrichment_queue.qsize() if self.running else 0}
        if self.misp:
            try:
                response = self.misp.session.get(f'{self.misp.url}/servers/getVersion', headers=self.misp._headers(), timeout=3, verify=self.misp.verify_ssl)
                health['misp'] = response.ok
            except Exception:
                health['misp'] = False
        return health

def create_enricher_from_config() -> HybridThreatEnricher:
    from config import MISP_URL, MISP_API_KEY, VERIFY_MISP_SSL
    import os
    return HybridThreatEnricher(misp_url=MISP_URL, misp_api_key=MISP_API_KEY, virustotal_api_key=os.environ.get('VIRUSTOTAL_API_KEY', ''), abuseipdb_api_key=os.environ.get('ABUSEIPDB_API_KEY', ''), verify_misp_ssl=VERIFY_MISP_SSL, cache_ttl=3600)
_enricher: Optional[HybridThreatEnricher] = None

def get_enricher() -> HybridThreatEnricher:
    global _enricher
    if _enricher is None:
        _enricher = create_enricher_from_config()
        _enricher.start_async_worker()
    return _enricher