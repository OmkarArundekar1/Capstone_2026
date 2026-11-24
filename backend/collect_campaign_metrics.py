import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Optional

sys.path.insert(0, str(Path(__file__).parent))

try:
    from neo4j import GraphDatabase
    from neo4j.time import Duration
except ImportError:
    print("ERROR: neo4j package not installed. Run: pip install neo4j", file=sys.stderr)
    sys.exit(1)


class CampaignMetricsCollector:
    def __init__(self, neo4j_uri: str, neo4j_user: str, neo4j_password: str):
        self.driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))

    def close(self):
        self.driver.close()

    def collect_all_metrics(self, observation_start: datetime, observation_end: datetime) -> Dict[str, Any]:
        print(f"Collecting metrics from {observation_start.isoformat()} to {observation_end.isoformat()}")

        with self.driver.session() as session:
            campaigns_per_pair = self._get_campaigns_per_pair(session, observation_start, observation_end)

            singleton_rate = self._get_singleton_rate(session, observation_start, observation_end)

            temporal_gaps = self._get_temporal_gaps(session, observation_start, observation_end)

            duration_stats = self._get_duration_stats(session, observation_start, observation_end)

            reopen_stats = self._get_reopen_stats(session, observation_start, observation_end)

            events_per_campaign = self._get_events_per_campaign(session, observation_start, observation_end)

            overlapping_campaigns = self._get_overlapping_campaigns(session, observation_start, observation_end)

            assignment_coverage = self._get_assignment_coverage(session, observation_start, observation_end)

            review_queue = self._get_review_queue(session, observation_start, observation_end)

            return {
                "metadata": {
                    "observation_start": observation_start.isoformat(),
                    "observation_end": observation_end.isoformat(),
                    "collection_timestamp": datetime.now(timezone.utc).isoformat(),
                    "methodology_version": "Phase_B2.1_Revised"
                },
                "campaigns_per_pair": campaigns_per_pair,
                "singleton_rate": singleton_rate,
                "temporal_gaps": temporal_gaps,
                "duration_stats": duration_stats,
                "reopen_stats": reopen_stats,
                "events_per_campaign": events_per_campaign,
                "overlapping_campaigns": overlapping_campaigns,
                "assignment_coverage": assignment_coverage,
                "review_queue": review_queue
            }

    def _get_campaigns_per_pair(self, session, start: datetime, end: datetime) -> Dict[str, Any]:
        query = """
        MATCH (c:Campaign)
        WHERE c.first_seen >= $start AND c.first_seen < $end
        WITH c,
             c.attacker_ip AS attacker_ip,
             c.victim_ip AS victim_ip,
             CASE
                 WHEN c.attacker_ip = c.victim_ip THEN 'self_to_self'
                 WHEN c.attacker_ip =~ '\\d+\\.\\d+\\.\\d+\\.\\d+'
                   AND c.victim_ip =~ '\\d+\\.\\d+\\.\\d+\\.\\d+' THEN 'ip_to_ip'
                 ELSE 'hostname_based'
             END AS identity_category
        WITH identity_category, attacker_ip, victim_ip, count(c) AS campaign_count
        RETURN identity_category,
               count(*) AS pairs_count,
               avg(campaign_count) AS avg_campaigns_per_pair,
               percentileCont(campaign_count, 0.5) AS median_campaigns_per_pair,
               max(campaign_count) AS max_campaigns_per_pair,
               sum(CASE WHEN campaign_count = 1 THEN 1 ELSE 0 END) AS singleton_pairs
        ORDER BY identity_category
        Metric 2: Singleton campaign rate (campaigns with only 1 event).

        Interpretation:
            - Lower = better (fewer trivial campaigns)
            - BUT: May reflect attack behavior not correlation

        Confounders:
            - Single-shot attacks vs. correlation failure
            - Alert tuning changes
        MATCH (c:Campaign)
        WHERE c.first_seen >= $start AND c.first_seen < $end
        OPTIONAL MATCH (c)-[:HAS_EVENT]->(e:AttackEvent)
        WITH c, count(e) AS event_count,
             CASE
                 WHEN c.attacker_ip = c.victim_ip THEN 'self_to_self'
                 WHEN c.attacker_ip =~ '\\d+\\.\\d+\\.\\d+\\.\\d+'
                   AND c.victim_ip =~ '\\d+\\.\\d+\\.\\d+\\.\\d+' THEN 'ip_to_ip'
                 ELSE 'hostname_based'
             END AS identity_category
        WITH identity_category,
             count(c) AS total_campaigns,
             sum(CASE WHEN event_count = 1 THEN 1 ELSE 0 END) AS singleton_campaigns
        RETURN identity_category,
               total_campaigns,
               singleton_campaigns,
               CASE WHEN total_campaigns > 0
                    THEN toFloat(singleton_campaigns) / total_campaigns
                    ELSE 0.0 END AS singleton_rate
        ORDER BY identity_category
        Metric 3: Temporal gaps between consecutive campaigns for same pair.

        Interpretation:
            - Short gaps (<120s) = potential fragmentation
            - Long gaps (>1h) = legitimate separate campaigns
            - Negative gaps = overlapping campaigns (potential over-merge)

        Confounders:
            - Legitimate attack bursts vs. correlation failure
        MATCH (c1:Campaign)
        WHERE c1.first_seen >= $start AND c1.first_seen < $end
        WITH c1.attacker_ip AS attacker, c1.victim_ip AS victim, c1
        ORDER BY c1.first_seen
        WITH attacker, victim, collect(c1) AS campaigns
        WHERE size(campaigns) > 1
        UNWIND range(0, size(campaigns)-2) AS i
        WITH attacker, victim,
             campaigns[i] AS c1,
             campaigns[i+1] AS c2,
             duration.between(campaigns[i].last_seen, campaigns[i+1].first_seen).seconds AS gap_seconds
        RETURN
            count(*) AS total_gaps,
            avg(gap_seconds) AS avg_gap_seconds,
            percentileCont(gap_seconds, 0.5) AS median_gap_seconds,
            sum(CASE WHEN gap_seconds < 0 THEN 1 ELSE 0 END) AS overlapping_count,
            sum(CASE WHEN gap_seconds >= 0 AND gap_seconds < 60 THEN 1 ELSE 0 END) AS gaps_under_60s,
            sum(CASE WHEN gap_seconds >= 60 AND gap_seconds < 120 THEN 1 ELSE 0 END) AS gaps_60_to_120s,
            sum(CASE WHEN gap_seconds >= 120 AND gap_seconds < 300 THEN 1 ELSE 0 END) AS gaps_120_to_300s,
            sum(CASE WHEN gap_seconds >= 300 AND gap_seconds < 3600 THEN 1 ELSE 0 END) AS gaps_5m_to_1h,
            sum(CASE WHEN gap_seconds >= 3600 THEN 1 ELSE 0 END) AS gaps_over_1h
        Metric 4: Campaign duration distribution.

        Interpretation:
            - Very short (<1m) = likely singletons or correlation failure
            - Very long (>24h) = potential over-merging
            - Median provides robust central tendency

        Confounders:
            - Attack campaign duration varies legitimately
        MATCH (c:Campaign)
        WHERE c.first_seen >= $start AND c.first_seen < $end
        WITH c, duration.between(c.first_seen, c.last_seen).seconds AS duration_seconds
        RETURN
            count(c) AS total_campaigns,
            avg(duration_seconds) AS avg_duration_seconds,
            percentileCont(duration_seconds, 0.5) AS median_duration_seconds,
            percentileCont(duration_seconds, 0.9) AS p90_duration_seconds,
            max(duration_seconds) AS max_duration_seconds,
            sum(CASE WHEN duration_seconds < 60 THEN 1 ELSE 0 END) AS under_1m,
            sum(CASE WHEN duration_seconds >= 60 AND duration_seconds < 300 THEN 1 ELSE 0 END) AS from_1m_to_5m,
            sum(CASE WHEN duration_seconds >= 300 AND duration_seconds < 3600 THEN 1 ELSE 0 END) AS from_5m_to_1h,
            sum(CASE WHEN duration_seconds >= 3600 AND duration_seconds < 86400 THEN 1 ELSE 0 END) AS from_1h_to_24h,
            sum(CASE WHEN duration_seconds >= 86400 THEN 1 ELSE 0 END) AS over_24h
        Metric 5: Campaign reopen frequency.

        Interpretation:
            - Ambiguous: Could indicate better correlation OR worse fragmentation
            - Requires human review to interpret

        Confounders:
            - Attack patterns (periodic attacks)
            - Alert generation patterns
        MATCH (c:Campaign)
        WHERE c.first_seen >= $start AND c.first_seen < $end
        RETURN
            count(c) AS total_campaigns,
            sum(COALESCE(c.reopened_count, 0)) AS total_reopens,
            avg(COALESCE(c.reopened_count, 0)) AS avg_reopens_per_campaign,
            max(COALESCE(c.reopened_count, 0)) AS max_reopens,
            sum(CASE WHEN COALESCE(c.reopened_count, 0) = 0 THEN 1 ELSE 0 END) AS never_reopened,
            sum(CASE WHEN COALESCE(c.reopened_count, 0) >= 1 AND c.reopened_count < 3 THEN 1 ELSE 0 END) AS reopened_1_to_2,
            sum(CASE WHEN COALESCE(c.reopened_count, 0) >= 3 AND c.reopened_count < 5 THEN 1 ELSE 0 END) AS reopened_3_to_4,
            sum(CASE WHEN COALESCE(c.reopened_count, 0) >= 5 THEN 1 ELSE 0 END) AS reopened_5_plus
        Metric 6: Events per campaign distribution.

        Interpretation:
            - Higher median = better correlation (fewer fragments)
            - Many campaigns with 1 event = potential fragmentation

        Confounders:
            - Attack intensity varies legitimately
        MATCH (c:Campaign)
        WHERE c.first_seen >= $start AND c.first_seen < $end
        OPTIONAL MATCH (c)-[:HAS_EVENT]->(e:AttackEvent)
        WITH c, count(e) AS event_count
        RETURN
            count(c) AS total_campaigns,
            avg(event_count) AS avg_events_per_campaign,
            percentileCont(event_count, 0.5) AS median_events_per_campaign,
            max(event_count) AS max_events_per_campaign,
            sum(CASE WHEN event_count = 1 THEN 1 ELSE 0 END) AS campaigns_with_1_event,
            sum(CASE WHEN event_count >= 2 AND event_count < 5 THEN 1 ELSE 0 END) AS campaigns_with_2_to_4_events,
            sum(CASE WHEN event_count >= 5 AND event_count < 10 THEN 1 ELSE 0 END) AS campaigns_with_5_to_9_events,
            sum(CASE WHEN event_count >= 10 THEN 1 ELSE 0 END) AS campaigns_with_10_plus_events
        Metric 7: Overlapping campaigns for same attacker-victim pair.

        Interpretation:
            - ANY overlap = potential fragmentation failure
            - Should be ZERO if correlation working correctly

        Confounders:
            - Parallel attack streams (rare but possible)
        MATCH (c1:Campaign), (c2:Campaign)
        WHERE c1.first_seen >= $start AND c1.first_seen < $end
          AND c2.first_seen >= $start AND c2.first_seen < $end
          AND c1.campaign_id < c2.campaign_id
          AND c1.attacker_ip = c2.attacker_ip
          AND c1.victim_ip = c2.victim_ip
          AND c1.first_seen <= c2.last_seen
          AND c2.first_seen <= c1.last_seen
        WITH c1, c2,
             duration.between(
                 CASE WHEN c1.first_seen > c2.first_seen THEN c1.first_seen ELSE c2.first_seen END,
                 CASE WHEN c1.last_seen < c2.last_seen THEN c1.last_seen ELSE c2.last_seen END
             ).seconds AS overlap_seconds
        RETURN
            count(*) AS overlapping_pair_count,
            avg(overlap_seconds) AS avg_overlap_seconds,
            max(overlap_seconds) AS max_overlap_seconds,
            collect({
                campaign_id_1: c1.campaign_id,
                campaign_id_2: c2.campaign_id,
                attacker: c1.attacker_ip,
                victim: c1.victim_ip,
                overlap_seconds: overlap_seconds
            })[0..10] AS sample_overlaps
        Metric 8: Alert assignment coverage.

        Interpretation:
            - Should be ~100% (all alerts assigned to campaigns)
            - Drop indicates correlation failures

        Confounders:
            - Service downtime
            - Alert types excluded from correlation
        MATCH (e:AttackEvent)
        WHERE e.first_seen >= $start AND e.first_seen < $end
        WITH count(e) AS total_alerts
        MATCH (e2:AttackEvent)-[:PART_OF_CAMPAIGN]->(:Campaign)
        WHERE e2.first_seen >= $start AND e2.first_seen < $end
        WITH total_alerts, count(e2) AS assigned_alerts
        RETURN total_alerts, assigned_alerts,
               CASE WHEN total_alerts > 0
                    THEN toFloat(assigned_alerts) / total_alerts
                    ELSE 0.0 END AS coverage_rate
        Metric 9: Generate human review queue for flagged campaigns.

        Flag campaigns if:
            - Duration > 24 hours (potential over-merge)
            - Duration > 7 days (likely over-merge)
            - Event count > 50 (potential over-merge)
            - Reopened > 5 times (unusual pattern)
        MATCH (c:Campaign)
        WHERE c.first_seen >= $start AND c.first_seen < $end
        OPTIONAL MATCH (c)-[:HAS_EVENT]->(e:AttackEvent)
        WITH c, count(e) AS event_count,
             duration.between(c.first_seen, c.last_seen).seconds AS duration_seconds,
             COALESCE(c.reopened_count, 0) AS reopened_count
        WHERE duration_seconds > 86400
           OR event_count > 50
           OR reopened_count > 5
        RETURN c.campaign_id AS campaign_id,
               c.attacker_ip AS attacker_ip,
               c.victim_ip AS victim_ip,
               c.first_seen AS first_seen,
               c.last_seen AS last_seen,
               event_count,
               duration_seconds,
               reopened_count,
               CASE
                   WHEN duration_seconds > 604800 THEN 'duration_over_7d'
                   WHEN duration_seconds > 86400 THEN 'duration_over_24h'
                   WHEN event_count > 50 THEN 'high_event_count'
                   WHEN reopened_count > 5 THEN 'high_reopen_count'
                   ELSE 'other'
               END AS flag_reason
        ORDER BY duration_seconds DESC
        LIMIT 50
    parser = argparse.ArgumentParser(
        description="Collect campaign correlation metrics for Phase B.2 validation"
    )
    parser.add_argument(
        "--observation-start",
        required=True,
        help="Observation start timestamp (ISO 8601 UTC, e.g., '2026-11-23T10:00:00Z')"
    )
    parser.add_argument(
        "--observation-end",
        required=False,
        help="Observation end timestamp (ISO 8601 UTC). Defaults to now."
    )
    parser.add_argument(
        "--neo4j-uri",
        default="bolt://localhost:7687",
        help="Neo4j URI (default: bolt://localhost:7687)"
    )
    parser.add_argument(
        "--neo4j-user",
        default="neo4j",
        help="Neo4j username (default: neo4j)"
    )
    parser.add_argument(
        "--neo4j-password",
        default="password",
        help="Neo4j password (default: password)"
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Output JSON file path"
    )

    return parser.parse_args()


def main():
    args = parse_args()

    try:
        observation_start = datetime.fromisoformat(args.observation_start.replace('Z', '+00:00'))
    except ValueError as e:
        print(f"ERROR: Invalid observation-start timestamp: {e}", file=sys.stderr)
        sys.exit(1)

    if args.observation_end:
        try:
            observation_end = datetime.fromisoformat(args.observation_end.replace('Z', '+00:00'))
        except ValueError as e:
            print(f"ERROR: Invalid observation-end timestamp: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        observation_end = datetime.now(timezone.utc)

    if observation_start >= observation_end:
        print("ERROR: observation-start must be before observation-end", file=sys.stderr)
        sys.exit(1)

    collector = CampaignMetricsCollector(
        args.neo4j_uri,
        args.neo4j_user,
        args.neo4j_password
    )

    try:
        metrics = collector.collect_all_metrics(observation_start, observation_end)

        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, 'w') as f:
            json.dump(metrics, f, indent=2, default=str)

        print(f"✅ Metrics collected successfully")
        print(f"📊 Output written to: {output_path}")
        print(f"📅 Observation period: {observation_start.isoformat()} to {observation_end.isoformat()}")

        if "duration_stats" in metrics and metrics["duration_stats"].get("total_campaigns", 0) > 0:
            total_campaigns = metrics["duration_stats"]["total_campaigns"]
            print(f"📈 Total campaigns in period: {total_campaigns}")

        if "review_queue" in metrics:
            flagged_count = metrics["review_queue"]["total_flagged"]
            print(f"🚩 Campaigns flagged for review: {flagged_count}")

    except Exception as e:
        print(f"ERROR: Failed to collect metrics: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)

    finally:
        collector.close()


if __name__ == "__main__":
    main()
