from typing import List
from neo4j_client import driver
from attribution_models import HistoricalCampaign

def _deduplicate_preserve_order(items):
    seen = set()
    result = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result

class AttributionContext:

    def load_historical_campaigns(self) -> List[HistoricalCampaign]:
        with driver.session() as session:
            result = session.run("\n                MATCH (c:Campaign)\n\n                WHERE c.status IN ['INACTIVE','ARCHIVED']\n\n                MATCH\n                    (c)-[:HAS_EVENT]->\n                    (e:AttackEvent)\n                    -[:MATCHES]->\n                    (t:Technique)\n\n                WITH\n                    c,\n                    e,\n                    t\n\n                ORDER BY\n                    c.campaign_id,\n                    e.first_seen\n\n                RETURN\n                    c.campaign_id AS campaign_id,\n                    c.attacker_ip AS attacker,\n                    c.victim_ip AS victim,\n                    collect(\n                        t.attack_id\n                    ) AS techniques,\n\n                    collect(\n                        toString(\n                            e.first_seen\n                        )\n                    ) AS timestamps\n                ")
            campaigns = []
            for row in result:
                techniques = _deduplicate_preserve_order(row['techniques'])
                campaigns.append(HistoricalCampaign(campaign_id=row['campaign_id'], attacker=row['attacker'], victim=row['victim'], techniques=techniques, timestamps=row['timestamps']))
            return campaigns
context = AttributionContext()