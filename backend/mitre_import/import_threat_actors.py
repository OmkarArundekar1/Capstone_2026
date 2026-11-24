from neo4j import GraphDatabase
from mitre_import.config import URI, USERNAME, PASSWORD
from mitre_import.parser import get_by_type
from mitre_import.mapper import map_threat_actor
driver = GraphDatabase.driver(URI, auth=(USERNAME, PASSWORD))
QUERY = '\nMERGE (a:ThreatActor {\n    actor_id:$actor_id\n})\nON CREATE SET\n    a.created_at = datetime()\nSET\n    a.stix_id = $stix_id,\n    a.name = $name,\n    a.description = $description,\n    a.url = $url,\n    a.aliases = $aliases,\n    a.created = datetime($created),\n    a.modified = datetime($modified),\n    a.revoked = $revoked,\n    a.last_synced = datetime()\n'

def import_threat_actors():
    actors = get_by_type('intrusion-set')
    imported = 0
    skipped = 0
    with driver.session() as session:
        for obj in actors:
            properties = map_threat_actor(obj)
            if properties is None:
                skipped += 1
                continue
            session.run(QUERY, **properties)
            imported += 1
            if imported % 25 == 0:
                print(f'[ThreatActor] Imported {imported}')
    print('\n========== Threat Actor Import ==========')
    print(f'Imported : {imported}')
    print(f'Skipped  : {skipped}')
    print('=========================================\n')

def close():
    driver.close()