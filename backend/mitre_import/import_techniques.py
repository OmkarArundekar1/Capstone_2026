from neo4j import GraphDatabase
from mitre_import.config import URI, USERNAME, PASSWORD
from mitre_import.parser import get_by_type
from mitre_import.mapper import map_technique
driver = GraphDatabase.driver(URI, auth=(USERNAME, PASSWORD))
QUERY = '\nMERGE (t:Technique {\n    attack_id:$attack_id\n})\n\nON CREATE SET\n    t.created_at = datetime()\n\nSET\n    t.stix_id = $stix_id,\n    t.name = $name,\n    t.description = $description,\n    t.url = $url,\n\n    t.created = datetime($created),\n    t.modified = datetime($modified),\n\n    t.revoked = $revoked,\n    t.deprecated = $deprecated,\n\n    t.attack_spec_version = $attack_spec_version,\n    t.object_version = $object_version,\n\n    t.platforms = $platforms,\n    t.domains = $domains,\n\n    t.kill_chain_phases = $kill_chain_phases,\n\n    t.is_subtechnique = $is_subtechnique,\n\n    t.last_synced = datetime()\n'

def import_techniques():
    techniques = get_by_type('attack-pattern')
    imported = 0
    skipped = 0
    with driver.session() as session:
        for obj in techniques:
            properties = map_technique(obj)
            if properties is None:
                skipped += 1
                continue
            session.run(QUERY, **properties)
            imported += 1
            if imported % 100 == 0:
                print(f'[Technique] Imported {imported}')
    print('\n========== Technique Import ==========')
    print(f'Imported : {imported}')
    print(f'Skipped  : {skipped}')
    print('======================================\n')

def close():
    driver.close()