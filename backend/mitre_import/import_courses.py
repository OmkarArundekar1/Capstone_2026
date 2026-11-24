from neo4j import GraphDatabase
from mitre_import.config import URI, USERNAME, PASSWORD
from mitre_import.parser import get_by_type
from mitre_import.mapper import map_course_of_action
driver = GraphDatabase.driver(URI, auth=(USERNAME, PASSWORD))
QUERY = '\nMERGE (c:CourseOfAction {\n    mitigation_id:$mitigation_id\n})\nON CREATE SET\n    c.created_at = datetime()\nSET\n    c.stix_id = $stix_id,\n    c.name = $name,\n    c.description = $description,\n    c.url = $url,\n    c.created = datetime($created),\n    c.modified = datetime($modified),\n    c.revoked = $revoked,\n    c.last_synced = datetime()\n'

def import_courses():
    mitigations = get_by_type('course-of-action')
    imported = 0
    skipped = 0
    with driver.session() as session:
        for obj in mitigations:
            properties = map_course_of_action(obj)
            if properties is None:
                skipped += 1
                continue
            session.run(QUERY, **properties)
            imported += 1
            if imported % 50 == 0:
                print(f'[CourseOfAction] Imported {imported}')
    print('\n========== Course Of Action Import ==========')
    print(f'Imported : {imported}')
    print(f'Skipped  : {skipped}')
    print('=============================================\n')

def close():
    driver.close()