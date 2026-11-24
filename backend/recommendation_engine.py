from neo4j_client import driver

def get_recommendations(technique_id):
    with driver.session() as session:
        result = session.run('\n            MATCH (t:Technique {attack_id:$attack_id})\n\n            MATCH (m:CourseOfAction)-[:MITIGATES]->(t)\n\n            RETURN\n                m.mitigation_id AS mitigation_id,\n                m.name AS mitigation_name,\n                m.description AS description\n            ORDER BY mitigation_name\n            ', attack_id=technique_id)
        recommendations = []
        for row in result:
            recommendations.append({'recommendation': row['mitigation_name'], 'priority': 'MITRE', 'mitre_mitigation': row['mitigation_id'], 'reason': row['description'], 'predicted_technique': technique_id, 'traceability': f"MITRE ATT&CK → {row['mitigation_id']}"})
        if recommendations:
            return recommendations
        return [{'recommendation': 'No mitigation available', 'priority': 'LOW', 'mitre_mitigation': 'N/A', 'reason': 'No official ATT&CK mitigation found.', 'predicted_technique': technique_id, 'traceability': 'MITRE ATT&CK'}]

def get_recommendation_strings(technique_id):
    return [r['recommendation'] for r in get_recommendations(technique_id)]