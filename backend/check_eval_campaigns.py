from neo4j_client import driver

eval_campaigns = {
    "SCN-SESSION-BOUNDARY-001": ["CAMP_23FB320A", "CAMP_1429ADB4", "CAMP_F91A7652", "CAMP_066240B7"],
    "SCN-SESSION-BOUNDARY-002": ["CAMP_5DD3F083", "CAMP_A93237FD", "CAMP_B12C16D4", "CAMP_1627943B",
                                   "CAMP_BB9A0F28", "CAMP_0E9C0284", "CAMP_C6E494CF", "CAMP_75FBEEBC",
                                   "CAMP_DDBFC6D9", "CAMP_10407C1A", "CAMP_D8605E81", "CAMP_DAE35509",
                                   "CAMP_E449E81D", "CAMP_6371D7E5", "CAMP_436330B7", "CAMP_F51E9C79",
                                   "CAMP_38EBD436", "CAMP_71320238", "CAMP_2845679C", "CAMP_835F5335",
                                   "CAMP_BB680773", "CAMP_F4E63855", "CAMP_E8E9F042", "CAMP_6988F109", "CAMP_5A4539E8"],
    "SCN-NMAP-001": ["CAMP_7331E223", "CAMP_9669CA33", "CAMP_B39F5C0A", "CAMP_947A7084",
                     "CAMP_67FCB361", "CAMP_427A075C", "CAMP_99EE7A64", "CAMP_5D691192",
                     "CAMP_0CCD0071", "CAMP_77263583", "CAMP_BB19A996", "CAMP_8FF3B37F",
                     "CAMP_B3CDBFA1", "CAMP_86D5837D", "CAMP_15E98B82", "CAMP_B177634A", "CAMP_1B8E9033"]
}

print("Checking historical evaluation campaigns in Neo4j...")
print("="*80)

with driver.session() as session:
    for scenario, campaign_ids in eval_campaigns.items():
        print(f"\n{scenario}: Expected {len(campaign_ids)} campaigns")
        found = 0
        missing = []

        for cid in campaign_ids:
            result = session.run("""
                MATCH (c:Campaign {campaign_id: $cid})
                RETURN c.campaign_id as id, c.attacker_ip as attacker, c.victim_ip as victim
