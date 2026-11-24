import os
from pathlib import Path
from dotenv import load_dotenv
load_dotenv()
BASE_DIR = Path(__file__).resolve().parent.parent
STIX_FILE = BASE_DIR / 'mitredata' / 'attack-stix-data' / 'enterprise-attack' / 'enterprise-attack.json'
URI = os.environ.get('NEO4J_URI', 'bolt://localhost:7687')
USERNAME = os.environ.get('NEO4J_USERNAME', '')
PASSWORD = os.environ.get('NEO4J_PASSWORD', '')