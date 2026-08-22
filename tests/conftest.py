"""Configuration commune aux tests.

`feed.py` lit sa configuration au moment de l'import et lève un KeyError si
les variables obligatoires manquent. On les pose donc AVANT tout import des
modules du projet, et on ajoute `scripts/` au path puisqu'il n'y a pas de
packaging (les scripts sont copiés à plat dans l'image Docker).
"""
import os
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS))

os.environ.setdefault("LAPI_BASE", "http://lapi.test/v1")
os.environ.setdefault("CS_MACHINE_ID", "test-machine")
os.environ.setdefault("CS_PASSWORD", "test-password")
os.environ.setdefault("GH_TOKEN", "test-token")
os.environ.setdefault("GH_OWNER", "test-owner")
os.environ.setdefault("GH_REPO", "test-repo")
# Valeurs exercées par les tests de filtrage et de sanitization
os.environ.setdefault("PUBLISH_EXCLUDE_IPS", "9.9.9.9, 1.0.0.1")
os.environ.setdefault("PII_IPS", "203.0.113.5")
os.environ.setdefault("PII_DOMAINS", "*.corp.example,secret.test")
os.environ.setdefault("PAYLOAD_MAX_LEN", "512")
