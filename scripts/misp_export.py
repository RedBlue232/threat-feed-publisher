#!/usr/bin/env python3

import os
import json
import base64
import hashlib
import logging
from datetime import datetime, timezone

import requests
from pymisp import PyMISP

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
MISP_URL        = os.environ["MISP_URL"]
MISP_KEY        = os.environ["MISP_KEY"]
MISP_VERIFY_SSL = os.environ.get("MISP_VERIFY_SSL", "true").lower() == "true"
MISP_EVENT_UUID = os.environ["MISP_EVENT_UUID"]

GH_TOKEN  = os.environ["GH_TOKEN"]
GH_OWNER  = os.environ["GH_OWNER"]
GH_REPO   = os.environ["GH_REPO"]
GH_BRANCH = os.environ.get("GH_BRANCH", "main")

# Sous-dossier du repo qui sert de racine de feed MISP
FEED_DIR = os.environ.get("MISP_FEED_DIR", "misp-feed")

GH_API = "https://api.github.com"
GH_HEADERS = {
    "Authorization": f"Bearer {GH_TOKEN}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# GitHub helpers (identiques à feed.py)
# ---------------------------------------------------------------------------

def gh_get_sha(path: str) -> str | None:
    url = f"{GH_API}/repos/{GH_OWNER}/{GH_REPO}/contents/{path}"
    r = requests.get(url, headers=GH_HEADERS, params={"ref": GH_BRANCH}, timeout=15)
    if r.status_code == 404:
        return None
    r.raise_for_status()
    return r.json()["sha"]


def gh_put_file(path: str, content: str, message: str) -> None:
    url = f"{GH_API}/repos/{GH_OWNER}/{GH_REPO}/contents/{path}"
    body = {
        "message": message,
        "content": base64.b64encode(content.encode("utf-8")).decode("ascii"),
        "branch": GH_BRANCH,
    }
    sha = gh_get_sha(path)
    if sha:
        body["sha"] = sha
    r = requests.put(url, headers=GH_HEADERS, json=body, timeout=30)
    r.raise_for_status()
    log.info("GitHub ✓ %s", path)


# ---------------------------------------------------------------------------
# Sanitization — retire les champs sensibles / internes avant publication
# ---------------------------------------------------------------------------

# Champs à supprimer au niveau de l'event
EVENT_STRIP = {
    "event_creator_email",       # email admin MISP → jamais en public
    "id", "org_id", "orgc_id",   # IDs internes numériques
    "proposal_email_lock", "locked", "protected",
    "CryptographicKey", "ShadowAttribute", "RelatedEvent",
}

# Champs à supprimer sur chaque attribut
ATTR_STRIP = {
    "id", "event_id", "object_id", "sharing_group_id",
    "Sighting",                  # peut contenir des UUIDs d'observateurs internes
    "ShadowAttribute",
}


def sanitize_event(event: dict) -> dict:
    """Nettoie l'event pour une publication publique."""
    e = dict(event)  # shallow copy

    for k in EVENT_STRIP:
        e.pop(k, None)

    # Force une distribution cohérente avec une publication publique
    e["distribution"] = "3"          # All communities
    e["published"] = True
    e["sharing_group_id"] = "0"

    # Nettoyage des attributs
    clean_attrs = []
    for attr in e.get("Attribute", []):
        a = {k: v for k, v in attr.items() if k not in ATTR_STRIP}
        a["distribution"] = "5"      # Inherit event
        clean_attrs.append(a)
    e["Attribute"] = clean_attrs

    # Nettoyage des objets (même logique sur leurs attributs)
    clean_objs = []
    for obj in e.get("Object", []):
        o = dict(obj)
        for k in ("id", "event_id", "sharing_group_id"):
            o.pop(k, None)
        o["Attribute"] = [
            {k: v for k, v in a.items() if k not in ATTR_STRIP}
            for a in obj.get("Attribute", [])
        ]
        clean_objs.append(o)
    e["Object"] = clean_objs

    return e


# ---------------------------------------------------------------------------
# Génération du format Feed MISP
# ---------------------------------------------------------------------------

def build_manifest_entry(event: dict) -> dict:
    """Extrait les champs attendus dans manifest.json pour un event."""
    return {
        "Orgc": event.get("Orgc", {}),
        "Tag": event.get("Tag", []),
        "info": event.get("info", ""),
        "date": event.get("date", ""),
        "analysis": event.get("analysis", "0"),
        "threat_level_id": event.get("threat_level_id", "4"),
        "timestamp": event.get("timestamp", ""),
    }


def build_hashes_csv(event: dict) -> str:
    """
    hashes.csv : une ligne par attribut exportable
        <event_uuid>,<md5(value)>
    Inclut aussi les attributs des objets MISP.
    """
    lines = []
    event_uuid = event["uuid"]

    def add(value: str):
        if not value:
            return
        h = hashlib.md5(value.encode("utf-8")).hexdigest()
        lines.append(f"{event_uuid},{h}")

    for attr in event.get("Attribute", []):
        if attr.get("to_ids"):       # seulement les IOCs actionnables
            add(attr.get("value", ""))

    for obj in event.get("Object", []):
        for attr in obj.get("Attribute", []):
            if attr.get("to_ids"):
                add(attr.get("value", ""))

    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    log.info("Connexion MISP → %s", MISP_URL)
    misp = PyMISP(MISP_URL, MISP_KEY, MISP_VERIFY_SSL)

    log.info("Fetch event %s", MISP_EVENT_UUID)
    raw = misp.get_event(MISP_EVENT_UUID, pythonify=False)
    if "Event" not in raw:
        raise RuntimeError(f"Event introuvable ou erreur MISP: {raw}")

    event = sanitize_event(raw["Event"])
    uuid = event["uuid"]
    log.info("Event nettoyé : %d attributs, %d objets",
             len(event.get("Attribute", [])), len(event.get("Object", [])))

    # 1. Fichier event : {"Event": {...}}
    event_json = json.dumps({"Event": event}, indent=2, ensure_ascii=False)

    # 2. Manifest : dict indexé par UUID
    manifest = {uuid: build_manifest_entry(event)}
    manifest_json = json.dumps(manifest, indent=2, ensure_ascii=False)

    # 3. Hashes
    hashes_csv = build_hashes_csv(event)

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%MZ")
    commit_msg = f"chore(misp): refresh feed {uuid} [{ts}]"

    gh_put_file(f"{FEED_DIR}/{uuid}.json",    event_json,    commit_msg)
    gh_put_file(f"{FEED_DIR}/manifest.json",  manifest_json, commit_msg)
    gh_put_file(f"{FEED_DIR}/hashes.csv",     hashes_csv,    commit_msg)

    log.info("Done.")


if __name__ == "__main__":
    main()
