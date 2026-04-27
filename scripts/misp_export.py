#!/usr/bin/env python3
"""
Export des events MISP rolling vers le format Feed MISP publié sur GitHub.

Workflow :
1. Pour chaque UUID configuré (`MISP_UUID_ALL`, `MISP_UUID_CROWDSEC`,
   `MISP_UUID_SURICATA`) on fetch l'event courant côté instance MISP.
2. On le sanitize (retire les champs sensibles, force la distribution
   publique).
3. On écrit `misp-feed/<uuid>.json`.
4. On agrège les 3 entrées dans un `manifest.json` unique et un
   `hashes.csv` unique (le format Feed MISP indexe par UUID).
5. On pousse les fichiers sur GitHub.

Un UUID absent ou un fetch en échec n'arrête pas le run : on logge et on
passe au suivant. Permet une transition douce (un scope manquant côté
instance MISP n'empêche pas la publication des autres).
"""

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

# Les 3 UUIDs sont lus depuis l'env. Au moins un doit être défini, sinon
# on raise (rien à exporter).
MISP_UUIDS: dict[str, str] = {
    scope: os.environ.get(f"MISP_UUID_{scope.upper()}", "").strip()
    for scope in ("all", "crowdsec", "suricata")
}

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

EVENT_STRIP = {
    "event_creator_email",
    "id", "org_id", "orgc_id",
    "proposal_email_lock", "locked", "protected",
    "CryptographicKey", "ShadowAttribute", "RelatedEvent",
}

ATTR_STRIP = {
    "id", "event_id", "object_id", "sharing_group_id",
    "Sighting",
    "ShadowAttribute",
}


def sanitize_event(event: dict) -> dict:
    """Nettoie l'event pour une publication publique."""
    e = dict(event)
    for k in EVENT_STRIP:
        e.pop(k, None)
    e["distribution"] = "3"
    e["published"] = True
    e["sharing_group_id"] = "0"

    clean_attrs = []
    for attr in e.get("Attribute", []):
        a = {k: v for k, v in attr.items() if k not in ATTR_STRIP}
        a["distribution"] = "5"
        clean_attrs.append(a)
    e["Attribute"] = clean_attrs

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


def build_hashes_lines(event: dict) -> list[str]:
    """
    Lignes hashes.csv pour un event :
        <event_uuid>,<md5(value)>
    Inclut aussi les attributs des objets MISP. Retourne une liste pour
    permettre l'agrégation cross-events sans concaténation à la chaîne.
    """
    lines: list[str] = []
    event_uuid = event["uuid"]

    def add(value: str):
        if not value:
            return
        h = hashlib.md5(value.encode("utf-8")).hexdigest()
        lines.append(f"{event_uuid},{h}")

    for attr in event.get("Attribute", []):
        if attr.get("to_ids"):
            add(attr.get("value", ""))
    for obj in event.get("Object", []):
        for attr in obj.get("Attribute", []):
            if attr.get("to_ids"):
                add(attr.get("value", ""))
    return lines


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    configured = {scope: uuid for scope, uuid in MISP_UUIDS.items() if uuid}
    if not configured:
        raise RuntimeError(
            "Aucun MISP_UUID_* configuré (au moins un parmi "
            "MISP_UUID_ALL, MISP_UUID_CROWDSEC, MISP_UUID_SURICATA est requis)"
        )

    log.info("Connexion MISP → %s", MISP_URL)
    log.info("Scopes à exporter : %s", ", ".join(sorted(configured.keys())))
    misp = PyMISP(MISP_URL, MISP_KEY, MISP_VERIFY_SSL)

    manifest: dict[str, dict] = {}
    hashes_lines: list[str] = []
    event_files: dict[str, str] = {}  # path → content

    fetched, failed = 0, 0
    for scope, uuid in configured.items():
        log.info("[%s] fetch event %s", scope, uuid)
        try:
            raw = misp.get_event(uuid, pythonify=False)
            if "Event" not in raw:
                log.warning("[%s] event %s introuvable côté MISP — skip", scope, uuid)
                failed += 1
                continue
            event = sanitize_event(raw["Event"])
            log.info(
                "[%s] event nettoyé : %d attributs, %d objets",
                scope, len(event.get("Attribute", [])), len(event.get("Object", [])),
            )
            event_files[f"{FEED_DIR}/{uuid}.json"] = json.dumps(
                {"Event": event}, indent=2, ensure_ascii=False
            )
            manifest[uuid] = build_manifest_entry(event)
            hashes_lines.extend(build_hashes_lines(event))
            fetched += 1
        except Exception as e:
            log.warning("[%s] export %s a échoué : %s", scope, uuid, e)
            failed += 1

    if not event_files:
        raise RuntimeError("Aucun event MISP n'a pu être exporté — abandon.")

    manifest_json = json.dumps(manifest, indent=2, ensure_ascii=False)
    hashes_csv = "\n".join(hashes_lines) + "\n"

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%MZ")
    commit_msg = f"chore(misp): refresh feed ({fetched} events) [{ts}]"

    for path, content in event_files.items():
        gh_put_file(path, content, commit_msg)
    gh_put_file(f"{FEED_DIR}/manifest.json", manifest_json, commit_msg)
    gh_put_file(f"{FEED_DIR}/hashes.csv",    hashes_csv,    commit_msg)

    log.info("Done. %d events exportés, %d échecs.", fetched, failed)


if __name__ == "__main__":
    main()
