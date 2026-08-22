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
import hashlib
import logging
import sys
from datetime import datetime, timezone

import github_publish
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

GH_HEADERS = github_publish.build_headers(GH_TOKEN)
GH_SESSION = github_publish.make_session()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger(__name__)


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
    # Contrairement à feed.py, l'échec n'est pas rendu tolérable ici : exporter
    # l'event MISP EST la seule raison d'être de ce script, sans connexion il n'y
    # a rien à publier. On remplace en revanche le traceback PyMISP brut par un
    # message actionnable — c'est ce silence illisible qui a laissé misp-feed/
    # figé deux mois sans que la cause saute aux yeux.
    try:
        misp = PyMISP(MISP_URL, MISP_KEY, MISP_VERIFY_SSL)
    except Exception as e:
        raise RuntimeError(
            f"connexion à MISP impossible ({e}) — vérifier MISP_URL/MISP_KEY et "
            "que la clé appartient à un utilisateur dont le rôle a l'accès API activé"
        ) from e

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

    # Un event et son manifeste n'ont de sens qu'ensemble : ils sont publiés en
    # un commit unique. Auparavant chaque fichier faisait son propre commit, ce
    # qui exposait un manifeste référençant un event pas encore écrit — et
    # provoquait des collisions avec feed.py lancé au même moment.
    fichiers = dict(event_files)
    fichiers[f"{FEED_DIR}/manifest.json"] = manifest_json
    fichiers[f"{FEED_DIR}/hashes.csv"] = hashes_csv

    sha = github_publish.publish_atomic(
        GH_SESSION, GH_HEADERS, GH_OWNER, GH_REPO, GH_BRANCH, fichiers, commit_msg
    )
    if sha is None:
        log.info("GitHub ✓ contenu inchangé — aucun commit créé")
    else:
        log.info("GitHub ✓ %d fichiers publiés en 1 commit (%s)", len(fichiers), sha[:7])

    log.info("Done. %d events exportés, %d échecs.", fetched, failed)


if __name__ == "__main__":
    # Même contrat que feed.py : une ligne d'erreur lisible dans `docker logs`
    # plutôt qu'un traceback, et un code de sortie non nul (rien n'a été exporté).
    try:
        main()
    except Exception as e:
        log.error("ERREUR FATALE : %s", e)
        sys.exit(1)
