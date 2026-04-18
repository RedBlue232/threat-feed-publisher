#!/usr/bin/env python3
"""Valide la fraîcheur et la forme des feeds CrowdSec + MISP.

Supporte le schéma v2 (multi-source) : les items peuvent porter un champ
optionnel `sources` (liste) et des scénarios préfixés `<source>/…`.
"""
import json, re, sys
from pathlib import Path
from datetime import datetime, timezone, timedelta

FEEDS_DIR = Path("feeds")
STATE_DIR = Path("state")
MISP_FEED_DIR = Path("misp-feed")
MAX_AGE_HOURS = 26  # 12h cadence + 2h marge
IP_RE = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3}$"          # IPv4
    r"|^[0-9a-fA-F:]+$"                  # IPv6 simplifié
)

# Sources connues en phase 1. Toute source non listée ici → warning (pas erreur).
KNOWN_SOURCES = {"crowdsec", "suricata"}

# Un scénario valide est soit "legacy" (crowdsecurity/…, conservé pour compat
# transitoire) soit préfixé par une source : "<source>/<nom>".
SCENARIO_RE = re.compile(r"^[a-zA-Z0-9_\-]+/.+$")

errors: list[str] = []
warnings: list[str] = []

# ---------------------------------------------------------------------------
# Feed CrowdSec
# ---------------------------------------------------------------------------

# 1. Vérifier que les fichiers existent
for f in ["crowdsec_7d.txt", "crowdsec_7d_v4.txt", "crowdsec_7d_v6.txt", "crowdsec_7d.json"]:
    if not (FEEDS_DIR / f).exists():
        errors.append(f"Fichier manquant : feeds/{f}")

# 2. Vérifier la fraîcheur via state/status.json
status_path = STATE_DIR / "status.json"
if not status_path.exists():
    errors.append("Fichier manquant : state/status.json")
else:
    status = json.loads(status_path.read_text())
    updated_at = datetime.fromisoformat(status["updated_at"].replace("Z", "+00:00"))
    age = datetime.now(timezone.utc) - updated_at
    if age > timedelta(hours=MAX_AGE_HOURS):
        errors.append(f"Feed trop ancien : {age} (max {MAX_AGE_HOURS}h)")

# 3. Vérifier le format des TXT (une IP/CIDR par ligne)
txt_path = FEEDS_DIR / "crowdsec_7d.txt"
if txt_path.exists():
    for i, line in enumerate(txt_path.read_text().splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if not IP_RE.match(line.split("/")[0]):
            errors.append(f"Ligne invalide dans crowdsec_7d.txt:{i} → {line!r}")

# 4. Vérifier le JSON enrichi
json_path = FEEDS_DIR / "crowdsec_7d.json"
if json_path.exists():
    try:
        data = json.loads(json_path.read_text())
        assert "items" in data and "generated_at" in data, "champs obligatoires manquants"

        for idx, item in enumerate(data.get("items", []), 1):
            # scénarios : liste de strings préfixées
            scenarios = item.get("scenarios", [])
            if not isinstance(scenarios, list):
                errors.append(f"items[{idx}].scenarios doit être une liste")
                continue
            for sc in scenarios:
                if not isinstance(sc, str) or not SCENARIO_RE.match(sc):
                    errors.append(f"items[{idx}].scenarios: scénario mal formé {sc!r}")

            # sources : optionnel, liste de strings
            if "sources" in item:
                srcs = item["sources"]
                if not isinstance(srcs, list) or not all(isinstance(s, str) for s in srcs):
                    errors.append(f"items[{idx}].sources doit être une liste de strings")
                else:
                    for s in srcs:
                        if s not in KNOWN_SOURCES:
                            warnings.append(f"items[{idx}].sources: source inconnue {s!r}")
    except Exception as e:
        errors.append(f"crowdsec_7d.json invalide : {e}")

# ---------------------------------------------------------------------------
# Feed MISP (optionnel — validé seulement si le dossier existe)
# ---------------------------------------------------------------------------

if MISP_FEED_DIR.exists():
    # 5. Fichiers obligatoires du format Feed MISP
    for f in ["manifest.json", "hashes.csv"]:
        if not (MISP_FEED_DIR / f).exists():
            errors.append(f"Fichier manquant : misp-feed/{f}")

    # 6. Manifest valide + cohérence avec les fichiers d'events + fraîcheur
    manifest_path = MISP_FEED_DIR / "manifest.json"
    if manifest_path.exists():
        try:
            manifest = json.loads(manifest_path.read_text())
            if not manifest:
                errors.append("misp-feed/manifest.json est vide")
            for uuid, meta in manifest.items():
                # Fichier d'event présent ?
                if not (MISP_FEED_DIR / f"{uuid}.json").exists():
                    errors.append(f"Event MISP {uuid} référencé mais fichier manquant")
                    continue
                # Event parsable + structure attendue ?
                try:
                    evt = json.loads((MISP_FEED_DIR / f"{uuid}.json").read_text())
                    if "Event" not in evt or evt["Event"].get("uuid") != uuid:
                        errors.append(f"misp-feed/{uuid}.json : structure invalide")
                except Exception as e:
                    errors.append(f"misp-feed/{uuid}.json invalide : {e}")
                # Fraîcheur du timestamp MISP (epoch stocké en string)
                try:
                    ts = datetime.fromtimestamp(int(meta["timestamp"]), tz=timezone.utc)
                    age = datetime.now(timezone.utc) - ts
                    if age > timedelta(hours=MAX_AGE_HOURS):
                        errors.append(f"Event MISP {uuid} trop ancien : {age} (max {MAX_AGE_HOURS}h)")
                except (KeyError, ValueError) as e:
                    errors.append(f"Event MISP {uuid} : timestamp illisible ({e})")
        except Exception as e:
            errors.append(f"misp-feed/manifest.json invalide : {e}")

    # 7. hashes.csv : format "<uuid>,<md5>" par ligne
    hashes_path = MISP_FEED_DIR / "hashes.csv"
    if hashes_path.exists():
        for i, line in enumerate(hashes_path.read_text().splitlines(), 1):
            line = line.strip()
            if not line:
                continue
            parts = line.split(",")
            if len(parts) != 2 or len(parts[1]) != 32:
                errors.append(f"Ligne invalide dans hashes.csv:{i} → {line!r}")

# ---------------------------------------------------------------------------
# Résultat
# ---------------------------------------------------------------------------

if warnings:
    print("Warnings :")
    for w in warnings:
        print(f"  - {w}")

if errors:
    print("Validation échouée :")
    for e in errors:
        print(f"  - {e}")
    sys.exit(1)

print("Feeds valides.")
