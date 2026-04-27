#!/usr/bin/env python3
"""Valide la fraîcheur et la forme des feeds (3 scopes : all / crowdsec /
suricata) + le format Feed MISP.

Schéma v2 multi-source : les items peuvent porter un champ optionnel
`sources` (liste) et des scénarios préfixés `<source>/…`.

Architecture v3 (split par source) : trois jeux de feeds publiés en
parallèle, un par scope. Le scope `all` est l'union, les autres sont
filtrés par source observée.
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

# Sources connues. Toute source non listée → warning (pas erreur) :
# permet l'ajout d'une 3e source future sans rebuilder le validator.
KNOWN_SOURCES = {"crowdsec", "suricata"}

# Scopes des feeds publiés. Doit rester aligné avec FEED_SCOPES dans feed.py.
FEED_SCOPES = ("all", "crowdsec", "suricata")

# Un scénario valide est préfixé par une source : "<source>/<nom>".
SCENARIO_RE = re.compile(r"^[a-zA-Z0-9_\-]+/.+$")

errors: list[str] = []
warnings: list[str] = []

# ---------------------------------------------------------------------------
# Feeds publics (3 scopes)
# ---------------------------------------------------------------------------

def _validate_feed_files(scope: str) -> dict | None:
    """Vérifie présence + format des 4 fichiers d'un scope. Retourne le JSON
    parsé si tout va bien (utile pour validations cross-scope), None sinon."""
    prefix = f"feed-{scope}-7d"
    expected = [f"{prefix}.txt", f"{prefix}_v4.txt", f"{prefix}_v6.txt", f"{prefix}.json"]

    # 1. Présence
    missing = [f for f in expected if not (FEEDS_DIR / f).exists()]
    for f in missing:
        errors.append(f"Fichier manquant : feeds/{f}")
    if missing:
        return None

    # 2. TXT : une IP/CIDR par ligne (idem pour v4 et v6 spécifiques)
    for txt_name in (f"{prefix}.txt", f"{prefix}_v4.txt", f"{prefix}_v6.txt"):
        for i, line in enumerate((FEEDS_DIR / txt_name).read_text().splitlines(), 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if not IP_RE.match(line.split("/")[0]):
                errors.append(f"Ligne invalide dans {txt_name}:{i} → {line!r}")

    # 3. JSON enrichi
    json_path = FEEDS_DIR / f"{prefix}.json"
    try:
        data = json.loads(json_path.read_text())
    except Exception as e:
        errors.append(f"{prefix}.json invalide : {e}")
        return None

    for required in ("items", "generated_at", "scope", "counts"):
        if required not in data:
            errors.append(f"{prefix}.json : champ manquant {required!r}")
    if data.get("scope") != scope:
        errors.append(
            f"{prefix}.json : champ `scope` = {data.get('scope')!r}, attendu {scope!r}"
        )

    for idx, item in enumerate(data.get("items", []), 1):
        scenarios = item.get("scenarios", [])
        if not isinstance(scenarios, list):
            errors.append(f"{prefix}.json items[{idx}].scenarios doit être une liste")
            continue
        for sc in scenarios:
            if not isinstance(sc, str) or not SCENARIO_RE.match(sc):
                errors.append(f"{prefix}.json items[{idx}].scenarios: mal formé {sc!r}")

        srcs = item.get("sources", [])
        if "sources" in item:
            if not isinstance(srcs, list) or not all(isinstance(s, str) for s in srcs):
                errors.append(f"{prefix}.json items[{idx}].sources : doit être une liste de strings")
            else:
                for s in srcs:
                    if s not in KNOWN_SOURCES:
                        warnings.append(f"{prefix}.json items[{idx}].sources : source inconnue {s!r}")

        # Cohérence scope ↔ sources : un item dans `crowdsec` doit avoir
        # `crowdsec` dans ses sources, idem pour suricata. `all` accepte tout.
        if scope != "all" and srcs and scope not in srcs:
            errors.append(
                f"{prefix}.json items[{idx}] : IP {item.get('ip')!r} sans la source "
                f"{scope!r} dans son champ `sources` ({srcs!r}) — mauvais filtrage"
            )

    return data


feed_data: dict[str, dict] = {}
for scope in FEED_SCOPES:
    parsed = _validate_feed_files(scope)
    if parsed is not None:
        feed_data[scope] = parsed

# Cross-scope : `all` doit être l'union des autres (au pire en compte d'IPs).
if {"all", "crowdsec", "suricata"} <= feed_data.keys():
    ips_all = {it["ip"] for it in feed_data["all"]["items"]}
    ips_union = (
        {it["ip"] for it in feed_data["crowdsec"]["items"]}
        | {it["ip"] for it in feed_data["suricata"]["items"]}
    )
    if ips_all != ips_union:
        only_in_all   = sorted(ips_all - ips_union)
        only_in_union = sorted(ips_union - ips_all)
        msg = (
            f"feed-all-7d.json incohérent avec l'union des scopes : "
            f"+{len(only_in_all)} dans `all` seul ({only_in_all[:3]}...), "
            f"+{len(only_in_union)} dans union seul ({only_in_union[:3]}...)"
        )
        errors.append(msg)

# Fraîcheur globale via state/status.json
status_path = STATE_DIR / "status.json"
if not status_path.exists():
    errors.append("Fichier manquant : state/status.json")
else:
    status = json.loads(status_path.read_text())
    try:
        updated_at = datetime.fromisoformat(status["updated_at"].replace("Z", "+00:00"))
        age = datetime.now(timezone.utc) - updated_at
        if age > timedelta(hours=MAX_AGE_HOURS):
            errors.append(f"Feed trop ancien : {age} (max {MAX_AGE_HOURS}h)")
    except (KeyError, ValueError) as e:
        errors.append(f"state/status.json : updated_at illisible ({e})")

    # Cohérence des comptes par feed dans status.json
    feeds_counts = status.get("feeds", {})
    for scope in FEED_SCOPES:
        if scope not in feeds_counts:
            warnings.append(f"state/status.json : `feeds.{scope}` manquant")
            continue
        if scope in feed_data:
            expected_total = feed_data[scope]["counts"].get("total")
            actual_total = feeds_counts[scope].get("total")
            if expected_total != actual_total:
                errors.append(
                    f"status.json feeds.{scope}.total ({actual_total}) ≠ "
                    f"feed-{scope}-7d.json counts.total ({expected_total})"
                )

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
