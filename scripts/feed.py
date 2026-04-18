#!/usr/bin/env python3
"""
Threat Feed Publisher
- Collecte les alertes depuis plusieurs sources (CrowdSec LAPI, Suricata via Splunk)
- Maintient un TTL glissant (default 7 jours) basé sur last_seen
- Publie les feeds TXT + JSON sur GitHub
- Pousse les IOCs vers MISP via PyMISP (optionnel)

Schéma interne v2 : chaque IP porte un dict `sources` qui discrimine l'origine
de l'observation (crowdsec, suricata, ...). Une migration automatique est
appliquée à la première lecture d'un state/db.json au schéma v1.
"""

import os
import json
import base64
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests

# PyMISP est optionnel : si non installé ou MISP non configuré, on skip silencieusement
try:
    from pymisp import PyMISP, MISPEvent, MISPAttribute
    PYMISP_AVAILABLE = True
except ImportError:
    PYMISP_AVAILABLE = False

# ---------------------------------------------------------------------------
# Configuration (depuis les variables d'environnement / .env)
# ---------------------------------------------------------------------------
LAPI_BASE      = os.environ["LAPI_BASE"]
CS_MACHINE_ID  = os.environ["CS_MACHINE_ID"]
CS_PASSWORD    = os.environ["CS_PASSWORD"]
LOOKBACK       = os.environ.get("LOOKBACK", "13h")

GH_TOKEN       = os.environ["GH_TOKEN"]
GH_OWNER       = os.environ["GH_OWNER"]
GH_REPO        = os.environ["GH_REPO"]
GH_BRANCH      = os.environ.get("GH_BRANCH", "main")

TTL_DAYS       = int(os.environ.get("TTL_DAYS", "7"))

# MISP — optionnels, le push est skippé si absents
MISP_URL        = os.environ.get("MISP_URL", "")
MISP_KEY        = os.environ.get("MISP_KEY", "")
MISP_VERIFY_SSL = os.environ.get("MISP_VERIFY_SSL", "false").lower() == "true"

# Tag utilisé pour retrouver l'événement MISP entre les runs
MISP_EVENT_TAG  = "crowdsec-feed"

# Suricata via Splunk — optionnels, désactivés par défaut
SURICATA_ENABLED      = os.environ.get("SURICATA_ENABLED", "false").lower() == "true"
SPLUNK_URL            = os.environ.get("SPLUNK_URL", "")
SPLUNK_TOKEN          = os.environ.get("SPLUNK_TOKEN", "")
SPLUNK_INDEX_BLOCK    = os.environ.get("SPLUNK_INDEX_BLOCK", "suricata_block")
SPLUNK_LOOKBACK       = os.environ.get("SPLUNK_LOOKBACK", "13h")
SPLUNK_VERIFY_SSL     = os.environ.get("SPLUNK_VERIFY_SSL", "true").lower() == "true"
_min_prio_raw         = os.environ.get("SURICATA_MIN_PRIORITY", "").strip()
SURICATA_MIN_PRIORITY = int(_min_prio_raw) if _min_prio_raw else None

# Flags de debug / test — jamais publiés dans env.example (documentés dans le README)
DRY_RUN        = os.environ.get("DRY_RUN", "false").lower() == "true"
MIGRATE_ONLY   = os.environ.get("MIGRATE_ONLY", "false").lower() == "true"
CROWDSEC_ONLY  = os.environ.get("CROWDSEC_ONLY", "false").lower() == "true"
SURICATA_ONLY  = os.environ.get("SURICATA_ONLY", "false").lower() == "true"
DRY_RUN_DIR    = Path(os.environ.get("DRY_RUN_DIR", "/tmp/feed-output"))

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

def ip_family(ip: str) -> str:
    return "v6" if ":" in ip else "v4"

def iso_to_dt(iso: str) -> datetime:
    return datetime.fromisoformat(iso.replace("Z", "+00:00"))

def iso_to_ms(iso: str) -> float:
    return iso_to_dt(iso).timestamp() * 1000


# ---------------------------------------------------------------------------
# 1. Auth LAPI
# ---------------------------------------------------------------------------

def lapi_login() -> str:
    url = f"{LAPI_BASE}/watchers/login"
    log.info("Auth LAPI → %s", url)
    resp = requests.post(
        url,
        json={"machine_id": CS_MACHINE_ID, "password": CS_PASSWORD},
        timeout=15,
    )
    resp.raise_for_status()
    token = resp.json().get("token")
    if not token:
        raise ValueError(f"Pas de token dans la réponse : {resp.text}")
    log.info("Token JWT obtenu ✓")
    return token


# ---------------------------------------------------------------------------
# 2. Fetch alertes CrowdSec
# ---------------------------------------------------------------------------

def fetch_alerts(token: str) -> list:
    url = f"{LAPI_BASE}/alerts"
    params = {"since": LOOKBACK, "limit": 0}
    headers = {"Authorization": f"Bearer {token}"}
    log.info("Fetch alertes CrowdSec → %s (since=%s)", url, LOOKBACK)
    resp = requests.get(url, params=params, headers=headers, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    alerts = data if isinstance(data, list) else data.get("alerts", [])
    log.info("%d alertes CrowdSec reçues", len(alerts))
    return alerts


# ---------------------------------------------------------------------------
# 3. Normalisation des alertes CrowdSec
#
# Produit des events au format commun :
#   {ip, family, event_time, scenario (préfixé "crowdsec/"), source="crowdsec",
#    alert_id, alert_uuid, machine_id}
# ---------------------------------------------------------------------------

def normalize_alerts(alerts: list, source: str = "crowdsec") -> list:
    events = []
    for a in alerts:
        if a.get("simulated"):
            continue
        src = a.get("source") or {}
        ip = src.get("ip") or (src.get("value") if src.get("scope") == "ip" else None)
        if not ip:
            continue
        event_time = a.get("created_at") or a.get("stop_at") or a.get("start_at") or now_iso()
        raw_scenario = a.get("scenario") or "unknown"
        # Normalise le préfixe : "crowdsecurity/xxx" ou "xxx" → "<source>/xxx"
        if "/" in raw_scenario:
            _, _, tail = raw_scenario.partition("/")
            scenario = f"{source}/{tail}"
        else:
            scenario = f"{source}/{raw_scenario}"
        events.append({
            "ip":          ip,
            "family":      ip_family(ip),
            "event_time":  event_time,
            "scenario":    scenario,
            "source":      source,
            "alert_id":    a.get("id"),
            "alert_uuid":  a.get("uuid"),
            "machine_id":  a.get("machine_id"),
        })
    log.info("%d events %s normalisés", len(events), source)
    return events


# ---------------------------------------------------------------------------
# 4. GitHub (lecture toujours ; écriture désactivée en DRY_RUN)
# ---------------------------------------------------------------------------

GH_API = "https://api.github.com"
GH_HEADERS = {
    "Authorization": f"Bearer {GH_TOKEN}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}

def gh_get_file(path: str) -> dict | None:
    url = f"{GH_API}/repos/{GH_OWNER}/{GH_REPO}/contents/{path}"
    resp = requests.get(url, headers=GH_HEADERS, params={"ref": GH_BRANCH}, timeout=15)
    if resp.status_code == 404:
        return None
    resp.raise_for_status()
    data = resp.json()
    content = base64.b64decode(data["content"]).decode("utf-8")
    return {"content": content, "sha": data["sha"]}


def gh_put_file(path: str, content: str, message: str, sha: str | None = None):
    url = f"{GH_API}/repos/{GH_OWNER}/{GH_REPO}/contents/{path}"
    body = {
        "message": message,
        "content": base64.b64encode(content.encode("utf-8")).decode("ascii"),
        "branch": GH_BRANCH,
    }
    if sha:
        body["sha"] = sha
    resp = requests.put(url, headers=GH_HEADERS, json=body, timeout=30)
    resp.raise_for_status()
    log.info("GitHub ✓ %s", path)


# ---------------------------------------------------------------------------
# 5. Migration schéma v1 → v2
#
# v1 (CrowdSec-only) :
#   {ip, family, first_seen, last_seen, scenarios{"crowdsecurity/…":{count,last_seen}},
#    last_alert_id, last_alert_uuid, machines[]}
#
# v2 (multi-source) :
#   {ip, family, first_seen, last_seen,
#    scenarios{"crowdsec/…":{count,last_seen}},
#    sources{crowdsec:{count, first_seen, last_seen, machines[],
#                      last_alert_id, last_alert_uuid}}}
#
# Idempotent : si schema_version=="2" ou si tous les items ont déjà `sources`,
# aucune modification n'est effectuée.
# ---------------------------------------------------------------------------

def migrate_db_schema(db: dict) -> dict:
    if db.get("schema_version") == "2":
        return db

    migrated = 0
    items = db.get("items", {})
    for ip, item in items.items():
        if "sources" in item:
            # Déjà migré (cas hybride après un run partiel)
            continue

        # Préfixe des scénarios : crowdsecurity/xxx → crowdsec/xxx
        new_scenarios = {}
        total_count = 0
        for k, v in item.get("scenarios", {}).items():
            if k.startswith("crowdsecurity/"):
                new_key = "crowdsec/" + k[len("crowdsecurity/"):]
            elif "/" not in k:
                new_key = f"crowdsec/{k}"
            else:
                new_key = k
            new_scenarios[new_key] = v
            total_count += v.get("count", 0)
        item["scenarios"] = new_scenarios

        # Construction du bloc sources.crowdsec
        crowdsec_src = {
            "count":      total_count,
            "first_seen": item["first_seen"],
            "last_seen":  item["last_seen"],
            "machines":   item.pop("machines", []) or [],
        }
        if "last_alert_id" in item:
            crowdsec_src["last_alert_id"] = item.pop("last_alert_id")
        if "last_alert_uuid" in item:
            crowdsec_src["last_alert_uuid"] = item.pop("last_alert_uuid")

        item["sources"] = {"crowdsec": crowdsec_src}
        migrated += 1

    db["schema_version"] = "2"
    if migrated:
        log.info("[migration] %d IPs migrées vers le schéma v2", migrated)
    else:
        log.info("[migration] schéma déjà v2, aucune migration nécessaire")
    return db


# ---------------------------------------------------------------------------
# 6. Fusion + TTL glissant
#
# La clé de dédup reste l'IP. Les champs de niveau top (first_seen/last_seen)
# reflètent l'observation la plus ancienne / la plus récente toutes sources
# confondues. Les métadonnées par source vivent dans sources.<name>.
# ---------------------------------------------------------------------------

def _update_source_block(src_block: dict, ev: dict, t_ms: float) -> None:
    """Met à jour un bloc sources.<name> avec un event normalisé."""
    src_block["count"] += 1

    if t_ms < iso_to_ms(src_block["first_seen"]):
        src_block["first_seen"] = ev["event_time"]
    is_newer = t_ms >= iso_to_ms(src_block["last_seen"])
    if is_newer:
        src_block["last_seen"] = ev["event_time"]

    if ev["source"] == "crowdsec":
        if ev.get("machine_id"):
            machines = src_block.setdefault("machines", [])
            if ev["machine_id"] not in machines:
                machines.append(ev["machine_id"])
        if is_newer and ev.get("alert_id") is not None:
            src_block["last_alert_id"]   = ev["alert_id"]
            src_block["last_alert_uuid"] = ev["alert_uuid"]
    elif ev["source"] == "suricata":
        if ev.get("sid") is not None:
            sids = src_block.setdefault("sids", [])
            if ev["sid"] not in sids:
                sids.append(ev["sid"])
        if ev.get("priority") is not None:
            # Priority Suricata : plus petit = plus sévère. On retient la plus
            # sévère observée sur cette IP (min).
            current = src_block.get("max_priority")
            if current is None or ev["priority"] < current:
                src_block["max_priority"] = ev["priority"]


def merge_and_ttl(events: list, db: dict) -> dict:
    ttl_ms = TTL_DAYS * 24 * 3600 * 1000
    now_ms = datetime.now(timezone.utc).timestamp() * 1000

    for ev in events:
        ip       = ev["ip"]
        t_ms     = iso_to_ms(ev["event_time"])
        scenario = ev["scenario"]
        source   = ev["source"]

        # Création de l'entrée IP si besoin
        if ip not in db["items"]:
            db["items"][ip] = {
                "ip":         ip,
                "family":     ev["family"],
                "first_seen": ev["event_time"],
                "last_seen":  ev["event_time"],
                "scenarios":  {},
                "sources":    {},
            }
        r = db["items"][ip]

        # Maj first/last_seen globaux
        if t_ms < iso_to_ms(r["first_seen"]):
            r["first_seen"] = ev["event_time"]
        if t_ms > iso_to_ms(r["last_seen"]):
            r["last_seen"] = ev["event_time"]

        # Maj du bloc sources.<name>
        if source not in r["sources"]:
            r["sources"][source] = {
                "count":      0,
                "first_seen": ev["event_time"],
                "last_seen":  ev["event_time"],
            }
            if source == "crowdsec":
                r["sources"][source]["machines"] = []
        _update_source_block(r["sources"][source], ev, t_ms)

        # Maj du scénario
        if scenario not in r["scenarios"]:
            r["scenarios"][scenario] = {"count": 0, "last_seen": ev["event_time"]}
        sc = r["scenarios"][scenario]
        sc["count"] += 1
        if t_ms > iso_to_ms(sc["last_seen"]):
            sc["last_seen"] = ev["event_time"]

    # Purge TTL (basée sur last_seen global)
    to_delete = [
        ip for ip, r in db["items"].items()
        if (now_ms - iso_to_ms(r["last_seen"])) > ttl_ms
    ]
    for ip in to_delete:
        del db["items"][ip]

    log.info("DB après fusion : %d IPs (%d purgées)", len(db["items"]), len(to_delete))
    db["updated_at"] = now_iso()
    return db


# ---------------------------------------------------------------------------
# 7. Générer les fichiers de sortie
# ---------------------------------------------------------------------------

def round_to_hour(iso: str) -> str:
    """Arrondit un timestamp ISO à l'heure — réduit la granularité des observations."""
    return iso[:13] + ":00:00Z"


def _sanitize_db_for_publish(db: dict) -> dict:
    """Retourne une copie du DB privée des champs internes qu'on ne veut pas
    exposer publiquement sur GitHub. Aujourd'hui : `machines` dans chaque
    `sources.<name>` (nom de la machine CrowdSec → potentiellement sensible).

    Le DB en mémoire reste intact pour le run courant ; seul le fichier
    sérialisé `state/db.json` poussé sur GitHub est assaini. Conséquence :
    `machines` ne persiste pas entre runs (repopulé à chaque fetch à partir
    des alertes fraîches), ce qui est acceptable puisque l'info n'est pas
    utilisée en logique cross-run.
    """
    import copy
    pub = copy.deepcopy(db)
    for item in pub.get("items", {}).values():
        for src_block in item.get("sources", {}).values():
            src_block.pop("machines", None)
    return pub


def generate_outputs(db: dict) -> dict:
    records = list(db["items"].values())
    ips_all = sorted(r["ip"] for r in records)
    ips_v4  = sorted(r["ip"] for r in records if r["family"] == "v4")
    ips_v6  = sorted(r["ip"] for r in records if r["family"] == "v6")

    # Feed public : métadonnées internes retirées (machines, sids, alert_id…),
    # timestamps arrondis à l'heure, scénarios sans compteurs, sources nommées.
    public_items = []
    for r in records:
        item = {
            "ip":         r["ip"],
            "family":     r["family"],
            "first_seen": round_to_hour(r["first_seen"]),
            "last_seen":  round_to_hour(r["last_seen"]),
            "scenarios":  sorted(r["scenarios"].keys()),
        }
        sources = sorted(r.get("sources", {}).keys())
        if sources:
            item["sources"] = sources
        public_items.append(item)

    feed_json = {
        "generated_at": round_to_hour(db["updated_at"]),
        "ttl_days":     TTL_DAYS,
        "counts":       {"total": len(ips_all), "v4": len(ips_v4), "v6": len(ips_v6)},
        "items":        public_items,
    }

    # Décompte par source (utile au monitoring CI)
    source_counts = {}
    for r in records:
        for s in r.get("sources", {}):
            source_counts[s] = source_counts.get(s, 0) + 1

    status = {
        "updated_at": round_to_hour(db["updated_at"]),
        "ttl_days":   TTL_DAYS,
        "counts":     feed_json["counts"],
    }
    if source_counts:
        status["sources"] = dict(sorted(source_counts.items()))

    return {
        "state/db.json":            json.dumps(_sanitize_db_for_publish(db), indent=2),
        "state/status.json":        json.dumps(status, indent=2),
        "feeds/crowdsec_7d.txt":    "\n".join(ips_all) + "\n",
        "feeds/crowdsec_7d_v4.txt": "\n".join(ips_v4)  + "\n",
        "feeds/crowdsec_7d_v6.txt": "\n".join(ips_v6)  + "\n",
        "feeds/crowdsec_7d.json":   json.dumps(feed_json, indent=2),
    }


# ---------------------------------------------------------------------------
# 8. Publier sur GitHub (ou en local en DRY_RUN)
# ---------------------------------------------------------------------------

def publish_github(outputs: dict):
    for path, content in outputs.items():
        existing = gh_get_file(path)
        sha = existing["sha"] if existing else None
        gh_put_file(
            path=path,
            content=content,
            message=f"chore: update {path} [threat-feed]",
            sha=sha,
        )


def write_outputs_local(outputs: dict, out_dir: Path):
    out_dir = Path(out_dir)
    for path, content in outputs.items():
        target = out_dir / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
        log.info("[dry-run] écrit %s", target)


# ---------------------------------------------------------------------------
# 9. Helpers MISP
# ---------------------------------------------------------------------------

def build_misp_comment(record: dict) -> str:
    sources = sorted(record.get("sources", {}).keys())
    sources_str = ", ".join(sources) if sources else "unknown"
    scenarios = ", ".join(sorted(record["scenarios"].keys()))
    total_hits = sum(v.get("count", 0) for v in record["scenarios"].values())
    return (
        f"Sources: {sources_str} | "
        f"first_seen: {record['first_seen']} | "
        f"last_seen: {record['last_seen']} | "
        f"hits: {total_hits} | "
        f"scenarios: {scenarios}"
    )

def aggregate_run_events(events: list) -> dict:
    """
    Agrège les événements du run courant par IP.
    Retient le timestamp le plus récent, les scénarios et les sources vues
    (avec leurs machines CrowdSec le cas échéant).
    """
    by_ip = {}
    for ev in events:
        ip = ev["ip"]
        ev_dt = iso_to_dt(ev["event_time"])
        rec = by_ip.setdefault(ip, {
            "last_seen_dt": ev_dt,
            "scenarios":    set(),
            "sources":      {},
        })
        if ev_dt > rec["last_seen_dt"]:
            rec["last_seen_dt"] = ev_dt
        if ev.get("scenario"):
            rec["scenarios"].add(ev["scenario"])
        source = ev.get("source", "unknown")
        src_data = rec["sources"].setdefault(source, {"machines": set()})
        if ev.get("machine_id"):
            src_data["machines"].add(ev["machine_id"])
    return by_ip


# ---------------------------------------------------------------------------
# 10. Push MISP via PyMISP
#
# Stratégie (inchangée en phase 1) : un seul événement MISP "rolling" identifié
# par MISP_EVENT_TAG. La correction multi-source (tags source:* par attribut,
# événements séparés, etc.) est reportée à une phase ultérieure.
# ---------------------------------------------------------------------------

def push_misp(db: dict, events: list):
    if not PYMISP_AVAILABLE:
        log.warning("PyMISP non installé — push MISP ignoré")
        return
    if not MISP_URL or not MISP_KEY:
        log.info("MISP non configuré (MISP_URL/MISP_KEY absents) — push ignoré")
        return

    log.info("Connexion MISP → %s", MISP_URL)
    misp = PyMISP(MISP_URL, MISP_KEY, MISP_VERIFY_SSL)

    run_obs = aggregate_run_events(events)

    # Chercher un événement existant avec notre tag
    existing_event = None
    results = misp.search(tags=[MISP_EVENT_TAG], pythonify=True)
    if results:
        existing_event = results[0]
        log.info("Événement MISP existant trouvé (id=%s)", existing_event.id)

    if existing_event is None:
        event = MISPEvent()
        event.info            = "Threat feed (rolling)"
        event.distribution    = 0  # 0=Org only — adapte : 1=Community, 3=All
        event.threat_level_id = 3  # Low
        event.analysis        = 2  # Completed
        event.add_tag(MISP_EVENT_TAG)
        event = misp.add_event(event, pythonify=True)
        log.info("Événement MISP créé (id=%s)", event.id)
    else:
        event = misp.get_event(existing_event.id, pythonify=True)

    # Index des attributs ip-src existants par valeur IP
    existing_ip_attrs = {
        attr.value: attr
        for attr in getattr(event, "attributes", [])
        if attr.type == "ip-src"
    }

    created_count = updated_count = sightings_count = 0

    for ip, record in db["items"].items():
        comment = build_misp_comment(record)
        attr = existing_ip_attrs.get(ip)

        # 1) Nouvelle IP : créer l'attribut
        if attr is None:
            created = misp.add_attribute(
                event,
                {"type": "ip-src", "value": ip, "comment": comment,
                 "to_ids": True, "category": "Network activity"},
                pythonify=True,
                break_on_duplicate=False,
            )
            if isinstance(created, MISPAttribute):
                attr = created
                existing_ip_attrs[ip] = attr
                created_count += 1
                log.info("MISP + nouvelle IP %s", ip)
            else:
                log.warning("Impossible de créer l'attribut MISP pour %s : %s", ip, created)
                continue

        # 2) IP existante : mettre à jour le commentaire si besoin
        else:
            if (attr.comment or "") != comment:
                attr.comment = comment
                updated = misp.update_attribute(attr, pythonify=True)
                if isinstance(updated, MISPAttribute):
                    existing_ip_attrs[ip] = updated
                updated_count += 1
                log.info("MISP ~ commentaire mis à jour pour %s", ip)

        # 3) Sighting uniquement si l'IP a été vue dans ce run
        if ip in run_obs:
            obs = run_obs[ip]
            source_names = sorted(obs["sources"].keys())
            source = "+".join(source_names) if source_names else "threat-feed"
            try:
                misp.add_sighting(
                    {"type": "0", "source": source,
                     "timestamp": int(obs["last_seen_dt"].timestamp())},
                    attribute=attr,
                    pythonify=False,
                )
                sightings_count += 1
                log.info("Sighting MISP ajouté pour %s", ip)
            except Exception as e:
                log.warning("Échec sighting pour %s : %s", ip, e)

    log.info(
        "MISP ✓ sync terminée (créées=%d, mises_à_jour=%d, sightings=%d, total_db=%d)",
        created_count, updated_count, sightings_count, len(db["items"]),
    )


# ---------------------------------------------------------------------------
# 11. Fetch multi-source tolérant aux pannes
#
# Chaque source est tentée indépendamment. Un échec est loggué mais n'arrête
# le run que si *toutes* les sources tentées ont échoué (pour éviter d'écraser
# l'état avec une DB vide).
# ---------------------------------------------------------------------------

def fetch_all_events() -> list:
    events = []
    attempted = 0
    succeeded = 0

    if not SURICATA_ONLY:
        attempted += 1
        try:
            token = lapi_login()
            alerts = fetch_alerts(token)
            events.extend(normalize_alerts(alerts, source="crowdsec"))
            succeeded += 1
        except Exception as e:
            log.error("CrowdSec fetch échoué : %s", e, exc_info=True)

    if SURICATA_ENABLED and not CROWDSEC_ONLY:
        if not (SPLUNK_URL and SPLUNK_TOKEN):
            log.warning("SURICATA_ENABLED=true mais SPLUNK_URL/SPLUNK_TOKEN absents — source ignorée")
        else:
            attempted += 1
            try:
                # Import local : permet d'exécuter feed.py sans suricata.py présent
                # tant que SURICATA_ENABLED=false (backward compat).
                from suricata import fetch_blocked_ips
                sura_events = fetch_blocked_ips(
                    url=SPLUNK_URL,
                    token=SPLUNK_TOKEN,
                    index=SPLUNK_INDEX_BLOCK,
                    lookback=SPLUNK_LOOKBACK,
                    verify_ssl=SPLUNK_VERIFY_SSL,
                    min_priority=SURICATA_MIN_PRIORITY,
                )
                events.extend(sura_events)
                succeeded += 1
            except Exception as e:
                log.error("Suricata/Splunk fetch échoué : %s", e, exc_info=True)

    if attempted == 0:
        raise RuntimeError("Aucune source activée — rien à faire (check SURICATA_ONLY / CROWDSEC_ONLY).")
    if succeeded == 0:
        raise RuntimeError(f"Toutes les sources ont échoué ({attempted}/{attempted}) — arrêt pour ne pas écraser l'état.")

    log.info("Fetch terminé : %d/%d sources OK, %d events au total", succeeded, attempted, len(events))
    return events


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    log.info("=== Threat Feed Publisher démarré ===")
    if DRY_RUN:
        log.warning("DRY_RUN actif — aucune publication GitHub ni push MISP (écriture locale %s)", DRY_RUN_DIR)
    if MIGRATE_ONLY:
        log.warning("MIGRATE_ONLY actif — arrêt après migration, pas de fetch ni de publication")
    if CROWDSEC_ONLY:
        log.info("CROWDSEC_ONLY actif — source Suricata ignorée pour ce run")
    if SURICATA_ONLY:
        log.info("SURICATA_ONLY actif — source CrowdSec ignorée pour ce run")

    # 1. Charger la DB existante depuis GitHub
    existing_db = gh_get_file("state/db.json")
    if existing_db:
        db = json.loads(existing_db["content"])
        log.info("DB existante chargée (%d IPs, schema_version=%s)",
                 len(db.get("items", {})), db.get("schema_version", "?"))
    else:
        db = {"schema_version": "2", "ttl_days": TTL_DAYS, "updated_at": now_iso(), "items": {}}
        log.info("Première exécution — DB initialisée (schéma v2)")

    # 2. Migration v1 → v2 (idempotent)
    db = migrate_db_schema(db)

    # 2bis. Short-circuit MIGRATE_ONLY : on écrit la DB migrée en local et on sort
    if MIGRATE_ONLY:
        out = {"state/db.json": json.dumps(db, indent=2)}
        write_outputs_local(out, DRY_RUN_DIR)
        log.info("=== MIGRATE_ONLY terminé — %d IPs dans la DB migrée ===", len(db["items"]))
        return

    # 3. Fetch multi-source
    events = fetch_all_events()

    # 4. Fusion + TTL
    db = merge_and_ttl(events, db)

    # 5. Générer les fichiers
    outputs = generate_outputs(db)

    # 6. Publier
    if DRY_RUN:
        write_outputs_local(outputs, DRY_RUN_DIR)
    else:
        publish_github(outputs)

    # 7. Push MISP
    if DRY_RUN:
        log.info("[dry-run] push MISP ignoré")
    else:
        push_misp(db, events)

    log.info("=== Terminé — %d IPs publiées ===", len(db["items"]))


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        log.error("ERREUR FATALE : %s", e, exc_info=True)
        sys.exit(1)
