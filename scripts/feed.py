#!/usr/bin/env python3
"""
CrowdSec Feed Publisher
- Collecte les alertes CrowdSec via LAPI (auth watcher)
- Maintient un TTL glissant de 7 jours basé sur last_seen
- Publie les feeds TXT + JSON sur GitHub
- Pousse les IOCs vers MISP via PyMISP
"""

import os
import json
import base64
import logging
import sys
from datetime import datetime, timezone

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
# 2. Fetch alertes
# ---------------------------------------------------------------------------

def fetch_alerts(token: str) -> list:
    url = f"{LAPI_BASE}/alerts"
    params = {"since": LOOKBACK, "limit": 0}
    headers = {"Authorization": f"Bearer {token}"}
    log.info("Fetch alertes → %s (since=%s)", url, LOOKBACK)
    resp = requests.get(url, params=params, headers=headers, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    alerts = data if isinstance(data, list) else data.get("alerts", [])
    log.info("%d alertes reçues", len(alerts))
    return alerts


# ---------------------------------------------------------------------------
# 3. Normaliser
# ---------------------------------------------------------------------------

def normalize_alerts(alerts: list) -> list:
    events = []
    for a in alerts:
        if a.get("simulated"):
            continue
        src = a.get("source") or {}
        ip = src.get("ip") or (src.get("value") if src.get("scope") == "ip" else None)
        if not ip:
            continue
        event_time = a.get("created_at") or a.get("stop_at") or a.get("start_at") or now_iso()
        events.append({
            "ip":          ip,
            "family":      ip_family(ip),
            "event_time":  event_time,
            "scenario":    a.get("scenario") or "unknown",
            "alert_id":    a.get("id"),
            "alert_uuid":  a.get("uuid"),
            "machine_id":  a.get("machine_id"),
        })
    log.info("%d événements normalisés (IPs extraites)", len(events))
    return events


# ---------------------------------------------------------------------------
# 4. GitHub
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
# 5. Fusion + TTL glissant 7 jours
# ---------------------------------------------------------------------------

def merge_and_ttl(events: list, db: dict) -> dict:
    ttl_ms = TTL_DAYS * 24 * 3600 * 1000
    now_ms = datetime.now(timezone.utc).timestamp() * 1000

    for ev in events:
        ip       = ev["ip"]
        t_ms     = datetime.fromisoformat(
            ev["event_time"].replace("Z", "+00:00")
        ).timestamp() * 1000
        scenario = ev["scenario"]

        if ip not in db["items"]:
            db["items"][ip] = {
                "ip":              ip,
                "family":          ev["family"],
                "first_seen":      ev["event_time"],
                "last_seen":       ev["event_time"],
                "scenarios":       {},
                "last_alert_id":   ev["alert_id"],
                "last_alert_uuid": ev["alert_uuid"],
                "machines":        [ev["machine_id"]] if ev["machine_id"] else [],
            }
        else:
            r = db["items"][ip]
            first_ms = datetime.fromisoformat(r["first_seen"].replace("Z", "+00:00")).timestamp() * 1000
            last_ms  = datetime.fromisoformat(r["last_seen"].replace("Z", "+00:00")).timestamp() * 1000
            if t_ms < first_ms:
                r["first_seen"] = ev["event_time"]
            if t_ms > last_ms:
                r["last_seen"]       = ev["event_time"]
                r["last_alert_id"]   = ev["alert_id"]
                r["last_alert_uuid"] = ev["alert_uuid"]
            if ev["machine_id"] and ev["machine_id"] not in r["machines"]:
                r["machines"].append(ev["machine_id"])

        r = db["items"][ip]
        if scenario not in r["scenarios"]:
            r["scenarios"][scenario] = {"count": 0, "last_seen": r["last_seen"]}
        r["scenarios"][scenario]["count"] += 1
        r["scenarios"][scenario]["last_seen"] = r["last_seen"]

    # Purge TTL
    to_delete = [
        ip for ip, r in db["items"].items()
        if (now_ms - datetime.fromisoformat(r["last_seen"].replace("Z", "+00:00")).timestamp() * 1000) > ttl_ms
    ]
    for ip in to_delete:
        del db["items"][ip]

    log.info("DB après fusion : %d IPs (%d purgées)", len(db["items"]), len(to_delete))
    db["updated_at"] = now_iso()
    return db


# ---------------------------------------------------------------------------
# 6. Générer les fichiers de sortie
# ---------------------------------------------------------------------------

def round_to_hour(iso: str) -> str:
    """Arrondit un timestamp ISO à l'heure — réduit la granularité des observations."""
    return iso[:13] + ":00:00Z"


def generate_outputs(db: dict) -> dict:
    records = list(db["items"].values())
    ips_all = sorted(r["ip"] for r in records)
    ips_v4  = sorted(r["ip"] for r in records if r["family"] == "v4")
    ips_v6  = sorted(r["ip"] for r in records if r["family"] == "v6")

    # Feed public : métadonnées internes retirées (machines, alert_id/uuid),
    # timestamps arrondis à l'heure, scénarios sans compteurs.
    public_items = [
        {
            "ip":         r["ip"],
            "family":     r["family"],
            "first_seen": round_to_hour(r["first_seen"]),
            "last_seen":  round_to_hour(r["last_seen"]),
            "scenarios":  list(r["scenarios"].keys()),
        }
        for r in records
    ]

    feed_json = {
        "generated_at": round_to_hour(db["updated_at"]),
        "ttl_days":     TTL_DAYS,
        "counts":       {"total": len(ips_all), "v4": len(ips_v4), "v6": len(ips_v6)},
        "items":        public_items,
    }

    # status.json : pas de lookback ni cadence (ne révèle pas le rythme d'ingestion)
    status = {
        "updated_at": round_to_hour(db["updated_at"]),
        "ttl_days":   TTL_DAYS,
        "counts":     feed_json["counts"],
    }

    return {
        "state/db.json":            json.dumps(db, indent=2),
        "state/status.json":        json.dumps(status, indent=2),
        "feeds/crowdsec_7d.txt":    "\n".join(ips_all) + "\n",
        "feeds/crowdsec_7d_v4.txt": "\n".join(ips_v4)  + "\n",
        "feeds/crowdsec_7d_v6.txt": "\n".join(ips_v6)  + "\n",
        "feeds/crowdsec_7d.json":   json.dumps(feed_json, indent=2),
    }


# ---------------------------------------------------------------------------
# 7. Publier sur GitHub
# ---------------------------------------------------------------------------

def publish_github(outputs: dict):
    for path, content in outputs.items():
        existing = gh_get_file(path)
        sha = existing["sha"] if existing else None
        gh_put_file(
            path=path,
            content=content,
            message=f"chore: update {path} [crowdsec-feed]",
            sha=sha,
        )


# ---------------------------------------------------------------------------
# Helpers MISP
# ---------------------------------------------------------------------------

def iso_to_dt(iso: str) -> datetime:
    return datetime.fromisoformat(iso.replace("Z", "+00:00"))

def build_misp_comment(record: dict) -> str:
    scenarios = ", ".join(sorted(record["scenarios"].keys()))
    total_hits = sum(v.get("count", 0) for v in record["scenarios"].values())
    return (
        f"CrowdSec | "
        f"first_seen: {record['first_seen']} | "
        f"last_seen: {record['last_seen']} | "
        f"hits: {total_hits} | "
        f"scenarios: {scenarios}"
    )

def aggregate_run_events(events: list) -> dict:
    """
    Agrège les événements du run courant par IP.
    Retient le timestamp le plus récent, les scénarios et machines vus.
    """
    by_ip = {}
    for ev in events:
        ip = ev["ip"]
        ev_dt = iso_to_dt(ev["event_time"])
        if ip not in by_ip:
            by_ip[ip] = {"last_seen_dt": ev_dt, "scenarios": set(), "machines": set()}
        else:
            if ev_dt > by_ip[ip]["last_seen_dt"]:
                by_ip[ip]["last_seen_dt"] = ev_dt
        if ev.get("scenario"):
            by_ip[ip]["scenarios"].add(ev["scenario"])
        if ev.get("machine_id"):
            by_ip[ip]["machines"].add(ev["machine_id"])
    return by_ip


# ---------------------------------------------------------------------------
# 8. Push MISP via PyMISP
#
# Stratégie : un seul événement MISP "rolling" identifié par MISP_EVENT_TAG.
# À chaque run :
#   - L'événement est créé s'il n'existe pas, sinon réutilisé
#   - Les IPs absentes de la DB (TTL expiré) ne sont PAS supprimées ici
#     → leur gestion est laissée à MISP (decay, manual review)
#   - Les nouvelles IPs sont ajoutées
#   - Les IPs existantes ont leur commentaire mis à jour
#   - Un sighting est ajouté uniquement pour les IPs vues dans CE run
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
        event.info            = "CrowdSec rolling feed (7 jours)"
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
            source = "crowdsec:" + ",".join(sorted(obs["machines"])) if obs["machines"] else "crowdsec-feed"
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
# Main
# ---------------------------------------------------------------------------

def main():
    log.info("=== CrowdSec Feed Publisher démarré ===")

    # 1. Auth CrowdSec
    token = lapi_login()

    # 2. Fetch alertes
    alerts = fetch_alerts(token)

    # 3. Normaliser
    events = normalize_alerts(alerts)

    # 4. Charger la DB existante depuis GitHub
    existing_db = gh_get_file("state/db.json")
    if existing_db:
        db = json.loads(existing_db["content"])
        log.info("DB existante chargée (%d IPs)", len(db.get("items", {})))
    else:
        db = {"schema_version": "1", "ttl_days": TTL_DAYS, "updated_at": now_iso(), "items": {}}
        log.info("Première exécution — DB initialisée")

    # 5. Fusion + TTL
    db = merge_and_ttl(events, db)

    # 6. Générer les fichiers
    outputs = generate_outputs(db)

    # 7. Publier sur GitHub
    publish_github(outputs)

    # 8. Push MISP
    push_misp(db, events)

    log.info("=== Terminé — %d IPs publiées ===", len(db["items"]))


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        log.error("ERREUR FATALE : %s", e, exc_info=True)
        sys.exit(1)