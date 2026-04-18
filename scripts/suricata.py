#!/usr/bin/env python3
"""
Suricata (via Splunk) — client de récupération des IP bloquées.

Cible l'index `suricata_block` qui contient les lignes block.log générées par
le package Suricata de pfSense, au format :

    04/18/2026-10:24:31.365412  [Block Src] [**] [1:2021076:3] ET HUNTING SUSPICIOUS ... \\
        [**] [Classification: Potentially Bad Traffic] [Priority: 2] {TCP} 172.189.127.19:80

La requête SPL extrait les champs via `rex` et renvoie un résultat par ligne
de log. Chaque résultat est normalisé en event compatible avec
`feed.merge_and_ttl()`.

Sécurité :
- URL/token passés en paramètres, jamais loggués
- `index` et `lookback` strictement validés avant interpolation (pas de
  construction SPL à partir de contenu utilisateur arbitraire)
- Chaque IP extraite est validée via `ipaddress` : les IP privées, loopback,
  link-local, multicast et réservées sont rejetées (on ne publie jamais une
  IP non globale dans un feed public)
- TLS strict par défaut (verify_ssl=True)
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re

import requests

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constantes / validation
# ---------------------------------------------------------------------------

_INDEX_RE    = re.compile(r"^[A-Za-z0-9_\-]+$")
_LOOKBACK_RE = re.compile(r"^\d+[smhdwMy]$")

# Fragment SPL qui fait l'extraction regex sur le format block.log.
# Maintenu ici, pas templaté depuis une env var, pour écarter toute surface
# d'injection SPL.
_SPL_REX = (
    r'| rex field=_raw "\[Block (?<block_dir>Src|Dst)\] \[\*\*\] '
    r'\[(?<gid>\d+):(?<sid>\d+):(?<rev>\d+)\] (?<signature>[^\[]+?) \[\*\*\] '
    r'\[Classification: (?<classification>[^\]]+)\] \[Priority: (?<priority>\d+)\] '
    r'\{(?<proto>\w+)\} (?<blocked_ip>[0-9a-fA-F\.:]+):(?<blocked_port>\d+)" '
)

HTTP_TIMEOUT = 60  # secondes


# ---------------------------------------------------------------------------
# Construction de la requête SPL
# ---------------------------------------------------------------------------

def build_spl(index: str, lookback: str, min_priority: int | None) -> str:
    """Construit la SPL à exécuter. Les entrées sont pré-validées par
    `fetch_blocked_ips`, mais on re-valide ici par sécurité."""
    if not _INDEX_RE.match(index):
        raise ValueError(f"SPLUNK_INDEX_BLOCK invalide: {index!r}")
    if not _LOOKBACK_RE.match(lookback):
        raise ValueError(f"SPLUNK_LOOKBACK invalide: {lookback!r}")

    priority_filter = ""
    if min_priority is not None:
        # priority plus petite = plus sévère côté Suricata. On filtre les
        # events dont la priorité est strictement plus élevée (donc moins
        # sévères) que le seuil.
        priority_filter = f"| where tonumber(priority)<={int(min_priority)} "

    return (
        f"search index={index} earliest=-{lookback} "
        + _SPL_REX
        + "| where isnotnull(blocked_ip) "
        + priority_filter
        + '| eval event_time=strftime(_time,"%Y-%m-%dT%H:%M:%SZ") '
        + "| table event_time, blocked_ip, sid, signature, classification, priority, block_dir "
        + "| head 50000"
    )


# ---------------------------------------------------------------------------
# Appel Splunk
# ---------------------------------------------------------------------------

def splunk_search_export(url: str, token: str, spl: str, verify_ssl: bool) -> list[dict]:
    """Exécute la SPL via l'endpoint synchrone /services/search/jobs/export.

    Splunk renvoie du NDJSON : une ligne par event, chacune de la forme
    `{"preview": false, "offset": N, "result": {...}}`.
    """
    endpoint = url.rstrip("/") + "/services/search/jobs/export"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept":        "application/json",
    }
    data = {
        "search":      spl,
        "output_mode": "json",
    }

    rows: list[dict] = []
    with requests.post(
        endpoint,
        headers=headers,
        data=data,
        verify=verify_ssl,
        stream=True,
        timeout=HTTP_TIMEOUT,
    ) as resp:
        # On ne logge jamais resp.text en entier : il pourrait refléter la
        # requête, ce qui est acceptable, mais certaines erreurs Splunk
        # retournent des HTML avec des headers bavards. On se contente du code.
        if resp.status_code >= 400:
            raise RuntimeError(f"Splunk HTTP {resp.status_code} sur {endpoint}")
        for raw_line in resp.iter_lines(decode_unicode=True):
            if not raw_line:
                continue
            try:
                payload = json.loads(raw_line)
            except json.JSONDecodeError:
                log.warning("[suricata] ligne NDJSON non-parsable ignorée")
                continue
            if payload.get("preview"):
                continue
            result = payload.get("result")
            if isinstance(result, dict):
                rows.append(result)
    return rows


# ---------------------------------------------------------------------------
# Validation IP : on ne publie jamais d'IP non globale
# ---------------------------------------------------------------------------

def is_publishable_ip(ip_str: str) -> bool:
    """Vrai ssi l'IP est valide ET routable publiquement (is_global)."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return ip_obj.is_global


def _ip_family(ip_str: str) -> str:
    return "v6" if ":" in ip_str else "v4"


# ---------------------------------------------------------------------------
# Parsing d'une ligne Splunk en event normalisé
# ---------------------------------------------------------------------------

def parse_blocked_row(row: dict) -> dict | None:
    """Transforme une row Splunk en event compatible `merge_and_ttl`.

    Retourne None si la row est inexploitable (pas d'IP, IP non globale,
    champ manquant, etc.). Les rejets sont loggués en debug seulement.
    """
    blocked_ip = (row.get("blocked_ip") or "").strip()
    if not blocked_ip or not is_publishable_ip(blocked_ip):
        return None

    event_time = (row.get("event_time") or "").strip()
    if not event_time:
        return None

    signature = (row.get("signature") or "unknown").strip()
    # Nettoyage : trim espace final laissé par la regex rex
    signature = signature.rstrip()

    # sid et priority sont des strings côté Splunk ; on les convertit proprement
    sid = row.get("sid")
    try:
        sid_int = int(sid) if sid not in (None, "") else None
    except (TypeError, ValueError):
        sid_int = None

    priority = row.get("priority")
    try:
        prio_int = int(priority) if priority not in (None, "") else None
    except (TypeError, ValueError):
        prio_int = None

    return {
        "ip":         blocked_ip,
        "family":     _ip_family(blocked_ip),
        "event_time": event_time,
        "scenario":   f"suricata/{signature}",
        "source":     "suricata",
        "sid":        sid_int,
        "priority":   prio_int,
    }


# ---------------------------------------------------------------------------
# Entrée publique
# ---------------------------------------------------------------------------

def fetch_blocked_ips(
    url: str,
    token: str,
    index: str,
    lookback: str,
    verify_ssl: bool = True,
    min_priority: int | None = None,
) -> list[dict]:
    """Récupère auprès de Splunk la liste des events Suricata ayant bloqué
    une IP, sous forme d'events normalisés prêts pour `merge_and_ttl`.
    """
    if not url:
        raise ValueError("SPLUNK_URL manquant")
    if not token:
        raise ValueError("SPLUNK_TOKEN manquant")
    if not _INDEX_RE.match(index):
        raise ValueError(f"SPLUNK_INDEX_BLOCK invalide: {index!r}")
    if not _LOOKBACK_RE.match(lookback):
        raise ValueError(f"SPLUNK_LOOKBACK invalide: {lookback!r}")

    spl = build_spl(index, lookback, min_priority)
    log.info(
        "[suricata] requête Splunk (index=%s, lookback=%s, min_priority=%s, verify_ssl=%s)",
        index, lookback,
        min_priority if min_priority is not None else "-",
        verify_ssl,
    )

    rows = splunk_search_export(url, token, spl, verify_ssl)
    log.info("[suricata] %d lignes reçues de Splunk", len(rows))

    events: list[dict] = []
    rejected = 0
    for row in rows:
        ev = parse_blocked_row(row)
        if ev is None:
            rejected += 1
            continue
        events.append(ev)

    if rejected:
        log.info("[suricata] %d lignes rejetées (IP invalide / non globale / champ manquant)", rejected)
    log.info("[suricata] %d events exploitables", len(events))
    return events
