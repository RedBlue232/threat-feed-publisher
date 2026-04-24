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
from typing import Iterable

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


# ---------------------------------------------------------------------------
# Payload enrichment via l'index eve (suricata_eve)
#
# L'index eve contient les events JSON structurés (event_type=alert), avec
# entre autres http.http_method, http.url, http.http_user_agent et
# payload_printable. On se sert de ces champs pour enrichir les IPs du feed
# avec un aperçu du payload observé — utile pour distinguer un scanner
# générique d'une exploitation ciblée.
#
# IMPORTANT : le payload brut peut contenir des PII (IP interne, nom d'hôte
# privé, voire du contenu binaire). Cette fonction n'applique PAS la
# sanitization : elle retourne la donnée brute, c'est au caller d'appeler
# sanitize.sanitize_and_truncate() avant publication.
#
# Modélisation IPs : on matche `src_ip IN (...)`. Les alertes outbound
# (src_ip interne → dest_ip attaquant) sont rares côté feed puisque les IPs
# privées sont de toute façon filtrées par is_publishable_ip. Si besoin on
# ajoutera un matching sur dest_ip plus tard.
# ---------------------------------------------------------------------------

# Nombre d'IPs max par requête Splunk (clause IN). Au-delà, on scinde.
_EVE_BATCH_IPS = 500

# Nombre max d'events renvoyés par batch (head). Pour dizaines d'IPs actives
# on veut ~10 events par IP en moyenne, soit 5000 events/batch.
_EVE_HEAD = 5000


def _build_eve_spl(index: str, lookback: str, ips: list[str]) -> str:
    """Construit la SPL de lookup payload pour un batch d'IPs.

    Les IPs sont pré-validées par le caller (`fetch_eve_payloads`). On les
    quote systématiquement pour Splunk — aucun caractère hors [0-9a-fA-F:.]
    ne peut passer après validation `ipaddress`.
    """
    if not _INDEX_RE.match(index):
        raise ValueError(f"SPLUNK_INDEX_EVE invalide: {index!r}")
    if not _LOOKBACK_RE.match(lookback):
        raise ValueError(f"SPLUNK_LOOKBACK invalide: {lookback!r}")

    ip_list = ",".join(f'"{ip}"' for ip in ips)
    return (
        f"search index={index} earliest=-{lookback} event_type=alert "
        f"| search src_ip IN ({ip_list}) "
        # Splunk auto-extrait les champs JSON avec des `.` ; on renomme pour
        # ne pas avoir de clés pointées côté client. On ne ramène QUE les
        # champs HTTP — pas `payload_printable`, qui contient des octets
        # bruts pour les alertes non-HTTP (IKE, DNS, TLS…).
        f'| rename "http.http_method" AS http_method, "http.url" AS http_url '
        f"| table src_ip, http_method, http_url "
        f"| head {_EVE_HEAD}"
    )


def _row_to_payload(row: dict) -> str | None:
    """Extrait un payload lisible d'une row eve. Retourne None si rien.

    On n'exporte un payload QUE si Suricata a réussi à parser du HTTP
    (http_method ET http_url présents). Le fallback sur `payload_printable`
    était dangereux : pour les alertes non-HTTP (IKE, DNS, TLS, SSH…),
    payload_printable est peuplé avec des octets bruts du paquet qui ne sont
    pas lisibles en texte et polluent le feed public. Si on veut enrichir
    d'autres protocoles plus tard, ça se fera via des extracteurs dédiés
    par protocole (`dns.rrname`, `tls.sni`…), pas via le payload brut.
    """
    method = (row.get("http_method") or "").strip()
    url    = (row.get("http_url") or "").strip()
    if method and url:
        return f"{method} {url}"
    return None


def fetch_eve_payloads(
    url: str,
    token: str,
    index: str,
    lookback: str,
    ips: Iterable[str],
    verify_ssl: bool = True,
) -> dict[str, list[str]]:
    """Récupère pour chaque IP donnée la liste des payloads HTTP observés
    dans l'index eve, dédupliqués (ordre d'apparition conservé).

    Retourne un dict `{ip: [payload_str, ...]}`. Best-effort : toute erreur
    réseau/Splunk lève (le caller doit gérer try/except).

    NB : pas de sanitization ici, c'est une responsabilité du caller.
    """
    if not url or not token:
        return {}

    # Validation stricte des IPs avant injection SPL — double ceinture avec
    # la validation déjà faite à l'ingestion block.
    validated: list[str] = []
    for ip in ips:
        try:
            ipaddress.ip_address(ip)
            validated.append(ip)
        except (TypeError, ValueError):
            continue
    if not validated:
        return {}

    log.info(
        "[suricata-eve] lookup payloads pour %d IPs (index=%s, lookback=%s)",
        len(validated), index, lookback,
    )

    raw: dict[str, list[str]] = {}
    for i in range(0, len(validated), _EVE_BATCH_IPS):
        chunk = validated[i:i + _EVE_BATCH_IPS]
        spl = _build_eve_spl(index, lookback, chunk)
        rows = splunk_search_export(url, token, spl, verify_ssl)
        for row in rows:
            src = (row.get("src_ip") or "").strip()
            if not src:
                continue
            payload = _row_to_payload(row)
            if payload is None:
                continue
            raw.setdefault(src, []).append(payload)
        log.info(
            "[suricata-eve] batch %d-%d : %d events répartis sur %d IPs",
            i, i + len(chunk), sum(len(v) for v in raw.values()), len(raw),
        )

    # Dédup tout en gardant l'ordre d'apparition
    out: dict[str, list[str]] = {}
    for ip, items in raw.items():
        seen: set[str] = set()
        unique: list[str] = []
        for p in items:
            if p not in seen:
                seen.add(p)
                unique.append(p)
        out[ip] = unique

    log.info("[suricata-eve] %d IPs enrichies sur %d demandées", len(out), len(validated))
    return out
