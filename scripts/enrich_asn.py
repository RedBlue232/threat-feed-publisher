#!/usr/bin/env python3
"""
Enrichissement ASN via l'API publique CIRCL IP-ASN-History.

API : https://bgpranking-ng.circl.lu/ipasn_history/mass_query
- Pas d'auth, pas de rate limit documenté
- POST avec body = liste de dicts [{"ip": "1.2.3.4"}, ...]
- Réponse observée (le schéma réel diffère de la doc upstream) :
      {
        "meta":      {"number_queries": N},
        "responses": [{
            "meta":     {"ip": "1.2.3.4"},
            "response": {"<timestamp>": {"asn": "15169", "prefix": "8.8.8.0/24"},
                         "<timestamp2>": {}},
            "error":    "..."   (optionnel)
        }, ...]
      }
- Placeholder "non résolu" : asn == "0" avec prefix "0.0.0.0/0" → à filtrer.
- Un timestamp peut être vide ({}), il faut redescendre sur le précédent.

Best-effort : tout échec (timeout, 5xx, JSON malformé) est loggué et l'IP
reste sans ASN — jamais bloquant. Le résultat est mémorisé dans la DB
(record["asn"]) pour ne pas re-questionner CIRCL à chaque run de 12h.

Optimisations :
- Batch envoyé en une seule requête (jusqu'à plusieurs centaines d'IPs).
- Si une IP a déjà `record["asn"]`, on ne la ré-interroge pas. L'ASN d'une
  /24 peut changer (très rare), au pire on garde un ASN obsolète jusqu'à
  purge TTL de l'IP — acceptable pour notre cas.
"""

import os
import logging
from datetime import datetime, timedelta, timezone
from typing import Iterable

import requests

log = logging.getLogger(__name__)

CIRCL_URL = os.environ.get(
    "CIRCL_ASN_URL",
    "https://bgpranking-ng.circl.lu/ipasn_history/mass_query",
)
CIRCL_TIMEOUT = float(os.environ.get("CIRCL_ASN_TIMEOUT", "30"))

# RIPE Stat : résolution ASN → nom du holder (GOOGLE, CLOUDFLARENET, ...).
# HTTPS sans auth, rate-limit large côté RIPE. On cache dans la DB pour
# amortir les appels entre runs.
RIPE_STAT_URL = os.environ.get(
    "RIPE_STAT_URL",
    "https://stat.ripe.net/data/as-overview/data.json",
)
RIPE_STAT_TIMEOUT = float(os.environ.get("RIPE_STAT_TIMEOUT", "10"))

# Au-delà, on découpe en batches pour éviter timeouts/payload trop gros côté serveur.
BATCH_SIZE = int(os.environ.get("CIRCL_ASN_BATCH_SIZE", "500"))

# Décalage (en jours) de la date de requête. CIRCL peut avoir des snapshots
# vides / asn="0" pour la date du jour (base pas encore remplie). L'ASN d'une
# IP ne change presque jamais à court terme, donc interroger "il y a N jours"
# garantit d'avoir une donnée et ne sacrifie pas la précision.
DATE_OFFSET_DAYS = int(os.environ.get("CIRCL_ASN_DATE_OFFSET_DAYS", "3"))


def _query_date() -> str:
    """YYYY-MM-DD de la date effective de requête (UTC, décalée)."""
    d = datetime.now(timezone.utc) - timedelta(days=DATE_OFFSET_DAYS)
    return d.strftime("%Y-%m-%d")


def _is_valid_asn(item: dict) -> bool:
    """Un item CIRCL est exploitable ssi il a un asn != "0". CIRCL utilise
    asn="0" + prefix="0.0.0.0/0" comme placeholder pour "non résolu à cette
    date" — ce n'est pas une vraie réponse."""
    asn = item.get("asn")
    if not asn:
        return False
    if str(asn) == "0":
        return False
    return True


def _parse_entry(entry: dict) -> tuple[str, dict] | None:
    """Convertit une entrée de réponse CIRCL en (ip, {asn, prefix}).
    Retourne None si aucune donnée exploitable.

    Itère les timestamps du plus récent au plus ancien et prend le premier
    snapshot avec un asn valide (CIRCL peut avoir des snapshots vides ou
    placeholder "0" pour les dates récentes où la base n'est pas encore à jour)."""
    meta = entry.get("meta") or {}
    ip = meta.get("ip")
    if not ip:
        return None
    if entry.get("error"):
        log.debug("CIRCL ASN error pour %s : %s", ip, entry["error"])
        return None

    response = entry.get("response") or {}
    if not response:
        return None

    # Parcours du plus récent au plus ancien
    for ts in sorted(response.keys(), reverse=True):
        item = response.get(ts) or {}
        if _is_valid_asn(item):
            out = {"asn": str(item["asn"])}
            if item.get("prefix") and item["prefix"] != "0.0.0.0/0":
                out["prefix"] = item["prefix"]
            return ip, out

    return None


def _post_batch(ips: list[str]) -> dict[str, dict]:
    """Envoie un batch à CIRCL et retourne {ip: {asn, prefix}} parsés."""
    date = _query_date()
    payload = [{"ip": ip, "date": date} for ip in ips]
    try:
        r = requests.post(CIRCL_URL, json=payload, timeout=CIRCL_TIMEOUT)
        r.raise_for_status()
        data = r.json()
    except requests.exceptions.RequestException as e:
        log.warning("CIRCL ASN batch failed (network/HTTP) : %s", e)
        return {}
    except ValueError as e:
        log.warning("CIRCL ASN batch failed (JSON malformé) : %s", e)
        return {}

    # Schéma observé : {"meta": {...}, "responses": [...]}. La doc upstream dit
    # "liste au top level" mais l'API réelle enveloppe. On gère les 2 cas.
    if isinstance(data, dict):
        entries = data.get("responses")
        if not isinstance(entries, list):
            log.warning("CIRCL ASN : dict sans clé 'responses' (keys=%r)", list(data.keys()))
            return {}
    elif isinstance(data, list):
        entries = data
    else:
        log.warning("CIRCL ASN : réponse inattendue (type=%r)", type(data).__name__)
        return {}

    out = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        parsed = _parse_entry(entry)
        if parsed:
            ip, info = parsed
            out[ip] = info
    return out


def enrich_batch(ips: Iterable[str]) -> dict[str, dict]:
    """Best-effort batch lookup. Retourne {ip: {"asn": ..., "prefix": ...}}
    pour les IPs résolues. Les IPs non résolues sont absentes du dict."""
    ips = sorted(set(ip for ip in ips if ip))
    if not ips:
        return {}

    date = _query_date()
    log.info("CIRCL ASN : %d IPs à résoudre (date=%s, batch=%d)",
             len(ips), date, BATCH_SIZE)
    out = {}
    for i in range(0, len(ips), BATCH_SIZE):
        chunk = ips[i:i + BATCH_SIZE]
        batch_out = _post_batch(chunk)
        out.update(batch_out)
        log.info("CIRCL ASN batch %d-%d : %d/%d IPs résolues",
                 i, i + len(chunk), len(batch_out), len(chunk))
    return out


# ---------------------------------------------------------------------------
# Résolution ASN → nom (RIPE Stat)
#
# Format typique de la réponse :
#   {
#     "status": "ok",
#     "data": {
#       "holder":   "GOOGLE",
#       "resource": "15169",
#       ...
#     }
#   }
# Best-effort : tout échec est loggué, l'ASN reste sans nom.
# ---------------------------------------------------------------------------

def _fetch_asn_name(asn: str) -> str | None:
    """Retourne le holder name de l'ASN via RIPE Stat, ou None si échec."""
    try:
        r = requests.get(
            RIPE_STAT_URL,
            params={"resource": f"AS{asn}"},
            timeout=RIPE_STAT_TIMEOUT,
        )
        r.raise_for_status()
        data = r.json()
    except (requests.exceptions.RequestException, ValueError) as e:
        log.debug("RIPE Stat AS%s : échec (%s)", asn, e)
        return None

    if not isinstance(data, dict):
        return None
    holder = (data.get("data") or {}).get("holder")
    if not holder or not isinstance(holder, str):
        return None
    # Les holders RIPE sont souvent de la forme "GOOGLE - Google LLC, US".
    # On garde la chaîne complète (requêtable côté MISP, lisible dans le JSON).
    return holder.strip()


def enrich_names(asns: Iterable[str], known: dict | None = None) -> dict[str, str]:
    """Pour chaque ASN fourni, retourne {asn: name}. Les ASN déjà présents
    dans `known` sont ignorés (cache côté caller). Best-effort : un ASN non
    résolu est absent du résultat."""
    known = known or {}
    todo = sorted(set(a for a in asns if a and a not in known and a != "0"))
    if not todo:
        return {}

    log.info("RIPE Stat : %d ASN à nommer", len(todo))
    out = {}
    for asn in todo:
        name = _fetch_asn_name(asn)
        if name:
            out[asn] = name
    log.info("RIPE Stat : %d/%d ASN nommés", len(out), len(todo))
    return out


__all__ = ["enrich_batch", "enrich_names", "CIRCL_URL", "RIPE_STAT_URL"]
