#!/usr/bin/env python3
"""
Enrichissement Tor exit-nodes via check.torproject.org/exit-addresses.

Source : liste officielle maintenue par le projet Tor. Format texte plat,
stable depuis ~2010, une strophe par relay :

    ExitNode   0011BD2485AD45D984EC4159C88FC066E5E3300E
    Published  2026-04-24 10:23:17
    LastStatus 2026-04-24 12:00:00
    ExitAddress 185.220.100.240 2026-04-24 12:47:18

On n'extrait que les lignes `ExitAddress <ip> <timestamp>`. Un même node
peut en avoir plusieurs (dual-stack, multi-homed) ; on les prend toutes.

Stratégie runtime : fetch à chaque run de feed.py (cadence 12h). La liste
fait ~50-100 KB (env. 1000-1500 IPs), c'est négligeable. En cas d'échec
(timeout, 5xx, DNS), on retourne un set vide — les IPs déjà présentes dans
le feed ne seront simplement pas taguées `tor:exit-node` ce run-ci. Le run
suivant re-essaiera. Pas de persistance cross-run volontairement : une IP
qui quitte Tor (relay fermé) ne doit pas conserver un tag obsolète.

API :
- `load_tor_exits() -> set[str]` : fetch + parse, peuplé d'IPs globales
  valides. Idempotent, cache le résultat en mémoire pour ne pas re-fetch
  pendant un même run.
- `enrich(ip: str) -> list[str]` : retourne `["tor:exit-node"]` si l'IP est
  dans le set, `[]` sinon. Harmonisé avec enrich_warninglists.enrich.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re

import requests

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

TOR_EXIT_URL = os.environ.get(
    "TOR_EXIT_URL",
    "https://check.torproject.org/exit-addresses",
)
TOR_FETCH_TIMEOUT = float(os.environ.get("TOR_FETCH_TIMEOUT", "30"))

# Tag publié côté feed public ET côté MISP. Convention : namespace `tor:`
# suivi du type de node. Lisible et greppable, pas besoin d'une valeur.
_TOR_TAG = "tor:exit-node"


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

# Match strict : le fichier est binairement stable depuis 15 ans, pas besoin
# d'être tolérant. Un ligne mal formée est un bug upstream, pas à nous.
_EXIT_ADDRESS_RE = re.compile(r"^ExitAddress\s+(\S+)\s+\d{4}-\d{2}-\d{2}", re.MULTILINE)


def _parse_exit_addresses(text: str) -> set[str]:
    """Extrait les IPs de sortie du document officiel. Les IPs non-globales
    (link-local, privées, loopback) sont filtrées par prudence — elles ne
    devraient jamais apparaître ici, mais on préfère un feed propre plutôt
    qu'une confiance aveugle dans la source."""
    exits: set[str] = set()
    rejected = 0
    for match in _EXIT_ADDRESS_RE.finditer(text):
        candidate = match.group(1)
        try:
            ip_obj = ipaddress.ip_address(candidate)
        except ValueError:
            rejected += 1
            continue
        if not ip_obj.is_global:
            rejected += 1
            continue
        exits.add(candidate)
    if rejected:
        log.warning("[tor] %d lignes ExitAddress rejetées (IP invalide/non globale)", rejected)
    return exits


# ---------------------------------------------------------------------------
# Fetch + cache in-memory (durée du process)
# ---------------------------------------------------------------------------

_CACHED_EXITS: set[str] | None = None
_CACHE_ATTEMPTED: bool = False


def _fetch_exits() -> set[str]:
    """Fetch HTTP best-effort. Toute erreur retourne set() et logge un
    warning — jamais de levée d'exception vers l'appelant."""
    try:
        r = requests.get(
            TOR_EXIT_URL,
            timeout=TOR_FETCH_TIMEOUT,
            headers={"User-Agent": "threat-feed-publisher/1 (+github)"},
        )
        r.raise_for_status()
        text = r.text
    except requests.exceptions.RequestException as e:
        log.warning("[tor] fetch %s échoué : %s", TOR_EXIT_URL, e)
        return set()
    except Exception as e:
        log.warning("[tor] erreur inattendue au fetch : %s", e)
        return set()

    exits = _parse_exit_addresses(text)
    log.info("[tor] %d exit-nodes chargés depuis %s", len(exits), TOR_EXIT_URL)
    return exits


def load_tor_exits() -> set[str]:
    """Charge (ou retourne la version déjà chargée durant ce run) le set
    des IPs exit-nodes Tor. Appels successifs dans le même run réutilisent
    le cache — feed.py appelle une fois en début puis enrich() à la volée."""
    global _CACHED_EXITS, _CACHE_ATTEMPTED
    if _CACHE_ATTEMPTED:
        return _CACHED_EXITS or set()
    _CACHED_EXITS = _fetch_exits()
    _CACHE_ATTEMPTED = True
    return _CACHED_EXITS


def reset_cache() -> None:
    """Pour les tests — force un re-fetch au prochain load_tor_exits()."""
    global _CACHED_EXITS, _CACHE_ATTEMPTED
    _CACHED_EXITS = None
    _CACHE_ATTEMPTED = False


# ---------------------------------------------------------------------------
# API publique — harmonisée avec enrich_warninglists.enrich
# ---------------------------------------------------------------------------

def enrich(ip: str) -> list[str]:
    """Retourne ['tor:exit-node'] si l'IP est un exit-node Tor connu, [] sinon.

    NB : idempotent à l'échelle du run — load_tor_exits() mémoise le set
    après le premier appel. Si le fetch initial a échoué, toutes les
    enrich() retourneront [] (best-effort, pas de second retry)."""
    exits = load_tor_exits()
    return [_TOR_TAG] if ip in exits else []


__all__ = [
    "load_tor_exits",
    "enrich",
    "reset_cache",
    "TOR_EXIT_URL",
]
