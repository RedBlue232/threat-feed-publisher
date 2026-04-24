#!/usr/bin/env python3
"""
Enrichissement par misp-warninglists : annote chaque IP avec des tags
correspondant aux listes publiques où elle apparaît (scanners, cloud, CDN).

Le repo MISP/misp-warninglists est embarqué au build Docker dans /app/warninglists.
Chaque dossier de `lists/` contient un `list.json` au format :

    {
      "name": "...",
      "type": "cidr" | "string" | ...,
      "matching_attributes": ["ip-src", ...],
      "list": ["1.2.3.0/24", "5.6.7.0/24", ...]
    }

Convention des tags posés : `mwl:<category>="<source>"` (mwl = misp-warninglist).
Ex: `mwl:scanner="censys"`, `mwl:cloud="aws"`, `mwl:cdn="cloudflare"`.

Mode dégradé : si le dossier warninglists n'existe pas (dev local sans Docker),
load_warninglists() loggue un warning et enrich() devient un no-op.
"""

import os
import json
import logging
import ipaddress
from pathlib import Path

log = logging.getLogger(__name__)

# Racine des warninglists embarquée par le Dockerfile.
WARNINGLISTS_ROOT = Path(os.environ.get(
    "WARNINGLISTS_ROOT", "/app/warninglists/lists"
))

# Mapping dossier → (category, source_slug). Liste blanche stricte : seuls les
# dossiers listés ici sont chargés. Les dossiers absents sur disque sont
# silencieusement ignorés (robuste aux renommages/suppressions upstream).
#
# Plusieurs dossiers peuvent partager la même (category, source) : les tags
# émis sont dédupliqués. Permet de couvrir les variants `*-nt-scanning`.
LISTS: dict[str, tuple[str, str]] = {
    # --- Scanners ---
    "censys-scanning":             ("scanner", "censys"),
    "shodan-scanning":             ("scanner", "shodan"),
    "shodan-nt-scanning":          ("scanner", "shodan"),
    "shadowserver":                ("scanner", "shadowserver"),
    "shadowserver-nt-scanning":    ("scanner", "shadowserver"),
    "internet-census-nt-scanning": ("scanner", "internet-census"),
    "onyphe-scanner":              ("scanner", "onyphe"),
    "modat-scanner":               ("scanner", "modat"),
    "rapid7-nt-scanning":          ("scanner", "rapid7"),
    "intrinsec-nt-scanning":       ("scanner", "intrinsec"),
    "ipinfo-nt-scanning":          ("scanner", "ipinfo"),
    # --- Cloud ---
    "amazon-aws":                  ("cloud", "aws"),
    "microsoft-azure":             ("cloud", "azure"),
    "microsoft-azure-china":       ("cloud", "azure"),
    "microsoft-azure-germany":     ("cloud", "azure"),
    "microsoft-azure-us-gov":      ("cloud", "azure"),
    "google-gcp":                  ("cloud", "gcp"),
    # --- CDN ---
    "cloudflare":                  ("cdn", "cloudflare"),
    "akamai":                      ("cdn", "akamai"),
    "fastly":                      ("cdn", "fastly"),
    # --- Tor (alimenté par 2.2bis depuis source externe) ---
    "tor-exit-addresses":          ("tor", "exit-node"),
}


def _format_tag(category: str, source: str) -> str:
    """Format canonique : mwl:scanner=\"censys\"."""
    return f'mwl:{category}="{source}"'


def _load_one_list(list_dir: Path, category: str, source: str) -> tuple[list, list, str]:
    """Charge un list.json et retourne (cidrs_v4, cidrs_v6, type) avec les
    CIDR précompilés. Ignore les `type` non supportés.

    Pour `type: string` on essaie de parser chaque entrée comme une IP/CIDR
    (cas Tor, où la liste est `["1.2.3.4", ...]` mais `type` peut varier)."""
    path = list_dir / "list.json"
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    list_type = data.get("type", "")
    if list_type not in ("cidr", "string"):
        log.warning("warninglists/%s : type=%r non supporté, skip", list_dir.name, list_type)
        return [], [], list_type

    v4, v6 = [], []
    bad = 0
    for entry in data.get("list", []):
        try:
            net = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            bad += 1
            continue
        (v4 if net.version == 4 else v6).append(net)

    if bad:
        log.debug("warninglists/%s : %d entrées non-IP ignorées", list_dir.name, bad)

    return v4, v6, list_type


# Cache module-level. Structure :
#   {"v4": [(network, tag), ...], "v6": [(network, tag), ...]}
# Trié par network pour bisect potentiel ultérieur ; on reste sur scan O(n)
# pour l'instant (volumes faibles).
_cache: dict | None = None


def load_warninglists() -> int:
    """Charge en mémoire toutes les warninglists déclarées dans LISTS.
    Retourne le nombre total de réseaux indexés. Idempotent."""
    global _cache
    if _cache is not None:
        return len(_cache["v4"]) + len(_cache["v6"])

    if not WARNINGLISTS_ROOT.exists():
        log.warning(
            "WARNINGLISTS_ROOT introuvable (%s) — enrichment désactivé. "
            "Build Docker requis pour activer cette feature.",
            WARNINGLISTS_ROOT,
        )
        _cache = {"v4": [], "v6": []}
        return 0

    v4_indexed: list[tuple] = []
    v6_indexed: list[tuple] = []
    loaded_dirs = 0
    skipped_dirs = 0

    for dirname, (category, source) in LISTS.items():
        list_dir = WARNINGLISTS_ROOT / dirname
        if not list_dir.is_dir():
            skipped_dirs += 1
            continue
        try:
            v4, v6, _ = _load_one_list(list_dir, category, source)
        except Exception as e:
            log.warning("warninglists/%s : échec de chargement (%s) — skip", dirname, e)
            skipped_dirs += 1
            continue

        tag = _format_tag(category, source)
        v4_indexed.extend((net, tag) for net in v4)
        v6_indexed.extend((net, tag) for net in v6)
        loaded_dirs += 1
        log.debug("warninglists/%s : %d v4 + %d v6 (tag=%s)",
                  dirname, len(v4), len(v6), tag)

    _cache = {"v4": v4_indexed, "v6": v6_indexed}
    log.info(
        "Warninglists chargées : %d listes OK (%d ignorées), %d réseaux v4, %d réseaux v6",
        loaded_dirs, skipped_dirs, len(v4_indexed), len(v6_indexed),
    )
    return len(v4_indexed) + len(v6_indexed)


def enrich(ip: str) -> list[str]:
    """Retourne la liste dédupliquée et triée des tags applicables à `ip`.
    Empty list si aucune warninglist ne match ou si le module est en mode
    dégradé (root absente)."""
    if _cache is None:
        load_warninglists()
    assert _cache is not None  # mypy

    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return []

    pool = _cache["v4"] if addr.version == 4 else _cache["v6"]
    matched = {tag for net, tag in pool if addr in net}
    return sorted(matched)


__all__ = ["load_warninglists", "enrich", "LISTS", "WARNINGLISTS_ROOT"]
