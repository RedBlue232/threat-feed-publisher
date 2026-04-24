#!/usr/bin/env python3
"""
Sanitization PII pour les payloads publiés.

Un payload HTTP (URL, méthode, corps) capté par CrowdSec ou Suricata peut
contenir des indices sur l'infrastructure cible : IP de destination, nom
d'hôte, sous-domaine privé. Ces éléments sont utiles aux défenseurs locaux
mais ne doivent pas se retrouver dans un feed public.

Ce module applique des substitutions regex avant publication :
- IPs de la liste `PII_IPS`          → remplacées par `[REDACTED_IP]`
- Domaines de la liste `PII_DOMAINS` → remplacés par `[REDACTED_DOMAIN]`

Syntaxe des domaines :
- `example.com`      : match exact (apex uniquement)
- `*.example.com`    : match apex + tous les sous-domaines (foo.example.com,
                       bar.foo.example.com, example.com)

Les matchings de domaines sont protégés contre les faux positifs évidents :
- `notsalledarcade.fr` ne matche PAS `salledarcade.fr` (bordure de label)

En revanche un lookalike du type `salledarcade.fr.evil.com` est redacté
(résultat : `[REDACTED_DOMAIN].evil.com`). C'est volontaire : si un
attaquant forge un domaine qui imite le nôtre, on préfère sur-redacter que
laisser fuiter la racine publique.

Config via env (comma-separated) :
- PII_IPS         : liste d'IPs à occulter (ex: "82.67.159.52,10.42.0.1")
- PII_DOMAINS     : liste de domaines (ex: "*.salledarcade.fr,example.com")
- PAYLOAD_MAX_LEN : longueur max après sanitization (défaut 512)

Invariants :
- `sanitize("")` retourne `""`
- `sanitize(s)` sur une string sans match retourne `s` inchangé
- La sanitization est idempotente : `sanitize(sanitize(s)) == sanitize(s)`
- L'ordre appliqué est domaines puis IPs (les domaines peuvent contenir des
  IPs, ex. `sni=192.168.1.1.xip.io`, on veut redact le domaine en entier)
"""

from __future__ import annotations

import logging
import os
import re

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

PAYLOAD_MAX_LEN = int(os.environ.get("PAYLOAD_MAX_LEN", "512"))

_REDACTED_IP     = "[REDACTED_IP]"
_REDACTED_DOMAIN = "[REDACTED_DOMAIN]"


def _parse_env_list(name: str) -> list[str]:
    raw = os.environ.get(name, "")
    return [x.strip() for x in raw.split(",") if x.strip()]


PII_IPS     = _parse_env_list("PII_IPS")
PII_DOMAINS = _parse_env_list("PII_DOMAINS")


# ---------------------------------------------------------------------------
# Compilation des patterns
# ---------------------------------------------------------------------------

def _compile_ip_pattern(ip: str) -> re.Pattern:
    """Regex qui matche `ip` sans déborder sur un octet voisin.

    Exemple : `10.0.0.1` ne doit pas matcher dans `10.0.0.12` ni `110.0.0.1`.
    On encadre par des classes négatives sur `[0-9.]` — IPv4-focus. Pour
    IPv6 on utilise `[0-9a-fA-F:]` comme classe de bordure.
    """
    escaped = re.escape(ip.strip())
    if ":" in ip:
        # IPv6
        boundary = r"[0-9a-fA-F:]"
    else:
        boundary = r"[0-9.]"
    return re.compile(rf"(?<!{boundary}){escaped}(?!{boundary})")


def _compile_domain_pattern(pattern: str) -> re.Pattern:
    """Regex qui matche `pattern` en tant que FQDN.

    - `example.com`    : matche exactement `example.com` (pas `foo.example.com`
                         ni `notexample.com`).
    - `*.example.com`  : matche apex (`example.com`) ET tous les sous-domaines
                         (`foo.example.com`, `a.b.example.com`).

    Les bordures (?<!…) / (?!…) évitent les chevauchements avec des labels
    adjacents. On autorise `_` dans les labels (cas des SRV records etc.).
    """
    pattern = pattern.strip().lower()
    if pattern.startswith("*."):
        base = pattern[2:]
        escaped = re.escape(base)
        # Prefixe optionnel : suite de labels séparés par '.'
        regex = (
            r"(?<![A-Za-z0-9._\-])"
            rf"(?:[A-Za-z0-9_\-]+\.)*{escaped}"
            r"(?![A-Za-z0-9\-])"
        )
    else:
        escaped = re.escape(pattern)
        regex = (
            r"(?<![A-Za-z0-9._\-])"
            rf"{escaped}"
            r"(?![A-Za-z0-9._\-])"
        )
    return re.compile(regex, re.IGNORECASE)


# Cache lazy : on compile au premier appel, permet aux tests de changer
# l'env avant l'import.
_ip_patterns: list[re.Pattern] | None = None
_domain_patterns: list[re.Pattern] | None = None


def _get_patterns() -> tuple[list[re.Pattern], list[re.Pattern]]:
    global _ip_patterns, _domain_patterns
    if _ip_patterns is None:
        _ip_patterns     = [_compile_ip_pattern(ip) for ip in PII_IPS]
        _domain_patterns = [_compile_domain_pattern(d) for d in PII_DOMAINS]
        log.info(
            "[sanitize] config: %d IPs, %d domaines, max_len=%d",
            len(_ip_patterns), len(_domain_patterns), PAYLOAD_MAX_LEN,
        )
    return _ip_patterns, _domain_patterns


def reload_patterns() -> None:
    """Force la recompilation — utile dans les tests quand on mute PII_IPS."""
    global _ip_patterns, _domain_patterns, PII_IPS, PII_DOMAINS
    PII_IPS     = _parse_env_list("PII_IPS")
    PII_DOMAINS = _parse_env_list("PII_DOMAINS")
    _ip_patterns = None
    _domain_patterns = None
    _get_patterns()


# ---------------------------------------------------------------------------
# API publique
# ---------------------------------------------------------------------------

def sanitize(text: str) -> str:
    """Remplace toutes les occurrences d'IPs/domaines configurés par des
    tokens typés. Idempotent."""
    if not text:
        return ""
    ip_patterns, domain_patterns = _get_patterns()
    # Domaines d'abord (peuvent englober un IP-like label)
    for p in domain_patterns:
        text = p.sub(_REDACTED_DOMAIN, text)
    for p in ip_patterns:
        text = p.sub(_REDACTED_IP, text)
    return text


def truncate(text: str, max_len: int | None = None) -> str:
    """Tronque à max_len (défaut PAYLOAD_MAX_LEN). Ajoute '…' si coupé."""
    max_len = max_len if max_len is not None else PAYLOAD_MAX_LEN
    if max_len <= 0 or len(text) <= max_len:
        return text
    if max_len == 1:
        return "…"
    return text[: max_len - 1] + "…"


def sanitize_and_truncate(text: str, max_len: int | None = None) -> str:
    """Pipeline standard : sanitize d'abord (peut faire grossir le texte
    lorsque l'IP 12 chars → token 14 chars) puis tronque."""
    return truncate(sanitize(text), max_len=max_len)


__all__ = [
    "sanitize",
    "truncate",
    "sanitize_and_truncate",
    "reload_patterns",
    "PAYLOAD_MAX_LEN",
    "PII_IPS",
    "PII_DOMAINS",
]
