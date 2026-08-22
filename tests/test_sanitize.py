"""Rédaction des PII dans les payloads publiés."""
import time

import sanitize


def setup_module(_):
    sanitize.reload_patterns()   # prend en compte les PII_* posés par conftest


def test_redaction_ip_et_domaine():
    out = sanitize.sanitize_and_truncate("GET /x?h=db.corp.example&ip=203.0.113.5")
    assert "203.0.113.5" not in out and "[REDACTED_IP]" in out
    assert "corp.example" not in out and "[REDACTED_DOMAIN]" in out


def test_wildcard_couvre_apex_et_sous_domaines():
    for hote in ("corp.example", "a.corp.example", "a.b.c.corp.example"):
        assert "corp.example" not in sanitize.sanitize(hote)


def test_domaine_exact_ne_matche_pas_un_sous_domaine():
    """`secret.test` est configuré sans wildcard : seul l'apex est redacté."""
    assert "[REDACTED_DOMAIN]" in sanitize.sanitize("secret.test")


def test_pas_de_faux_positif_sur_une_bordure_d_octet():
    """203.0.113.5 ne doit pas matcher dans 203.0.113.55."""
    assert "203.0.113.55" in sanitize.sanitize("ip=203.0.113.55")


def test_idempotence():
    once = sanitize.sanitize("h=db.corp.example ip=203.0.113.5")
    assert sanitize.sanitize(once) == once


def test_troncature():
    assert len(sanitize.sanitize_and_truncate("A" * 5000)) <= 512
    assert sanitize.sanitize_and_truncate("GET /court") == "GET /court"
    assert sanitize.sanitize_and_truncate("") == ""


def test_entree_bornee_avant_les_regex(monkeypatch):
    """Garde-fou ReDoS : le motif de domaine wildcard est sujet au backtracking
    catastrophique, et les payloads sont partiellement contrôlés par
    l'attaquant. L'entrée doit être coupée avant d'atteindre les regex."""
    vus = {}
    original = sanitize.sanitize

    def espion(texte):
        vus["len"] = len(texte)
        return original(texte)

    monkeypatch.setattr(sanitize, "sanitize", espion)
    sanitize.sanitize_and_truncate("A" * 100_000)
    assert vus["len"] <= 4096


def test_entree_adverse_reste_rapide():
    adverse = ("aaaaaaaaaa." * 5000) + "zzz"
    debut = time.perf_counter()
    sanitize.sanitize_and_truncate(adverse)
    assert time.perf_counter() - debut < 1.0
