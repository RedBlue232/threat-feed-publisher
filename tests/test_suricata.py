"""Client Splunk : construction de la requête SPL et parsing des résultats."""
import pytest

import suricata


def test_spl_contient_index_et_fenetre():
    spl = suricata.build_spl("suricata_block", "13h", None)
    assert "index=suricata_block" in spl and "earliest=-13h" in spl


@pytest.mark.parametrize("index", ["a;b", "a|delete", "a b", "a'b", ""])
def test_index_invalide_rejete(index):
    """Anti-injection SPL : l'index est interpolé, il doit être strictement validé."""
    with pytest.raises(ValueError):
        suricata.build_spl(index, "13h", None)


@pytest.mark.parametrize("lookback", ["13z", "abc", "13", "-13h", ""])
def test_lookback_invalide_rejete(lookback):
    with pytest.raises(ValueError):
        suricata.build_spl("suricata_block", lookback, None)


def test_filtre_de_priorite():
    assert "tonumber(priority)<=2" in suricata.build_spl("suricata_block", "13h", 2)
    assert "tonumber(priority)" not in suricata.build_spl("suricata_block", "13h", None)


def _row(**kw):
    base = {"blocked_ip": "45.146.164.110", "event_time": "2026-06-18T10:00:00Z",
            "sid": "2021076", "signature": "ET HUNTING X ", "priority": "2"}
    base.update(kw)
    return base


def test_parse_row_nominal():
    ev = suricata.parse_blocked_row(_row())
    assert ev["ip"] == "45.146.164.110"
    assert ev["scenario"] == "suricata/ET HUNTING X"   # espace final nettoyé
    assert ev["sid"] == 2021076 and ev["priority"] == 2
    assert ev["source"] == "suricata"


@pytest.mark.parametrize("champ,valeur", [
    ("blocked_ip", "192.168.1.1"),   # non globale
    ("blocked_ip", "pas-une-ip"),
    ("blocked_ip", ""),
    ("event_time", ""),
])
def test_parse_row_rejette_les_lignes_inexploitables(champ, valeur):
    assert suricata.parse_blocked_row(_row(**{champ: valeur})) is None


def test_parse_row_tolere_sid_et_priorite_illisibles():
    ev = suricata.parse_blocked_row(_row(sid="abc", priority=None))
    assert ev is not None and ev["sid"] is None and ev["priority"] is None


def test_payload_extrait_uniquement_si_http_complet():
    assert suricata._row_to_payload({"http_method": "GET", "http_url": "/a"}) == "GET /a"
    assert suricata._row_to_payload({"http_method": "GET", "http_url": ""}) is None
    assert suricata._row_to_payload({}) is None
