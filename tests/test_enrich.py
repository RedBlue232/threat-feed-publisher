"""Enrichissements : ASN (CIRCL + repli RIPE) et nœuds de sortie Tor.
Aucun appel réseau — les clients HTTP sont remplacés."""
import enrich_asn
import enrich_tor


def test_repli_ripe_quand_circl_ne_resout_rien(monkeypatch):
    """Les snapshots CIRCL sont indexés par date et souvent vides : sans repli,
    une IP fraîche reste sans ASN jusqu'à ce qu'un run ultérieur tombe par
    chance sur une date exploitable."""
    monkeypatch.setattr(enrich_asn, "_post_batch", lambda ips: {})
    monkeypatch.setattr(enrich_asn, "_fetch_ip_asn_ripe",
                        lambda ip: {"asn": "6939", "prefix": "184.104.0.0/15"})
    out = enrich_asn.enrich_batch(["184.105.139.67", "1.1.1.1"])
    assert out["184.105.139.67"]["asn"] == "6939"
    assert len(out) == 2


def test_circl_prioritaire_et_ripe_en_complement(monkeypatch):
    monkeypatch.setattr(enrich_asn, "_post_batch", lambda ips: {"1.1.1.1": {"asn": "13335"}})
    monkeypatch.setattr(enrich_asn, "_fetch_ip_asn_ripe", lambda ip: {"asn": "6939"})
    out = enrich_asn.enrich_batch(["1.1.1.1", "184.105.139.67"])
    assert out["1.1.1.1"]["asn"] == "13335"        # CIRCL gagne
    assert out["184.105.139.67"]["asn"] == "6939"  # RIPE complète


def test_double_echec_ne_leve_pas(monkeypatch):
    monkeypatch.setattr(enrich_asn, "_post_batch", lambda ips: {})
    monkeypatch.setattr(enrich_asn, "_fetch_ip_asn_ripe", lambda ip: None)
    assert enrich_asn.enrich_batch(["1.1.1.1"]) == {}


def test_placeholder_circl_ignore():
    """asn="0" + 0.0.0.0/0 est le marqueur « non résolu » de CIRCL."""
    assert not enrich_asn._is_valid_asn({"asn": "0", "prefix": "0.0.0.0/0"})
    assert enrich_asn._is_valid_asn({"asn": "15169"})


def test_parse_tor_exit_addresses():
    texte = (
        "ExitNode 0011BD2485AD45D984EC4159C88FC066E5E3300E\n"
        "Published 2026-04-24 10:23:17\n"
        "ExitAddress 185.220.100.240 2026-04-24 12:47:18\n"
        "ExitAddress 10.0.0.1 2026-04-24 12:47:18\n"      # non globale : rejetée
        "ExitAddress pas-une-ip 2026-04-24 12:47:18\n"
    )
    exits = enrich_tor._parse_exit_addresses(texte)
    assert exits == {"185.220.100.240"}


def test_enrich_tor_tague_uniquement_les_exit_nodes(monkeypatch):
    monkeypatch.setattr(enrich_tor, "_CACHED_EXITS", {"185.220.100.240"})
    monkeypatch.setattr(enrich_tor, "_CACHE_ATTEMPTED", True)
    assert enrich_tor.enrich("185.220.100.240") == ["tor:exit-node"]
    assert enrich_tor.enrich("8.8.8.8") == []
