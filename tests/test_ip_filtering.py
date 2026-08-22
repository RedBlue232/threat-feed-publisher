"""Filtrage des IPs publiables — le garde-fou qui empêche une IP interne
d'atterrir dans un feed public."""
import pytest

import feed
import suricata


@pytest.mark.parametrize("ip", ["8.8.8.8", "45.146.164.110", "2606:4700:4700::1111"])
def test_ip_globale_publiable(ip):
    assert feed.is_publishable_ip(ip)


@pytest.mark.parametrize("ip", [
    "10.0.0.1", "192.168.1.10", "172.16.0.1",   # privées
    "127.0.0.1",                                 # loopback
    "169.254.1.1",                               # link-local
    "203.0.113.99",                              # TEST-NET-3
    "fc00::1",                                   # ULA v6
    "pas-une-ip", "", "1.2.3.4.5",
])
def test_ip_non_publiable(ip):
    assert not feed.is_publishable_ip(ip)


@pytest.mark.parametrize("ip", ["9.9.9.9", "1.0.0.1"])
def test_ip_explicitement_exclue(ip):
    """PUBLISH_EXCLUDE_IPS (posé par conftest) l'emporte sur is_global.
    L'espace après la virgule doit être ignoré."""
    assert not feed.is_publishable_ip(ip)


def _alerte(ip):
    return {"source": {"ip": ip}, "created_at": "2026-07-01T00:00:00Z",
            "scenario": "crowdsecurity/http-probing", "id": 1, "uuid": "u",
            "machine_id": "host"}


def test_normalize_alerts_ecarte_les_non_publiables():
    events = feed.normalize_alerts(
        [_alerte("8.8.8.8"), _alerte("192.168.1.10"), _alerte("9.9.9.9"), _alerte("77.88.99.11")]
    )
    assert {e["ip"] for e in events} == {"8.8.8.8", "77.88.99.11"}


def test_normalize_alerts_ignore_les_simulees():
    a = _alerte("8.8.8.8"); a["simulated"] = True
    assert feed.normalize_alerts([a]) == []


def test_normalize_alerts_prefixe_le_scenario_par_la_source():
    assert feed.normalize_alerts([_alerte("8.8.8.8")])[0]["scenario"] == "crowdsec/http-probing"


def test_suricata_applique_le_meme_filtre():
    assert suricata.is_publishable_ip("8.8.8.8")
    assert not suricata.is_publishable_ip("10.0.0.1")
    assert not suricata.is_publishable_ip("nope")
