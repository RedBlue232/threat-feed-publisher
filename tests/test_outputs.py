"""Génération des fichiers publiés — test de bout en bout de la mise en forme."""
import json

import feed


def _db():
    return {
        "schema_version": "2",
        "updated_at": "2026-08-22T13:47:59+02:00",   # décalé : doit sortir en UTC
        "asn_names": {"15169": "GOOGLE", "666": "ORPHELIN"},
        "items": {
            "8.8.8.8": {
                "ip": "8.8.8.8", "family": "v4",
                "first_seen": "2026-08-20T09:15:00+02:00",
                "last_seen": "2026-08-22T13:47:59Z",
                "scenarios": {"crowdsec/http-probing": {"count": 2, "last_seen": "2026-08-22T13:47:59Z"}},
                "sources": {"crowdsec": {"count": 2, "first_seen": "2026-08-20T09:15:00+02:00",
                                         "last_seen": "2026-08-22T13:47:59Z",
                                         "machines": ["host-a"], "last_alert_id": 7,
                                         "payloads": ["GET /admin.php"]}},
                "asn": "15169", "asn_prefix": "8.8.8.0/24",
            },
            "45.146.164.110": {
                "ip": "45.146.164.110", "family": "v4",
                "first_seen": "2026-08-21T10:00:00Z", "last_seen": "2026-08-22T10:00:00Z",
                "scenarios": {"suricata/ET SCAN": {"count": 1, "last_seen": "2026-08-22T10:00:00Z"}},
                "sources": {"suricata": {"count": 1, "first_seen": "2026-08-21T10:00:00Z",
                                         "last_seen": "2026-08-22T10:00:00Z", "sids": [2021076]}},
            },
        },
    }


def test_les_quatre_fichiers_de_chaque_scope_sont_produits():
    out = feed.generate_outputs(_db())
    for scope in ("all", "crowdsec", "suricata"):
        for suffixe in (".txt", "_v4.txt", "_v6.txt", ".json"):
            assert f"feeds/feed-{scope}-7d{suffixe}" in out
    assert "state/db.json" in out and "state/status.json" in out


def test_scopes_filtres_par_source():
    out = feed.generate_outputs(_db())
    cs = json.loads(out["feeds/feed-crowdsec-7d.json"])
    su = json.loads(out["feeds/feed-suricata-7d.json"])
    assert {i["ip"] for i in cs["items"]} == {"8.8.8.8"}
    assert {i["ip"] for i in su["items"]} == {"45.146.164.110"}


def test_le_scope_all_est_l_union():
    out = feed.generate_outputs(_db())
    tous = json.loads(out["feeds/feed-all-7d.json"])
    assert {i["ip"] for i in tous["items"]} == {"8.8.8.8", "45.146.164.110"}
    assert tous["counts"]["total"] == 2


def test_horodatages_publies_en_utc_arrondis():
    out = feed.generate_outputs(_db())
    tous = json.loads(out["feeds/feed-all-7d.json"])
    item = next(i for i in tous["items"] if i["ip"] == "8.8.8.8")
    assert tous["generated_at"] == "2026-08-22T11:00:00Z"   # +02:00 converti
    assert item["first_seen"] == "2026-08-20T07:00:00Z"
    assert item["last_seen"] == "2026-08-22T13:00:00Z"


def test_le_db_publie_est_assaini():
    out = feed.generate_outputs(_db())
    bloc = json.loads(out["state/db.json"])["items"]["8.8.8.8"]["sources"]["crowdsec"]
    assert not {"machines", "last_alert_id", "last_alert_uuid"} & set(bloc)


def test_status_coherent_avec_les_feeds():
    out = feed.generate_outputs(_db())
    status = json.loads(out["state/status.json"])
    for scope in ("all", "crowdsec", "suricata"):
        attendu = json.loads(out[f"feeds/feed-{scope}-7d.json"])["counts"]["total"]
        assert status["feeds"][scope]["total"] == attendu
    assert status["sources"] == {"crowdsec": 1, "suricata": 1}


def test_payloads_et_asn_exposes():
    out = feed.generate_outputs(_db())
    item = next(i for i in json.loads(out["feeds/feed-all-7d.json"])["items"]
                if i["ip"] == "8.8.8.8")
    assert item["payloads"] == ["GET /admin.php"]
    assert item["asn"] == "15169" and item["asn_name"] == "GOOGLE"


def test_fichier_txt_une_ip_par_ligne():
    out = feed.generate_outputs(_db())
    lignes = [l for l in out["feeds/feed-all-7d.txt"].splitlines() if l]
    assert sorted(lignes) == ["45.146.164.110", "8.8.8.8"]
