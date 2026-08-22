"""Entretien de la base : TTL, migration de schéma, purge du cache ASN,
et retrait des métadonnées internes avant publication."""
from datetime import datetime, timedelta, timezone

import feed


def _iso(dt):
    return dt.isoformat().replace("+00:00", "Z")


def _record(ip, seen):
    return {"ip": ip, "family": "v4", "first_seen": seen, "last_seen": seen,
            "scenarios": {},
            "sources": {"crowdsec": {"count": 1, "first_seen": seen,
                                     "last_seen": seen, "machines": []}}}


def test_ttl_purge_les_ips_expirees_et_garde_les_fraiches():
    now = datetime.now(timezone.utc)
    frais = _iso(now - timedelta(hours=1))
    perime = _iso(now - timedelta(days=feed.TTL_DAYS + 2))
    db = {"items": {"8.8.8.8": _record("8.8.8.8", frais),
                    "1.1.1.1": _record("1.1.1.1", perime)}}
    out = feed.merge_and_ttl([], db)
    assert "8.8.8.8" in out["items"]
    assert "1.1.1.1" not in out["items"]


def test_merge_purge_les_ips_devenues_non_publiables():
    """Une IP privée déjà en base (ingérée avant le filtre, ou ajoutée à
    PUBLISH_EXCLUDE_IPS après coup) doit disparaître sans attendre le TTL."""
    frais = _iso(datetime.now(timezone.utc) - timedelta(hours=1))
    db = {"items": {"10.0.0.5": _record("10.0.0.5", frais),
                    "9.9.9.9": _record("9.9.9.9", frais),
                    "8.8.4.4": _record("8.8.4.4", frais)}}
    out = feed.merge_and_ttl([], db)
    assert set(out["items"]) == {"8.8.4.4"}


def test_migration_v1_vers_v2():
    v1 = {"items": {"9.9.9.9": {
        "ip": "9.9.9.9", "family": "v4",
        "first_seen": "2026-01-01T00:00:00Z", "last_seen": "2026-01-02T00:00:00Z",
        "scenarios": {"crowdsecurity/http-probing": {"count": 2, "last_seen": "2026-01-02T00:00:00Z"}},
        "machines": ["h1"], "last_alert_id": 7, "last_alert_uuid": "abc"}}}
    out = feed.migrate_db_schema(v1)
    item = out["items"]["9.9.9.9"]
    assert out["schema_version"] == "2"
    assert "crowdsec/http-probing" in item["scenarios"]
    assert item["sources"]["crowdsec"]["machines"] == ["h1"]
    assert item["sources"]["crowdsec"]["last_alert_id"] == 7
    assert "machines" not in item


def test_migration_idempotente():
    v1 = {"items": {"9.9.9.9": {
        "ip": "9.9.9.9", "family": "v4",
        "first_seen": "2026-01-01T00:00:00Z", "last_seen": "2026-01-02T00:00:00Z",
        "scenarios": {"crowdsecurity/x": {"count": 1, "last_seen": "2026-01-02T00:00:00Z"}},
        "machines": ["h1"]}}}
    once = feed.migrate_db_schema(v1)
    twice = feed.migrate_db_schema(once)
    assert twice["items"]["9.9.9.9"]["sources"]["crowdsec"]["machines"] == ["h1"]


def test_purge_asn_names_retire_les_orphelins():
    db = {"items": {"1.1.1.1": {"asn": "13335"}, "8.8.8.8": {"asn": "15169"}, "9.9.9.9": {}},
          "asn_names": {"13335": "CLOUDFLARENET", "15169": "GOOGLE",
                        "666": "ORPHELIN", "777": "ORPHELIN"}}
    assert feed.purge_asn_names(db) == 2
    assert set(db["asn_names"]) == {"13335", "15169"}


def test_purge_asn_names_idempotente_et_tolerante():
    db = {"items": {"1.1.1.1": {"asn": "13335"}}, "asn_names": {"13335": "CLOUDFLARENET"}}
    assert feed.purge_asn_names(db) == 0
    assert feed.purge_asn_names({"items": {}, "asn_names": {}}) == 0
    assert feed.purge_asn_names({"items": {}}) == 0


def test_db_publie_sans_metadonnees_internes():
    """machines / last_alert_id / last_alert_uuid ne doivent jamais sortir."""
    db = {"items": {"1.2.3.4": {"ip": "1.2.3.4", "sources": {"crowdsec": {
        "count": 3, "machines": ["host-a"], "last_alert_id": 42,
        "last_alert_uuid": "u", "payloads": ["GET /x"]}}}}}
    bloc = feed._sanitize_db_for_publish(db)["items"]["1.2.3.4"]["sources"]["crowdsec"]
    assert not {"machines", "last_alert_id", "last_alert_uuid"} & set(bloc)
    assert bloc["count"] == 3 and bloc["payloads"] == ["GET /x"]
    # la base en mémoire du run courant reste intacte
    assert "machines" in db["items"]["1.2.3.4"]["sources"]["crowdsec"]
