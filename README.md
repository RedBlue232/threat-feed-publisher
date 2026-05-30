# Threat Feed Publisher

Public threat feed built from alerts collected by self-hosted sensors.

It publishes a rolling 7-day list of source IPs seen triggering detection scenarios, updated every 12 hours. Sources currently supported: **CrowdSec** (LAPI) and **Suricata on pfSense** (via Splunk).

Every IP is enriched with: ASN (CIRCL IP-ASN-History + RIPE Stat name lookup), [misp-warninglists](https://github.com/MISP/misp-warninglists) classification (cloud providers, scanners, etc.), [Tor exit-node](https://check.torproject.org/exit-addresses) flag, and PII-sanitized HTTP payload samples observed by the sensors.

Feeds are split per source (`all`, `crowdsec`, `suricata`) so consumers can pick the right scope for their use case. A MISP-format feed is also published alongside, with one event per scope. An interactive viewer is available at [feed.cyberdefense.blue](https://feed.cyberdefense.blue).

> This is a best-effort feed derived from a single self-hosted sensor. It may contain false positives, stale entries, or shared infrastructure IPs — review it before enforcing it blindly.

---

## Feed URLs

Three scopes are published in parallel: `all` (union of all sources), `crowdsec` (CrowdSec-only IPs), and `suricata` (Suricata-only IPs). An IP observed by multiple sources appears in the relevant per-source feeds **and** in `all`.

Base URL: `https://raw.githubusercontent.com/RedBlue232/threat-feed-publisher/main/feeds/`

| Scope | Plain text (all) | IPv4 only | IPv6 only | Enriched JSON |
|---|---|---|---|---|
| `all` | `feed-all-7d.txt` | `feed-all-7d_v4.txt` | `feed-all-7d_v6.txt` | `feed-all-7d.json` |
| `crowdsec` | `feed-crowdsec-7d.txt` | `feed-crowdsec-7d_v4.txt` | `feed-crowdsec-7d_v6.txt` | `feed-crowdsec-7d.json` |
| `suricata` | `feed-suricata-7d.txt` | `feed-suricata-7d_v4.txt` | `feed-suricata-7d_v6.txt` | `feed-suricata-7d.json` |

**MISP feed root** (one event per scope, sharing a single manifest): `https://raw.githubusercontent.com/RedBlue232/threat-feed-publisher/main/misp-feed` *(no trailing slash)*

**Web viewer** (interactive): [feed.cyberdefense.blue](https://feed.cyberdefense.blue)

Use the plain text feeds for direct firewall blocking. Use the JSON feed when you need scenario metadata, ASN, tags, or observation timestamps. Use the MISP feed if you run a MISP instance and want native ingestion with correlation across the three scopes.

### Feed format

Plain text feeds follow the **one IP per line** format, directly consumable by firewalls and blocklist tools:
```
1.2.3.4
5.6.7.8
2001:db8::1
```

The enriched JSON feed includes scenarios, timestamps rounded to the hour, originating sources, ASN data, classification tags, and HTTP payload samples (sanitized):
```json
{
  "generated_at": "2026-03-21T12:00:00Z",
  "ttl_days": 7,
  "scope": "all",
  "counts": { "total": 42, "v4": 38, "v6": 4 },
  "items": [
    {
      "ip": "1.2.3.4",
      "family": "v4",
      "first_seen": "2026-03-15T08:00:00Z",
      "last_seen":  "2026-03-21T11:00:00Z",
      "scenarios":  ["crowdsec/http-probing", "suricata/ET SCAN Zmap User-Agent (Inbound)"],
      "sources":    ["crowdsec", "suricata"],
      "asn":        "16509",
      "asn_name":   "AMAZON-02 - Amazon.com",
      "asn_prefix": "3.131.0.0/16",
      "tags":       ["mwl:cloud=\"aws\""],
      "payloads":   ["GET /admin.php", "GET /.env"]
    }
  ]
}
```

Scenarios are prefixed by their originating source (`crowdsec/…`, `suricata/…`). The `sources` field lists every sensor that has observed the IP within the rolling window — useful to gauge corroboration across detectors. The `tags` field follows MISP convention (`mwl:scanner="censys"`, `mwl:cloud="aws"`, `tor:exit-node`). See [Enrichments](#enrichments) below for the full list.

The MISP feed is the standard MISP feed layout (`manifest.json`, `hashes.csv`, `<uuid>.json`), directly subscribable from any MISP instance — see [MISP subscription](#misp-subscription).

### Feed status

Current feed health and IP counts are available in [`state/status.json`](./state/status.json).

---

## What is this?

[CrowdSec](https://crowdsec.net) is an open-source security engine that detects malicious behaviors by analyzing logs. When an IP triggers a detection scenario (brute force, port scan, HTTP probing, etc.), CrowdSec records an alert with context: scenario name, timestamps, and source IP.

This project pulls those alerts, deduplicates them by IP, keeps entries for 7 days after their last observation (sliding TTL on `last_seen`), and republishes the result as text, JSON, and MISP feeds.

**This feed is:**
- A rolling list of IPs seen triggering CrowdSec or Suricata scenarios
- Enriched with scenario names, sources, ASN data, classification tags, and sanitized HTTP payloads
- Split per source so consumers pick the scope they want
- Published in plain text, JSON, and MISP feed format
- Browsable in an interactive web viewer

**This feed is not:**
- A global reputation feed — it reflects a single sensor's view
- A guarantee that every listed IP is still malicious at time of consumption
- A substitute for your own filtering logic

---

## Architecture

```
CrowdSec LAPI  ──(JWT auth)──▶┐
                              │      ┌─▶ misp-warninglists (cloud, scanners…)
Splunk (suricata_block + eve)─┤      │
                              │      ├─▶ Tor exit-addresses
                              ▼      │
                          feed.py ──▶┼─▶ CIRCL IP-ASN-History  ──▶ GitHub (feeds/*, state/*)
                              │      │   + RIPE Stat                 │
                              │      └─▶ PII sanitizer                ▼
                              │                                   feed-viewer
                              ▼                              (feed.cyberdefense.blue)
                       MISP (3 events: all, crowdsec, suricata)
                              │
                              ▼
                       misp_export.py ──▶ GitHub (misp-feed/)
```

The pipeline runs in Docker, scheduled with [supercronic](https://github.com/aptible/supercronic):

1. **`feed.py`** authenticates to each configured source (CrowdSec LAPI via JWT, Splunk via auth token), fetches recent alerts, normalizes them, deduplicates by IP across sources, merges with the existing state, applies the TTL purge based on `last_seen`, enriches each IP (warninglists, ASN, Tor, sanitized payloads), publishes the three scoped feeds to GitHub, and updates the three rolling MISP events. Sources are independent: disabling one does not affect the others, and a transient failure on one source does not interrupt the run (unless every source fails).
2. **`misp_export.py`** fetches the three MISP events by UUID, sanitizes them (strips internal IDs, creator email, sightings), and publishes them to GitHub as a standard MISP feed with one shared `manifest.json` / `hashes.csv` and one `<uuid>.json` per scope.

Internally, each IP record carries a `sources` dictionary that discriminates per-source observations (counts, timestamps, sensor metadata, sanitized payload samples). The state schema is versioned (`schema_version: "2"`); older v1 state files are migrated automatically on first load.

---

## Self-hosting

### Prerequisites

- Docker + Docker Compose
- A running [CrowdSec](https://docs.crowdsec.net) instance (LAPI accessible)
- A GitHub repository, preferably public if the feeds are meant to be consumed directly by firewalls or third-party systems
- A GitHub fine-grained token with **Contents: read/write** scoped to this repo
- *(Optional)* A MISP instance — required only if you want to publish the MISP feed
- *(Optional)* A Splunk instance ingesting the Suricata `block.log` from pfSense — required only if you want to add Suricata as a second source (see [Suricata via Splunk](#suricata-via-splunk))

### 1. Register a CrowdSec watcher machine

On your CrowdSec host:
```bash
sudo cscli machines add feed-publisher --password 'YOUR_STRONG_PASSWORD'
sudo cscli machines list  # verify: status should be "validated"
```

### 2. Configure the environment

```bash
cp env.example .env
# Edit .env with your values
```

See [Configuration](#configuration) below for all available variables.

### 3. Build and test

```bash
# Build the image
docker build -t threat-feed-publisher:latest ./scripts

# One-shot test of the CrowdSec publisher
docker run --rm --env-file .env threat-feed-publisher:latest python /app/feed.py

# One-shot test of the MISP feed publisher (if MISP is configured)
docker run --rm --env-file .env threat-feed-publisher:latest python /app/misp_export.py
```

If your MISP instance runs on the same Docker host, the container needs to reach it. Either attach the test run to the MISP network (`--network <misp_network>` with `MISP_URL=https://misp`) or use `--add-host=host.docker.internal:host-gateway` with `MISP_URL=https://host.docker.internal`.

Expected output of `feed.py`:
```
... [INFO] Token JWT obtained ✓
... [INFO] 12 alerts received
... [INFO] DB after merge: 82 IPs (3 purged)
... [INFO] GitHub ✓ feeds/feed-all-7d.txt
... [INFO] GitHub ✓ feeds/feed-crowdsec-7d.txt
... [INFO] GitHub ✓ feeds/feed-suricata-7d.txt
... [INFO] [all] MISP ✓ created=4 updated=8 ...
... [INFO] [crowdsec] MISP ✓ created=24 ...
... [INFO] [suricata] MISP ✓ created=60 ...
... [INFO] MISP ✓ 3/3 events synchronisés
... [INFO] Done — 82 IPs published
```

Expected output of `misp_export.py`:
```
... [INFO] Scopes to export: all, crowdsec, suricata
... [INFO] [all] fetch event d177856e-...
... [INFO] [crowdsec] fetch event 6a10e5d8-...
... [INFO] [suricata] fetch event 8f09de10-...
... [INFO] GitHub ✓ misp-feed/<uuid>.json (×3)
... [INFO] GitHub ✓ misp-feed/manifest.json
... [INFO] GitHub ✓ misp-feed/hashes.csv
... [INFO] Done. 3 events exported, 0 failures.
```

### 4. Deploy

```bash
docker compose up -d
```

The container runs silently and executes the scripts on the following schedule (UTC):
- `feed.py` at **01:00** and **13:00**
- `misp_export.py` at **01:30** and **13:30** (offset by 30 min so the MISP event is up to date when exported)

---

## Configuration

Copy `env.example` to `.env` and fill in your values. **Never commit `.env`** — it is listed in `.gitignore`.

| Variable | Required | Description |
|---|---|---|
| `LAPI_BASE` | ✅ | CrowdSec LAPI base URL, e.g. `http://crowdsec:8080/v1` |
| `CS_MACHINE_ID` | ✅ | Machine ID registered with `cscli machines add` |
| `CS_PASSWORD` | ✅ | Password for the machine |
| `LOOKBACK` | — | Alert fetch window, default `13h` (covers 12h cadence + margin) |
| `GH_TOKEN` | ✅ | GitHub fine-grained token (Contents: read/write) |
| `GH_OWNER` | ✅ | GitHub username or organization |
| `GH_REPO` | ✅ | Target repository name |
| `GH_BRANCH` | — | Target branch, default `main` |
| `TTL_DAYS` | — | Sliding TTL in days, default `7` |
| `MISP_URL` | — | MISP instance URL (leave empty to disable MISP push from `feed.py`) |
| `MISP_KEY` | — | MISP auth key |
| `MISP_VERIFY_SSL` | — | `true` / `false`, default `true` |
| `MISP_UUID_ALL` | — | UUID of the rolling MISP event for the `all` scope. Used by `feed.py` (push) and `misp_export.py` (publish). |
| `MISP_UUID_CROWDSEC` | — | UUID of the rolling MISP event for the `crowdsec` scope. |
| `MISP_UUID_SURICATA` | — | UUID of the rolling MISP event for the `suricata` scope. |
| `MISP_FEED_DIR` | — | Subfolder of the repo used as MISP feed root, default `misp-feed` |
| `SURICATA_ENABLED` | — | `true` / `false`, default `false`. Master switch for the Suricata source. |
| `SPLUNK_URL` | — | Splunk REST base URL (e.g. `https://splunk.example.com:8089`). Required if `SURICATA_ENABLED=true`. |
| `SPLUNK_TOKEN` | — | Splunk auth token scoped to a minimal-privilege role (see [Suricata via Splunk](#suricata-via-splunk)). |
| `SPLUNK_INDEX_BLOCK` | — | Splunk index containing Suricata `block.log`, default `suricata_block`. |
| `SPLUNK_INDEX_EVE` | — | Splunk index containing Suricata `eve.json` (used to extract HTTP payload samples), default `suricata_eve`. |
| `SPLUNK_LOOKBACK` | — | Search window, default `13h`. Accepts Splunk time syntax (`s`, `m`, `h`, `d`, `w`, `M`, `y`). |
| `SPLUNK_VERIFY_SSL` | — | `true` / `false`, default `true`. **Keep on** unless you have a very good reason. |
| `SURICATA_MIN_PRIORITY` | — | Optional severity filter. Keep only events whose Suricata priority is ≤ this value (lower = more severe). Empty = no filter. |
| `ASN_ENABLED` | — | `true` / `false`, default `true`. Toggle ASN enrichment via CIRCL + RIPE Stat. |
| `TOR_ENABLED` | — | `true` / `false`, default `true`. Toggle Tor exit-node tagging. |
| `PII_IPS` | — | Comma-separated IPs to redact from payloads (e.g. your public IP). |
| `PII_DOMAINS` | — | Comma-separated domains to redact (e.g. `*.your-private-domain.tld`). |
| `PAYLOAD_MAX_LEN` | — | Max length of a single payload after sanitization, default `512`. |
| `PAYLOADS_PER_SOURCE_CAP` | — | Max number of payloads kept per (IP, source) in the DB, default `20`. FIFO eviction. |
| `PAYLOADS_MISP_SHOW` | — | Number of recent payloads shown in the MISP attribute comment, default `3`. |

### Debug / test flags

These are not meant for production and are intentionally absent from `env.example`. Set them temporarily when iterating locally:

| Variable | Effect |
|---|---|
| `DRY_RUN=true` | Skip GitHub publish and MISP push. Writes outputs to `DRY_RUN_DIR` (default `/tmp/feed-output`) instead. |
| `MIGRATE_ONLY=true` | Run the v1→v2 schema migration against the current `state/db.json`, write the result locally, and stop. |
| `CROWDSEC_ONLY=true` | Skip the Suricata source for this run. |
| `SURICATA_ONLY=true` | Skip the CrowdSec source for this run. |
| `DRY_RUN_DIR` | Override the destination directory for `DRY_RUN` / `MIGRATE_ONLY` outputs. |

---

## Suricata via Splunk

The Suricata source is optional and disabled by default. When enabled, `feed.py` queries a Splunk instance that already ingests the pfSense Suricata `block.log`, extracts the blocked IPs with their signature / classification / priority, and merges them with the CrowdSec state under a unified per-IP record.

### Why via Splunk and not directly from pfSense

Pulling `block.log` or `eve.json` directly from pfSense (SSH, syslog, Redis) would either require a long-running listener in the container or a second file-shipping path. If you already forward pfSense logs to Splunk for SIEM purposes, querying Splunk gives you rich, already-parsed data with no additional change on pfSense. The publisher uses the cron-friendly synchronous `/services/search/jobs/export` endpoint.

### Security model

This integration is designed to be safe for a public repository:

- **Least-privilege Splunk role.** Create a dedicated role (e.g. `threat_feed_reader`) with only the `search` capability and read access restricted to the block index. Never reuse an admin or power-user token. Example role setup via Splunk UI: *Settings → Access controls → Roles → New Role → Capabilities: `search` only → Indexes: only `suricata_block` selected (all others unchecked)*.
- **Dedicated auth token.** Generate a Splunk auth token attached to a service user that holds *only* the `threat_feed_reader` role: *Settings → Tokens → New Token*. Set an expiration matching your rotation policy. Put the token in `.env` (`SPLUNK_TOKEN`); never commit it.
- **Strict TLS.** `SPLUNK_VERIFY_SSL=true` by default. Only disable on disposable lab setups. The container trusts standard CAs, so a Let's Encrypt certificate on your Splunk endpoint works out of the box.
- **Hardened SPL.** The search query is built from a template in [`scripts/suricata.py`](scripts/suricata.py). Only `SPLUNK_INDEX_BLOCK` (strictly validated to `[A-Za-z0-9_-]+`) and `SPLUNK_LOOKBACK` (matching Splunk time syntax) are interpolated. No user content is reflected into the SPL.
- **IP validation.** Every IP extracted from Splunk is validated with Python's `ipaddress` module. Non-global addresses (private RFC1918, loopback, link-local, multicast, reserved) are rejected and never reach the feed — this protects the public output even if the log parsing ever misbehaves.
- **Token never logged.** The token flows only through the `Authorization: Bearer …` header. Logs report `verify_ssl`, `lookback`, and `index` but never the token value.
- **Graceful failure isolation.** If Splunk is unreachable, the run logs the error and continues with CrowdSec data only. The state is never overwritten with an empty DB.

### 1. Verify the data in Splunk

Before enabling the integration, confirm that the block events are where you expect. In Splunk, run:

```
search index=suricata_block earliest=-13h
| head 5
```

The raw events should look like:

```
04/18/2026-10:24:31.365412  [Block Src] [**] [1:2021076:3] ET HUNTING SUSPICIOUS Dotted Quad Host MZ Response [**] [Classification: Potentially Bad Traffic] [Priority: 2] {TCP} 172.189.127.19:80
```

Then run the full extraction SPL (the same template the publisher uses) to validate that the regex captures every field correctly on your deployment:

```
search index=suricata_block earliest=-13h
| rex field=_raw "\[Block (?<block_dir>Src|Dst)\] \[\*\*\] \[(?<gid>\d+):(?<sid>\d+):(?<rev>\d+)\] (?<signature>[^\[]+?) \[\*\*\] \[Classification: (?<classification>[^\]]+)\] \[Priority: (?<priority>\d+)\] \{(?<proto>\w+)\} (?<blocked_ip>[0-9a-fA-F\.:]+):(?<blocked_port>\d+)"
| where isnotnull(blocked_ip)
| table _time, blocked_ip, sid, signature, classification, priority, block_dir
```

If any `blocked_ip` is empty or a signature looks truncated, the regex needs adjustment for your block.log variant — open an issue before enabling the integration.

### 2. Configure the publisher

In `.env`:

```
SURICATA_ENABLED=true
SPLUNK_URL=https://splunk.example.com:8089
SPLUNK_TOKEN=<token_generated_in_step_1>
SPLUNK_INDEX_BLOCK=suricata_block
SPLUNK_LOOKBACK=13h
SPLUNK_VERIFY_SSL=true
```

### 3. Dry-run locally before publishing

```bash
# Run the whole pipeline without writing to GitHub or MISP.
docker run --rm --env-file .env -e DRY_RUN=true \
  threat-feed-publisher:latest python /app/feed.py

# Or isolate the Suricata source to verify the Splunk leg in isolation.
docker run --rm --env-file .env -e DRY_RUN=true -e SURICATA_ONLY=true \
  threat-feed-publisher:latest python /app/feed.py
```

Inspect the generated files in the container path `/tmp/feed-output/` (mount a volume if you want them on the host).

### 4. What the Suricata source produces

- An entry per blocked IP under `sources.suricata` in the internal state (`count`, `first_seen`, `last_seen`, deduplicated `sids`, most severe observed `priority`, sanitized payload samples).
- Prefixed scenarios of the form `suricata/<signature>` in the JSON feeds.
- Inclusion of `suricata` in the per-item `sources` list of every enriched JSON feed it appears in.
- Its own scoped feed (`feed-suricata-7d.*`) and its own MISP event.
- HTTP payload samples (URL + method) extracted from the `suricata_eve` index — see `SPLUNK_INDEX_EVE` in [Configuration](#configuration). Only payloads where Suricata successfully parsed HTTP are exported (no raw binary fallback).

---

## Enrichments

Every IP that enters the feed goes through a chain of best-effort enrichments. A failure of any single enrichment never prevents publication — it just leaves the affected field unset on that run.

### ASN (CIRCL + RIPE Stat)

IP → ASN + announced prefix via [CIRCL IP-ASN-History](https://github.com/D4-project/IPASN-History) (no auth, batched up to 500 IPs per request). ASN → operator name via [RIPE Stat](https://stat.ripe.net/) `as-overview`. Both are unauthenticated public services with conservative rate-limit handling.

Disable with `ASN_ENABLED=false` in `.env`.

### misp-warninglists

The [MISP warninglists](https://github.com/MISP/misp-warninglists) catalog ships with curated lists of well-known infrastructure (cloud providers, scanners, search engines…). At build time the Docker image embeds a shallow clone; at runtime each IP is matched against the loaded CIDR sets and tagged accordingly. Tag format follows MISP convention: `mwl:cloud="aws"`, `mwl:scanner="censys"`, `mwl:scanner="shodan"`, etc.

Useful to spot at a glance whether a hit is from a known internet scanner (less actionable) or from an unknown source (more interesting).

### Tor exit-nodes

The official [Tor exit-addresses list](https://check.torproject.org/exit-addresses) is fetched at every run and IPs matching are tagged `tor:exit-node`. No new IPs are pulled in from this list; it only annotates IPs already in the feed.

Disable with `TOR_ENABLED=false`.

### HTTP payload samples + PII sanitization

For each IP, a few sanitized HTTP payload samples (URL + method) observed by CrowdSec or Suricata are kept in the JSON feed and in the MISP event comment. Helpful to distinguish a scanner from a targeted CVE attempt at a glance.

Sanitization is mandatory and applies before publication: configured PII (your public IP, your private domain) is redacted with `[REDACTED_IP]` / `[REDACTED_DOMAIN]` tokens. A FIFO cap (`PAYLOADS_PER_SOURCE_CAP`, default 20) prevents unbounded growth, and a max length (`PAYLOAD_MAX_LEN`, default 512) bounds individual payloads.

Configure with `PII_IPS`, `PII_DOMAINS`, and the `PAYLOAD_*` variables in `.env`.

---

## MISP Integration

This project integrates with MISP in two complementary ways.

### Push from sensors to MISP (3 events)

When `MISP_URL` and `MISP_KEY` are set, `feed.py` maintains **three rolling MISP events**, one per scope:

- `MISP_UUID_ALL`      — all IPs from all sources
- `MISP_UUID_CROWDSEC` — IPs observed by CrowdSec
- `MISP_UUID_SURICATA` — IPs observed by Suricata

Each IP in the relevant event(s) is an `ip-src` attribute tagged with `source:crowdsec` / `source:suricata`, plus the warninglist and Tor tags from the enrichment chain. The attribute comment carries first/last seen, hit counts, ASN, scenarios, and the most recent sanitized payload samples.

If your MISP instance does not yet have the events, the publisher creates them with the configured UUIDs on first run. To skip a scope (e.g. transition window), leave its `MISP_UUID_*` empty.

### Publish the MISP events as a public feed

`misp_export.py` fetches the three events by UUID from your MISP instance, sanitizes them (removes `event_creator_email`, internal IDs, sightings, shadow attributes and related events), and publishes them as a standard MISP feed on GitHub: a single shared `manifest.json` + `hashes.csv`, plus one `<uuid>.json` per event. The feed is then subscribable from any other MISP instance with native correlation across the three scopes.

Requires `MISP_URL`, `MISP_KEY`, and at least one of `MISP_UUID_*`.

---

## MISP subscription

Consumers with a MISP instance can subscribe to the feed natively. A single subscription covers the three scopes — MISP creates one local event per UUID found in the manifest. In MISP → **Sync Actions → Feeds → Add Feed**:

- Provider: `cyberdefense.blue`
- URL: `https://raw.githubusercontent.com/RedBlue232/threat-feed-publisher/main/misp-feed` *(no trailing slash — MISP appends `/manifest.json` itself)*
- Source Format: `MISP Feed`
- Enabled: ✓

The feed refreshes every 12 hours. IPs are published as `ip-src` attributes, each annotated with `source:*` tags, classification tags (warninglists, Tor), originating scenarios, ASN, and the `first_seen` / `last_seen` window. An IP observed by multiple sensors is correlated automatically across the three local events thanks to MISP's per-attribute correlation engine.

---

## pfBlocker-NG Integration

In pfSense → **pfBlockerNG → IP → IP Lists → Add**:

- URL: `https://raw.githubusercontent.com/RedBlue232/threat-feed-publisher/main/feeds/feed-all-7d_v4.txt`
- Format: `IP`
- Action: `Deny Inbound` (or `Alias Only` for custom rules)
- Update frequency: `Every 12 hours`

Add a second entry for the IPv6 feed (`feed-all-7d_v6.txt`) if needed. If you only want IPs corroborated by Suricata's signature engine, swap the URL for `feed-suricata-7d_v4.txt` instead — it gives a smaller, more conservative blocklist.

---

## CI / Monitoring

A GitHub Actions workflow ([`monitor.yml`](.github/workflows/monitor.yml)) runs every 13 hours — slightly offset from the 12-hour publish cycle to avoid checking the feed at the exact moment it is being updated. It opens an issue if either the CrowdSec feed (`state/status.json`) or the MISP feed (`misp-feed/manifest.json`) has not been refreshed within the expected window.

A validation workflow ([`ci.yml`](.github/workflows/ci.yml)) runs on every push to `main` and validates the format and internal consistency of all published feeds.

---

## A note on how this was built

A part of the code and CI workflows in this repository were designed with the help of Claude AI (Anthropic). The overall architecture and security choices were reviewed and validated before deployment.

---

## License

MIT — see [LICENSE](./LICENSE).

Feedback, fixes, and additional output targets are welcome.