# Threat Feed Publisher

Public threat feed built from alerts collected by self-hosted sensors.

It publishes a rolling 7-day list of source IPs seen triggering detection scenarios, updated every 12 hours. Sources currently supported: **CrowdSec** (LAPI) and **Suricata on pfSense** (via Splunk). A curated MISP feed is also published alongside the plain text and JSON feeds for threat intelligence platforms.

> This is a best-effort feed derived from a single self-hosted sensor. It may contain false positives, stale entries, or shared infrastructure IPs — review it before enforcing it blindly.

---

## Feed URLs

Consume the feed directly from GitHub raw URLs:

| Feed | Format | URL |
|---|---|---|
| All IPs (v4 + v6) | Plain text | `https://raw.githubusercontent.com/RedBlue232/threat-feed-publisher/main/feeds/crowdsec_7d.txt` |
| IPv4 only | Plain text | `https://raw.githubusercontent.com/RedBlue232/threat-feed-publisher/main/feeds/crowdsec_7d_v4.txt` |
| IPv6 only | Plain text | `https://raw.githubusercontent.com/RedBlue232/threat-feed-publisher/main/feeds/crowdsec_7d_v6.txt` |
| Enriched | JSON | `https://raw.githubusercontent.com/RedBlue232/threat-feed-publisher/main/feeds/crowdsec_7d.json` |
| MISP Feed | MISP Feed format | `https://raw.githubusercontent.com/RedBlue232/threat-feed-publisher/main/misp-feed/` |

Use the plain text feeds for direct firewall blocking. Use the JSON feed when you need scenario metadata and observation timestamps. Use the MISP feed if you run a MISP instance and want native ingestion with correlation.

### Feed format

Plain text feeds follow the **one IP per line** format, directly consumable by firewalls and blocklist tools:
```
1.2.3.4
5.6.7.8
2001:db8::1
```

The enriched JSON feed includes scenarios, timestamps rounded to the hour, and the originating sources:
```json
{
  "generated_at": "2026-03-21T12:00:00Z",
  "ttl_days": 7,
  "counts": { "total": 42, "v4": 38, "v6": 4 },
  "items": [
    {
      "ip": "1.2.3.4",
      "family": "v4",
      "first_seen": "2026-03-15T08:00:00Z",
      "last_seen":  "2026-03-21T11:00:00Z",
      "scenarios":  ["crowdsec/ssh-bf", "suricata/ET SCAN Zmap User-Agent (Inbound)"],
      "sources":    ["crowdsec", "suricata"]
    }
  ]
}
```

Scenarios are prefixed by their originating source (`crowdsec/…`, `suricata/…`). The optional `sources` field lists every sensor that has observed the IP within the rolling window — useful to gauge corroboration across detectors.

The MISP feed is the standard MISP feed layout (`manifest.json`, `hashes.csv`, `<uuid>.json`), directly subscribable from any MISP instance — see [MISP subscription](#misp-subscription).

### Feed status

Current feed health and IP counts are available in [`state/status.json`](./state/status.json).

---

## What is this?

[CrowdSec](https://crowdsec.net) is an open-source security engine that detects malicious behaviors by analyzing logs. When an IP triggers a detection scenario (brute force, port scan, HTTP probing, etc.), CrowdSec records an alert with context: scenario name, timestamps, and source IP.

This project pulls those alerts, deduplicates them by IP, keeps entries for 7 days after their last observation (sliding TTL on `last_seen`), and republishes the result as text, JSON, and MISP feeds.

**This feed is:**
- A rolling list of IPs seen triggering CrowdSec scenarios
- Enriched with scenario names and observation window (timestamps rounded to the hour)
- Published in plain text, JSON, and MISP feed format

**This feed is not:**
- A global reputation feed — it reflects a single sensor's view
- A guarantee that every listed IP is still malicious at time of consumption
- A substitute for your own filtering logic

---

## Architecture

```
CrowdSec LAPI  ──(JWT auth)──▶┐
                              │
Splunk (suricata_block)  ─────┼──▶  feed.py  ──▶  GitHub (feeds/*.txt, feeds/*.json, state/)
                              │        │
                              │        └────────▶  MISP event (ip-src attributes)
                              │                         │
                                                        ▼
                                                misp_export.py  ──▶  GitHub (misp-feed/)
```

The pipeline runs in Docker, scheduled with [supercronic](https://github.com/aptible/supercronic):

1. **`feed.py`** authenticates to each configured source (CrowdSec LAPI via JWT, Splunk via auth token), fetches recent alerts, normalizes them, deduplicates by IP across sources, merges with the existing state, applies the TTL purge based on `last_seen`, publishes text and JSON feeds to GitHub, and updates a single rolling MISP event. Sources are independent: disabling one does not affect the others, and a transient failure on one source does not interrupt the run (unless every source fails).
2. **`misp_export.py`** fetches that MISP event, sanitizes it (strips internal IDs, creator email, sightings), and publishes it to GitHub as a standard MISP feed.

Internally, each IP record carries a `sources` dictionary that discriminates per-source observations (counts, timestamps, sensor metadata). The state schema is versioned (`schema_version: "2"`); older v1 state files are migrated automatically on first load.

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
... [INFO] DB after merge: 5 IPs (0 purged)
... [INFO] GitHub ✓ feeds/crowdsec_7d.txt
... [INFO] Done — 5 IPs published
```

Expected output of `misp_export.py`:
```
... [INFO] Connexion MISP → https://misp
... [INFO] Fetch event d177856e-6e46-44ee-8eb5-83ef1c7452c7
... [INFO] Event nettoyé : 113 attributs, 0 objets
... [INFO] GitHub ✓ misp-feed/d177856e-6e46-44ee-8eb5-83ef1c7452c7.json
... [INFO] GitHub ✓ misp-feed/manifest.json
... [INFO] GitHub ✓ misp-feed/hashes.csv
... [INFO] Done.
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
| `MISP_EVENT_UUID` | ✅ *(for `misp_export.py`)* | UUID of the MISP event to publish as a feed |
| `MISP_FEED_DIR` | — | Subfolder of the repo used as MISP feed root, default `misp-feed` |
| `SURICATA_ENABLED` | — | `true` / `false`, default `false`. Master switch for the Suricata source. |
| `SPLUNK_URL` | — | Splunk REST base URL (e.g. `https://splunk.example.com:8089`). Required if `SURICATA_ENABLED=true`. |
| `SPLUNK_TOKEN` | — | Splunk auth token scoped to a minimal-privilege role (see [Suricata via Splunk](#suricata-via-splunk)). |
| `SPLUNK_INDEX_BLOCK` | — | Splunk index containing Suricata `block.log`, default `suricata_block`. |
| `SPLUNK_LOOKBACK` | — | Search window, default `13h`. Accepts Splunk time syntax (`s`, `m`, `h`, `d`, `w`, `M`, `y`). |
| `SPLUNK_VERIFY_SSL` | — | `true` / `false`, default `true`. **Keep on** unless you have a very good reason. |
| `SURICATA_MIN_PRIORITY` | — | Optional severity filter. Keep only events whose Suricata priority is ≤ this value (lower = more severe). Empty = no filter. |

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

### 4. Current scope

In the current phase the Suricata source produces:

- An entry per blocked IP under `sources.suricata` in the internal state (`count`, `first_seen`, `last_seen`, deduplicated `sids`, most severe observed `priority`).
- Prefixed scenarios of the form `suricata/<signature>` in `feeds/crowdsec_7d.json`.
- Inclusion of `suricata` in the per-item `sources` list of the enriched JSON feed.

The following are intentionally out of scope for now and will be addressed in follow-up phases: per-source split feeds (`crowdsec_7d.txt` vs `suricata_7d.txt` vs `global_7d.txt`), per-source MISP event separation and `source:*` attribute tags, and the payload enrichment from `eve.json`.

---

## MISP Integration

This project integrates with MISP in two complementary ways.

### Push from CrowdSec to MISP

When `MISP_URL` and `MISP_KEY` are set, `feed.py` maintains a **single rolling MISP event** tagged `crowdsec-feed`:

- On first run: creates the event with all current IPs as `ip-src` attributes
- On subsequent runs: replaces attributes with the current TTL-filtered IP set

To disable this push, leave `MISP_URL` empty in your `.env`.

### Publish the MISP event as a public feed

`misp_export.py` fetches that same event from your MISP, sanitizes it (removes `event_creator_email`, internal IDs, sightings, shadow attributes and related events), and publishes it as a standard MISP feed on GitHub. The feed is then subscribable from any other MISP instance.

Requires `MISP_URL`, `MISP_KEY`, and `MISP_EVENT_UUID`.

---

## MISP subscription

Consumers with a MISP instance can subscribe to the feed natively. In MISP → **Sync Actions → Feeds → Add Feed**:

- Provider: `cyberdefense.blue`
- URL: `https://raw.githubusercontent.com/RedBlue232/threat-feed-publisher/main/misp-feed/`
- Source Format: `MISP Feed`
- Enabled: ✓

The feed refreshes every 12 hours. IPs are published as `ip-src` attributes, each annotated with the originating CrowdSec scenarios and the `first_seen` / `last_seen` observation window.

---

## pfBlocker-NG Integration

In pfSense → **pfBlockerNG → IP → IP Lists → Add**:

- URL: `https://raw.githubusercontent.com/RedBlue232/threat-feed-publisher/main/feeds/crowdsec_7d_v4.txt`
- Format: `IP`
- Action: `Deny Inbound` (or `Alias Only` for custom rules)
- Update frequency: `Every 12 hours`

Add a second entry for the IPv6 feed (`crowdsec_7d_v6.txt`) if needed.

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