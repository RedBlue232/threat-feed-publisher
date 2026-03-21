# CrowdSec CTI Feed

A community threat intelligence feed built on top of [CrowdSec](https://crowdsec.net) alerts, publishing a rolling 7-day blocklist of malicious IPs, updated every 12 hours from my personnal homelab.

> This feed is generated from real-world attack observations collected by a self-hosted CrowdSec instance. It is shared as-is for the community, with no guarantees. Use at your own discretion.

---

## Feed URLs

Consume the feed directly from GitHub raw URLs:

| Feed | Format | URL |
|---|---|---|
| All IPs (v4 + v6) | Plain text | `https://raw.githubusercontent.com/RedBlue232/crowdsec-alerts-feed/main/feeds/crowdsec_7d.txt` |
| IPv4 only | Plain text | `https://raw.githubusercontent.com/RedBlue232/crowdsec-alerts-feed/main/feeds/crowdsec_7d_v4.txt` |
| IPv6 only | Plain text | `https://raw.githubusercontent.com/RedBlue232/crowdsec-alerts-feed/main/feeds/crowdsec_7d_v6.txt` |
| Enriched JSON | JSON | `https://raw.githubusercontent.com/RedBlue232/crowdsec-alerts-feed/main/feeds/crowdsec_7d.json` |

### Feed format

Plain text feeds follow the **one IP per line** format, directly consumable by firewalls and blocklist tools:
```
1.2.3.4
5.6.7.8
2001:db8::1
```

The enriched JSON feed includes scenarios and rounded timestamps (to the hour):
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
      "scenarios":  ["crowdsecurity/ssh-bf", "crowdsecurity/http-probing"]
    }
  ]
}
```

### Feed status

Current feed health and IP counts are available in [`state/status.json`](./state/status.json).

---

## What is this?

[CrowdSec](https://crowdsec.net) is an open-source security engine that detects and blocks malicious behaviors based on log analysis. When an IP triggers a detection scenario (brute force, port scan, HTTP probing, etc.), CrowdSec records an **alert** with context: scenario name, timestamps, and source IP.

This project collects those alerts, deduplicates them, applies a **7-day sliding TTL** based on the last observation, and publishes the resulting IP list as a structured feed — ready to be consumed by firewalls, SIEMs, or threat intelligence platforms.

**What this feed is:**
- A rolling blocklist of IPs that have triggered CrowdSec detection scenarios
- Enriched with attack scenario names and observation window
- Updated automatically on a regular cadence

**What this feed is not:**
- A replacement for the [CrowdSec CTI](https://www.crowdsec.net/cyber-threat-intelligence) (which aggregates millions of sensors)
- A guarantee of maliciousness — IPs may have been recycled or belong to shared infrastructure

---

## Architecture

```
CrowdSec LAPI  ──(JWT auth)──▶  feed.py (Python)
                                    │
                    ┌───────────────┼───────────────┐
                    ▼               ▼               ▼
              GitHub repo         MISP           (extensible)
          feeds/*.txt          Event
          feeds/*.json     ip-src attributes
          state/
```

The pipeline runs in a **lightweight Docker container** scheduled via [supercronic](https://github.com/aptible/supercronic):

1. Authenticates to the CrowdSec LAPI as a watcher (JWT)
2. Fetches recent alerts (`/v1/alerts`)
3. Normalizes and deduplicates by IP
4. Merges with the existing state, applies TTL purge
5. Publishes feeds to GitHub via the Contents API
6. Optionally pushes IOCs to MISP via PyMISP

---

## Self-hosting

### Prerequisites

- Docker + Docker Compose
- A running [CrowdSec](https://docs.crowdsec.net) instance (LAPI accessible)
- A GitHub repository (public for pfBlocker/firewall consumption)
- A GitHub fine-grained token with **Contents: read/write** on this repo
- *(Optional)* A MISP instance

### 1. Register a CrowdSec watcher machine

On your CrowdSec host:
```bash
sudo cscli machines add feed-publisher --password 'YOUR_STRONG_PASSWORD'
sudo cscli machines list  # verify: status should be "validated"
```

### 2. Configure the environment

```bash
cp .env.example .env
# Edit .env with your values
```

See [Configuration](#configuration) below for all available variables.

### 3. Build and test

```bash
# Build the image
docker build -t crowdsec-feed:latest ./script

# Run a one-shot test before enabling the schedule
docker run --rm --env-file .env crowdsec-feed:latest python /app/feed.py
```

Expected output:
```
... [INFO] Token JWT obtained ✓
... [INFO] 12 alerts received
... [INFO] DB after merge: 5 IPs (0 purged)
... [INFO] GitHub ✓ feeds/crowdsec_7d.txt
... [INFO] Done — 5 IPs published
```

### 4. Deploy

```bash
docker compose up -d
```

The container runs silently and executes the script at **01:00 and 13:00 UTC** daily via supercronic.

---

## CI / Monitoring

A GitHub Actions workflow ([`monitor.yml`](.github/workflows/monitor.yml)) runs every 13 hours and validates feed freshness and format. It opens an issue if the feed has not been updated within the expected window.

A validation workflow ([`ci.yml`](.github/workflows/ci.yml)) runs on every push to `main`.

---

## Licence

MIT — see [LICENSE](./LICENSE).

Contributions welcome. If you self-host this and publish your own feed, consider opening a PR to add it to a community list.