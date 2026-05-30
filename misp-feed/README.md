# MISP Feed

This folder is a [MISP feed](https://www.misp-project.org/) root, refreshed every 12 hours from **three rolling MISP events** aggregating IPs observed by self-hosted sensors over a rolling 7-day window:

- **all** — every IP from every source
- **crowdsec** — IPs observed by CrowdSec only
- **suricata** — IPs observed by Suricata only

An IP seen by multiple sensors appears in the relevant per-source events **and** in `all`. MISP's correlation engine links them automatically.

## Subscribe from MISP

A single subscription covers the three scopes. **Sync Actions → Feeds → Add Feed**:

- Provider: `cyberdefense.blue`
- URL: `https://raw.githubusercontent.com/RedBlue232/threat-feed-publisher/main/misp-feed` *(no trailing slash — MISP appends `/manifest.json` itself)*
- Source Format: `MISP Feed`
- Enabled: ✓

MISP will create one local event per UUID found in the manifest.

## Contents

| File | Purpose |
|---|---|
| `manifest.json` | Event index — three entries, one per scope |
| `hashes.csv`    | MD5 of every attribute value across all three events |
| `<uuid>.json`   | Full event payload (one file per scope) |

Each IP is published as an `ip-src` attribute annotated with:

- `source:crowdsec` and/or `source:suricata` tags
- `mwl:cloud="aws"`, `mwl:scanner="censys"`… ([misp-warninglists](https://github.com/MISP/misp-warninglists) classification)
- `tor:exit-node` if applicable
- A comment listing scenarios, ASN, hit counts, `first_seen` / `last_seen`, and recent sanitized HTTP payload samples

## Disclaimer

Best-effort feed from a single sensor stack. Expect false positives and shared-infrastructure IPs. See the [main README](../README.md) for the full context.
