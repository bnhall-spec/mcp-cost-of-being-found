[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.23070611.svg)](https://doi.org/10.5281/zenodo.23070611)
# The Cost of Being Found — dataset

Server-side observations of a public Model Context Protocol server over the 45 days following
a single registry listing.

**Paper:** *The Cost of Being Found: Six Weeks of Server-Side Observation After One MCP Registry
Listing.* Bowman Hall, 2026. arXiv:XXXX.XXXXX
**Licence:** CC0 1.0 (data) · MIT (code)

---

## What this is

On **12 August 2026 at 17:25 UTC** a remote MCP server was published to the official MCP
registry under a DNS-verified namespace, and submitted nowhere else. This repository contains
the derived measurements of what subsequently arrived at it.

The published measurement literature on MCP is *outside-in*: registries are crawled, servers are
located by internet-wide scanning and then probed. This is the inverse — one server, one
listing, one clock, and its own logs.

Headline figures, all reproducible from the files below:

| | |
|---|---|
| requests/day before the listing | 6.4 |
| requests/day after | 1,462.8 |
| JSON-RPC requests in the window | 34,235 |
| `tools/call` attempts | 126 |
| `tools/call` served | **0** |
| `tools/list` : `tools/call` | 105 : 1 |
| mean distinct clients/day, week 0 → week 5 | 39.7 → 71.1 |
| sources completing the RFC 9728 chain | 111 of 171 |
| sources presenting ≥2 forged vendor identities | 43 |

---

## Files

| file | rows | what it holds |
|---|---|---|
| `timeline.csv` | daily | requests, distinct clients, distinct sources, monitoring share |
| `client_classes.csv` | per client | class, volume, active days, max response size, tool-result observed, OAuth chain completed |
| `daily_arrivals.csv` | client × day | first and last seen, requests, 2xx count |
| `polling_clients.csv` | per client | mean rate, median interval, distinct source count, methods, status codes |
| `oauth_discovery.csv` | per source | RFC 9728 chain steps reached |
| `conformance.csv` | per failure mode | client, occurrences |
| `impersonation.csv` | per source | count and list of vendor identities presented, hostile request count |
| `controls.csv` | — | pre/post-listing rates; the opt-out before/after |
| `figure1.svg` | — | daily requests and distinct clients, days 0–41 |

`mcp_dataset.py` regenerates every CSV from access logs. It is included so the derivation can be
criticised, not because it can be run against data nobody else has.

---

## What is deliberately absent

**Raw logs are not published and will not be.** They contain OAuth callback URLs bearing live
authorisation codes, end-user query text, and session identifiers. No aggregation of them would
make that safe to release.

**Residential source addresses are withheld.** Addresses are published only where they fall
within identified datacentre ranges; anything else is reported as `residential`. Datacentre
addresses are published routinely by threat-intelligence feeds, and the distinction errs toward
withholding when a range is unrecognised.

**No defensive configuration is described** — no rules, no thresholds, no blocklists. This
repository records what was observed, never what stops it.

**The server is not anonymised**, because it cannot be: the registry namespace is public. The
commercial service it belongs to is out of scope here and no traffic, revenue or customer data
appears in these files.

---

## Method, briefly

Requests are classified by **behaviour and source, never by user-agent alone**. The paper's §3.3
shows why: a single declared client was observed polling from 555 distinct addresses, and 43
datacentre sources presented forged vendor identities in shared, tool-specific sets. Counting
user-agents therefore understates infrastructure in one direction and overstates vendors in the
other.

Three terms are kept distinct throughout and are never summed:

- **source** — a distinct network source address
- **declared client** — the identity in the User-Agent header
- **vendor identity** — an organisation or product name claimed in a User-Agent

Tool invocation is measured from an application log recording the JSON-RPC method, whether a
credential was presented, and the outcome — not inferred from response size. The access log
cannot supply it: every JSON-RPC request appears there only as `POST /mcp`.

---

## Reproducing

```
python3 mcp_dataset.py -o ./data <access-log> [<older-log> ...]
```

The window is anchored on `T0` in the script. Outputs are the CSVs listed above.

---

## Updates

The series continues. The repository is updated as the window extends, and each update is a
commit rather than a replacement, so earlier states remain inspectable.

⚠ The live access log is trimmed to 30 days. From roughly late October the CSVs here will be the
only surviving record of the first fortnight, including the day of the listing.

---

## Citing

```bibtex
@misc{hall2026cost,
  author = {Bowman Hall},
  title  = {The Cost of Being Found: Six Weeks of Server-Side Observation
            After One MCP Registry Listing},
  year   = {2026},
  eprint = {XXXX.XXXXX},
  archivePrefix = {arXiv},
  primaryClass  = {cs.CR}
}
```

## Corrections

Errors in these files are mine and I would rather know. Open an issue.
