# phishnet

A Python tool that aggregates phishing URLs from multiple threat intel feeds, deduplicates them, crawls each new URL for HTTP/TLS metadata and fingerprinting data, hunts for phishing kit zips, and optionally submits confirmed kit URLs to urlscan.io. Only URLs where a kit is found are persisted to the SQLite database.

---

## Features

- Ingests **TXT** and **CSV** feeds (configurable delimiter, column name or index)
- **Deduplicates** across all feeds each run; scheme-less URLs (`evil.com/path`) are fixed automatically
- **Seen-URL accumulator** — `phishing_urls.txt` only ever grows; feed outages never trigger re-crawls of already-processed URLs
- Bails out safely if all feeds return zero URLs to prevent corrupting history
- **SQLite database** stores only URLs where a phishing kit was found, plus full crawl metadata
- **Crawls** each new URL: HTTP status, redirect chain, response headers, server info, TLS cert details
- **Fingerprinting** fields extracted from every response: resolved IP, page title, form action URL
- **Parallel crawling** via `ThreadPoolExecutor`; worker count is configurable
- **Kit hunter** — pure Python port of [kitphishr](https://github.com/cybercdh/kitphishr): walks path segments, probes `.zip` variants and Apache/Nginx open directory listings, downloads and saves confirmed kit zips
- **urlscan.io** — automatically submits kit-hit URLs for scanning (configurable visibility and tags)
- **User-Agent rotation** from a configurable pool; per-feed UA overrides supported
- Browser-realistic headers (`Accept`, `Sec-Fetch-*`, etc.) to avoid trivial bot detection
- Retry logic, proxy support, configurable timeouts, optional response body capture
- **Colored console output** — kit discoveries highlighted in green, warnings in yellow, errors in red
- Runs **once** (cron-friendly) or as a **daemon** with an internal scheduler

---

## Requirements

- Python 3.11+

```bash
pip install -r requirements.txt
```

---

## Quick start

```bash
# Single run (default — good for cron)
python collector.py

# Custom config
python collector.py --config /etc/phish/config.yaml

# Run as daemon (internal scheduler, no cron needed)
python collector.py --daemon

# Re-process all known URLs, not just new ones
python collector.py --crawl-all
```

---

## Output files

| File | Description |
|------|-------------|
| `data/phishing_urls.txt` | Cumulative seen-URL list — **grows every run, never shrinks** |
| `data/phishing_urls.txt.bak` | Previous run's list |
| `data/new_phishing_urls_YYYYMMDD_HHMMSS.txt` | URLs new to this run — **kept forever** |
| `data/phishnet.db` | SQLite database — **only kit-hit URLs** |
| `data/kits/` | Downloaded phishing kit zip files |
| `data/collector.log` | Log file (if configured) |

---

## Configuration

All settings live in `config.yaml`.

### `settings`

```yaml
settings:
  interval_hours: 6            # daemon mode run interval
  data_dir: ./data             # root for all output files
  db_path: ./data/phishnet.db
  run_kit_hunt: true           # set false to skip kit hunting
  kit_output_dir: ./data/kits  # where downloaded zips are saved
  crawl_workers: 5             # parallel worker threads
  log_level: INFO              # DEBUG | INFO | WARNING | ERROR
  log_file: ./data/collector.log  # omit or set null for stdout only
```

### `user_agents`

```yaml
user_agents:
  # UA used when fetching feed index files.
  # Set to null to rotate from pool instead.
  feed_ua: "phishnet/1.0"

  # Randomly pick a different UA from the pool for each crawl request.
  rotate: true

  pool:
    - "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ..."
    - "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) ..."
    - ...
```

Priority order for UA selection:

```
per-feed user_agent  >  user_agents.feed_ua  >  pool (random or first)
```

### `crawling`

```yaml
crawling:
  timeout: 20              # HTTP request timeout (seconds)
  tls_timeout: 10          # TLS handshake timeout for cert probing
  feed_timeout: 30         # Timeout when fetching feed lists
  follow_redirects: true
  max_redirects: 10
  retry_count: 2           # Retry connection/timeout errors
  retry_delay: 5           # Seconds between retries
  verify_ssl: false        # Skip SSL verification (phishing sites have bad certs)
  max_content_length: 5242880   # Max body to download per URL (bytes)
  capture_body: false      # Store response body in DB (can grow large)
  body_max_bytes: 102400   # Truncate body to this size if capture_body is true
  proxy: null              # Set to {http: ..., https: ...} to route through a proxy
  extra_headers:
    Accept: "text/html,..."
    Accept-Language: "en-US,en;q=0.9"
    Sec-Fetch-Dest: "document"
    ...
```

### `urlscan`

```yaml
urlscan:
  api_key: ""              # leave empty to disable
  visibility: private      # public | unlisted | private
  tags:
    - phishing
    - phishnet
```

URLs where a kit is found are automatically submitted to urlscan.io when `api_key` is set.

### `feeds`

```yaml
feeds:
  # Plain text — one URL per line
  - name: OpenPhish
    url: https://openphish.com/feed.txt
    type: txt
    comment_char: "#"      # skip lines starting with this (default: #)

  # CSV — reference column by header name
  - name: PhishTank
    url: http://data.phishtank.com/data/online-valid.csv
    type: csv
    delimiter: ","
    url_field: url         # column header name

  # CSV — reference column by zero-based index
  - name: My Feed
    url: https://example.com/feed.csv
    type: csv
    delimiter: ";"
    url_field: 2           # integer = column index
    skip_rows: 1           # skip N rows before header/data

  # Per-feed UA override
  - name: Private API Feed
    url: https://internal.example.com/phish.txt
    type: txt
    user_agent: "MyOrg-ThreatIntel/2.0 (token=secret)"
```

---

## Database schema

Only URLs where the kit hunter finds and downloads a zip are written to the database.

### `urls`

| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER | Primary key |
| `url` | TEXT | Unique phishing URL |
| `date_added` | TEXT | ISO-8601 UTC timestamp — first seen |
| `date_last_seen` | TEXT | ISO-8601 UTC timestamp — last seen in any feed |

### `crawls`

One row per kit-hit crawl. A URL may appear multiple times with `--crawl-all`.

| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER | Primary key |
| `url_id` | INTEGER | FK → `urls.id` |
| `crawl_date` | TEXT | ISO-8601 UTC timestamp |
| `user_agent_used` | TEXT | UA string used for this crawl |
| `http_status` | INTEGER | HTTP response status code |
| `redirect_chain` | TEXT | JSON array of intermediate redirect URLs |
| `final_url` | TEXT | URL after all redirects |
| `content_type` | TEXT | `Content-Type` header value |
| `content_length` | INTEGER | Actual bytes downloaded |
| `response_time_ms` | INTEGER | Total response time (ms) |
| `retries_needed` | INTEGER | How many retries were required |
| `server` | TEXT | `Server` header |
| `x_powered_by` | TEXT | `X-Powered-By` header |
| `response_headers` | TEXT | Full response headers as JSON |
| `response_body` | TEXT | Response body (only when `capture_body: true`) |
| `ip_address` | TEXT | Resolved IP address of the hostname |
| `page_title` | TEXT | `<title>` tag extracted from response body |
| `form_action` | TEXT | First `<form action="...">` value (credential exfil endpoint) |
| `cert_subject` | TEXT | TLS cert subject as JSON |
| `cert_issuer` | TEXT | TLS cert issuer as JSON |
| `cert_valid_from` | TEXT | TLS cert notBefore |
| `cert_valid_to` | TEXT | TLS cert notAfter |
| `cert_san` | TEXT | Subject Alternative Names as JSON array |
| `cert_fingerprint` | TEXT | SHA-256 fingerprint of the DER cert |
| `kitphishr_ran` | INTEGER | 1 if kit hunter ran |
| `kitphishr_status` | TEXT | `success`, `no_kit_found`, or error string |
| `kitphishr_zip` | TEXT | Path to the downloaded kit zip |
| `kitphishr_output` | TEXT | Log of probed URLs and result |
| `urlscan_uuid` | TEXT | urlscan.io submission UUID |
| `urlscan_result_url` | TEXT | urlscan.io result page URL |

---

## Kit hunter

The kit hunter is a pure Python implementation of the [kitphishr](https://github.com/cybercdh/kitphishr) algorithm. No external binary is required.

For each phishing URL it walks path segments from deepest to root, generating candidate targets:

```
https://evil.com/bank/login.php  →
  https://evil.com/bank/login.php       check as open dir
  https://evil.com/bank/login.php.zip   direct zip probe
  https://evil.com/bank                 check as open dir
  https://evil.com/bank.zip             direct zip probe
  https://evil.com                      check as open dir
```

For `.zip` candidates: checks `Content-Type: application/zip` and a valid `Content-Length`.
For HTML responses: looks for `"Index of /"` in the `<title>` tag, then extracts and downloads any `.zip` hrefs found in the directory listing.

Downloaded zips are saved to `kit_output_dir` with a filename derived from the full URL (all non-alphanumeric chars stripped), matching kitphishr's naming convention.

---

## Cron example

Run every 6 hours, log to file:

```cron
0 */6 * * * /usr/bin/python3 /opt/phishnet/collector.py --config /opt/phishnet/config.yaml >> /var/log/phishnet.log 2>&1
```

Or use the built-in daemon mode (systemd, screen, tmux, etc.):

```bash
python collector.py --daemon
```

---

## Querying the database

```bash
sqlite3 data/phishnet.db
```

```sql
-- All kit hits found today
SELECT url, date_added FROM urls
WHERE date_added >= date('now')
ORDER BY date_added DESC;

-- Kit hits with page title and credential exfil endpoint
SELECT u.url, c.page_title, c.form_action, c.ip_address
FROM crawls c JOIN urls u ON u.id = c.url_id
ORDER BY c.crawl_date DESC;

-- Sites using Let's Encrypt (common on phishing infra)
SELECT u.url, c.cert_issuer, c.cert_valid_to
FROM crawls c JOIN urls u ON u.id = c.url_id
WHERE c.cert_issuer LIKE '%Let%Encrypt%';

-- All downloaded kit zips
SELECT u.url, c.kitphishr_zip, c.crawl_date
FROM crawls c JOIN urls u ON u.id = c.url_id
WHERE c.kitphishr_status = 'success'
ORDER BY c.crawl_date DESC;

-- Kit hits submitted to urlscan.io
SELECT u.url, c.urlscan_result_url, c.crawl_date
FROM crawls c JOIN urls u ON u.id = c.url_id
WHERE c.urlscan_uuid IS NOT NULL
ORDER BY c.crawl_date DESC;

-- Redirect chains
SELECT u.url, c.final_url, c.redirect_chain
FROM crawls c JOIN urls u ON u.id = c.url_id
WHERE c.redirect_chain IS NOT NULL;

-- Group kit hits by hosting IP
SELECT c.ip_address, COUNT(*) AS kits
FROM crawls c
WHERE c.kitphishr_status = 'success'
GROUP BY c.ip_address
ORDER BY kits DESC;
```

---

## Project structure

```
phishnet/
├── collector.py            # Main script
├── config.yaml             # Feed and crawl configuration
├── requirements.txt
└── data/                   # Created automatically on first run
    ├── phishnet.db
    ├── phishing_urls.txt
    ├── phishing_urls.txt.bak
    ├── new_phishing_urls_YYYYMMDD_HHMMSS.txt
    ├── collector.log
    └── kits/               # Downloaded kit zip files
```
