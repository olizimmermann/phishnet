# phishnet

A Python tool that aggregates phishing URLs from multiple threat intel feeds, deduplicates them, tracks them in a SQLite database, crawls each new URL for HTTP/TLS metadata, and optionally downloads phishing kits via [kitphishr](https://github.com/cybercdh/kitphishr).

---

## Features

- Ingests **TXT** and **CSV** feeds (configurable delimiter, column name or index)
- **Deduplicates** across all feeds each run
- **Diffs** against the previous run — new URLs are saved to a timestamped file and kept forever
- Full-list `phishing_urls.txt` is replaced each run; the previous version is kept as `.bak`
- **SQLite database** tracks every URL, when it was first seen, and all crawl results
- **Crawls** each new URL: HTTP status, redirect chain, response headers, server info, TLS certificate details
- **User-Agent rotation** from a configurable pool; per-feed UA overrides supported
- Browser-realistic headers (`Accept`, `Sec-Fetch-*`, etc.) to avoid trivial bot detection
- Retry logic, proxy support, configurable timeouts, optional response body capture
- Runs **once** (cron-friendly) or as a **daemon** with an internal scheduler
- Runs **kitphishr -d** on each new URL to download phishing kits, stores zip path and output in DB

---

## Requirements

- Python 3.11+
- [kitphishr](https://github.com/cybercdh/kitphishr) in `$PATH` (or set `kitphishr_bin` in config)

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

# Re-crawl all known URLs, not just new ones
python collector.py --crawl-all
```

---

## Output files

| File | Description |
|------|-------------|
| `data/phishing_urls.txt` | Full deduplicated URL list — **replaced every run** |
| `data/phishing_urls.txt.bak` | Previous run's list — **overwritten every run** |
| `data/new_phishing_urls_YYYYMMDD_HHMMSS.txt` | URLs new to this run — **kept forever** |
| `data/phishnet.db` | SQLite database — see schema below |
| `data/kits/` | Phishing kit zip files downloaded by kitphishr |
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
  run_kitphishr: true           # set false to skip kit downloads
  kitphishr_bin: kitphishr       # path to kitphishr binary
  kitphishr_output_dir: ./data/kits
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

### `urls`

| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER | Primary key |
| `url` | TEXT | Unique phishing URL |
| `date_added` | TEXT | ISO-8601 UTC timestamp — first seen |
| `date_last_seen` | TEXT | ISO-8601 UTC timestamp — last seen in any feed |

### `crawls`

One row per crawl attempt. A URL may be crawled multiple times (e.g. with `--crawl-all`).

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
| `response_time_ms` | INTEGER | Time to first complete response (ms) |
| `retries_needed` | INTEGER | How many retries were required |
| `server` | TEXT | `Server` header |
| `x_powered_by` | TEXT | `X-Powered-By` header |
| `response_headers` | TEXT | Full response headers as JSON |
| `response_body` | TEXT | Response body (only when `capture_body: true`) |
| `cert_subject` | TEXT | TLS cert subject as JSON |
| `cert_issuer` | TEXT | TLS cert issuer as JSON |
| `cert_valid_from` | TEXT | TLS cert notBefore |
| `cert_valid_to` | TEXT | TLS cert notAfter |
| `cert_san` | TEXT | Subject Alternative Names as JSON array |
| `cert_fingerprint` | TEXT | SHA-256 fingerprint of the DER cert |
| `kitphishr_ran` | INTEGER | 1 if kitphishr was invoked |
| `kitphishr_status` | TEXT | `success`, `exit:N`, `timeout`, `binary_not_found` |
| `kitphishr_zip` | TEXT | Path to the downloaded zip file |
| `kitphishr_output` | TEXT | Combined stdout/stderr from kitphishr (truncated at 8 KB) |

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
-- All URLs found today
SELECT url, date_added FROM urls
WHERE date_added >= date('now')
ORDER BY date_added DESC;

-- Live sites (HTTP 200) from last crawl
SELECT u.url, c.http_status, c.server, c.cert_subject
FROM crawls c JOIN urls u ON u.id = c.url_id
WHERE c.http_status = 200
ORDER BY c.crawl_date DESC;

-- Sites still using a specific cert issuer (e.g. Let's Encrypt)
SELECT u.url, c.cert_issuer, c.cert_valid_to
FROM crawls c JOIN urls u ON u.id = c.url_id
WHERE c.cert_issuer LIKE '%Let%Encrypt%';

-- URLs where kitphishr successfully downloaded a kit
SELECT u.url, c.kitphishr_zip, c.crawl_date
FROM crawls c JOIN urls u ON u.id = c.url_id
WHERE c.kitphishr_status = 'success'
ORDER BY c.crawl_date DESC;

-- Redirect chains
SELECT u.url, c.final_url, c.redirect_chain
FROM crawls c JOIN urls u ON u.id = c.url_id
WHERE c.redirect_chain IS NOT NULL;
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
    └── kits/               # kitphishr zip downloads
```
