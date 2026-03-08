#!/usr/bin/env python3
"""
phishnet — Phishing URL Feed Collector & Crawler

Usage:
  python collector.py                    # run once (default, good for cron)
  python collector.py --daemon           # run on internal schedule
  python collector.py --config my.yaml  # custom config path
  python collector.py --crawl-all       # (re)crawl all known URLs, not just new
"""

import argparse
import csv
import hashlib
import io
import json
import logging
import random
import shutil
import os
import signal
import socket
import sqlite3
import ssl
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import requests
import schedule
import urllib3
import yaml

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger("phishnet")


# ─── Schema ───────────────────────────────────────────────────────────────────

_SCHEMA = """
CREATE TABLE IF NOT EXISTS urls (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    url             TEXT    UNIQUE NOT NULL,
    date_added      TEXT    NOT NULL,
    date_last_seen  TEXT
);

CREATE TABLE IF NOT EXISTS crawls (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    url_id              INTEGER NOT NULL REFERENCES urls(id),
    crawl_date          TEXT    NOT NULL,
    user_agent_used     TEXT,

    -- HTTP response
    http_status         INTEGER,
    redirect_chain      TEXT,       -- JSON array of intermediate URLs
    final_url           TEXT,
    content_type        TEXT,
    content_length      INTEGER,
    response_time_ms    INTEGER,
    retries_needed      INTEGER DEFAULT 0,

    -- Server headers
    server              TEXT,
    x_powered_by        TEXT,
    response_headers    TEXT,       -- full headers as JSON

    -- Response body (optional, controlled by capture_body in config)
    response_body       TEXT,

    -- TLS / certificate
    cert_subject        TEXT,       -- JSON {"commonName": "...", ...}
    cert_issuer         TEXT,       -- JSON
    cert_valid_from     TEXT,
    cert_valid_to       TEXT,
    cert_san            TEXT,       -- JSON array of SANs
    cert_fingerprint    TEXT,       -- SHA-256 hex

    -- kitphishr
    kitphishr_ran        INTEGER DEFAULT 0,
    kitphishr_status     TEXT,
    kitphishr_zip        TEXT,
    kitphishr_output     TEXT
);

CREATE INDEX IF NOT EXISTS idx_crawls_url_id   ON crawls(url_id);
CREATE INDEX IF NOT EXISTS idx_crawls_date      ON crawls(crawl_date);
CREATE INDEX IF NOT EXISTS idx_urls_date_added  ON urls(date_added);
"""

_CRAWL_COLS = [
    "url_id", "crawl_date", "user_agent_used",
    "http_status", "redirect_chain", "final_url",
    "content_type", "content_length", "response_time_ms", "retries_needed",
    "server", "x_powered_by", "response_headers", "response_body",
    "cert_subject", "cert_issuer", "cert_valid_from", "cert_valid_to",
    "cert_san", "cert_fingerprint",
    "kitphishr_ran", "kitphishr_status", "kitphishr_zip", "kitphishr_output",
]


# ─── Database helpers ─────────────────────────────────────────────────────────

def open_db(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.executescript(_SCHEMA)
    conn.commit()
    return conn


def db_insert_url(conn: sqlite3.Connection, url: str, now: str) -> tuple[int, bool]:
    """Upsert a URL. Returns (row_id, is_new)."""
    cur = conn.execute("SELECT id FROM urls WHERE url = ?", (url,))
    row = cur.fetchone()
    if row:
        conn.execute("UPDATE urls SET date_last_seen = ? WHERE id = ?", (now, row["id"]))
        return row["id"], False
    cur = conn.execute(
        "INSERT INTO urls (url, date_added, date_last_seen) VALUES (?, ?, ?)",
        (url, now, now),
    )
    conn.commit()
    return cur.lastrowid, True


def db_insert_crawl(conn: sqlite3.Connection, url_id: int, data: dict):
    data = dict(data)
    data["url_id"] = url_id
    cols = ", ".join(_CRAWL_COLS)
    placeholders = ", ".join("?" for _ in _CRAWL_COLS)
    values = [data.get(c) for c in _CRAWL_COLS]
    conn.execute(f"INSERT INTO crawls ({cols}) VALUES ({placeholders})", values)
    conn.commit()


# ─── User-Agent helpers ───────────────────────────────────────────────────────

def pick_ua(ua_cfg: dict) -> str:
    """Pick a crawl User-Agent from the pool (random or first, per config)."""
    pool = ua_cfg.get("pool") or []
    if not pool:
        return "phishnet/1.0"
    if ua_cfg.get("rotate", True):
        return random.choice(pool)
    return pool[0]


def feed_ua(ua_cfg: dict, feed: dict) -> str:
    """Return the UA to use for a specific feed fetch."""
    # Per-feed override takes highest priority
    if feed.get("user_agent"):
        return feed["user_agent"]
    # Dedicated feed_ua (static string, not rotated)
    if ua_cfg.get("feed_ua"):
        return ua_cfg["feed_ua"]
    # Fall back to the crawl pool
    return pick_ua(ua_cfg)


# ─── Feed fetching ────────────────────────────────────────────────────────────

def _is_valid_url(s: str) -> bool:
    try:
        p = urlparse(s)
        return p.scheme in ("http", "https") and bool(p.netloc)
    except Exception:
        return False


def _normalize(url: str) -> str:
    return url.strip().rstrip("/")


def _ensure_scheme(url: str) -> str:
    """Prepend http:// if the URL has no scheme."""
    if not url.startswith(("http://", "https://")):
        return "http://" + url
    return url


def fetch_feed(feed: dict, ua_cfg: dict, crawl_cfg: dict) -> set[str]:
    name = feed.get("name", feed["url"])
    feed_type = feed.get("type", "txt").lower()
    comment_char = feed.get("comment_char", "#")
    timeout = int(crawl_cfg.get("feed_timeout", 30))
    ua = feed_ua(ua_cfg, feed)

    log.info("Fetching [%s] %s  (UA: %s)", name, feed["url"], ua[:60])
    try:
        resp = requests.get(
            feed["url"],
            timeout=timeout,
            verify=False,
            headers={"User-Agent": ua},
        )
        resp.raise_for_status()
        text = resp.text
    except Exception as exc:
        log.warning("  Failed to fetch %s: %s", name, exc)
        return set()

    urls: set[str] = set()

    if feed_type == "txt":
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith(comment_char):
                continue
            line = _ensure_scheme(line)
            if _is_valid_url(line):
                urls.add(_normalize(line))

    elif feed_type == "csv":
        delimiter = feed.get("delimiter", ",")
        url_field = feed.get("url_field", 0)   # str = header name, int = column index
        skip_rows = int(feed.get("skip_rows", 0))

        reader = csv.reader(io.StringIO(text), delimiter=delimiter)
        headers: list[str] | None = None

        for i, row in enumerate(reader):
            if i < skip_rows:
                continue
            if not row:
                continue
            if row[0].strip().startswith(comment_char):
                continue

            if isinstance(url_field, str):
                if headers is None:
                    headers = [h.strip().lstrip("#").strip() for h in row]
                    continue
                field_key = url_field.lstrip("#").strip()
                try:
                    idx = headers.index(field_key)
                    candidate = row[idx].strip()
                except (ValueError, IndexError):
                    continue
            else:
                try:
                    candidate = row[int(url_field)].strip()
                except IndexError:
                    continue

            candidate = _ensure_scheme(candidate)
            if _is_valid_url(candidate):
                urls.add(_normalize(candidate))

    else:
        log.warning("  Unknown feed type '%s' for %s — skipping", feed_type, name)

    log.info("  → %d URLs from [%s]", len(urls), name)
    return urls


# ─── TLS / certificate info ───────────────────────────────────────────────────

def get_cert_info(hostname: str, port: int = 443, timeout: int = 10) -> dict:
    result = {
        "cert_subject": None, "cert_issuer": None,
        "cert_valid_from": None, "cert_valid_to": None,
        "cert_san": None, "cert_fingerprint": None,
    }
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=timeout) as raw:
            raw.settimeout(timeout)
            with ctx.wrap_socket(raw, server_hostname=hostname) as ssock:
                ssock.settimeout(timeout)
                cert = ssock.getpeercert()
                der = ssock.getpeercert(binary_form=True)
        if not cert:
            return result
        result["cert_fingerprint"] = hashlib.sha256(der).hexdigest()
        result["cert_subject"] = json.dumps(dict(x[0] for x in cert.get("subject", [])))
        result["cert_issuer"] = json.dumps(dict(x[0] for x in cert.get("issuer", [])))
        result["cert_valid_from"] = cert.get("notBefore")
        result["cert_valid_to"] = cert.get("notAfter")
        result["cert_san"] = json.dumps([v for _, v in cert.get("subjectAltName", [])])
    except Exception as exc:
        log.debug("cert_info failed for %s:%d — %s", hostname, port, exc)
    return result


# ─── HTTP crawling ────────────────────────────────────────────────────────────

def _build_crawl_session(ua: str, crawl_cfg: dict) -> requests.Session:
    """Build a requests.Session pre-configured for a single crawl."""
    session = requests.Session()

    # Headers: extra_headers first, then UA on top (UA always wins)
    headers = dict(crawl_cfg.get("extra_headers") or {})
    headers["User-Agent"] = ua
    session.headers.update(headers)

    # Redirect handling
    max_redir = int(crawl_cfg.get("max_redirects", 10))
    session.max_redirects = max_redir

    # Proxy
    proxy = crawl_cfg.get("proxy")
    if proxy:
        session.proxies.update(proxy)

    return session


def crawl_url(url: str, ua: str, crawl_cfg: dict) -> dict:
    """
    Crawl a URL with the given User-Agent and crawl configuration.
    Retries on connection/timeout errors. Returns a dict matching _CRAWL_COLS.
    """
    timeout        = int(crawl_cfg.get("timeout", 20))
    tls_timeout    = int(crawl_cfg.get("tls_timeout", 10))
    verify_ssl     = bool(crawl_cfg.get("verify_ssl", False))
    follow_redir   = bool(crawl_cfg.get("follow_redirects", True))
    retry_count    = int(crawl_cfg.get("retry_count", 2))
    retry_delay    = int(crawl_cfg.get("retry_delay", 5))
    capture_body   = bool(crawl_cfg.get("capture_body", False))
    body_max_bytes = int(crawl_cfg.get("body_max_bytes", 102400))
    max_content    = int(crawl_cfg.get("max_content_length", 5 * 1024 * 1024))

    data: dict = {
        "crawl_date":       _utcnow(),
        "user_agent_used":  ua,
        "final_url":        url,
        "retries_needed":   0,
    }

    session = _build_crawl_session(ua, crawl_cfg)
    last_exc: Exception | None = None

    for attempt in range(retry_count + 1):
        if attempt > 0:
            log.debug("  Retry %d/%d for %s", attempt, retry_count, url)
            time.sleep(retry_delay)
            data["retries_needed"] = attempt

        try:
            t0 = time.monotonic()
            resp = session.get(
                url,
                timeout=timeout,
                allow_redirects=follow_redir,
                verify=verify_ssl,
                stream=True,            # stream to enforce max_content_length
            )

            # Read body up to max_content_length, with an overall wall-clock
            # timeout so slow/streaming servers can't hang the process.
            body_bytes = b""
            for chunk in resp.iter_content(chunk_size=65536):
                body_bytes += chunk
                if len(body_bytes) >= max_content:
                    body_bytes = body_bytes[:max_content]
                    break
                if (time.monotonic() - t0) > timeout:
                    break

            elapsed_ms = int((time.monotonic() - t0) * 1000)

            data["response_time_ms"] = elapsed_ms
            data["http_status"]      = resp.status_code
            data["final_url"]        = resp.url
            data["content_type"]     = resp.headers.get("Content-Type")
            data["content_length"]   = len(body_bytes)
            data["server"]           = resp.headers.get("Server")
            data["x_powered_by"]     = resp.headers.get("X-Powered-By")
            data["response_headers"] = json.dumps(dict(resp.headers))

            if resp.history:
                data["redirect_chain"] = json.dumps([r.url for r in resp.history])

            if capture_body:
                try:
                    body_text = body_bytes[:body_max_bytes].decode("utf-8", errors="replace")
                    data["response_body"] = body_text
                except Exception:
                    pass

            last_exc = None
            break   # success — stop retrying

        except (requests.exceptions.ConnectionError,
                requests.exceptions.Timeout) as exc:
            last_exc = exc
            log.debug("  Crawl attempt %d failed for %s: %s", attempt + 1, url, exc)
        except Exception as exc:
            last_exc = exc
            log.debug("  Crawl error (non-retryable) for %s: %s", url, exc)
            break   # don't retry on unexpected errors

    if last_exc is not None:
        log.debug("  All attempts exhausted for %s: %s", url, last_exc)

    session.close()

    # TLS cert probe (independent of HTTP crawl success)
    parsed = urlparse(url)
    if parsed.scheme == "https":
        host = parsed.hostname
        port = parsed.port or 443
        data.update(get_cert_info(host, port, timeout=tls_timeout))

    return data


# ─── kitphishr ────────────────────────────────────────────────────────────────

def run_kitphishr(url: str, binary: str, output_dir: str) -> dict:
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    try:
        proc = subprocess.Popen(
            [binary, "-d", "-v", "-o", output_dir, url],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            preexec_fn=os.setsid,   # new process group so we can kill the whole tree
        )
        try:
            stdout, stderr = proc.communicate(timeout=120)
        except subprocess.TimeoutExpired:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            stdout, stderr = proc.communicate()
            return {"kitphishr_ran": 1, "kitphishr_status": "timeout",
                    "kitphishr_output": "Process timed out after 120s"}

        output = (stdout + stderr).strip()
        zips = sorted(Path(output_dir).glob("*.zip"), key=lambda p: p.stat().st_mtime)
        zip_path = str(zips[-1]) if zips else None
        status = "success" if proc.returncode == 0 else f"exit:{proc.returncode}"
        return {
            "kitphishr_ran": 1,
            "kitphishr_status": status,
            "kitphishr_zip": zip_path,
            "kitphishr_output": output[:8192],
        }
    except FileNotFoundError:
        log.warning("kitphishr not found at '%s' — skipping", binary)
        return {"kitphishr_ran": 0, "kitphishr_status": "binary_not_found"}
    except Exception as exc:
        return {"kitphishr_ran": 1, "kitphishr_status": f"error: {exc}"}


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


# ─── Main collection run ──────────────────────────────────────────────────────

def run_collection(cfg: dict, crawl_all: bool = False):
    s          = cfg["settings"]
    ua_cfg     = cfg.get("user_agents", {})
    crawl_cfg  = cfg.get("crawling", {})

    data_dir = Path(s.get("data_dir", "./data"))
    data_dir.mkdir(parents=True, exist_ok=True)

    db_path       = s.get("db_path", str(data_dir / "phishnet.db"))
    do_crawl      = crawl_cfg.get("timeout") is not None or s.get("crawl_new_urls", True)
    do_kitphishr   = bool(s.get("run_kitphishr", True))
    kitphishr_bin  = s.get("kitphishr_bin", "kitphishr")
    kitphishr_dir  = s.get("kitphishr_output_dir", str(data_dir / "kits"))

    current_file = data_dir / "phishing_urls.txt"
    backup_file  = data_dir / "phishing_urls.txt.bak"

    log.info("=" * 60)
    log.info("Collection run started at %s", _utcnow())
    log.info("=" * 60)

    # ── 1. Fetch all feeds ────────────────────────────────────────────────────
    all_urls: set[str] = set()
    for feed in cfg.get("feeds", []):
        all_urls.update(fetch_feed(feed, ua_cfg, crawl_cfg))

    log.info("Total unique URLs collected from feeds: %d", len(all_urls))

    # ── 2. Diff against previous run ─────────────────────────────────────────
    previous_urls: set[str] = set()
    if current_file.exists():
        previous_urls = {u for u in current_file.read_text().splitlines() if u.strip()}
        shutil.copy2(current_file, backup_file)
        log.info("Backed up previous list (%d URLs) → %s", len(previous_urls), backup_file)

    new_urls = all_urls - previous_urls
    log.info("New URLs this run: %d", len(new_urls))

    # ── 3. Write current full list (replaced every run) ───────────────────────
    current_file.write_text("\n".join(sorted(all_urls)) + "\n")
    log.info("Full list written (%d URLs) → %s", len(all_urls), current_file)

    # ── 4. Write timestamped new-URL file (kept forever) ─────────────────────
    if new_urls:
        new_file = data_dir / f"new_phishing_urls_{_ts()}.txt"
        new_file.write_text("\n".join(sorted(new_urls)) + "\n")
        log.info("New URLs file → %s", new_file)

    # ── 5. Update database ────────────────────────────────────────────────────
    conn = open_db(db_path)
    now = _utcnow()

    urls_to_process: list[tuple[int, str]] = []
    for url in all_urls:
        url_id, is_new = db_insert_url(conn, url, now)
        if is_new or crawl_all:
            urls_to_process.append((url_id, url))

    conn.commit()
    log.info("DB: %d URLs to crawl/process this run", len(urls_to_process))

    # ── 6. Crawl + kitphishr ───────────────────────────────────────────────────
    for i, (url_id, url) in enumerate(urls_to_process, 1):
        ua = pick_ua(ua_cfg)
        log.info("[%d/%d] %s  (UA: %s)", i, len(urls_to_process), url, ua[:60])

        crawl_data: dict = {"crawl_date": _utcnow(), "user_agent_used": ua, "final_url": url}

        if do_crawl:
            crawl_data = crawl_url(url, ua, crawl_cfg)

        if do_kitphishr:
            log.info("  Running kitphishr on %s", url)
            k = run_kitphishr(url, kitphishr_bin, kitphishr_dir)
            crawl_data.update(k)

        db_insert_crawl(conn, url_id, crawl_data)

    conn.close()
    log.info("=" * 60)
    log.info("Run complete. DB: %s", db_path)
    log.info("=" * 60)


# ─── Logging setup ────────────────────────────────────────────────────────────

def setup_logging(level_name: str, log_file: str | None):
    level = getattr(logging, level_name.upper(), logging.INFO)
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stdout)]
    if log_file:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(log_file))
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)-8s] %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
        handlers=handlers,
    )


# ─── Entry point ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Phishing URL feed collector & crawler")
    parser.add_argument("--config",    default="config.yaml", help="Config YAML (default: config.yaml)")
    parser.add_argument("--daemon",    action="store_true",   help="Run continuously on internal schedule")
    parser.add_argument("--crawl-all", action="store_true",   help="(Re)crawl all URLs, not just new ones")
    args = parser.parse_args()

    with open(args.config) as f:
        cfg = yaml.safe_load(f)

    s = cfg.get("settings", {})
    setup_logging(s.get("log_level", "INFO"), s.get("log_file") or None)

    if args.daemon:
        interval_hours = int(s.get("interval_hours", 6))
        log.info("Daemon mode — interval: %d hours", interval_hours)

        def _job():
            run_collection(cfg, crawl_all=args.crawl_all)

        _job()  # run immediately at startup
        schedule.every(interval_hours).hours.do(_job)

        def _shutdown(sig, frame):
            log.info("Signal %d received — shutting down", sig)
            sys.exit(0)

        signal.signal(signal.SIGINT, _shutdown)
        signal.signal(signal.SIGTERM, _shutdown)

        while True:
            schedule.run_pending()
            time.sleep(30)
    else:
        run_collection(cfg, crawl_all=args.crawl_all)


if __name__ == "__main__":
    main()
