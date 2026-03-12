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
import re
import shutil
import signal
import socket
import sqlite3
import ssl
import sys
import time
import itertools
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import colorama
from colorama import Fore, Style
import requests
import schedule
import urllib3
import yaml
from cryptography import x509 as _x509
from cryptography.hazmat.backends import default_backend as _crypto_backend

colorama.init(autoreset=True)

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

    -- Fingerprinting
    ip_address          TEXT,       -- resolved IP of the hostname
    page_title          TEXT,       -- <title> extracted from response body
    form_action         TEXT,       -- first <form action="..."> value
    geo_country         TEXT,       -- ISO country code from ipinfo.io
    geo_city            TEXT,       -- city from ipinfo.io
    asn                 TEXT,       -- ASN (e.g. AS15169)
    asn_org             TEXT,       -- organisation name (e.g. Google LLC)

    -- kitphishr
    kitphishr_ran        INTEGER DEFAULT 0,
    kitphishr_status     TEXT,
    kitphishr_zip        TEXT,
    kitphishr_output     TEXT,

    -- urlscan.io
    urlscan_uuid        TEXT,
    urlscan_result_url  TEXT
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
    "ip_address", "page_title", "form_action",
    "geo_country", "geo_city", "asn", "asn_org",
    "kitphishr_ran", "kitphishr_status", "kitphishr_zip", "kitphishr_output",
    "urlscan_uuid", "urlscan_result_url",
]

# Columns added after initial release — migrated automatically on open
_MIGRATION_COLS = [
    ("ip_address",         "TEXT"),
    ("page_title",         "TEXT"),
    ("form_action",        "TEXT"),
    ("urlscan_uuid",       "TEXT"),
    ("urlscan_result_url", "TEXT"),
    ("geo_country",        "TEXT"),
    ("geo_city",           "TEXT"),
    ("asn",                "TEXT"),
    ("asn_org",            "TEXT"),
]


# ─── Database helpers ─────────────────────────────────────────────────────────

def open_db(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.executescript(_SCHEMA)
    for col, col_type in _MIGRATION_COLS:
        try:
            conn.execute(f"ALTER TABLE crawls ADD COLUMN {col} {col_type}")
        except sqlite3.OperationalError:
            pass  # column already exists
    conn.commit()
    return conn


def db_insert_url(conn: sqlite3.Connection, url: str, now: str) -> tuple[int, bool]:
    """Upsert a URL. Returns (row_id, is_new)."""
    cur = conn.execute("SELECT id FROM urls WHERE url = ?", (url,))
    row = cur.fetchone()
    if row:
        conn.execute("UPDATE urls SET date_last_seen = ? WHERE id = ?", (now, row["id"]))
        conn.commit()
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
                der = ssock.getpeercert(binary_form=True)

        if not der:
            return result

        # getpeercert() returns {} with CERT_NONE — parse from DER bytes instead
        result["cert_fingerprint"] = hashlib.sha256(der).hexdigest()
        cert = _x509.load_der_x509_certificate(der, _crypto_backend())

        def _name_dict(name) -> dict:
            return {attr.oid.dotted_string: attr.value for attr in name}

        result["cert_subject"]    = json.dumps(_name_dict(cert.subject))
        result["cert_issuer"]     = json.dumps(_name_dict(cert.issuer))
        result["cert_valid_from"] = cert.not_valid_before_utc.isoformat()
        result["cert_valid_to"]   = cert.not_valid_after_utc.isoformat()

        try:
            san = cert.extensions.get_extension_for_class(_x509.SubjectAlternativeName)
            result["cert_san"] = json.dumps(san.value.get_values_for_type(_x509.DNSName))
        except _x509.ExtensionNotFound:
            result["cert_san"] = json.dumps([])

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


def crawl_url(url: str, ua: str, crawl_cfg: dict, ipinfo_token: str = "") -> dict:
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

            # Fingerprinting — skip for binary/non-HTML responses
            _ct = (data.get("content_type") or "").lower()
            _is_html = "html" in _ct or _ct == "" or "text" in _ct
            _is_zip_url = url.lower().split("?")[0].endswith(
                (".zip", ".rar", ".exe", ".gz", ".tar")
            )
            if _is_html and not _is_zip_url:
                try:
                    body_text_fp = body_bytes[:body_max_bytes].decode("utf-8", errors="replace")
                    m = re.search(r"<title[^>]*>(.*?)</title>", body_text_fp, re.I | re.S)
                    if m:
                        data["page_title"] = m.group(1).strip()[:512]
                    m = re.search(r'<form\b[^>]*?\saction\s*=\s*["\']([^"\']*)["\']', body_text_fp, re.I)
                    if m and m.group(1).strip():
                        data["form_action"] = m.group(1).strip()[:512]
                except Exception:
                    pass

            if capture_body:
                try:
                    data["response_body"] = body_bytes[:body_max_bytes].decode("utf-8", errors="replace")
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

    # IP resolution + TLS cert probe (independent of HTTP crawl success)
    parsed = urlparse(url)
    host   = parsed.hostname
    if host:
        try:
            data["ip_address"] = socket.gethostbyname(host)
        except Exception as exc:
            log.debug("  DNS lookup failed for %s: %s", host, exc)
        if data.get("ip_address") and ipinfo_token:
            data.update(get_ip_geo(data["ip_address"], ipinfo_token))
        if parsed.scheme == "https":
            port = parsed.port or 443
            data.update(get_cert_info(host, port, timeout=tls_timeout))

    return data


# ─── ipinfo.io geo / ASN lookup ───────────────────────────────────────────────

def get_ip_geo(ip: str, token: str) -> dict:
    """
    Look up geo location and ASN via the ipinfo.io Lite API.
    Lite response fields: asn, as_name, as_domain, country_code, country,
    continent_code, continent. No city on the free/lite tier.
    """
    result = {"geo_country": None, "geo_city": None, "asn": None, "asn_org": None}
    if not ip or not token:
        return result
    try:
        resp = requests.get(
            f"https://api.ipinfo.io/lite/{ip}",
            params={"token": token},
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
        result["geo_country"] = data.get("country_code")
        result["geo_city"]    = data.get("city")          # present on paid plans
        result["asn"]         = data.get("asn")           # already "AS15169" format
        result["asn_org"]     = data.get("as_name")
    except Exception as exc:
        log.debug("  ipinfo lookup failed for %s: %s", ip, exc)
    return result


# ─── Kit hunting (Python replacement for kitphishr) ──────────────────────────

def _kit_targets(url: str) -> list[str]:
    """
    Mirror kitphishr's GenerateTargets: walk path segments from deepest to root,
    emitting the raw path URL and a .zip variant at each level.

    https://evil.com/bank/login.php →
        https://evil.com/bank/login.php        (check as open dir)
        https://evil.com/bank/login.php.zip    (direct zip)
        https://evil.com/bank                  (check as open dir)
        https://evil.com/bank.zip              (direct zip)
        https://evil.com                       (check as open dir)
        [https://evil.com.zip skipped — fewer than 3 slashes]
    """
    parsed = urlparse(url)
    base  = f"{parsed.scheme}://{parsed.netloc}"
    paths = parsed.path.split("/")   # preserves leading empty string

    seen: set[str] = set()
    candidates: list[str] = []

    def add(u: str) -> None:
        if u not in seen:
            seen.add(u)
            candidates.append(u)

    for i in range(len(paths)):
        segment = paths[:len(paths) - i]
        tmp_url = base + "/".join(segment)
        add(tmp_url)

        zip_url = tmp_url + ".zip"
        # kitphishr skips http://example.com/.zip and http://example.com.zip
        if zip_url.endswith("/.zip") or zip_url.count("/") < 3:
            continue
        add(zip_url)

    return candidates


def _kit_save(content: bytes, zip_url: str, output_dir: str) -> str:
    """
    Mirror kitphishr's SaveResponse: derive filename by stripping all
    non-alphanumeric chars (except dots) from the full URL, then truncate
    to stay under the 255-char filesystem limit.
    """
    filename = re.sub(r"[^a-zA-Z0-9.]", "", zip_url)
    dest_str = str(Path(output_dir) / filename)
    if len(dest_str) >= 255:
        diff = len(dest_str) - 255
        dest_str = dest_str[:100] + dest_str[100 + diff:]
    dest = Path(dest_str)
    if not dest.exists():
        dest.write_bytes(content)
    return str(dest)


def find_phishing_kit(url: str, crawl_cfg: dict, output_dir: str) -> dict:
    """
    Hunt for a phishing kit zip — Python port of kitphishr.
    Probes each target URL: .zip URLs are checked by Content-Type + Content-Length;
    HTML responses are checked for Apache/Nginx open-directory titles.
    """
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    timeout  = int(crawl_cfg.get("timeout", 20))
    max_size = 100 * 1024 * 1024  # 100 MB — same as kitphishr

    ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36"
    session = requests.Session()
    session.headers["User-Agent"] = ua
    session.headers["Connection"] = "close"
    session.verify = False

    log_lines: list[str] = []

    def _fetch(target: str) -> tuple[requests.Response, bytes] | None:
        """
        Fetch target with stream=True and a wall-clock body-read timeout so a
        server that trickles data slowly can never hang the worker indefinitely.
        Returns (response, body_bytes) or None on failure.
        """
        try:
            r = session.get(target, timeout=timeout, stream=True, allow_redirects=True)
            if r.status_code != 200:
                r.close()
                return None
            t0 = time.monotonic()
            body = b""
            for chunk in r.iter_content(65536):
                body += chunk
                if len(body) >= max_size or (time.monotonic() - t0) > timeout:
                    break
            r.close()
            return r, body
        except Exception as exc:
            log_lines.append(f"probe {target}: {exc}")
        return None

    def _save_zip(body: bytes, zip_url: str) -> str | None:
        try:
            if len(body) > 0 and len(body) <= max_size and body[:2] == b"PK":
                return _kit_save(body, zip_url, output_dir)
        except Exception as exc:
            log_lines.append(f"save failed {zip_url}: {exc}")
        return None

    for candidate in _kit_targets(url):
        log.debug("  [kit] probing %s", candidate)
        result = _fetch(candidate)
        if result is None:
            continue
        r, body = result

        ct = r.headers.get("Content-Type", "")
        cl = r.headers.get("Content-Length", "")

        if candidate.endswith(".zip"):
            # Mirror kitphishr: Content-Type must contain "zip",
            # Content-Length must be present, positive, and under 100 MB
            try:
                content_length = int(cl)
            except (ValueError, TypeError):
                content_length = -1
            if "zip" in ct and 0 < content_length <= max_size:
                zip_path = _save_zip(body, candidate)
                if zip_path:
                    log.info("  [kit] zip from URL: %s → %s", candidate, zip_path)
                    log_lines.append(f"zip from URL: {candidate}")
                    session.close()
                    return {
                        "kitphishr_ran": 1, "kitphishr_status": "success",
                        "kitphishr_zip": zip_path,
                        "kitphishr_output": "\n".join(log_lines),
                    }

        elif "text/html" in ct:
            # Mirror kitphishr's ZipFromDir: look for "Index of /" in <title>
            body_text = body.decode("utf-8", errors="replace")
            m = re.search(r"<title[^>]*>(.*?)</title>", body_text, re.I | re.S)
            title = m.group(1) if m else ""
            if "Index of /" in title:
                for href in re.findall(r'href=["\']([^"\'?#]+\.zip)["\']', body_text, re.I):
                    # mirror kitphishr URL construction
                    if href.startswith("http"):
                        zip_url = href
                    elif href.startswith("/"):
                        zip_url = f"{urlparse(candidate).scheme}://{urlparse(candidate).netloc}{href}"
                    else:
                        zip_url = candidate.rstrip("/") + "/" + href
                    result2 = _fetch(zip_url)
                    if result2 is None:
                        continue
                    _, body2 = result2
                    zip_path = _save_zip(body2, zip_url)
                    if zip_path:
                        log.info("  [kit] zip from open dir: %s → %s", zip_url, zip_path)
                        log_lines.append(f"zip from open dir: {zip_url}")
                        session.close()
                        return {
                            "kitphishr_ran": 1, "kitphishr_status": "success",
                            "kitphishr_zip": zip_path,
                            "kitphishr_output": "\n".join(log_lines),
                        }

    session.close()
    return {
        "kitphishr_ran": 1, "kitphishr_status": "no_kit_found",
        "kitphishr_zip": None,
        "kitphishr_output": "\n".join(log_lines),
    }


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


# ─── URL defanging ────────────────────────────────────────────────────────────

def _defang(url: str) -> str:
    """
    Defang a URL so it cannot be clicked or auto-linked in chat apps.
    https://evil.com/path  →  hxxps://evil[.]com/path
    """
    url = url.replace("https://", "hxxps://").replace("http://", "hxxp://")
    # Replace dots in the hostname only (up to the first slash after the scheme)
    scheme_end = url.find("//")
    if scheme_end == -1:
        return url
    path_start = url.find("/", scheme_end + 2)
    host_part  = url[scheme_end + 2 : path_start] if path_start != -1 else url[scheme_end + 2:]
    rest       = url[path_start:] if path_start != -1 else ""
    host_part  = host_part.replace(".", "[.]")
    return url[: scheme_end + 2] + host_part + rest


# ─── Telegram notifications ───────────────────────────────────────────────────

def send_telegram(token: str, chat_id: str, text: str) -> None:
    try:
        resp = requests.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json={"chat_id": chat_id, "text": text, "parse_mode": "HTML"},
            timeout=15,
        )
        resp.raise_for_status()
        log.debug("Telegram notification sent")
    except Exception as exc:
        log.warning("Telegram notification failed: %s", exc)


def _build_telegram_message(kit_hits: list[dict], total_processed: int) -> str:
    lines = [
        f"🎣 <b>phishnet run complete</b>",
        f"🔍 Processed: {total_processed} URLs",
        f"📦 Kits found: {len(kit_hits)}",
    ]
    if kit_hits:
        lines.append("")
        for hit in kit_hits:
            lines.append(f"🌐 <code>{_defang(hit['url'])}</code>")
            if hit.get("ip_address"):
                lines.append(f"   IP: {hit['ip_address']}")
            if hit.get("page_title"):
                lines.append(f"   Title: {hit['page_title'][:80]}")
            if hit.get("urlscan_result_url"):
                lines.append(f"   urlscan: {hit['urlscan_result_url']}")
            lines.append("")
    return "\n".join(lines).strip()


# ─── Slack notifications ──────────────────────────────────────────────────────

def send_slack(webhook_url: str, text: str) -> None:
    try:
        resp = requests.post(
            webhook_url,
            json={"text": text},
            timeout=15,
        )
        resp.raise_for_status()
        log.debug("Slack notification sent")
    except Exception as exc:
        log.warning("Slack notification failed: %s", exc)


def _build_slack_message(kit_hits: list[dict], total_processed: int) -> str:
    lines = [
        f"🎣 *phishnet run complete*",
        f"🔍 Processed: {total_processed} URLs",
        f"📦 Kits found: {len(kit_hits)}",
    ]
    if kit_hits:
        lines.append("")
        for hit in kit_hits:
            lines.append(f"🌐 `{_defang(hit['url'])}`")
            if hit.get("ip_address"):
                lines.append(f"   IP: {hit['ip_address']}")
            if hit.get("page_title"):
                lines.append(f"   Title: {hit['page_title'][:80]}")
            if hit.get("urlscan_result_url"):
                lines.append(f"   urlscan: {hit['urlscan_result_url']}")
            lines.append("")
    return "\n".join(lines).strip()


# ─── urlscan.io ───────────────────────────────────────────────────────────────

def submit_urlscan(url: str, api_key: str, visibility: str = "public", tags: list | None = None) -> dict:
    payload: dict = {"url": url, "visibility": visibility}
    if tags:
        payload["tags"] = tags
    log.debug("  urlscan.io payload: %s", payload)
    try:
        resp = requests.post(
            "https://urlscan.io/api/v1/scan/",
            headers={"API-Key": api_key, "Content-Type": "application/json"},
            json=payload,
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        confirmed_visibility = data.get("visibility", "unknown")
        log.info("  urlscan.io submitted %s → %s  (visibility: %s)",
                 url, data.get("result"), confirmed_visibility)
        return {
            "urlscan_uuid":       data.get("uuid"),
            "urlscan_result_url": data.get("result"),
        }
    except requests.exceptions.HTTPError as exc:
        log.warning("  urlscan.io submission failed for %s: %s — %s",
                    url, exc, exc.response.text[:300] if exc.response else "")
        return {}
    except Exception as exc:
        log.warning("  urlscan.io submission failed for %s: %s", url, exc)
        return {}


# ─── Extra URL file ingestion ─────────────────────────────────────────────────

def load_extra_urls(path: str) -> set[str]:
    """
    Load URLs from a plain text file (one per line, # comments supported).
    Applies the same scheme-fixing and validation as feed ingestion.
    Returns an empty set if the file doesn't exist.
    """
    p = Path(path)
    if not p.exists():
        log.debug("Extra URLs file not found, skipping: %s", path)
        return set()

    urls: set[str] = set()
    for raw in p.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        line = _ensure_scheme(line)
        if _is_valid_url(line):
            urls.add(_normalize(line))

    log.info("Extra URLs file: %d URLs loaded from %s", len(urls), path)
    return urls


# ─── Per-URL worker (runs in thread pool) ────────────────────────────────────

def _process_url(
    url: str,
    ua_cfg: dict, crawl_cfg: dict,
    do_kit_hunt: bool, kit_dir: str,
    ipinfo_token: str = "",
) -> tuple[str, dict]:
    # Kit hunt first — crawl metadata only collected when a kit is found
    # so we don't waste network requests on the majority of URLs
    if do_kit_hunt:
        log.info("  Hunting kit for %s", url)
        kit_data = find_phishing_kit(url, crawl_cfg, kit_dir)
        if kit_data.get("kitphishr_status") != "success":
            return url, kit_data

    ua = pick_ua(ua_cfg)
    log.info("  Crawling %s  (UA: %s)", url, ua[:60])
    crawl_data = crawl_url(url, ua, crawl_cfg, ipinfo_token)
    if do_kit_hunt:
        crawl_data.update(kit_data)
    return url, crawl_data


# ─── Main collection run ──────────────────────────────────────────────────────

def run_collection(cfg: dict, crawl_all: bool = False, extra_urls_file: str | None = None):
    s          = cfg["settings"]
    ua_cfg     = cfg.get("user_agents", {})
    crawl_cfg  = cfg.get("crawling", {})

    data_dir = Path(s.get("data_dir", "./data"))
    data_dir.mkdir(parents=True, exist_ok=True)

    db_path      = s.get("db_path", str(data_dir / "phishnet.db"))
    do_kit_hunt  = bool(s.get("run_kit_hunt", True))
    kit_dir      = s.get("kit_output_dir", str(data_dir / "kits"))

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

    # ── 1b. Ingest extra URLs file (CLI flag or config setting) ───────────────
    extra_file = extra_urls_file or s.get("extra_urls_file") or ""
    if extra_file:
        all_urls.update(load_extra_urls(extra_file))
        log.info("Total unique URLs after merging extra file: %d", len(all_urls))

    if not all_urls:
        log.warning("No URLs collected from any source — skipping run to avoid corrupting seen-URL history")
        return

    # ── 2. Load previously seen URLs — stream line-by-line (no giant string) ──
    previous_urls: set[str] = set()
    if current_file.exists():
        with current_file.open(encoding="utf-8") as fh:
            previous_urls = {line.strip() for line in fh if line.strip()}
        log.info("Previously seen URLs: %d", len(previous_urls))

    new_urls = all_urls - previous_urls
    log.info("New URLs this run: %d", len(new_urls))

    # Determine which URLs to process BEFORE all_urls is mutated below
    urls_to_process: list[str] = sorted(all_urls if crawl_all else new_urls)

    # ── 3. Write union of all seen URLs (never shrinks on feed failure) ───────
    # Merge in-place so we avoid creating a third set, then free previous_urls.
    all_urls |= previous_urls
    del previous_urls
    if current_file.exists():
        shutil.copy2(current_file, backup_file)
    with current_file.open("w", encoding="utf-8") as fh:  # line-by-line — avoids huge string in memory
        for url in sorted(all_urls):
            fh.write(url + "\n")
    log.info("Seen-URL list written (%d URLs) → %s", len(all_urls), current_file)
    del all_urls   # no longer needed; free memory before processing

    # ── 4. Write timestamped new-URL file (kept forever) ─────────────────────
    if new_urls:
        new_file = data_dir / f"new_phishing_urls_{_ts()}.txt"
        with new_file.open("w", encoding="utf-8") as fh:
            for url in sorted(new_urls):
                fh.write(url + "\n")
        log.info("New URLs file → %s", new_file)

    # ── 5. Open DB — urls/crawls only written for kit hits ────────────────────
    conn    = open_db(db_path)
    now     = _utcnow()
    urlscan_key        = cfg.get("urlscan", {}).get("api_key") or ""
    urlscan_visibility = cfg.get("urlscan", {}).get("visibility", "public")
    urlscan_tags       = cfg.get("urlscan", {}).get("tags") or ["phishing", "phishnet"]
    tg_token      = cfg.get("telegram", {}).get("bot_token") or ""
    tg_chat_id    = cfg.get("telegram", {}).get("chat_id") or ""
    slack_webhook = cfg.get("slack", {}).get("webhook_url") or ""
    ipinfo_token  = s.get("ipinfo_token") or ""
    kit_hits: list[dict] = []

    del new_urls

    total      = len(urls_to_process)
    workers    = int(s.get("crawl_workers", 5))
    batch_size = int(s.get("batch_size", 500))
    log.info("URLs to process: %d  workers: %d  batch: %d",
             total, workers, batch_size)

    # ── 6. Crawl + kit hunt (parallel, batched) ───────────────────────────────
    # Submit in fixed-size batches so at most `batch_size` Future objects exist
    # in memory at once — critical for large URL sets (500k+).
    def _batched(iterable: list, n: int):
        for i in range(0, len(iterable), n):
            yield iterable[i:i + n]

    done = 0
    with ThreadPoolExecutor(max_workers=workers) as executor:
      for batch in _batched(urls_to_process, batch_size):
        future_to_url = {
            executor.submit(
                _process_url,
                url, ua_cfg, crawl_cfg,
                do_kit_hunt, kit_dir, ipinfo_token,
            ): url
            for url in batch
        }
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            done += 1
            try:
                result_url, crawl_data = future.result()
                kit_found = crawl_data.get("kitphishr_status") == "success"
                if kit_found:
                    if urlscan_key:
                        crawl_data.update(submit_urlscan(
                            result_url, urlscan_key, urlscan_visibility, urlscan_tags,
                        ))
                    url_id, _ = db_insert_url(conn, result_url, now)
                    db_insert_crawl(conn, url_id, crawl_data)
                    kit_hits.append({
                        "url":               result_url,
                        "ip_address":        crawl_data.get("ip_address"),
                        "page_title":        crawl_data.get("page_title"),
                        "urlscan_result_url": crawl_data.get("urlscan_result_url"),
                    })
                    log.info("[%d/%d] KIT FOUND — saved %s  http=%s  ip=%s  title=%s",
                             done, total, result_url,
                             crawl_data.get("http_status", "-"),
                             crawl_data.get("ip_address", "-"),
                             (crawl_data.get("page_title") or "-")[:60])
                else:
                    log.info("[%d/%d] no kit  %s", done, total, result_url)
            except Exception as exc:
                log.error("[%d/%d] failed %s — %s", done, total, url, exc)

    conn.close()
    log.info("=" * 60)
    log.info("Run complete. Kits found: %d / %d processed. DB: %s",
             len(kit_hits), total, db_path)
    log.info("=" * 60)

    notify_empty = (cfg.get("telegram", {}).get("notify_empty_runs")
                    or cfg.get("slack", {}).get("notify_empty_runs"))

    if kit_hits or notify_empty:
        if tg_token and tg_chat_id:
            send_telegram(tg_token, tg_chat_id, _build_telegram_message(kit_hits, total))
        if slack_webhook:
            send_slack(slack_webhook, _build_slack_message(kit_hits, total))


# ─── Logging setup ────────────────────────────────────────────────────────────

class _ColorFormatter(logging.Formatter):
    """Colored console formatter — applied to StreamHandler only."""
    _LEVEL = {
        logging.DEBUG:    Style.DIM,
        logging.WARNING:  Fore.YELLOW,
        logging.ERROR:    Fore.RED + Style.BRIGHT,
        logging.CRITICAL: Fore.RED + Style.BRIGHT,
    }
    _KIT = Fore.GREEN + Style.BRIGHT

    def format(self, record: logging.LogRecord) -> str:
        msg = super().format(record)
        if "KIT FOUND" in msg or "[kit] zip" in msg:
            return self._KIT + msg
        color = self._LEVEL.get(record.levelno, "")
        return color + msg if color else msg


def setup_logging(level_name: str, log_file: str | None):
    level = getattr(logging, level_name.upper(), logging.INFO)
    fmt      = "%(asctime)s [%(levelname)-8s] %(message)s"
    datefmt  = "%Y-%m-%dT%H:%M:%S"

    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(_ColorFormatter(fmt=fmt, datefmt=datefmt))

    handlers: list[logging.Handler] = [console]
    if log_file:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(logging.Formatter(fmt=fmt, datefmt=datefmt))
        handlers.append(file_handler)

    logging.basicConfig(level=level, handlers=handlers)


# ─── Entry point ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Phishing URL feed collector & crawler")
    parser.add_argument("--config",            default="config.yaml", help="Config YAML (default: config.yaml)")
    parser.add_argument("--daemon",            action="store_true",   help="Run continuously on internal schedule")
    parser.add_argument("--crawl-all",         action="store_true",   help="(Re)crawl all URLs, not just new ones")
    parser.add_argument("--extra-urls",        default=None,          help="Path to a text file of extra URLs to ingest this run")
    parser.add_argument("--send-test-message", action="store_true",   help="Send a Telegram test message and exit")
    args = parser.parse_args()

    with open(args.config) as f:
        cfg = yaml.safe_load(f)

    s = cfg.get("settings", {})
    setup_logging(s.get("log_level", "INFO"), s.get("log_file") or None)

    if args.send_test_message:
        sent = False
        tg = cfg.get("telegram", {})
        if tg.get("bot_token") and tg.get("chat_id"):
            send_telegram(tg["bot_token"], tg["chat_id"],
                          "✅ <b>phishnet</b> — Telegram test message. Configuration works!")
            log.info("Telegram test message sent")
            sent = True
        sl = cfg.get("slack", {})
        if sl.get("webhook_url"):
            send_slack(sl["webhook_url"],
                       "✅ *phishnet* — Slack test message. Configuration works!")
            log.info("Slack test message sent")
            sent = True
        if not sent:
            log.error("No notification service configured (telegram or slack)")
            sys.exit(1)
        sys.exit(0)

    if args.daemon:
        interval_hours = int(s.get("interval_hours", 6))
        log.info("Daemon mode — interval: %d hours", interval_hours)

        def _job():
            run_collection(cfg, crawl_all=args.crawl_all, extra_urls_file=args.extra_urls)

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
        run_collection(cfg, crawl_all=args.crawl_all, extra_urls_file=args.extra_urls)


if __name__ == "__main__":
    main()
