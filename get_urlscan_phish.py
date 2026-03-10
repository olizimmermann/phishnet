#!/usr/bin/env python3
"""
get_urlscan_phish.py — Fetch phishing URLs from urlscan.io

API key is read automatically from the phishnet config.yaml.

Usage:
    python get_urlscan_phish.py -o urlscan_urls.txt
    python get_urlscan_phish.py -o urlscan_urls.txt --exclude-tag phishnet
    python get_urlscan_phish.py -o urlscan_urls.txt --days 7 --max 5000
    python get_urlscan_phish.py -o urlscan_urls.txt --exclude-tag phishnet --exclude-tag automated
    python get_urlscan_phish.py --query "verdicts.malicious:true" -o out.txt
    python get_urlscan_phish.py -o urlscan_urls.txt --config /path/to/config.yaml
"""

import argparse
import sys
import time
from pathlib import Path

import requests
import yaml

# ── Config discovery ──────────────────────────────────────────────────────────

_CONFIG_CANDIDATES = [
    Path(__file__).parent / "config.yaml",          # same dir as this script
    Path.cwd() / "config.yaml",                      # current working dir
    Path.home() / ".config" / "phishnet" / "config.yaml",
]

SEARCH_URL = "https://urlscan.io/api/v1/search/"


def find_api_key(config_path: str | None) -> str:
    """Find and return the urlscan API key from config.yaml."""
    candidates = [Path(config_path)] if config_path else _CONFIG_CANDIDATES
    for path in candidates:
        if path.exists():
            try:
                cfg = yaml.safe_load(path.read_text(encoding="utf-8"))
                key = (cfg.get("urlscan") or {}).get("api_key") or ""
                if key:
                    _log(f"API key loaded from {path}")
                    return key
            except Exception as exc:
                _log(f"Could not parse {path}: {exc}")
    _log("No API key found in any config.yaml — proceeding unauthenticated (heavily rate-limited)")
    return ""


# ── Helpers ───────────────────────────────────────────────────────────────────

def _log(msg: str) -> None:
    print(f"[urlscan] {msg}", file=sys.stderr, flush=True)


def build_query(base: str, exclude_tags: list[str], days: int | None) -> str:
    """
    Combine the base query with tag exclusions and date range.
    Uses Elasticsearch Query String syntax supported by urlscan.
    """
    parts = [base]
    for tag in exclude_tags:
        parts.append(f'NOT task.tags:"{tag}"')
    if days:
        parts.append(f"date:>now-{days}d")
    return " ".join(parts)


# ── Fetching ──────────────────────────────────────────────────────────────────

def fetch(
    api_key: str,
    query: str,
    page_size: int,
    max_results: int,
) -> list[str]:
    """
    Page through urlscan search results, returning up to max_results URLs.
    Uses `search_after` for cursor-based pagination.
    """
    headers: dict = {}
    if api_key:
        headers["API-Key"] = api_key

    urls: list[str] = []
    search_after: str | None = None

    while len(urls) < max_results:
        want = min(page_size, max_results - len(urls))
        params: dict = {"q": query, "size": want}
        if search_after:
            params["search_after"] = search_after

        try:
            resp = requests.get(SEARCH_URL, headers=headers, params=params, timeout=30)
            resp.raise_for_status()
        except requests.exceptions.HTTPError as exc:
            body = exc.response.text[:300] if exc.response else ""
            _log(f"HTTP error: {exc} — {body}")
            break
        except Exception as exc:
            _log(f"Request failed: {exc}")
            break

        data = resp.json()
        results = data.get("results") or []

        if not results:
            _log("No more results.")
            break

        for r in results:
            # task.url = originally submitted phishing URL (what we want)
            # page.url = final URL after redirects (fallback)
            url = (r.get("task") or {}).get("url") or (r.get("page") or {}).get("url")
            if url:
                urls.append(url)

        _log(f"{len(urls)} URLs collected so far…")

        if not data.get("has_more", False):
            _log("Reached end of results.")
            break

        # Cursor for next page: comma-joined sort values from the last result
        last_sort = results[-1].get("sort")
        if not last_sort:
            break
        # sort is a list (e.g. [timestamp_ms, uuid])
        search_after = ",".join(str(v) for v in last_sort) \
            if isinstance(last_sort, list) else str(last_sort)

        time.sleep(0.5)   # be polite to the API

    return urls


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Fetch phishing URLs from urlscan.io search API",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "-o", "--output", default="-",
        help="Output file (default: stdout)",
    )
    parser.add_argument(
        "--exclude-tag", action="append", default=[], dest="exclude_tags", metavar="TAG",
        help="Exclude results tagged with TAG (repeatable)",
    )
    parser.add_argument(
        "--query",
        default="task.tags:phishing",
        help='Base Elasticsearch query (default: task.tags:phishing). '
             'Alternative: "verdicts.malicious:true" for all malicious scans.',
    )
    parser.add_argument(
        "--days", type=int, default=1,
        help="Limit to scans from the last N days (default: 1)",
    )
    parser.add_argument(
        "--max", type=int, default=1000, dest="max_results",
        help="Maximum URLs to fetch (default: 1000)",
    )
    parser.add_argument(
        "--size", type=int, default=100,
        help="Results per API page, max 100 (default: 100)",
    )
    parser.add_argument(
        "--config", default=None,
        help="Path to config.yaml (auto-detected if omitted)",
    )
    args = parser.parse_args()

    api_key = find_api_key(args.config)
    query   = build_query(args.query, args.exclude_tags, args.days)

    _log(f"Query: {query}")
    _log(f"Max results: {args.max_results}  Page size: {args.size}")

    raw_urls = fetch(api_key, query, args.size, args.max_results)

    # Deduplicate while preserving order
    seen: set[str] = set()
    unique: list[str] = []
    for url in raw_urls:
        if url not in seen:
            seen.add(url)
            unique.append(url)

    _log(f"Done — {len(unique)} unique URLs")

    content = "\n".join(unique) + ("\n" if unique else "")

    if args.output == "-":
        sys.stdout.write(content)
    else:
        Path(args.output).write_text(content, encoding="utf-8")
        _log(f"Saved → {args.output}")


if __name__ == "__main__":
    main()
