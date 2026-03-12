#!/usr/bin/env python3
"""
export_stats.py — Generate stats.json and feed.txt for the phishnet.cc dashboard.
Run via cron after each collector.py run.

Usage:
    python export_stats.py
    python export_stats.py --config /path/to/config.yaml
    python export_stats.py --output /path/to/output/dir
"""

import argparse
import json
import sqlite3
from datetime import datetime, timezone, timedelta
from pathlib import Path

import yaml


def _defang(url: str) -> str:
    url = url.replace("https://", "hxxps://").replace("http://", "hxxp://")
    scheme_end = url.find("//")
    if scheme_end == -1:
        return url
    path_start = url.find("/", scheme_end + 2)
    host = url[scheme_end + 2 : path_start] if path_start != -1 else url[scheme_end + 2:]
    rest = url[path_start:] if path_start != -1 else ""
    return url[: scheme_end + 2] + host.replace(".", "[.]") + rest


def export(cfg: dict, output_dir: Path) -> None:
    s        = cfg["settings"]
    db_path  = s.get("db_path", "./data/phishnet.db")
    data_dir = Path(s.get("data_dir", "./data"))
    output_dir.mkdir(parents=True, exist_ok=True)

    # Open DB strictly read-only
    conn = sqlite3.connect(f"file:{Path(db_path).resolve()}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row

    now       = datetime.now(timezone.utc)
    cut_24h   = (now - timedelta(hours=24)).isoformat(timespec="seconds")
    cut_7d    = (now - timedelta(days=7)).isoformat(timespec="seconds")
    cut_30d   = (now - timedelta(days=30)).isoformat(timespec="seconds")

    # ── Aggregate stats ───────────────────────────────────────────────────────
    total_kits = conn.execute("SELECT COUNT(*) FROM urls").fetchone()[0]
    total_ips  = conn.execute(
        "SELECT COUNT(DISTINCT ip_address) FROM crawls WHERE ip_address IS NOT NULL"
    ).fetchone()[0]
    kits_24h = conn.execute(
        "SELECT COUNT(*) FROM crawls WHERE crawl_date >= ?", (cut_24h,)
    ).fetchone()[0]
    kits_7d = conn.execute(
        "SELECT COUNT(*) FROM crawls WHERE crawl_date >= ?", (cut_7d,)
    ).fetchone()[0]

    # ── Recent kit hits ───────────────────────────────────────────────────────
    recent_rows = conn.execute("""
        SELECT u.url, c.ip_address, c.page_title, c.crawl_date,
               c.cert_issuer, c.urlscan_result_url, c.http_status, c.form_action
        FROM crawls c JOIN urls u ON u.id = c.url_id
        ORDER BY c.crawl_date DESC
        LIMIT 25
    """).fetchall()

    # ── Kit discoveries over time (last 30 days, daily) ───────────────────────
    timeline_rows = conn.execute("""
        SELECT DATE(crawl_date) as day, COUNT(*) as count
        FROM crawls
        WHERE crawl_date >= ?
        GROUP BY day
        ORDER BY day
    """, (cut_30d,)).fetchall()

    # ── Top hosting IPs ───────────────────────────────────────────────────────
    top_ip_rows = conn.execute("""
        SELECT ip_address, COUNT(*) as count
        FROM crawls
        WHERE ip_address IS NOT NULL
        GROUP BY ip_address
        ORDER BY count DESC
        LIMIT 10
    """).fetchall()

    # ── Most impersonated brands (page titles) ────────────────────────────────
    brand_rows = conn.execute("""
        SELECT page_title, COUNT(*) as count
        FROM crawls
        WHERE page_title IS NOT NULL AND TRIM(page_title) != ''
        GROUP BY page_title
        ORDER BY count DESC
        LIMIT 15
    """).fetchall()

    conn.close()

    # ── Total URLs seen (from accumulator file) ───────────────────────────────
    urls_file = data_dir / "phishing_urls.txt"
    total_urls_seen = 0
    if urls_file.exists():
        with urls_file.open(encoding="utf-8") as fh:
            total_urls_seen = sum(1 for line in fh if line.strip() and not line.startswith("#"))

    # ── Assemble stats.json ───────────────────────────────────────────────────
    stats = {
        "generated_at": now.isoformat(timespec="seconds"),
        "stats": {
            "total_urls_seen":  total_urls_seen,
            "total_kit_hits":   total_kits,
            "total_unique_ips": total_ips,
            "kits_last_24h":    kits_24h,
            "kits_last_7d":     kits_7d,
        },
        "recent_kits": [
            {
                "url":               _defang(r["url"]),
                "ip_address":        r["ip_address"],
                "page_title":        r["page_title"],
                "crawl_date":        r["crawl_date"],
                "cert_issuer":       r["cert_issuer"],
                "urlscan_result_url": r["urlscan_result_url"],
                "http_status":       r["http_status"],
                "form_action":       _defang(r["form_action"]) if r["form_action"] else None,
            }
            for r in recent_rows[:5]
        ],
        "kits_over_time": [
            {"date": r["day"], "count": r["count"]} for r in timeline_rows
        ],
        "top_ips": [
            {"ip": r["ip_address"], "count": r["count"]} for r in top_ip_rows
        ],
        "top_titles": [
            {"title": r["page_title"], "count": r["count"]} for r in brand_rows
        ],
    }

    stats_file = output_dir / "stats.json"
    stats_file.write_text(json.dumps(stats, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[export] stats.json → {stats_file}  ({total_kits} kit hits)")

    # ── Write feed.txt ────────────────────────────────────────────────────────
    # Serve the latest 1000 entries from the seen-URL accumulator (actual URLs,
    # not defanged — suitable for tool ingestion).
    feed_file = output_dir / "feed.txt"
    if urls_file.exists():
        with urls_file.open(encoding="utf-8") as fh:
            all_urls = [l.strip() for l in fh if l.strip() and not l.startswith("#")]
        with feed_file.open("w", encoding="utf-8") as fh:
            fh.write(f"# phishnet.cc — Phishing URL Feed\n")
            fh.write(f"# Updated: {now.isoformat(timespec='seconds')}\n")
            fh.write(f"# Total tracked: {len(all_urls)}\n")
            fh.write(f"# Showing: latest 1000\n#\n")
            for url in all_urls[-1000:]:
                fh.write(url + "\n")
        print(f"[export] feed.txt  → {feed_file}  ({min(len(all_urls), 1000)} URLs)")
    else:
        print("[export] feed.txt skipped — phishing_urls.txt not found")


def main() -> None:
    parser = argparse.ArgumentParser(description="Export phishnet stats for the web dashboard")
    parser.add_argument("--config", default="config.yaml", help="Config YAML (default: config.yaml)")
    parser.add_argument("--output", default=None,          help="Output directory (default: data_dir from config)")
    args = parser.parse_args()

    with open(args.config, encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh)

    out = Path(args.output) if args.output else Path(cfg["settings"].get("data_dir", "./data"))
    export(cfg, out)


if __name__ == "__main__":
    main()
