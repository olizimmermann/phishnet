#!/usr/bin/env python3
"""
repair_db.py — Re-crawl kit-hit URLs that have NULL fingerprinting fields.

Only fills NULL fields — never overwrites existing data.
If a target is unreachable the existing row is left completely untouched.

Usage:
    python repair_db.py
    python repair_db.py --config config.yaml
    python repair_db.py --fields ip_address,page_title,cert_subject
    python repair_db.py --limit 100 --workers 5
    python repair_db.py --dry-run
"""

import argparse
import sqlite3
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import yaml

# Import crawl helpers from collector — no code duplication
from collector import crawl_url, pick_ua, setup_logging, log

# ── Fields that can be repaired by re-crawling ────────────────────────────────
REPAIRABLE = [
    "http_status",
    "final_url",
    "content_type",
    "server",
    "x_powered_by",
    "ip_address",
    "page_title",
    "form_action",
    "cert_subject",
    "cert_issuer",
    "cert_valid_from",
    "cert_valid_to",
    "cert_san",
    "cert_fingerprint",
]


def find_incomplete(conn: sqlite3.Connection, fields: list[str], limit: int) -> list[dict]:
    """Return crawl rows that have at least one NULL in the requested fields."""
    null_checks = " OR ".join(f"c.{f} IS NULL" for f in fields)
    select_fields = ", ".join(f"c.{f}" for f in fields)
    query = f"""
        SELECT c.id, u.url, {select_fields}
        FROM crawls c
        JOIN urls u ON u.id = c.url_id
        WHERE {null_checks}
        ORDER BY c.crawl_date DESC
        LIMIT ?
    """
    rows = conn.execute(query, (limit,)).fetchall()
    return [dict(r) for r in rows]


def repair_row(
    row: dict,
    fields: list[str],
    ua_cfg: dict,
    crawl_cfg: dict,
    dry_run: bool,
    conn: sqlite3.Connection,
) -> tuple[int, int]:
    """
    Re-crawl a single URL and update only the NULL fields that come back
    with a real value. Returns (fields_updated, fields_skipped).
    """
    url = row["url"]
    ua  = pick_ua(ua_cfg)

    log.info("  Recrawling %s", url)
    new_data = crawl_url(url, ua, crawl_cfg)

    # Only update a field if:
    #   1. It was NULL in the DB (no overwrite)
    #   2. The new crawl returned a non-None value (page was reachable enough)
    updated = 0
    skipped = 0

    for field in fields:
        old_val = row.get(field)
        new_val = new_data.get(field)

        if old_val is not None:
            # Already has data — skip
            continue

        if new_val is None:
            # Page didn't return this field (down, no title, etc.) — skip
            skipped += 1
            continue

        log.debug("    %s: NULL → %s", field, str(new_val)[:80])
        if not dry_run:
            # AND field IS NULL guard: prevents overwriting a concurrent update
            conn.execute(
                f"UPDATE crawls SET {field} = ? WHERE id = ? AND {field} IS NULL",
                (new_val, row["id"]),
            )
        updated += 1

    if updated and not dry_run:
        conn.commit()

    return updated, skipped


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Re-crawl kit hits with missing DB fields",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--config",  default="config.yaml")
    parser.add_argument("--fields",  default=",".join(REPAIRABLE),
                        help=f"Comma-separated fields to repair (default: all {len(REPAIRABLE)})")
    parser.add_argument("--limit",   type=int, default=500,
                        help="Max rows to process per run (default: 500)")
    parser.add_argument("--workers", type=int, default=5,
                        help="Parallel crawl workers (default: 5)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show what would be updated without writing")
    args = parser.parse_args()

    with open(args.config, encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh)

    s          = cfg.get("settings", {})
    ua_cfg     = cfg.get("user_agents", {})
    crawl_cfg  = cfg.get("crawling", {})
    db_path    = s.get("db_path", "./data/phishnet.db")

    setup_logging(s.get("log_level", "INFO"), None)  # console only

    fields = [f.strip() for f in args.fields.split(",") if f.strip() in REPAIRABLE]
    if not fields:
        log.error("No valid fields specified. Available: %s", ", ".join(REPAIRABLE))
        sys.exit(1)

    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row

    rows = find_incomplete(conn, fields, args.limit)
    total = len(rows)

    if not rows:
        log.info("Nothing to repair — all checked fields are populated.")
        conn.close()
        return

    log.info("Found %d rows with at least one NULL in: %s", total, ", ".join(fields))
    if args.dry_run:
        log.info("DRY RUN — no changes will be written")

    total_updated = 0
    total_skipped = 0
    done = 0

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        future_map = {
            executor.submit(repair_row, row, fields, ua_cfg, crawl_cfg, args.dry_run, conn): row
            for row in rows
        }
        for future in as_completed(future_map):
            row  = future_map[future]
            done += 1
            try:
                updated, skipped = future.result()
                total_updated += updated
                total_skipped += skipped
                log.info("[%d/%d] %s — filled %d field(s), %d still empty",
                         done, total, row["url"], updated, skipped)
            except Exception as exc:
                log.error("[%d/%d] %s — error: %s", done, total, row["url"], exc)

    conn.close()

    log.info("Done — %d field(s) updated across %d rows (%s)",
             total_updated, total,
             "dry run, nothing written" if args.dry_run else "committed")


if __name__ == "__main__":
    main()
