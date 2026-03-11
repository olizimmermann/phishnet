#!/usr/bin/env python3
"""
repair_db.py — Re-crawl kit-hit URLs that have NULL fingerprinting fields,
               and/or backfill missing urlscan.io submissions.

Only fills NULL fields — never overwrites existing data.
If a target is unreachable the existing row is left completely untouched.

Usage:
    python repair_db.py
    python repair_db.py --config config.yaml
    python repair_db.py --fields ip_address,page_title,cert_subject
    python repair_db.py --limit 100 --workers 5
    python repair_db.py --submit-urlscan
    python repair_db.py --submit-urlscan --fields ""   # urlscan only, skip crawl repair
    python repair_db.py --dry-run
"""

import argparse
import sqlite3
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import yaml

# Import helpers from collector — no code duplication
from collector import crawl_url, pick_ua, setup_logging, submit_urlscan, log

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

# Fields that only make sense for HTML pages — skip .zip/.rar/.exe URLs
HTML_ONLY_FIELDS = {"page_title", "form_action"}


def find_incomplete(conn: sqlite3.Connection, fields: list[str], limit: int) -> list[dict]:
    """Return crawl rows that have at least one NULL in the requested fields."""
    null_checks   = " OR ".join(f"c.{f} IS NULL" for f in fields)
    select_fields = ", ".join(f"c.{f}" for f in fields)

    # If all requested fields are HTML-only, exclude binary file URLs entirely —
    # they will never have titles or form actions regardless of retries.
    zip_exclusion = ""
    if all(f in HTML_ONLY_FIELDS for f in fields):
        zip_exclusion = "AND u.url NOT LIKE '%.zip' AND u.url NOT LIKE '%.rar' AND u.url NOT LIKE '%.exe'"

    query = f"""
        SELECT c.id, u.url, {select_fields}
        FROM crawls c
        JOIN urls u ON u.id = c.url_id
        WHERE ({null_checks})
        {zip_exclusion}
        ORDER BY c.crawl_date DESC
        LIMIT ?
    """
    return [dict(r) for r in conn.execute(query, (limit,)).fetchall()]


def find_missing_urlscan(conn: sqlite3.Connection, limit: int) -> list[dict]:
    """Return crawl rows that were never submitted to urlscan.io."""
    query = """
        SELECT c.id, u.url
        FROM crawls c
        JOIN urls u ON u.id = c.url_id
        WHERE c.urlscan_uuid IS NULL
        ORDER BY c.crawl_date DESC
        LIMIT ?
    """
    return [dict(r) for r in conn.execute(query, (limit,)).fetchall()]


def repair_row(
    row: dict,
    fields: list[str],
    ua_cfg: dict,
    crawl_cfg: dict,
    dry_run: bool,
    conn: sqlite3.Connection,
) -> tuple[int, int]:
    """Re-crawl and update only NULL fields that come back with a real value."""
    url     = row["url"]
    ua      = pick_ua(ua_cfg)
    new_data = crawl_url(url, ua, crawl_cfg)

    updated = skipped = 0
    for field in fields:
        if row.get(field) is not None:
            continue                       # already populated — never overwrite
        new_val = new_data.get(field)
        if new_val is None:
            skipped += 1
            continue
        log.debug("    %s: NULL → %s", field, str(new_val)[:80])
        if not dry_run:
            conn.execute(
                f"UPDATE crawls SET {field} = ? WHERE id = ? AND {field} IS NULL",
                (new_val, row["id"]),
            )
        updated += 1

    if updated and not dry_run:
        conn.commit()
    return updated, skipped


def submit_urlscan_row(
    row: dict,
    api_key: str,
    visibility: str,
    tags: list,
    dry_run: bool,
    conn: sqlite3.Connection,
) -> bool:
    """Submit a single URL to urlscan.io and store the result. Returns True on success."""
    url = row["url"]
    if dry_run:
        log.info("  [dry-run] would submit %s", url)
        return True

    result = submit_urlscan(url, api_key, visibility, tags)
    if result.get("urlscan_uuid"):
        conn.execute(
            """UPDATE crawls
               SET urlscan_uuid = ?, urlscan_result_url = ?
               WHERE id = ? AND urlscan_uuid IS NULL""",
            (result["urlscan_uuid"], result.get("urlscan_result_url"), row["id"]),
        )
        conn.commit()
        return True
    return False


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Repair NULL fields and/or backfill urlscan.io submissions",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--config",         default="config.yaml")
    parser.add_argument("--fields",         default=",".join(REPAIRABLE),
                        help=f"Comma-separated crawl fields to repair (default: all). Pass \"\" to skip crawl repair.")
    parser.add_argument("--limit",          type=int, default=500,
                        help="Max rows per operation (default: 500)")
    parser.add_argument("--workers",        type=int, default=5,
                        help="Parallel workers for crawl repair (default: 5)")
    parser.add_argument("--submit-urlscan", action="store_true",
                        help="Backfill urlscan.io submissions for rows missing urlscan_uuid")
    parser.add_argument("--dry-run",        action="store_true",
                        help="Show what would be updated without writing")
    args = parser.parse_args()

    with open(args.config, encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh)

    s         = cfg.get("settings", {})
    ua_cfg    = cfg.get("user_agents", {})
    crawl_cfg = cfg.get("crawling", {})
    db_path   = s.get("db_path", "./data/phishnet.db")

    setup_logging(s.get("log_level", "INFO"), None)

    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row

    # ── 1. Crawl field repair ─────────────────────────────────────────────────
    fields = [f.strip() for f in args.fields.split(",") if f.strip() in REPAIRABLE]

    if fields:
        rows  = find_incomplete(conn, fields, args.limit)
        total = len(rows)

        if not rows:
            log.info("Crawl repair: nothing to do — all checked fields are populated.")
        else:
            log.info("Crawl repair: %d rows with NULL in: %s", total, ", ".join(fields))
            if args.dry_run:
                log.info("DRY RUN — no changes will be written")

            total_updated = total_skipped = done = 0
            with ThreadPoolExecutor(max_workers=args.workers) as executor:
                future_map = {
                    executor.submit(
                        repair_row, row, fields, ua_cfg, crawl_cfg, args.dry_run, conn
                    ): row
                    for row in rows
                }
                for future in as_completed(future_map):
                    row   = future_map[future]
                    done += 1
                    try:
                        updated, skipped  = future.result()
                        total_updated    += updated
                        total_skipped    += skipped
                        log.info("[%d/%d] %s — filled %d, still empty %d",
                                 done, total, row["url"], updated, skipped)
                    except Exception as exc:
                        log.error("[%d/%d] %s — %s", done, total, row["url"], exc)

            log.info("Crawl repair done — %d field(s) filled across %d rows%s",
                     total_updated, total,
                     " (dry run)" if args.dry_run else "")

    # ── 2. urlscan.io backfill ────────────────────────────────────────────────
    if args.submit_urlscan:
        us_cfg     = cfg.get("urlscan", {})
        api_key    = us_cfg.get("api_key") or ""
        visibility = us_cfg.get("visibility", "public")
        tags       = us_cfg.get("tags") or ["phishing", "phishnet"]

        if not api_key:
            log.error("urlscan backfill: no api_key set in config — aborting")
            conn.close()
            sys.exit(1)

        rows  = find_missing_urlscan(conn, args.limit)
        total = len(rows)

        if not rows:
            log.info("urlscan backfill: nothing to do — all rows already submitted.")
        else:
            log.info("urlscan backfill: %d rows missing urlscan_uuid", total)
            if args.dry_run:
                log.info("DRY RUN — no submissions will be made")

            submitted = failed = 0
            for i, row in enumerate(rows, 1):
                ok = submit_urlscan_row(row, api_key, visibility, tags, args.dry_run, conn)
                if ok:
                    submitted += 1
                    log.info("[%d/%d] submitted %s", i, total, row["url"])
                else:
                    failed += 1
                    log.warning("[%d/%d] failed   %s", i, total, row["url"])
                # urlscan rate limit: ~4 submissions/sec on free tier — be safe
                if not args.dry_run:
                    time.sleep(0.3)

            log.info("urlscan backfill done — %d submitted, %d failed%s",
                     submitted, failed, " (dry run)" if args.dry_run else "")

    conn.close()


if __name__ == "__main__":
    main()
