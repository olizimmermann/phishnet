#!/usr/bin/env python3
"""Archive old new_phishing_urls_*.txt files no longer needed by export_stats.py.

export_stats.py builds feed.txt by reading the per-run new_phishing_urls_*.txt
files newest-first until it has collected --feed-size (default 1000) unique
URLs.  Any file older than the set needed to cover that window is dead weight
in data/ and can be moved to data/archive_new_phishing/YYYY/MM/ without
changing the feed output.

A configurable safety margin (--keep-extra, default 5 files) is kept on top of
the strictly-needed set, so a shrinking feed window or a re-run with a larger
--feed-size still has headroom.

Usage:
    python archive_new_urls.py                 # archive with defaults
    python archive_new_urls.py --dry-run       # show what would move
    python archive_new_urls.py --data-dir ./data --feed-size 1000 --keep-extra 5
"""

from __future__ import annotations

import argparse
import re
import shutil
import sys
from pathlib import Path

FILE_RE = re.compile(r"^new_phishing_urls_(\d{4})(\d{2})(\d{2})_\d{6}\.txt$")
ARCHIVE_DIR_NAME = "archive_new_phishing"


def count_unique_urls(path: Path, seen: set[str]) -> int:
    """Count URLs in *path* not already in *seen*, adding them to *seen*."""
    added = 0
    with path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            url = line.strip()
            if url and not url.startswith("#") and url not in seen:
                seen.add(url)
                added += 1
    return added


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--data-dir", default="./data", type=Path,
                    help="Data directory holding new_phishing_urls_*.txt (default: ./data)")
    ap.add_argument("--feed-size", default=1000, type=int,
                    help="Unique-URL window export_stats.py serves (default: 1000)")
    ap.add_argument("--keep-extra", default=5, type=int,
                    help="Extra newest files to keep beyond the feed window (default: 5)")
    ap.add_argument("--dry-run", action="store_true",
                    help="Only print what would be moved")
    args = ap.parse_args()

    data_dir: Path = args.data_dir
    if not data_dir.is_dir():
        print(f"[archive] data dir not found: {data_dir}", file=sys.stderr)
        return 1

    files = sorted(
        (p for p in data_dir.iterdir() if p.is_file() and FILE_RE.match(p.name)),
        key=lambda p: p.name,
        reverse=True,   # newest timestamp first — same order export_stats.py uses
    )
    if not files:
        print(f"[archive] no new_phishing_urls_*.txt files in {data_dir}")
        return 0

    # Walk newest-first, mirroring export_stats.py, until the feed window is
    # covered.  Everything needed for that plus --keep-extra stays put.
    seen: set[str] = set()
    needed = 0
    for path in files:
        needed += 1
        count_unique_urls(path, seen)
        if len(seen) >= args.feed_size:
            break

    keep = min(len(files), needed + max(args.keep_extra, 0))
    to_move = files[keep:]

    print(f"[archive] {len(files)} run files, {needed} cover the "
          f"{args.feed_size}-URL feed window ({len(seen)} unique URLs), "
          f"keeping {keep}, archiving {len(to_move)}")

    if not to_move:
        return 0

    archive_root = data_dir / ARCHIVE_DIR_NAME
    moved = 0
    for path in to_move:
        year, month, _day = FILE_RE.match(path.name).groups()
        dest_dir = archive_root / year / month
        dest = dest_dir / path.name
        if dest.exists():
            print(f"[archive] SKIP (already exists): {dest}", file=sys.stderr)
            continue
        if args.dry_run:
            print(f"[archive] would move {path.name} → {dest}")
            continue
        dest_dir.mkdir(parents=True, exist_ok=True)
        shutil.move(str(path), str(dest))
        moved += 1

    if args.dry_run:
        print(f"[archive] dry run — nothing moved")
    else:
        print(f"[archive] moved {moved} files → {archive_root}/YYYY/MM/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
