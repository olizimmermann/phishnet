#!/usr/bin/env python3
"""
sort_kits.py — Triage downloaded phishing kit zips.

Moves kits into sub-folders based on their filename (derived from the
source URL by stripping non-alphanumeric chars):

  potential_malware/  — filename contains a raw IPv4 address
                        (e.g. http185.220.101.45evilkit.zip)
  github_kits/        — filename contains raw.githubusercontent.com
                        (likely dropper/stager scripts, not real kits)
  <left in place>     — everything else — most likely genuine phishing kits

Usage:
    python sort_kits.py                        # uses ./data/kits
    python sort_kits.py --kits-dir /path/kits  # custom directory
    python sort_kits.py --dry-run              # preview without moving
"""

import argparse
import re
import shutil
from pathlib import Path

# IPv4 address pattern — matches four dot-separated octets
_IP_RE = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")


def classify(filename: str) -> str | None:
    """Return destination sub-folder name or None to leave in place."""
    if _IP_RE.search(filename):
        return "potential_malware"
    if "raw.githubusercontent.com" in filename:
        return "github_kits"
    return None


def sort_kits(kits_dir: Path, dry_run: bool) -> None:
    zips = sorted(kits_dir.glob("*.zip"))
    if not zips:
        print(f"No zip files found in {kits_dir}")
        return

    counts: dict[str, int] = {}

    for zip_path in zips:
        dest_name = classify(zip_path.name)
        if dest_name is None:
            print(f"  [keep]  {zip_path.name}")
            counts["kept"] = counts.get("kept", 0) + 1
            continue

        dest_dir = kits_dir / dest_name
        dest_file = dest_dir / zip_path.name

        print(f"  [{dest_name}]  {zip_path.name}")
        counts[dest_name] = counts.get(dest_name, 0) + 1

        if not dry_run:
            dest_dir.mkdir(parents=True, exist_ok=True)
            shutil.move(str(zip_path), str(dest_file))

    print()
    print("Summary" + (" (dry run — nothing moved)" if dry_run else "") + ":")
    for label, count in sorted(counts.items()):
        print(f"  {label}: {count}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Triage phishing kit zips into sub-folders")
    parser.add_argument("--kits-dir", default="./data/kits", help="Path to kits folder (default: ./data/kits)")
    parser.add_argument("--dry-run", action="store_true", help="Preview without moving any files")
    args = parser.parse_args()

    kits_dir = Path(args.kits_dir).expanduser().resolve()
    if not kits_dir.is_dir():
        print(f"Error: {kits_dir} is not a directory")
        raise SystemExit(1)

    print(f"Sorting kits in {kits_dir}" + (" [DRY RUN]" if args.dry_run else "") + "\n")
    sort_kits(kits_dir, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
