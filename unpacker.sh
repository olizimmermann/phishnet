#!/usr/bin/env bash
# unpacker.sh — safely extract phishing kit zips
#
# Usage:
#   ls kits/          | ./unpacker.sh -o ./extracted -s kits/
#   ls kits/*.zip     | ./unpacker.sh -o ./extracted
#   find kits/ -name "*.zip" | ./unpacker.sh -o ./extracted
#
# Each zip is extracted into its own sub-directory under <output_dir>.
# Safety checks performed before extraction:
#   1. Magic bytes  — must start with PK (0x504b)
#   2. Integrity    — unzip -t must pass
#   3. Zip slip     — entries with ../ or absolute paths are rejected

set -uo pipefail

usage() {
    cat <<EOF
Usage: <file-list> | $(basename "$0") -o <output_dir> [-s <source_dir>]

Options:
  -o <dir>   destination directory for extracted contents (required)
  -s <dir>   source directory prefix for bare filenames   (default: .)
  -h         show this help
EOF
    exit 1
}

OUTPUT_DIR=""
SOURCE_DIR="."

while getopts "o:s:h" opt; do
    case $opt in
        o) OUTPUT_DIR="$OPTARG" ;;
        s) SOURCE_DIR="${OPTARG%/}" ;;
        h) usage ;;
        *) usage ;;
    esac
done

[[ -z "$OUTPUT_DIR" ]] && { echo "Error: -o is required"; echo; usage; }

mkdir -p "$OUTPUT_DIR"

ok=0; skipped=0; failed=0

while IFS= read -r line; do
    # strip Windows CR if present
    line="${line%$'\r'}"
    [[ -z "$line" ]] && continue

    # resolve full path — accept absolute paths, existing relative paths,
    # or bare filenames that need the source dir prepended
    if [[ "$line" = /* ]] || [[ -f "$line" ]]; then
        filepath="$line"
    else
        filepath="$SOURCE_DIR/$line"
    fi

    filename=$(basename "$filepath")

    # must end in .zip (case-insensitive)
    if [[ "${filename,,}" != *.zip ]]; then
        skipped=$((skipped + 1))
        continue
    fi

    if [[ ! -f "$filepath" ]]; then
        echo "  [skip]   $filename — file not found"
        skipped=$((skipped + 1))
        continue
    fi

    # ── 1. Magic bytes: ZIP files start with PK (50 4b) ──────────────────────
    magic=$(od -A n -N 2 -t x1 "$filepath" 2>/dev/null | tr -d ' \n')
    if [[ "$magic" != "504b" ]]; then
        echo "  [skip]   $filename — not a valid zip (bad magic bytes: $magic)"
        skipped=$((skipped + 1))
        continue
    fi

    # ── 2. Integrity check ────────────────────────────────────────────────────
    if ! unzip -t "$filepath" >/dev/null 2>&1; then
        echo "  [skip]   $filename — failed integrity check (corrupt zip)"
        skipped=$((skipped + 1))
        continue
    fi

    # ── 3. Zip slip protection ────────────────────────────────────────────────
    # Use Python (available in the venv) to reliably inspect entry names
    if ! python3 - "$filepath" <<'PYEOF'
import zipfile, sys

with zipfile.ZipFile(sys.argv[1]) as z:
    for entry in z.namelist():
        parts = entry.replace("\\", "/").split("/")
        if entry.startswith("/") or ".." in parts:
            print(f"  [WARN]   unsafe entry detected: {entry}", flush=True)
            sys.exit(1)
PYEOF
    then
        echo "  [skip]   $filename — contains path traversal entries (zip slip), skipping"
        skipped=$((skipped + 1))
        continue
    fi

    # ── Extract into its own sub-directory ───────────────────────────────────
    dest="$OUTPUT_DIR/${filename%.zip}"

    # avoid clobbering an existing extraction
    if [[ -d "$dest" ]]; then
        dest="${dest}_$(date +%s)"
    fi

    mkdir -p "$dest"

    if unzip -q "$filepath" -d "$dest" 2>/dev/null; then
        count=$(find "$dest" -type f | wc -l | tr -d ' ')
        echo "  [ok]     $filename → $dest  ($count files)"
        ok=$((ok + 1))
    else
        echo "  [fail]   $filename — extraction failed"
        rmdir "$dest" 2>/dev/null || true
        failed=$((failed + 1))
    fi

done

echo
echo "Done — extracted: $ok  skipped: $skipped  failed: $failed"
