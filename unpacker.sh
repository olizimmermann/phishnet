#!/usr/bin/env bash
# unpacker.sh — safely extract phishing kit archives
#
# Supported formats: .zip  .rar  .7z  .tar.gz  .tgz  .tar.bz2  .tbz2  .tar  .gz  .bz2
#
# Usage:
#   ls kits/          | ./unpacker.sh -o ./extracted -s kits/
#   ls kits/*.zip     | ./unpacker.sh -o ./extracted
#   find kits/ | ./unpacker.sh -o ./extracted
#
# Each archive is extracted into its own sub-directory under <output_dir>.
# Safety checks performed before extraction:
#   1. Magic bytes     — format-specific signature check
#   2. Integrity       — tool integrity/list test
#   3. Path traversal  — entries with ../ or absolute paths are rejected

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

# Detect archive format from filename (case-insensitive), echo format key or "".
detect_format() {
    local fn="${1,,}"
    case "$fn" in
        *.tar.gz|*.tgz)    echo "tar.gz"  ;;
        *.tar.bz2|*.tbz2)  echo "tar.bz2" ;;
        *.tar)             echo "tar"     ;;
        *.zip)             echo "zip"     ;;
        *.rar)             echo "rar"     ;;
        *.7z)              echo "7z"      ;;
        *.gz)              echo "gz"      ;;
        *.bz2)             echo "bz2"     ;;
        *)                 echo ""        ;;
    esac
}

# Strip the archive extension to produce the output sub-directory name.
strip_ext() {
    local fn="$1" fn_lower="${1,,}"
    for ext in .tar.gz .tar.bz2 .tgz .tbz2 .zip .rar .7z .tar .gz .bz2; do
        local extlen=${#ext}
        if [[ "${fn_lower: -$extlen}" == "$ext" ]]; then
            echo "${fn:0:$((${#fn} - extlen))}"
            return
        fi
    done
    echo "${fn%.*}"
}

# Check magic bytes: check_magic <file> <expected_hex> <n_bytes>
check_magic() {
    local actual
    actual=$(od -A n -N "$3" -t x1 "$1" 2>/dev/null | tr -d ' \n')
    [[ "$actual" == "$2" ]]
}

while IFS= read -r line; do
    # strip Windows CR if present
    line="${line%$'\r'}"
    [[ -z "$line" ]] && continue

    # resolve full path
    if [[ "$line" = /* ]] || [[ -f "$line" ]]; then
        filepath="$line"
    else
        filepath="$SOURCE_DIR/$line"
    fi

    filename=$(basename "$filepath")
    fmt=$(detect_format "$filename")

    if [[ -z "$fmt" ]]; then
        skipped=$((skipped + 1))
        continue
    fi

    if [[ ! -f "$filepath" ]]; then
        echo "  [skip]   $filename — file not found"
        skipped=$((skipped + 1))
        continue
    fi

    # track 7z binary name across steps within this iteration
    tool_7z=""

    # ── 1. Magic bytes ────────────────────────────────────────────────────────
    magic_ok=true
    case "$fmt" in
        zip)     check_magic "$filepath" "504b"     2 || magic_ok=false ;;
        rar)     check_magic "$filepath" "52617221" 4 || magic_ok=false ;;
        7z)      check_magic "$filepath" "377abcaf" 4 || magic_ok=false ;;
        tar.gz|gz)   check_magic "$filepath" "1f8b"  2 || magic_ok=false ;;
        tar.bz2|bz2) check_magic "$filepath" "425a68" 3 || magic_ok=false ;;
        tar)     : ;;  # no universal magic for plain tar
    esac

    if [[ "$magic_ok" == false ]]; then
        actual=$(od -A n -N 4 -t x1 "$filepath" 2>/dev/null | tr -d ' \n')
        echo "  [skip]   $filename — bad magic bytes for .$fmt (got: $actual)"
        skipped=$((skipped + 1))
        continue
    fi

    # ── 2. Tool availability + integrity check ────────────────────────────────
    case "$fmt" in
        zip)
            if ! command -v unzip &>/dev/null; then
                echo "  [skip]   $filename — unzip not found"
                skipped=$((skipped + 1)); continue
            fi
            if ! unzip -t "$filepath" >/dev/null 2>&1; then
                echo "  [skip]   $filename — failed integrity check (corrupt zip)"
                skipped=$((skipped + 1)); continue
            fi
            ;;
        rar)
            if ! command -v unrar &>/dev/null; then
                echo "  [skip]   $filename — unrar not found (install unrar)"
                skipped=$((skipped + 1)); continue
            fi
            if ! unrar t "$filepath" >/dev/null 2>&1; then
                echo "  [skip]   $filename — failed integrity check (corrupt rar)"
                skipped=$((skipped + 1)); continue
            fi
            ;;
        7z)
            for bin in 7z 7za 7zz; do
                command -v "$bin" &>/dev/null && { tool_7z="$bin"; break; }
            done
            if [[ -z "$tool_7z" ]]; then
                echo "  [skip]   $filename — 7z not found (install p7zip)"
                skipped=$((skipped + 1)); continue
            fi
            if ! $tool_7z t "$filepath" >/dev/null 2>&1; then
                echo "  [skip]   $filename — failed integrity check (corrupt 7z)"
                skipped=$((skipped + 1)); continue
            fi
            ;;
        tar.gz|tar.bz2|tar)
            if ! command -v tar &>/dev/null; then
                echo "  [skip]   $filename — tar not found"
                skipped=$((skipped + 1)); continue
            fi
            if ! tar -tf "$filepath" >/dev/null 2>&1; then
                echo "  [skip]   $filename — failed integrity check (corrupt tar)"
                skipped=$((skipped + 1)); continue
            fi
            ;;
        gz)
            if ! command -v gunzip &>/dev/null; then
                echo "  [skip]   $filename — gunzip not found"
                skipped=$((skipped + 1)); continue
            fi
            if ! gunzip -t "$filepath" 2>/dev/null; then
                echo "  [skip]   $filename — failed integrity check (corrupt gz)"
                skipped=$((skipped + 1)); continue
            fi
            ;;
        bz2)
            if ! command -v bunzip2 &>/dev/null; then
                echo "  [skip]   $filename — bunzip2 not found"
                skipped=$((skipped + 1)); continue
            fi
            if ! bunzip2 -t "$filepath" 2>/dev/null; then
                echo "  [skip]   $filename — failed integrity check (corrupt bz2)"
                skipped=$((skipped + 1)); continue
            fi
            ;;
    esac

    # ── 3. Path traversal check ───────────────────────────────────────────────
    case "$fmt" in
        zip)
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
                skipped=$((skipped + 1)); continue
            fi
            ;;
        tar.gz|tar.bz2|tar)
            if ! python3 - "$filepath" <<'PYEOF'
import tarfile, sys
with tarfile.open(sys.argv[1]) as t:
    for member in t.getmembers():
        name = member.name.replace("\\", "/")
        parts = name.split("/")
        if name.startswith("/") or ".." in parts:
            print(f"  [WARN]   unsafe entry detected: {name}", flush=True)
            sys.exit(1)
PYEOF
            then
                echo "  [skip]   $filename — contains path traversal entries, skipping"
                skipped=$((skipped + 1)); continue
            fi
            ;;
        rar)
            # unrar vb prints bare file paths, one per line
            if unrar vb "$filepath" 2>/dev/null | grep -qE '(^\.\.|/\.\.|^/)'; then
                echo "  [skip]   $filename — contains path traversal entries, skipping"
                skipped=$((skipped + 1)); continue
            fi
            ;;
        7z)
            # 7z l -ba prints one filename per line (no header/footer)
            if $tool_7z l -ba "$filepath" 2>/dev/null | awk '{print $NF}' | grep -qE '(^\.\.|/\.\.|^/)'; then
                echo "  [skip]   $filename — contains path traversal entries, skipping"
                skipped=$((skipped + 1)); continue
            fi
            ;;
        gz|bz2)
            # Single-file compressed archives have no directory structure — no traversal risk
            ;;
    esac

    # ── Extract into its own sub-directory ───────────────────────────────────
    base=$(strip_ext "$filename")
    dest="$OUTPUT_DIR/$base"

    if [[ -d "$dest" ]]; then
        dest="${dest}_$(date +%s)"
    fi

    mkdir -p "$dest"
    extract_ok=true

    case "$fmt" in
        zip)
            unzip -q "$filepath" -d "$dest" 2>/dev/null    || extract_ok=false ;;
        rar)
            unrar x -y "$filepath" "$dest/" >/dev/null 2>&1 || extract_ok=false ;;
        7z)
            $tool_7z x "$filepath" -o"$dest" -y >/dev/null 2>&1 || extract_ok=false ;;
        tar.gz)
            tar -xzf "$filepath" -C "$dest" 2>/dev/null    || extract_ok=false ;;
        tar.bz2)
            tar -xjf "$filepath" -C "$dest" 2>/dev/null    || extract_ok=false ;;
        tar)
            tar -xf  "$filepath" -C "$dest" 2>/dev/null    || extract_ok=false ;;
        gz)
            # standalone gzip — decompress the single inner file
            gunzip -c "$filepath" > "$dest/${filename%.gz}" 2>/dev/null || extract_ok=false ;;
        bz2)
            bunzip2 -c "$filepath" > "$dest/${filename%.bz2}" 2>/dev/null || extract_ok=false ;;
    esac

    if [[ "$extract_ok" == true ]]; then
        count=$(find "$dest" -type f | wc -l | tr -d ' ')
        echo "  [ok]     $filename → $dest  ($count files)"
        ok=$((ok + 1))
    else
        echo "  [fail]   $filename — extraction failed"
        rm -rf "$dest"
        failed=$((failed + 1))
    fi

done

echo
echo "Done — extracted: $ok  skipped: $skipped  failed: $failed"
