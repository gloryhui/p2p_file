#!/usr/bin/env bash
# Build and verify a native Linux x86_64 GUI candidate using the shared packaging audit chain.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
REPO_ROOT=$(cd "$SCRIPT_DIR/../.." && pwd -P)
TARGET=x86_64-unknown-linux-gnu
REQUESTED_OUTPUT=

usage() {
    cat <<'USAGE'
Usage: build.sh [--output PATH]

  --output PATH  Write outside the repository; paths may contain spaces.
USAGE
}

while (($#)); do
    case "$1" in
        --output)
            if (($# < 2)) || [[ -z "$2" ]]; then
                echo "--output requires a path" >&2
                exit 2
            fi
            REQUESTED_OUTPUT=$2
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if DOCTOR_OUTPUT=$("$SCRIPT_DIR/doctor.sh" 2>&1); then
    printf '%s\n' "$DOCTOR_OUTPUT"
else
    DOCTOR_EXIT=$?
    printf '%s\n' "$DOCTOR_OUTPUT" >&2
    echo "Build stopped by doctor before Cargo was started." >&2
    exit "$DOCTOR_EXIT"
fi

PYTHON_BIN=
for candidate in python3.12 python3 python; do
    if candidate_path=$(command -v "$candidate" 2>/dev/null); then
        if "$candidate_path" -c 'import sys, tomllib; assert sys.version_info >= (3, 11)' >/dev/null 2>&1; then
            PYTHON_BIN=$candidate_path
            break
        fi
    fi
done
if [[ -z "$PYTHON_BIN" ]]; then
    echo "No Python >= 3.11 with tomllib is available after doctor passed." >&2
    exit 1
fi

if ! git -C "$REPO_ROOT" rev-parse --verify HEAD >/dev/null 2>&1; then
    echo "Could not read Git HEAD from $REPO_ROOT." >&2
    exit 1
fi
if [[ -n "$(git -C "$REPO_ROOT" status --porcelain --untracked-files=all)" ]]; then
    echo "Complete packaging requires a clean Git worktree; commit or stash local changes first." >&2
    exit 1
fi
BUILD_SHA=$(git -C "$REPO_ROOT" rev-parse HEAD)
SHORT_SHA=${BUILD_SHA:0:12}

if [[ -z "$REQUESTED_OUTPUT" ]]; then
    STAMP=$(date -u +%Y%m%dT%H%M%SZ)
    REQUESTED_OUTPUT="${HOME:?HOME must be set}/p2p-file-builds/linux-x86_64-${STAMP}-${SHORT_SHA}"
    SUFFIX=1
    while [[ -e "$REQUESTED_OUTPUT" || -L "$REQUESTED_OUTPUT" ]]; do
        REQUESTED_OUTPUT="${HOME:?HOME must be set}/p2p-file-builds/linux-x86_64-${STAMP}-${SHORT_SHA}-${SUFFIX}"
        SUFFIX=$((SUFFIX + 1))
    done
fi
OUTPUT_DIR=$("$PYTHON_BIN" -c 'from pathlib import Path; import sys; print(Path(sys.argv[1]).expanduser().resolve())' "$REQUESTED_OUTPUT")
case "$OUTPUT_DIR" in
    "$REPO_ROOT"|"$REPO_ROOT"/*)
        echo "Output must be outside the repository: $OUTPUT_DIR" >&2
        exit 2
        ;;
esac
if [[ -e "$OUTPUT_DIR" || -L "$OUTPUT_DIR" ]]; then
    if [[ ! -d "$OUTPUT_DIR" ]]; then
        echo "Output path exists and is not a directory: $OUTPUT_DIR" >&2
        exit 2
    fi
    if [[ -n "$(ls -A "$OUTPUT_DIR")" ]]; then
        echo "Output directory is not empty; candidate evidence will not be overwritten: $OUTPUT_DIR" >&2
        exit 2
    fi
fi

CARGO_BIN=$(command -v cargo)

cd "$REPO_ROOT"
"$PYTHON_BIN" scripts/package-desktop-tests.py
"$CARGO_BIN" build --locked --release --features gui --bin p2p-desktop --target "$TARGET"
"$PYTHON_BIN" scripts/package-desktop.py \
    --binary "target/$TARGET/release/p2p-desktop" \
    --target "$TARGET" \
    --output "$OUTPUT_DIR"
"$PYTHON_BIN" scripts/verify-desktop-package.py "$OUTPUT_DIR/candidate.json"

ARCHIVE=$("$PYTHON_BIN" -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["archive"])' "$OUTPUT_DIR/candidate.json")
PACKAGE_NAME=${ARCHIVE%.tar.gz}
PACKAGE_ROOT="$OUTPUT_DIR/$PACKAGE_NAME"
ARCHIVE_SHA256=$("$PYTHON_BIN" -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["archive_sha256"])' "$OUTPUT_DIR/candidate.json")
PACKAGE_BUILD_SHA=$("$PYTHON_BIN" -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["build_sha"])' "$OUTPUT_DIR/candidate.json")
PACKAGE_TARGET=$("$PYTHON_BIN" -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["target"])' "$OUTPUT_DIR/candidate.json")
PACKAGE_EXECUTABLE=$("$PYTHON_BIN" -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["executable"])' "$OUTPUT_DIR/candidate.json")
PACKAGE_SIGNING=$("$PYTHON_BIN" -c 'import json,sys; d=json.load(open(sys.argv[1], encoding="utf-8")); print(d["signing"]["status"] + "; notarization=" + d["signing"]["notarization"])' "$OUTPUT_DIR/candidate.json")
RUNTIME_WARNINGS=$(printf '%s\n' "$DOCTOR_OUTPUT" | awk -F '|' '$1 ~ /WARN/ && $2 ~ /(WSL environment|GUI session environment|xdg-desktop-portal|desktop portal backend)/')

echo "build SHA: $PACKAGE_BUILD_SHA"
echo "target: $PACKAGE_TARGET"
echo "artifact path: $OUTPUT_DIR/$ARCHIVE"
echo "archive SHA256: $ARCHIVE_SHA256"
echo "executable path: $PACKAGE_ROOT/$PACKAGE_EXECUTABLE"
echo "signing status: $PACKAGE_SIGNING"
if [[ -n "$RUNTIME_WARNINGS" ]]; then
    echo "GUI runtime warning summary:"
    printf '%s\n' "$RUNTIME_WARNINGS"
else
    echo "GUI runtime warning summary: none reported by doctor"
fi
