#!/usr/bin/env bash
# Build and verify a native Intel GUI package using the shared packaging audit chain.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
REPO_ROOT=$(cd "$SCRIPT_DIR/../.." && pwd -P)
TARGET=x86_64-apple-darwin
APP_ONLY=0
REQUESTED_OUTPUT=

usage() {
    cat <<'USAGE'
Usage: build.sh [--output PATH] [--app-only]

  --output PATH  Write outside the repository; paths may contain spaces.
  --app-only     Create a lightweight local .app, not a complete audit candidate.
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
        --app-only)
            APP_ONLY=1
            shift
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

"$SCRIPT_DIR/doctor.sh"

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

if [[ -n "$(git -C "$REPO_ROOT" status --porcelain --untracked-files=all)" ]]; then
    echo "Complete packaging requires a clean Git worktree; commit or stash local changes first." >&2
    exit 1
fi
BUILD_SHA=$(git -C "$REPO_ROOT" rev-parse HEAD)
SHORT_SHA=${BUILD_SHA:0:12}

if [[ -z "$REQUESTED_OUTPUT" ]]; then
    STAMP=$(date -u +%Y%m%dT%H%M%SZ)
    REQUESTED_OUTPUT="${HOME:?HOME must be set}/p2p-file-builds/macos-x86_64-${STAMP}-${SHORT_SHA}"
    SUFFIX=1
    while [[ -e "$REQUESTED_OUTPUT" ]]; do
        REQUESTED_OUTPUT="${HOME:?HOME must be set}/p2p-file-builds/macos-x86_64-${STAMP}-${SHORT_SHA}-${SUFFIX}"
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
if [[ -e "$OUTPUT_DIR" ]]; then
    if [[ ! -d "$OUTPUT_DIR" ]]; then
        echo "Output path exists and is not a directory: $OUTPUT_DIR" >&2
        exit 2
    fi
    if [[ -n "$(ls -A "$OUTPUT_DIR")" ]]; then
        echo "Output directory is not empty; candidate evidence will not be overwritten: $OUTPUT_DIR" >&2
        exit 2
    fi
fi

export MACOSX_DEPLOYMENT_TARGET=13.0

cd "$REPO_ROOT"
"$PYTHON_BIN" scripts/package-desktop-tests.py
cargo build --locked --release --features gui --bin p2p-desktop --target "$TARGET"

if (( APP_ONLY )); then
    echo "APP-ONLY: 本机轻量运行包，不是完整审计候选。"
    "$PYTHON_BIN" scripts/package-desktop.py \
        --binary "target/$TARGET/release/p2p-desktop" \
        --target "$TARGET" \
        --output "$OUTPUT_DIR" \
        --app-only
    echo "build SHA: $BUILD_SHA"
    echo "target: $TARGET"
    echo "artifact path: $OUTPUT_DIR/P2P File.app"
    echo "archive: not produced (app-only)"
    echo "archive SHA256: not applicable (app-only)"
    echo "executable/app path: $OUTPUT_DIR/P2P File.app/Contents/MacOS/p2p-desktop"
    echo "signing status: ad-hoc; not notarized"
    exit 0
fi

"$PYTHON_BIN" scripts/package-desktop.py \
    --binary "target/$TARGET/release/p2p-desktop" \
    --target "$TARGET" \
    --output "$OUTPUT_DIR"
"$PYTHON_BIN" scripts/verify-desktop-package.py "$OUTPUT_DIR/candidate.json"

ARCHIVE=$("$PYTHON_BIN" -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["archive"])' "$OUTPUT_DIR/candidate.json")
ARCHIVE_SHA256=$("$PYTHON_BIN" -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["archive_sha256"])' "$OUTPUT_DIR/candidate.json")
PACKAGE_DIR=${ARCHIVE%.zip}
APP_PATH="$OUTPUT_DIR/$PACKAGE_DIR/P2P File.app"
EXECUTABLE_PATH="$APP_PATH/Contents/MacOS/p2p-desktop"

echo "build SHA: $BUILD_SHA"
echo "target: $TARGET"
echo "artifact path: $OUTPUT_DIR/$ARCHIVE"
echo "archive SHA256: $ARCHIVE_SHA256"
echo "executable/app path: $EXECUTABLE_PATH"
echo "signing status: ad-hoc; not notarized"
