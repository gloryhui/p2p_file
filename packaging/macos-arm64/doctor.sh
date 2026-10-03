#!/usr/bin/env bash
# Diagnose a native Apple Silicon macOS packaging environment. This script never installs software.

set -o pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
REPO_ROOT=$(cd "$SCRIPT_DIR/../.." && pwd -P)
FAILURES=0
WARNINGS=0
TARGET=aarch64-apple-darwin

report() {
    local state=$1 name=$2 detected=$3 required=$4 remediation=$5
    printf '%-4s | %s | detected: %s | required: %s | remediation: %s\n' \
        "$state" "$name" "$detected" "$required" "$remediation"
    case "$state" in
        FAIL) FAILURES=$((FAILURES + 1)) ;;
        WARN) WARNINGS=$((WARNINGS + 1)) ;;
    esac
}

check_versioned_command() {
    local name=$1 argument=$2 required=$3 remediation=$4 path version
    if path=$(command -v "$name" 2>/dev/null); then
        version=$("$path" "$argument" 2>&1 | head -n 1)
        if [[ -n "$version" ]]; then
            report PASS "$name" "$path ($version)" "$required" "none"
        else
            report FAIL "$name" "$path (version unavailable)" "$required" "$remediation"
        fi
    else
        report FAIL "$name" "not found" "$required" "$remediation"
    fi
}

extract_rust_version() {
    local tool=$1 output=$2
    local pattern="^${tool}[[:space:]]+([0-9]+)\\.([0-9]+)\\.([0-9]+)([-+][[:alnum:].-]+)?([[:space:]]|$)"
    if [[ "$output" =~ $pattern ]]; then
        printf '%s.%s.%s\n' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}"
    else
        return 1
    fi
}

rust_version_at_least_minimum() {
    local version=$1 major minor patch
    [[ "$version" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]] || return 2
    major=${BASH_REMATCH[1]}
    minor=${BASH_REMATCH[2]}
    patch=${BASH_REMATCH[3]}

    if (( 10#$major > 1 )); then
        return 0
    elif (( 10#$major < 1 )); then
        return 1
    elif (( 10#$minor > 90 )); then
        return 0
    elif (( 10#$minor < 90 )); then
        return 1
    fi
    (( 10#$patch >= 0 ))
}

check_rust_version() {
    local name=$1 path output version remediation
    remediation="Run: rustup update stable"
    if ! path=$(command -v "$name" 2>/dev/null); then
        report FAIL "$name version" "not found" ">= 1.90.0" "Install Rust with rustup, then run: $remediation"
        return
    fi

    if ! output=$("$path" --version 2>&1); then
        report FAIL "$name version" "$path (version command failed: ${output%%$'\n'*})" ">= 1.90.0" "$remediation"
        return
    fi
    output=${output%%$'\n'*}
    if ! version=$(extract_rust_version "$name" "$output"); then
        report FAIL "$name version" "$path (unrecognized version output: $output)" ">= 1.90.0" "$remediation"
        return
    fi

    if rust_version_at_least_minimum "$version"; then
        report PASS "$name version" "$path ($version)" ">= 1.90.0" "none"
    else
        report FAIL "$name version" "$path ($version)" ">= 1.90.0" "$remediation"
    fi
}

echo "P2P File macOS packaging doctor"
echo "repo: $REPO_ROOT"
echo "target: $TARGET"

OS_NAME=$(uname -s 2>/dev/null || true)
if [[ "$OS_NAME" == Darwin ]]; then
    report PASS "operating system" "$OS_NAME" "macOS 13+" "none"
else
    report FAIL "operating system" "${OS_NAME:-unavailable}" "Darwin; macOS 13+" "Run on macOS 13 or later."
fi

MACOS_VERSION=$(sw_vers -productVersion 2>/dev/null || true)
if [[ -n "$MACOS_VERSION" ]]; then
    MACOS_MAJOR=${MACOS_VERSION%%.*}
    if [[ "$MACOS_MAJOR" =~ ^[0-9]+$ ]] && (( MACOS_MAJOR >= 13 )); then
        report PASS "macOS version" "$MACOS_VERSION" "13.0 or newer" "none"
    else
        report FAIL "macOS version" "$MACOS_VERSION" "13.0 or newer" "Upgrade to macOS 13 or later."
    fi
else
    report FAIL "macOS version" "sw_vers unavailable" "13.0 or newer" "Run this doctor on macOS; check the macOS installation."
fi

PROCESS_ARCH=$(uname -m 2>/dev/null || true)
if [[ "$PROCESS_ARCH" == arm64 ]]; then
    report PASS "native architecture" "$PROCESS_ARCH" "Apple Silicon arm64; $TARGET" "none"
else
    TRANSLATED=$(sysctl -in sysctl.proc_translated 2>/dev/null || echo 0)
    HARDWARE_ARM=$(sysctl -in hw.optional.arm64 2>/dev/null || echo 0)
    if [[ "$TRANSLATED" == 1 ]]; then
        DETECTED="$PROCESS_ARCH process running under Rosetta on arm64 hardware"
        FIX="Use a native arm64 terminal; do not launch it with Rosetta."
    elif [[ "$HARDWARE_ARM" == 1 ]]; then
        DETECTED="$PROCESS_ARCH process on Apple Silicon (likely translated)"
        FIX="Use a native arm64 terminal outside Rosetta."
    else
        DETECTED="${PROCESS_ARCH:-unknown}; Intel/unrecognized host"
        FIX="Use a native Apple Silicon Mac for this entrypoint. Intel users should use packaging/macos-x86_64/build.sh."
    fi
    report FAIL "native architecture" "$DETECTED" "arm64 process; $TARGET" "$FIX"
fi

if path=$(command -v xcode-select 2>/dev/null); then
    DEVELOPER_DIR=$("$path" -p 2>/dev/null || true)
    if [[ -n "$DEVELOPER_DIR" && -d "$DEVELOPER_DIR" ]]; then
        report PASS "Xcode Command Line Tools" "$path; developer directory $DEVELOPER_DIR" "active Apple developer tools" "none"
    else
        report FAIL "Xcode Command Line Tools" "${DEVELOPER_DIR:-no active developer directory}" "active Apple developer tools" "Install Xcode Command Line Tools with: xcode-select --install"
    fi
else
    report FAIL "Xcode Command Line Tools" "xcode-select not found" "active Apple developer tools" "Install Xcode Command Line Tools with: xcode-select --install"
fi

if path=$(command -v xcrun 2>/dev/null); then
    SDK_PATH=$("$path" --show-sdk-path 2>/dev/null || true)
    if [[ -n "$SDK_PATH" && -d "$SDK_PATH" ]]; then
        report PASS "Apple SDK" "$path; SDK $SDK_PATH" "macOS SDK available through xcrun" "none"
    else
        report FAIL "Apple SDK" "$path; SDK unavailable" "macOS SDK available through xcrun" "Install or select Xcode Command Line Tools with: xcode-select --install"
    fi
else
    report FAIL "Apple SDK" "xcrun not found" "macOS SDK available through xcrun" "Install Xcode Command Line Tools with: xcode-select --install"
fi

check_versioned_command clang --version "Apple clang from Xcode Command Line Tools" "Install Xcode Command Line Tools with: xcode-select --install"
check_versioned_command git --version "Git available on PATH" "Install Git from https://git-scm.com/download/mac or install Xcode Command Line Tools."
check_versioned_command rustup --version "rustup available on PATH" "Install Rust using rustup: https://rustup.rs/"
check_rust_version rustc
check_rust_version cargo

for tool in codesign otool; do
    if path=$(command -v "$tool" 2>/dev/null); then
        if [[ "$tool" == codesign ]]; then
            VERSION=$({ "$path" --version 2>&1 || true; } | head -n 1)
        else
            VERSION="Apple toolchain utility (version follows selected developer directory)"
        fi
        report PASS "$tool" "$path${VERSION:+ ($VERSION)}" "Apple toolchain utility available" "none"
    else
        report FAIL "$tool" "not found" "Apple toolchain utility available" "Install Xcode Command Line Tools with: xcode-select --install"
    fi
done

if command -v rustup >/dev/null 2>&1; then
    INSTALLED_TARGETS=$(rustup target list --installed 2>/dev/null || true)
    if printf '%s\n' "$INSTALLED_TARGETS" | grep -Fxq "$TARGET"; then
        report PASS "Rust target" "$TARGET installed" "$TARGET" "none"
    else
        report FAIL "Rust target" "${INSTALLED_TARGETS:-no installed targets}" "$TARGET" "Install it with: rustup target add $TARGET"
    fi
else
    report FAIL "Rust target" "rustup unavailable" "$TARGET installed" "Install Rust using rustup, then run: rustup target add $TARGET"
fi

PYTHON_BIN=
PYTHON_INFO=
for candidate in python3.12 python3 python; do
    if candidate_path=$(command -v "$candidate" 2>/dev/null); then
        if candidate_info=$("$candidate_path" -c 'import sys, tomllib; assert sys.version_info >= (3, 11); print("Python %s.%s.%s; tomllib import OK; %s" % (*sys.version_info[:3], sys.executable))' 2>/dev/null); then
            PYTHON_BIN=$candidate_path
            PYTHON_INFO=$candidate_info
            break
        fi
    fi
done
if [[ -n "$PYTHON_BIN" ]]; then
    report PASS "Python" "$PYTHON_BIN ($PYTHON_INFO)" "Python >= 3.11 with tomllib; 3.12 recommended" "none"
else
    report FAIL "Python" "no usable python3.12/python3/python found" "Python >= 3.11 with tomllib" "Install Python 3.12 from https://www.python.org/downloads/macos/; optional Homebrew example: brew install python@3.12"
fi

for relative in Cargo.toml scripts/package-desktop.py scripts/package-desktop-tests.py scripts/verify-desktop-package.py; do
    if [[ -f "$REPO_ROOT/$relative" ]]; then
        report PASS "repository file $relative" "$REPO_ROOT/$relative" "file present" "none"
    else
        report FAIL "repository file $relative" "missing" "file present" "Restore the file from the repository's main branch."
    fi
done

if command -v df >/dev/null 2>&1; then
    AVAILABLE=$(df -h "${HOME:-/}" 2>/dev/null | tail -n 1 | awk '{print $4}')
    if [[ -n "$AVAILABLE" ]]; then
        report PASS "free disk space" "$AVAILABLE available near ${HOME:-/}" "enough space for Cargo build and dependency source archive" "The complete candidate includes Cargo source archives and is much larger than app-only; free space if the build reports ENOSPC."
    else
        report WARN "free disk space" "unable to determine" "enough space for build and candidate archive" "Check available disk space manually; this check is advisory."
    fi
else
    report WARN "free disk space" "df unavailable" "enough space for build and candidate archive" "Check available disk space manually; this check is advisory."
fi

if (( FAILURES == 0 )); then
    if (( WARNINGS == 0 )); then
        echo "READY"
    else
        echo "READY WITH WARNINGS"
    fi
    exit 0
fi

echo "NOT READY ($FAILURES required check(s) failed)"
exit 1
