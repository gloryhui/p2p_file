#!/usr/bin/env bash
# Diagnose a native Linux x86_64 packaging environment. This script never installs software.

set -o pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
REPO_ROOT=$(cd "$SCRIPT_DIR/../.." && pwd -P)
TARGET=x86_64-unknown-linux-gnu
FAILURES=0
WARNINGS=0
NATIVE_FAILURES=0
DISTRO_ID=unknown
DISTRO_VERSION=unknown
DISTRO_ID_LIKE=
DISTRO_FAMILY=unknown
OFFICIAL_TARGET=0

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
    elif (( 10#$minor > 85 )); then
        return 0
    elif (( 10#$minor < 85 )); then
        return 1
    fi
    (( 10#$patch >= 0 ))
}

check_rust_version() {
    local name=$1 path output version remediation
    remediation="Run: rustup update stable"
    if ! path=$(command -v "$name" 2>/dev/null); then
        report FAIL "$name version" "not found" ">= 1.85.0" "Install Rust with rustup, then run: $remediation"
        return
    fi

    if ! output=$("$path" --version 2>&1); then
        report FAIL "$name version" "$path (version command failed: ${output%%$'\n'*})" ">= 1.85.0" "$remediation"
        return
    fi
    output=${output%%$'\n'*}
    if ! version=$(extract_rust_version "$name" "$output"); then
        report FAIL "$name version" "$path (unrecognized version output: $output)" ">= 1.85.0" "$remediation"
        return
    fi

    if rust_version_at_least_minimum "$version"; then
        report PASS "$name version" "$path ($version)" ">= 1.85.0" "none"
    else
        report FAIL "$name version" "$path ($version)" ">= 1.85.0" "$remediation"
    fi
}

native_package_for() {
    local module=$1
    case "$DISTRO_FAMILY:$module" in
        apt:fontconfig) echo libfontconfig1-dev ;;
        apt:freetype2) echo libfreetype6-dev ;;
        apt:wayland-client) echo libwayland-dev ;;
        apt:x11) echo libx11-dev ;;
        apt:x11-xcb) echo libx11-xcb-dev ;;
        apt:xcb) echo libxcb1-dev ;;
        apt:xcb-render) echo libxcb-render0-dev ;;
        apt:xcb-shape) echo libxcb-shape0-dev ;;
        apt:xcb-xfixes) echo libxcb-xfixes0-dev ;;
        apt:xcb-randr) echo libxcb-randr0-dev ;;
        apt:xkbcommon) echo libxkbcommon-dev ;;
        apt:xkbcommon-x11) echo libxkbcommon-x11-dev ;;
        dnf:fontconfig) echo fontconfig-devel ;;
        dnf:freetype2) echo freetype-devel ;;
        dnf:wayland-client) echo wayland-devel ;;
        dnf:x11|dnf:x11-xcb) echo libX11-devel ;;
        dnf:xcb|dnf:xcb-render|dnf:xcb-shape|dnf:xcb-xfixes|dnf:xcb-randr) echo libxcb-devel ;;
        dnf:xkbcommon) echo libxkbcommon-devel ;;
        dnf:xkbcommon-x11) echo libxkbcommon-x11-devel ;;
        pacman:fontconfig) echo fontconfig ;;
        pacman:freetype2) echo freetype2 ;;
        pacman:wayland-client) echo wayland ;;
        pacman:x11|pacman:x11-xcb) echo libx11 ;;
        pacman:xcb|pacman:xcb-render|pacman:xcb-shape|pacman:xcb-xfixes|pacman:xcb-randr) echo libxcb ;;
        pacman:xkbcommon|pacman:xkbcommon-x11) echo libxkbcommon ;;
        *) echo "the -dev/-devel package providing pkg-config module $module" ;;
    esac
}

find_portal_component() {
    local name=$1 path candidate
    if path=$(command -v "$name" 2>/dev/null); then
        printf '%s\n' "$path"
        return 0
    fi
    for candidate in "/usr/libexec/$name" "/usr/lib/$name" "/usr/lib/xdg-desktop-portal/$name"; do
        if [[ -x "$candidate" ]]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    return 1
}

basic_package_for() {
    local tool=$1
    case "$DISTRO_FAMILY:$tool" in
        apt:compiler) echo build-essential ;;
        apt:linker|apt:readelf) echo binutils ;;
        apt:pkg-config) echo pkg-config ;;
        apt:git) echo git ;;
        apt:ldd) echo libc-bin ;;
        dnf:compiler) echo gcc gcc-c++ ;;
        dnf:linker|dnf:readelf) echo binutils ;;
        dnf:pkg-config) echo pkgconf-pkg-config ;;
        dnf:git) echo git ;;
        dnf:ldd) echo glibc-common ;;
        pacman:compiler) echo base-devel ;;
        pacman:linker|pacman:readelf) echo binutils ;;
        pacman:pkg-config) echo pkgconf ;;
        pacman:git) echo git ;;
        pacman:ldd) echo glibc ;;
        *) echo "the package providing $tool" ;;
    esac
}

basic_remediation() {
    local tool=$1 package
    package=$(basic_package_for "$tool")
    case "$DISTRO_FAMILY" in
        apt) echo "Ubuntu/Debian package: $package; print-only example: sudo apt install -y $package" ;;
        dnf) echo "Fedora/RHEL package: $package; print-only example: sudo dnf install -y $package" ;;
        pacman) echo "Arch/Manjaro package: $package; print-only example: sudo pacman -S --needed $package" ;;
        *) echo "Install the distribution package providing $tool; no package-manager command is assumed." ;;
    esac
}

echo "P2P File Linux packaging doctor"
echo "repo: $REPO_ROOT"
echo "target: $TARGET"

SYSTEM_NAME=$(uname -s 2>/dev/null || true)
SYSTEM_ARCH=$(uname -m 2>/dev/null || true)
if [[ "$SYSTEM_NAME" == Linux ]]; then
    report PASS "operating system" "$SYSTEM_NAME" "Linux" "none"
else
    report FAIL "operating system" "${SYSTEM_NAME:-unavailable}" "Linux" "Run this doctor on Linux."
fi
if [[ "$SYSTEM_ARCH" == x86_64 ]]; then
    report PASS "CPU architecture" "$SYSTEM_ARCH" "$TARGET" "none"
else
    report FAIL "CPU architecture" "${SYSTEM_ARCH:-unavailable}" "x86_64; other architectures are unsupported" "Use an x86_64 Linux host; cross-building another architecture is outside this package workflow."
fi

if [[ -r /etc/os-release ]]; then
    DISTRO_ID=$(sed -n 's/^ID=//p' /etc/os-release | head -n 1 | tr -d '"')
    DISTRO_VERSION=$(sed -n 's/^VERSION_ID=//p' /etc/os-release | head -n 1 | tr -d '"')
    DISTRO_ID_LIKE=$(sed -n 's/^ID_LIKE=//p' /etc/os-release | head -n 1 | tr -d '"')
    PRETTY_NAME=$(sed -n 's/^PRETTY_NAME=//p' /etc/os-release | head -n 1 | sed 's/^"//; s/"$//')
    DISTRO_ID=${DISTRO_ID:-unknown}
    DISTRO_VERSION=${DISTRO_VERSION:-unknown}
    PRETTY_NAME=${PRETTY_NAME:-$DISTRO_ID $DISTRO_VERSION}
    report PASS "distribution identity" "$PRETTY_NAME (ID=$DISTRO_ID; VERSION_ID=$DISTRO_VERSION)" "/etc/os-release readable" "none"
else
    PRETTY_NAME=unknown
    report WARN "distribution identity" "/etc/os-release missing or unreadable" "ID and VERSION_ID detectable when available" "This distribution cannot be classified; build capability checks still apply."
fi

case "$DISTRO_ID" in
    ubuntu|debian) DISTRO_FAMILY=apt ;;
    fedora|rhel|centos|rocky|almalinux) DISTRO_FAMILY=dnf ;;
    arch|manjaro) DISTRO_FAMILY=pacman ;;
    *)
        if [[ " $DISTRO_ID_LIKE " == *" debian "* ]]; then DISTRO_FAMILY=apt
        elif [[ " $DISTRO_ID_LIKE " == *" fedora "* || " $DISTRO_ID_LIKE " == *" rhel "* ]]; then DISTRO_FAMILY=dnf
        elif [[ " $DISTRO_ID_LIKE " == *" arch "* ]]; then DISTRO_FAMILY=pacman
        fi
        ;;
esac

if [[ "$DISTRO_ID" == ubuntu && "$DISTRO_VERSION" == 24.04 ]]; then
    OFFICIAL_TARGET=1
    report PASS "distribution support level" "$PRETTY_NAME; official validation target OS" "Ubuntu 24.04 LTS x86_64" "none"
elif [[ "$DISTRO_ID" == ubuntu || "$DISTRO_ID" == debian || "$DISTRO_ID" == fedora || "$DISTRO_ID" == arch || "$DISTRO_ID" == manjaro || "$DISTRO_FAMILY" != unknown ]]; then
    report WARN "distribution support level" "$PRETTY_NAME; best-effort build guidance" "Ubuntu 24.04 LTS x86_64 is the only formal validation target" "Use Ubuntu 24.04 LTS Desktop for formal platform validation."
else
    report WARN "distribution support level" "$PRETTY_NAME; unsupported/unclassified distribution" "Ubuntu 24.04 LTS x86_64 is the only formal validation target" "Install equivalent compiler, linker, pkg-config, and native -dev/-devel capabilities; support is not claimed."
fi

KERNEL_RELEASE=$(uname -r 2>/dev/null || true)
if [[ "${KERNEL_RELEASE,,}" == *microsoft* || -n "${WSL_INTEROP:-}" ]]; then
    report WARN "WSL environment" "$KERNEL_RELEASE" "native Linux Desktop for formal GUI validation" "WSL is not a formal Linux Desktop acceptance environment; use Ubuntu 24.04 Desktop for that validation."
else
    report PASS "WSL environment" "WSL not detected" "native Linux Desktop for formal GUI validation" "none"
fi

CC_BIN=
CC_VERSION=
CC_MACHINE=
for candidate in cc gcc; do
    if path=$(command -v "$candidate" 2>/dev/null); then
        version=$("$path" --version 2>&1 | head -n 1)
        machine=$("$path" -dumpmachine 2>/dev/null || true)
        if [[ -n "$version" && "$machine" == *x86_64* ]]; then
            CC_BIN=$path
            CC_VERSION=$version
            CC_MACHINE=$machine
            break
        fi
    fi
done
if [[ -n "$CC_BIN" ]]; then
    report PASS "C compiler" "$CC_BIN ($CC_VERSION; target=$CC_MACHINE)" "cc or gcc producing native x86_64 code" "none"
else
    report FAIL "C compiler" "cc/gcc missing, unusable, or not targeting x86_64" "working x86_64 cc or gcc" "$(basic_remediation compiler)"
fi

LINKER_BIN=
for candidate in ld ld.lld; do
    if path=$(command -v "$candidate" 2>/dev/null); then
        version=$("$path" --version 2>&1 | head -n 1)
        if [[ -n "$version" ]]; then
            LINKER_BIN=$path
            report PASS "linker" "$path ($version)" "native Linux linker" "none"
            break
        fi
    fi
done
if [[ -z "$LINKER_BIN" ]]; then
    report FAIL "linker" "ld and ld.lld not found or unusable" "native Linux linker" "$(basic_remediation linker)"
fi

if command -v pkg-config >/dev/null 2>&1; then
    check_versioned_command pkg-config --version "pkg-config available with a readable version" "$(basic_remediation pkg-config)"
else
    report FAIL "pkg-config" "not found" "pkg-config available with a readable version" "$(basic_remediation pkg-config)"
    NATIVE_FAILURES=$((NATIVE_FAILURES + 1))
fi
check_versioned_command git --version "Git available with a readable version" "$(basic_remediation git)"
check_versioned_command ldd --version "ldd available for ELF dependency inspection" "$(basic_remediation ldd)"
check_versioned_command readelf --version "readelf available for ELF version inspection" "$(basic_remediation readelf)"
check_versioned_command rustup --version "rustup available; use rustup for Rust installation" "Install Rust using the official rustup instructions at https://rustup.rs/; do not prefer an older distro rustc package."
check_rust_version rustc
check_rust_version cargo

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
PYTHON_DETAIL=
PYTHON_ATTEMPTS=
for candidate in python3.12 python3 python; do
    if path=$(command -v "$candidate" 2>/dev/null); then
        details=$("$path" -c 'import sys; print("{}.{}.{}|{}".format(*sys.version_info[:3], sys.executable))' 2>/dev/null || true)
        version=${details%%|*}
        executable=${details#*|}
        if [[ -n "$version" ]]; then
            if "$path" -c 'import tomllib' >/dev/null 2>&1; then
                tomllib_status=available
            else
                tomllib_status=missing
            fi
            PYTHON_ATTEMPTS+="$path (Python $version; tomllib $tomllib_status); "
            IFS=. read -r py_major py_minor _ <<< "$version"
            if [[ "$tomllib_status" == available ]] && (( py_major > 3 || (py_major == 3 && py_minor >= 11) )); then
                PYTHON_BIN=$path
                PYTHON_DETAIL="$executable (Python $version; tomllib import OK)"
                break
            fi
        fi
    fi
done
if [[ -n "$PYTHON_BIN" ]]; then
    report PASS "Python" "$PYTHON_BIN; $PYTHON_DETAIL" "Python >= 3.11 with tomllib; 3.12 recommended" "none"
else
    report FAIL "Python" "${PYTHON_ATTEMPTS:-no python3.12/python3/python executable found}" "Python >= 3.11 with tomllib" "Install Python 3.11 or newer; Ubuntu 24.04 supplies Python 3.12. Rust should be installed separately with rustup."
fi

if command -v pkg-config >/dev/null 2>&1; then
    for capability in fontconfig freetype2 wayland-client x11 x11-xcb xcb xcb-render xcb-shape xcb-xfixes xcb-randr xkbcommon xkbcommon-x11; do
        if pkg-config --exists "$capability" 2>/dev/null; then
            module_version=$(pkg-config --modversion "$capability" 2>/dev/null || true)
            module_dir=$(pkg-config --variable=pcfiledir "$capability" 2>/dev/null || true)
            report PASS "GPUI native capability $capability" "pkg-config $module_version; pcfiledir=${module_dir:-unknown}" "module $capability available" "none"
        else
            package=$(native_package_for "$capability")
            remediation="Install the package providing $capability manually"
            case "$DISTRO_FAMILY" in
                apt) remediation="Ubuntu/Debian package: $package; print-only example: sudo apt install -y $package" ;;
                dnf) remediation="Fedora/RHEL capability package: $package; print-only example: sudo dnf install -y $package" ;;
                pacman) remediation="Arch/Manjaro capability package: $package; print-only example: sudo pacman -S --needed $package" ;;
                *) remediation="Install the distribution's -dev/-devel package providing pkg-config module $capability; package name not assumed." ;;
            esac
            report FAIL "GPUI native capability $capability" "pkg-config module missing" "module $capability available" "$remediation"
            NATIVE_FAILURES=$((NATIVE_FAILURES + 1))
        fi
    done
else
    report FAIL "GPUI native capabilities" "pkg-config unavailable; module checks could not run" "fontconfig, freetype2, Wayland, X11/XCB, and xkbcommon modules" "$(basic_remediation pkg-config)"
    NATIVE_FAILURES=$((NATIVE_FAILURES + 1))
fi

for relative in Cargo.toml scripts/package-desktop.py scripts/package-desktop-tests.py scripts/verify-desktop-package.py; do
    if [[ -f "$REPO_ROOT/$relative" ]]; then
        report PASS "repository file $relative" "$REPO_ROOT/$relative" "file present" "none"
    else
        report FAIL "repository file $relative" "missing" "file present" "Restore the file from the repository's main branch."
    fi
done

SESSION_TYPE=${XDG_SESSION_TYPE:-unset}
DISPLAY_VALUE=${DISPLAY:-unset}
WAYLAND_VALUE=${WAYLAND_DISPLAY:-unset}
if [[ "$DISPLAY_VALUE" != unset || "$WAYLAND_VALUE" != unset ]]; then
    report PASS "GUI session environment" "XDG_SESSION_TYPE=$SESSION_TYPE DISPLAY=$DISPLAY_VALUE WAYLAND_DISPLAY=$WAYLAND_VALUE" "display variables present for an interactive GUI session" "Variable presence does not prove that a native GUI window was tested."
else
    report WARN "GUI session environment" "XDG_SESSION_TYPE=$SESSION_TYPE DISPLAY=unset WAYLAND_DISPLAY=unset" "display variables present for interactive GUI runtime validation" "A package build may continue, but run the app in a real desktop session to validate GUI runtime."
fi

PORTAL_PATH=$(find_portal_component xdg-desktop-portal 2>/dev/null || true)
PORTAL_BACKEND=
for backend in xdg-desktop-portal-gtk xdg-desktop-portal-gnome xdg-desktop-portal-kde xdg-desktop-portal-wlr xdg-desktop-portal-hyprland; do
    if PORTAL_BACKEND=$(find_portal_component "$backend" 2>/dev/null); then
        break
    fi
done
if [[ -n "$PORTAL_PATH" ]]; then
    report PASS "xdg-desktop-portal" "$PORTAL_PATH" "portal service available for file/directory chooser at GUI runtime" "none"
else
    report WARN "xdg-desktop-portal" "service executable not discovered" "portal service available for GUI file/directory chooser" "Install xdg-desktop-portal and the backend matching the desktop session; build is not blocked."
fi
if [[ -n "$PORTAL_BACKEND" ]]; then
    report PASS "desktop portal backend" "$PORTAL_BACKEND" "backend matching the active desktop environment" "none"
else
    report WARN "desktop portal backend" "no GTK/GNOME/KDE/WLR/Hyprland backend discovered" "backend matching the active desktop environment" "Install a matching xdg-desktop-portal backend (for Ubuntu GNOME, xdg-desktop-portal-gnome or xdg-desktop-portal-gtk); build is not blocked."
fi

if (( OFFICIAL_TARGET && NATIVE_FAILURES > 0 )); then
    echo "Ubuntu 24.04 native dependency repair command (printed only; not executed):"
    cat <<'APT_COMMAND'
sudo apt update
sudo apt install -y \
  build-essential pkg-config git python3 \
  libfontconfig1-dev libfreetype6-dev libwayland-dev \
  libx11-dev libx11-xcb-dev \
  libxcb1-dev libxcb-render0-dev libxcb-shape0-dev \
  libxcb-xfixes0-dev libxcb-randr0-dev \
  libxkbcommon-dev libxkbcommon-x11-dev \
  binutils
APT_COMMAND
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
