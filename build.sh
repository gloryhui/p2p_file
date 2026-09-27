set -e

P2P_REPO_DIR="$(git rev-parse --show-toplevel)"
P2P_RELEASE_SHA="abf82c19d21becfe6ab442f0355148ee6d1afa3a"

git -C "$P2P_REPO_DIR" fetch origin main
if [[ "$(git -C "$P2P_REPO_DIR" rev-parse origin/main)" != "$P2P_RELEASE_SHA" ]]; then
  print -u2 "origin/main 已变化，请先确认要打包的 commit"
  exit 1
fi

P2P_BUILD_DIR="$(mktemp -d "${TMPDIR:-/tmp}/p2p-file-clean.XXXXXX")"
rmdir "$P2P_BUILD_DIR"
git -C "$P2P_REPO_DIR" worktree add --detach "$P2P_BUILD_DIR" "$P2P_RELEASE_SHA"
cd "$P2P_BUILD_DIR"

test -z "$(git status --porcelain)"
test "$(uname -m)" = arm64
xcode-select -p
python3.12 --version

rustup toolchain install stable --profile minimal
rustup target add aarch64-apple-darwin --toolchain stable
export RUSTUP_TOOLCHAIN=stable
export MACOSX_DEPLOYMENT_TARGET=13.0
export CARGO_TARGET_DIR="$P2P_REPO_DIR/target"

cargo fetch --locked
python3.12 scripts/package-desktop-tests.py
cargo build --locked --release --features gui --bin p2p-desktop --target aarch64-apple-darwin

export P2P_PACKAGE_DIR="$HOME/Desktop/p2p-file-mac-arm64"
mkdir -p "$P2P_PACKAGE_DIR"
test -z "$(find "$P2P_PACKAGE_DIR" -mindepth 1 -maxdepth 1 -print -quit)"

python3.12 scripts/package-desktop.py \
  --binary "$CARGO_TARGET_DIR/aarch64-apple-darwin/release/p2p-desktop" \
  --target aarch64-apple-darwin \
  --output "$P2P_PACKAGE_DIR"

python3.12 scripts/verify-desktop-package.py \
  "$P2P_PACKAGE_DIR/candidate.json"

cat "$P2P_PACKAGE_DIR"/*.zip.sha256