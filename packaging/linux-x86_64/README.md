# Linux x86_64 GUI package

本目录提供 Linux 本机 GUI 打包诊断与构建入口，复用仓库现有候选包测试、打包器和 verifier，不复制打包核心。

## 支持范围

- **正式构建验收目标：Ubuntu 24.04 LTS Desktop x86_64**
- Rust target：`x86_64-unknown-linux-gnu`
- Debian、Fedora、Arch、Manjaro 等只提供 best-effort 依赖映射与构建诊断；未经真实验证不视为等价正式支持
- WSL 不是 Linux Desktop 正式验收环境；无 X11/Wayland 会话的服务器也不能证明 GUI runtime 可用

脚本把构建环境与 GUI runtime 分开报告。缺少 DISPLAY/Wayland 或 portal 会产生 WARN，不阻止纯打包；这不代表窗口、文件选择器、Wayland、显卡或真实桌面交互已验证。

## 环境诊断

```bash
./packaging/linux-x86_64/doctor.sh
```

doctor 只检测、解释和打印建议，不会调用 `sudo` 或安装系统软件。构建不需要 root。它检查编译器/链接器、pkg-config、Git、Rust 工具链/target、Python/tomllib、打包审计工具所需的 `ldd`/`readelf`，以及 GPUI 使用的 Fontconfig、FreeType、Wayland、X11/XCB、xkbcommon native 开发能力。

Ubuntu 24.04 缺少编译工具或 GPUI 开发库时，可手动复制以下命令。doctor 只会打印，不会执行：

```bash
sudo apt update
sudo apt install -y \
  build-essential pkg-config git python3 \
  libfontconfig1-dev libfreetype6-dev libwayland-dev \
  libx11-dev libx11-xcb-dev \
  libxcb1-dev libxcb-render0-dev libxcb-shape0-dev \
  libxcb-xfixes0-dev libxcb-randr0-dev \
  libxkbcommon-dev libxkbcommon-x11-dev \
  binutils
```

Rust 和 Cargo 最低版本均为 1.85.0。建议使用 [rustup](https://rustup.rs/) stable；旧版本运行 rustup update stable 后重新执行 doctor，然后安装目标：

```bash
rustup update stable
rustup target add x86_64-unknown-linux-gnu
```

Python 需要 3.11+（推荐 3.12）且能 `import tomllib`。Ubuntu 24.04 系统 Python 满足版本要求；若其它发行版自带版本过旧，请按该发行版或 [python.org](https://www.python.org/downloads/source/) 的方式单独安装新版本，不要用旧版系统 `rustc/cargo` 替代 rustup。

best-effort 发行版示例（需根据 doctor 报出的缺失 capability 调整；不会自动运行）：

```bash
# Fedora / RHEL family
sudo dnf install -y gcc gcc-c++ pkgconf-pkg-config git python3 binutils \
  fontconfig-devel freetype-devel wayland-devel libX11-devel libxcb-devel \
  libxkbcommon-devel libxkbcommon-x11-devel

# Arch / Manjaro family
sudo pacman -S --needed base-devel pkgconf git python binutils \
  fontconfig freetype2 wayland libx11 libxcb libxkbcommon libxkbcommon-x11
```

如果某发行版模块名与示例不同，请安装提供 doctor 指定 pkg-config capability 的 `-dev` / `-devel` 包；这些命令不是正式支持承诺。

Linux GUI 文件选择器依赖 D-Bus 上可用的 `xdg-desktop-portal` 服务，以及与桌面环境匹配的 portal backend（如 GTK/GNOME/KDE）。Ubuntu GNOME 可手动安装 `xdg-desktop-portal` 与 `xdg-desktop-portal-gnome`；其它桌面请选对应 backend。portal 缺失或没有交互会话只作为 runtime WARN。doctor 看到 DISPLAY 或 WAYLAND_DISPLAY 也只证明变量存在，不证明 GUI 窗口能正常启动。

## 构建候选

完整候选需要干净的 Git 工作区。默认输出到仓库外的 `$HOME/p2p-file-builds/` 新目录；可指定含空格的输出路径：

```bash
./packaging/linux-x86_64/build.sh
./packaging/linux-x86_64/build.sh --output "$HOME/p2p-file-builds/acceptance linux"
```

脚本按顺序调用 doctor、clean worktree 检查、`scripts/package-desktop-tests.py`、锁定依赖的 release GUI build、`scripts/package-desktop.py` 与 `scripts/verify-desktop-package.py`。doctor 的必需项失败会在 Cargo 编译前停止。输出目录已有文件时拒绝覆盖。

输出包括 `.tar.gz`、`candidate.json`、共享打包器生成的 `.sha256` sidecar。build 摘要从 `candidate.json` 读取 build SHA、target、archive SHA256 和签名状态，并报告包内 executable 路径与 doctor 的 GUI runtime WARN 摘要。

打包只确认 ELF 架构、动态依赖/符号版本和候选清单；它不证明 DISPLAY/Wayland/portal、GPU/Vulkan、中文输入法、物理桌面窗口或其它发行版运行验收。

## 常见问题

- **pkg-config 找不到模块**：按 doctor 显示的 capability 安装对应 `-dev` / `-devel` 包；Ubuntu 24.04 的完整命令见上文。
- **X11/XCB headers 或 Wayland headers 缺失**：检查 `libx11-xcb-dev`、各 `libxcb-*-dev`、`libwayland-dev` 等能力。
- **portal 文件选择器不可用**：安装 `xdg-desktop-portal` 与桌面匹配的 backend，并在真实桌面 D-Bus session 验证。
- **没有 DISPLAY / WAYLAND_DISPLAY**：包可以编译；在交互桌面启动应用后再验证 GUI runtime。
- **WSL**：可用于 best-effort 编译实验，但不能记为 Ubuntu Desktop 验收。
- **Python 太旧**：使用 Python 3.11+ 并确认 `python3 -c 'import tomllib'` 成功。
- **Rust target 缺失**：运行 `rustup target add x86_64-unknown-linux-gnu`。
- **dirty tree**：提交或 stash 变更后再构建候选。
- **输出路径含空格**：将完整路径放在引号内传给 `--output`。

Linux 包未做代码签名；候选 metadata 中的签名状态如实保持为 unsigned。
