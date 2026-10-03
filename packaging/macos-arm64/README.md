# macOS Apple Silicon GUI package

本目录提供 macOS 本机诊断和候选包构建入口，调用仓库现有的共享打包器、边界测试和 verifier；它不复制打包逻辑。

## 支持范围

- 构建机：Apple Silicon arm64，原生 arm64 终端环境
- 最低系统：macOS 13
- Rust target：`aarch64-apple-darwin`
- 此入口不接受 Intel Mac、Rosetta 进程或 universal2 候选构建；Intel 使用 [macos-x86_64 入口](../macos-x86_64/README.md)。

Rosetta 下的 `x86_64` 进程不能作为正式候选构建环境，即使主机本身是 Apple Silicon。请在 Finder 的终端应用信息中关闭“使用 Rosetta 打开”，再启动原生终端。

## 准备环境

先运行 doctor；它只检查和解释，不会安装软件或修改系统：

```bash
./packaging/macos-arm64/doctor.sh
```

完整候选需要 Xcode Command Line Tools、Git、rustup 管理的稳定 Rust 工具链（rustc 与 Cargo 最低版本均为 **1.90.0**）、`aarch64-apple-darwin` target，以及 Python 3.11 或更新版本（推荐 3.12，且需包含 `tomllib`）。建议使用 rustup stable；已有 Rust 工具链可运行 `rustup update stable` 升级，然后重新运行 doctor。

- 缺少 Apple 工具时，doctor 会提示 `xcode-select --install`。请自行确认并启动安装。
- Rust 使用 [rustup](https://rustup.rs/) 安装；安装工具链后运行 `rustup target add aarch64-apple-darwin`。
- Python 可从 [python.org](https://www.python.org/downloads/macos/) 获取。若你已使用 Homebrew，也可自行运行 `brew install python@3.12`；Homebrew 不是强制依赖。

## 构建完整候选

完整候选要求干净的 Git 工作区，且输出目录必须位于仓库外。默认输出到 `$HOME/p2p-file-builds/` 下的新目录：

```bash
./packaging/macos-arm64/build.sh
./packaging/macos-arm64/build.sh --output "$HOME/p2p-file-builds/acceptance macos"
```

构建脚本按顺序运行 doctor、`scripts/package-desktop-tests.py`、锁定依赖的 release GUI build、`scripts/package-desktop.py` 和 `scripts/verify-desktop-package.py`。已有非空输出目录不会被覆盖。完整候选 ZIP、`candidate.json`、旁置 SHA256、依赖源码和许可证材料由共享打包器生成；终端摘要中的 archive SHA256 读取自 `candidate.json`。

## 本机轻量 `.app`

只需在本机运行的轻量应用时：

```bash
./packaging/macos-arm64/build.sh --app-only --output "$HOME/p2p-file-builds/local app"
```

脚本会明确输出：**本机轻量运行包，不是完整审计候选**。此模式保留许可证声明，但不生成候选 ZIP、`candidate.json`、archive SHA256 或完整依赖源码归档，因此不运行候选 verifier。应用的可执行文件位于 `.app/Contents/MacOS/p2p-desktop`。

## 签名与安全边界

共享打包器会验证 `.app` 的 ad-hoc 签名。准确状态是 **ad-hoc / not notarized**；它不是 Developer ID 正式签名，也没有 Apple 公证。不要为了通过启动检查而关闭 Gatekeeper 或移除 quarantine。系统是否允许打开应用，按本机安全提示处理。

## 常见问题

- **doctor 报 Rosetta 或 x86_64**：使用原生 arm64 Terminal/iTerm 进程；Intel Mac 使用 `packaging/macos-x86_64/build.sh`。
- **缺少 Xcode Command Line Tools / SDK**：按 doctor 提示手动执行 `xcode-select --install`，并确认 `xcode-select -p` 指向有效开发者目录。
- **Rust target 缺失**：运行 `rustup target add aarch64-apple-darwin`。
- **Python 太旧或没有 `tomllib`**：安装 Python 3.11+，推荐 3.12，并确认 `python3 -c 'import tomllib'` 成功。
- **dirty worktree**：完整候选必须对应一个已提交的干净源码树；先提交或 stash 变更。
- **输出目录非空**：指定新的仓库外目录；已有证据不会被覆盖。

本地脚本、静态检查或 GitHub Actions 都不等同于 Apple Silicon 真机安装、公证或 GUI 交互验收。当前非 macOS 环境无法证明这些行为。
