# macOS Intel GUI package

Intel Mac 的本机诊断与构建入口，复用共享打包器、边界测试与 verifier。

## 支持范围

- Intel x86_64 Mac，macOS 13 或更新版本，Rust target `x86_64-apple-darwin`。
- Apple Silicon 使用 [arm64 入口](../macos-arm64/README.md)，两种架构分别打包。
- 环境检查拒绝 Apple Silicon/Rosetta 进程；不以翻译执行替代 Intel 本机验证。
- CI 使用 `macos-15-intel` 原生构建和回归；macOS 13 最低系统、菜单栏与登录启动仍需实机验收。

## 准备与构建

```bash
./packaging/macos-x86_64/doctor.sh
./packaging/macos-x86_64/build.sh --output "$HOME/p2p-file-builds/intel candidate"
./packaging/macos-x86_64/build.sh --app-only --output "$HOME/p2p-file-builds/intel app"
```

需要 Xcode Command Line Tools、有效 macOS SDK、Git、rustup、rustc/Cargo >=1.90.0、
Python >=3.11（含 tomllib）和 `x86_64-apple-darwin` target。doctor 只检查并给出修复
命令，不自动安装软件；缺少 target 时执行 `rustup target add x86_64-apple-darwin`。

构建要求干净工作区和仓库外的新/空输出目录。完整模式依次执行共享边界测试、锁定依赖的
release GUI build、候选打包与校验，保留依赖来源材料、SHA256 和源码提交信息。
`--app-only` 仅输出可运行的 `P2P File.app` 与许可证材料，不生成完整审计候选。

CI 下载中，`p2p-desktop-app-only-x86_64-apple-darwin-*` 是轻量 Intel 应用 ZIP；
`p2p-desktop-x86_64-apple-darwin-*` 是完整候选。下载后解压轻量 ZIP，将 `P2P File.app`
放入 Applications，通过 Finder 打开。完整安装说明见 [RUNNING.md](../RUNNING.md)。

签名状态为经过检查的 ad-hoc / not notarized，没有 Developer ID 或 Apple 公证。
真实系统登录、中文输入、菜单栏交互与 Intel/Apple Silicon 互传不由构建结果替代。
