# p2p_file

点对点（P2P）文件传输工具。**Rust** 实现，目标是**公网 NAT 穿透直连**，中继只作为兜底。

## 状态

仓库已初始化，尚未写代码。架构见 [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)。

## 开发

```bash
# 需要 Rust 工具链（尚未安装）
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"

cargo build
cargo run -- --help
```
