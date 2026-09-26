# T012 候选交付与实测矩阵

GPUI-0017 / attempt1；base `805724d51540887da229c8cbc05d49e57cc27924`。固定验收 ref `2041a38756b87ba7856dcd343624d98df2283c5a`。最终候选 head、完整本地结果、四作业 exact-head CI、三平台下载链接、600秒原始证据和审查/合并状态以 [Issue #24](https://github.com/gloryhui/p2p_file/issues/24) 的结构化事件为准；此文不提前填未来成功。

本地 Linux 优化构建预检：实际 executable33373568 bytes，带794个锁定上游源码归档/许可证的 tar.gz144759449 bytes。源是 base805724d 的 dirty 预检，明确 `candidate=false`，不是最终 head 产物；两项 SHA256 以预检日志为准。实际 X11/Xvfb/Openbox/Mesa 两个独立生产 GPUI 窗口映射耗时0.106416/0.124343秒，warm local 观察而非用户机器冷启动；metadata probe0.002976秒不是GUI启动。最终候选需重编、打包、verify和原生启动，不能复用旧SHA。

打包和边界检查：

```sh
python3 scripts/package-desktop-tests.py
cargo build --locked --release --features gui --bin p2p-desktop
python3 scripts/package-desktop.py --binary target/release/p2p-desktop --target x86_64-unknown-linux-gnu --output /tmp/p2p-candidate-new
python3 scripts/verify-desktop-package.py /tmp/p2p-candidate-new/candidate.json
```

Windows 用 Python3.12，binary为 `target/x86_64-pc-windows-msvc/release/p2p-desktop.exe`，target相应改为MSVC；macOS用arm64 native Rust/Python，`MACOSX_DEPLOYMENT_TARGET=13.0`、binary `target/aarch64-apple-darwin/release/p2p-desktop`。不是交叉编译就能做 native smoke。预检参数 `--allow-dirty` / `--allow-preflight` 不允许正式验收使用。

4项独立边界测试覆盖：实际格式架构不允许混平台/IntelMac；实际PE import RVA解析与越界拒绝；危险路径拒绝；dirty预检不能accepted及归档损坏被检测。完整 verify 实际解包、逐文件和794份源码哈希检查。最终包SHA还需与CI artifact中的candidate.json对照。

| 项目 | 当前证据边界 | 最终记录 |
| --- | --- | --- |
| 软件本地门禁 | fmt/full core/GUI/desktop/Clippy/check/build及原CLI E2E | Issue REPORT附命令/退出/计数 |
| Ubuntu24.04 x86_64 | 优化ELF、实际依赖、X11生产窗口；Wayland非实测 | exact-head Linux job/包及原生日志 |
| Windows x64 | hosted windows-2022完整GUI回归+windows-all，实际PE/Authenticode/zip | CI成功后才填写artifact |
| macOS arm64 | hosted macos14编译/全库/部署target13/实际ad-hoc .app校验 | 不代替AppleSilicon/macOS13交互 |
| 真实600秒 | 必须生产GPUI实际墙钟运行，记录两端接收bytes/elapsed/同一认证连接/方向和无新增文件任务 | Issue独立原始截图/单调观察/二进制SHA |
| 恢复/重名/中文 | T010原生512MiB暂停继续/目录备份/中文粘贴；T011实际OSkill/两端70MiB完整hash/10发布边界；三平台继续保留 | 不是实际满盘/断电/IME证据 |
| 双NAT/Apple互传/最低OS | 没有对应设备/独立NAT端点，BLOCKED | 不用loopback/CI/VPS单机替代 |
| 正式签名/公证 | Windows未签名，macOS仅ad-hoc无证书/未公证 | 签名状态从产物实查 |

最小外部步骤：

1. 下载本次exact-head三平台候选、校验归档SHA256与内置build-info；分别在Win10 22H2、Win11、macOS13+ Apple Silicon记录OS/架构/GPU/窗口启动、输入法/粘贴/缩放/原生选择器、签名提示，不删quarantine掩盖实际结果。
2. Windows与Linux置于两个真实独立NAT网络，自建同一信令服务；两方向中文/嵌套/空/大文件，记录已认证QUIC remote address、同TaskID暂停继续/OS强杀恢复、完整SHA256、双方持久回执、重名唯一备份。记录真实NAT环境与限制造成的失败。
3. 同一认证连接双方向测速，记录实际receiver bytes/elapsed、MiB/s/Mbps/取消后下一次测试和文件成功；至少600秒一次。Apple Silicon再与其它平台互传相同内容、恢复和目录。
4. 提供原始截图/日志/命令/head/binaryhash，经Controller实际证据复核。所有mandatory项满足后才能FINAL_ACCEPTANCE/关闭Issue24/决定正式Release；目前最终收尾应是FINAL_BLOCKED_EXTERNAL_VALIDATION。

CI artifacts保留14天，下载后可长期离线保管；产物中的完整来源材料会增大包体积，不承诺几MB。解包候选不删除用户配置/密钥/TaskStore/staging/journal/旧备份；回滚保留这些数据并手动继续，见 [运行文档](../../../packaging/RUNNING.md)。
