# T010 原生界面与集成验证

GPUI-0015 / T010 attempt 1；基线 T009 merge `9392f747ceb7a471551c9772fdff2db0e73bf0cc`，固定验收 ref `2041a38756b87ba7856dcd343624d98df2283c5a`。最终候选 SHA、exact-head CI、独立 Review 和合并结果以 Issue #24 的 REPORT/ACCEPTED/MERGED 为准，不预填未来结果。

## 本地门禁

12 项门禁：fmt、GUI 全库 418、desktop 专项 147、核心库 271+二进制 1、核心/GUI Clippy（-D warnings）、signal/net/transport 专项、GUI check/build、CLI build；全部 0 failed / 0 ignored。最终候选 CLI E2E 另在 REPORT 记录。T004–T009 原测试全部保留，包括真实进程强杀恢复。

新增行为边界：
- 实际 QUIC TransferService 的 UI 投影跟随 Queued→Paused→显式 Continue→双方持久回执 Completed，固定 peer/TaskID、非活动速率为零，文件内容一致；不是用发送命令成功假装完成。
- 目录部分失败不能显示整体完成，空文件未收到回执时不是 100% 完成；展开只改变展示。
- 速率按相邻真实 bytes/elapsed 样本计算，平均和瞬时分开；旧 ID 基线不污染新测速；迟滞、取消、断开归零且不假完成。
- 测速终态缓存有界，新增历史不会驱逐活动测速。

## 实际 Linux 原生窗口 smoke

环境：本机 Linux x86_64，GPUI 0.2.2；X11/Xvfb、Openbox、Mesa software Vulkan；两个真实生产 GUI 进程，独立配置/身份/TaskStore/接收根；真实现有 signal-server 在 localhost。选择器是系统 GTK desktop portal，操作使用 xdotool 和 X11 剪贴板；截图直接来自原生窗口，没有绘制替代图或 mock 后端。这是软件显示服务器上的原生窗口，不是物理设备或双 NAT。

操作步骤与检查：
1. 保存配置后启动 A/B；用复制完整 ID 按钮/快捷键得到 B 的 32 位 ID，A 原生粘贴并 Ctrl+Enter。B 保持 peer 输入为空，仍完成认证、被动接收和自动任务显示。重启复制的 ID 不变，旧任务仍显示。
2. Ctrl+O 调用系统文件选择器，发送 151552 字节中文文件；两端回执 Completed，接收文件 SHA256 与源一致。Ctrl+Shift+O 调用目录选择器，发送 `folder/子目录/中文.txt` 与空目录；内容一致，目录分组 4/4 完成。Ctrl+E 展开，列表实际虚拟滚动。
3. Ctrl+T 启动 30 秒发送测速；运行期间 Ctrl+N/Save 将并发 1 改为 2，磁盘配置与队列限额均为 2，原连接测速仍继续。B Ctrl+Shift+T 取消，双方显示已取消和零速率，可立即再次测速。
4. Ctrl+D 切换接收方向，Ctrl+T 完成真实 30 秒；两端最终显示同一接收方 bytes/elapsed/Mbps。数值是本机测试结果，不作为固定性能门槛或公网承诺。
5. 原生选择 512 MiB `pause.bin`；Ctrl+Down 选择该任务，Ctrl+P 实际暂停，截图中已暂停且速率零；Ctrl+R 继续。双方同一 TaskID 持久 Completed/receipt，实际 SHA256 `9acca8e8c22201155389f65abbf6bc9723edc7384ead80503839f49dcc56d767` 一致。首个 harness 的 35 秒等待用尽时仍在 Transferring，之后核对实际完成与完整性；未将等待超时改写成及时成功。
6. 另一个真实 GUI 进程使用 GPUI 官方 X11 scale factor=2，内容 1520×1120 对应逻辑 760×560。测试 Tab、设置展开/收起、中文/emoji 剪贴板粘贴/选择/复制往返；截图中输入字段可见。没有将剪贴板往返称为物理中文 IME 测试。

原生 smoke 发现并修复隐藏设置输入焦点、逗号快捷键字面值和被动连接提示；心跳通知不再覆盖操作结果。原生 portal 自动化早期因无窗口管理器/未聚焦选择器及路径补全操作未选中文件夹，未产生目录成功证据；最终通过实际点击系统选择器的目录及选择按钮，才核对接收内容。旧失败日志保留在施工审计目录，未绕过选择器。窗口标题最后收敛为 `P2P File`；早期交互截图保留其原始标题。最终相同业务代码构建再次重启 A/B，身份与完成任务保留，并再次完成 30 秒接收测速：两端均显示 1996771095 字节、30.00 秒（UI 两位小数）、平均 532.45 Mbps。最终截图使用新标题，未伪造早期捕获时的代码 SHA。

## 截图

截图是测试专用身份和目录，没有私钥。以下原始图保留原生字体/显示服务器样式：

- [目录分组和被动接收](t010-native-directory.png)
- [测速期间保存并发](t010-native-speed-running.png)
- [远端取消与零速率](t010-native-speed-cancelled.png)
- [原生 Pause](t010-native-paused.png)
- [相同任务 Continue 后完成](t010-native-resumed.png)
- [2x 缩放、最小窗口与中文剪贴板](t010-native-dpi2.png)
- [最终构建原生 smoke](t010-native-final.png)

## 留到 T012 的真实外部验收

物理 Win10 22H2/Win11、Apple Silicon、Wayland、真实中文 IME、物理高 DPI、Windows↔Linux 双 NAT、原生 600 秒及签名/安装包仍需 T012 实际证据。Linux/Xvfb 软件窗口、单机 QUIC 和 CI 构建不能代替这些结果。完整故障、多实例及进程强杀矩阵在 T011 harness 记录。
