# 桌面后台运行与状态面板（Issue #61）

设置页新增「后台运行」：关闭窗口后后台运行、登录系统时启动。两项默认关闭，分别
保存并立即反馈结果，不要求先填写信令地址。旧 schema v1–v5 配置迁移至 v6，默认
保持关闭，保留密码、可信设备、接收目录和端口规则。普通设置旧草稿不会覆盖已保存的
后台选项或安全字段。

macOS 启动后始终在顶部菜单栏显示双节点连接图标。图标随真实状态切换：离线为横线、
连接中为双短线、在线为圆点、传输或测速中为活动标记、需要处理为感叹号。
使用系统 template 图像以适配浅色/深色菜单栏，悬停显示状态文字。左键展开实时面板，
右键菜单提供状态面板、打开主窗口、设置和退出。Dock 再次打开应用也会恢复主窗口。

面板显示本机设备 ID、信令状态、已认证设备数、活动和排队文件数、合计实时速度、
运行/等待/异常隧道数、测速状态和最近提示。每 200 毫秒消费现有业务投影；折叠目录不
影响计数。不展示密码、授权密钥或远端文件路径。面板失焦关闭，再次点击可重开；面板
与主窗口共享同一 Session，不创建第二条业务连接。

Windows 提供通知区域图标和状态菜单，左键恢复主窗口。Linux 使用 SNI/D-Bus 托盘，
不增加 GTK 或 AppIndicator 系统依赖；桌面须支持 StatusNotifierItem（GNOME 可安装
相应扩展）。托盘初始化失败时保留主窗口；后台隐藏后托盘 host 消失时恢复主窗口。

## 窗口、后台和退出

- 启用关闭后后台运行且托盘可用：macOS / Windows / Linux X11 隐藏原生窗口，保留
  同一窗口和 Session；文件与隧道继续运行。再次打开恢复原窗口，不重置状态。
- Linux Wayland 没有客户端任意隐藏窗口的通用协议；关闭时最小化窗口，保留任务栏
  和托盘入口，后台业务继续运行。没有托盘时关闭窗口正常退出。
- 默认关闭后退出；托盘「退出」、面板「退出」、Ctrl/Cmd+Q 始终明确退出。退出先停止
  Session 并有界等待结构化清理，保存可恢复进度；不会通过直接终止进程退出。
- 重启后仍需显式继续未完成文件。可信设备、免密、隧道自动启动与撤销沿用已有授权。

## 登录启动

仅注册当前用户登录启动，不装系统服务，不要求管理员权限，不保存对端密码。程序
启动参数为 `--background`。登录启动已启用、已有网络设置且托盘创建成功时后台启动；
首次密码提示、缺少网络设置或无可用托盘时显示主窗口。

| 平台 | 当前用户启动项 |
| --- | --- |
| macOS | `~/Library/LaunchAgents/io.github.gloryhui.p2p-file.plist`，RunAtLoad，无 KeepAlive |
| Windows | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` 中的 `P2P File` |
| Linux | `$XDG_CONFIG_HOME/autostart/p2p-file.desktop`，未设置 XDG 时使用标准用户配置目录 |

启用/关闭从下次登录生效。注册失败不会显示保存成功；配置写入失败时尝试恢复原启动
选项并报告回退失败。启动项包含当前可执行文件的绝对路径，移动应用或改安装路径后应
关闭再开启登录启动。macOS 建议先将应用放入 Applications；系统「登录项」中禁用
后台项目会阻止启动，系统选择优先。

## 验证边界

`cargo test --locked --features gui --lib` 覆盖迁移、旧草稿保留、图标状态、信令与 peer
状态独立、退出条件和启动项路径编码。三平台 GPUI CI 负责原生构建和业务回归。

Linux X11 原生窗口/模拟 SNI host 冒烟：

```bash
cargo build --locked --features gui --bin p2p-desktop
dbus-run-session -- /usr/bin/python3 scripts/desktop-background-smoke.py \
  --binary "$PWD/target/debug/p2p-desktop" --output /tmp/new-background-evidence
```

需要 Xvfb、openbox、xdotool、xwininfo、python3-dbus、python3-gi。使用隔离的 D-Bus、
X11 和应用数据，不修改当前用户真实登录项。验证关闭隐藏、同窗口恢复、面板失焦与
重开、host 消失回退、退出和无托盘登录启动；不证明真实 macOS 菜单栏、Windows
Explorer、Wayland 最小化、系统登录或公网传输。

macOS 人工验收：浅色/深色与高 DPI 菜单栏、点击/右键、双屏定位、面板实时状态；
传输与隧道运行时关闭窗口后继续工作；恢复主窗口和 Dock reopen；退出后端口释放；
登录启动与关闭启动。Windows 和 Linux 分别验证真实桌面托盘、登录启动及无托盘回退。
