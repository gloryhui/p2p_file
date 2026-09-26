# T009 测速验证证据

GPUI-0014 / T009 attempt 1。基线 T008 merge `3efa1faf585f78e3f7fbc5c3ba82a33ad739c6f7`；固定验收 ref `2041a38756b87ba7856dcd343624d98df2283c5a`。

12 项本地门禁已通过：GUI 全库 414、desktop 专项 143、核心库 271+二进制 1，全部 0 failed / 0 ignored；fmt、核心/GUI Clippy（-D warnings）、GUI check/build、signal/net/transport 专项与 CLI build 均通过。最终 exact-head CLI E2E、CI 与 Review/merge 的 SHA 和链接以 Issue #24 的 REPORT/ACCEPTED/MERGED 为准。本文件在提交前生成，不预填未完成的结果。

- 共享内存 kernel 的可控 Tokio 时钟：300/599 秒仍运行、600 秒结束，137 字节短写实际计数，600000ms 接受/600001ms 拒绝。CLI 301/599/600 接受，601 拒绝；默认 10 秒和既有 upload 接收方 elapsed、两方向 loopback 回归保留。
- 实际认证 QUIC/Ed25519/channel-binding+能力协商上的生产测速 dispatcher：双方向最终 bytes/elapsed 两端一致；两个 receive 目录无新增条目、TaskStore 无测速任务。
- 完成后的旧 lease 清理期间，新请求实际进入等待、旧 permit 释放后新 ID 正常执行；使用两个确定性 gate，无 sleep 时序假设，保留去除等待时立即 Busy 的 negative 日志。
- 双方同时请求：较小 NodeId 唯一协调者，一方成功另一方明确 Busy，随后下一次测速正常；不新建未经身份确认的连接。
- 活动/预留文件拒绝测速且原 Queued/Paused 状态保留；测速拒绝新选择且不创建任务；接收侧 Busy 不关闭共享连接。
- 双方分别发起取消，终态为 Cancelled 且速率归零；旧 lease 单向流不能污染下一次测速；下一次真实文件传输内容与双方持久回执正确。
- 在合法数据 stream 开始前注入错误 token 与 4097 字节首帧，实际检查 stop=5，合法数据和下一次测速继续正常。
- 旧 schema-only Hello 能力 15/31/63 明确拒绝执行协商；旧字节和 CLI 编号仍有黄金断言。
- 保留 T004–T008 所有原回归，包括真实进程强杀、checkpoint、暂停、目录/重名事务发布与字节公平。

本地早期测试曾发现旧 CLI 301 秒非法边界、当前 Hello 能力字节未升级、跨端快照未等对端 Completed，以及取消终态断言失败。修复业务/测试契约及取消确认，保留最终一致性、安全和取消断言。具体日志保存在施工审计目录并由 Issue #24 总结，不删除失败测试或虚构平台结果。

集成时长缩放与可控时钟不冒充真实 600 秒。物理 Windows 10/11、Apple Silicon、双 NAT、原生长时测试与签名仍属于 T012 的外部验收。
