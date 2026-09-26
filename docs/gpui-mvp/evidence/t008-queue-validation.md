# T008 全局队列与公平调度证据

Task T008，dispatch GPUI-0013，attempt 2（前次 GPUI-0012/PR #36 的 Review 请求返工）。基线是 T007 merge `c07ab1fb6c79debb0254f7948b878e1a48dd5ca7`。固定验收文档 ref：`2041a38756b87ba7856dcd343624d98df2283c5a`；不变更其门禁。

最终 attempt 2 的 12 项本地检查全部通过：GUI 全库 405 项、desktop 专项 135 项、核心全目标 270 项库测试及 1 项二进制测试，全部 0 ignored；fmt、核心/GUI Clippy（-D warnings）、GUI check/build、signal/net/transport 专项与 CLI build 均通过。最终 exact-head CI/Review 以 Issue #24 对应 REPORT/ACCEPTED 为准；前次候选的成功 CI 不能用于本次返工验收。

本地完整验证与最终候选 exact-head CI/Review 的 SHA、run/job、结果以 Issue #24 的 REPORT/ACCEPTED/MERGED 为准；本文件在最终候选 commit 前生成，不预填未来 SHA 或虚构运行结果。

- `queue::tests`：FIFO 跳过离线 peer、降 3→1 不杀任务且不超额补位、非法配置拒绝、目录元数据独立槽、4096 等待容量的原子入队、TaskId 不重绑定、旧 completion nonce 不释放新尝试，以及速率的恢复 baseline/暂停/时钟/计数边界。
- `queue::fairness_tests`：实际 AsyncWrite 就绪/短写模型，N=1/2/3 持续就绪时每次 poll 的最大累计 payload 差 ≤64 KiB，三组短写顺序（含全部整 quantum）各 20000 轮检查且每项获得多份额；异步 write_all 模型逐次断言差值与 poll 无全局锁；连续新小任务不饥饿既有就绪任务、三个 writer 的登记上限和释放重用；100 quantum 慢写借用与重新就绪无信用积累；底层写 panic 后其他项继续运行。算法和接收端在途误差见 ADR-007。
- `frame_budget::tests`：56 MiB 大帧总限额、控制帧预留、8 MiB 单任务限额、取消/非法长度归还预算；实际 1 MiB 分片解码在处理期间保留 lease，坏帧释放预算。
- `transfer::tests`：真实认证连接上 1/2/3 文件发送，满额接收明确 Busy且尚未创建接收任务，手动重试完成；预留槽在启动之前暂停、旧执行器拒绝且不误释放新槽；排队暂停及无效 batch 不留下改绑/无所有者任务；阻塞任务旁边的另一个文件完成并验证暂停释放槽；目录组一个文件缺失时其余完成、累计字节准确且 group 非 Completed。
- `task_events::tests` 和 transfer overflow 测试：10000 进度合并、不挤掉终态；超过 256 生命周期事件时 resync 标志及随附权威快照恢复全部当前状态；快照读取不产生进度事件。
- 全部现有文件/目录、持久 checkpoint、暂停、回执丢失、真实 child process kill 与继续传输回归保留。

前次候选 Review 发现 Queued 持久化与内存队列 admission 的可见间隙。新增 cfg(test) worker gate 复现暂停返回“未传输或排队”，保留失败证据。修复同一 writer 临界区的可见性、首次文件/目录选择直接 admission 和 Session 删除隐式二次入队；保留原失败断言，并增加首次选择返回前的文件/目录暂停及队列满额保留 Interrupted 后真实 QUIC 手动继续回归。真实 QUIC 暂停后的 cleanup gate 还复现了 Continue 被仍持有旧槽的执行器当作重复请求忽略，返回 Ok 却没有新排队任务；修复在 writer 锁外等待旧活动和旧槽释放，再持久入队，验证同一 TaskId 的实际继续与双方回执。单 blocking worker 的确定性队列还复现了选择 future 在持久提交排队期间取消却生成幽灵任务；在首次写入前再次检查取消 token/session epoch，保留失败断言后验证无任务、无队列条目。

增加整 quantum 首项后，旧实现曾复现 0..131072 字节差，超过 64 KiB；本地保留失败日志，修正首次入环优先份额与同步成功写的 cooperative yield，保留扩展断言后重新验证。

本地使用 Linux loopback QUIC、真实临时文件及受控 gate；公平部分使用确定性模拟写就绪，不声称公网吞吐或物理跨平台 UI 验收。物理 Windows 10/11、Apple Silicon、双 NAT、原生长时测速与发行签名仍需 T012 真实环境证据。Windows 目录 fsync 和文件系统发布能力边界沿用 ADR-006。
