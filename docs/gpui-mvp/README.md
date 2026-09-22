# GPUI 桌面 MVP：开发与 Agent 调度入口

状态：设计交付，尚未授权按本文档自动开始代码施工。
规格版本：1.0（2026-09-23）。
代码基线：`312d4665a6688e66f0b1de790e27b65ce59b7834`（#20 / PR #23 已合并）。
本次文档 PR 不包含 GUI 依赖或实现代码。

## 1. 从哪里开始

| 文件 | 谁必须读 | 内容 |
| --- | --- | --- |
| [PRODUCT.md](PRODUCT.md) | 所有 Agent | 用户需求、默认决策、界面、功能验收与排除项 |
| [TECHNICAL.md](TECHNICAL.md) | 施工与复核 Agent | 当前代码证据、模块边界、网络、协议、任务状态、存储与崩溃恢复 |
| [TASKS.md](TASKS.md) | 所有 Agent | T001—T012 工程任务、允许修改范围、产物、逐项验收 |
| [PIPELINE.md](PIPELINE.md) | 所有自动 Agent | Issue 事件格式、派工、领取、租约、报告、复核、合并、恢复与幂等 |
| [AGENT_PROMPTS.md](AGENT_PROMPTS.md) | 定时器配置者及各 Agent | 可复制的控制/施工 Agent 提示词与运行要求 |

总控入口：[Issue #24](https://github.com/gloryhui/p2p_file/issues/24)。文档 PR、固定文档 SHA 和当前审核状态见该 Issue 的 BOOTSTRAP 事件。
**以总控 Issue 的有效控制事件为唯一施工入口，不能仅因 TASKS.md 列出了任务就自行施工。**

## 2. 本轮明确交付

1. 一份可由其它 Agent 实施的详细开发规格。
2. 一条可重复触发、可审计的控制/施工流水线。
3. 一个 GitHub 总控 Issue，后续派工、领取和工作汇报均在该 Issue 评论中追加。
4. 文档提交与 PR，供控制 Agent 首次审核。

不实现桌面代码，不安装定时器，不替用户选择定时 Agent 模型，不自动合并本次文档 PR。

## 3. 两层职责

- 控制 Agent：读取报告 → 审查具体代码和测试 → 明确接收/返工/阻塞 → 合并已通过 PR → 发布下一施工单。
- 施工 Agent：读取有效施工单 → 合法领取 → 在指定基线上施工 → 测试 → commit/push/PR → 汇报 → 停止。
- 人类：提供仓库权限、调度环境及跨平台真机；处理超出规格的产品决策。
- 第一次控制运行先审核本套文档和文档 PR（GPUI-0000 / T000），合并后才能发布 GPUI-0001 / T001。

## 4. 工作边界

GUI 使用 GPUI，不以 WebView、网站、Tauri 或截图替代。复用现有 Rust 核心，保留 CLI。
第一版无接收方批准弹窗，知道节点 ID 即可尝试发起自动接收；仍保留密码学身份校验。
支持目标：Ubuntu 24.04 LTS x86_64、Windows 10 22H2 及更新版本 x86_64、Apple Silicon macOS。
目标平台是否真正可用必须由 T001 技术验证及 T012 原生测试证明，不允许写“能编译所以都支持”。

#21（1 GiB 队列/disk writer）和 #22（传输窗口调优）不是本流水线的默认任务。
为了 GPUI 线程安全、暂停、队列、目录和恢复允许调整对应核心接口；这不等于允许顺手实现其它 Issue。

## 5. 何为完成

T001—T012 均被控制 Agent 接收并合并，三平台交付与人工验收矩阵完成，控制 Agent 追加 FINAL_ACCEPTANCE，才关闭总控 Issue。
缺少 Windows 10 或 Apple Silicon 实机验证时必须记录 BLOCKED / 待验证，不能将 GitHub runner 编译成功当作完整发布验收。
