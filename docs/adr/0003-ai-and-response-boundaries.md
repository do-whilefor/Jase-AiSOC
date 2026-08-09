# ADR-0003：AI 与响应安全边界

状态：Proposed  
日期：2026-08-03

## 背景

原始日志可包含攻击者控制文本，模型会产生幻觉，多个模型一致也不证明事实。响应执行器具有高权限；如果分析与执行共享自由文本或服务身份，错误结论会直接扩大成业务影响。

## 决策

- AI 只接收通过 Review Gate 的 Incident Evidence Package，不逐条消费原始日志流。
- Analyzer 输出原子 Claim、证据 ID、未知项和替代解释；确定性工具结果优先。
- Tool Gateway 默认只读，按租户和对象重新授权，输入/输出都经 Schema、大小、超时和结果量检查。
- 模型保证等级只能减少允许动作或增加审核，不能单独提高权限。
- 响应使用 R0-R3 阶梯。Action Runner 只接受注册动作 ID 和固定参数；R2 需要 TTL/回滚/验证，R3 默认人工审批，关键资产双人审批。
- 原生 Action Runner 初版只允许 `local_single_node`，并从本机私有 Agent config 绑定 tenant/host/
  agent；不匹配在命令前拒绝。多主机动作必须经未来的认证 Agent-side 固定动作边界，禁止中央主机
  代执行远端目标。
- 通知由独立 worker 从 outbox 领取，目标只来自部署配置；固定 host allowlist、HTTPS、HMAC、
  幂等 ID、最小字段、无重定向和有界 retry/DLQ 是强制边界。
- 模型、工具或 Provider 全部不可用时，确定性检测、Incident、证据查询和人工响应继续运行。
- 运营控制台只能调用固定的响应详情、审批、排队与回滚 API；浏览器不能选择任意上游 URL/Adapter、
  改写 tenant 或启用执行器。写请求具有 Origin/Referer、绑定 exact origin+Bearer 的 HMAC nonce、
  请求大小/字段白名单与幂等键，后端 RBAC、自审批隔离和状态机仍是唯一授权依据。

## 结果

AI 可以提高分析效率但不成为事实源或高权限执行器。代价是需要 Claim-Evidence 校验、策略/审批服务和更多失败/降级测试。

## 验证

使用日志/URL/文件名 Prompt 注入、伪造 evidence_id、跨租户工具参数、Provider 全故障、旧审批重放、PID/path 替换、动作超预算和回滚失败场景进行动态验证；未授权工具调用和跨租户引用必须为 0。
