# P5 Web Guard / AI-Web-Guard

状态：**部分完成，尚未达到 V4.0 P5 退出条件**。

依据 `AI-SOC_Rust_AI-Web-Guard_项目计划书_V4.0.docx`，P5 的主阶段对象是 Rust 原生 Web Guard，而不是旧阶段文档中的“主机运行时”。旧主机运行时/Falco/audit/eBPF 内容已保留到 `p4-host-runtime-detection-annex.md`，其确定性行为规则属于 P4 Detection，采集能力属于 P2 Agent。

## 已实现

- `aisoc-web-guard` 是 Linux-only Rust crate，生产入口为独立 `aisoc-web-guard` binary，无 Python runtime dependency。
- Axum reverse proxy 已实现请求大小上限、hop-by-hop header 清理、CONNECT 拒绝、歧义 framing 拒绝、upstream redirect 禁止和 timeout。
- URI/文本 canonicalization、确定性 Fast Path、risk score/rule hit/reason code 已在 Rust 实现。
- `monitor -> shadow -> canary -> enforce` 四种模式已实现；canary 使用稳定采样比例，确定性高置信规则可以在 canary/enforce 阻断。
- 灰区 AI 调用受 `AiReviewBudget`、结构化 provider 输出、timeout 和 circuit breaker 控制；模型不可用时继续使用确定性结果，不能提升确定性高危规则的权限。
- Web request envelope 与 Web security event 使用 `aisoc-contracts` 的统一 DTO；安全决策写结构化 tracing 记录。
- `deploy/Dockerfile.web-guard` 为 Rust-only production image，`scripts/check-rust-first.sh` 会阻止 Python 运行时回退。

## 本轮审计确认的缺口

1. Web Guard 目前主要把 `WebRequestEnvelope + WebSecurityEvent` 写入结构化日志，**尚未直接通过 authenticated Ingest/mTLS/stream transport 落 central repository**；这使 P5→P3/P4 的生产证据链未完全闭环。
2. `route_id` 当前仍为 `None`，缺少 route-specific policy、AI budget、allow/deny exception、灰度范围与版本绑定。
3. 当前动作为 `ALLOW/MONITOR/BLOCK` 主路径；计划书要求的 challenge/rate-limit 等控制尚未形成完整执行与回滚/观察闭环。
4. 尚无真实 TLS/H2/request-smuggling differential gate，也没有在主流 Linux/反向代理组合上执行正式兼容矩阵。
5. 尚无可审计的 P95/P99 latency、AI review ratio、误报率、阻断率和上游故障退化基线。
6. 需要把 Web Guard event 与后续 Detection/Incident/Evidence 的 `request_id/event_id/raw hash` 做端到端一致性测试。

## P5 退出门禁

- Rust Web Guard 在真实 Linux reverse-proxy 场景启动并持续运行，生产进程无 Python。
- Web Guard 事件通过受认证链路进入 Ingest/central repository；断链、重试、重复投递和背压不丢失证据且保持幂等。
- monitor/shadow/canary/enforce 与 route-specific policy 有动态测试；高风险 Fast Path 不依赖 AI 才能阻断。
- AI 故障、超时、熔断、预算耗尽不会阻塞 deterministic Fast Path，也不会扩大权限。
- TLS/H1/H2、请求走私/歧义 framing、编码绕过、超大 body、upstream timeout 有差分与负面测试。
- 形成 P95/P99 latency、误报/阻断、AI 调用占比和资源上限报告，并达到计划书阈值。

在这些动态门禁关闭前，P5 只能标记“部分完成”。
