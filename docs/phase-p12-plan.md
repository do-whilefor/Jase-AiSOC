# P12 Console / Operations

状态：**部分完成，尚未达到 V4.0 P12 退出条件**。

V4.0 的 P12 是安全运营控制台与运营可观测面。原 `phase-p12-plan.md` 中的跨发行版硬化/性能/安全/发布内容属于 P13，已完整保留到 `p13-hardening-detail-annex.md`，P13 主文档继续作为 Hardening / Production Readiness 门禁。

## 已实现

- 已存在 Rust `aisoc-console` crate、控制面 API 与前端 `console/`，并覆盖总览、Incident、资产、攻击溯源、恶意文件、模型审核、规则/情报、响应队列和系统运营等视图的首版能力。
- Incident 当前 revision 的 timeline、evidence index、Claim、实体/边和 trace 可通过租户作用域 API 查询。
- Response 详情、审批/拒绝、执行排队与 rollback request 已具备受控写入口；服务端仍执行 RBAC/审批/幂等/策略约束。
- Rule lifecycle、model review summary、Agent heartbeat/version、系统状态与审计数据已形成部分运营读模型。
- Browser 写操作具有 Origin/Referer、write-session nonce、有界请求/响应与 fixed-path proxy 等安全边界；secret 不应进入浏览器持久化存储。

## 仍未闭环

1. Web Guard 路由、命中、shadow/canary/enforce 指标没有与 central event/Incident 形成完整运营闭环。
2. Rule/IOC 运营仍缺完整质量数据、受管 IOC lifecycle、golden dataset precision/recall/FPR 与一键 rollback 证据。
3. Model Ops 缺主动 provider health、credential validation、budget/cost/latency SLO 和 provider failover 的真实运营数据。
4. Response Ops 缺多主机 Agent Action Runner 的真实执行、TTL、post-verification 和至少三类已验证 rollback 证据。
5. System Ops 缺 JetStream backlog/age、对象存储容量、数据库容量、deployment inventory、备份/恢复状态、依赖探测和真实告警联动。
6. 尚未在真实 HTTPS reverse proxy + 浏览器会话下完成双租户 RBAC/CSRF/Origin/nonce/幂等安全验收。

## P12 退出门禁

- WebGuard / Incident / Evidence / Rule / Model / Malware / Trace / Response / System 九类运营面均从 authoritative Rust/central storage 读取，不从 legacy Python 生产服务取数。
- 所有写操作都有租户 RBAC、审计、幂等和失败回滚；浏览器不能绕过服务端审批/策略边界。
- 运营页不伪造不可用指标；关键 SLO/health/backlog/capacity/backup 数据具有真实来源与 freshness。
- 双租户 HTTP 负面测试、HTTPS 浏览器安全测试、并发操作和故障注入通过。

以上门禁未关闭前，P12 保持“部分完成”。
