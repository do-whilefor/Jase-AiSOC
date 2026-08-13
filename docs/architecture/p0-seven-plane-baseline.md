# P0 七平面架构冻结基线

状态：P0 代码基线已实现，待 Linux 编译和验证。本文以《AI-SOC_项目开发与实施计划书》为唯一上位设计，不引入第二套生产架构。

## 强制技术边界

- 生产应用层统一使用 Rust；浏览器交互层使用 Leptos + Rust/WASM/SSR。
- PostgreSQL 是中心权威状态，NATS JetStream 负责 Central/HA 消息解耦，S3/MinIO 保存不可覆盖的 Raw Evidence。
- Bash、TOML、YAML、SQL migration、systemd unit 和容器清单仅用于声明、构建与部署，不承载生产安全业务逻辑。
- 生产目标为 Linux x86_64/aarch64。配置、状态与 Secret 的目标目录分别为 `/etc/aisoc`、`/var/lib/aisoc`、`/run/aisoc-secrets`。
- 禁止任意 Shell、SQL、URL 通用执行器；AI 不拥有事实覆盖权、Policy 写权或 R2/R3 执行权。

## 七平面与信任边界

| 平面 | Rust 组件 | 权威输入/输出 | 不可跨越的边界 |
|---|---|---|---|
| 实时 Web 防护数据面 | `aisoc-web-guard` | `WebRequestEnvelope` + `WebRouteFailPolicy` → `WebSecurityEvent` | 攻击者输入始终是数据；请求必须建立单一语义；模型无工具和策略写权；AI 失败按服务端 route-scoped Policy ID/version 显式决策并记录来源。 |
| Linux/网络采集数据面 | `aisoc-agent`、`aisoc-linux` | Linux telemetry → `AgentEnvelope` | mTLS 身份决定 tenant/agent/host；单个 Collector 失败不得拖垮 Agent 主链。 |
| 中心分析面 | `aisoc-ingest`、`aisoc-normalize`、`aisoc-detection`、`aisoc-incident` | Raw → Normalized → Detection → Incident Revision | Raw first、幂等、可重放；Incident revision 与服务端解析的 Detection/Claim 集合、Evidence lineage 和 EntitySet 形成闭包；相邻 revision 保留既有 Detection/Evidence/Claim 和 Timeline 事实，late event 可按 occurred_at 插入但不得改写历史；AI、搜索和控制台故障不阻断确定性 Detection。 |
| AI 研判面 | `aisoc-ai` | `EvidencePackage` → `ModelAssessment`/`Claim` | EvidencePackage 先绑定权威 Incident revision 与逐字段 EvidenceRef；assessment/package/claims 再绑定 tenant/incident/model run/集合/时间；Claim 必须经程序化证据验证；模型多数票不替代事实。 |
| 证据面 | `aisoc-evidence`、`aisoc-storage` | `EvidenceRef`、Custody、Integrity | Append-only；同租户；对象不可覆盖；下载需要 tenant + incident membership + classification 二次授权；confirmed Incident revision 的全部 Evidence 必须在同一权威访问上下文中可用。 |
| 控制面 | `aisoc-api`、`aisoc-console`、`aisoc-ui`、`aisocctl` | OIDC/mTLS context、Policy、Approval、Audit | 服务端 Rust 再验证 tenant/RBAC/ABAC；浏览器不保存平台长期 Secret。 |
| 响应面 | `aisoc-policy`、`aisoc-response`、Agent/Guard Runner | `ResponseAction` → ActionResult/Evidence/Audit | 仅固定动作；执行前目标重验证；R2 TTL/rollback；R3 人工/关键资产双审。 |

## 数据流冻结

```text
Web:
  Internet -> optional traditional WAF -> aisoc-web-guard -> business service
                                    \-> WebSecurityEvent -> Ingest

SOC:
  Linux Agent / Suricata / Falco / auditd / journald / service logs
    -> Ingest -> Raw Evidence -> Normalize -> Deterministic Detection
    -> Detection -> bound Incident Revision (Detection / Claim / Evidence / Entity closure)
    -> bound EvidencePackage -> bound ModelAssessment/Claims
    -> programmatic verification -> AI review result / Malware / Trace

Control and response:
  Console / API / aisocctl -> server-side RBAC/ABAC -> Policy/Approval
    -> typed ResponseAction -> target revalidation -> Runner
    -> ActionResult / rollback / post-check -> Evidence/Audit -> Incident Revision
```

## Rust crate 依赖方向

```text
contracts / core / crypto / config / telemetry / linux
                    |
                    v
storage / normalize / detection / incident / evidence / ai / malware / trace / policy / response
                    |
                    v
agent / ingest / api / web-guard / console / ui / db / aisocctl
```

P0 仅落地 `aisoc-contracts` 及其最小 Workspace 载体。P1 才建立 core/crypto/config/telemetry、错误实现、健康/关闭、SQLx、CI、SBOM、签名与 Rust Runtime 发布骨架。禁止为追求目录完整而提前创建无实现的后续 crate。

## P0 安全不变量

1. 鉴权上下文决定 tenant，payload、HTTP 字段和模型输出不得覆盖租户归属。
2. Web Guard 输入永远按不可信数据处理，模型不能修改 route、规则、白名单、Provider 或 Policy。
3. AI 故障不影响确定性 SOC 主链；Web 实时链的 AI budget/timeout/circuit/unavailable/invalid-output 均按 tenant/service/route 绑定的版本化 fail policy 决策，事件来源不可伪装。
4. Raw Evidence append-only；`confirmed_compromise` 必须具备存在、同租户、完整性有效且可访问的完整 Evidence 覆盖。
5. Response Runner 只接受枚举化动作和带 fingerprint 的目标快照，不接受任意 Shell/SQL/URL。
6. Agent CA 私钥、Provider Key、对象存储 Secret 和数据库密码不得进入仓库、浏览器 bundle 或普通日志。
7. Schema、Rule、Prompt、Model、Policy 和 ResponseAction 必须带版本与审计引用。

## 架构变更门槛

下列变更必须先更新本基线和威胁模型，再修改契约：新增平面或权威数据源；改变 tenant 归属来源；新增高权限 Collector；新增模型工具；新增 R2/R3 动作；引入新的中心权威存储；改变证据下载或样本隔离边界。
