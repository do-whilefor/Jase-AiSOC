# Jase-AiSOC V4.0 P0–P14 阶段里程碑与门禁

本表严格采用 `AI-SOC_Rust_AI-Web-Guard_项目计划书_V4.0_RustFirst_实施完善版.docx` 的 P0–P14 定义。阶段编号表达技术依赖；旧版把 P5/P12 等阶段映射到其他主题的记录不再作为 V4.0 Rust First 验收依据。

| 阶段 | 计划书目标 | 当前状态 | 未关闭的关键门禁 |
|---|---|---|---|
| P0 | V4.0 架构、威胁模型、Schema、Rust Workspace 基线 | 进行中 | Rust schema drift/contract test、安全不变量与 ADR 评审 |
| P1 | Rust 基础平台与工程治理 | **阻断** | Cargo.lock、Rust 1.82 全套 `--locked`、真实 PG migration、release/SBOM/audit smoke |
| P2 | Rust Linux Agent | 进行中 | 真实 collector/断网/升级回滚/多发行版 VM |
| P3 | Ingest 与事件管道 | 进行中 | JetStream、S3/MinIO、redelivery/backpressure 与 DB/object 故障注入 |
| P4 | Rust Detection Engine | 进行中 | Rule IR、generic window/sequence、replay recall/FP/perf、无 Python runtime 动态证明 |
| P5 | AISOC Web Guard | 进行中 | H1/H2 smuggling differential、真实 upstream、P95/P99、Prompt/model failure 与 rollout 回归 |
| P6 | Incident 与 Evidence | 进行中 | custody/legal-hold 基础已补；仍需 retention lifecycle、typed timeline/entity graph、confirmed Claim 100% evidence coverage 与真实 PG 边界测试 |
| P7 | Rust AI Review | 进行中 | real provider、只读工具、预算/熔断/降级动态门禁；AI 不审核全部日志 |
| P8 | Claim Verification | 早期/进行中 | Blind Verifier、冲突/Adjudicator、人审 assurance、伪造证据/跨租户/工具注入动态拒绝 |
| P9 | Malware | 早期 | YARA-X/ClamAV/quarantine/reputation/sandbox adapter 与 fuzz/权限门禁 |
| P10 | Attack Trace | 早期 | PG evidence graph、入口/横向/影响范围/ATT&CK、bounded export 与身份归因门禁 |
| P11 | Response | 进行中 | R0-R3、Agent Runner、target revalidation/TTL、三类真实 rollback、双审/幂等/outbox |
| P12 | Console & Operations | 进行中 | OIDC/RBAC/CSRF/审计 E2E、跨租户角色矩阵、所有写操作 Rust 再授权 |
| P13 | 兼容/性能/安全硬化 | 未关闭 | distro/fuzz/DAST/perf/HA/backup/RPO-RTO/供应链最终门禁 |
| P14 | 试点与生产发布 | 未开始 | 真实 shadow→canary→block、SLO/误报/AI 成本/rollback、Go/No-Go 与风险接受 |

阶段详细差距以 `docs/v4-gap-2026-08-12-p6-evidence.md` 和最新推进记录为准。任何未在真实 Linux/Rust/PostgreSQL 环境执行的动态门禁不得标记为完成。
