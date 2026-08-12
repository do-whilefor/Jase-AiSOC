# Jase-AiSOC V4.0 Rust First — P0–P14 当前差距（P6 Evidence 增量后）

基线：`AI-SOC_Rust_AI-Web-Guard_项目计划书_V4.0_RustFirst_实施完善版.docx`。本文件只记录当前仓库实际 Rust production path 与可验证状态；旧 Python/Alembic 实现只能作为迁移/differential baseline，不作为阶段完成依据。

## 当前生产结构事实

- Cargo Workspace 已包含计划书要求的 18 个 native production default members；`aisoc-python` 不在 production default-members。
- Rust production crate 目前约 2.2 万行源码；核心链路 Agent/Ingest/Normalize/Detection/Incident/Evidence/AI/Malware/Trace/Policy/Response/API/Web Guard 均已有 Rust crate，源码中未发现 `todo!()` / `unimplemented!()` 占位。
- production Dockerfile、P1/P2 Compose、systemd ExecStart 与 Makefile runtime target 由 Rust-first gate 限制为 native binary；Python 仅保留 legacy/migration、schema/static gate 和 differential test 路径。
- 当前沙箱无 Rust 1.82/Cargo、PostgreSQL/Docker，且 DNS/外网下载不可用。因此任何 `cargo fmt/check/clippy/test/build`、真实 SQLx migration、Rust 服务启动和 PostgreSQL/API 联调均仍是未执行门禁。

## P0–P14 差距

| 阶段 | 当前状态 | 已有 Rust 基础 | 仍需关闭的计划书退出条件 |
|---|---|---|---|
| P0 | 部分完成 | 18-crate production workspace、23 authoritative DTO/schema gate、错误/ID/tenant 基础不变量 | schema drift 的真实 Rust export 对照、两条主链 contract test、安全边界/ADR 人工评审闭环 |
| P1 | **阻断/未关闭** | SQLx migration、native `aisoc-db`、release manager、Rust-only runtime image/compose/systemd gate | 重建并提交正确 `Cargo.lock`；Rust 1.82 `fmt/check/clippy/test/build --locked`；真实 PG migration；audit/SBOM/签名 release smoke |
| P2 | 部分完成 | Rust Agent durable queue/raw spool、collector runtime、mTLS transport、Linux capability/runtime | journald/audit/process/network 真实采集；断网重传；enrollment/updater；DEB/RPM；Debian/Ubuntu/Kali/Rocky VM 安装升级回滚 |
| P3 | 部分完成 | Rust Ingest/Normalize、PG central repository、raw object abstraction/local immutable store、DLQ/replay、gap-safe watermark | Central/HA JetStream durable consumer/ACK/redelivery/backpressure；S3/MinIO adapter；NATS/DB/object outage 与乱序故障注入 |
| P4 | 部分完成 | Rust Web/SSH/network/host 检测基础、source-aware window、状态分层、回放单测源码 | 完整 Rule IR + generic single/window/sequence state；真实 replay benchmark/recall/FP；Rust-only runtime 动态证明 |
| P5 | 部分完成 | Rust reverse proxy、canonicalization、Fast Path/grey path、route config、shadow/canary/enforce、AI budget、Prompt injection marker | H1/H2 smuggling differential、streaming/upgrade/真实 upstream、P95/P99、模型故障降级、shadow→canary→enforce 动态回归 |
| P6 | **部分完成，本轮推进** | bounded correlation/revision；authoritative `evi_*`；verified/chained custody；retention metadata；append-only legal hold/lifecycle；revision→evidence ID；tenant-scoped evidence API | retention deletion/object lifecycle；完整 typed timeline/entity/edge repository；confirmed Claim 100% authoritative evidence coverage；真实 PG 双租户/并发/late event/backdated hold 负向测试 |
| P7 | 部分完成 | `ReviewGate`、`EvidencePackage`、`ModelProvider`、预算/circuit；EvidencePackage 已修正为 authoritative `evi_*` | real provider smoke、只读工具网关 runtime、结构化输出率/超时/降级门禁；明确证明 provider 全故障不影响 Detection/Incident |
| P8 | 早期/部分 | Rust programmatic assertion、evidence reference verification；Blind Verifier/Adjudicator contracts | Blind Verifier/冲突/Adjudicator 完整 Rust orchestrator；伪造 evidence/tool injection/跨租户动态拒绝；human-review assurance 持久化 |
| P9 | **早期** | Rust bounded static file analysis、ELF/entropy/string profile、静态保守 disposition | YARA-X、ClamAV、quarantine、reputation、archive/parser fuzz、独立 sandbox adapter 与权限/样本生命周期；当前 Rust 源码未实现这些生产适配器 |
| P10 | 早期 | Rust evidence-required edge 与 bounded graph query (`max_depth`/`max_nodes`) | PostgreSQL evidence-bound graph、入口/横向/影响范围、ATT&CK 映射、身份归因门禁、bounded export 和跨 Host 动态验证 |
| P11 | 部分完成 | Rust Policy assurance/approval 与 Response runtime/rollback 基础 | R0–R3 端到端；Agent-side Runner target revalidation/TTL；至少三类真实可回滚动作；R3 双审；幂等/outbox 动态门禁 |
| P12 | 部分完成 | Rust API tenant/RBAC 基础、Next.js operations console、CSRF proxy、安全字段隐藏与 Jase-AiSOC 品牌 | OIDC/JWKS 生产认证、完整角色/跨租户矩阵、所有写操作 Rust 再授权、全页面 Incident/Rule/Model/Response/System Ops 浏览器 E2E |
| P13 | 未关闭 | Linux-first scripts/release gate 有基础 | distro matrix、cargo-fuzz、DAST、容量/性能、OTel、HA、备份恢复、RPO/RTO、依赖/供应链最终 hardening 报告 |
| P14 | 未关闭 | 尚未进入真实试点 | 真实业务 shadow→canary→block、SOC/Web Guard 联动、SLO/误报/AI 成本/回滚验收、Go/No-Go、培训/运维手册/风险接受 |

## 当前执行优先级

1. P1：在可获得 Rust 1.82 + PostgreSQL 的可信 Linux builder 重建 Cargo.lock，并一次性关闭全部 `--locked` 编译/测试/migration 门禁。
2. P6：真实执行本轮 custody/legal-hold/evidence integration，之后补 retention deletion/object lifecycle 与 typed timeline/entity/edge。
3. P3：JetStream + S3/MinIO central profile 和故障注入，这是当前 HA 数据路径最大结构缺口。
4. P5/P2/P4：真实 Linux/代理/采集/replay 性能与安全门禁。
5. P7/P8：仅在 Incident/Evidence Review Gate 之后运行 AI；不得回退到“AI 审核全部原始日志”。
6. P9/P10/P11/P12 依计划书补足真实生产 adapter 和动态门禁，最后进入 P13/P14。
