# AI-SOC V4.0 P0-P14 对照审计与整改记录

日期：2026-08-11  
依据：`AI-SOC_Rust_AI-Web-Guard_项目计划书_V4.0.docx`  
范围：当前压缩包中的源码、Cargo Workspace、Python 基线、部署、CI/CD、测试与 Linux 沙箱实际验证。

## 结论

按“阶段验收门禁是否真正闭环”而不是“是否存在同名文件”评估，当前 P0-P14 **总体完成度约 44%**。这是工程估算，不是自动代码覆盖率。Workspace 结构已经明显向 V4.0 收敛，但 P1 数据层、完整生产流式拓扑、AI/Response 端到端闭环、P13/P14 生产化验收仍是主要缺口。

Rust 迁移有两个口径：

- **架构/代码骨架迁移约 65%**：V4 目标的 18 个 native crate 均已存在，核心链路大多已有 Rust 类型和首版实现。
- **生产验收迁移约 50%**：正常 systemd/release/Docker 路径已改成 Rust-only，但缺少 SQLx/PostgreSQL、若干 production worker/binary、完整集成/性能/兼容验收；旧 Python 仍承载部分尚未等价迁移的高级功能。

因此，当前可以称为“Rust-first migration branch”，不能称为“P0-P14 已完成”或“Python 已完全退役”。

## P0-P14 对照

| 阶段 | 估算 | 状态 | 已具备 | 主要未关闭验收 |
|---|---:|---|---|---|
| P0 架构/威胁/契约冻结 | 80% | 部分完成 | V4 计划书、Workspace、contracts/schema、威胁模型与安全不变量已存在 | ADR/安全评审仍有 Proposed/迁移态内容；需要以真实跨模块 contract test 证明冻结 |
| P1 Rust 平台与工程治理 | 40% | 部分完成 | Cargo Workspace、Rust 1.82、CI、Axum API health、release checksum/signature、日志/错误基础 | `Cargo.lock` 陈旧；SQLx migration 未实现；Rust SBOM/可复现 release 证据不完整 |
| P2 Rust Linux Agent | 65% | 部分完成 | capability probe、collector、durable queue/spool、mTLS transport、Rust installer/release rollback | 真实 enrollment、mTLS、多发行版 VM、journald/audit/process/network collector、升级降级矩阵未闭环 |
| P3 Ingest/Normalize/Raw Evidence | 55% | 部分完成 | Rust Ingest、身份 header/proxy secret、raw append、normalize/detect/incident pipeline、状态查询 | NATS/JetStream、PostgreSQL/Object Store、生产 DLQ/stream replay/out-of-order/idempotence 集成验证不足 |
| P4 Rust Detection | 60% | 部分完成 | Web/SSH/host 等规则和窗口逻辑已存在 | Rust replay/attack simulation、状态层级、质量指标和大规模回放门禁不足；Rust test 数量偏少 |
| P5 Web Guard | 70% | 部分完成 | reverse proxy、canonicalization、Fast Path、prompt-injection、monitor/shadow/canary/enforce、AI provider/budget/circuit | 直接 mTLS Ingest 事件、route-specific policy/budget、TLS/H2/走私差异测试、challenge/rate-limit、正式 P95/P99 基线 |
| P6 Incident/Evidence | 45% | 部分完成 | Rust Incident、tenant/host correlation、append-only evidence/custody/verify | 多实体时间线、late revision、跨 tenant 负面测试、central transactional storage、完整 EvidencePackage 路径 |
| P7 AI Review | 60% | 部分完成 | Provider trait、ReviewGate、EvidencePackage、Analyzer、budget/circuit/degrade、OpenAI-compatible provider | 独立 SOC AI worker/持久化、provider gateway 运营、真实 Evidence 输入闭环和 failover 集成测试 |
| P8 Claim Verification | 45% | 部分完成 | ClaimStatus、evidence resolver、deterministic report verification | Blind Verifier/冲突 adjudication/human-review 工作流与持久化闭环未完成 |
| P9 Malware | 30% | 部分完成 | Rust 静态分析与 profile/interface 骨架 | YARA-X、ClamAV、quarantine、reputation、sandbox concrete adapter 与隔离执行验收不足 |
| P10 Attack Trace | 30% | 部分完成 | AttackGraph、evidence-bound edge、shortest path/query 基础 | 跨主机数据输入、initial entry/lateral/impact 推导、ATT&CK evidence coverage、真实场景测试不足 |
| P11 Response | 45% | 部分完成 | Rust Policy、registered action/revalidation、IP block/file quarantine/account lock 与 rollback runner | Agent action 下发、R0-R3 审批、TTL、post-verification、端到端 rollback 与权限隔离未闭环 |
| P12 Console/Ops | 25% | 部分完成 | Rust Console 和基础 API proxy/health | WebGuard/Incident/Rule/Model/Response/System 全运营页面、审计操作与 RBAC 仍不完整 |
| P13 Hardening | 10% | 未完成 | systemd hardening、release 生命周期测试、安全 CI 基础 | distro matrix、fuzz、DAST、性能/长稳、SELinux/AppArmor、备份恢复、RPO/RTO、灾难演练 |
| P14 Pilot/Go-No-Go | 5% | 未完成 | shadow/canary/enforce 机制和流程文档基础 | 真实业务流量、分阶段 canary/block、SLO/误报证据、运维手册、风险接受、Go/No-Go 记录 |

## Workspace 与模块检查

根 `Cargo.toml` 的 `default-members` 已覆盖：`aisoc-core`、`contracts`、`linux`、`agent`、`ingest`、`normalize`、`detection`、`incident`、`evidence`、`ai`、`malware`、`trace`、`policy`、`response`、`storage`、`api`、`console`、`web-guard`。`aisoc-python` 仅是额外 workspace member，不属于 default production members。

优点：模块命名基本符合 V4.0，原生 crate 默认 `#![forbid(unsafe_code)]`，没有发现业务 crate 中的实际 `unsafe` 使用；Agent、Web Guard、Ingest、API 等具有独立边界。

主要架构偏差：

1. `aisoc-storage` 当前不是计划书目标的 PostgreSQL/SQLx central storage，P1 migration 仍由旧 Alembic/Python 基线承担。
2. 没有完整生产 NATS/JetStream/Object Store 拓扑；P3 更接近本地原生 pipeline prototype。
3. AI、Malware、Trace、Response 多数是 library capability，尚缺计划书交付层面的独立 worker/service 或端到端 wiring。
4. release bundle 当前只打包 Agent/Ingest/API/Console/Web Guard 五个 binary；不能覆盖计划书最终二进制清单。
5. Console 仍是早期 Rust 控制台，不等于 P12 完整运营面。

## Python 遗留

当前共 **285 个 `.py` 文件**：

| 位置 | 文件数 | 约 LOC | 用途 |
|---|---:|---:|---|
| `src/aisoc` | 162 | 46,603 | 旧生产功能基线/迁移对照；部分高级能力仍只在此完整实现 |
| `tests` | 101 | 23,716 | Python 行为回归、integration/differential 基线 |
| `migrations` | 18 | 3,808 | Alembic/PostgreSQL 旧 migration；P1 SQLx 完成前不能直接删除 |
| `scripts` | 4 | 719 | schema/replay/enrollment/迁移工具 |

`src/aisoc` 中最大的遗留域为：`storage` 12,681 LOC、`agent_core` 9,071、`domain` 5,338、`ai_review` 3,363、`api_server` 2,238、`detection_engine` 2,121、`response_engine` 2,047、`normalize` 2,019、`malware_engine` 1,612、`incident_engine` 1,443、`trace_engine` 1,245。

这些文件目前不能机械删除或逐行翻译。尤其 SQLAlchemy/Alembic storage、旧 AI/Malware/Response/Trace 与完整 Python integration tests 仍是迁移验证资产。正确做法是：先补齐 Rust production implementation + contract/differential test + data migration/rollback，再删除对应 Python implementation。

本轮已把生产入口进一步隔离：正常 Linux installer、systemd、production Dockerfile、P1/P2 Rust Compose 不执行 Python；Python 只能通过明确的 legacy 路径进入。

## 本轮直接修复

1. **修复 multi-binary Dockerfile**：固定 `ENTRYPOINT aisoc-api` 改为默认 `CMD`，Compose 的 `command` 现在可以真正选择 `aisoc-ingest` / `aisoc-agent` 等 Rust binary。
2. **重写 P1/P2 Compose**：移除 Rust-only 镜像中的 Alembic/Python 命令，修复 Rust 实际读取的 `AISOC_API_BIND` / `AISOC_INGEST_BIND` 等变量，加入本地 secrets init、health check、Rust Agent probe。
3. **新增 Rust-first gate**：`scripts/check-rust-first.sh` 检查 production Docker/systemd/Compose/Make runtime target 不回退 Python，并确保 `aisoc-python` 不进入 `default-members`。
4. **新增 Cargo.lock 静态 gate**：`scripts/check-cargo-lock.sh` 无需 Cargo 即可发现 native workspace package 未进入锁文件。
5. **修复 CI 行为**：删除 GitHub Actions 中“先 `cargo generate-lockfile` 再继续”的掩盖逻辑；现在 committed lock 不完整会直接失败。
6. **Makefile 收敛**：`probe` 改为 Rust Agent probe；生产 `migrate` 对尚未实现的 SQLx fail closed；旧 Alembic 只保留为 `legacy-migrate`。
7. **更新 Linux 部署文档**：正常路径改为 verified Rust release bundle；Python 仅显式 legacy。
8. **补 P13/P14 阶段文档**：明确 Hardening 与 Pilot 的未关闭验收。
9. **Web Guard 配置补齐**：示例中加入 canary ratio、AI prompt version/timeout 和显式 provider secret/config 字段。

## 实际测试结果

当前 Linux 沙箱：Python 3.13.5、uv 0.10.0、Node 22.16 可用；**没有 `cargo`、`rustc`、`rustfmt`、`clippy`，也没有 Docker**。尝试通过 rustup 获取 Rust 1.82 时，沙箱 DNS 无法解析外部 host，因此本轮不能真实执行或伪造 Rust 编译结果。

已经实际执行：

- `python3 -m compileall -q src tests migrations scripts` -> **PASS**。
- `python3 scripts/check_v4_contract_schemas.py` -> **PASS**，23 个 authoritative DTO 检查通过。
- `bash tests/deploy/test_release_manager.sh` -> **PASS**，覆盖 install v1/v2、rollback、signature/checksum gate。
- `bash -n` 部署/打包/签名脚本 -> **PASS**。
- YAML parse：P1/P2 Compose、CI、CodeQL -> **PASS**。
- `./scripts/check-rust-first.sh` -> **PASS**。
- `./scripts/check-cargo-lock.sh` -> **FAIL（真实 blocker）**：当前 `Cargo.lock` 缺少 17 个 native workspace package。
- `cargo fmt/check/clippy/test/build --locked` -> **BLOCKED：沙箱无 Rust toolchain；且 committed `Cargo.lock` 已知不满足 immutable lock gate**。
- Rust integration/replay/start -> **BLOCKED**：同上；Docker start 也因沙箱无 Docker 无法执行。
- retained Python `pytest` 全量套件 -> **BLOCKED**：系统只有 Python 3.13，项目锁定 3.12，且沙箱缺少 `structlog` 等迁移依赖；直接尝试在 collection 阶段即因环境不完整终止。

这意味着本轮不能把 P1/Rust CI 标为通过。下一次在有 Rust registry 的环境中必须首先重新生成并提交 `Cargo.lock`，然后完整跑 `cargo fmt`、`cargo check`、`cargo clippy -D warnings`、`cargo test`、`cargo build`，根据真实编译器错误继续修复。

## 下一步优先级

1. **P1 第一优先级**：Rust 1.82 环境重建/提交 `Cargo.lock`；让全部 `--locked` CI 真正跑通。随后把 PostgreSQL schema/migration 从 Alembic 迁到 SQLx，并加 upgrade/downgrade/integration test。
2. **P3**：确定并实现 JetStream/Object Store/PostgreSQL 生产 profile，补 DLQ/replay/out-of-order/idempotence 实际故障测试。
3. **P5/P6**：Web Guard 事件直接进入 authenticated Ingest；Incident/Evidence 落 central storage，补跨 tenant 和 late-event 回归。
4. **P7/P8**：把 AI Review/Claim Verification 从 library 能力接成 SOC worker，完成 persistence、blind verifier/adjudication/human review。
5. **P9-P11**：Concrete malware adapters、跨主机 trace、Agent Action Runner/approval/TTL/rollback 全链。
6. **P12-P14**：完整运营 Console，然后执行兼容/fuzz/DAST/perf/灾备和真实 shadow/canary/block 试点。
