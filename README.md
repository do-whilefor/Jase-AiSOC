# Jase-AiSOC V4.0

Jase-AiSOC 是面向蓝队和安全运营团队的通用 Linux 安全分析、证据溯源与实时 Web 防护平台。当前实现严格以 `AI-SOC_Rust_AI-Web-Guard_项目计划书_V4.0_RustFirst_实施完善版.docx` 为目标：**Rust First、确定性检测优先、AI 按需参与、证据驱动结论、分级响应**。

V4.0 的生产目标不是“Rust Core + Python Service Layer”，而是 Agent、Web Guard、Ingest、Normalize、Detection、Incident、Evidence、AI、Malware、Trace、Policy、Response、API/Console 的关键链路由 Rust 实现，正式运行不依赖 Python runtime。`src/aisoc`、Alembic 和 Python worker 仍保留为迁移期行为基线与回归资产；其中部分高级能力尚未完全迁移，所以不能视为已经完成的 P0-P14 产品。

## V4.0 链路

```text
Web 数据面：
Internet -> Traditional WAF(optional) -> AISOC Web Guard -> Business Service
                                      -> WebSecurityEvent -> Ingest -> Detection/Incident

SOC 证据链：
Linux Agent / Suricata / Falco / Service Logs
  -> Ingest -> Raw Evidence -> Normalize -> Deterministic Detection
  -> Incident -> EvidencePackage -> AI Review / Malware / Trace
  -> Policy -> Approval -> Registered Action -> Verification/Rollback
```

系统区分 `observed`、`attack_attempt`、`blocked`、`suspected_success` 与 `confirmed_compromise`。攻击请求命中本身不能直接等同于已失陷；`confirmed_compromise` 必须绑定可验证 evidence。

## 当前 Rust Workspace

当前 Cargo workspace 已包含计划书定义的原生 crate：

```text
aisoc-core          aisoc-contracts     aisoc-linux
 aisoc-agent         aisoc-web-guard     aisoc-ingest
 aisoc-normalize     aisoc-detection     aisoc-incident
 aisoc-evidence      aisoc-ai            aisoc-malware
 aisoc-trace         aisoc-policy        aisoc-response
 aisoc-storage       aisoc-api           aisoc-console
```

另有 `aisoc-python` PyO3 bridge，仅用于迁移回归，不在 `default-members`，也不属于生产 runtime。

目前已有的原生能力包括：Linux capability/collector/queue/mTLS Agent 基础链；Rust Ingest + 不可变 raw object + Normalize/Detection/Incident 管线；Web/SSH/host 等确定性检测；Incident/Evidence ledger；AI Provider/Review Gate/EvidencePackage/claim verification/circuit-breaker；Malware 静态分析骨架；AttackGraph；Policy/Response runner；Axum API；Rust Console；Web Guard reverse proxy、canonicalization、Fast Path、shadow/canary/enforce 和 OpenAI-compatible provider 接入。

这只是“架构已铺开”，不等于各阶段验收关闭。详细差距见 `docs/v4-plan-conformance-2026-08-11.md`。

## Rust-first 生产部署

正常 Linux 安装使用经过校验的 Rust release bundle：

```bash
make rust-first-check
make rust-lock-check
make rust-ci
make rust-release

sudo -E bash deploy/linux/install.sh \
  --role control \
  --release-dir /secure/release/aisoc-v4 \
  --enable-services
```

生产 Dockerfile、P1/P2 Rust Compose、systemd unit 和正常 release bundle 不执行 Python/Alembic。Python 兼容环境必须显式 `--legacy-python`，旧数据库迁移必须显式 `make legacy-migrate`。

P1 已新增 `aisoc-storage` SQLx/PostgreSQL migration plane 与原生 `aisoc-db migrate|health`，P1/P2 Compose、Linux production installer 和 CI 均使用该 Rust 路径，不再调用 Alembic。P3 Base/Standalone profile 已把 raw bytes 下沉到 Rust 不可变 Object Store，并把 Agent inventory、batch/raw metadata、normalized event、Detection、Incident 与 DLQ 的权威读写切入 PostgreSQL；本地 append-only journal 只保留恢复 metadata 和旧格式迁移入口。完整 P1/P3 仍需关闭 Cargo.lock/真实 Rust CI、Central/HA S3/MinIO adapter 与 JetStream 等门禁。

完整安装说明见 `docs/deploy-linux.md`。

## Web Guard

```bash
export AISOC_WEB_GUARD_UPSTREAM=http://127.0.0.1:8080
export AISOC_TENANT_ID=tenant-local
export AISOC_SERVICE_ID=web-local
export AISOC_WEB_GUARD_MODE=shadow
cargo run --locked -p aisoc-web-guard
```

Web Guard 已具备有界 Body、TE/CL 歧义拒绝、URI/Unicode canonicalization、SQLi/XSS/命令注入/遍历/SSRF/JNDI/XXE/模板/Prompt Injection 等确定性检测，以及 monitor/shadow/canary/enforce 策略。AI 默认关闭；启用后需要显式 model gateway/key/model/budget/timeout。确定性高置信结果不能被模型覆盖。

尚未关闭的 P5 门禁包括：直接 mTLS Ingest 事件发送、route-specific policy/budget、TLS/H2/request-smuggling 差异测试、challenge/rate-limit 执行器与正式性能基线。

## 验证命令

在具备 Rust 1.82 的 Linux 环境：

```bash
./scripts/check-rust-first.sh
./scripts/check-cargo-lock.sh
cargo metadata --locked --no-deps --format-version 1
cargo fmt --all --check
cargo check --locked --workspace --all-targets --all-features
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace
cargo build --locked --workspace
```

本次 2026-08-11 检查所在沙箱没有 `cargo/rustc/rustfmt/clippy`，外网 DNS 也阻止安装 Rust 1.82，因此不能伪造上述 Rust 命令的成功结果。静态门禁已确认当前 `Cargo.lock` 仍是旧基线，缺少 17 个 native workspace package；GitHub Actions 已改为 fail-closed，不再在 CI 内 `cargo generate-lockfile` 后继续。需要在可访问 Rust registry 的环境重新生成、审查并提交锁文件，再运行完整 Rust 门禁。

在当前沙箱已实际通过：Python `compileall`、V4 Rust contract schema 静态检查、SQLx migration 结构门禁、release install/upgrade/rollback/signature 测试、shell syntax、YAML parse 与更新后的 Rust-first 生产门禁。准确结果见审计/推进报告。

## Python 遗留策略

当前仓库仍有 287 个 `.py` 文件，其中 162 个位于 `src/aisoc`，101 个为测试，18 个位于 Alembic migration 目录（含 `env.py`），6 个为迁移/CI/静态验收工具脚本。旧 Python 实现不能简单删除：它仍是完整 PostgreSQL/FastAPI/SQLAlchemy、旧 Agent、AI、Malware、Response、Trace 等能力的迁移基线，其中一些能力尚无等价 Rust production 实现。

迁移原则：

1. 生产入口、systemd、Docker、release bundle 不回退 Python。
2. 新功能优先进入计划书对应 Rust crate，而不是继续扩展 Python service layer。
3. Python 测试可保留用于 differential/regression，直到 Rust 端存在等价测试与真实 Linux 验收。
4. SQLAlchemy/Alembic 只有在 SQLx schema/migration、数据兼容和回滚测试完成后才能退役。
5. PyO3 bridge 仅用于迁移验证，不得成为生产关键依赖。

## 当前主要缺口

- `Cargo.lock` 未与完整 Workspace 同步，导致 `--locked` release/CI 无法通过。
- P1 SQLx/PostgreSQL migration plane 与 P3 base central repository cutover 已落地，但 `Cargo.lock`/真实 Rust 1.82 + PostgreSQL 验收尚未关闭。
- P3 DLQ lease/replay 与 Base/Standalone 不可变 Object Store 已进入 Rust 主链；NATS/JetStream、Central/HA S3/MinIO adapter、late/gap 故障注入、enrichment/freshness 的正式 Rust 路径仍未完成。
- P7/P8 AI Review/Claim Verification 尚未形成独立生产 worker/persistence 全链。
- P9 YARA-X/ClamAV/reputation/sandbox concrete adapters 不完整。
- P10 跨主机 trace 与真实数据输入闭环不足。
- P11 ResponseRunner 尚未与 Agent/control-plane 审批、下发、TTL/rollback 形成端到端闭环。
- P12 Console 仍是基础 Rust Console，不是完整运营控制台。
- P13/P14 的兼容、安全、性能、灾备和真实业务试点尚未执行。

## 文档

- 核心计划书：`AI-SOC_Rust_AI-Web-Guard_项目计划书_V4.0_RustFirst_实施完善版.docx`
- 本轮 P0-P14 审计：`docs/v4-plan-conformance-2026-08-11.md`
- V05 P1 SQLx 推进：`docs/v4-next-step-2026-08-11.md`
- V06 P3 central/replay 推进：`docs/v4-next-step-v06-2026-08-11.md`
- P3 DLQ 重放 runbook：`docs/p3-dlq-replay-runbook.md`
- Rust 迁移记录：`docs/v4-rust-migration.md`
- Linux Rust-first 部署：`docs/deploy-linux.md`
- 威胁模型：`docs/architecture/threat-model.md`
- 兼容矩阵：`docs/compatibility-matrix.md`
- 测试计划：`docs/test-plan.md`
- P0-P14 阶段计划：`docs/phase-p0-plan.md` ～ `docs/phase-p14-plan.md`

git add -A
git commit -m "Update project"
git push
