# Jase-AiSOC V4.0 Rust-first 迁移状态

依据：`AI-SOC_Rust_AI-Web-Guard_项目计划书_V4.0_RustFirst_实施完善版.docx`。
更新：2026-08-12 / Migration 09（P4 Detection 主体隔离 + P6 revision/evidence 边界）。

## 迁移原则

V4.0 的目标是生产主链路 Rust First，而不是“Rust Core + Python Service Layer”。旧 Python 代码保留为行为对照、数据迁移和 differential/regression 资产；只要对应 Rust production capability 尚未通过验收，就不能为了降低 Python 文件数量直接删除有效功能。

生产默认路径必须满足：

- Docker/systemd/release/正常 Make runtime 不执行 Python/Alembic；
- `aisoc-python` 不进入 Cargo `default-members`；
- 新生产能力优先进入计划书对应的 native crate；
- Python bridge/legacy DB migration 只能显式启用，不能成为隐藏依赖。

## 当前 native Workspace

原生生产 crate：

`aisoc-core / contracts / linux / agent / web-guard / ingest / normalize / detection / incident / evidence / ai / malware / trace / policy / response / storage / api / console`

另保留 `aisoc-python` PyO3 bridge，仅作迁移验证。

## 当前已形成的 Rust 生产链

### Linux / Web 数据入口

- `aisoc-agent`：Linux capability、collector/runtime、本地队列和 mTLS 传输基础；
- `aisoc-web-guard`：reverse proxy、canonicalization、确定性 Web Fast Path、shadow/canary/enforce 与受限 AI provider 路径；
- `aisoc-ingest`：mTLS proxy identity 边界、heartbeat/event schema、batch 幂等、backpressure、Rust immutable raw object evidence。

### 分析数据面

`aisoc-ingest -> aisoc-normalize -> aisoc-detection -> aisoc-incident`

本地 pipeline journal 用于崩溃恢复；raw bytes 由 `aisoc-storage::object_store::LocalObjectStore` 以 tenant-bound `evidence://` locator、内容 hash、write-once 文件和逐次读取完整性校验保存。PostgreSQL 已通过 `aisoc-storage::central::CentralStore` 成为 base profile 的 central authoritative repository，保存 Agent inventory、batch/raw object metadata、normalized event、Detection、Incident、watermark 和 DLQ 状态。Normalized Event 与 Detection 的同 key 重试现在必须内容一致，否则返回 `DataConflict`，避免迁移/重放覆盖既有安全事实。

P4 Rust Detection 的 Web Recon/SSH burst 已按 source IP 主体隔离；P6 Rust Incident 已采用同 tenant/host + 主体/证据 anchor + 有界时间窗的关联，并将每个 Incident revision、revision Detection membership、evidence event refs 和 entity keys 追加保存。`incidents` 仅作为最新状态 materialization，旧 revision 可经租户作用域 API 审计读取。

API production 查询 Agent/Detection/Incident 时直接读取 PostgreSQL，不再把 Ingest 内存映射当作 system of record。

### P3 replay

normalize rejected event 进入 PostgreSQL `event_dlq`。Rust replay control 支持：

- `pending / leased / resolved`；
- `FOR UPDATE SKIP LOCKED` claim；
- lease timeout/reclaim；
- immutable local raw evidence lookup；
- normalize retry；
- central repository repair；
- successful resolution / bounded backoff；
- historical rejected backfill 不重新打开 resolved DLQ。

详见 `docs/phase-p3-plan.md` 和 `docs/p3-dlq-replay-runbook.md`。

## Python 遗留

当前仍有 287 个 `.py`：

- `src/aisoc`：162 个，约 46.6K LOC，主要是旧完整业务实现与迁移参照；
- `tests`：101 个，legacy/differential regression；
- `migrations`：18 个（17 个 Alembic version + `env.py`），仅 legacy schema；
- `scripts`：6 个，迁移/CI/静态验收用途。

这些 Python 文件不等于生产 runtime 仍依赖 Python。是否完成迁移以生产入口、数据权威源、行为等价和验收门禁为准，而不是文件数量。

## 尚未关闭的 Rust 迁移门禁

1. committed `Cargo.lock` 仍是旧迁移基线，缺失 17 个 native default-member package 和当前 pinned workspace dependencies。
2. 当前沙箱无 Cargo/Rust 1.82，且无法下载工具链，因此新增代码尚无真实 `cargo fmt/check/clippy/test/build --locked` 结果。
3. P3 Base/Standalone Object Store 已进入 Rust 主链；JetStream transport、Central/HA S3/MinIO adapter、完整 late/gap reconciliation 与 stream/backpressure 故障注入未闭环。
4. P4 source-aware Detection 与 P6 bounded Incident/revision 已继续向 Rust 生产语义迁移，但当前沙箱无法编译；P6 authoritative custody/legal hold 基础已进入 Rust/SQLx；retention deletion/object lifecycle、完整 timeline/entity graph、confirmed Claim evidence coverage 及真实 PostgreSQL 跨租户/并发门禁仍未关闭。
5. P7-P12 中若干高级能力虽然已有 native crate/骨架或部分实现，但尚未完成与旧 Python 行为的完整 production cutover 和 Linux/PostgreSQL 验收。
6. P13 hardening 与 P14 pilot 未执行。

## 下一迁移顺序

1. 在可信 Rust 1.82 builder 重建并审查 `Cargo.lock`，运行完整 workspace CI。
2. 在真实 PostgreSQL 执行 central repository + DLQ replay + P6 revision/evidence integration，加入 DataConflict、跨租户 FK、并发、DB restart/transaction/crash-window 故障注入。
3. P3 实现 Rust JetStream + S3/MinIO Object Store production profile，关闭跨节点 replay/late/gap/backpressure 门禁。
4. 实际运行 P4 source-isolation replay/测试，并继续 P6 retention lifecycle、timeline/entity graph 与 confirmed Claim coverage。
5. 随后按 P7→P12 热路径继续做行为等价迁移，只有 Rust 侧验收完成后再删除对应 Python production baseline。
