# P3：Ingest 与事件管道（Rust First）

状态：**部分完成，尚未达到 V4.0 P3 退出条件**。  
依据：`AI-SOC_Rust_AI-Web-Guard_项目计划书_V4.0.docx` P3，以及“接入与数据管道”“消息”“Pipeline”相关架构要求。

## V4.0 验收口径

P3 的退出条件不是“存在 ingest/normalize crate”，而是以下能力共同闭环：

- Schema 校验；
- 限流/背压；
- raw evidence 持久化并可校验；
- normalize 主链路；
- DLQ；
- 可控重放；
- 乱序/水位线处理；
- 幂等；
- 中心化/高吞吐部署时的 JetStream consumer、背压和 DLQ；
- 搜索/AI 等下游故障不能阻断基础检测数据面。

## 当前 Rust 主链路

生产数据路径当前为：

`Agent/Web Guard -> aisoc-ingest -> local immutable raw journal -> normalize -> detection -> incident -> PostgreSQL central repository`

其中 PostgreSQL 已成为 Agent inventory、raw event index、normalized event、Detection、Incident 和 DLQ 状态的中心权威查询源；API 在 production 不再把 Ingest 内存映射作为这些资源的 system of record。

本地 append-only JSONL 当前仍保留为 P3 raw staging/recovery source，用于进程崩溃恢复、数据库短暂失败后的幂等补写，以及 normalize DLQ replay。它不是 Control Plane 的权威查询数据库。

## 本轮已闭环的能力

### 1. Central repository cutover

`aisoc-storage::central::CentralStore` 已提供 typed SQLx repository：

- Agent inventory；
- ingest batch/raw event index；
- normalized event；
- Detection；
- Incident + Detection link；
- event watermark；
- normalize DLQ；
- tenant status/read model。

Event batch + raw index + pipeline 写入位于同一 PostgreSQL transaction 内；batch/raw 冲突采用 fail-closed `DataConflict`，防止同一幂等键承载不同内容。

### 2. 身份绑定与吊销

Ingest 在落本地 raw journal **之前**检查 PostgreSQL Agent 状态，并在写事务中再次检查：

- `tenant_id / agent_id / host_id` 已绑定后不可通过 heartbeat/event 静默换绑；
- `revoked` Agent 不可由新 heartbeat/event 自动恢复为 online；
- 历史 journal backfill 可导入旧证据，但不会把 revoked Agent 重新激活。

### 3. Startup backfill / database repair

Rust Ingest 启动时会把本地 inventory/raw/pipeline journal 幂等回填到 PostgreSQL。客户端在“本地 raw 已成功、central transaction 失败”的窗口重试时，Ingest 会重新构造确定性 evidence，使 central repository 可以补写，而不是因为本地幂等命中永久漏写数据库。

### 4. DLQ replay control plane

新增 SQLx migration `202608110005_dlq_replay_control.sql`：

- `event_dlq.state = pending|leased|resolved`；
- `lease_owner` / `lease_until`；
- `resolved_at`；
- claim index。

`CentralStore` 新增：

- `claim_normalize_dlq`；
- `release_normalize_dlq`；
- `resolve_normalize_dlq_claim`；
- `persist_pipeline_replay`。

claim 使用 PostgreSQL `FOR UPDATE SKIP LOCKED`，允许多个 Rust worker 并发领取且不重复处理；过期 lease 可被下一 worker 回收。重复 rejected journal 不会重新打开已经 resolved 的 DLQ。

Ingest 新增仅内部控制面的：

`POST /internal/v1/replay/normalize-dlq`

重放只从本地不可变 raw evidence 读取原始输入，不接受调用方提供替换 payload。成功 normalize 后写入 pipeline journal 并幂等修复 PostgreSQL；缺失 raw evidence、仍无法 normalize 或 central write 失败时，DLQ 带退避重新进入 pending。

### 5. Watermark / 基础乱序保护

PostgreSQL `event_watermarks` 只在 incoming sequence 与当前 contiguous watermark 相邻或重叠时前移。存在 gap 时不会把更大的 sequence 误报为连续完成。

这已经具备“不能因为乱序而错误推进连续水位”的最低安全语义，但尚未完成 V4.0 要求的完整 late-event 分类、gap reconciliation、故障注入与 JetStream 重放验证。

## 当前自动化门禁

- `scripts/check-sqlx-migrations.py`：forward SQLx migration/schema 门禁；
- `scripts/check-central-repository.py`：central read/write、identity、DLQ lease/replay、production wiring 的 fail-closed 结构门禁；
- `scripts/check-rust-first.sh`：生产 Docker/Compose/systemd/Make 路径禁止 Python runtime，并组合执行 storage/central 门禁；
- `crates/aisoc-storage/tests/central_repository.rs`：在 CI PostgreSQL service 中覆盖 inventory -> batch -> normalize -> detection -> incident、幂等、host binding、revocation、DLQ claim/release/expired lease reclaim/resolution。

## 尚未完成

P3 目前仍不能标记为完成，主要缺口：

1. `Cargo.lock` 尚未在可联网可信 Rust 1.82 builder 中重建，因此新增 Rust 代码仍缺少真实 `cargo fmt/clippy/test/build --locked` 结果。
2. 当前沙箱没有 PostgreSQL server，central repository integration test 只能交由 CI/真实 Linux 环境执行。
3. JetStream/`async-nats` stream profile 尚未进入正式 Rust production path；中心化高吞吐情况下的 durable consumer、ACK/redelivery、consumer lag/backpressure 仍待实现。
4. late event / gap reconciliation / disconnect-reconnect / out-of-order 故障注入尚未形成完整 P3 acceptance suite。
5. raw body 当前主要依赖本地 append-only journal；V4 Object Store immutable evidence + lifecycle/retention 尚未完成。
6. enrichment 仍未完成 Rust production cutover。
7. replay 目前是内部 Ingest control endpoint；面向 Operator 的 RBAC/audit API 属于后续 P12 收敛。

## P3 下一验收批次

1. 在 Rust 1.82 + PostgreSQL 环境修复 `Cargo.lock` 并跑真实 workspace CI。
2. 对 central repository integration test 增加并发 claim、DB restart、transaction rollback 和 replay crash-window 测试。
3. 实现 Rust JetStream transport abstraction 与 durable consumer，保持 base/local profile 可独立运行。
4. 增加 `1,3,2`、gap replay、重复 batch、断网重连、consumer redelivery、DLQ replay 的容器级验收。
5. 把 raw immutable body 下沉到 V4 Object Store，并让 PostgreSQL 只保存 locator/hash/metadata。
6. 完成 Rust enrichment + freshness/lag metrics 后，再按 P3 硬门禁决定是否关闭阶段。
