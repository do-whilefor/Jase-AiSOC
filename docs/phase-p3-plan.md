# P3：接入网关、消息、标准化、DLQ、幂等/重放/乱序、查询与新鲜度

状态：base profile 主链路已实现并完成本地修正；stream profile（NATS JetStream）、新鲜度监控和 PostgreSQL/Linux VM 重验仍未完成。
计划来源：项目计划书第 18 章“P3 接入网关、消息和标准化”，§7.2 流水线，§7.5 顺序/迟到/幂等，§12.1/§12.4，§16.1 SLO。

## 部署剖面

- `deployment_profile: base|stream`（`Settings`）：base = 进程内有界队列 + PG/object-store checkpoint，无 NATS；stream = NATS JetStream（ACK/重放/DLQ/分区）。NATS 为 optional `[stream]` extra，base 不安装，惰性 import + 启动 fail-fast。
- gRPC EventStream 评估为保持 mTLS HTTPS + JSON（与 FastAPI/Pydantic 栈一致）。

## 已完成（批次 C，2026-08-04）

- `Settings` 新增 `deployment_profile` + `ingest_normalize_workers/queue_depth` + `ingest_allowed_lateness_seconds` + `freshness_*` + NATS 字段；`require_nats_for_stream_profile` 校验。
- Migration `20260804_0005_normalize_pipeline`：`normalized_events`（UQ tenant+dedupe / tenant+event_id、lineage、watermark 字段、revision、status）、`event_dlq`、`event_watermarks`、`event_freshness`、`enrichment_cache`；`agent_events` 加 `normalize_status` 列。`alembic check` 无漂移。
- `src/aisoc/normalize/`：`Normalizer` Protocol + `RawInput`/`NormalizeResult`/`DlqEntry`/`dedupe_key`/`partition_key`/`clock_offset_ms`；`watermark.advance`；Agent、Suricata、journald、Nginx/Apache access log、Falco JSON 和 auditd serial-group adapter；尚未实现的 file_scan/import 明确进入 `no_normalizer` DLQ。
- `src/aisoc/storage/event_repository.py`：`insert_normalized_event` 使用 `(tenant_id,dedupe_key)` 保证重放幂等；新的迟到事实以独立 dedupe key 追加并标记 `revision_reason=late_arrival`，不会覆盖或伪造同一事件 revision；另含查询、DLQ 和 watermark 原子推进。
- `src/aisoc/enrich/`：`Enricher.orchestrate`（asset via `repositories.get_host` + external IOC/ASN/reputation，外部失败返回 None 不阻塞，extensions/labels 32/64 上限）。
- 单测覆盖 registry、各 adapter、dedupe、watermark/迟到分类、重复迟到事件仍幂等、DLQ 和 enrichment 降级；Falco P5 adapter 另有独立用例。

## 退出条件对照（§18.1：断网重连无不可解释重复；非法入 DLQ；可重放）

- 幂等/乱序：`NormalizeWorker` 现在会实际读取并推进 partition watermark；新迟到事件追加并标记，重复 dedupe key 仍返回原事实。✅ 本地逻辑与 worker 单测通过；真实 PostgreSQL 乱序/并发重验待 Linux VM。
- 非法入 DLQ：`EventDlqRecord` + normalizer 失败路径。✅ 代码就绪，**集成验证在批次 D**。
- 可重放：base 扫 `agent_events.normalize_status='pending'` 重处理 + dedupe UQ；stream durable consumer + dedupe UQ。✅ 字段就绪，**管道接入在批次 D**。

## 已完成（批次 D/E，2026-08-04）

### 批次 D：管道接入（base profile）
- `src/aisoc/normalize/worker.py`：`NormalizeWorker` 轮询 `agent_events.normalize_status='pending'` → 读对象存储 envelope → `AgentNormalizer` pass-through → `insert_normalized_event` → 置 `done`/`failed`（DLQ）。
- `src/aisoc/detection_engine/worker.py`：`DetectionWorker` 轮询 `normalized_events` active（lookback ≥ 2×突发窗口且覆盖 P5 host-chain 窗口）→ 重建 `SecurityEvent` → `DetectionEngine.evaluate` → `create_detection`（幂等）。
- `src/aisoc/api_server/app.py`：lifespan 启停两个后台 worker（`workers_enabled` 开关）；`aisoc-process` CLI 离线推进。
- 集成测试 `tests/integration/test_pipeline_e2e.py`：301 事件 → normalize → detect → 查 `/api/v1/events` + `/api/v1/detections` → 幂等重放。
- **stream profile（NATS JetStream）与容器级 reconnect/乱序集成仍为实验**，未在本轮交付。

### 批次 E：查询 API + 文档
- `src/aisoc/api_server/routes/events.py`：`GET /api/v1/events`（list + filters）、`GET /api/v1/events/{id}`。
- `src/aisoc/api_server/routes/detections.py`：`GET /api/v1/detections`（list + filters）、`GET /api/v1/detections/{id}`。
- `NormalizedEventRead` 领域模型；`DetectionRead` schema 导出。
- **新鲜度监控后台任务（FreshnessMonitor）已实现**（见 2026-08-09 增量）：`observability/freshness.py` 按 (tenant, host) 从 active `normalized_events` 计算最新 event_time 滞后、对照 verify/production SLO 分类（fresh/stale/degraded）并以 `ON CONFLICT (tenant_id, host_id)` 幂等 upsert `event_freshness`；`api_server/routes/freshness.py` 暴露租户隔离的 `GET /api/v1/freshness` 与 `/metrics`；接入 api_server lifespan 后台 worker；`tests/unit/test_freshness_monitor.py` + `tests/integration/test_freshness.py` 覆盖分类、幂等与租户隔离。

## 2026-08-08 审计修正

- 修复原实现“声明支持 watermark 但 worker 从未调用”的断链；`NormalizeWorker` 现按配置的 allowed lateness 分类并持久化 watermark。
- 删除不可执行的“同 dedupe key 迟到事件 revision+1”路径：该路径与两条唯一约束冲突，真实 PostgreSQL 必然失败。事件事实保持不可变，版本化重算属于 P6 Incident/时间线。
- pending 批次查询增加 `FOR UPDATE SKIP LOCKED`，避免同一 base 队列记录被并发 worker 重复处理；对象存储读取失败保留 DLQ 记录。
- 修复 tenant-wide 唯一约束与 source-local ID 的作用域错配：dedupe key 现在哈希 trusted
  tenant/host/agent/boot/source 后再使用 source ID 或内容摘要；双主机单测证明相同 native payload 或
  audit boot+serial 不会互相吞并，同一主机重放仍稳定。真实 PostgreSQL 对照留到 Linux VM。

## 待完成（stream profile）

> 新鲜度（FreshnessMonitor + `/api/v1/freshness` + `/metrics`）已于 2026-08-09 实现（见上文批次 E 与 `observability/freshness.py`），并经 `tests/integration/test_freshness.py` 在真实 PostgreSQL 上验证。剩余仅 stream profile（NATS JetStream）。

### 批次 D-stream：JetStream
- 抽 `ingest_gateway/server.py::_events` per-envelope block 到 `ingest_pipeline.py`（`BaseIngestPipeline` 进程内 worker + `StreamIngestPipeline`）；`normalize_status` 由 worker 置 `done`/`failed`；崩溃恢复扫 `pending`。
- 集成测试 `test_normalize_pipeline`（3 事件→3 normalized + watermark + freshness）、`test_ingest_reconnect_replay`（停/重启无 dup）、`test_ingest_out_of_order`（1,3,2）、`test_ingest_invalid_dlq`。
- `messaging/`：`NatsPublisher`/`NormalizerConsumer`（durable + DLQ stream）、`inproc_queue`、`p3.yml`（nats 服务）、CI `integration-stream` job、`pyproject` `[stream]` extra + `aisoc-process` processing entry point。

### 批次 E：查询 API + 新鲜度 + 文档
- `api_server/routes/events.py`（`/api/v1/events` list/single/revisions，租户隔离）、`routes/freshness.py`（`/api/v1/freshness` + `/metrics`）、`FreshnessMonitor` 后台任务、`observability/metrics.py` P3 指标。
- 容器烟雾 `test_container_reconnect_replay`、`phase-p3-plan`/`milestones`/`README` 更新。

## 非目标（本轮）

- 检测引擎（P4）、主机行为链（P5）、Incident 关联（P6）、AI 研判（P7+）。
- 迟到事件的 Incident/时间线版本化重算（P3 只在不可变事件上标记 `late_arrival`，重算在 P6）。
- 显式 replay REST endpoint（Q3 决策：靠幂等重处理满足“可重放”，endpoint 推迟 P4）。
