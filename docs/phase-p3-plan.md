# P3：接入网关、消息、标准化、DLQ、幂等/重放/乱序、查询与新鲜度

状态：批次 C/D/E 已完成（base profile）；stream profile（NATS JetStream）与容器集成仍为实验推进。
计划来源：项目计划书第 18 章“P3 接入网关、消息和标准化”，§7.2 流水线，§7.5 顺序/迟到/幂等，§12.1/§12.4，§16.1 SLO。

## 部署剖面

- `deployment_profile: base|stream`（`Settings`）：base = 进程内有界队列 + PG/object-store checkpoint，无 NATS；stream = NATS JetStream（ACK/重放/DLQ/分区）。NATS 为 optional `[stream]` extra，base 不安装，惰性 import + 启动 fail-fast。
- gRPC EventStream 评估为保持 mTLS HTTPS + JSON（与 FastAPI/Pydantic 栈一致）。

## 已完成（批次 C，2026-08-04）

- `Settings` 新增 `deployment_profile` + `ingest_normalize_workers/queue_depth` + `ingest_allowed_lateness_seconds` + `freshness_*` + NATS 字段；`require_nats_for_stream_profile` 校验。
- Migration `20260804_0005_normalize_pipeline`：`normalized_events`（UQ tenant+dedupe / tenant+event_id、lineage、watermark 字段、revision、status）、`event_dlq`、`event_watermarks`、`event_freshness`、`enrichment_cache`；`agent_events` 加 `normalize_status` 列。`alembic check` 无漂移。
- `src/blue_team/normalize/`：`Normalizer` Protocol + `RawInput`/`NormalizeResult`/`DlqEntry`/`dedupe_key`/`partition_key`/`clock_offset_ms`；`watermark.advance`（纯逻辑）；`normalizer_registry`；`AgentNormalizer`（pass-through + clock_offset）、`SuricataNormalizer`（EVE→network.* ）、`JournaldNormalizer`（export→service_log.line）；`stub_normalizers`（falco/auditd/service_log/file_scan/import → DLQ `no_normalizer`）。
- `src/blue_team/storage/event_repository.py`：`insert_normalized_event`（UQ 幂等，迟到 append-only + revision+1 + 旧行 superseded）、`get_event`、`list_events`、`list_revisions`、`insert_dlq`、`advance_watermark`（upsert + greatest）、`get_watermark`。
- `src/blue_team/enrich/`：`Enricher.orchestrate`（asset via `repositories.get_host` + external IOC/ASN/reputation，外部失败返回 None 不阻塞，extensions/labels 32/64 上限）。
- 单测 `tests/unit/normalize/test_normalize.py`：13 用例（registry、agent/suricata/journald 映射、dedupe_key、watermark 推进/迟到、late revision 逻辑、DLQ invalid、DLQ no_normalizer、enrichment 失败不阻塞）。

## 退出条件对照（§18.1：断网重连无不可解释重复；非法入 DLQ；可重放）

- 幂等/乱序：`normalized_events.uq_tenant_dedupe` + `advance_watermark` + `WatermarkAdvance.is_late` + 迟到 append-only revision。✅ 数据结构与逻辑就绪，**集成验证在批次 D**（base 管道接入 + reconnect/乱序集成测试）。
- 非法入 DLQ：`EventDlqRecord` + normalizer 失败路径。✅ 代码就绪，**集成验证在批次 D**。
- 可重放：base 扫 `agent_events.normalize_status='pending'` 重处理 + dedupe UQ；stream durable consumer + dedupe UQ。✅ 字段就绪，**管道接入在批次 D**。

## 已完成（批次 D/E，2026-08-04）

### 批次 D：管道接入（base profile）
- `src/blue_team/normalize/worker.py`：`NormalizeWorker` 轮询 `agent_events.normalize_status='pending'` → 读对象存储 envelope → `AgentNormalizer` pass-through → `insert_normalized_event` → 置 `done`/`failed`（DLQ）。
- `src/blue_team/detection_engine/worker.py`：`DetectionWorker` 轮询 `normalized_events` active（lookback ≥ 2× 窗口）→ 重建 `SecurityEvent` → `DetectionEngine.evaluate` → `create_detection`（幂等）。
- `src/blue_team/api_server/app.py`：lifespan 启停两个后台 worker（`workers_enabled` 开关）；`blue-team-process` CLI 离线推进。
- 集成测试 `tests/integration/test_pipeline_e2e.py`：301 事件 → normalize → detect → 查 `/api/v1/events` + `/api/v1/detections` → 幂等重放。
- **stream profile（NATS JetStream）与容器级 reconnect/乱序集成仍为实验**，未在本轮交付。

### 批次 E：查询 API + 文档
- `src/blue_team/api_server/routes/events.py`：`GET /api/v1/events`（list + filters）、`GET /api/v1/events/{id}`。
- `src/blue_team/api_server/routes/detections.py`：`GET /api/v1/detections`（list + filters）、`GET /api/v1/detections/{id}`。
- `NormalizedEventRead` 领域模型；`DetectionRead` schema 导出。
- **新鲜度监控后台任务（FreshnessMonitor）尚未实现**，列为后续增量。

## 待完成（stream profile + 新鲜度）

### 批次 D-stream：JetStream
- 抽 `ingest_gateway/server.py::_events` per-envelope block 到 `ingest_pipeline.py`（`BaseIngestPipeline` 进程内 worker + `StreamIngestPipeline`）；`normalize_status` 由 worker 置 `done`/`failed`；崩溃恢复扫 `pending`。
- 集成测试 `test_normalize_pipeline`（3 事件→3 normalized + watermark + freshness）、`test_ingest_reconnect_replay`（停/重启无 dup）、`test_ingest_out_of_order`（1,3,2）、`test_ingest_invalid_dlq`。
- `messaging/`：`NatsPublisher`/`NormalizerConsumer`（durable + DLQ stream）、`inproc_queue`、`p3.yml`（nats 服务）、CI `integration-stream` job、`pyproject` `[stream]` extra + `blue-team-normalizer` script。

### 批次 E：查询 API + 新鲜度 + 文档
- `api_server/routes/events.py`（`/api/v1/events` list/single/revisions，租户隔离）、`routes/freshness.py`（`/api/v1/freshness` + `/metrics`）、`FreshnessMonitor` 后台任务、`observability/metrics.py` P3 指标。
- 容器烟雾 `test_container_reconnect_replay`、`phase-p3-plan`/`milestones`/`README` 更新。

## 非目标（本轮）

- 检测引擎（P4）、主机行为链（P5）、Incident 关联（P6）、AI 研判（P7+）。
- 迟到事件的 incident 重算（P3 只记 `revision` + `incident.revision_needed` 审计，重算在 P4）。
- 显式 replay REST endpoint（Q3 决策：靠幂等重处理满足“可重放”，endpoint 推迟 P4）。
