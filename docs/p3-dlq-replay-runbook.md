# P3 Normalize DLQ Replay Runbook

此 runbook 适用于当前 Rust-only Ingest 的 normalize DLQ 人工重放。该接口是内部控制面，不应直接暴露到公网或 Agent 网络。

## 前置条件

- `aisoc-ingest` 正常运行；
- `AISOC_DATABASE_URL` 可用且 SQLx migration 已完成；
- 操作者能够读取 Ingest 的 `AISOC_INGEST_CONTROL_SECRET`；
- 目标 raw evidence 仍存在于本地 append-only raw journal。

## 执行

默认 Ingest 监听 `127.0.0.1:8080` 时：

```bash
curl --fail-with-body \
  -X POST 'http://127.0.0.1:8080/internal/v1/replay/normalize-dlq' \
  -H "content-type: application/json" \
  -H "x-aisoc-control-secret: ${AISOC_INGEST_CONTROL_SECRET}" \
  -d '{"tenant_id":"ten_example","limit":25}'
```

`limit` 范围为 1..100。每次调用只处理本次成功领取的 DLQ 项。

响应统计字段：

- `claimed`：成功取得 lease 的条目数；
- `processed`：本次重新 normalize 并成功写入 central repository；
- `repaired`：本地 pipeline 已成功、仅修复 central repository；
- `deduplicated`：normalizer 判定为已有事实，DLQ 被安全关闭；
- `still_rejected`：重放后仍无法 normalize；
- `missing_evidence`：本地 immutable raw evidence 已不存在；
- `failed`：状态/存储等其他失败。

## 并发和崩溃语义

- PostgreSQL 使用 lease + `FOR UPDATE SKIP LOCKED`，多个 worker 不会同时领取同一 active claim。
- 默认 lease 为 120 秒；worker 崩溃导致 lease 过期后，其他 worker 可以重新领取。
- normalize 仍失败或 raw evidence 缺失时，条目会释放回 pending，并设置退避时间。
- successful pipeline write 会把匹配 DLQ 标记为 resolved；后续 startup historical backfill 不会把 resolved 项重新打开。

## Fail-closed 原则

- 调用方不能提交 replacement raw payload；重放必须使用已持久化 raw evidence。
- raw evidence 缺失时不伪造、不跳过 hash/lineage 校验，也不把条目标记成功。
- central persistence 失败时不把 DLQ 标记 resolved。
- Agent 已吊销或 host binding 异常的 live event 仍由 ingress path 拒绝；historical replay 不得用于恢复 Agent 身份状态。

## 当前限制

当前 raw replay source 仍是本地 journal。V4 的 Object Store immutable raw body、跨节点 replay source、Operator RBAC/audit replay API 和 JetStream durable replay 尚未完成，因此该 runbook 只代表 P3 base profile 的当前能力，不代表 P3 已验收关闭。
