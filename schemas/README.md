# 契约目录

`security-event-v0.1.schema.json` 是 P0 的统一安全事件契约。P2 同时提供
`agent-envelope-v0.1.schema.json`、`agent-heartbeat-v0.1.schema.json`、
`event-batch-v0.1.schema.json` 和 `batch-ack-v0.1.schema.json`，用于固定 Agent 身份、
源序列、队列遥测、批次完整性和确认语义。P4 增加
`detection-v0.1.schema.json`，固定检测告警（detection）的类别、攻击状态、证据引用与
聚合指标契约。

规则：

- `event_id` 在首次接收后不可变；`tenant.id` 必须由鉴权上下文校验，不能信任客户端单独声明。
- `event_time` 表示源事件时间，`ingest_time` 表示中心首次接收时间；排序和迟到修订不能混用二者。
- `raw_ref` 是不透明证据定位符，读取时必须再次执行租户和对象授权，禁止把它当作任意 URL 获取。
- 核心字段默认拒绝未知属性；源特有字段只能放入带命名空间的 `extensions`。
- v0.x 仍允许调整，但任何破坏性修改都必须更新版本、迁移/重放策略和契约测试。
- Agent 事件正文中的 tenant/agent/host/boot/sequence 必须与可信 Envelope 完全一致；
  接入端仍需以 mTLS 身份重新校验，不能仅因 Schema 通过就信任正文。
- 部分 ACK 不得改变原批次内容；重试复用相同 `batch_id` 和完整性摘要，直至完整确认。
