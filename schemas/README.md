# 契约目录

`security-event-v0.1.schema.json` 是 P0 的统一安全事件契约。P2 同时提供
`agent-envelope-v0.1.schema.json`、`agent-heartbeat-v0.1.schema.json`、
`event-batch-v0.1.schema.json` 和 `batch-ack-v0.1.schema.json`，用于固定 Agent 身份、
源序列、队列遥测、批次完整性和确认语义。Heartbeat 的 `agent_version` 是有界 semver 可选字段：
新 runtime 会报告，旧 Agent 可省略，接入端仍必须用 mTLS 证书身份复验 tenant/Agent/Host 后才能持久化。
P4 增加
`detection-v0.1.schema.json`，固定检测告警（detection）的类别、攻击状态、证据引用与
聚合指标契约。P10 增加 `attack-trace-report-v0.1.schema.json`、
`attack-trace-graph-query-v0.1.schema.json`、`attack-trace-graph-result-v0.1.schema.json` 与
`investigation-export-v0.1.schema.json`，固定跨主机路径、技术归因、零身份断言、有界图查询和
无 raw/sample bytes 的调查导出契约。
P11 增加 `response-plan-input-v0.1.schema.json`、`response-approval-input-v0.1.schema.json` 和
`response-action-v0.1.schema.json`，把动作请求固定为封闭的 typed target union，并保存 evidence、
策略门禁、审批、目标重验证、执行后验证与回滚结果；Schema 不接受任意 shell、SQL、URL 或工具名。
`signed-rule-lifecycle-manifest-v0.1.schema.json` 与 `rule-lifecycle-state-v0.1.schema.json` 固定
Ed25519 签名的 tenant/rule/version/sequence/previous-manifest/catalog/dataset/Canary Host 绑定，以及
持久 current state 的有效 emission scope；Draft 不存在持久 manifest，缺失或失效状态必须 fail closed。
`console-snapshot-v0.1.schema.json` 固定租户内有界的控制台指标、事件、资产、恶意样本、模型调用与
响应动作摘要；每类明细最多返回 50 条。`console-incident-investigation-v0.1.schema.json` 固定同一
Incident revision 下有界的 evidence index、时间线、Claim 和可见实体/边；
`console-incident-evidence-v0.1.schema.json` 只返回已经过 tenant + Incident revision + evidence_id
成员关系验证的单条 normalized fact 和 `raw_ref`，不返回对象存储原始字节、样本字节、凭据或命令。
`console-attack-trace-investigation-v0.1.schema.json` 固定由已验证 seed Incident 解析出的 current P10
revision 浏览器投影：source Incident/evidence/key path/impacted Host/cluster/technique/entity/edge 最多为
50/100/100/100/50/50/200/400，每个 evidence/Host/Incident/rule ID 样本最多 8 条；截断字段必须与
原始计数闭合，所有可见结论 evidence 和 graph edge endpoint 必须闭合。契约不含 `raw_ref`、原始证据
字节、entity attributes 或 identity assertions，并固定任意 graph query 与 investigation export 为不可用。
`console-malware-investigation-v0.1.schema.json` 固定 sample metadata、扫描任务、分析结论、normalized
engine provenance 和租户内同哈希 context 的有界投影；所有缩减都有原始计数/截断标记，且契约中没有
`quarantine_ref`、静态 strings、archive entries 或 sample bytes。
`console-rule-intelligence-v0.1.schema.json` 固定只读规则治理与租户运营投影：当前/历史版本命中、
Incident feedback、未测量的质量字段和 enrichment cache 元数据都有固定上限。契约不返回任意 cache
payload value，并明确 `lifecycle_enforcement_available=true`、`managed_ioc_lifecycle_available=false`。
规则条目显示签名 current state、effective scope、manifest/key/catalog、Canary/validation 边界及
governed/legacy/shadow 计数；cache 可见性仍不能描述成受管 IOC 生命周期。
`console-model-operations-v0.1.schema.json` 固定 Provider/role 配置状态、tenant-scoped review outcomes、
Provider/model/role 调用聚合与最近运行。契约只报告 key/base URL 是否配置，不包含 key、URL、Prompt、
请求或响应；主动 health/credential probe 和 labeled feedback linkage 固定为 unavailable，未测量的
Precision、Recall、ground-truth agreement 与 false-positive rate 保持 `null`。
`console-system-operations-v0.1.schema.json` 固定 auditor/tenant_admin 的 tenant-scoped 系统运营投影：
pipeline/work status 必须闭合，最近 Agent queue heartbeat 最多聚合 1000 个 Host，操作凭据最多 100 条且
不含 token/digest。Agent version inventory 只使用每个 Host 当前 Agent 绑定的最新 heartbeat；版本组最多
50 个并与 bound/reported/unreported Host 计数闭合。来源固定为 `self_reported_heartbeat`，且
`binary_integrity_verified=false`。记录数量不冒充数据库或对象存储容量；broker/backlog age、dependency
health、deployment inventory、human user directory、签名制品/升级/自动回滚与 backup/restore evidence
均固定为 unavailable。数据库只报告当前 migration version，Schema compatibility 固定为 `not_evaluated`。

规则：

- `event_id` 在首次接收后不可变；`tenant.id` 必须由鉴权上下文校验，不能信任客户端单独声明。
- `event_time` 表示源事件时间，`ingest_time` 表示中心首次接收时间；排序和迟到修订不能混用二者。
- `raw_ref` 是不透明证据定位符，读取时必须再次执行租户和对象授权，禁止把它当作任意 URL 获取。
- 核心字段默认拒绝未知属性；源特有字段只能放入带命名空间的 `extensions`。
- v0.x 仍允许调整，但任何破坏性修改都必须更新版本、迁移/重放策略和契约测试。
- Agent 事件正文中的 tenant/agent/host/boot/sequence 必须与可信 Envelope 完全一致；
  接入端仍需以 mTLS 身份重新校验，不能仅因 Schema 通过就信任正文。
- 部分 ACK 不得改变原批次内容；重试复用相同 `batch_id` 和完整性摘要，直至完整确认。
