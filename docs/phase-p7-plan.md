# P7 AI Review Gate、单 Analyzer 与只读 Tool Gateway

## 阶段边界

P7 只审核 P6 的版本化 Incident，不逐日志、逐网络包或逐 syscall 调用模型。确定性检测、Incident
聚合和证据留存是主链路；模型调用是可关闭、可降级的旁路。P8 的 Verifier、盲审、冲突比较和
Adjudicator 不进入本阶段。

本阶段实现依据计划书 P7 要求：`ReviewDecision`、`EvidencePackage`、Provider 适配、结构化 Prompt、
JSON Schema、超时/重试/熔断、token/成本预算、租户作用域最小权限只读工具、原子 Claim、unknowns、
alternative explanations 和追加写审计。

## 已实现数据流

```text
P6 Incident revision
  -> deterministic Review Gate
  -> bounded EvidencePackage (<=20 samples + full_query_ref)
  -> single Analyzer (<=3 runs, <=8 read-only tool calls)
  -> strict AnalyzerReport validation
  -> append-only task/run/tool/Claim/evidence-link persistence
```

关键不变量：

- Gate 只读取服务端 Incident 字段和服务端 Host criticality；普通/低阈值 Incident 返回 `skip`，不会
  构造模型请求。
- `EvidencePackage` 固定 tenant、Incident、revision、样本、证据索引和 P6 `full_query_ref`；证据数据
  始终标为 untrusted。
- system instructions 与 EvidencePackage/tool result 分别进入 system/user 消息；证据里的 Prompt
  注入文本不能进入受信 system instructions。
- Provider 只暴露 `complete/health/capabilities`。OpenAI-compatible、Kimi、GLM、DeepSeek、OpenAI 官方
  adapter 使用固定 HTTPS 端点（仅 loopback 允许 HTTP），不跟随重定向，限制响应字节，API key 使用
  `SecretStr`。固定 base 由 `PROVIDER_PRESETS` 集中管理；接入见 [docs/model-providers.md](model-providers.md)。
- 仅 timeout、HTTP 429 和 5xx 可重试；达到阈值后熔断。失败返回 `model_unavailable`，且
  `deterministic_result_preserved=true`。
- 默认预算为 20 samples、16k context tokens、8 tool calls、3 model runs、30 reviews/minute；每个
  Incident 另有成本上限。预算耗尽不产生报告。
- Tool Gateway 只有 `search_events`、`get_process_tree`、`get_incident_timeline`、`get_entity_graph`；
  没有写方法。每次调用都绑定 package tenant/Incident/revision，查询工具还必须匹配同一
  `full_query_ref`，并限制行数和返回字节。
- AnalyzerReport 只允许 `recommend_only`。supported/partially-supported/contradicted Claim 必须引用
  package 或已审计 Tool result 的 event ID；无证据 Claim 只能为 insufficient/unsupported，且必须
  写明 unknowns。跨 Incident 或未知 evidence ID 使整个模型输出无效。

## 持久化与 API

迁移 `20260809_0009` 添加：

- `ai_review_tasks`：一个 Incident revision + policy version 对应一个不可变终态；
- `ai_model_runs`：provider/model/role/status/evidence count/token/cost/latency/retry/tool/degradation；
- `ai_tool_calls`：参数摘要、受限结果、行数、结果 hash 和拒绝原因；
- `ai_analyzer_claims` 与 `ai_analyzer_claim_evidence`：原子 Claim 和 normalized event 引用。

任务、run、tool、Claim 都带精确 tenant/Incident/revision 外键；Claim evidence 还引用
`normalized_events(tenant_id,event_id)`，Tool-backed evidence 可回到对应只读调用。

API：

- `POST /api/v1/incidents/{incident_id}/review`：使用认证 tenant、当前 Incident revision 和服务端 Host
  criticality；相同 task 重放返回既有结果。
- `GET /api/v1/incidents/{incident_id}/reviews/{review_task_id}`：只按认证 tenant 读取终态。

AI review 默认关闭。启用时必须配置 provider、model 和 secret；关闭或故障不会停止 normalize、detect
或 Incident worker。

## 当前非 Docker 证据

- Gate、EvidencePackage、Provider、Prompt 边界、Tool Gateway、Orchestrator、预算、熔断、持久化映射、
  配置和 OpenAPI 均有单元测试。
- Provider 测试覆盖 secret masking、注入隔离、Kimi/GLM/custom URL、strict JSON、tool parsing、
  timeout/429/5xx retry、非重试错误、熔断恢复、成本和响应字节限制。
- Orchestrator 测试证明普通日志零模型调用、Provider 失败保持确定性结果、Tool loop 闭环、未知 evidence
  拒绝，以及 token/cost/tool/rate budget fail closed。
- `tests/integration/test_ai_review_persistence.py` 已提交，覆盖真实 PostgreSQL 任务重放、复合 FK、Claim
  evidence、Tool query 和跨租户读取；当前没有设置 `AISOC_TEST_DATABASE_URL`，因此留待 Linux VM。

## 未关闭门禁

- Linux VM PostgreSQL 上执行 `base -> 20260809_0009 -> base` 在线迁移与上述 P7 集成测试；
- 两个真实 tenant credential 通过 HTTP 对同一/不同 Incident、review task、query ref 做读写对照；
- 并发 review 请求证明同一 revision/policy 只产生一个 task，且不会重复计费；
- Kimi、GLM 和用户指定 OpenAI-compatible 服务的真实响应兼容、限流、超时和熔断故障注入；
- 原生 Linux P4/P5 攻击链进入 P6 后的端到端 AI review，以及 30 reviews/minute 容量与成本审计。

上述动态证据完成前，P7 保持“进行中”，不能把 mock、Schema 或离线迁移当成生产门禁。
