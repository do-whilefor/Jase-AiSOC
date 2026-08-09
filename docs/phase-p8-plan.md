# P8 多模型盲审、确定性校验与冲突裁决

## 阶段边界

P8 扩展 P7 的 Incident 级 AI 旁路，不改变确定性 detect/Incident 主链。Analyzer 先生成原子 Claim，
程序校验随后无条件运行；只有受信 Gate 或 Analyzer 输出后的受信策略触发盲审。Verifier 不接收
Analyzer provider/model、support/contradiction score、verdict 或隐藏 reasoning。Adjudicator 只处理已检测的
Claim 冲突，且不能覆盖程序校验矛盾。

本阶段仍不执行响应动作。所有模型输出的 `allowed_response` 固定为 `recommend_only`；模型历史只用于
Verifier 路由顺序，不赋予事实或响应权限。

## 已实现数据流

```text
P7 Gate + EvidencePackage
  -> Analyzer
  -> deterministic Claim-Evidence verification (always)
  -> dynamic verification decision
  -> 0..N blind Verifier slots
  -> conflict detection
  -> optional Adjudicator
  -> assurance + human-review requirement
  -> append-only P8 persistence
```

关键不变量：

- high/critical severity、risk >= 80、critical asset 或 destructive-action context 在模型调用前选择
  `analyze_and_verify`；medium 默认只运行 Analyzer。
- Analyzer 输出后，unsupported/insufficient Claim 或确定性矛盾可动态升级为盲审；普通低阈值日志中的
  “发送整份日志”“调用工具”等文本不能绕过 Gate。
- `DeterministicAssertion` 只访问白名单事实索引：aggregate 指标、EvidencePackage event
  time/type/host/hash/time-quality/late 状态，以及已审计 ToolResult 标量。不存在字段、混合类型比较、
  不存在 evidence ID 均为 invalid；时间只与 ISO 时间比较，数值只与数值比较。
- `BlindClaim` 保留原子陈述、epistemic status、evidence IDs、assertions、unknowns 和 alternatives；删除
  Analyzer score/verdict/identity/reasoning。Evidence、Claim、program check、review、conflict 和 ToolResult
  始终作为不可信 data 发送。
- Verifier/Adjudicator 只能使用 P7 的四个只读工具，仍绑定 tenant/Incident/revision/query_ref。未知工具、
  重复 call ID、超预算或越界 query 在数据访问前拒绝。
- Analyzer、全部 Verifier、Adjudicator 共用默认 3 model runs、8 tool calls 和单 Incident cost budget。
  后续角色失败保留 Analyzer 报告和确定性结果，并降低 assurance 或要求人工审核。
- 同 provider+model 的第二次调用最多为 `basic`；不同 Analyzer+Verifier 可为 `enhanced`；两个不同
  Verifier 且无未解决冲突可为 `high`。需要验证但没有 Verifier 为 `unreviewed`；没有 Analyzer 结果为
  `deterministic_only`。
- 多模型一致不构成独立证据。未裁决冲突强制 `human_review_required=true` 并降低 assurance；非法
  Adjudicator 输出不能把 deterministic invalid Claim 改成 supported。

## 持久化与 API

迁移 `20260809_0010` 扩展 `ai_review_tasks` 的 assurance、verification/human-review 状态和完整 P8 JSON
结果，并增加：

- `ai_claim_program_verifications`；
- `ai_verifier_reports` 与 `ai_verifier_claim_reviews`；
- `ai_claim_conflicts`；
- `ai_adjudications` 与 `ai_adjudication_resolutions`；
- tenant-scoped `ai_model_history` 路由统计；
- `ai_analyzer_claims.assertions`。

规范化记录通过 task/revision/Claim 复合外键保持同一 tenant 和 Incident revision。现有
`POST /api/v1/incidents/{incident_id}/review` 与 GET 终态接口直接返回扩展后的 `ReviewOutcome`，不创建
第二套任务模型。tenant 模型历史在每次请求中读取，只改变候选 Verifier 顺序。

新增 Schema：

- `ai-blind-verifier-input-v0.1.schema.json`；
- `ai-verifier-report-v0.1.schema.json`；
- `ai-adjudication-report-v0.1.schema.json`；
- 扩展后的 AnalyzerReport 和 ReviewOutcome Schema。

## 当前非 Docker 证据

- `test_ai_review_verification.py` 动态覆盖盲字段剥离、count/time/hash/entity/process/session 程序校验、
  nonexistent evidence=invalid、预先/动态升级、same-model Basic、cross-model Enhanced、双 Verifier High、
  冲突无裁决的人工审核、三次调用共享预算、恶意 Claim 的未授权工具拒绝和整日志触发文本零调用。
- `test_ai_review_repository.py` 覆盖 program/slot/review/conflict/adjudication/resolution 的精确
  task/Claim 映射；持久化入口再次校验 evidence、Claim、slot 和 conflict 作用域。
- `tests/integration/test_ai_review_persistence.py` 已扩展为 P8 真实 PostgreSQL 门禁，覆盖三角色 run、
  全部规范化 P8 记录、终态重放、stored query 和跨租户拒绝；当前未设置测试数据库，因此待 Kali。

## 未关闭门禁

- Kali PostgreSQL 在线执行 `base -> 20260809_0010 -> base`，运行 P6/P7/P8 集成测试并验证所有复合 FK；
- 用两个真实 tenant credential 通过 HTTP 对 review task、Verifier 结果、conflict 和 model history 做隔离对照；
- 对 Kimi、GLM 和指定 OpenAI-compatible Provider 注入 malicious log/Claim/ToolResult，验证无未授权工具、
  nonexistent evidence=0、secret 不进入错误/日志；
- 并发高风险 review 验证同 revision/policy 不重复 task/计费，且三角色共享预算原子；
- 使用固定金标 Incident 回放评估不同模型历史路由、冲突率、overclaim/miss 和 assurance 校准。

上述原始动态证据完成前，P8 保持“进行中”；本地 fake Provider、Schema 与离线 SQL 不能关闭生产门禁。
