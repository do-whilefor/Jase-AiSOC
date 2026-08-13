# P0 威胁模型与负向安全属性

状态：安全不变量和验证用例已评审成文，动态验证待 Linux 环境。

## 保护目标与攻击者

保护事件/证据的真实性、完整性、顺序和租户归属；Agent 身份与升级链；Policy/Approval/Audit；敏感日志、模型输入输出与恶意样本；响应目标准确性、影响预算和恢复能力。

攻击者包括匿名网络攻击者、普通租户用户、恶意或失陷 Agent 主机、被盗分析员会话、恶意日志/样本生产者、供应链攻击者和误操作管理员。不假定平台能抵御已完全控制中心基础设施及密钥托管系统的攻击者，但必须限制单个服务身份的爆炸半径并保留审计。

## 边界、失败结果与强制控制

| 边界 | 失败结果 | P0 强制控制 | 后续动态验证 |
|---|---|---|---|
| HTTP/TLS → Web Guard | Smuggling、规范化歧义、Prompt Injection、敏感字段出域 | 单一语义；authority/URI 歧义字符拒绝；raw/canonical Hash；bounded selected fields；AI 无工具/策略写权；版本化 route fail policy 显式处理 budget/timeout/circuit/unavailable/invalid output | H1/H2 differential、编码/Unicode/body fuzz、Provider failure × tenant/service/route policy 矩阵 |
| Agent → Ingest | 伪造身份、跨租户/agent/host 覆盖、boot 替换、重放、批次冲突、嵌套对象绕过、断网丢失 | mTLS context 为权威；envelope 与每个 Event 绑定 tenant/agent/host，Event 绑定 boot/sequence；typed Event/Evidence 子契约；有界 payload；canonical digest；同 key 异 digest=`DATA_CONFLICT` | 上下文/envelope 版本、tenant/agent/host/boot 替换、缺失/越界/逆序 sequence、Event/Evidence 子契约、digest mismatch、重放/乱序/断点续传 |
| Ingest → Raw/Worker | ACK 前未落 Raw、毒消息、积压、静默丢失 | Raw first；显式 ACK；DLQ/replay；优先级和 drop audit | PG/NATS/ObjectStore 故障注入、磁盘满、redelivery |
| Worker → PostgreSQL | tenant predicate 遗漏、竞态、跨租户引用 | newtype IDs；tenant 复合约束；事务；最小 DB 身份 | 双租户同形 ID、并发 revision、migration rollback |
| API → Evidence/Object Store | object_key 直取、SSRF/路径、覆盖、跨租户/跨 Incident/越级 classification 下载 | opaque locator；append-only/hash；版本化 EvidenceAccessContext 去重且有界；Evidence 使用前依次验证子契约、tenant、incident membership、classification、非零内容、integrity 与 custody | 上下文版本/重复/超限、ID/object/tenant/incident substitution、classification 越级、零字节、hash mismatch、pending/failed integrity、expired custody、覆盖尝试 |
| Detection/Claim → Incident → AI | 跨 tenant/incident/revision/review 拼接、伪造 Evidence、同 ID metadata 替换、历史事实删改、无支持自报 confirmed、模型覆盖工具事实、未来对象倒灌 | Incident 绑定服务端解析的 Detection/Claim 精确集合、Evidence/Entity/origin/time 闭包；访问上下文不得混入 revision 外 Evidence，confirmed 必须具备全量 Evidence 访问权并由 confirmed Detection 或独立验证的 confirmed Claim 支持；Evidence 生命周期状态可演进但不可变身份不得替换；相邻 revision 保留关系与 Timeline 事实多重集，允许 late event 按 occurred_at 插入；EvidencePackage 再绑定权威 Incident revision；assessment/package/claims 绑定 tenant/incident/model run/集合/时间；Claim programmatic verification | 虚假 Detection/Claim/Evidence ID、跨租户/incident/revision/model run、Evidence identity 替换、访问集合污染或缺口、Entity/Claim/confirmed-support 集合缺口、非相邻 revision、revision/包/Claim/assessment 时间逆序、重复 Timeline 事实删除、冲突工具结果 |
| Policy/Approval → Runner | tier/capability 伪报、审批绕过/重放、approver 身份复用、目标或 Incident 替换、无证据高风险动作、重复执行、不可回滚、runbook 注入 URL | typed action→tier→capability→target；Supporting Evidence；digest-bound time-bounded unique approvals；idempotency；target snapshot/revalidation；R2 TTL + registered inverse；R3 human runbook/关键资产双审 | tier/capability/target/Incident substitution、旧/重复/拒绝/不足审批、重复 approver、PID/inode/hash 变化、空/重复 Evidence、重复消息、TTL/deadline mismatch、rollback/runbook failure |
| Sample → Analyzer | 样本执行、archive bomb、scanner 串样 | 默认不执行；隔离 noexec；有界 parser；scanner scope/hash 复验 | archive/parser fuzz、权限和 mount 检查、scanner identity 替换 |
| Browser/Service → Control API | actor 混淆、OIDC/mTLS 类型替换、roles/attributes 注入、IDOR、角色/租户绕过、CSRF、Secret 泄漏 | 版本化 context；恰一 actor；OIDC=User、mTLS=ServiceIdentity；有界去重 token claims；鉴权 tenant、客户端对象声明与 repository/registry 解析的真实 owner scope 三方绑定；服务端 RBAC/ABAC；写操作审计；浏览器无长期 Secret | 缺失/双 actor、auth kind 替换、重复/非法 claims、双账号/双租户/对象/owner 替换矩阵、CSRF、bundle/network secret inspection |

## 必须保持的负向属性

- 修改 payload 中的 `tenant_id`、对象 ID、`object_key`、角色或状态不能跨越服务端所有权边界。
- 单个规则命中、IOC、端口、资源峰值、模型置信度或多模型一致不能单独产生 `confirmed_compromise`。
- 不存在、其他租户、无访问权或完整性失败的证据不能支持 Claim。
- 模型、插件、Scanner 或客户端输出不能直接成为 Shell、SQL、URL、argv 或高风险 ResponseAction。
- replay、late-event、redelivery 或重复审批不能造成动作重复执行或 Incident 历史覆盖。
- IP、ASN、User-Agent、语言、基础设施相似性或模型输出不能升级为真实身份归因。
- Provider、NATS、对象存储、搜索或 Console 局部失败不能制造虚假成功或静默数据丢失。
- Web AI 失败结果不得由请求或事件字段自行选择；必须与服务端 tenant/service/route 绑定的 Policy ID/version 和 failure kind 一致。

## P0 合同测试映射

| 域 | 静态测试源 | 当前覆盖 |
|---|---|---|
| Web（27 项） | `crates/aisoc-contracts/tests/web_contract.rs` | WebBindingDecision 6/6、WebDataMinimizationDecision 4/4、WebRequestContractDecision 22/22、WebRouteFailPolicyDecision 3/3、WebSecurityEventDecision 21/21 与 WebFailPolicyApplicationDecision 9/9 全结果直接样例；覆盖未知字段/非法 method、context/request/event/policy 版本、tenant/service/route 替换、authority/URI/parser/selected field 的空值与容量、敏感 header/query/body、正文 Hash、typed 外部 WAF rule ID 及 URL/冒号/空分段/traversal-shaped 负向变体、versioned Rule release、完全互斥 decision provenance、五类 route-scoped AI failure disposition、模型/失败策略不可伪报 CHALLENGE/RATE_LIMIT、跨 tenant/service/route/Policy substitution、无效 event/policy 与非 route-fail 来源、monitor/shadow 非执行语义、Web 状态上限，以及 Rule/reason/Evidence 的 contract/tenant/duplicate/empty/limit/time 边界和合法 block 样本。 |
| SOC（168 项） | `crates/aisoc-contracts/tests/soc_contract.rs` | AgentBindingDecision 24/24、SecurityEventDecision 20/20、DetectionContractDecision 17/17、IncidentContractDecision 25/25、IncidentRelationshipDecision 28/28、IncidentRevisionTransitionDecision 15/15、EvidenceRefDecision 5/5、EvidenceAccessContextDecision 4/4、EvidenceUseDecision 10/10、EvidenceLifecycleDecision 4/4、EvidencePackageDecision 11/11、EvidencePackageBindingDecision 9/9、ClaimContractDecision 14/14、ClaimVerificationDecision 19/19、ModelAssessmentDecision 13/13 与 ModelAssessmentBindingDecision 16/16 均具备全结果直接样例；覆盖 Agent mTLS/envelope/Event 绑定、Linux SecurityEvent 语义、Detection lineage、Incident revision/关系/Timeline 多重集、Evidence identity/lifecycle/二次授权、Claim 两阶段验证和 assessment/package/claim review graph。 |
| Control（46 项） | `crates/aisoc-contracts/tests/control_contract.rs` | SchemaVersionDecision 2/2、SafeFieldsDecision 8/8、AuthenticationContextDecision 8/8、TenantScopeDecision 6/6、AuditContractDecision 15/15 与 ErrorContractDecision 6/6 均具备全结果直接样例；覆盖 schema version、safe field 数量/名称/敏感性/值边界、actor 单一性、OIDC/mTLS、roles/attributes、客户端声明与服务端真实 owner scope、Audit 必填字段/token/版本化治理对象/correlation/hash-chain，以及 Error 规范消息/retryability/安全上下文。 |
| Response（38 项） | `crates/aisoc-contracts/tests/response_contract.rs` | ResponseContractDecision 全结果矩阵覆盖 schema、action/tier/capability/target、target 稳定参数与 Incident 绑定、canonical digest、Linux path、Supporting Evidence、idempotency token、有效窗、R0 approval 禁止、R2 TTL/registered inverse/deadline、R3 人工 runbook/关键资产双审、低风险标签不可绕过 R3 审批、approval digest/reject/count/ID/approver/time、集合上限及合法 R2/R3 样本。 |
| Schema（3 项） | `crates/aisoc-contracts/tests/schema_contract.rs` | 21 项清单/生成器集合一致、版本化文件名、根 DTO 拒绝未知字段。 |

本阶段遵守“只写不运行”，因此以上测试均未执行。Linux 阶段还必须补齐动态身份、对象、状态、重放、解析和故障注入变量。
