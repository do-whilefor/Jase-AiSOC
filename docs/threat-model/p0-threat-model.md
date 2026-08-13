# P0 威胁模型与负向安全属性

状态：安全不变量和验证用例已评审成文，动态验证待 Linux 环境。

## 保护目标与攻击者

保护事件/证据的真实性、完整性、顺序和租户归属；Agent 身份与升级链；Policy/Approval/Audit；敏感日志、模型输入输出与恶意样本；响应目标准确性、影响预算和恢复能力。

攻击者包括匿名网络攻击者、普通租户用户、恶意或失陷 Agent 主机、被盗分析员会话、恶意日志/样本生产者、供应链攻击者和误操作管理员。不假定平台能抵御已完全控制中心基础设施及密钥托管系统的攻击者，但必须限制单个服务身份的爆炸半径并保留审计。

## 边界、失败结果与强制控制

| 边界 | 失败结果 | P0 强制控制 | 后续动态验证 |
|---|---|---|---|
| HTTP/TLS → Web Guard | Smuggling、规范化歧义、Content-Type/body 解释分歧、Prompt Injection、敏感字段出域 | 单一语义；authority/URI 歧义字符拒绝；Content-Type bounded ASCII type/subtype、唯一参数、quoted-string 与 multipart boundary 守卫，已解析 body fields 必须绑定 Content-Type；raw/canonical Hash；bounded selected fields；AI 无工具/策略写权；版本化 route fail policy 显式处理 budget/timeout/circuit/unavailable/invalid output | H1/H2 differential、原始 Content-Type/Content-Length/Transfer-Encoding/body boundary 绑定、编码/Unicode/body fuzz、Provider failure × tenant/service/route policy 矩阵 |
| Agent → Ingest | 伪造身份、跨租户/agent/host 覆盖、boot 替换、重放、批次冲突、嵌套对象绕过、断网丢失 | mTLS context 为权威；envelope 与每个 Event 绑定 tenant/agent/host，Event 绑定 boot/sequence；typed Event/Evidence 子契约；有界 payload；canonical digest；同 key 异 digest=`DATA_CONFLICT` | 上下文/envelope 版本、tenant/agent/host/boot 替换、缺失/越界/逆序 sequence、Event/Evidence 子契约、digest mismatch、重放/乱序/断点续传 |
| Ingest → Raw/Worker | ACK 前未落 Raw、毒消息、积压、静默丢失 | Raw first；显式 ACK；DLQ/replay；优先级和 drop audit | PG/NATS/ObjectStore 故障注入、磁盘满、redelivery |
| Worker → PostgreSQL | tenant predicate 遗漏、竞态、跨租户引用 | newtype IDs；tenant 复合约束；事务；最小 DB 身份 | 双租户同形 ID、并发 revision、migration rollback |
| API → Evidence/Object Store | object_key 直取、SSRF/路径、覆盖、跨租户/跨 Incident/越级 classification 下载、伪造当前 custody/integrity、截断或重排 custody 历史 | opaque locator；对象不可覆盖；版本化 EvidenceAccessContext 去重且有界；`EvidenceCustodyChain` 用 typed actor、Evidence digest、非零 sequence、相邻前 Hash 与 record Hash 形成完整追加链，首项绑定 collection instant、末项绑定 EvidenceRef 当前状态；sequence 是排序权威；服务端解析完整 chain 后，Evidence 使用前依次验证子契约、chain、tenant、incident membership、classification、非零内容、integrity 与 custody | 上下文版本/重复/超限、ID/object/tenant/incident substitution、classification 越级、零字节、object hash mismatch、custody record/chain hash mismatch、sequence gap/reorder、前 Hash/actor/Evidence digest/末状态替换、缺失或截断 chain、pending/failed integrity、expired custody、覆盖与并发追加 |
| Detection/Claim → Incident → AI | 跨 tenant/incident/revision/review 拼接、Detection Host/Entity 替换、伪造 Evidence/custody、同 ID metadata 替换、历史事实删改、无支持自报 confirmed、模型覆盖工具事实、未来对象倒灌 | Incident 绑定服务端解析的 Detection/Claim 精确集合、Evidence/Entity/origin/time 闭包及有界唯一且不跨 revision 的完整 custody chain 集合；Detection 的 typed Host ID 必须出现在其引用的 Incident Entity 中；访问上下文不得混入 revision 外 Evidence，confirmed 必须具备全量 Evidence 访问权、有效 chain，并由 confirmed Detection 或独立验证的 confirmed Claim 支持；Evidence 生命周期状态可按冻结状态机演进但不可变身份不得替换；相邻 revision 保留关系与 Timeline 事实多重集，允许 late event 按 occurred_at 插入；EvidencePackage 再绑定权威 Incident revision；assessment/package/claims 绑定 tenant/incident/model run/集合/时间；Claim programmatic verification 同样要求服务端完整 chain | 虚假 Detection/Claim/Evidence ID、Detection Host 与 stable-key Entity 不一致、跨租户/incident/revision/model run、Evidence identity/custody chain 替换、chain 集合超限/重复/污染/缺失、访问集合污染或缺口、Entity/Claim/confirmed-support 集合缺口、非相邻 revision、revision/包/Claim/assessment 时间逆序、重复 Timeline 事实删除、冲突工具结果 |
| Policy/Approval → Runner | tier/capability 伪报、审批绕过/重放、approver 身份复用、Policy/目标/Incident revision/Evidence/custody 替换、无证据高风险动作、重复执行、不可回滚、runbook 注入 URL | typed action→tier→capability→target；Incident revision 进入 digest；Supporting Evidence；digest-bound time-bounded unique approvals；服务端 `ResponseAuthorizationContext` 将 Action 与权威 Policy、完整 Approval attestation 集合、Incident revision、Evidence membership/authorization 和完整 custody chain 集合闭合；idempotency；target snapshot/revalidation；R2 TTL + registered inverse；R3 human runbook/关键资产双审 | schema/tenant/action/Policy/Incident/revision/digest/approval substitution、旧/重复/拒绝/不足审批、重复 approver、custody chain 超限/重复/跨 revision/缺失/篡改、revision 外/未来/无权限/坏完整性或 custody Evidence、PID/inode/hash 变化、重复消息、TTL/deadline mismatch、rollback/runbook failure |
| Sample → Analyzer | 样本执行、archive bomb、scanner 串样 | 默认不执行；隔离 noexec；有界 parser；scanner scope/hash 复验 | archive/parser fuzz、权限和 mount 检查、scanner identity 替换 |
| Browser/Service → Control API | actor 混淆、OIDC/mTLS 类型替换、roles/attributes 注入、IDOR、角色/租户绕过、Request/Host/Agent/Service/Route 审计关联替换、CSRF、Secret 泄漏 | 版本化 context；恰一 actor；OIDC=User、mTLS=ServiceIdentity；有界去重 token claims；鉴权 tenant、客户端对象声明与 repository/registry 解析的真实 owner scope 三方绑定；服务端 RBAC/ABAC；每个 request 使用 typed Request ID，关键稳定资源的 audit object/correlation 同类 ID 必须一致；写操作审计；浏览器无长期 Secret | 缺失/双 actor、auth kind 替换、重复/非法 claims、双账号/双租户/对象/owner/audit correlation 替换矩阵、CSRF、bundle/network secret inspection |

## 必须保持的负向属性

- 修改 payload 中的 `tenant_id`、对象 ID、`object_key`、角色或状态不能跨越服务端所有权边界。
- 单个规则命中、IOC、端口、资源峰值、模型置信度或多模型一致不能单独产生 `confirmed_compromise`。
- 不存在、其他租户、无访问权、缺失/截断/篡改完整 custody chain 或完整性失败的证据不能支持 Claim。
- 模型、插件、Scanner 或客户端输出不能直接成为 Shell、SQL、URL、argv 或高风险 ResponseAction。
- replay、late-event、redelivery 或重复审批不能造成动作重复执行或 Incident 历史覆盖。
- IP、ASN、User-Agent、语言、基础设施相似性或模型输出不能升级为真实身份归因。
- Provider、NATS、对象存储、搜索或 Console 局部失败不能制造虚假成功或静默数据丢失。
- Web AI 失败结果不得由请求或事件字段自行选择；必须与服务端 tenant/service/route 绑定的 Policy ID/version 和 failure kind 一致。

## P0 合同测试映射

| 域 | 静态测试源 | 当前覆盖 |
|---|---|---|
| Web（32 项） | `crates/aisoc-contracts/tests/web_contract.rs` | WebBindingDecision 6/6、WebDataMinimizationDecision 4/4、WebRequestContractDecision 24/24、WebRouteFailPolicyDecision 3/3、WebSecurityEventDecision 21/21、WebFailPolicyApplicationDecision 9/9 与 WebModelAssessmentBindingDecision 17/17 全结果直接样例；覆盖未知字段/非法 method、context/request/event/policy 版本、tenant/service/route 替换、authority/URI/parser/selected field 的空值与容量、Content-Type 控制字符/非法或重复参数/quoted-string/multipart boundary 及合法正向样例、敏感 header/query/body、非零正文缺少 Hash、零长度正文夹带 body fields、已解析 body fields 缺少 Content-Type、typed 外部 WAF rule ID 及 URL/冒号/空分段/traversal-shaped 负向变体、versioned Rule release、完全互斥 decision provenance、五类 route-scoped AI failure disposition、模型/失败策略不可伪报 CHALLENGE/RATE_LIMIT、跨 tenant/service/route/Policy substitution、无效 event/policy 与非 route-fail 来源、monitor/shadow 非执行语义、Web 状态上限、权威 ingress 与 Request/Event/Assessment 的互斥主体/model run/必需 Evidence/时间闭包，以及 Rule/reason/Evidence 的 contract/tenant/duplicate/empty/limit/time 边界和合法 block 样本。 |
| SOC（216 项） | `crates/aisoc-contracts/tests/soc_contract.rs` | AgentBindingDecision 24/24、SecurityEventDecision 21/21、DetectionContractDecision 17/17、IncidentContractDecision 25/25、IncidentRelationshipDecision 34/34、IncidentRevisionTransitionDecision 15/15、EvidenceRefDecision 5/5、EvidenceAccessContextDecision 4/4、CustodyRecordDecision 10/10、CustodyTransitionDecision 10/10、EvidenceCustodyChainDecision 11/11、EvidenceUseDecision 12/12、EvidenceLifecycleDecision 4/4、EvidencePackageDecision 11/11、EvidencePackageBindingDecision 9/9、ClaimContractDecision 14/14、ClaimVerificationDecision 24/24、ModelAssessmentDecision 13/13 与 ModelAssessmentBindingDecision 16/16 均具备全结果直接样例；覆盖 Agent mTLS/envelope/Event 绑定、Linux SecurityEvent 语义及 Event/Raw Evidence producer-source lineage 的替换拒绝与计划支持的正向来源矩阵、Detection lineage 与 Host/Entity 绑定、Incident revision/关系/Timeline 多重集、Evidence identity/lifecycle/二次授权/完整 custody hash-chain（含 Verified→Failed、Failed 不可恢复、AI/Incident 集合内坏链 fail closed）、Claim 两阶段验证和 assessment/package/claim review graph。 |
| Control（51 项） | `crates/aisoc-contracts/tests/control_contract.rs` | SchemaVersionDecision 2/2、SafeFieldsDecision 8/8、AuthenticationContextDecision 8/8、TenantScopeDecision 6/6、AuditContractDecision 16/16、AuditChainTransitionDecision 8/8 与 ErrorContractDecision 6/6 均具备全结果直接样例；覆盖 schema version、safe field 数量/名称/敏感性/值边界、actor 单一性、OIDC/mTLS、roles/attributes、客户端声明与服务端真实 owner scope、Audit 必填字段/token、typed Request/Host/Agent/Service/Route 及版本化治理对象 correlation、stream/sequence/hash-chain，以及 Error 规范消息/retryability/安全上下文。 |
| Response（70 项） | `crates/aisoc-contracts/tests/response_contract.rs` | ResponseContractDecision 36/36 覆盖 schema、Incident revision、action/tier/capability/target、target 稳定参数与 Incident 绑定、canonical digest、Linux path、Supporting Evidence、idempotency token、有效窗、R0 approval 禁止、R2 TTL/registered inverse/deadline、R3 人工 runbook/关键资产双审、低风险标签不可绕过 R3 审批、approval digest/reject/count/ID/approver/time、集合上限及合法 R2/R3 样本；ResponseAuthorizationBindingDecision 29/29 覆盖服务端 authority schema/tenant/action/Incident/revision/Policy/digest/approval set/time、权威 Incident、Evidence access context、custody chain 集合容量/唯一性/revision membership/每条链完整性、请求时间和 Evidence 可用性闭包。 |
| Schema（3 项） | `crates/aisoc-contracts/tests/schema_contract.rs` | 23 项 manifest/generator 各自无重复且集合精确一致；文件名是版本化安全小写 ASCII basename；递归检查根/嵌套固定对象和 tagged enum variant 拒绝未知字段，同时不禁止受业务守卫约束的动态键 map。 |

本阶段遵守“只写不运行”，因此以上测试均未执行。Linux 阶段还必须补齐动态身份、对象、状态、重放、解析和故障注入变量。
