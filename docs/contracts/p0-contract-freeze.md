# P0 契约冻结登记

契约权威源为 `crates/aisoc-contracts` 中的 Rust 类型。`schemars` 只从权威类型导出 JSON Schema；其他服务不得复制 DTO 并自行演化。所有以 `_id`/`_ids` 命名的跨边界字段（包括规则发布、对象存储注册项和外部 WAF 规则标识）均使用 Rust newtype。当前冻结 major 版本为 `1`，breaking change 必须新增 major 版本并记录 ADR。

## 冻结契约

| 契约 | 权威 Rust 类型 | 信任边界用途 | 核心不变量 |
|---|---|---|---|
| Agent Envelope | `AuthenticatedAgentContext` + `AgentEnvelope` + `AgentPayload` | Agent → Ingest | mTLS context 决定 tenant/agent/host，envelope 声明及每个嵌套 Event 的 tenant/host/agent 必须一致；Event boot 必须存在并绑定 envelope boot，sequence 必须存在、位于声明范围、批内严格递增且首尾一致，允许后续 Ingest 显式识别 gap；嵌套 SecurityEvent/EvidenceRef 必须通过子契约；`canonical_digest` 固定为解压后 typed `AgentPayload` 的项目规范 JSON（对象键按 UTF-8 字节递归排序，数组顺序不变，无额外空白）SHA-256；payload 是 1 至 4096 项的 typed event 列表。 |
| Security Event | `SecurityEvent` | Normalize/Detection 主链 | Linux 源、typed identity、Raw Evidence lineage 不可丢失；嵌套 EvidenceRef 必须同 tenant、通过子契约且 coarse producer source 与 Event source 一致：Agent/Web Guard/Response Runner/Import 精确绑定，journald/auditd/procfs/netlink/service log/Suricata/Falco 按是否携带 Agent identity 绑定 Agent 或 Sensor，file scan 同理绑定 Agent 或 Scanner；category/action/source/version/auth method/result 为有界 ASCII token；Agent source 必须携带 Agent ID；process PID 必须非零、可选 start ticks 不得以零伪装未知值，network/file/auth 子对象必须携带可识别端点/对象/主体；命令行/路径仍作为数据保留；entity IDs 不得重复且集合有界，labels/extensions 有界并拒绝敏感字段名，extensions 序列化上限 64 KiB；SecurityEventDecision 21/21 结果均有直接样例。 |
| Web Request | `WebIngressContext` + `WebRequestEnvelope` | Web Guard 内部/审计 | ingress context 与 request schema 都必须受支持，服务端 context 对 tenant/service/route 具有权威性，客户端请求字段不得替换；raw/canonical 并存；只保留 selected 字段；解析器版本与 Hash 固定；非零正文长度必须携带 body Hash，零长度正文不能夹带已解析 body fields，已解析 body fields 必须绑定合法 Content-Type；Content-Type 只接受 ASCII `type/subtype` 与合法、名称唯一的 token/quoted-string 参数，multipart 必须携带唯一、解引号后 1–70 字节、符合 RFC 2046 字符集合且不以空格结尾的 boundary；authority 禁止 userinfo、路径/查询/片段分隔符、反斜杠、空白和控制字符，URI 文本禁止片段、反斜杠、空白和控制字符，歧义输入 fail closed；外部 WAF rule ID 是最多 128 字节的 typed registry selector，只允许安全 token 片段和非空 `/` 分段，拒绝 URL、冒号、空分段与 traversal-shaped 值；WebBindingDecision、WebDataMinimizationDecision 与 WebRequestContractDecision 24/24 均有全结果直接样例。 |
| Web Route Fail Policy | `WebRouteFailPolicy` | Control/Policy → Web Guard | 每个 tenant/service/route 绑定 typed Policy ID/version；AI budget、timeout、circuit open、unavailable 和 invalid output 均有显式 fallback，禁止使用进程级隐式 fail-open/fail-closed 默认值；失败类型只选择策略中预定义结果，不能把模型输出当作 fallback；无效 event/policy、非 route-fail 来源，以及 tenant/service/route/Policy/decision 替换均 fail closed；WebRouteFailPolicyDecision 与 WebFailPolicyApplicationDecision 均有全结果直接样例。 |
| Web Security Event | `WebSecurityEvent` | Web Guard → Ingest | deterministic hit、model assessment 和 route fail policy 来源完全互斥，后两者不能夹带 deterministic hit；Rule 使用 typed ID/version/release，Policy 使用 typed ID/version；AI 失败决策必须与服务端权威 route fail policy 的 tenant/service/route/policy/失败类型和结果一致；CHALLENGE/RATE_LIMIT 只能由 deterministic source 产生，模型与失败策略不能直接声明已执行动作；只允许 `observed`/`attack_attempt`/`blocked`，成功/失陷状态由后续 Evidence 链判定；monitor/shadow 只允许 ALLOW/MONITOR，不能伪报已执行 CHALLENGE/RATE_LIMIT/BLOCK；攻击/阻断事件必须有同 tenant、通过子契约、非空且不晚于 decision 的 Evidence；rule/reason/Evidence 集合有界且拒绝重复/非法值；WebSecurityEventDecision 具备全结果直接样例。 |
| Detection | `Detection` | Detection → Incident | rule/version/release、SecurityState、EvidenceRefs；所有 Detection 必须保留同 tenant 且通过子契约的 Evidence lineage；entity/Evidence 集合和文本有界且去重；observation window 必须正向且 count 非零；suppressed 状态与非空 suppression reason 双向一致；confirmed 不接受零字节、完整性未验证或 custody 已 expired 的 Evidence；不得执行响应；DetectionContractDecision 17/17 结果均有直接样例。 |
| Incident | `Incident` | Incident → Review/Console | append revision；不覆盖 Detection/Evidence；title/entity/timeline/引用集合有界且去重；timeline 引用闭合；`validate_incident_relationships` 将 ID 集合绑定到服务端解析的 Detection/Claim 对象与完整 Evidence custody chain 集合，要求同 tenant/incident、对象集合精确、custody chain 无超限/重复/revision 外对象、Detection Evidence/Entity 与 Claim Evidence/Detection origin 均纳入该 revision；Detection 携带 typed Host ID 时，该 Host 必须出现在 Incident revision 的 EntitySet 中，不能由伪装 stable key 掩盖 Host 替换；Detection/Claim 时间不得晚于 revision；访问上下文只能声明该 revision 内的 Evidence，普通 observed revision 可按调用者权限使用子集，confirmed revision 则要求全部 Evidence 在同一上下文中可访问且具备有效完整 custody chain；Evidence 不可变身份必须一致，integrity/custody 可随生命周期演进；confirmed 除完整 Evidence 与 verified Assurance 外，至少需要已绑定的 confirmed Detection，或已绑定且独立验证、请求 confirmed 的 Verified Claim，不能由 Incident 字段自我提升；`validate_incident_revision_transition` 绑定相邻 revision、tenant/incident/created/revised time，保留既有 Detection/Evidence/Claim，拒绝 Evidence 身份替换和生命周期回退，并按多重集保留既有 Timeline 事实；late event 可按 occurred_at 插入新 revision。 |
| Evidence | `EvidenceRef` + `EvidenceAccessContext` + `EvidenceCustodyChain` | Evidence 面跨服务 | tenant、evidence/raw ref、source/version、opaque locator、Hash、size、classification、integrity、custody 完整；object key 不能是 URL/路径穿越，store selector 仅接受服务端注册 ID token，不能携带 URL 或路径；custody record 使用 typed user/service actor、非零 sequence、操作/来源版本、Evidence digest、前项 Hash 与自身 Hash 绑定 tenant/Evidence；首项必须是 collection instant 的 `Collected`，后续 sequence 严格相邻、前 Hash 精确、custody 单向演进，integrity 允许 Pending→Verified/Failed 与 Verified→Failed 但 Failed 不可恢复；链末状态必须等于 EvidenceRef 当前状态。`authorize_evidence_use` 只接受服务端按 tenant/Evidence ID 解析出的完整 chain，先验证版本化访问上下文、Evidence 子契约与 chain，再绑定 tenant、Incident membership、classification 上限、非零内容、verified integrity 和可用 custody，缺失、截断、篡改或替换链均拒绝使用；业务时间不作为链排序权威，sequence 才是。 |
| Claim | `Claim` | AI/Verifier → Incident | Claim 携带 typed origin 和 producer version，不是事实；status 与 Assurance 冻结为 verified/contradicted/unsupported/unknown 对应状态机；verifier ID/version 必须成对出现，readonly tool 与 verifier service identity 必须独立且不因 proposed 状态放宽；Evidence 与服务端解析的 custody chain 集合各最多 512 项且去重，chain 不能指向 available Evidence 集合外对象；任何 status 携带的引用都必须先完成存在性、tenant、子契约、时间、完整 custody chain 和访问权验证，不能以非 verified 状态绕过；引用验证成功只把 proposed Claim 提升到 `EvidenceValidated` 决策，只有已具备独立 verifier 与 verified assurance 的 Claim 才返回 `Verified`；confirmed 必须由非空、非零字节、同租户、完整性有效、custody 未 expired、在 Claim 创建时已经采集且获授权的 Evidence 完整覆盖。 |
| Model Assessment | `ModelAssessment` | Provider → AI | strict structured output；主体使用 `ModelAssessmentSubject` 明确且互斥地绑定 Web Request 或 Incident，禁止无主体或同时声明两类主体；Provider/Model/Prompt 均使用 typed ID，Provider/Model/Prompt/Input Schema 版本齐全；Claim/Evidence 引用最多各 512 项，reason 最多 256 项且有界去重；`validate_evidence_package_binding` 先把 EvidencePackage 绑定到权威 Incident ID/revision 及逐字段一致的 EvidenceRef，`validate_model_assessment_binding` 再将 Incident Assessment、EvidencePackage 与返回 Claims 绑定为同 tenant/incident/model run 的精确 Claim 集合，并限制 Evidence 只能来自输入包、时间只能位于 package creation 到 assessment completion 闭区间；`validate_web_model_assessment_binding` 先以服务端 `WebIngressContext` 绑定 Request，再将 Web Assessment 绑定到精确 tenant/request/model run、服务/route 一致的 Event、至少一项 Event Evidence 和 request/evidence→assessment→decision 时间窗，且 Web 分类不得输出 Incident Claim。 |
| Control Scope | `AuthenticatedRequestContext` + `ClientObjectScope` + `AuthoritativeObjectScope` | API/Console/CLI → Control | 鉴权上下文必须版本受支持且恰有一个 actor；OIDC 只接受 User，mTLS 只接受 ServiceIdentity；roles 非空，roles/attributes 均有界、去重且为安全 token。鉴权上下文、客户端声明与服务端 repository/registry 解析出的真实对象范围三方独立；对象 ID 必须一致，认证 tenant、声明 tenant 与真实 owner tenant 必须一致；客户端字段不得构造或覆盖权威对象范围；AuthenticationContextDecision 与 TenantScopeDecision 均有全结果直接样例。 |
| Response Action | `ResponseAction` + `ResponseAuthorizationContext` | Policy/Approval → Runner | 枚举动作、固定 action→tier→capability→target 映射、risk level、Linux-safe immutable target snapshot、非零 Incident revision、参数上限、最长 24 小时有效期、最多 16 个唯一 approval/approver、最多 512 个唯一且非空的高风险 Supporting Evidence 引用、idempotency；canonical digest 从固定字段序列重算并纳入 Incident revision，审批绑定该摘要且必须位于有效窗，任一 reject fail closed；rollback strategy 为 closed enum，R2 仅允许带同期限 deadline 的 registered inverse，R3 仅允许 opaque human runbook。`validate_response_authorization_binding` 将 Action 绑定到服务端解析的 Policy/Approval authority、精确 approval attestation 集合、权威 Incident revision、Evidence membership/访问上下文及有界唯一、不跨 revision 且每条都完整有效的 custody chain 集合；Supporting Evidence 必须属于该 revision、在请求前已采集、具有匹配 EvidenceRef 当前状态的完整有效 chain、非空、完整性 verified、custody 可用且 classification 获授权。审批和回滚门槛由固定 action→tier 映射决定，不能通过修改 risk level 绕过；ResponseContractDecision 36/36、ResponseAuthorizationBindingDecision 29/29 结果均有直接样例。 |
| Audit Event | `AuditEvent` | 七平面 → Audit | actor/operation/object/outcome/source version/hash chain 可追溯；`AuditStreamId` 与非零 sequence 冻结权威审计流和顺序，sequence=1 必须无前链、sequence>1 必须携带前链；`validate_audit_chain_transition` 要求相邻事件同 stream/tenant、Event ID 不重复、sequence 严格相邻且前 Hash 指向真实上项；必填 `AuditObjectRef` 是主审计引用，Request、Host、Agent、Service、Route 与数据对象均使用 typed ID，Model、Prompt、Contract Schema、Rule release、Policy 与 ResponseAction 还携带相应版本或 release ID；`AuditCorrelation` 冻结 request/host/agent/service/route 及数据/治理对象的可选跨事件辅助索引，不要求重复主对象字段，但一旦提供同类 ID 就必须与主对象一致；tenant 只使用 `AuditEvent.tenant_id` 及 Tenant 主对象守卫，不在 correlation 中复制第二份声明；代码/版本字段只接受 ASCII token，safe attributes 拒绝控制字符；`event_hash` 对除自身外的冻结字段序列重算，并纳入 stream、sequence、`previous_event_hash` 和有序 safe attributes；AuditContractDecision 16/16 与 AuditChainTransitionDecision 8/8 结果均有直接样例。 |
| Error Envelope | `ErrorEnvelope` | HTTP/消息边界 | 稳定 ErrorCode、request_id、与 ErrorCode 一一对应的规范公开消息、安全上下文；只有 rate-limit、dependency unavailable 和 deadline 类错误可声明 retryable；不得携带内部错误、控制字符或 Secret；ErrorContractDecision 6/6 结果均有直接样例。 |

## Schema 输出清单

`aisoc-export-schemas` 计划导出以下快照：

- `agent-envelope-v1.schema.json`
- `agent-payload-v1.schema.json`
- `authenticated-agent-context-v1.schema.json`
- `authenticated-request-context-v1.schema.json`
- `authoritative-object-scope-v1.schema.json`
- `audit-event-v1.schema.json`
- `claim-v1.schema.json`
- `client-object-scope-v1.schema.json`
- `detection-v1.schema.json`
- `error-envelope-v1.schema.json`
- `evidence-package-v1.schema.json`
- `evidence-ref-v1.schema.json`
- `evidence-access-context-v1.schema.json`
- `evidence-custody-chain-v1.schema.json`
- `incident-v1.schema.json`
- `model-assessment-v1.schema.json`
- `response-action-v1.schema.json`
- `response-authorization-context-v1.schema.json`
- `security-event-v1.schema.json`
- `web-ingress-context-v1.schema.json`
- `web-request-envelope-v1.schema.json`
- `web-route-fail-policy-v1.schema.json`
- `web-security-event-v1.schema.json`

当前 Windows 阶段未运行 exporter，仓库中不伪造生成结果。清单与生成映射的源码文本比对为 23/23；共享文件名谓词将名称限定为以 `-v1.schema.json` 结尾的安全小写 ASCII basename，并有目录穿越、路径分隔符、大写、空/连字符边界、错误 major 和额外点号的直接拒绝样例。Schema Contract 源码分别拒绝 manifest 侧或 generator 侧重复文件名并要求两侧集合精确相等；exporter 自身也在创建目录或读写任何文件前执行同一 manifest/generator/filename 预检。递归 Schema 样例还要求每个含固定 `properties` 的对象节点声明 `additionalProperties=false`，覆盖根 DTO、嵌套 DTO 与 tagged enum variant，同时保留 `safe_attributes`、selected fields、labels/extensions 等受业务守卫约束的动态键 map。切换到 Linux 后，应由同一锁定 toolchain 生成 `schemas/`，随后使用 exporter 的 `--check` 模式执行字节级 Schema drift 比较；只有 drift 为 0 且清单/文件名/递归严格性样例执行通过才可关闭 P0。

## 计划书 8.1 字段对照

| 计划书契约 | 计划书关键字段 | 当前 Rust 对应 |
|---|---|---|
| AgentEnvelope | tenant/agent/host/boot/batch/sequence/compression/digest/payload | 全部为必填 typed 字段；payload 为 `AgentPayload`。 |
| SecurityEvent | source/category/action/entities/network/process/file/auth/timestamps/raw_ref | `EventSource`、category/action、typed `EventEntityRef`、具备最小可识别语义的 process/network/file/auth、event/ingest time 与完整 `EvidenceRef.raw_ref`。 |
| WebRequestEnvelope | request/service/route/src/method/host/raw/canonical URI/selected fields/hash/WAF context | 全部已冻结；method 使用有界 HTTP token，scheme 为 enum，authority/URI 先拒绝控制字符与歧义分隔符，selected fields 有数量/长度/敏感键守卫，WAF rule registry selector 的运行时与 Schema 共同限制为安全非空分段。 |
| WebSecurityEvent | rule hits/model assessment/policy decision/latency/response/evidence | `deterministic_rule_hits` 携带 Rule ID/version/release；`model_assessment_id` 与 route fail policy 来源互斥；Policy ID/version、latency/upstream status、EvidenceRefs 全部冻结。 |
| WebRouteFailPolicy | tenant/service/route/policy/AI failure dispositions | route-scoped typed Policy；AI budget/timeout/circuit/unavailable/invalid-output fallback 全部显式并由服务端权威策略绑定。 |
| Detection | rule/version/severity/security state/first-last/evidence/suppression | 全部已冻结，并校验 observation window、suppression reason 和 confirmed Evidence。 |
| Incident | tenant/revision/status/risk/timeline/entities/detections/evidence/claims/assurance | 全部已冻结，并校验 revision link、timeline Evidence 闭包、Evidence 采集时间、Detection/Claim 精确集合及 tenant/incident/time/Evidence/Entity/origin 关系，以及相邻 revision 的 append-only 关系和 Timeline 多重集保留；relationship guard 还接收服务端解析的有界唯一 custody chain 集合；confirmed 必须具备全量 Evidence 访问权与完整有效 chain，并由 confirmed Detection 或独立验证的 confirmed Claim 支持。 |
| EvidenceRef | evidence/tenant/source/raw/object/hash/size/classification/custody/integrity | 全部已冻结；source version 必填；object key 是 opaque traversal-free newtype；`EvidenceCustodyChain` 以 tenant/Evidence digest/sequence/typed actor/前后 Hash/状态演进绑定完整保管链，链末状态必须匹配 EvidenceRef；使用前由版本化 `EvidenceAccessContext` 执行 tenant + incident membership + classification 二次授权并验证非零内容、完整性、custody 与服务端完整 chain。 |
| Claim | statement/type/status/evidence/verifier/assurance/time | 全部已冻结；typed origin/producer version 必填；verifier identity/version 成对；readonly tool 不得以 proposed 状态绕过 verifier 独立性；任何 status 携带的 Evidence 引用都先验证服务端 custody chain；Verified Claim 要求 verified assurance；晚于 Claim 创建时间才采集的 Evidence 不得反向支撑该 Claim。 |
| ModelAssessment | Web Request/Incident subject/provider/model/prompt/input schema/verdict/risk/confidence/claim/evidence/reasons/time | 主体由 tagged enum 二选一；Provider/Model/Prompt 使用 typed ID；Provider/Model/Prompt/Input Schema 版本必填；引用与 reason 有界去重；Incident review 的 assessment/package/claims 绑定 tenant、incident、model run、精确 Claim 集合、Evidence 输入集合和时间闭包；Web review 先验证权威 ingress context，再绑定 tenant/request/model run、service/route、Event Evidence 和 request→assessment→decision 时间闭包。 |
| ControlScope | authenticated tenant/client claim/authoritative owner/object | `AuthenticatedRequestContext`、`ClientObjectScope` 与 `AuthoritativeObjectScope` 分离；服务端真实 owner tenant 及对象引用必须与鉴权上下文、客户端声明同时一致。 |
| ResponseAction | action/Incident revision/target/risk/approval/ttl/rollback/idempotency | 全部已冻结；动作、固定 capability 与 target 类型一致；Linux 文件路径/target 参数有界；R2 TTL 等于有效窗口并绑定 rollback deadline；拒绝票 fail-closed；服务端 `ResponseAuthorizationContext` 将 Policy/Approval authority、精确审批集合和 Incident/Evidence 关系绑定到同一 action digest。 |

`LinuxPath` 的 JSON Schema 提供绝对路径、长度和基本分段约束；`.`/`..`、NUL 与控制字符等语义约束由 Rust newtype 反序列化继续 fail closed。此处不使用依赖不兼容正向预查的正则表达式。

Agent/Event 字段守卫按阶段边界冻结：`AgentEnvelope.created_at` 是可离线排队和重传的生产者时间，不与连接建立时的 `AuthenticatedAgentContext.authenticated_at` 比较；压缩/解压字节数与压缩比、服务端 receive time 下的时间漂移、`batch_id` 幂等键及同键异 digest 的 `DataConflict` 需要 P3 Ingest 的原始消息和持久化状态；证书注册、轮换、吊销及 fingerprint 权威解析需要 P2 Agent/Enrollment。P0 不从已经解码的 `AgentPayload` 伪造这些运行时结论，也不预设 P4 Detection 的事件时间关联算法。

## 错误码冻结

| 类别 | ErrorCode | 语义 |
|---|---|---|
| 身份/权限 | `AUTHENTICATION_REQUIRED`、`AUTHENTICATION_INVALID`、`AUTHORIZATION_DENIED`、`TENANT_MISMATCH` | 身份缺失/无效、权限拒绝、租户上下文不一致。 |
| 输入/契约 | `SCHEMA_INVALID`、`UNSUPPORTED_SCHEMA_VERSION`、`PAYLOAD_TOO_LARGE`、`RATE_LIMITED` | 边界 Schema、版本、容量和速率拒绝。 |
| 幂等/状态 | `DATA_CONFLICT`、`IDEMPOTENCY_CONFLICT`、`OBJECT_NOT_FOUND` | 同 key 异内容、动作键冲突、对象不可见/不存在。 |
| Evidence | `EVIDENCE_NOT_FOUND`、`EVIDENCE_INTEGRITY_FAILED`、`EVIDENCE_ACCESS_DENIED` | 证据存在性、完整性或二次授权失败。 |
| Response | `POLICY_DENIED`、`APPROVAL_REQUIRED`、`APPROVAL_INVALID`、`TARGET_CHANGED`、`ACTION_EXPIRED` | Policy/Approval/目标重验证/TTL 边界。 |
| 运行故障 | `DEPENDENCY_UNAVAILABLE`、`DEADLINE_EXCEEDED`、`INTERNAL` | 可选依赖、deadline 和脱敏后的内部错误。 |

## 兼容策略

- 同 major 的新增字段必须是可选字段或具有安全默认值；接收端仍默认拒绝未知字段，必须完成协调发布后才接收新增字段。
- 枚举新增值视为需要协调的兼容变更，旧接收端必须 fail closed 或显式标记 unknown，不能映射为高权限状态。
- 删除/改名/改变语义/改变 ID 前缀属于 breaking change，必须发布新 major。
- 任何兼容适配不得改变 tenant 权威来源、Evidence 完整性要求或 Response 审批门槛。
- Agent 项目规范 JSON、Response 固定字段摘要和 Audit hash-chain 摘要预像均属于 major 契约；修改对象键排序规则、字段序列或摘要预像必须升 major 并记录 ADR。
