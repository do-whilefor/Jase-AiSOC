# P0 阶段状态

结论：P0 为当前最早未完成阶段。本轮已完成代码和静态设计基线，但受当前环境约束，P0 尚未达到计划书退出条件。

## P0-P14 静态盘点

| 阶段 | 实际状态 | 静态依据 |
|---|---|---|
| P0 | 代码已实现，待 Linux 编译和验证；阶段未关闭 | 仓库仅有 `aisoc-contracts`、五类契约测试源和 P0 架构/威胁模型/评审材料；Schema drift、Contract Test 和正式评审证据均未执行。 |
| P1 | 未进入 | 仅有为 P0 提供依赖边界的最小 Workspace；计划书要求的 toolchain/lock、core/crypto/config/telemetry/storage/db、migration、CI、SBOM、签名和 Runtime 发布骨架尚不存在。 |
| P2-P14 | 未进入 | 对应生产 crate、数据库/消息/对象存储实现、Linux Agent/Web Guard/中心主链、Console/CLI、部署制品与发布验证均尚不存在；P0 契约中出现的后续领域类型不等于后续阶段实现。 |

因此必须继续停留在 P0；在 P0 退出证据成立前，不以创建空 crate 或占位文件的方式越级推进 P1-P14。

## 已实现（待 Linux 编译和验证）

- 最小 Cargo Workspace，仅纳入 P0 的 `aisoc-contracts`，未提前恢复 P1-P14 运行模块。
- P0 使用仓库既有 Rust 1.82 MSRV，直接依赖精确固定版本；Cargo.lock 与 toolchain 文件仍属于 P1 工程治理退出项，本阶段不在 Windows 生成或恢复。
- 关键 ID newtype（含 PromptId、RuleReleaseId、StoreId、WafRuleId 注册标识）、SchemaVersion、Timestamp、SHA-256、SecurityState、Assurance、Classification 等基础语义；跨边界 `_id`/`_ids` 字段不使用裸 `String`；WafRuleId 的运行时与 Schema 同步限定为安全、非空的 `/` 分段 registry selector，拒绝 URL、冒号、空分段和 traversal-shaped 值。
- Agent、SecurityEvent、WebRequest/WebSecurityEvent、Detection、Incident、Evidence、Claim、ModelAssessment、ResponseAction、Audit 和 Error 契约。
- authenticated tenant/agent/host binding、Agent envelope 与嵌套 Event 的 agent/host/boot/sequence/子契约闭包、Agent payload 递归对象键规范化摘要、SecurityEvent Linux process/network/file/auth 最小语义及 Event source 与 Raw Evidence coarse producer source lineage、Evidence tenant/incident membership/classification/integrity/custody/time 二次授权、Evidence custody 的 typed actor/sequence/Evidence digest/相邻 Hash/状态演进/链末状态闭包、Control 的客户端对象声明与服务端真实 owner scope 双绑定、Incident 与服务端解析的 Detection/Claim/Evidence/Entity/custody chain 关系闭包（含 Detection typed Host ID 与其引用 Entity 的绑定）、Incident 相邻 revision 的 append-only 关系与 Timeline 多重集闭包、Claim verifier 成对与独立性状态机、ModelAssessment 的 Web Request/Incident 互斥主体、Incident Assessment/EvidencePackage/Claims review graph 与 Web Request/Event/Assessment graph 绑定、Web authority/URI 单一语义及正文长度/Hash/Content-Type/body-field 最小一致性（含唯一参数和 multipart boundary）、Web AI route-scoped fail policy 与互斥决策来源、Audit typed Request/Host/Agent/Service/Route 主对象和可选同类 correlation、typed stream/单调 sequence/首项形状/相邻过渡/hash-chain、Error retryability、Response tier/capability/target/approval/Evidence/TTL/rollback/runbook 内部守卫，以及 Response 与服务端权威 Policy/Approval、Incident revision、Evidence membership/权限/时间/custody chain 的关系闭包。
- JSON Schema 统一导出入口、固定输出清单、共享安全 basename 守卫、清单一致性测试和 `--check` 漂移检查代码；exporter 在任何目录创建或文件读写前先拒绝 manifest/generator 重复、集合漂移及不安全文件名。
- 23 项 JSON Schema 固定清单；manifest 和 generator 各自拒绝重复文件名且集合一一对应，文件名限定为版本化安全小写 ASCII basename；对根/嵌套固定对象及 tagged enum variant 的未知字段拒绝编写递归静态测试守卫；动态键 map 仍由各自业务守卫控制，不被误判为固定 DTO。
- Web/SOC/Control/Response/Schema 五个测试源文件，共 372 个 `#[test]` 静态声明（Web 32、SOC 216、Control 51、Response 70、Schema 3）。直接结果矩阵已闭合 SchemaVersionDecision 2/2、SafeFieldsDecision 8/8、AuthenticationContextDecision 8/8、TenantScopeDecision 6/6、AgentBindingDecision 24/24、SecurityEventDecision 21/21、DetectionContractDecision 17/17、IncidentContractDecision 25/25、IncidentRelationshipDecision 34/34、IncidentRevisionTransitionDecision 15/15、EvidenceRefDecision 5/5、EvidenceAccessContextDecision 4/4、CustodyRecordDecision 10/10、CustodyTransitionDecision 10/10、EvidenceCustodyChainDecision 11/11、EvidenceUseDecision 12/12、EvidenceLifecycleDecision 4/4、EvidencePackageDecision 11/11、EvidencePackageBindingDecision 9/9、ClaimContractDecision 14/14、ClaimVerificationDecision 24/24、ModelAssessmentDecision 13/13、ModelAssessmentBindingDecision 16/16、WebModelAssessmentBindingDecision 17/17、WebRequestContractDecision 24/24、AuditContractDecision 16/16、AuditChainTransitionDecision 8/8、ErrorContractDecision 6/6，以及其余 Web 组、ResponseContractDecision 36/36 与 ResponseAuthorizationBindingDecision 29/29 的全部结果；样例覆盖版本化身份/tenant/object 绑定、Linux 事件语义及 Event/Raw Evidence producer-source 替换拒绝与计划支持的正向来源矩阵、Web Content-Type/body metadata 边界、Detection Host/Entity 替换拒绝、Evidence 完整性/生命周期/完整 custody hash-chain（含 Verified→Failed 后续篡改发现、Failed 不可恢复、AI/Incident/Response 集合内未引用坏链也 fail closed）、Incident append-only revision、Incident/Web 两类 AI review graph、Web route fail policy、审计流顺序/hash-chain、规范错误，以及 Response 内部审批/目标边界和权威 Policy/Approval/Incident/Evidence/custody 关系闭包。所有数字均来自源码文本静态计数，测试未执行。
- 跨边界集合和非 ID 文本已冻结显式上限：Agent payload 4096 events；Evidence/Claim/Model/Response 关键引用 512；EvidencePackage 最多 512 项、64 MiB；SecurityEvent extensions 最多 64 项/64 KiB；Response 最长有效期 24 小时、最多 16 个审批声明。
- 七平面架构、依赖方向、威胁模型、错误码、兼容策略和安全不变量评审材料。
- 安全不变量静态评审矩阵，逐项映射 Rust 权威守卫、负向样本与待 Linux 动态证据。
- 已按计划书附录 A 创建完整仓库目录骨架，包括 24 个 Rust crate 目录（含现有 `aisoc-contracts`）、Schema/规则/migration/fixture/replay/bench/fuzz 目录、六类部署目录、ADR/运维/兼容性文档目录和辅助工具目录；新目录仅以 `.gitkeep` 保留，未创建后续 crate、未加入 Workspace，也不作为 P1-P14 已启动或完成的证据。

## 当前未执行

依照用户要求，本阶段未执行 Cargo build/check/test/clippy/fmt/run，未运行 Schema exporter，未安装依赖，未启动服务、数据库、容器或 migration，也未渲染计划书。不能声称代码已编译、测试或运行成功。

## P0 退出条件与待验证证据

| 计划书退出条件 | 当前状态 | Linux 验证证据 |
|---|---|---|
| Schema drift = 0 | 代码已实现，未运行 | 锁定 toolchain 导出 `schemas/`，与提交快照字节级比较。 |
| Web Contract Test | 测试源已实现，未运行 | `web_contract` 测试结果及负向解析样本。 |
| SOC Contract Test | 测试源已实现，未运行 | `soc_contract` 测试结果及跨租户/坏 Hash 样本。 |
| Control Contract Test | 测试源已实现，未运行 | `control_contract` 结果及双租户/双角色矩阵。 |
| Response Contract Test | 测试源已实现，未运行 | `response_contract` 结果及 replay/target-change 用例。 |
| 安全不变量评审完成 | 文档已形成，需正式评审 | 架构/安全评审记录与批准的 ADR/issue。 |

## 下一步

当前 P0 的代码与静态材料已进一步收敛。Windows 阶段下一步仍不是 P1，而是继续静态审阅跨契约组合边界和冻结材料的一致性；Schema 清单/生成映射已完成 23/23 文本闭合，并为所有固定对象层级补充递归未知字段 Schema 守卫，Evidence 已冻结完整 custody hash-chain，AI/Incident/Response 必须接收服务端解析的 chain 集合，Audit 已冻结 typed Request/Host/Agent/Service/Route 关联、stream、sequence 和相邻过渡，Error 及 SchemaVersion/SafeFields 公共前置结果也具有直接样例。切换到 Linux 后，再使用锁定 Rust toolchain 编译并执行 Schema drift、Web/SOC/Control/Response Contract Test，最后完成正式安全不变量评审。只有这些退出证据全部成立，才能关闭 P0 并进入 P1。

AgentEnvelope/SecurityEvent 的 8.1 字段审计已记录阶段归属：P0 只冻结无需外部状态即可证明的 identity/sequence/subcontract/digest/source-lineage；P2 负责证书注册、轮换和吊销，P3 负责原始压缩比、服务端 receive-time 漂移、batch 幂等与同键异 digest 冲突。离线重传场景下不把 producer `created_at` 与连接 `authenticated_at` 误作先后不变量。

建议 Linux 验证顺序：使用 Linux 环境中明确选择且满足当前 MSRV 的 Rust toolchain 编译 `aisoc-contracts`；生成 23 项 Schema 快照并执行 `--check`；运行五个契约测试 target；完成双租户/双身份、完整 custody chain 的存储解析/原子追加/并发/截断/篡改、Web AI 故障 × route policy、Response 权威 Policy/Approval/Incident/Evidence substitution 动态矩阵与正式安全评审。`rust-toolchain.toml`、`Cargo.lock`、CI/SBOM/签名等工程治理文件仍按顺序留到 P1，不作为提前推进 P1 的借口。命令仅在切换到 Linux 后按当时仓库脚本确定，本阶段不预执行。
