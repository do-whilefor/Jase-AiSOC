# P0 阶段状态

结论：P0 为当前最早未完成阶段。本轮已完成代码和静态设计基线，但受当前环境约束，P0 尚未达到计划书退出条件。

## 已实现（待 Linux 编译和验证）

- 最小 Cargo Workspace，仅纳入 P0 的 `aisoc-contracts`，未提前恢复 P1-P14 运行模块。
- P0 使用仓库既有 Rust 1.82 MSRV，直接依赖精确固定版本；Cargo.lock 与 toolchain 文件仍属于 P1 工程治理退出项，本阶段不在 Windows 生成或恢复。
- 关键 ID newtype（含 PromptId、RuleReleaseId、StoreId、WafRuleId 注册标识）、SchemaVersion、Timestamp、SHA-256、SecurityState、Assurance、Classification 等基础语义；跨边界 `_id`/`_ids` 字段不使用裸 `String`；WafRuleId 的运行时与 Schema 同步限定为安全、非空的 `/` 分段 registry selector，拒绝 URL、冒号、空分段和 traversal-shaped 值。
- Agent、SecurityEvent、WebRequest/WebSecurityEvent、Detection、Incident、Evidence、Claim、ModelAssessment、ResponseAction、Audit 和 Error 契约。
- authenticated tenant/agent/host binding、Agent envelope 与嵌套 Event 的 agent/host/boot/sequence/子契约闭包、Agent payload 递归对象键规范化摘要、SecurityEvent Linux process/network/file/auth 最小语义、Evidence tenant/incident membership/classification/integrity/custody/time 二次授权、Control 的客户端对象声明与服务端真实 owner scope 双绑定、Incident 与服务端解析的 Detection/Claim/Evidence/Entity 关系闭包、Incident 相邻 revision 的 append-only 关系与 Timeline 多重集闭包、Claim verifier 成对与独立性状态机、Incident ModelAssessment/EvidencePackage/Claims review graph 绑定、Web authority/URI 单一语义、Web AI route-scoped fail policy 与互斥决策来源、Audit token/版本化治理对象/hash-chain、Error retryability、Response tier/capability/target/approval/Evidence/TTL/rollback/runbook 全结果静态守卫。
- JSON Schema 统一导出入口、固定输出清单、清单一致性测试和 `--check` 漂移检查代码。
- 21 项 JSON Schema 固定清单；清单与生成器一一对应，并对版本化文件名、根契约未知字段拒绝编写静态测试守卫。
- Web/SOC/Control/Response/Schema 五个测试源文件，共 282 个 `#[test]` 静态声明（Web 27、SOC 168、Control 46、Response 38、Schema 3）。直接结果矩阵已闭合 SchemaVersionDecision 2/2、SafeFieldsDecision 8/8、AuthenticationContextDecision 8/8、TenantScopeDecision 6/6、AgentBindingDecision 24/24、SecurityEventDecision 20/20、DetectionContractDecision 17/17、IncidentContractDecision 25/25、IncidentRelationshipDecision 28/28、IncidentRevisionTransitionDecision 15/15、EvidenceRefDecision 5/5、EvidenceAccessContextDecision 4/4、EvidenceUseDecision 10/10、EvidenceLifecycleDecision 4/4、EvidencePackageDecision 11/11、EvidencePackageBindingDecision 9/9、ClaimContractDecision 14/14、ClaimVerificationDecision 19/19、ModelAssessmentDecision 13/13、ModelAssessmentBindingDecision 16/16、AuditContractDecision 15/15、ErrorContractDecision 6/6，以及 Web 六组与 ResponseContractDecision 35/35 的全部结果；样例覆盖版本化身份/tenant/object 绑定、Linux 事件语义、Evidence 完整性与生命周期、Incident append-only revision、AI review graph、Web route fail policy、审计哈希链、规范错误与 Response 审批/目标重验证边界。
- 跨边界集合和非 ID 文本已冻结显式上限：Agent payload 4096 events；Evidence/Claim/Model/Response 关键引用 512；EvidencePackage 最多 512 项、64 MiB；SecurityEvent extensions 最多 64 项/64 KiB；Response 最长有效期 24 小时、最多 16 个审批声明。
- 七平面架构、依赖方向、威胁模型、错误码、兼容策略和安全不变量评审材料。
- 安全不变量静态评审矩阵，逐项映射 Rust 权威守卫、负向样本与待 Linux 动态证据。

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

当前 P0 的代码与静态材料已进一步收敛。Windows 阶段下一步仍不是 P1，而是继续静态审阅 Schema 生成清单、跨契约组合边界和冻结材料的一致性；Audit/Error 及其 SchemaVersion/SafeFields 公共前置结果已具有直接样例。切换到 Linux 后，再使用锁定 Rust toolchain 编译并执行 Schema drift、Web/SOC/Control/Response Contract Test，最后完成正式安全不变量评审。只有这些退出证据全部成立，才能关闭 P0 并进入 P1。

建议 Linux 验证顺序：使用 Linux 环境中明确选择且满足当前 MSRV 的 Rust toolchain 编译 `aisoc-contracts`；生成 21 项 Schema 快照并执行 `--check`；运行五个契约测试 target；完成双租户/双身份、Web AI 故障 × route policy 动态矩阵与正式安全评审。`rust-toolchain.toml`、`Cargo.lock`、CI/SBOM/签名等工程治理文件仍按顺序留到 P1，不作为提前推进 P1 的借口。命令仅在切换到 Linux 后按当时仓库脚本确定，本阶段不预执行。
