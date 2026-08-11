# 阶段里程碑与门禁

阶段编号表达技术依赖，不代表所有工作只能串行。未通过前置门禁的实验结果不得进入生产主链路。

| 阶段 | 目标 | 关键前置/门禁 | 状态 |
|---|---|---|---|
| P0 | 架构、威胁、Schema、部署和工程基线 | 人工架构/安全评审，无阻塞项 | 进行中 |
| P1 | Python 核心平台、迁移、对象存储抽象、健康页 | P0 Accepted；锁定安装与全链路测试 | 进行中（本地门禁已验证，待 P0/CI） |
| P2 | Linux Agent、能力探测、缓存、mTLS、制品 | P0/P1 契约；跨发行版安装/采集/降级 | 进行中（实验：探测、身份、进程 runtime、有界候选健康门禁、本地 tar 安装；本轮新增 mTLS Ingest 网关 + Agent 传输 + 单活租约续期，Docker 级闭环已实现并单元测试） |
| P3 | gRPC 接入、JetStream、标准化、DLQ/重放 | P1 Schema + P2 批次；幂等/乱序/非法数据 | 进行中（base 管道已实现并修复实际 watermark/迟到语义；FreshnessMonitor 后台任务 + `/api/v1/freshness`(+`/metrics`) 已实现并经真实 PostgreSQL 集成测试验证；DLQ 重放消费者已实现并接入 normalize worker 循环；资产富化 Enricher 已接入 normalize 管道；stream profile/NATS 仍未完成） |
| P4 | 网络/Web/SSH 检测和状态分层 | P3 事件；尝试与成功不混淆 | 进行中（扫描、真实 sshd 日志、Nginx/Apache、注入/异常方法、严格回放和 host/entity/rule-version 去重修复已实现；九条规则的 version-bound 治理目录、Ed25519 tenant-scoped Draft→Shadow→Canary→Released/rollback/deprecate/upgrade 持久执行和只读运营投影已实现，但独立质量测量及真实 PostgreSQL/双租户 rollout/rollback 观察未完成） |
| P5 | eBPF/audit/Falco 与主机行为链 | P2/P3；至少三类发行版 L2 与 L1 降级 | 进行中（audit.log polling Collector、持久 sequence/cursor+pending serial、Falco/audit normalizer、DB 回看重建、四类行为链与 5 组主机回放已实现；原生 Linux auditd/Falco、eBPF、高 EPS PostgreSQL 和 VM 门禁未完成） |
| P6 | Incident、证据、时间线与实体边 | P4/P5 告警；判断可回到原文，迟到可修订 | 进行中（确定性聚合、10k→1 Incident 缩减、版本化 evidence/Claim/timeline/entity/edge、查询引用、worker/API 及 merge/split/close/feedback 已完成非 Docker 实现；真实 PostgreSQL、双租户与 Kali 攻击链门禁未运行） |
| P7 | Review Gate、单 Analyzer、只读工具 | P6 EvidencePackage；模型故障不阻塞，Claim 可验证 | 进行中（Gate、EvidencePackage、Kimi/GLM/OpenAI-compatible、Prompt/Schema、预算/熔断、租户+revision 只读 Tool Gateway、单 Analyzer、追加写 task/run/tool/Claim、API 已完成非 Docker 实现；真实 Provider、PostgreSQL、双租户 HTTP、并发与 Kali 门禁未运行） |
| P8 | 多模型审核、冲突与 Prompt 注入验证 | P7 原子 Claim；确定性校验优先 | 进行中（程序化 Claim-Evidence 校验、盲 Verifier slots、冲突检测、可选 Adjudicator、assurance/human-review、三角色共享预算、模型历史路由、追加写 P8 记录与注入测试已完成非 Docker 实现；真实 Provider/PostgreSQL/双租户 HTTP/并发/Kali 门禁未运行） |
| P9 | 静态恶意文件与独立沙箱接口 | P2/P6 文件上下文；平台不直接执行样本 | 进行中（独立 AES-GCM quarantine、有界 ELF/script/ZIP/TAR 静态检查、多源 family/type 门禁、上下文关联、租约式独立 worker、样本/扫描 API、签名沙箱报告 Schema/导入和迁移 0011 已完成非 Docker 实现；真实 YARA-X adapter 已接入 `yara-x` 包并经单元测试验证；真实 ClamAV adapter（clamd INSTREAM 协议）已实现并接入 worker、经单元测试验证；信誉源 Provider 接口已定义但具体外部源未接入；PostgreSQL/双租户/并发、Linux noexec mount 与独立动态沙箱门禁未运行） |
| P10 | 跨主机图谱、技术溯源和导出 | P6 实体边；无证据身份归因为 0 | 进行中（确定性跨 Incident/Host graph、双侧 session+target success 横向门禁、初始入口/key path/影响范围、精确基础设施 cluster、evidence-bound ATT&CK、identity assertion=0、append-only 迁移 0012、bounded query 和无 raw/sample bytes 的 hash export 已完成非 Docker 实现；真实 PostgreSQL、双租户 HTTP、并发、真实攻击回放、性能与 custody 门禁未运行） |
| P11 | 响应、审批和完整控制台 | P6/P8；R2/R3 门禁和回滚 | 进行中（typed 响应策略、RBAC/审批、执行与通知租约、审计/outbox、固定目标签名 Webhook worker、目标重验证 Runner、显式 local-single-node 原生 worker 与三类 rollback Adapter 初版、迁移 0013-0016、Ed25519 tenant rule lifecycle、Snapshot API、Incident revision/成员证据、基于 seed Incident 的 current P10 跨主机溯源有界视图、恶意文件分析/同哈希上下文、只读规则治理/情报 cache、无 secret 的模型运营及 auditor/admin 租户 work/queue/error/credential 和当前绑定 heartbeat 自报 Agent version 真相视图、响应详情/审批/排队/回滚 UI 已完成非 Docker 实现；控制台任意图查询/调查导出、多主机 Agent-side 执行、三类真实回滚、受管 IOC、真实 Provider health/credential/labeled quality、broker/capacity/dependency、部署/签名制品/二进制验证/升级编排运营、真实 Webhook、PostgreSQL/双租户/浏览器/Kali 门禁未完成） |
| P12 | 跨发行版硬化、性能、安全与发布 | 全部阶段；最终 Go 或正式风险接受 | 进行中（P7-P12 安全审计完成：1 HIGH + 2 MEDIUM + 5 LOW 漏洞已修复，核心安全属性全部验证通过，依赖供应链审计无已知漏洞；P12 阶段计划已编写，兼容矩阵、性能压测、安全测试、升级/回滚、备份恢复和运维就绪待执行） |

## 产品里程碑

- **MVP**：P0-P7 完成，并通过首个可验证闭环基线。
- **V1.0**：P12 完成，兼容、容量、供应链、审批、回滚和运维达到试点门槛。
- **V1.x**：HA、多租户生产隔离、规则运营、SIEM/SOAR 集成。
- **V2.0**：Kubernetes、云审计、Windows、跨地域和高级模型；不得削弱 Linux 主链路。
