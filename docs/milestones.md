# 阶段里程碑与门禁

阶段编号表达技术依赖，不代表所有工作只能串行。未通过前置门禁的实验结果不得进入生产主链路。

| 阶段 | 目标 | 关键前置/门禁 | 状态 |
|---|---|---|---|
| P0 | 架构、威胁、Schema、部署和工程基线 | 人工架构/安全评审，无阻塞项 | 进行中 |
| P1 | Python 核心平台、迁移、对象存储抽象、健康页 | P0 Accepted；锁定安装与全链路测试 | 进行中（本地门禁已验证，待 P0/CI） |
| P2 | Linux Agent、能力探测、缓存、mTLS、制品 | P0/P1 契约；跨发行版安装/采集/降级 | 进行中（实验：探测、身份、进程 runtime、有界候选健康门禁、本地 tar 安装；本轮新增 mTLS Ingest 网关 + Agent 传输 + 单活租约续期，Docker 级闭环已实现并单元测试） |
| P3 | gRPC 接入、JetStream、标准化、DLQ/重放 | P1 Schema + P2 批次；幂等/乱序/非法数据 | 进行中（base profile 批次 C/D/E 完成：normalizer 框架 + NormalizeWorker + events/detections 查询 API + 端到端集成测试；stream profile/NATS/新鲜度监控仍为实验） |
| P4 | 网络/Web/SSH 检测和状态分层 | P3 事件；尝试与成功不混淆 | 进行中（首增量完成：detection_engine 模块 + web.recon.scanning/auth.ssh.bruteforce 规则 + detections 表 + migration 0006 + 攻击状态机 + 回放数据集 + 25 单测/1 集成测试；Nginx/Apache 适配、注入/异常方法规则待后续增量） |
| P5 | eBPF/audit/Falco 与主机行为链 | P2/P3；至少三类发行版 L2 与 L1 降级 | 未开始 |
| P6 | Incident、证据、时间线与实体边 | P4/P5 告警；判断可回到原文，迟到可修订 | 未开始 |
| P7 | Review Gate、单 Analyzer、只读工具 | P6 EvidencePackage；模型故障不阻塞，Claim 可验证 | 未开始 |
| P8 | 多模型审核、冲突与 Prompt 注入验证 | P7 原子 Claim；确定性校验优先 | 未开始 |
| P9 | 静态恶意文件与独立沙箱接口 | P2/P6 文件上下文；平台不直接执行样本 | 未开始 |
| P10 | 跨主机图谱、技术溯源和导出 | P6 实体边；无证据身份归因为 0 | 未开始 |
| P11 | 响应、审批和完整控制台 | P6/P8；R2/R3 门禁和回滚 | 未开始 |
| P12 | 跨发行版硬化、性能、安全与发布 | 全部阶段；最终 Go 或正式风险接受 | 未开始 |

## 产品里程碑

- **MVP**：P0-P7 完成，并通过首个可验证闭环基线。
- **V1.0**：P12 完成，兼容、容量、供应链、审批、回滚和运维达到试点门槛。
- **V1.x**：HA、多租户生产隔离、规则运营、SIEM/SOAR 集成。
- **V2.0**：Kubernetes、云审计、Windows、跨地域和高级模型；不得削弱 Linux 主链路。
