# P0 架构基线

## 产品边界

平台从 Linux 端点、网络传感器和服务日志获取事实，经标准化、确定性检测和 Incident 聚合后，按风险决定是否生成 AI Review Task。AI 输出是待验证 Claim，不是原始事实。响应必须经过独立策略、审批和固定执行器。

MVP 必须覆盖：基础 Agent、进程执行/出站连接、Suricata、Web/SSH、统一事件、确定性检测、Incident、证据引用、单 Analyzer、静态恶意文件和人工/短时可回滚响应。

MVP 非前置依赖：全量 PCAP、完整 LSM 文件追踪、ClickHouse、OpenSearch、图数据库、多 Verifier、动态沙箱、Kubernetes、HA 和高风险自动响应。

## 逻辑数据流

```text
Collectors
  -> Agent Buffer (priority, batch, retry, sequence)
  -> mTLS Ingest (identity, tenant binding, schema, limits)
  -> Raw Evidence (immutable object + integrity metadata)
  -> Normalized Event (versioned and replayable)
  -> Deterministic Detection (rule/window/sequence/file)
  -> Incident (dedupe, timeline, entity, evidence refs)
  -> AI Review Gate ----no----> deterministic result remains available
          |
         yes
          v
     Evidence Package -> Analyzer -> Claim Verification
                                      |
                                      v
                              Policy / Approval
                                      |
                                      v
                       Registered Action -> Verify/Rollback
```

## 部署基线

### 开发与 P1：Base All-in-One

- 单个 Python 主服务；
- PostgreSQL 保存控制面和事务状态；
- 本地不可执行目录实现对象存储接口；
- 进程内有界队列加数据库检查点；
- Mock Agent/Provider 用于契约与降级测试。

目标是最小依赖下验证迁移、健康、租户/资产/空事件与证据存储抽象，不宣称中心化生产能力。

### MVP 集成：Stream Central + Agents

- api-server、ingest、normalizer、detection、incident/AI Worker 可独立运行；
- PostgreSQL + NATS JetStream + MinIO/S3 兼容对象存储；
- 至少两个 Agent 验证背压、断网、重放、乱序和身份隔离；
- ClickHouse/OpenSearch 保持关闭，除非容量测试证明需要。

## 不可破坏的安全不变量

1. 鉴权上下文确定租户，客户端字段不能覆盖租户归属。
2. 原始证据只追加；标准化事件可以按版本重算但不能覆盖原文。
3. 每个确认结论必须引用可访问、同租户、完整性状态明确的证据。
4. 模型不可用、超时或预算耗尽不能阻断确定性主链路。
5. 不可信日志是数据而不是指令；工具调用必须匹配注册 Schema 和租户范围。
6. Action Runner 不接收任意 Shell/SQL/URL；写动作必须重新验证目标身份。
7. R3 默认人工审批，关键资产要求双人审批；模型不能单独提升允许动作。
8. 样本存储不可执行；动态沙箱如果启用，必须位于独立信任域。
9. Schema、规则、Prompt、模型、策略和动作均保留版本与审计引用。
10. 丢弃、采样、聚合、降级和失败必须可观察、可计数并能说明影响能力。

## 包与服务边界

初始 Python 包按 `domain`、`platform`、`agent_core`、`config`、`storage`、`api_server`
划分；后续服务只复用领域契约，不复制 Schema。Agent、接入、检测、Incident、AI 和响应
模块通过版本化消息/API 连接。外部组件通过 Protocol/Adapter 隔离。

Agent 本地队列以单一 tenant/agent/host 身份绑定，使用 SQLite 事务、WAL 和 FULL
synchronous 保存逐事件压缩载荷。未完整 ACK 的批次保持不可变并复用 batch_id；P0/P1
无法入队时进入保护模式，P2/P3 主动降维或丢弃必须生成可重放审计记录。

## 技术运行边界

- I/O：`asyncio`/ASGI/grpc.aio；Linux 可选 uvloop。
- CPU 密集：独立进程池或 Worker，不阻塞事件循环。
- eBPF：受限 C/BCC 或签名 libbpf CO-RE 辅助程序；不接受远程任意探针源码。
- 数据：PostgreSQL 为事务事实源，对象存储为原始证据载体；NATS 只承担消息与重放。
- 可观测性：结构化日志、Prometheus 指标、OpenTelemetry trace，贯穿 ingest 到 action。

## 质量属性

- 事件新鲜度验证基线 P95 不高于 10 秒。
- 不可解释数据丢失和跨租户证据引用为 0。
- 确认失陷 Claim 证据覆盖率 100%。
- 正常日志触发 AI 的比例在验证阶段不高于 0.5%。
- Agent 各 Profile 的 CPU/内存分别验收，外部传感器不混入 Agent 预算。
