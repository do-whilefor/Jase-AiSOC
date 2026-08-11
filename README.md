# Blue Team AI Agent

面向通用 Linux 的安全分析、事件溯源与恶意程序识别平台。项目坚持“确定性检测优先、事件级 AI 门控、证据可回溯、响应受策略控制”的边界。

## 当前状态

项目处于 **P0/P1 正式门禁未关闭、P2-P5 按实验增量推进、P6-P11 非 Docker 初版继续实现**。
P3 base 管道、新鲜度监控后台任务（`FreshnessMonitor` + `/api/v1/freshness`(+`/metrics`)）、P4 Nginx/Apache/sshd 适配及扫描/爆破/注入/异常方法规则已实现；P5 已有 Falco/audit normalizer、真实 audit.log polling 接入代码、持久 sequence/cursor+pending serial、DB 回看重建和四类主机行为链；P6 已有确定性聚合、版本化证据/Claim/时间线/实体边、查询引用、数据缩减审计及 merge/split/close/feedback；P7 已有 Review Gate、EvidencePackage、Provider、只读 Tool Gateway、预算/熔断、单 Analyzer、追加写审计与 API；P8 已有程序校验、盲 Verifier slots、冲突检测、可选 Adjudicator、assurance 和模型历史路由；P9 已有独立 AES-GCM quarantine、有界静态检查、多信号结论、文件上下文、租约 worker、样本/扫描 API 和签名沙箱报告入口；P10 已有跨 Incident/Host evidence graph、初始入口/key path/影响范围、有限 ATT&CK mapping、精确基础设施 cluster、有界 graph query 和 hash export，identity assertion 被固定为 0；P11 已有 typed 响应策略、RBAC/审批、执行租约/审计/outbox、目标重验证 Runner、显式 local-single-node 原生 worker 初版、迁移 0013-0016、独立签名 Webhook worker、Ed25519 tenant-scoped 规则生命周期、控制台 Snapshot API、Incident revision 与恶意文件上下文调查工作区、基于固定 seed Incident 的跨主机攻击溯源视图、只读规则治理/情报缓存、无 secret 的模型运营和 auditor/admin 系统运营真相视图及响应详情/审批/排队/回滚 UI。P2 VM 级、P3 NATS/新鲜度、P4 独立质量指标与生命周期的真实 PostgreSQL/双租户 rollout 验证、P5 原生 Linux auditd/Falco/eBPF、高 EPS PostgreSQL，以及 P6-P11 真实 PostgreSQL、Provider/Scanner、双租户 HTTP、并发、多主机 Agent-side 响应/真实回滚、真实 Webhook、动态沙箱、真实攻击回放和 Kali 门禁仍未完成。
`blue-team-ingest` 负责 mTLS 上传；`blue-team-api` 可启动 normalize/detect/query 后台任务。二者是独立进程，不再把单独启动 API 描述成完整 ingest 闭环。
当前基线包括：

- 可行性结论与范围边界；
- MVP 部署剖面和关键架构决策；
- 威胁模型、数据分类和兼容矩阵；
- Security Event Schema v0.1；
- API/契约版本策略、测试清单和阶段门禁；
- Python 工程质量、依赖审计和 SBOM 的 CI 基线。
- 可启动的 P1 API、PostgreSQL 迁移、不可变本地对象存储和请求级事务；
- 由数据库凭据绑定的租户身份，客户端提供的租户上下文不能改变认证租户；
- Linux 平台信息与 Collector 能力报告的严格类型契约。
- P2 AgentEnvelope/Heartbeat/Batch/ACK 契约，以及优先级、完整性和重试可审计的本地
  SQLite 队列初版。
- P2 一次性 Agent 注册、服务端绑定的 P-256 mTLS 证书、轮换/吊销/重新注册、本地机器绑定
  与 PostgreSQL 单活会话租约初版；真实 Ingest 接入前不宣称端到端克隆阻断。
- P2 确定性 Agent 生命周期、Collector 故障隔离、Heartbeat 调度，以及 SQLite protection mode
  驱动的非必要 Collector 暂停/恢复初版；新增真实 `blue-team-agent run` 入口、单实例状态锁及
  `0600` fsync 生命周期/Heartbeat journal。
- P2 Ed25519 签名制品清单、Linux 目标和 payload 完整性校验、sequence/版本防重放、持久化
  安全版本下限、确定性灰度及独立回滚权限；已验证本地 tar 安全解包、健康门禁、原子激活、
  跨进程安装锁和崩溃恢复初版；候选版本通过固定 `health-probe` argv 的有界进程 supervisor
  验证启动、健康与 TERM→KILL 回收，尚未接入网络下载、systemd/策略激活链路。
- P3 worker 实际执行 partition watermark、迟到标记、不可变重放和 DLQ；新迟到事实不再与唯一约束冲突，normalize 去重键纳入 trusted host/source 作用域以防跨主机互相吞并。
- P4 检测按 tenant/host/entity/rule/window 去重，避免同租户跨主机或同主机跨来源告警互相吞并；回放数据集可由生成器重建并校验 SHA-256。
- P5 audit.log Collector 由 Agent run-once 循环驱动，完整事实与 gap 分优先级入可靠队列，Heartbeat
  保留 drop/backlog/parse/incomplete 计数；DetectionWorker 可从完整 DB 窗口重建跨批次链并在
  超限时显式失败。成功链仍只到 `suspected_success`，当前仅 Windows 临时文件/离线回放证据，
  原生 Linux Collector 与 L1/L2 证据待 Kali/VM。
- P6 IncidentWorker 使用完整有界 detection/evidence 回看；同 tenant/host/subject 的攻击链确定性聚合，
  重放不新增 revision，迟到事实追加 revision。Claim、时间线和关系边均通过租户作用域外键回到
  normalized event/raw_ref/integrity hash；10,000 条重复上下文缩减为 20 条主样本并保留
  `full_query_ref`。当前仅单元/Mock/离线迁移证据，真实 PostgreSQL 集成测试留到 Kali。
- P7 AI Review 默认关闭且只审核 Incident revision；普通低阈值 Incident 零模型调用。EvidencePackage 最多
  20 个主样本，system instructions 与不可信证据分离；Provider 受 timeout/retry/circuit/token/cost
  预算约束。Tool Gateway 只读且固定 tenant/Incident/revision/query_ref；最终 Claim 只能引用 package
  或已审计 Tool evidence。Provider 支持 Kimi/GLM/DeepSeek/OpenAI 官方与自定义 OpenAI 兼容端点
  （`PROVIDER_PRESETS` 集中管理固定 base；接入见 [docs/model-providers.md](docs/model-providers.md)）。
  迁移 `20260809_0009` 和真实 PostgreSQL 集成测试已提交，当前留待 Kali。
- P8 在 Analyzer 后无条件执行程序化 Claim-Evidence 校验；高风险、关键资产、破坏性动作以及
  unsupported/conflicting Claim 触发盲 Verifier。Verifier 不接收 Analyzer verdict/score/identity；冲突由
  可选 Adjudicator 处理，确定性矛盾不能被模型覆盖。默认三角色共用 3 次模型调用，缺少审核或未解决
  冲突会降低 assurance 并要求人工。迁移 `20260809_0010` 与真实 PostgreSQL 门禁已提交，当前留待 Kali。
- P9 使用独立 key 的 AES-256-GCM quarantine；API 不返回 ref，也没有样本下载/导出路由。ZIP/TAR/
  ELF/script 静态检查严格有界且不提取/执行；YARA-X/ClamAV 未配置时明确标为 unavailable，单一信号
  不能确认 family/type。静态分析只由独立 `blue-team-malware-worker` 进程执行；动态沙箱当前禁用，
  仅接受绑定 tenant/sample/hash 且通过 Ed25519/Schema/大小验证的报告。迁移 `20260809_0011` 和
  PostgreSQL 集成门禁已提交，真实 scanner、双租户、并发、Linux noexec mount 与沙箱逃逸/外联待 Kali。
- P10 只从当前 Incident revision 的 normalized evidence 构建 seed 连通分量；两主机同 session 仅形成
  技术关联，必须再有目标主机成功认证/执行证据才形成 lateral step。ATT&CK 与 infrastructure cluster
  全部引用 evidence，真实身份归因 Schema 固定为 0。迁移 `20260809_0012`、bounded graph query 和
  canonical SHA-256 调查导出已提交；真实 PostgreSQL/双租户/并发/攻击回放/性能与 custody 待 Kali。
- P11 响应计划只引用精确 Incident revision/evidence 和当前 Host/Agent 绑定；R2/R3 受 AttackState、
  资产关键度、模型审核、预算、审批、回滚和目标重验证门控，请求人不能自批，关键资产需要双审批。
  `blue-team-response-worker` 当前只支持显式 `local_single_node`：从私有 Agent config 加载 tenant/host/
  agent 绑定，拒绝任何远端目标；提供临时 IP block、普通文件 quarantine 和精确 allowlist 账号禁用
  三类初始 rollback Adapter。它不是多主机远程执行器，默认关闭，且尚无 Kali 原生证据。控制台通过
  固定同源有界代理读取 Snapshot、Incident revision 调查/成员证据、当前 seed Incident 的 P10 攻击溯源、恶意文件分析/同哈希上下文及响应详情，并已提供审批/拒绝、
  执行排队和回滚请求。规则运营页把九条 bundled rule 的 owner/source/version/dataset/误报预期/
  ATT&CK/suppression/rollback 与租户命中/反馈并列展示，并显示签名 lifecycle state、effective scope、
  manifest/key/catalog、Canary/validation 边界和 governed/legacy/shadow 计数；DetectionWorker 对 Draft/
  缺失/过期/漂移状态 fail closed，且页面不提供无签名发布控件，也不把 enrichment cache 冒充受管 IOC
  生命周期。操作员令牌及
  模型运营页只显示 provider/model/role 配置状态、租户 review outcomes、成本/延迟/失败聚合和有界
  最近运行；不返回 key、base URL、Prompt 或响应，也不在缺少主动探测/ground truth 时伪造健康或
  Precision/Recall。系统运营页仅向 auditor/tenant_admin 显示当前租户的持久化 work state、最近 Agent
  queue telemetry、记录/错误/新鲜度计数、运行/迁移版本、当前 Host-Agent 绑定的 heartbeat 自报版本聚合
  和无 token/digest 的操作凭据；该版本值不证明运行二进制或签名制品完整性。NATS backlog age、容量、
  依赖健康、deployment inventory、human user directory、签名升级编排与自动回滚仍明确不可用。攻击溯源页只显示
  当前租户/current revision 的有界技术投影，保持 evidence/graph closure，不返回 raw_ref、原始字节或实体 attributes，
  identity assertion 固定为 0；任意图查询和调查导出尚未接入控制台。操作员令牌及 HMAC
  绑定写入 nonce 仅保留在页面内存。独立
  `blue-team-notification-worker` 对 outbox 使用短租约、
  指数退避/DLQ、固定目标 allowlist、HMAC-SHA256 和最小化事件；请求不能提供目标 URL，非 loopback
  必须 HTTPS，重定向不跟随。真实 Adapter、三类回滚、真实 Webhook/PostgreSQL、完整基础设施遥测/升级运营和 Kali
  边界待验证。

完整计划来源：`AI安全分析与溯源_项目计划书_Python.docx`。

## 架构边界

```text
Linux Sensors/Agent -> Ingest -> Normalize -> Detect -> Incident
                                                |
                                                v
                                      AI Review Gate (optional)
                                                |
                                                v
                                  Policy/Approval -> Fixed Actions

Tenant Upload -> Encrypted Quarantine -> Standalone Static Worker -> Malware Report
                                           X
                              no in-process sample execution

Incident revisions -> Evidence-bound Cross-host Trace -> Query / Structured Export
                                             |
                                  identity attribution = 0

Response outbox -> Standalone Notification Worker -> Fixed signed Webhook
```

- AI 只审核事件证据包，不逐日志、逐网络包或逐 syscall 运行。
- 原始证据不可被 AI 输出覆盖，确认结论必须引用 `evidence_id` 或可验证查询。
- Action Runner 只接受已注册的结构化动作，不接受任意 Shell。
- 当前原生 Runner 只允许与本机私有 Agent config 完全匹配的 action；多主机响应必须在未来通过
  认证的 Agent-side 固定动作通道实现，不能在中央服务主机代执行。
- 关闭模型、搜索、图数据库或沙箱后，基础采集、确定性检测和证据留存仍应运行。

## 开发基线

要求 Python 3.12+ 和 [uv](https://docs.astral.sh/uv/)：

```bash
uv sync --locked --all-groups
uv run ruff format --check .
uv run ruff check .
uv run mypy src tests migrations
uv run blue-team-export-schemas --check
uv run alembic check
uv run pytest
```

集成测试需要 PostgreSQL（见 `docs/phase-p3-plan.md` 与 `tests/integration/_helpers.py`）：

```bash
export BLUE_TEAM_TEST_DATABASE_URL="postgresql+asyncpg://blue_team:blue_team_dev@127.0.0.1:55432/blue_team"
uv run alembic upgrade head
uv run pytest tests/integration -v
```

### 可选 Rust 加速器

少量纯函数（SHA-256 / HMAC-SHA256）在 `rust/blue-team-rust` 用 PyO3 实现，由 `src/blue_team/_rusthash.py` 封装并在扩展缺失时回退到标准库 `hashlib`/`hmac`（输出逐字节一致，由 `tests/unit/test_rust_hash.py` 校验）。不构建扩展时平台与全部测试仍可通过：

```bash
uv tool install maturin   # 一次
VIRTUAL_ENV="$(pwd)/.venv" maturin develop --manifest-path rust/blue-team-rust/Cargo.toml
# 或 make rust-extension
```


端到端验证（需 PostgreSQL，见 `docs/phase-p3-plan.md`）：

```bash
export BLUE_TEAM_TEST_DATABASE_URL="postgresql+asyncpg://blue_team:blue_team_dev@127.0.0.1:55432/blue_team"
uv run alembic upgrade head
uv run pytest tests/integration -v
```

## Kali Linux 原生部署

提供一条命令在 Kali/Debian 系主机上完成原生安装（中心服务 + 端点 Agent），详见 [Kali 部署指南](docs/deploy-kali.md)：

```bash
sudo bash deploy/kali/install.sh
sudo systemctl enable --now blue-team-api blue-team-ingest blue-team-agent
```

端点 Agent 现已接入计划书要求的 L0/L1 采集器（在 `/etc/blue-team/agent.json` 按开关启用）：

- `journald`：托管 `journalctl -o json --follow` 子进程，持久化 `__CURSOR`，覆盖 sshd/服务单元日志
- `suricata`：有界 tail `/var/log/suricata/eve.json`，逐行归一化 EVE JSON
- `service_log`：有界 tail Nginx/Apache Common/Combined 访问日志
- `auditd`：原有 `audit.log` polling 采集器（sequence/cursor + pending serial）

所有文件类采集器共享 `agent_core/file_tail.py` 的有界 tail，统一处理 cursor、logrotate 与截断，崩溃后重放可经去重键幂等。

项目资料入口：

- [Kali 部署指南](docs/deploy-kali.md)


- [可行性分析](docs/feasibility.md)
- [P0 执行计划](docs/phase-p0-plan.md)
- [P1 执行与验证状态](docs/phase-p1-plan.md)
- [P2 Agent 与能力探测状态](docs/phase-p2-plan.md)
- [P3 接入网关与标准化](docs/phase-p3-plan.md)
- [P4 检测引擎与状态分层](docs/phase-p4-plan.md)
- [P5 主机运行时与行为链](docs/phase-p5-plan.md)
- [P6 Incident、证据、时间线与实体边](docs/phase-p6-plan.md)
- [P7 AI Review Gate、单 Analyzer 与只读 Tool Gateway](docs/phase-p7-plan.md)
- [P8 多模型盲审、确定性校验与冲突裁决](docs/phase-p8-plan.md)
- [P9 静态恶意文件、隔离存储与独立沙箱接口](docs/phase-p9-plan.md)
- [P10 跨主机攻击图谱、技术溯源与调查导出](docs/phase-p10-plan.md)
- [P11 响应、审批与安全运营控制台](docs/phase-p11-plan.md)
- [架构基线](docs/architecture/baseline.md)
- [威胁模型](docs/architecture/threat-model.md)
- [兼容矩阵](docs/compatibility-matrix.md)
- [测试计划](docs/test-plan.md)

## 贡献与维护

```cmd
git add -A
git commit -m "Update project"
git push
```

提交前必须通过格式、静态检查、类型检查、单元测试、依赖审计和 Schema 契约检查。详细约定见 [CONTRIBUTING.md](CONTRIBUTING.md)。
