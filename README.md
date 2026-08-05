# Blue Team AI Agent

面向通用 Linux 的安全分析、事件溯源与恶意程序识别平台。项目坚持“确定性检测优先、事件级 AI 门控、证据可回溯、响应受策略控制”的边界。

## 当前状态

项目处于 **P0 正式评审未完成、P1 本地门禁已通过、P2 容器级闭环已验证、P3 base profile 完成、P4 首增量 + 实时管道接入完成**。
远端 CI 和 P0/P1 正式 Accepted 尚未完成；P2 VM 级、P3 stream profile（NATS）与新鲜度监控、P4 Nginx/Apache 适配与注入规则仍为后续增量。
当前 `blue-team-api` 一条命令启动即形成 ingest → normalize → detect → 查询闭环。
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
```

- AI 只审核事件证据包，不逐日志、逐网络包或逐 syscall 运行。
- 原始证据不可被 AI 输出覆盖，确认结论必须引用 `evidence_id` 或可验证查询。
- Action Runner 只接受已注册的结构化动作，不接受任意 Shell。
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

端到端验证（需 PostgreSQL，见 `docs/phase-p3-plan.md`）：

```bash
export BLUE_TEAM_TEST_DATABASE_URL="postgresql+asyncpg://blue_team:blue_team_dev@127.0.0.1:55432/blue_team"
uv run alembic upgrade head
uv run pytest tests/integration -v
```

项目资料入口：

- [可行性分析](docs/feasibility.md)
- [P0 执行计划](docs/phase-p0-plan.md)
- [P1 执行与验证状态](docs/phase-p1-plan.md)
- [P2 Agent 与能力探测状态](docs/phase-p2-plan.md)
- [P3 接入网关与标准化（占位）](docs/phase-p3-plan.md)
- [P4 检测引擎与状态分层](docs/phase-p4-plan.md)
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
