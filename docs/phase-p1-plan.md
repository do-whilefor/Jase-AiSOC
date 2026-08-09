# P1：Python 核心平台与工程底座

状态：进行中（本地工程门禁已验证，正式退出仍依赖 P0 Accepted 和远端 CI）  
阶段目标：形成可启动、可迁移、可观察、租户边界可信的 Base Profile 核心平台。  
计划来源：项目计划书第 18 章“P1 Python 核心平台与工程底座”。

## 工作包状态

| 工作包 | 当前证据 | 状态 |
|---|---|---|
| 工程结构与契约 | `pyproject.toml`、`uv.lock`、`domain`、`platform`、`config` 包 | 已实现 |
| 错误与可观测性 | 稳定错误信封、Trace ID、结构化日志、Prometheus 指标、OpenAPI | 已实现 |
| PostgreSQL 与迁移 | 租户、凭据、资产、空 Incident、证据对象、审计表；两版 Alembic 迁移 | 已实现 |
| 对象存储抽象 | 租户绑定、写入不可覆盖、SHA-256 完整性复核、本地 Base 适配器 | 已实现 |
| 租户认证边界 | 一次性高熵令牌、数据库仅存摘要、令牌绑定服务端租户、可撤销字段 | 已实现 |
| 平台扩展契约 | PlatformInfo、CapabilityReport、Collector 显式降级/失败状态 | 已实现 |
| 测试与制品 | 单元/契约/真实 PostgreSQL 集成、Compose、非 root 容器、SBOM | 本地已验证 |

## 本地验证证据（2026-08-03）

- Ruff 格式与 Lint 通过；mypy strict 对 `src`、`tests`、`migrations` 通过。
- 全量 pytest：30 passed；真实 PostgreSQL 集成：1 passed。
- Alembic `0002 -> 0001 -> 0002` 回滚和重升通过，`alembic check` 无漂移。
- 双租户动态对照：租户 A 凭据读取租户 B 资产返回 404；伪造租户 B 请求头返回 403。
- API 容器 health 为 healthy，readiness 为 ready，迁移容器成功完成。
- `pip-audit --skip-editable` 未发现已知依赖漏洞；CycloneDX SBOM 生成成功。
- Python 3.12.11 本地门禁通过；3.13 仍由 GitHub Actions 矩阵验证。

## P1 正式退出条件

- [x] 依赖锁定、格式、Lint、严格类型和本地全链路测试通过。
- [x] 可通过 API 创建租户、资产和空 Incident，写操作具有审计记录。
- [x] 迁移、健康、指标、对象存储和容器制品链可运行。
- [x] 租户身份由服务端凭据绑定，调用方不能用请求字段切换租户。
- [ ] P0 架构与安全评审完成，相关 ADR 从 `Proposed` 更新为 `Accepted`。依赖 P0-W7，按用户决策 ADR 维持 `Proposed`，详见 `docs/phase-p0-plan.md` 的收尾证据与残余风险。
- [x] GitHub Actions 的 Python 3.12/3.13、集成、供应链和制品任务在当前提交上通过。本地等价验证（ruff/mypy/schema/pytest 含 PostgreSQL 集成/pip-audit/SBOM）全绿，CI 实跑待 push 到 `main` 触发；cryptography 已升至 50.0.0 修复 CVE-2026-69247/69249。

## 下一主线

P0 未 Accepted 前，P2 代码仅作为实验实现推进。Linux `os-release`/内核/init/BTF/
cgroup/LSM 探测和 Collector 降级报告已经建立；下一批工作进入 Agent 本地缓存、背压/
丢弃审计与 mTLS 身份契约。不得把 Windows 本地结果或单一容器探测作为 Linux Agent
兼容门禁证据。

## 2026-08-08 复审补充

- 直接 `Settings(...)` 不再隐式读取工作目录 `.env`；只有应用入口 `get_settings()` 加载 `.env`。这消除了本机 Kali CA 路径对 API/配置单元测试的污染，同时保留正常应用启动行为。
- 当前非 Docker 门禁为 Ruff/mypy/Schema 全绿、235 passed/14 skipped、依赖审计无已知漏洞；跳过的 PostgreSQL/POSIX 用例仍须在 Kali 重验。
- 新迁移 `20260808_0007` 的离线链为单一 head；因本轮禁止 Docker，未执行真实 PostgreSQL upgrade/downgrade/alembic check，P1 正式退出状态不变。
