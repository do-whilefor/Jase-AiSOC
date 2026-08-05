# P0：架构与需求冻结执行计划

状态：进行中  
阶段目标：冻结可进入 P1 的功能边界、信任边界、核心契约、部署基线和工程门禁。  
退出条件：关键接口与数据边界评审通过，且无未决阻塞性架构问题。

## 工作包与完成标准

| 工作包 | 产物 | 当前状态 | 完成标准 |
|---|---|---|---|
| P0-W1 范围与可行性 | `feasibility.md`、架构基线 | 已起草 | MVP/非目标/降级边界和条件式 Go 结论明确。 |
| P0-W2 信任与数据 | 威胁模型、数据分类 | 已起草 | 每个信任边界有控制、验证方法和责任组件。 |
| P0-W3 核心契约 | Security Event Schema v0.1、版本策略 | 已起草 | 正/反例契约测试通过；破坏性变更策略明确。 |
| P0-W4 部署与兼容 | 部署 ADR、兼容矩阵 | 已起草 | Base/Stream 边界、组件启用条件和 Linux 验证矩阵明确。 |
| P0-W5 工程治理 | `pyproject.toml`、锁文件、CI、SBOM/依赖审计 | 已完成（本地；CI 待 push 实跑） | 锁定安装、格式、Lint、类型、测试、依赖审计和 SBOM 构建通过。 |
| P0-W6 验收规划 | 里程碑、测试计划与追踪表 | 已完成 | P1-P12 的前置、证据和 Go/No-Go 可追踪。 |
| P0-W7 架构评审 | 评审记录与 ADR 状态 | 待评审（ADR 维持 Proposed） | 项目负责人、架构、安全、Agent/数据负责人接受，或记录正式风险接受。 |

## 执行顺序

1. 评审 ADR-0001 至 ADR-0003，确认部署剖面、契约和 AI/响应边界。
2. 用代表事件验证 Schema v0.1；补充 Agent 批次和 ACK 契约后再进入 P2/P3 实现。
3. 在 Linux CI 上建立 Python 3.12/3.13 质量门禁、依赖审计和 CycloneDX SBOM。
4. 配置 PostgreSQL 集成环境，为 P1 迁移、健康检查和基础表实现准备测试夹具。
5. 召开 P0 退出评审，关闭或接受所有阻塞项，再将 ADR 状态从 `Proposed` 改为 `Accepted`。

## P0 评审清单

- [ ] MVP 必须能力、非目标和 P1-P7 边界已被产品/安全负责人接受。
- [ ] `tenant_id` 来源、Agent 身份绑定和证据读取的二次授权已确认。
- [ ] 事件时间、接收时间、`boot_id`、`sequence`、幂等键和迟到修订语义已确认。
- [ ] 原始证据不可覆盖、完整性哈希和生命周期策略已确认。
- [ ] 外部模型数据出域策略与模型完全不可用的降级路径已确认。
- [ ] R0-R3 权限、审批、动作预算、目标重验证和回滚边界已确认。
- [ ] Base 与 Stream 部署剖面及升级触发条件已确认。
- [ ] Linux 发行版/内核测试环境的负责人和可用方式已确定。
- [ ] CI、锁文件、依赖审计、SBOM 和制品签名路线已确认。
- [ ] P1 验收所需 PostgreSQL/Docker 或等效 Linux 集成环境已就绪。

## 当前阻塞项

这些项目不阻止 P0 文档与契约工作，但会阻止阶段退出或 P1 集成验收：

1. 尚未完成人工架构/安全评审；ADR 当前只能标记为 `Proposed`。
2. Docker Desktop 的 Linux Engine 已可用，可执行 PostgreSQL/NATS/MinIO 容器集成；当前宿主仍不是 Linux，需要 Linux CI/VM 执行 Agent、systemd、auditd 和 eBPF 门禁。
3. 仓库许可证、发布签名身份、目标制品仓库和密钥托管方案尚未决策；它们最迟在首个发布制品前冻结。

## P0 工程治理收尾证据（2026-08-04）

按用户决策，ADR 维持 `Proposed`、P0/P1 以实验实现推进，但工程治理门禁已在当前提交本地验证全绿：

- `uv sync --locked --all-groups` 通过（cryptography 升至 50.0.0 修 CVE-2026-69247/69249，pip-audit 无已知漏洞）。
- `ruff format --check .`（81 files）、`ruff check .`、`mypy src tests migrations`、`blue-team-export-schemas --check` 全过。
- `alembic upgrade head` 至 `20260804_0004`，`alembic check` 无漂移。
- `pytest --cov`：126 passed、8 skipped（skip 全为 POSIX/符号链接/Windows 进程语义，需 Linux CI；3 个 PostgreSQL 集成用例在 Docker Linux Engine 下已实跑），覆盖率 80%。
- CycloneDX SBOM 生成至 `reports/sbom.cdx.json`（CI 制品，未提交）。

残余风险（评审前不得视作已 Accepted）：

1. P0-W7 人工架构/安全评审未排期 → ADR-0001~0003 维持 `Proposed`，部署剖面、事件/证据契约、AI/响应边界未正式确认。
2. Linux VM/CI 缺失：Docker Linux Engine 覆盖 PostgreSQL/NATS/MinIO 容器集成，但不覆盖 Agent/systemd/auditd/eBPF/全盘克隆等宿主级门禁；需真 Linux VM 矩阵。
3. 仓库许可证、发布签名身份、目标制品仓库、密钥托管未冻结（最迟首个发布制品前）。

后续推进以容器级闭环作为 P2 收尾边界，VM 级验证标记 Experimental。
