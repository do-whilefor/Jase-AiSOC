# AI-SOC

AI-SOC 是面向通用 Linux 的安全分析、Incident 聚合、证据溯源、恶意文件分析和受控响应平台。项目以 `AI安全分析与溯源_项目计划书_Python.docx` 为产品方向依据，在现有实现上采用 **Rust Core + Python AI/Service Layer**：确定性、安全敏感和性能敏感能力优先进入 Rust；LLM、Prompt、Provider 编排和服务层继续使用 Python。

## 设计边界

- Linux 是唯一目标运行平台，不依赖特定发行版或预装安全工具。
- 优先使用 `/proc`、`/sys`、`/etc`、POSIX/Linux API 与能力探测；缺失 journald、auditd、eBPF、Suricata、Falco 时按能力降级。
- 原始日志不逐条交给 LLM。Normalize、Detection、Incident 归并和证据裁剪先由确定性链路完成，AI 只审阅受限的 Incident EvidencePackage。
- AI 结论不能覆盖原始证据；Claim、ToolResult、模型输出和响应动作均受结构化契约和审计约束。
- 响应执行默认关闭，并受租户、Host/Agent 绑定、RBAC、审批、目标重验证和固定 Adapter 限制。
- 生产路径不以 `todo!()`、固定成功返回或假扫描结果冒充已实现能力。

## 架构

```text
Linux Agent / external sensors
        │
        ▼
Ingest Gateway ──► Normalize / Enrichment ──► Detection
                                            │
                                            ▼
                                        Incident
                                            │
                    ┌───────────────────────┼───────────────────────┐
                    ▼                       ▼                       ▼
              Evidence / Trace       Malware Analysis          AI Review
                    │                       │                       │
                    └───────────────────────┴──────────────┬────────┘
                                                          ▼
                                                Policy / Response Gate
```

Rust Core 当前负责：

- SHA-256、HMAC-SHA256、常量时间比较与受限文件 Hash。
- Linux 发行版/init/cgroup/LSM/BTF/journald/auditd/eBPF/包管理器能力探测。
- 文件熵、可打印字符串和 ELF 头静态解析。
- IP/domain/SHA-256 IOC 精确匹配。

Python 继续负责：

- FastAPI、SQLAlchemy/Alembic、worker 编排和业务契约。
- AI/LLM Provider、Prompt、EvidencePackage、Verifier/Adjudicator。
- 当前尚未迁移的 Agent collector、规则编排和响应控制面。

PyO3 扩展模块为 `aisoc_rust`。Python 侧通过 `src/aisoc/_rustcore.py` 访问，并为开发、测试和诊断保留确定性的 Python fallback；常规 Linux 安装和运行容器默认要求 Rust bridge 存在，避免生产部署在不知情的情况下退回 Python。需要 Rust 才能提供的能力不会伪造结果。

## 目录

```text
.
├── crates/
│   ├── aisoc-core/          # 无 Python 依赖的 Rust 核心
│   └── aisoc-python/        # PyO3 bridge: aisoc_rust
├── src/aisoc/               # Python 服务层、AI 层和当前 Agent 编排
├── configs/                 # 预留：部署配置应外置，不提交 secret
├── deploy/
│   ├── linux/               # 通用 Linux 安装入口
│   ├── systemd/             # 可选 systemd units
│   └── compose/             # 集成/验证 profile
├── schemas/                 # 版本化事件/Agent schema
├── migrations/              # Alembic migrations
├── scripts/                 # enrollment、replay、artifact 工具
├── tests/                   # unit / integration / smoke / replay
├── docs/                    # 架构、阶段计划、部署和安全报告
├── console/                 # 运营控制台
├── Cargo.toml               # Cargo workspace
└── pyproject.toml
```

`configs/` 在部署时可以由环境管理系统提供；仓库不会生成真实证书、Agent 身份或 API Key。

## 当前阶段状态

| 阶段 | 当前状态 |
|---|---|
| P0-P1 | 核心契约、存储、API、迁移和工程治理主体已实现；人工架构评审仍需项目侧关闭。 |
| P2 | Agent、身份、队列、mTLS、auditd/journald/Suricata/service-log collector、能力探测已有实现；DEB/RPM、真实 VM 兼容矩阵和升级/回滚门禁未关闭。 |
| P3-P5 | base pipeline、Normalize、DLQ、检测、规则生命周期、主机行为链已有实现；stream profile、高 EPS 与真实多发行版采集门禁未关闭。 |
| P6-P10 | Incident、Evidence/Claim、AI Review、恶意文件分析、跨 Host Trace 已有非生产实现；真实 PostgreSQL/Provider/Scanner/双租户/动态隔离和攻击回放仍需验收。 |
| P11 | 响应契约、审批、租约、通知、规则治理和控制台主体已实现；多 Host Agent-side 执行、真实回滚和 HTTPS 运营门禁未关闭。 |
| P12 | 跨发行版发布、性能、安全动态测试、备份恢复和正式运维验收尚未完成。 |

本轮重构新增了固定摘要校验的本地 IOC feed 与确定性 `ioc.exact_match` 规则。IP、域名和 SHA-256 均使用精确匹配；域名可从 Suricata DNS/HTTP 事件进入 enrichment。IOC 命中仍受现有规则生命周期治理，不直接提升为 confirmed compromise。

## 本地开发

需要 Python 3.12+。完整依赖安装：

```bash
make dev-install
```

基础检查：

```bash
make lint
make typecheck
make test
```

Schema 一致性：

```bash
.venv/bin/aisoc-export-schemas --check
```

### Rust

需要 Rust stable、Cargo 与 Clippy：

```bash
make rust-check
make rust-test
```

构建 PyO3 bridge：

```bash
python3 -m venv .venv
.venv/bin/pip install -e . maturin==1.14.1
make rust-extension
.venv/bin/python -c 'import aisoc_rust; print(aisoc_rust.version())'
```

构建发布 wheel / 容器：

```bash
make rust-wheel
make container
```

`deploy/Dockerfile` 会验证并安装 `dist-rust/` 中的 Rust wheel；缺少 wheel 时镜像构建直接失败，而不是静默使用 Python fallback。CI 的 release job 会先生成 Rust wheel，再构建运行镜像，并同时上传 Python 与 Rust 制品。

CI 会执行 `cargo fmt --check --all`、`cargo check --workspace`、`cargo clippy --workspace --all-targets --all-features -- -D warnings`、`cargo test --workspace` 以及 Rust-enabled Python unit tests。

## 通用 Linux 部署

部署脚本不假设 apt、yum/dnf、systemd、auditd 或任何发行版预装工具：

```bash
export AISOC_DATABASE_URL='postgresql+asyncpg://aisoc:<password>@db.internal:5432/aisoc'
export AISOC_RUST_WHEEL=/secure/release/aisoc_python-0.1.0-cp312-abi3-linux_x86_64.whl
sudo -E bash deploy/linux/install.sh --role control --enable-services
```

也可以在目标机提供 Rust/Cargo 1.82+，让安装器用固定版本 maturin 从源码构建 bridge。只有开发或诊断场景才应显式使用 `--allow-python-core-fallback`。

Agent 必须使用已完成 enrollment 的私有配置，安装器不会生成假身份或假证书：

```bash
export AISOC_AGENT_CONFIG_SOURCE=/secure/path/agent.json
sudo -E bash deploy/linux/install.sh --role agent --enable-services
```

详细说明见 [docs/deploy-linux.md](docs/deploy-linux.md)。

## IOC feed

IOC feed 是启动时只读加载的本地、固定摘要数据源。配置必须成对出现：

```text
AISOC_DETECTION_IOC_FEED_PATH=/etc/aisoc/ioc/feed.json
AISOC_DETECTION_IOC_FEED_SHA256=<64 lowercase hex chars>
```

Feed 仅接受普通、非 symlink、非 group/world-writable 文件，并在 JSON 解析前校验 SHA-256。其用途是提供可复现的确定性匹配，不替代后续完整的受管威胁情报生命周期。

## 生产限制

当前 `Settings.auth_mode` 只有 `development`。当 `AISOC_ENVIRONMENT=production` 时配置会 fail closed，因此仓库目前不能宣称生产认证已完成。正式发布前还必须完成生产身份认证、跨发行版 VM 矩阵、真实 PostgreSQL/双租户验收、响应回滚、性能容量、备份恢复和安全动态测试。

本次重构明细与未关闭项见 [docs/refactor-2026-08-11.md](docs/refactor-2026-08-11.md)。

## 贡献与维护

```cmd
git add -A
git commit -m "Update project"
git push
```