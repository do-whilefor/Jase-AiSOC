# 仓库目录骨架登记

本目录骨架逐项对应《AI-SOC 项目开发与实施计划书》附录 A。创建目录不代表对应阶段或模块已经实现；各目录只有在 P0 → P14 的前置退出条件满足后，才按计划书顺序加入 Cargo Workspace 并承载生产代码。

## Rust crate 目录

| 目录 | 计划书职责 | 首次主要实施阶段 |
|---|---|---|
| `crates/aisoc-contracts` | 版本化契约、Schema、DTO | P0，当前代码实现目录 |
| `crates/aisoc-core` | ID、Hash、时间、安全原语 | P1 |
| `crates/aisoc-crypto` | 证书、签名、密钥封装 | P1 |
| `crates/aisoc-config` | TOML、环境变量、credential 配置 | P1 |
| `crates/aisoc-telemetry` | tracing、metrics、OpenTelemetry | P1 |
| `crates/aisoc-linux` | Linux capability、procfs、netlink、LSM | P1/P2 |
| `crates/aisoc-storage` | PostgreSQL、Object Store、Journal、NATS adapter | P1/P3 |
| `crates/aisoc-agent` | Collector、Queue、Spool、Transport、Updater、Runner | P2 |
| `crates/aisoc-ingest` | Auth、Idempotency、Raw Staging、DLQ | P3 |
| `crates/aisoc-normalize` | SecurityEvent、lineage、watermark | P3 |
| `crates/aisoc-detection` | Rule IR、window、sequence、state、replay | P4 |
| `crates/aisoc-incident` | correlation、revision、timeline、entity | P6 |
| `crates/aisoc-evidence` | EvidenceRef、custody、integrity | P6 |
| `crates/aisoc-ai` | Review、Provider、Claim、Verifier、Budget | P7/P8 |
| `crates/aisoc-malware` | 有界静态分析、scanner adapter | P9 |
| `crates/aisoc-trace` | evidence-bound graph、ATT&CK | P10 |
| `crates/aisoc-policy` | assurance、approval、action gate | P11 |
| `crates/aisoc-response` | typed action、revalidation、rollback | P11 |
| `crates/aisoc-api` | tenant scope、RBAC/ABAC、control API | P12 |
| `crates/aisoc-console` | Axum BFF、SSR host | P12 |
| `crates/aisoc-ui` | Leptos Rust/WASM UI | P12 |
| `crates/aisoc-web-guard` | proxy、canonicalization、Fast Path | P5 |
| `crates/aisoc-db` | migration、DB administration | P1 |
| `crates/aisocctl` | diagnose、replay、rule、schema、operations CLI | P1 起按阶段扩展 |

生产二进制 `aisoc-worker` 按计划书由 Normalize、Detection、Incident、Evidence、Trace 等 worker 模块组合，不另行发明计划书未列出的 crate 目录。

## 数据、验证与部署目录

- `schemas/`：Rust 权威契约导出的 JSON Schema；P0 Linux drift gate 前不伪造快照。
- `proto/`：仅在启用 Protobuf/gRPC 时使用。
- `rules/`：签名规则、IOC 与 rollout/rollback metadata。
- `migrations/`：SQLx migrations。
- `fixtures/`：契约、解析器和集成测试固定样本。
- `replay/`：可重放数据集与场景声明。
- `benches/`：性能基准源码。
- `fuzz/`：Parser、Archive、Schema、Rule 等 fuzz target。
- `deploy/systemd/`、`deploy/openrc/`：Linux 服务管理集成。
- `deploy/containers/`：容器化运行清单。
- `deploy/deb/`、`deploy/rpm/`、`deploy/tarball/`：Linux 发布制品定义。
- `docs/adr/`、`docs/threat-model/`、`docs/operations/`、`docs/compatibility/`：架构决策、安全模型、运维和兼容性材料。
- `tools/`：构建、测试和发布辅助，不承载生产安全业务逻辑。

## 当前边界

当前阶段仍为 P0。根 `Cargo.toml` 继续只包含 `aisoc-contracts`；空目录中的 `.gitkeep` 仅保证目录骨架可由 Git 保存，不是 crate、依赖、构建目标、运行时或阶段完成证据。`rust-toolchain.toml`、`Cargo.lock`、`deny.toml`、`.cargo/config.toml` 以及后续 crate 的 `Cargo.toml/src` 均按 P1 及其后续阶段实现，本轮不提前创建。
