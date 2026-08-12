# Rust workspace

V4.0 的目标是让生产关键路径以 Rust 为唯一主语言。当前 workspace 从原来的 `aisoc-core + aisoc-python` 过渡形态开始拆分，第一批新增以下原生 Rust 边界：

- `aisoc-core`：安全确定性基础能力与迁移期兼容重导出。
- `aisoc-linux`：Linux 能力探测、发行版/Init/Cgroup/LSM/Collector 能力发现；P2 平台兼容层起点。
- `aisoc-contracts`：Web/SOC 共用的版本化 Rust 契约与 Schema 导出入口。
- `aisoc-web-guard`：独立 Rust Web Guard 数据面，当前实现请求规范化、确定性 Fast Path、策略判定、敏感字段最小化和反向代理基础链路。
- `aisoc-python`：仅作为迁移期 PyO3 兼容桥保留，不属于 V4.0 最终生产主路径。

根 `Cargo.toml` 的 `default-members` 仅包含原生 Rust 路径；后续会按计划书继续加入 `aisoc-agent`、`aisoc-ingest`、`aisoc-normalize`、`aisoc-detection`、`aisoc-incident`、`aisoc-evidence`、`aisoc-ai`、`aisoc-malware`、`aisoc-trace`、`aisoc-policy`、`aisoc-response`、`aisoc-storage` 与 `aisoc-api`。

基础验证：

```bash
cargo fmt --check --all
cargo check --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo run -p aisoc-contracts --bin export_schemas -- schemas
```

迁移期 Python bridge：

```bash
VIRTUAL_ENV="$(pwd)/.venv" maturin develop --manifest-path crates/aisoc-python/Cargo.toml
```
