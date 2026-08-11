# Rust workspace

AI-SOC 的 Rust 层分为两个 crate：

- `aisoc-core`：不依赖 Python 的 Linux/安全核心，可独立测试和复用。
- `aisoc-python`：PyO3 bridge，生成 Python 模块 `aisoc_rust`。

当前迁移范围是 hashing、Linux capability probe、静态文件基础分析和确定性 IOC matcher。FastAPI、SQLAlchemy/Alembic 与 LLM Provider 编排暂留 Python，因为这些路径的主要约束是生态和迭代速度，而不是 CPU/内存热点。

验证：

```bash
cargo fmt --check --all
cargo check --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
```

Python bridge：

```bash
VIRTUAL_ENV="$(pwd)/.venv" maturin develop --manifest-path crates/aisoc-python/Cargo.toml
```
