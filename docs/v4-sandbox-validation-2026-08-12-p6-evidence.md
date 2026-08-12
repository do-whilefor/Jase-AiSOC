# Jase-AiSOC V4.0 Linux 沙箱验证记录 — P6 Evidence 增量

日期：2026-08-12

## 环境事实

- Linux：Debian GNU/Linux 13 (trixie), x86_64。
- 当前沙箱未提供 `cargo`、`rustc`、`psql`、`docker`。
- 当前 shell DNS/外网下载不可用，无法补装项目锁定的 Rust 1.82.0 工具链或 PostgreSQL。
- 因此本记录严格区分“实际通过”和“环境阻断”；未执行的 Rust/PostgreSQL 动态门禁不标记为 PASS。

## 实际执行并通过

```text
make deploy-check
  Rust-first production gate: OK
  SQLx/PostgreSQL migration gate: OK (10 migrations, 22 tables)
  Central PostgreSQL repository gate: OK
  shell syntax: PASS
  release manager checksum/tamper/signature/rollback deployment tests: PASS

python3 scripts/check_v4_contract_schemas.py
  V4 Rust contract schemas: OK (23 authoritative DTOs checked)

python3 -m compileall -q src tests scripts migrations
  PASS

PYTHONPATH=src python3 -m pytest -q \
  tests/unit/test_incident_correlator.py \
  tests/unit/test_incident_repository.py \
  tests/unit/test_object_store.py
  20 passed
```

上述 Python 测试只作为旧实现的迁移/differential baseline，不代表 production runtime 依赖 Python。

## Fail-closed / 环境阻断

```text
bash scripts/check-cargo-lock.sh
  FAIL：当前 Cargo.lock 缺少 17 个 native workspace packages，且缺少 serde/serde_json/
  schemars/thiserror/tracing/chrono/uuid/tokio/sqlx 等 pinned workspace dependency。

cargo --version
cargo fmt --all -- --check
  cargo: command not found
```

因此以下门禁尚未执行：

- `cargo fmt --all -- --check`
- `cargo check --locked --workspace`
- `cargo clippy --locked --workspace --all-targets`
- `cargo test --locked --workspace`
- `cargo build --locked --workspace` / release binary build
- SQLx migration 对真实 PostgreSQL
- `aisoc-storage` central repository PostgreSQL integration test
- API / Agent / Ingest / Web Guard Rust 二进制启动与端到端联调

## 本轮 P6 动态测试源码已补但未执行

- authoritative raw-event evidence 创建、verified/chained custody 状态。
- Incident revision → authoritative evidence ID 绑定。
- legal-hold apply 与 exact replay 幂等。
- 跨 tenant legal-hold transition 拒绝。
- backdated legal-hold transition fail closed。
- legal-hold release 后当前投影恢复为 false。

下一次进入具备 Rust 1.82 + PostgreSQL 的 Linux builder 时，应先重建并提交正确 `Cargo.lock`，随后立即运行上述全部 `--locked` 和 PostgreSQL 动态门禁；若出现编译或 SQL 语义问题，P6 不得标记为阶段完成。
