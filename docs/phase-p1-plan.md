# P1：Rust 平台与工程治理

状态：进行中。V4 Rust-first 工程骨架、原生 SQLx migration plane 与部署门禁已建立；正式退出仍被 committed `Cargo.lock`、真实 Rust 1.82 构建以及 central repository cutover 阻塞。

计划书硬验收：**Cargo CI、SQLx migration、API health、SBOM、签名和错误/日志规范通过。**

## 当前工作包状态

| 工作包 | 当前证据 | 状态 |
|---|---|---|
| Cargo Workspace | 18 个 native production crate + migration-only `aisoc-python`；生产 `default-members` 不含 Python bridge | 部分完成：Workspace 已收敛，锁文件陈旧 |
| Rust CI | GitHub Actions 固定 Rust 1.82，包含 fmt/check/clippy/test/schema/audit | 部分完成：当前提交必须在修复 `Cargo.lock` 后真实跑绿 |
| SQLx/PostgreSQL | `aisoc-storage` 新增 SQLx 0.8.3、3 个 embedded migration、`aisoc-db migrate|health` | 已实现首版，真实 PostgreSQL execution 待 Rust 环境验证 |
| API health/readiness | Rust Axum API 的 production 启动要求 PostgreSQL；`/readyz` 同时检查 DB 与 Ingest | 已实现首版 |
| Rust-first 部署 | production Docker、P1/P2 Compose、Linux installer、release bundle 均走 Rust；`aisoc-db` 纳入 release | 已实现首版 |
| Release integrity | `manifest.sha256`、detached signature、install/upgrade/rollback 测试 | 本地部署回归已通过 |
| 错误/日志规范 | 原生 crate 使用 typed error、结构化 tracing；生产入口禁止 Python fallback | 部分完成：跨 crate error taxonomy 仍需统一 |
| SBOM/供应链 | Python SBOM 保留；Rust job 新增 pinned `cargo-cyclonedx` 生成/上传 Workspace CycloneDX SBOM，并保留 cargo-audit | 已实现 CI 配置，待修复锁文件后远端实跑留证 |
| Central storage cutover | schema 已覆盖 tenant/host/agent/audit、event pipeline、detection/incident/evidence/claim 基础事实 | 未完成：运行态 Ingest/Detection/Incident 仍有本地 append-only journal |

## 本轮新增的原生数据库链路

1. `crates/aisoc-storage/src/postgres.rs`：PostgreSQL pool、healthcheck、embedded SQLx migrator。
2. `crates/aisoc-storage/src/bin/aisoc-db.rs`：独立 `migrate` / `health` Rust binary，不依赖 Python/Alembic。
3. `crates/aisoc-storage/migrations/202608110001_*` ～ `003_*`：建立 15 张 V4 基础表，使用 tenant-qualified 外键约束跨租户关系。
4. `scripts/check-sqlx-migrations.py`：无需 Cargo 即可执行的 fail-closed schema 结构门禁。
5. P1/P2 Compose：PostgreSQL healthy 后由 `aisoc-db migrate` 完成 schema，再允许 Ingest 启动。
6. Linux installer：production control role 必须提供 `AISOC_DATABASE_URL`，启动 systemd 服务前运行 release 中的 `aisoc-db migrate`。
7. Rust API：production 缺少数据库 URL 时拒绝启动；readiness 把 PostgreSQL health 纳入依赖状态。
8. CI：Rust job 新增 PostgreSQL service，并计划在 `cargo test` 后实际执行 migration + health。

## 当前实际验证（2026-08-11）

已在当前 Linux 沙箱执行并通过：

- `python3 scripts/check-sqlx-migrations.py`：PASS，3 migrations / 15 tables。
- `./scripts/check-rust-first.sh`：PASS。
- `python3 scripts/check_v4_contract_schemas.py`：PASS，23 个 authoritative DTO。
- `bash tests/deploy/test_release_manager.sh`：PASS，release bundle 已包含 `aisoc-db`，覆盖 install/upgrade/rollback/signature/tamper gate。
- shell syntax：PASS。
- CI / P1 / P2 YAML parse：PASS。
- legacy Settings PostgreSQL DSN compatibility：24 tests PASS。

明确未通过/被阻塞：

- `./scripts/check-cargo-lock.sh`：FAIL，committed `Cargo.lock` 缺少 17 个 native workspace package。
- `cargo fmt/check/clippy/test/build --locked`：BLOCKED，当前沙箱不存在 Cargo/Rust 1.82，且外网不可达，不能安全生成新锁文件或下载 crates。
- SQLx migrations 对真实 PostgreSQL 的执行：BLOCKED，同一 Rust toolchain/lock blocker。

## P1 正式退出条件

- [x] Rust-first production entrypoint 不依赖 Python runtime。
- [x] 原生 SQLx migration plane 与独立 migration binary 已进入源码、镜像、release、Compose、installer、CI。
- [x] API production 配置把 PostgreSQL 设为硬依赖并纳入 readiness。
- [x] release checksum/signature/install/upgrade/rollback 本地回归通过。
- [ ] 使用 Rust 1.82 重新生成并审查 `Cargo.lock`，提交后所有 `--locked` 命令可复现。
- [ ] `cargo fmt --all --check`、`cargo check --workspace --all-targets --all-features`、`cargo clippy -D warnings`、`cargo test --workspace`、`cargo build --release` 全绿。
- [ ] SQLx migration 在真实 PostgreSQL 上完成 fresh install、重复 migrate、upgrade compatibility 与失败回滚/恢复测试。
- [ ] Ingest/Detection/Incident/Evidence 的 central repository 从本地 journal 切换到 PostgreSQL/Object Store，避免“只迁 schema、不迁生产数据路径”。
- [ ] 当前提交的 Rust SBOM、dependency audit、签名制品和远端 CI 全部留存证据。

## 下一主线

P1 下一增量不再扩展旧 Python storage。优先在有 Rust registry 的可信 Linux runner 修复锁文件并跑真实编译；随后以 `aisoc-storage` 为边界逐步迁移 central repositories，先覆盖 Agent inventory、Ingest batch/raw index、normalized event、Detection/Incident/Evidence，再进入 P3 JetStream/Object Store 生产 profile。
