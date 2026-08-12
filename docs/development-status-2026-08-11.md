# AI-SOC V4.0 开发与 CI 状态（2026-08-11）

依据：`AI-SOC_Rust_AI-Web-Guard_项目计划书_V4.0.docx`。

## 本轮推进范围

本轮优先关闭 P0/P1 工程门禁并继续推进 P2/P5，不把现有 Python 迁移层误当成最终架构。

### P2 Linux 平台层

- 新增 `crates/aisoc-linux`。
- 把发行版、init system、package manager、BTF、cgroup、LSM、journald/audit capability probe 从 `aisoc-core` 拆入独立平台 crate。
- `aisoc-core` 继续通过 `pub use aisoc_linux as linux` 提供兼容接口，避免当前 PyO3 bridge 与迁移期 Python 调用一次性断裂。
- 下一步 P2 应建立 `aisoc-agent`，迁移 procfs、journald/audit、Suricata/service log parser、本地队列和 mTLS transport。

### P5 Web Guard

- 请求 framing 从“TE/CL 基础检查”加强为：TE+CL 拒绝、重复 Content-Length 拒绝、不支持的 Transfer-Encoding 链拒绝、非法长度值拒绝。
- URI canonicalization 增加 malformed percent encoding 与 percent-decoded invalid UTF-8 拒绝。
- 文本 Body 在进入确定性检测前执行 canonicalization；声明为文本但不是有效 UTF-8 的请求直接拒绝。先验证完整文本 Body 的 UTF-8，再按字符边界截断采样，避免在多字节字符中间截断导致误报。正文允许普通字面量 `%`，但仍解码其中合法 `%xx` 序列，避免用一个畸形 `%` 阻断恶意编码解码；URI 则继续严格拒绝 malformed percent encoding。
- 新增 XXE entity 与 Java serialized object marker 的确定性规则。
- 新增 `AiReviewBudget`，用原子计数保证 `AISOC_WEB_GUARD_AI_MAX_RATIO` 不再只是未使用配置；预算统计覆盖全部请求，只对灰区候选发放 AI review 名额。
- `AISOC_WEB_GUARD_MAX_BODY_SAMPLE` 的硬上限收紧到 64 KiB，与 `WebRequestEnvelope.body_sample` 契约一致，避免运维配置把运行时事件推到 Schema 边界之外。
- 仍未接入真实 ModelProvider；`AISOC_WEB_GUARD_AI_ENABLED` 默认改为 `false`。显式启用后，被预算选中的灰区请求仅记录结构化日志并 fail-to-monitor，不允许模型缺失破坏 fast path。
- 新增 `/readyz`，健康/就绪端点限制为 GET/HEAD，并补充 SIGTERM 优雅退出。
- systemd unit 增加 no-new-privileges、private tmp/devices、kernel/control-group/proc/namespace 限制、空 capability bounding set、严格 umask 等 sandbox 配置；安全事件日志 target 也加入默认 `RUST_LOG`，避免结构化安全决策被过滤。
- Rust-only 容器继续使用 non-root UID 10001，并声明 SIGTERM stop signal。

## CI/CD 排查与修复

### 已定位的失败类别

当前主分支最近一次已查看的 CI 失败点包括：

1. Python 3.12 `ruff format --check`。
2. Python 3.13 `ruff format --check`。
3. Rust workspace 质量门禁。
4. PostgreSQL integration。
5. 旧版 JavaScript Actions 运行时弃用警告。

### 本轮工作流改造

- checkout 升级到 `actions/checkout` v7.0.1 固定 SHA，并关闭 `persist-credentials`。
- `astral-sh/setup-uv` 升级到 v9.0.0 固定 SHA，CI uv 固定为 0.12.3。
- `actions/upload-artifact` 升级到 v7.0.1 固定 SHA。
- CodeQL 升级到 v4.37.6 固定 SHA，并把矩阵扩展为 Python + Rust；Rust 使用 `build-mode: none` 与固定 Rust 1.82 toolchain。
- CI 增加 concurrency cancellation 与 job timeout，避免陈旧提交继续占用 runner。
- Python 格式检查增加 `--diff`，lint 使用 GitHub annotation 输出，mypy 显示错误码。
- Dependabot 增加 Cargo ecosystem。
- Rust 门禁统一为：`cargo fmt --all --check`、`cargo check --locked --workspace --all-targets --all-features`、`cargo clippy --locked ... -D warnings`、`cargo test --locked --workspace`、schema export、PyO3 bridge build/test、`cargo audit`。
- 当前 `Cargo.lock` 已知落后于新增 workspace；CI 在本迁移批次中会先 `cargo generate-lockfile`，随后所有可锁定命令使用 `--locked`。如果生成后发生变化，CI 会发出 warning 并上传生成后的 `Cargo.lock`。最终仍必须把稳定锁文件提交到仓库，才能关闭 P1 reproducibility 门禁。
- `cargo-audit` 暂固定 0.21.2：该版本支持 Rust 1.81+；0.22.2 已要求 Rust 1.88，与项目 Rust 1.82 MSRV 冲突。

### Rust 契约门禁

- `EvidenceRef`、`RuleHit`、`ModelAssessment`、`WebRequestEnvelope`、`WebSecurityEvent` 增加 `#[serde(deny_unknown_fields)]`，Rust 反序列化不再静默接受 Schema 禁止的未知字段。
- `ModelAssessment` 增加 evidence/attack-type/target/reason 数量边界校验，`EvidenceRef` 增加小写 64 位 SHA-256 约束。
- 新增 `scripts/check_v4_contract_schemas.py`：离线比较 Rust struct 字段、schema version、顶层 closed-object 语义及关键长度/风险边界，避免 CI 只把 Rust 导出结果写到 `/tmp` 却没有检查仓库内版本化 Schema 漂移。
- Makefile 的 `rust-lock-check` 改为只读 `cargo metadata --locked`；`rust-resolve` 仅保留为显式迁移恢复动作，常规 `rust-ci` 不再静默重写 `Cargo.lock`。

### PostgreSQL/mTLS 回归处理

数据库 service 仍使用映射到 runner 的 `127.0.0.1:5432`。mTLS hostname negative test 不再通过连接 `127.0.0.2` 间接触发失败，而是连接实际监听的 `127.0.0.1`，显式传入错误 `server_hostname=127.0.0.2`，直接断言 `ssl.SSLCertVerificationError`。这样验证的是 TLS hostname verification 本身，避免把 loopback routing/httpx 异常封装差异混入测试结果。

## 本地验证状态

当前执行环境可用 Python 3.13，但没有 Cargo/Rust toolchain，也无法从外网下载 Rust/Ruff 二进制。因此本轮不能把 Rust 编译结果或 Ruff 全仓格式结果伪装成已通过。

已在当前环境实际完成：

```text
python3 -m compileall -q src tests migrations scripts
# exit 0

PYTHONPATH=src python3 -m pytest \
  tests/unit/test_agent_identity.py tests/unit/test_rust_core.py -q
# 40 passed

make help
make -n rust-ci
# 均 exit 0；Makefile 目标/依赖关系可解析

# PyYAML 解析
.github/workflows/ci.yml
.github/workflows/codeql.yml
.github/dependabot.yml
# 三份 YAML 均解析成功

# 其余离线结构门禁
# schemas/*.json 全部 JSON 解析成功
# Cargo.toml / rust-toolchain.toml / pyproject.toml TOML 解析成功
# scripts/ 与 deploy/ 下 shell 脚本 bash -n 通过
# git diff --check 通过
# Python src/tests/migrations/scripts 行长 >100 扫描为 0
# python3 scripts/check_v4_contract_schemas.py -> V4 Rust contract schemas: OK
# UV_PYTHON=3.13 uv lock --check --offline -> exit 0
```

静态复核 Rust 代码时还发现并修复了 `request.rs` 中重复 `let sample = sample?;` 导致的确定性编译错误；由于没有 Rust toolchain，仍必须以 Actions 的真实 `cargo check/clippy/test` 作为最终判定。

完整 `tests/unit` 已尝试执行，但当前容器在 collection 阶段因缺少锁定运行依赖 `structlog` 停止；`uv sync --locked --all-groups --offline --python 3.13` 又因本地缓存缺少 `aiohttp==3.14.3` 无法补齐。因此该结果属于沙箱依赖缺失，不记作代码测试通过或失败。

`systemd-analyze verify deploy/systemd/aisoc-web-guard.service` 能解析 unit；当前唯一报告项是本机不存在尚未安装的 `/opt/aisoc/bin/aisoc-web-guard`，因此不能在该沙箱完成安装后级别的 unit 验证。

未能在当前沙箱直接执行：

```text
uv run ruff format --check --diff .
uv run ruff check .
uv run mypy src tests migrations
cargo fmt --all --check
cargo check --locked --workspace --all-targets --all-features
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace
cargo audit --file Cargo.lock
```

这些命令已经固化到 CI/Makefile，提交后必须由 GitHub Actions 实际执行；其中任何一项失败都不应视为阶段完成。

## 未关闭门禁与下一顺序

1. 用具备 Rust registry 的环境生成并提交最终 `Cargo.lock`。
2. 根据 CI `ruff format --check --diff` 输出清理全部 Python 迁移层格式债务；不能通过取消格式门禁来“修复” Checks。
3. 运行 Rust fmt/check/clippy/test，修复本轮新增 `aisoc-linux` 与 Web Guard 代码的真实编译/lint 问题。
4. 继续 P2：建立 `aisoc-agent` 原生二进制及本地可靠队列/mTLS transport。
5. 继续 P5：ModelProvider、route budget、Ingest event、policy hot-reload、challenge/rate-limit、TLS/H2、smuggling differential tests、性能基线。
6. P3/P4 开始 `aisoc-ingest`、`aisoc-normalize`、`aisoc-detection` Rust 化，逐步缩小 Python 生产路径。
