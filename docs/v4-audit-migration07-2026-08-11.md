# AI-SOC Rust / AI-Web-Guard V4.0 全面检查与迁移整改报告

日期：2026-08-11  
基线：`AI-SOC_Rust_AI-Web-Guard_项目计划书_V4.0.docx`  
输入工程：`Jase-AiSOC_V4_Rust_Migration_06_p3_central_replay`

## 1. 结论摘要

本轮严格按 V4.0 的 P0–P14、Rust First、18 个原生 crate、统一安全事件契约、Linux 生产链路与验收门禁进行检查，并直接修复了 P4 Detection/replay、Web Guard 时间契约、阶段文档编号和 Rust-first workspace 门禁等问题。

- **V4.0 总体完成度：约 49%**。这是按 P0–P14 验收项的保守工程估算，不按代码行数计算。
- **正式生产入口 Rust First：当前门禁通过**。生产 Dockerfile、P1/P2 Compose、systemd 与 Make runtime target 未发现 Python 运行时依赖。
- **Rust 功能迁移/验收完成度：约 72%**。18 个 V4 原生 crate 均已存在，但若干模块仍是初始实现，最终规划的 8 个正式二进制仅有 4 个同名目标落地，且本沙箱无法实际编译 Rust。
- **严格 hard-gate 下 P0–P14 暂无一个阶段可以标记为完全 Accepted**。P0–P12 为不同程度“部分完成”，P13–P14 尚未形成计划书要求的真实环境验收闭环。
- **Python 未迁完**。`src/aisoc` 仍有 162 个 Python 文件、46,610 LOC；其主要用途是旧功能基线/迁移对照。另有 101 个 Python 测试、18 个历史 Alembic migration、6 个 Python 脚本。它们目前不是正式 Rust-first 生产入口，但不能据此宣称功能迁移完成。
- **Cargo.lock 是当前 P1 的真实发布阻塞项**：锁文件缺 17 个原生 workspace package 和 9 个 workspace 固定依赖；必须使用 Rust 1.82/Cargo 重新解析、生成并提交，不能手工伪造。
- **沙箱无 Rust 工具链**：`cargo/rustc/rustfmt/clippy` 均不存在，且外部包源不可用。因此 `cargo fmt/clippy/test/build` 均已实际尝试，但以 `cargo: command not found`（rc=127）结束；不能将其标记为通过。

## 2. 本轮直接完成的整改

1. **P4 Rust 原生 replay 骨架落地**
   - 为 9 组 replay 数据集生成 `canonical-events.jsonl`，直接使用规范化后的 `SecurityEvent` 作为 Rust Detection 输入。
   - manifest 增加 `canonical_events_sha256`，防止 replay fixture 静默漂移。
   - 新增 `crates/aisoc-detection/tests/replay.rs`，按 manifest 校验 category、attack state、最小/最大命中数量，并拒绝未声明类别。
   - `Makefile` 新增 `rust-replay`，并纳入 `rust-ci`。
   - `scripts/replay_detection.py` 明确降级为迁移期 differential baseline，不再作为 V4 Rust 权威验收入口。

2. **Detection Rust 功能补齐**
   - Web 注入统一输出 `web.attack.injection`，细分 rule id 为 SQLi/XSS/command injection。
   - 修复 `http.status` 为 JSON 数字时未被识别的问题，403/406/429 等现在可正确进入 `blocked`。
   - 降低 `javascript:` 的宽泛 XSS 误报，保留更具体信号。
   - 新增五条主机行为链规则：
     - `host.web_process.shell`
     - `host.download.execute`
     - `host.persistence.change`
     - `host.web_shell.outbound`
     - `host.lateral.scan`
   - 保留启动代次/PID、链路时间窗、私网横向扫描等语义，而不是逐行翻译 Python。

3. **Rust-first 架构门禁强化**
   - `scripts/check-rust-first.sh` 现在不仅禁止 `aisoc-python` 进入 default-members，还要求 default-members **精确等于 V4.0 的 18 个原生 crate**。
   - 生产 Dockerfile/Compose/systemd/Make runtime target Rust-only 检查继续通过。

4. **Web Guard 合同修复**
   - Web Guard 安全记录时间从自定义 `unix:` 字符串改为 RFC3339 UTC 纳秒格式，便于 Incident/Evidence/Trace 跨模块时间线统一。

5. **P0–P14 文档编号纠偏**
   - `phase-p5-plan.md` 重新对齐 V4.0 P5 Web Guard；旧主机运行时内容保留到 `p4-host-runtime-detection-annex.md`。
   - `phase-p11-plan.md` 重新对齐 V4.0 P11 Response；原 Response+Console 合并内容保留为 `p11-response-console-legacy-annex.md`。
   - `phase-p12-plan.md` 重新对齐 V4.0 P12 Console/Ops；原 Hardening 内容保留到 `p13-hardening-detail-annex.md`。
   - 未通过删除旧功能来“满足编号”。

6. **压缩包执行位问题修复**
   - 恢复 shebang shell/check/deploy 测试脚本执行位；此前的 `Permission denied` 属于打包权限损失，不是业务逻辑失败。

## 3. P0–P14 严格对照

| 阶段 | 估算 | 状态 | 当前实现与缺口 |
|---|---:|---|---|
| P0 架构/威胁/Schema/Workspace | 85% | 部分完成 | 18 个原生默认 crate 齐全、contracts/schema 较完整；物理 workspace 仍有第 19 个迁移桥 `aisoc-python`，最终二进制矩阵未闭环。 |
| P1 平台/治理/CI/DB | 62% | 部分完成 | Rust CI/SQLx/health/release/signing 门禁已有；`Cargo.lock` 严重陈旧，当前无法执行真实 Rust CI；SBOM/audit/全发布验证尚未闭环。 |
| P2 Rust Linux Agent | 68% | 部分完成 | Agent/Linux crate、身份/mTLS/队列/采集与部署框架存在；缺真实 Kali/Ubuntu/Debian/RHEL 系兼容矩阵、升级/降级/故障注入完整验收。 |
| P3 Ingest/Event Pipeline | 58% | 部分完成 | canonical schema、normalize、SQLx central store、DLQ/replay/idempotency 有实现；NATS/JetStream/ObjectStore、乱序/背压/真实全链路压测未闭环。 |
| P4 Detection | 72% | 部分完成 | Web/SSH/scan/host-chain Rust 规则与 canonical replay test 已补；Rust replay 尚未被实际编译执行，真实误报/漏报基准和状态层级还需验收。 |
| P5 Web Guard | 70% | 部分完成 | reverse proxy、canonicalization、Fast Path、policy mode、AI budget/circuit 基础存在；Web Guard → Ingest 的认证事件提交、route policy、完整 challenge/rate-limit/TLS/H2/smuggling/perf 验收不完整。 |
| P6 Incident/Evidence | 50% | 部分完成 | Rust incident/evidence/storage 基础模型存在；revision、late-arrival、跨事件证据链、租户隔离和完整生命周期验收不足。 |
| P7 AI Review | 62% | 部分完成 | Rust provider/review/budget/fallback 基础存在；真实 provider、tool gateway、超时/熔断/成本/可追溯输出验收未闭环。 |
| P8 Claim Verification | 48% | 部分完成 | claim/verification 数据结构和基础逻辑存在；blind verifier、adjudicator、人审升级、证据绑定完整流程不足。 |
| P9 Malware | 32% | 部分完成 | Rust malware crate 已有基础实现；YARA-X/ClamAV/隔离/信誉/沙箱/样本治理未形成完整 Rust 生产链。 |
| P10 Attack Trace | 32% | 部分完成 | Rust trace 图模型初步存在；跨主机入口、攻击路径、scope、evidence-bound 映射与真实攻击回放不足。 |
| P11 Response | 48% | 部分完成 | policy/response runner 和本地 adapter 基础存在；真实可回滚动作、远端 runner、审批/证据/故障恢复完整验收不足。 |
| P12 Console/Ops | 35% | 部分完成 | API/console 基础目标存在；运营真值、完整指标/审计/RBAC/系统控制/HTTPS 运维面未闭环。 |
| P13 Hardening | 10% | 未完成 | 缺计划书要求的 distro matrix、fuzz、DAST、性能容量、备份恢复、RPO/RTO 等系统化验收。 |
| P14 Pilot / Go-No-Go | 5% | 未完成 | 尚无真实业务 shadow→canary→block、持续 pilot 数据、Go/No-Go 会议与运维交付闭环。 |

**严格阶段结论：已完全 Accepted 的阶段 = 0；P0–P12 部分完成；P13–P14 未完成。** 这里使用计划书 hard-gate 口径，而不是“代码存在即完成”。

## 4. Cargo Workspace / crate / 依赖检查

### 4.1 Workspace

- V4.0 要求的 18 个原生 crate 均存在并位于 `default-members`。
- `default-members` 精确数量：18。
- 物理 `members`：19；额外成员为 `crates/aisoc-python`，属于 PyO3 迁移桥。
- `aisoc-python` 未进入默认生产构建，但最终 V4 架构收口时应移出生产 workspace 或完全退役。
- 18 个原生 crate 根均声明 `#![forbid(unsafe_code)]`。
- Rust 原生代码：55 个 `.rs`，约 20,003 LOC。
- 依赖静态检查未发现内部 crate 循环；主要依赖关系符合分层，但 `aisoc-core -> aisoc-contracts + aisoc-linux` 使 core 层并非完全最底层，后续可继续收敛职责。

### 4.2 当前内部依赖

- `aisoc-agent -> contracts, core, linux`
- `aisoc-ingest -> contracts, core, detection, incident, normalize, storage`
- `aisoc-detection -> contracts, core`
- `aisoc-evidence -> core, storage`
- `aisoc-ai -> contracts`
- `aisoc-malware -> contracts, core`
- `aisoc-response -> contracts, core, storage`
- `aisoc-api -> contracts, core, storage`
- `aisoc-web-guard -> ai, contracts, core`
- `incident/trace/policy -> contracts`
- `normalize -> contracts, core`
- `storage -> core`
- `console/contracts/linux` 当前无内部依赖。

### 4.3 Linux 兼容性

- `core/linux/agent/web-guard` 存在明确 Linux 编译/平台约束；其余服务 crate 主要依赖部署环境而非显式 compile guard。
- 当前沙箱为 Linux，可执行 shell/deployment 静态与 fake release 测试。
- 尚不能替代计划书要求的 Kali、Debian/Ubuntu、RHEL 系等真实 distro matrix。

## 5. 最终二进制矩阵偏差

V4.0 最终期望：

- `aisoc-agent`
- `aisoc-web-guard`
- `aisoc-ingest`
- `aisoc-worker`
- `aisoc-ai`
- `aisoc-api`
- `aisoc-response`
- `aisocctl`

当前同名目标已存在 4/8：`aisoc-agent`、`aisoc-web-guard`、`aisoc-ingest`、`aisoc-api`。

当前另有 `aisoc-console`、`aisoc-db`，以及开发用 schema export bin。**缺失的 `aisoc-worker`、`aisoc-ai`、`aisoc-response`、`aisocctl` 不应通过创建空壳二进制来“补数量”**，而应在相应 crate 的核心流程可独立运行、可观测、可部署、可测试后再落地。

当前 release/Docker 打包集合也仍以 `agent/ingest/api/console/web-guard/db` 为主，尚未达到最终 V4 二进制交付矩阵。

## 6. Python 遗留及用途

### 6.1 数量

- `src/aisoc`: **162 文件 / 46,610 LOC**
- `tests`: **101 文件 / 23,723 LOC**
- `migrations`: **18 文件 / 3,808 LOC**
- `scripts`: **6 文件 / 942 LOC**
- 本次盘点合计：**287 个 Python 文件 / 75,083 LOC**

完整逐文件清单见：`docs/python-legacy-inventory-2026-08-11.txt`。

### 6.2 主要功能映射

| Python 遗留 | Rust 目标 | 当前判断 |
|---|---|---|
| `agent_core` | `aisoc-agent` + `aisoc-linux` | 旧实现/验收基线仍大量保留；Rust 已承担正式入口但功能验收未完全等价。 |
| `ingest_gateway` + `normalize` | `aisoc-ingest` + `aisoc-normalize` | Rust 主链已有，broker/object store/完整异常流仍需推进。 |
| `detection_engine` | `aisoc-detection` | 本轮重点推进；Python replay 降级为 differential baseline。 |
| `incident_engine` | `aisoc-incident` + `aisoc-evidence` | Rust 基础实现存在，复杂生命周期仍需迁移。 |
| `ai_review` | `aisoc-ai` | Rust provider/orchestration 基础存在，尚无最终 `aisoc-ai` 服务二进制。 |
| `malware_engine` | `aisoc-malware` | Rust 覆盖不足。 |
| `trace_engine` | `aisoc-trace` | Rust 覆盖不足。 |
| `response_engine` | `aisoc-policy` + `aisoc-response` | Rust runner 基础存在，尚无最终 `aisoc-response` 服务二进制。 |
| `api_server` | `aisoc-api` + `aisoc-console` | Rust API/Console 已起步，但功能/运营面尚未完全迁移。 |
| `storage` | `aisoc-storage` | SQLx 中心存储已推进，但旧 Python repository 仍作为迁移基线保留。 |
| `domain` | `aisoc-contracts` + `aisoc-core` | Rust DTO 已成为 V4 重点契约，仍需继续消除双定义。 |

### 6.3 Python scripts

- `bootstrap_agent_enrollment.py`、`build_agent_artifact.py`：迁移期运维/构建工具；最终应由 `aisocctl`/原生 release tooling 替换。
- `check-central-repository.py`、`check-sqlx-migrations.py`、`check_v4_contract_schemas.py`：开发/CI 检查工具，不属于生产业务运行时。
- `replay_detection.py`：迁移期 differential replay；本轮已明确 Rust integration test 为最终权威方向。
- 18 个 Python Alembic migration：历史迁移资产；当前生产 migration 路径已切换到 SQLx gate。

因此，**“生产入口不依赖 Python”当前成立，但“Python 核心功能已全部迁完”不成立。**

## 7. 实际测试结果

### 7.1 已通过

| 检查 | 结果 |
|---|---|
| `./scripts/check-rust-first.sh` | PASS；18 个 default native crates 精确门禁 + 生产入口无 Python runtime |
| `make deploy-check` | PASS |
| SQLx migration gate | PASS；5 migrations / 15 tables |
| Central PostgreSQL repository gate | PASS |
| release manager fake package / activate / v1→v2 / rollback / signed | PASS |
| `python3 scripts/check_v4_contract_schemas.py` | PASS；23 个 authoritative Rust DTO schema |
| 9 组 Python differential replay | PASS |
| 9 组 canonical replay fixture SHA + JSON Schema | PASS；589 events |
| `python3 -m compileall -q src scripts tests migrations` | PASS |
| 55 个原生 Rust 文件词法括号平衡检查 | PASS；**仅静态辅助，不替代编译器** |

日志位于 `docs/audit-logs/`。

### 7.2 Rust 命令——已真实尝试，但被沙箱工具链阻塞

| 命令 | 结果 |
|---|---|
| `cargo fmt --all --check` | BLOCKED，rc=127，`cargo: command not found` |
| `cargo clippy --locked --workspace --all-targets --all-features -- -D warnings` | BLOCKED，rc=127 |
| `cargo test --locked --workspace` | BLOCKED，rc=127 |
| `cargo build --locked --workspace --all-targets` | BLOCKED，rc=127 |
| `cargo test --locked -p aisoc-detection --test replay` | BLOCKED，rc=127 |

本沙箱没有 `cargo/rustc/rustfmt/clippy`，且无法从外部包源安装。不能把上述项目写成 PASS。由于仓库也没有可直接执行的真实 Rust release 二进制，实际服务 startup/health 启动测试同样无法完成；`deploy-check` 中通过的是 release-manager 的 fake/package 流程，不应与真实服务启动混淆。

### 7.3 Cargo.lock 项目缺陷

`./scripts/check-cargo-lock.sh` **FAIL**：

- 缺 17 个 V4 原生 workspace package（除 `aisoc-core` 外）。
- 缺 workspace 固定依赖：`serde`、`serde_json`、`schemars`、`thiserror`、`tracing`、`chrono`、`uuid`、`tokio`、`sqlx`。

即使换到有 Cargo 的环境，第一优先级也应先用 Rust 1.82 正常执行解析/锁定并提交新的 `Cargo.lock`，再跑 fmt/clippy/test/build。禁止手工编辑锁文件来伪造通过。

### 7.4 Python 全量 pytest

`PYTHONPATH=src python3 -m pytest -q` 在 collection 阶段退出 rc=2：15 errors、1 skipped。主要是当前沙箱 Python 依赖环境问题：

- 缺 `structlog`；
- 系统 `aiohttp` 与项目预期 API 不兼容（`aiohttp.web.RequestKey` 不存在）；
- `yara_x` 缺失导致相关测试 skip。

尝试按 `uv.lock` 离线恢复环境也因项目 Python 版本/精确 wheel 不在本地缓存而无法完成。因此这些结果不能归类为业务断言失败，也不能归类为测试通过。

## 8. 当前最重要架构偏差

1. `Cargo.lock` 未跟上 workspace，是 P1/整个 Rust CI 的首要 blocker。
2. 物理 workspace 仍包含 `aisoc-python` PyO3 迁移桥；虽然不在 default-members，但最终应移出生产 workspace/退役。
3. 最终 8 个 V4 服务/CLI 二进制仅 4 个同名目标落地；`worker/ai/response/aisocctl` 缺失。
4. Web Guard 已构建 WebRequest/WebSecurityEvent，但对 Ingest 的认证、可靠、可回放投递还未形成完整生产闭环。
5. P3 缺真正消息总线/object store/背压与乱序的系统验收。
6. P6–P12 的 Rust crate 多为可用骨架或部分核心逻辑，离“完全替代旧 Python 功能 + hard-gate Accepted”仍有距离。
7. P13/P14 尚未进入真实多发行版、性能、安全、备份恢复和业务 pilot 阶段。

## 9. 下一步推进顺序

1. 在具备 **Rust 1.82 + Cargo** 的 Linux CI/主机执行 `cargo update/generate-lockfile` 的受控解析，重建 `Cargo.lock`，随后依次跑 `cargo fmt --check`、`cargo clippy -D warnings`、`cargo test --locked --workspace`、`cargo build --locked --workspace --all-targets`，修到全绿。
2. 首先实际运行本轮新增 `aisoc-detection` Rust replay；任何编译/语义差异以 Rust 测试结果为准修复。
3. 在不做空壳的前提下落地 `aisoc-worker`、`aisoc-ai`、`aisoc-response`、`aisocctl`，并更新 Docker/release/systemd/Compose。
4. 完成 P3 的 NATS/JetStream/ObjectStore/背压/幂等/乱序真实集成链路。
5. 完成 Web Guard → Ingest 的认证事件流和 P5 性能/协议安全验收。
6. 按功能域逐步把 P6–P12 的 Python 基线迁为 Rust，并用 differential/replay/contract test 证明等价后再删旧实现。
7. 进入 P13 多发行版/fuzz/DAST/performance/backup-restore，再进入 P14 真实 shadow→canary→block pilot。
8. 功能等价完成后，将 `aisoc-python` 从主 workspace 移出并逐步退役 `src/aisoc`，而不是提前删除历史有效能力。

## 10. 本轮关键文件

- `crates/aisoc-detection/src/lib.rs`
- `crates/aisoc-detection/tests/replay.rs`
- `crates/aisoc-web-guard/src/main.rs`
- `crates/aisoc-web-guard/Cargo.toml`
- `tests/replay/*/canonical-events.jsonl`
- `tests/replay/*/manifest.json`
- `scripts/replay_detection.py`
- `scripts/check-rust-first.sh`
- `Makefile`
- `docs/phase-p4-plan.md`
- `docs/phase-p5-plan.md`
- `docs/phase-p11-plan.md`
- `docs/phase-p12-plan.md`
- `docs/p4-host-runtime-detection-annex.md`
- `docs/p11-response-console-legacy-annex.md`
- `docs/p13-hardening-detail-annex.md`
- `docs/python-legacy-inventory-2026-08-11.txt`
- `docs/audit-logs/*`

