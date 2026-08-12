# P4：网络/Web/SSH 检测与状态分层

状态：首增量、批次 B、version-bound 规则治理与签名生命周期初版已实现；检测 worker 已接入 base 管道。完整质量指标和 PostgreSQL/Linux VM rollout 重验仍未完成，因此 P4 尚未退出。
计划来源：项目计划书第 18 章"P4 网络、Web 与认证检测"，§8.2/§8.3 检测场景与状态机，§8.4 规则生命周期，§7.4 证据包与按需检索。

## 已完成（首增量，2026-08-04）

### 输入适配
- `suricata_normalizer` 扩展：`network.http` 携带 `http.method`/`http.url`/`http.status`/`http.protocol`。Suricata SSH 只在存在明确失败签名时标记 failure，其余保持 unknown，不再把协议握手误写为登录成功。
- `JournaldNormalizer` 从身份确认为 `sshd` 的 `Failed/Accepted` 消息生成真实 `network.ssh` 认证结果；非 sshd 服务即使伪造相同文本也不会成为认证事实。
- `ServiceLogNormalizer` 支持 Nginx/Apache Common/Combined access log，统一输出 `network.http`，不合法格式进入 DLQ。
- 新增 3 个 normalize 单测（HTTP extensions、SSH failure 映射、SSH client_ip）。

### 检测引擎
- `src/aisoc/detection_engine/`：`base.py`（`Detection` dataclass、`Rule` Protocol、`RuleContext`、`AttackState` enum、`detect_bursts` 贪心非重叠滑窗 helper）；`rule_registry.py`（`@register` 装饰器 + `register_all`）；`engine.py`（`DetectionEngine.evaluate` 按 tenant+host 分组、按 `applicable_event_types` 分发）；`rules/web_recon_scan.py`、`rules/ssh_bruteforce.py`。
- `domain/detection.py`：`AttackState`（attack_attempt/blocked/suspected_success/confirmed_compromise/unknown）、`DetectionCategory`、`DetectionStatus`、`DetectionCreate`/`DetectionRead`。
- `storage/detection_repository.py`：`create_detection` 按 tenant/host/rule/version/entity/window 幂等，并在并发冲突时用 savepoint 返回已有行。
- Migration `20260804_0006_detection_engine` 建表；`20260808_0007_detection_dedupe_scope` 修复原去重键遗漏 host/entity、导致跨主机或跨来源告警被吞掉的问题。
- Migration `20260809_0016_p11_rule_lifecycle` 再把 rule_version 纳入去重键，并增加签名 lifecycle current/event、Shadow observation 与 detection governance 引用。
- `schema_export`：新增 `detection-v0.1.schema.json`；`--check` 通过。
- `settings.py`：`detection_window_seconds`、`detection_web_scan_*`、`detection_ssh_bruteforce_failures` 阈值字段，env 可调。

### 规则与状态机（§8.3）
- Web 扫描：`request_count>300 AND unique_path_count>100 AND (4xx_ratio>0.70 OR sensitive_path_hits>=5)` → `web.recon.scanning`，`attack_state=attack_attempt`。
- SSH 爆破：同源 60s 内失败登录 >10 → `auth.ssh.bruteforce`，`attack_state=attack_attempt`。
- Web 注入：SQLi/XSS/命令注入的有界签名匹配；明确拒绝状态映射 `blocked`，其他只为 `attack_attempt`。
- 异常方法：TRACE/CONNECT/WebDAV 等输出 `web.request.abnormal_method`，并记录授权 WebDAV/代理诊断这一预期误报条件。
- `suspected_success`/`confirmed_compromise` 不在单一 Web/SSH 请求信号中判定；主机序列证据属于 P4 Detection 的 host-behavior 子域，规则 `next_steps` 指向 P5。

### 测试与回放
- P4 检测单测覆盖扫描、SSH、注入、异常方法、边界/反例、engine 分发与状态机；P4 host-behavior 另覆盖多段序列、PID reuse、跨 boot 和运维反例。
- 集成测试 `tests/integration/test_detection_persistence.py`：真实 PostgreSQL 验证落库 + 幂等重放 + 审计。
- `tests/replay/build_datasets.py` 可确定性重建 `web_scan`、真实 sshd journald `ssh_bruteforce`、`normal_baseline` 与 `web_injection`；manifest 固定来源、版本、许可和 SHA-256。
- `scripts/replay_detection.py` 不读取本机 `.env`，并校验数据集哈希、DLQ、攻击状态、最小/最大命中数和意外类别。

### 实时管道接入（2026-08-04 补完）
- `DetectionWorker`（`src/aisoc/detection_engine/worker.py`）：轮询 `normalized_events` active（lookback ≥ 2×突发窗口且覆盖 host-chain window）→ 重建 `SecurityEvent` → `DetectionEngine.evaluate` → `create_detection`（幂等）。
- `NormalizeWorker`（`src/aisoc/normalize/worker.py`）：轮询 `agent_events.normalize_status='pending'` → normalize → `normalized_events`。
- 两个 worker 作为 `aisoc-api` lifespan 后台任务运行；`aisoc-process` CLI 离线推进。
- 端到端集成测试 `tests/integration/test_pipeline_e2e.py`：301 事件经 normalize → detect → `/api/v1/detections` 可查，幂等重放不重复。
- 检测已在 PostgreSQL 集成管道测试中覆盖，但本轮按用户要求未启动 Docker/PostgreSQL；Linux VM 重验前只视为已有测试证据，不宣称当前环境再次通过。

## 退出条件对照（§18.1：核心 Web 扫描和 SSH 爆破达到 MVP 指标；正常基线误报可解释）

- 九个确定性本地回放均通过：P4 的 Web 扫描 1、SSH 爆破 1、注入 3、正常基线 0；host-behavior 成功链 5，其余正常/失败/缺源/超窗口各 0。✅
- 尝试/阻断/疑似成功不混淆：P4 请求信号只输出 `attack_attempt`/`blocked`；P4 host-behavior Web→shell 行为才允许 `suspected_success`。✅
- MVP 的 Precision≥80%、Web 扫描 Recall≥90%、每主机日误报和数据源缺失敏感度尚无足量独立验收集。❌ P4 不得据当前四个小型合成集正式退出。

## 待完成（后续增量）

### 批次 C：完整状态机 + ATT&CK 映射
- `suspected_success` 已有 Web 进程派生 shell、下载执行、外联和持久化的 P4 host-behavior 规则；仍需真实 Collector 与请求↔PID 关联来闭合影响链。
- ATT&CK 技术映射（T1190/T1110 等）、owner、测试数据集、预期误报、抑制条件和回滚方案已进入 version-bound catalog。
- Ed25519 tenant manifest 已实现 Draft→Shadow→Canary→Released、逐级 rollback、Deprecated 和新版本 upgrade；sequence、previous hash、catalog、完整 dataset evidence 与 Canary Host tenant membership 均 fail closed。Shadow/非 Canary Host 不进入 detection/Incident；Canary/Released detection 绑定 stage+manifest hash。
- 真实 PostgreSQL 双租户并发 import/replay/rollback、过期/corruption 故障注入与持续 rollout 观察仍待 Linux VM。

### 批次 D：检测质量度量
- Precision/Recall/每主机每天误报数度量（§8.4）。
- 规则历史回放差异报告（规则变更触发受影响数据集回放）。
- 数据源缺失敏感度分析。

## 尚未完成边界

- Incident 关联（P6）、AI 研判（P7+）、响应执行（P11）。
- eBPF/auditd 主动采集、真实 Falco 宿主接入和跨发行版验证属于 P2 Agent/Linux VM 与 P4 Detection 联合门禁。

## V4.0 Rust 原生回放整改（2026-08-11）

- 九组 replay 数据集新增冻结的 `canonical-events.jsonl` 与 `canonical_events_sha256`，把 normalize 后的契约输入固定下来，避免 Rust 验收依赖 Python normalizer。
- `crates/aisoc-detection/tests/replay.rs` 直接反序列化 V4 `SecurityEvent`、校验 SHA-256 与契约有效性，并用 Rust `DetectionEngine` 对 manifest 的类别、状态与命中数量做验收。
- Rust Detection 已补齐 `host.web_process.shell`、`host.download.execute`、`host.persistence.change`、`host.web_shell.outbound`、`host.lateral.scan` 五条主机行为链规则，并修复 numeric `http.status` 导致 blocked 状态漏判的问题。
- Web 注入统一输出 `web.attack.injection` 类别，具体 SQLi/XSS/command 由 `rule_id`/summary 区分；同时收窄 `javascript:` 误报条件以保护正常基线。
- `scripts/replay_detection.py` 继续保留为迁移期差异基线，不再是 V4 Rust P4 的权威退出门禁；权威命令为 `make rust-replay`。
- 本沙箱没有 Rust 1.82 toolchain，且当前 `Cargo.lock` 不完整，因此新增 Rust replay 尚未能在本轮环境中真正编译执行；这项必须在 P1 lock/toolchain 修复后重验，不能据静态检查标记 P4 Accepted。

## V4.0 Rust 主体窗口隔离整改（2026-08-12）

- 对照 legacy Python 规则确认 Web Recon 与 SSH brute-force 都是 source-scoped burst；共享目标 host 不能成为合并不同攻击来源的充分条件。
- `aisoc-detection` Web Recon 现先按 `src_ip` 分组，再独立计算滑动窗口指标；缺少来源地址的事件不进入来源型 burst。
- SSH brute-force 的 entity key 统一为 `src_ip:{source}`；Web injection 的单事件 key 同时携带来源与 `event` anchor，供 P6 做有界主体关联。
- 新增 Rust 测试验证两个不同 source 的流量不会被拼成一次扫描、同一 source 仍可达到扫描阈值。
- 当前沙箱没有 Rust 1.82/Cargo，以上 Rust 测试尚未真实执行；P4 状态仍为“部分完成”，不得据源码变更宣称退出。
