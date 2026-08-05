# P4：网络/Web/SSH 检测与状态分层

状态：首增量完成 + 检测 worker 已接入实时管道；后续增量 Nginx/Apache 适配、注入/异常方法规则、完整 ATT&CK 映射待推进。
计划来源：项目计划书第 18 章"P4 网络、Web 与认证检测"，§8.2/§8.3 检测场景与状态机，§8.4 规则生命周期，§7.4 证据包与按需检索。

## 已完成（首增量，2026-08-04）

### 输入适配
- `suricata_normalizer` 扩展：`network.http` 携带 `http.method`/`http.url`/`http.status`/`http.protocol`；`network.ssh` 携带 `ssh.auth_event`(success/failure)/`ssh.auth_method`/`ssh.client_ip`/`ssh.username`，全部走 `extensions`（不改顶层 Schema v0.1）。
- 新增 3 个 normalize 单测（HTTP extensions、SSH failure 映射、SSH client_ip）。

### 检测引擎
- `src/blue_team/detection_engine/`：`base.py`（`Detection` dataclass、`Rule` Protocol、`RuleContext`、`AttackState` enum、`detect_bursts` 贪心非重叠滑窗 helper）；`rule_registry.py`（`@register` 装饰器 + `register_all`）；`engine.py`（`DetectionEngine.evaluate` 按 tenant+host 分组、按 `applicable_event_types` 分发）；`rules/web_recon_scan.py`、`rules/ssh_bruteforce.py`。
- `domain/detection.py`：`AttackState`（attack_attempt/blocked/suspected_success/confirmed_compromise/unknown）、`DetectionCategory`、`DetectionStatus`、`DetectionCreate`/`DetectionRead`。
- `storage/detection_repository.py`：`create_detection`（幂等：同 rule+window 返回已有行）、`get_detection`、`list_detections`。
- Migration `20260804_0006_detection_engine`：`detections` 表 + 唯一约束 `(tenant_id, rule_id, window_start, window_end)` + 索引。`alembic check` 无漂移。
- `schema_export`：新增 `detection-v0.1.schema.json`；`--check` 通过。
- `settings.py`：`detection_window_seconds`、`detection_web_scan_*`、`detection_ssh_bruteforce_failures` 阈值字段，env 可调。

### 规则与状态机（§8.3）
- Web 扫描：`request_count>300 AND unique_path_count>100 AND (4xx_ratio>0.70 OR sensitive_path_hits>=5)` → `web.recon.scanning`，`attack_state=attack_attempt`。
- SSH 爆破：同源 60s 内失败登录 >10 → `auth.ssh.bruteforce`，`attack_state=attack_attempt`。
- `suspected_success`/`confirmed_compromise` 不在首增量判定（需 P5 主机证据），规则 `next_steps` 指向 P5。

### 测试与回放
- 单测 `tests/unit/detection/`：25 用例（web 正例/反例/敏感路径/正常基线/跨 src_ip/窗口边界；ssh 阈值/成功不计数/窗口边界/混合；engine 分发/幂等/状态机）。
- 集成测试 `tests/integration/test_detection_persistence.py`：真实 PostgreSQL 验证落库 + 幂等重放 + 审计。
- 回放数据集 `tests/replay/{web_scan,ssh_bruteforce,normal_baseline}/`（EVE JSONL + manifest）；`scripts/replay_detection.py` 端到端验证。

### 实时管道接入（2026-08-04 补完）
- `DetectionWorker`（`src/blue_team/detection_engine/worker.py`）：轮询 `normalized_events` active（lookback ≥ 2× 窗口）→ 重建 `SecurityEvent` → `DetectionEngine.evaluate` → `create_detection`（幂等）。
- `NormalizeWorker`（`src/blue_team/normalize/worker.py`）：轮询 `agent_events.normalize_status='pending'` → normalize → `normalized_events`。
- 两个 worker 作为 `blue-team-api` lifespan 后台任务运行；`blue-team-process` CLI 离线推进。
- 端到端集成测试 `tests/integration/test_pipeline_e2e.py`：301 事件经 normalize → detect → `/api/v1/detections` 可查，幂等重放不重复。
- 检测**在真实管道上触发**（非仅离线回放），P4 退出条件"检测在真实管道触发"满足。

## 退出条件对照（§18.1：核心 Web 扫描和 SSH 爆破达到 MVP 指标；正常基线误报可解释）

- Web 扫描命中：回放 `web_scan` → 1 个 `web.recon.scanning`。✅
- SSH 爆破命中：回放 `ssh_bruteforce` → 1 个 `auth.ssh.bruteforce`。✅
- 正常基线无命中：回放 `normal_baseline` → 0 检测（误报可解释）。✅
- 尝试与成功不混淆：所有检测 `attack_state=attack_attempt`；`suspected_success` 需 P5 主机证据，规则 `next_steps` 显式标记。✅

## 待完成（后续增量）

### 批次 B：Nginx/Apache 适配 + 注入规则 + 异常方法
- Nginx/Apache access log normalizer → `network.http`（复用 extensions 约定）。
- 注入规则（SQLi/XSS/命令注入签名）+ 异常 HTTP 方法规则。
- `blocked` 状态判定（命中注入 + 响应被拒绝 + 无主机后续异常）。

### 批次 C：完整状态机 + ATT&CK 映射
- `suspected_success` 判定接入 P5 主机证据（Web 进程产生 shell/下载/外联）。
- ATT&CK 技术映射（T1190/T1110 等）+ 归因限制模板。
- 规则元数据完整化（owner、测试数据集、预期误报、抑制条件、回滚方案，§8.4）。

### 批次 D：检测质量度量
- Precision/Recall/每主机每天误报数度量（§8.4）。
- 规则历史回放差异报告（规则变更触发受影响数据集回放）。
- 数据源缺失敏感度分析。

## 非目标（本轮）

- Incident 关联（P6）、AI 研判（P7+）、响应执行（P11）。
- 主机行为链（P5）——`suspected_success` 依赖 P5 但本轮不实现 P5。
- eBPF/auditd/Falco 检测（P5）。
