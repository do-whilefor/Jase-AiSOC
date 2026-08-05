# 测试与验收计划

## 测试层

| 层次 | 首批对象 | 工具/环境 | 证据 |
|---|---|---|---|
| 契约/单元 | Schema、解析、配置、策略、错误 | pytest、Hypothesis、JSON Schema | 测试报告、正反例 fixture |
| 集成 | PostgreSQL、对象存储、NATS、Agent 流、模型 mock | Linux + testcontainers/compose | 服务日志、迁移结果、Trace |
| 回放 | EVE、auditd、Web/SSH、乱序/重复/缺失事件 | 固定版本数据集和 replay runner | 输入摘要、规则版本、差异报告 |
| 攻击仿真 | 扫描、爆破、Web shell 链、下载执行、持久化、C2 | 隔离授权 VM/网络 | 请求/响应、事件、Incident、证据引用 |
| 兼容 | 安装、采集、升级、回滚、卸载、降级 | 固定 Linux VM 矩阵 | 兼容报告和能力清单 |
| 性能 | EPS、延迟、CPU/内存、积压、存储 | 代表硬件、k6、benchmark、故障注入 | 原始指标、配置、容量结论 |
| 安全 | 身份/对象/租户、Prompt/工具、供应链、响应 | 双身份/双租户、SAST/DAST、模糊测试 | 可复现请求/状态/审计 |
| 恢复 | 断网、磁盘满、消息/DB/对象故障 | 故障注入与备份恢复 | RPO/RTO 和一致性报告 |

## P0 追踪矩阵

| 要求 | 当前验证 | 通过标准 |
|---|---|---|
| Event Schema v0.1 有效 | `tests/test_p0_baseline.py` | Draft 2020-12 校验通过 |
| 安全边界字段必需 | 删除 tenant/host/raw_ref/event_id 的负例 | 全部被拒绝 |
| 拒绝未知受信字段 | 注入 `trusted_role` | 被拒绝，只能使用命名空间扩展 |
| 契约版本固定 | 修改 `schema_version` | 不支持版本被拒绝 |
| 工程质量 | Ruff、mypy、pytest | CI 全绿 |
| 供应链 | 锁定安装、pip-audit、CycloneDX | 锁文件无漂移；审计通过；SBOM 作为制品 |

## MVP 核心验收基线

- Web 扫描召回率至少 90%，关键攻击链召回率至少 85%，正式高危规则 Precision 至少 80%。
- 正常业务误报密度不高于 0.20 条/主机日，攻击尝试误判为成功不高于 3%。
- 确认失陷 Claim 的证据覆盖率 100%；不存在/跨租户引用、模型覆盖确定性工具和注入导致未授权工具调用均为 0。
- 初步检测延迟 P95 不高于 10 秒；正常日志触发 AI 不高于 0.5%。
- 断网恢复不重复执行响应，所有丢弃、采样和降级均可统计。

## P2 Agent 身份追踪矩阵

| 要求 | 当前动态验证 | 通过标准 |
|---|---|---|
| 一次性、租户/Host 绑定注册 | 双租户 API + PostgreSQL 状态对照 | 跨租户 404；无效 CSR 不消费；成功后重放 401；数据库无明文令牌 |
| 服务端证书身份 | 带伪造 Subject/SAN 的有效 P-256 CSR | 签发结果只包含服务端 tenant/host/agent/installation/hardware SAN |
| mTLS | 本地真实 `ssl` server/client socket | 有可信客户端证书成功；无客户端证书握手失败 |
| 轮换与吊销 | 旧私钥 proof、错误私钥、新旧证书状态对照 | 错误 proof 失败；旧证书立即失效；新证书成功；吊销后失败 |
| 镜像克隆限制 | 本地 binding 变化 + PostgreSQL 并发会话 | binding 变化报告 clone；相同证书并发租约只有一个提交成功 |
| 重新注册 | 租户显式签发新令牌并替换 installation/binding | 旧证书保持吊销；新证书与新 installation 可建立租约 |

## P2 Agent runtime 追踪矩阵

| 要求 | 当前动态验证 | 通过标准 |
|---|---|---|
| 生命周期 | 可控时钟 + 正常/重复/非法调用 | 状态转换固定；只能启动一次；停止幂等；Collector 反序停止 |
| Collector 隔离 | start/health 失败和正常 Collector 对照 | 正常 Collector 继续；失败项在 Heartbeat 中为 failed 且保留原因 |
| 队列保护联动 | fake telemetry + 真实 SQLite P0 容量 | 非必要 Collector pause；essential 保持；P0 drop=0；恢复后 resume |
| Heartbeat 调度 | 首次到期、成功间隔、传输失败和恢复 | 失败进入 degraded 并短间隔重试；成功后清零失败状态 |
| 观测退化 | queue 读取异常、平台 probe 暂时异常 | queue 异常强制 protection；probe 使用最后证据且保持 degraded；恢复可见 |
| 真实进程入口 | 私有配置、两进程竞争、SIGTERM、journal 重启读取 | 同一状态目录仅一个进程；首次 Heartbeat 与所有 lifecycle 转换持久化；有界停止 |
| 候选进程门禁 | 启动/健康超时、崩溃、拒绝退出、输出洪泛、argv/env 变化 | 固定 argv、无 shell/父环境/多余 FD；输出有界；TERM 超时后 KILL 并拒绝激活 |
| Linux 可运行性 | UID 10001、只读镜像、锁定依赖运行 runtime/process/supervisor/installer tests | 43 tests passed + 独立 smoke；不要求 root；不修改源码或宿主虚拟环境 |

## P2 签名制品追踪矩阵

| 要求 | 当前动态验证 | 通过标准 |
|---|---|---|
| 签名与授权 | Ed25519 正常/篡改签名、未知 key、跨 kind key | 只接受受信且获该 kind 授权的 key；manifest 任意变化使签名失效 |
| Payload 与目标 | 正常/篡改 bytes、长度、架构、发行版、有效期 | SHA-256 与长度同时匹配；仅在 manifest 时间窗内且 Linux 目标完全匹配 |
| 重放与版本 | 旧/相同 sequence、相同版本新 sequence、重启加载 | 不同内容不能复用 sequence 或版本；已应用的相同制品幂等识别 |
| 安全下限与回滚 | 签名降级、回滚 key 权限、approval 到期、持久化 floor | 无独立权限或有效审批则拒绝；任何签名 manifest 都不能降低持久化 floor |
| 灰度 | 固定 installation/rollout ID 重复计算 | 选择结果稳定；deferred 制品不能记录为已应用 |
| 状态持久化 | 重启、私有文件、符号链接、内存/磁盘 stale revision | `0700/0600`、拒绝链接/非普通文件；只允许验证过的下一 revision 原子替换 |
| 安全解包 | traversal/绝对/反斜杠/碰撞路径、链接、特殊文件、空目录、大小上限 | 仅独占写入规范普通文件；不越界；条目/单文件/总解包预算均强制执行 |
| 健康门禁 | callback 正反例 + 真实候选进程的启动/健康/停止与超时 | 固定 `health-probe` 依次报告 started/healthy 且可在期限内停止；再做二次完整性校验；失败保持旧 active/state 和队列 |
| 崩溃恢复 | state 提交前/后、active 写入前、journal 清理前、孤立 staging | 提交前删除候选；提交后完成 active；临时文件可恢复清理且不倒退 state |
| 安装并发 | 同进程和 Linux 独立进程竞争同一安装根 | 只有持锁事务继续；竞争者明确返回 busy，不覆盖 journal/state/active |
| 回滚审计 | 降级→升级→复用旧 approval 再降级 | state v2 记录 approval/reason/manifest；全局拒绝 approval ID 复用 |

上述矩阵已覆盖 verifier、本地 tar 安装事务、真实 Agent 进程入口及候选子进程健康超时，但不
覆盖网络下载/Heartbeat 传输、systemd/策略热切换、root-owned updater、DEB/RPM、签名服务或
发行版兼容性；这些必须在后续传输、发布制品和 Linux VM 矩阵中另行动态验证。

## P4 检测引擎追踪矩阵

| 要求 | 当前动态验证 | 通过标准 |
|---|---|---|
| Web 扫描命中 | `tests/unit/detection/test_web_recon_scan.py` + `tests/replay/web_scan/` | 301 请求/110 路径/75% 4xx → 命中 `web.recon.scanning`；回放脚本 exit 0 |
| SSH 爆破命中 | `tests/unit/detection/test_ssh_bruteforce.py` + `tests/replay/ssh_bruteforce/` | 11 失败/3 用户/60s → 命中 `auth.ssh.bruteforce`；回放脚本 exit 0 |
| 正常基线无误报 | `test_web_recon_scan.py::test_web_scan_normal_baseline_does_not_fire` + `tests/replay/normal_baseline/` | 200 请求/50 路径/200 OK → 0 检测 |
| 阈值边界 | `test_web_scan_does_not_fire_below_*`、`test_ssh_bruteforce_does_not_fire_at_or_below_threshold` | 严格 `>` 阈值，边界值不命中 |
| 窗口隔离 | `test_web_scan_window_boundary_excludes_old_events`、`test_ssh_bruteforce_window_boundary_excludes_old_failures` | 60s 外事件不进窗口 |
| 跨源不聚合 | `test_web_scan_groups_by_source_ip_separately`、`test_ssh_bruteforce_groups_by_source_ip` | 每个 src_ip 独立判定 |
| 尝试/成功不混淆 | `test_attack_state_is_attempt_not_success_without_host_evidence` | `attack_state=attack_attempt`；`suspected_success` 需 P5，`next_steps` 标记 |
| 幂等落库 | `tests/integration/test_detection_persistence.py`（真实 PG） | 同 window 重放返回已有行，不重复；审计 1 条 |
| 回放可重放 | `scripts/replay_detection.py` × 3 数据集 | 数据集 + manifest 驱动，exit 码反映期望匹配 |
| 证据可追溯 | `Detection.evidence_event_ids` 引用 `event_id` | 每个检测携带 ≤50 evidence_id（§7.4） |

## P3/P4 实时管道追踪矩阵

| 要求 | 当前动态验证 | 通过标准 |
|---|---|---|
| normalize 接入 | `tests/unit/test_normalize_worker.py` + `tests/integration/test_pipeline_e2e.py` | `agent_events.normalize_status='pending'` → `done`；`normalized_events` 有行 |
| 非法入 DLQ | `test_normalize_worker_marks_failed_on_bad_envelope` | 坏 envelope → `failed` + `insert_dlq` |
| detect 接入 | `tests/unit/test_detection_worker.py` + e2e | `normalized_events` → `DetectionEngine.evaluate` → `create_detection` |
| 幂等重放不重复 | `test_pipeline_e2e::test_pipeline_normalize_detect_query_end_to_end` 步骤 5 | 重跑 worker → `normalized_events`/`detections` 行数不变 |
| events 查询 API | `tests/unit/test_api_basics.py::test_openapi_*` + e2e 步骤 4 | `GET /api/v1/events` 返回 tenant-scoped 列表 |
| detections 查询 API | e2e 步骤 4 | `GET /api/v1/detections` 返回命中检测 |
| workers 开关 | `test_workers_disabled_does_not_start_background_tasks` | `workers_enabled=false` 不启后台任务 |
| 离线推进 | `blue-team-process --help` + CLI 可用 | 不启动 web 即可推进管道 |

## 数据集要求

每个场景至少包含正常、失败攻击、成功攻击、弱信号、数据缺失、时钟偏差、乱序和重复变体，并记录生成脚本、来源、许可、版本与哈希。调优集与最终验收集隔离；Schema、规则、Collector、Prompt 或模型路由变化必须触发受影响数据集回放。

## 安全验证原则

涉及认证、授权、对象所有权、租户隔离、状态机和响应权限时，必须使用至少两个身份、两个租户或两个对象进行动态对照。错误码、静态路由、扫描器命中或模型判断仅作为线索，不能替代真实请求、状态和审计证据。
