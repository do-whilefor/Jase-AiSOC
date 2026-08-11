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
| Collector 隔离 | start/poll/health 失败、degraded 和正常 Collector 对照 | 正常 Collector 继续；失败项在 Heartbeat 中为 failed，保留原因及最后 drop/backlog/parse/incomplete 计数 |
| 队列保护联动 | fake telemetry + 真实 SQLite P0 容量 | 非必要 Collector pause；essential 保持；P0 drop=0；恢复后 resume |
| Heartbeat 调度 | 首次到期、成功间隔、传输失败和恢复 | 失败进入 degraded 并短间隔重试；成功后清零失败状态 |
| 观测退化 | queue 读取异常、平台 probe 暂时异常 | queue 异常强制 protection；probe 使用最后证据且保持 degraded；恢复可见 |
| 真实进程入口 | 私有配置、两进程竞争、SIGTERM、journal 重启读取 | 同一状态目录仅一个进程；首次 Heartbeat 与所有 lifecycle 转换持久化；有界停止 |
| 候选进程门禁 | 启动/健康超时、崩溃、拒绝退出、输出洪泛、argv/env 变化 | 固定 argv、无 shell/父环境/多余 FD；输出有界；TERM 超时后 KILL 并拒绝激活 |
| Linux 可运行性 | UID 10001、只读镜像、锁定依赖运行 runtime/process/supervisor/installer tests | 43 tests passed + 独立 smoke；不要求 root；不修改源码或宿主虚拟环境 |
| audit.log polling | 临时普通文件、partial line、truncation、坏行、超时和重启 | 完整 serial P2；gap P1；cursor+pending serial 原子恢复；sequence 跨重启不复用；真机语义待 Linux VM |

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
| Web 扫描命中 | `tests/unit/detection/test_web_recon_scan.py` + `tests/replay/web_scan/` | 301 请求/110 路径/100% 4xx → 恰好 1 个 `web.recon.scanning`；回放脚本 exit 0 |
| SSH 爆破命中 | sshd journald normalizer + `tests/replay/ssh_bruteforce/` | 11 条明确失败/3 用户/11s → 恰好 1 个 `auth.ssh.bruteforce` |
| Web 输入适配 | `test_normalize.py` 的 service-log/sshd/Suricata 对照 | Common/Combined → `network.http`；非 sshd 伪造消息不能生成认证事实；协议 SSH 未知结果不写 success |
| 注入/异常方法 | `test_web_request_anomalies.py` + `tests/replay/web_injection/` | SQLi/XSS/命令注入按响应分为 blocked/attempt；普通方法和 benign 关键字不命中 |
| 正常基线无误报 | `test_web_recon_scan.py::test_web_scan_normal_baseline_does_not_fire` + `tests/replay/normal_baseline/` | 200 请求/50 路径/200 OK → 0 检测 |
| 阈值边界 | `test_web_scan_does_not_fire_below_*`、`test_ssh_bruteforce_does_not_fire_at_or_below_threshold` | 严格 `>` 阈值，边界值不命中 |
| 窗口隔离 | `test_web_scan_window_boundary_excludes_old_events`、`test_ssh_bruteforce_window_boundary_excludes_old_failures` | 60s 外事件不进窗口 |
| 跨源不聚合 | `test_web_scan_groups_by_source_ip_separately`、`test_ssh_bruteforce_groups_by_source_ip` | 每个 src_ip 独立判定 |
| 尝试/成功不混淆 | `test_attack_state_is_attempt_not_success_without_host_evidence` | `attack_state=attack_attempt`；`suspected_success` 需 P5，`next_steps` 标记 |
| 幂等落库 | `tests/integration/test_detection_persistence.py`（真实 PG，待 Linux VM 重验） | 同 subject/rule/window 重放不重复；相同时间窗的另一 host/entity 不被吞并 |
| 回放可重放 | `build_datasets.py` + `replay_detection.py` × 9 数据集 | 生成后 SHA-256 一致；DLQ、状态、最小/最大命中和意外类别均受检 |
| 证据可追溯 | `Detection.evidence_event_ids` 引用 `event_id` | 每个检测携带 ≤50 evidence_id（§7.4） |

## P3/P4 实时管道追踪矩阵

| 要求 | 当前动态验证 | 通过标准 |
|---|---|---|
| normalize 接入 | `tests/unit/test_normalize_worker.py` + `tests/integration/test_pipeline_e2e.py` | `agent_events.normalize_status='pending'` → `done`；`normalized_events` 有行 |
| 非法入 DLQ | `test_normalize_worker_marks_failed_on_bad_envelope` | 坏 envelope → `failed` + `insert_dlq` |
| 对象读取失败 | `test_normalize_worker_records_object_store_failure_in_dlq` | 不静默标记失败；保留 raw_ref、原因与错误详情 |
| watermark/迟到 | `test_normalize_worker_marks_event_older_than_watermark_as_late` + watermark 单测 | worker 实际读取/推进 watermark；新迟到事实标记，重复迟到事件仍幂等 |
| normalize 去重作用域 | `test_normalize.py` + `test_auditd_normalizer.py` 双 host 对照 | trusted tenant/host/agent/boot/source 进入 key；同 host 重放稳定，另一 host 的同 payload/source ID 不被吞并 |
| detect 接入 | `tests/unit/test_detection_worker.py` + e2e | `normalized_events` → `DetectionEngine.evaluate` → `create_detection` |
| 幂等重放不重复 | `test_pipeline_e2e::test_pipeline_normalize_detect_query_end_to_end` 步骤 5 | 重跑 worker → `normalized_events`/`detections` 行数不变 |
| events 查询 API | `tests/unit/test_api_basics.py::test_openapi_*` + e2e 步骤 4 | `GET /api/v1/events` 返回 tenant-scoped 列表 |
| detections 查询 API | e2e 步骤 4 | `GET /api/v1/detections` 返回命中检测 |
| workers 开关 | `test_workers_disabled_does_not_start_background_tasks` | `workers_enabled=false` 不启后台任务 |
| 离线推进 | `aisoc-process --help` + CLI 可用 | 不启动 web 即可推进管道 |

## P5 离线增量追踪矩阵

| 要求 | 当前动态验证 | 通过标准 |
|---|---|---|
| Falco exec 适配 | `tests/unit/normalize/test_falco_normalizer.py` | PID/PPID、用户、命令、父进程与 raw_ref 保留为 `process.exec` |
| 事件类型边界 | 同文件 connect 对照 | Falco connect 即使携带 proc 字段也保持 `network.connect` |
| audit serial 聚合 | `tests/unit/test_auditd_aggregator.py` | 交错 serial 独立到 EOE；容量/record/byte bound 和关闭 flush 输出 incomplete；原始 UTF-8 行不被改写 |
| auditd 标准化 | `tests/unit/normalize/test_auditd_normalizer.py` | boot/type/serial 校验；EXECVE/SYSCALL/PATH/CWD/PAM/SOCKADDR 合并；坏组进 DLQ；同 host+boot+serial 幂等且跨 host 隔离 |
| audit.log Collector | `tests/unit/test_auditd_collector.py` | 完整行 tail、cursor+半组重启、P1 gap、P2 事件、原始行、kernel/tail/parse/incomplete 计数和跨 host 诊断 ID |
| sequence 分配 | `tests/unit/test_agent_queue.py` | SQLite 高水位并发串行；手工 sequence 推进 floor；升级后已 ACK sequence 不复用，允许无害 gap |
| 时钟质量 | Agent/Falco/auditd normalizer 对照 | 记录 `clock_offset_ms`；超过 5 分钟标为 `skew_detected` |
| Web→shell | `tests/unit/detection/test_host_behavior.py` | Web parent + 成功 shell/interpreter exec → `suspected_success`；失败 exec、systemd→shell、nginx→nginx 不命中 |
| 下载执行链 | 同文件 + `tests/replay/host_success_chains/` | downloader exec→write→chmod→exec 跨 PID 按 boot/path 还原；缺阶段、跨 boot、PID reuse 不命中 |
| 持久化 | 同文件 | shell 等可疑 writer 成功修改 cron/systemd/authorized_keys → suspected；失败写和 dpkg 反例不命中 |
| Web shell 外联 | 同文件 | 同 boot/PID/latest-exec 的 Web shell→公网 connect → suspected；PID reuse/私网反例不命中 |
| 横向扫描 | 同文件 | 同 process generation 在 60s 内连接 20 个私网目标 → attack_attempt；缺 process source/跨 boot/低于阈值不命中 |
| 序列回放 | `host_{normal_baseline,failed_attacks,success_chains,missing_source,clock_skew}` | 成功集含乱序+重复并恰好产生 5 个预期检测；正常/失败/缺源/超窗口各 0 |
| worker 回看契约 | `test_config.py` + `test_detection_worker.py` | lookback 覆盖 2× burst 与 host-chain window；新 worker 从完整 DB 窗口重建链；超过 max-events 显式失败，禁止静默截断 |
| 不过度结论 | P5 全部正例 | 序列事实不输出 `confirmed_compromise`，next_steps 要求请求/文件内容/外联结果佐证 |
| 真机门禁 | 尚无 | auditd/eBPF/Falco 宿主接入、L1/L2 和三发行版验证必须留到 Linux VM，当前不得宣称通过 |

## P6 Incident 与证据追踪矩阵

| 要求 | 当前动态验证 | 通过标准 |
|---|---|---|
| 顺序无关与重放幂等 | `test_incident_correlator.py` + `test_incident_repository.py` | Detection/evidence 重排、重复得到同一候选；相同 snapshot 不新增 revision |
| 主体/主机隔离 | 不同 src subject、host 对照 | 共享目标资产不能合并不同主体；host 边界始终独立 |
| 判断证据闭环 | Claim/timeline/edge evidence 集合对照 | 每个引用均存在于同 revision evidence index；数据库复合 FK 再连接 normalized event |
| 迟到与时钟质量 | late + skew_detected 对照 | 新迟到事实产生 `late_evidence_recompute`；timeline assurance 降级；旧 revision 保留 |
| 10k 缩减 | 10,000 条重复 `network.http` | 恰好 1 Incident；20 主样本；9,980 dropped；`full_query_ref` 和 query 范围保留 |
| 禁止静默截断 | detection max+1、evidence max+1 | worker/correlator 显式抛出 overflow；不 commit 部分 Incident |
| 持久化与并发 | `test_incident_persistence.py`（真实 PG，待 Linux VM） | tenant-scoped FK 生效；savepoint 重放/竞争只产生一个 Incident/revision |
| Evidence API | OpenAPI + repository bundle tests | evidence/raw_ref/integrity/query/reduction、timeline、claims、graph 均由认证 tenant 查询 |
| 生命周期 | `test_incident_lifecycle.py` | close resolve member detections；merge=单 component；split=精确 component partition；lineage/feedback/audit 追加写 |
| 真机门禁 | 尚无 | Linux VM PostgreSQL + 真实 P4/P5 链、双租户、跨 poll/restart/迟到、10k 与并发验证全部通过后才关闭 P6 |

## P7 AI Review 与 Tool Gateway 追踪矩阵

| 要求 | 当前动态验证 | 通过标准 |
|---|---|---|
| 普通日志不触发模型 | `test_ai_review_orchestrator.py::test_normal_incident_is_skipped_without_any_model_or_tool_call` | 低 severity/risk 正常活动返回 skip；Provider/Tool 调用均为 0 |
| Provider 故障隔离 | Provider failure、timeout/retry、circuit open/recovery 对照 | 返回 `model_unavailable`；`deterministic_result_preserved=true`；detect/Incident 不依赖模型 |
| Prompt/数据边界 | 注入字符串放入 EvidencePackage aggregate data | 注入只出现在 user JSON，不进入 system instructions；输出仍经 trusted JSON Schema 校验 |
| Provider 适配 | Kimi/GLM/custom URL、400/401/429/5xx、malformed JSON、oversize response | URL 不重复前缀；仅 timeout/429/5xx 重试；secret 不出现在 repr/错误；超限拒绝 |
| EvidencePackage 边界 | tenant/Incident/revision、20 samples、full_query_ref 对照 | 跨 revision 拒绝；样本全在 evidence index；普通 skip 不构包 |
| Tool 最小权限 | `test_ai_review_tool_gateway.py` query_ref/unknown/extra/coercion/row/byte 对照 | 仅 4 个只读工具；精确 scope；跨 query 在数据访问前拒绝；结果标为 untrusted |
| Claim 闭环 | package evidence、Tool evidence、未知/跨 Incident evidence 对照 | supported Claim 必须引用允许 event ID；无证据仅 insufficient/unsupported+unknowns；错误输出整体无效 |
| 预算 | context/output/tool/model-run/rate/cost 对照 | 默认 20/16k/8/3/30；任一耗尽返回 budget_exceeded，不产生报告 |
| 追加写审计 | `test_ai_review_repository.py` | task、run、tool、Claim、evidence link、audit 一起写；伪造 task/revision 在 DB 前拒绝 |
| PostgreSQL/租户 | `tests/integration/test_ai_review_persistence.py`（待 Linux VM） | exact FK、task replay=1、Claim link、stored-query Tool read；另一 tenant 读/Tool query 均失败 |
| 真实 Provider/Linux VM | 尚无 | 真实 Kimi/GLM/custom、并发 review、30/min、双租户 HTTP、Linux P4/P5→P6→P7 全链通过后关闭 P7 |

## P8 盲审、程序校验与冲突追踪矩阵

| 要求 | 当前动态验证 | 通过标准 |
|---|---|---|
| 预先升级 | `test_ai_review_gate.py` high/risk/critical/destructive 对照 | 高/严重、risk>=80、关键资产或破坏性上下文返回 `analyze_and_verify`；medium 默认 Analyzer only |
| 动态升级 | unsupported/insufficient、deterministic invalid Analyzer Claim 对照 | Analyzer 后受信策略触发 Verifier；模型文本本身不能改变 Gate/策略 |
| 盲输入 | `test_blind_claim_removes_analyzer_identity_scores_verdict_and_reasoning` | Verifier 看不到 Analyzer provider/model、score、verdict、reasoning；保留原子 Claim 与证据 |
| 程序校验 | count/time/hash/host/entity/process/session assertions | 字段存在且同类型比较才 valid；不存在 evidence/字段或矛盾为 invalid；不存在 evidence reference=0 |
| 确定性优先 | invalid assertion + Verifier/Adjudicator 支持对照 | 模型不能把 deterministic invalid 改为 supported；输出无效或保留 conflict/human review |
| Assurance | 无 Verifier、同模型、异模型、双 Verifier 对照 | required+missing=`unreviewed`；same model<=Basic；cross-model=Enhanced；多独立 Verifier且无未解决冲突=High |
| 冲突与裁决 | verdict/evidence/missing-review/deterministic conflict 对照 | 无 Adjudicator 时降低 assurance 且 `human_review_required=true`；裁决只能处理已检测 conflict |
| 共享预算 | Analyzer→Verifier→Adjudicator | 默认总 run 数<=3；tool/cost/context 同样共享；后续失败保留 Analyzer/确定性结果 |
| 注入与工具 | malicious Claim/full-log/tool call 对照 | 恶意文本只在 untrusted input；未知写工具在数据源前拒绝；普通整日志触发文本保持零 Provider/Tool 调用 |
| 模型历史 | 两个 Verifier 不同 routing score | tenant-scoped history 只改变候选顺序；高 score 不提高事实权限或同模型 assurance 上限 |
| 追加写记录 | `test_ai_review_repository.py` | program、slot/report/review、conflict、adjudication/resolution 精确绑定同 tenant/task/revision/Claim |
| PostgreSQL/租户 | `tests/integration/test_ai_review_persistence.py`（待 Linux VM） | 迁移 0010、三角色 runs、全部 P8 行、终态 replay=1、跨租户读取/Tool 拒绝 |
| 真实 Provider/Linux VM | 尚无 | Kimi/GLM/custom adversarial input、双租户 HTTP、并发计费/预算和金标 assurance 校准完成后关闭 P8 |

## P9 恶意文件、隔离区与沙箱报告追踪矩阵

| 要求 | 当前动态验证 | 通过标准 |
|---|---|---|
| 加密隔离 | `test_malware_quarantine.py` key/tenant/ref/密文篡改对照 | AES-GCM AAD 绑定 tenant/hash/object；落盘无明文；错误 key/tenant/ref/密文失败；无 get/export 方法 |
| raw upload | `test_malware_api.py` Content-Length/chunked/真实 ASGI upload | 两种传输均不能越过 byte bound；空/编码 body 拒绝；文件名只作元数据；response/OpenAPI 无 ref/download/export |
| 静态解析 | `test_malware_static.py` script、truncated ELF、ZIP/TAR adversarial metadata | 不执行/不提取；entry/size/ratio/string/path/link 越界明确记录；超 entry ZIP 在 central-directory parse 前停止 |
| scanner coverage | 无 scanner、单 fake scanner、YARA-X+ClamAV fake 对照 | 未配置显式 unavailable；零命中不伪造 clean；单命中最多 suspicious/family candidate |
| 多信号结论 | scanner/scanner 与 scanner/context 对照 | malicious 至少两个 positive source 且一个 malicious；具体 type/family corroborated 至少两个 source；context 不能命名 family/type |
| 上下文关联 | 同 hash 的 creator/executor/parent/source/destination/persistence/Host | 查询同 tenant+hash 的完整有界 context；跨 Host/path/domain 可见；跨 tenant/sample domain validation 拒绝 |
| worker 隔离 | `test_malware_worker.py` transaction-depth 对照 | API 不启动 worker；独立进程 claim 后提交；解密/解析时 transaction depth=0；稳定 error code，不记录样本/错误原文 |
| lease/持久化 | 迁移 0011 + `test_malware_persistence.py`（待 Linux VM） | SKIP LOCKED、lease token/expiry/retry、report scope/hash/size、normalized engine rows、审计及跨租户 FK 全部通过 |
| sandbox import | `test_malware_sandbox.py` signature/sample/destroyed 对照 | 仅受信 Ed25519 key；tenant/sample/hash 精确绑定；环境销毁为 true；Schema/size/artifact 引用受限；文本仍 untrusted |
| 动态隔离/Linux VM | 尚无 | 独立虚拟化集群、默认 no egress、按任务 controlled/simulated network、凭据隔离、逃逸/资源耗尽、任务销毁和报告重放门禁完成后关闭 P9 |

## P10 跨主机图谱、技术溯源与导出追踪矩阵

| 要求 | 当前动态验证 | 通过标准 |
|---|---|---|
| entity canonicalization | `test_trace_builder.py` Host/process/user/file/IP/session 对照 | process 纳入 Host+boot+PID；path-only file 纳入 Host；稳定重放 entity/edge ID；无 self-loop/悬空 endpoint |
| seed 连通分量 | 同文件顺序反转 + isolated Incident | 输入顺序不影响 report；只有 exact observable/session 连通的 Incident 保留；无关系第三 Incident 不进入 |
| 初始入口 | Web injection seed + missing-entry 逻辑 | 只从有限 evidence-backed rule mapping 选最早 entry；缺少时为 null+limitation，不补全理论路径 |
| 跨主机/横向 | Host A outbound + Host B same session + success follow-up | two-sided session 单独最多 `communicates_with`；只有 target success corroboration 才为 `lateral_to`/lateral step |
| 影响范围/key path | entry→shell→session→target activity | 两 Host 均在 graph/impacted scope；每个 step 绑定 source/target/time/state/evidence；引用不存在为 0 |
| ATT&CK | current rule→`p10-attack-map-v0.1.0` | 只输出有限 mapping、observed/inferred、rule IDs 和 evidence；mapping 不提升 AttackState 或身份 |
| 基础设施 cluster | exact IP/domain/cert/file hash 跨 Incident/Host | similarity basis 只能 exact_observable_match；ASN/geo/language/model 不参与；单点不伪造 cluster |
| 身份归因 | domain/OpenAPI/ASGI tests | `status=not_attributed`、assertion_count maximum=0、assertions maxItems=0；任意 assertion validation 失败 |
| 图查询 | root/depth/node/relationship allowlist | root 必须存在；depth≤8、nodes≤1000；max nodes 显式 `truncated`；无任意 SQL/URL/file 参数 |
| 调查导出 | canonical hash + ASGI export | tenant/trace/revision/evidence count 一致；SHA-256 可复算；raw_content/sample_content=false；写 export+audit |
| 版本/持久化 | `test_trace_repository.py` + migration 0012 | exact replay no-op；late/source change append；source Incident/evidence、edge/technique refs 全部 composite FK；audit 不复制 evidence index |
| PostgreSQL/租户 | `tests/integration/test_trace_persistence.py`（待 Linux VM） | 两 Host chain 落库、replay=1 revision、export=1；另一 tenant 无行；直接伪造 FK/并发 build/export 失败或幂等 |
| 真实攻击/Linux VM | 尚无 | Web/SSH entry、成功/失败横向、one-sided、NAT/proxy/jump host、公共基础设施反例、迟到/乱序/重复和大图门禁完成后关闭 P10 |

## P11 响应、审批与控制台增量矩阵

| 要求 | 当前动态验证 | 通过标准 |
|---|---|---|
| 策略门控 | `test_response_policy.py` R1/R2/R3、AttackState、criticality、assurance 对照 | 模型保证不提升权限；R3 非确认失陷/未解决审核/无回滚均拒绝；关键资产双审批 |
| 审批与 RBAC | `test_response_rbac.py`、`test_response_repository.py` 请求人/审批人/双审批对照 | 角色来自服务端 credential；请求人不能自批；相同审批人不能重复；R3 业务确认完整 |
| 固定 Adapter | `test_response_adapters.py` typed target、argv、path、PID generation 对照 | 无 shell 字符串；目标变化写入前拒绝；执行/验证/回滚结果结构化且 fail closed |
| Worker 租约 | `test_response_worker.py` fake Adapter + transaction-depth instrumentation | 高权限调用期间无数据库事务；lease/worker/target 变化失败；结果只能由有效租约提交 |
| 本机原生边界 | `test_response_native.py` local/remote binding、三类 stateful fake backend、argv/output bound | 只接受私有 Agent config 对应 tenant/host/agent；远端目标在命令前拒绝；root/非 allowlist/低 UID 账号拒绝；无 shell、命令输出/超时有界 |
| 未知状态分类 | `test_response_adapters.py`、`test_response_worker.py` execute/verify/commit fault injection | 写入后超时或 post-check 失败为 verification_failed；result commit 失败不伪造成已知 action failure，租约留待保守恢复 |
| API 租户边界 | `test_response_api.py`、`test_console_api.py` authenticated tenant/role 对照 | caller header/body 不能覆盖 tenant；auditor 不能写；执行默认禁用时 fail closed |
| Schema/持久化 | migrations 0013-0016 + `test_response_persistence.py`、`test_notification_persistence.py`、`test_rule_lifecycle_persistence.py`、`test_ingest_mtls.py`（待 Linux VM） | action 绑定精确 Incident/evidence/Host；审批、执行、回滚、事件、审计/outbox/attempt 租户一致且并发幂等；heartbeat version 列可空且身份绑定；rule state/event/shadow FK、sequence、并发、重放与 dedupe version 约束闭合 |
| 通知租约/重试 | `test_notification_repository.py`、`test_notification_worker.py` | claim 使用 digest-only lease 和 SKIP LOCKED；HTTP 期间 transaction depth=0；过期 lease 先恢复、指数退避有上限、耗尽或永久失败进入 DLQ |
| Webhook 边界 | `test_notification_webhook.py` + `test_config.py` | URL 只来自配置且 host 精确 allowlist；非 loopback HTTPS；无 userinfo/query/fragment/redirect；响应大小/超时有界；HMAC、幂等 ID、字段最小化可复算 |
| 控制台代理 | `console/tests/rendered-html.test.mjs` + production build | 不保留 token/nonce；固定 Snapshot/Incident/evidence/attack-trace/malware/rule/model/system/response operation path；ID 精确；非 loopback HTTPS；无 redirect；请求/响应/超时/content-type 有界 |
| Incident 调查 | `test_console_repository.py` + `test_console_api.py` + console production worker requests | 当前 revision 读锁；tenant/Incident/evidence membership；100/200/400 固定 DB 上限；时间线/Claim/实体边证据链接；normalized payload React 转义；不按 raw_ref 取任意对象 |
| 攻击溯源调查 | `test_console_repository.py` + `test_console_api.py` + Schema/OpenAPI + console production worker requests | responder/approver/auditor 且必须有 tenant；tenant+seed Incident 查询对 current trace pointer 持 `FOR SHARE`，再校验 revision/report scope/canonical snapshot hash；50/100/100/100/50/50/200/400 上限、每对象 8 条引用样本、截断计数、结论 evidence 与 graph endpoint 闭合；无 raw_ref/raw bytes/entity attributes/identity assertions；fixed exact route 且拒绝 query/path substitution，interactive query/export flags=false |
| 恶意文件调查 | `test_console_repository.py` + `test_console_api.py` + console production worker requests | sample read lock；tenant+sample/hash/task/engine 绑定；50/8/8 固定 DB 上限和字段级缩减记账；无 quarantine_ref/sample bytes；source_url 仅作文本 |
| 规则治理目录 | `test_rule_governance.py` + `test_rule_lifecycle.py` + `test_console_repository.py` | 九条 runtime rule 与 catalog 的 ID/version/applicable source 必须完全一致；owner/source/dataset/误报预期/ATT&CK/suppression/rollback 非空；签名 current state/effective scope/manifest/key/catalog/Canary/validation 与 governed/legacy/shadow 指标如实显示；质量字段不伪造 |
| 规则/情报只读 API | `test_console_repository.py` + `test_console_api.py` + Schema/OpenAPI + production worker requests | responder/approver/auditor 且必须有 tenant；hit/history/feedback SQL 均 tenant-scoped，feedback 只经当前 Incident revision membership；历史≤64、cache≤50、field names≤16；无 payload value；fixed exact path 且拒绝 query/path substitution |
| 签名规则生命周期 | `test_rule_lifecycle.py`、`test_rule_lifecycle_repository.py`、`test_detection_worker.py`、`test_rule_lifecycle_api.py`、`test_rule_lifecycle_persistence.py`（PostgreSQL 待 Linux VM） | Ed25519 key/tenant/rule/version/catalog/dataset/time 绑定；sequence+previous hash 防重放；Draft→Shadow→Canary→Released、逐级 rollback/deprecate/upgrade；Canary Host 租户隔离；Shadow 不入 detection/Incident；缺失/过期/漂移 fail closed；无 unsigned mutation |
| IOC 负向门禁 | contract/UI source assertions | `managed_ioc_lifecycle_available=false`；cache visibility 不能描述成受管 IOC；实现跨租户 IOC ownership/expiry/disable/audit 前不得关闭 |
| 模型运营只读 API | `test_console_repository.py` + `test_console_api.py` + Schema/OpenAPI + production worker requests | responder/approver/auditor 且必须有 tenant；review task/run/group SQL tenant-scoped；aggregate≤100、recent≤50 并保留总数/截断；key/base URL 仅给出配置状态，不返回值、Prompt、request/response/evidence package；fixed exact path 且拒绝 query/path substitution |
| 模型健康/质量负向门禁 | contract/UI source assertions | credential validity=`not_tested`、Provider health=`not_probed`；三个 availability flag 固定 false；无金标 linkage 时 precision/recall/agreement/FPR 为 null，不能用成功率、人审数量或 assurance 冒充质量；Linux VM 上另验真实 Provider timeout/circuit/recovery、credential probe 与 audited labeled feedback |
| 系统运营只读 API | `test_console_repository.py` + `test_console_api.py` + Schema/OpenAPI + production worker requests | 仅 auditor/tenant_admin 且必须有 tenant；credential≤100、latest heartbeat Host≤1000 并保留总数/截断；normalize/malware/response/notification 状态计数闭合；tenant SQL、fixed exact path、拒绝 query substitution；无 token/digest/error detail |
| Agent 版本 heartbeat/目录 | `test_agent_runtime.py`、`test_agent_process.py`、`test_transport.py`、`test_ingest_mtls.py`、`test_console_repository.py` + contract/UI assertions | 新 runtime 报告有界 semver，旧 heartbeat 可省略、畸形值拒绝；接入持久化复验 mTLS tenant/Agent/Host；目录只取当前 Host-Agent 绑定，排除被替换身份，版本组≤50 且计数闭合；来源为 self-reported，binary integrity=false |
| 系统遥测/升级负向门禁 | contract/UI source assertions | persisted record count 不冒充容量，Agent heartbeat queue 不冒充 broker depth/backlog age，自报版本不冒充运行二进制或签名制品证明；database/object capacity、dependency probe、deployment inventory、human user directory、signed artifact/upgrade/rollback/backup evidence 固定 unavailable；migration 只报告 observed version，compatibility=`not_evaluated` |
| 控制台写入 | production worker request tests + `test_response_api.py` | Origin/Referer fail closed；nonce HMAC 绑定 origin+Bearer 且有 TTL；字段白名单；queue/rollback 幂等；后端 tenant/RBAC/自审批/状态机/执行开关权威 |
| 依赖安全 | `npm audit --omit=dev` | production dependency 漏洞为 0；无修复的 build-time 公告记录输入边界与重开条件 |
| 原生回滚/Linux VM | 尚无 | 至少三类动作在真实 Linux 通过重验证、执行后验证、重复请求、故障注入和可观测回滚 |

## 数据集要求

每个场景至少包含正常、失败攻击、成功攻击、弱信号、数据缺失、时钟偏差、乱序和重复变体，并记录生成脚本、来源、许可、版本与哈希。调优集与最终验收集隔离；Schema、规则、Collector、Prompt 或模型路由变化必须触发受影响数据集回放。

## 安全验证原则

涉及认证、授权、对象所有权、租户隔离、状态机和响应权限时，必须使用至少两个身份、两个租户或两个对象进行动态对照。错误码、静态路由、扫描器命中或模型判断仅作为线索，不能替代真实请求、状态和审计证据。
