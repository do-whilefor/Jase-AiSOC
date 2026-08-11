# P12 跨发行版硬化、性能、安全与发布

## 阶段边界

P12 是最终发布阶段，以 P0–P11 全部阶段为基础。本阶段不引入新检测、AI、响应或图谱
能力，而是硬化兼容性、性能、安全边界、供应链、升级/回滚、备份恢复和运维就绪度。
退出条件要求全部最终验收标准达到，或有经批准的风险接受记录。

## 安全审计先行

P7–P12 安全审计已于 2026-08-09 完成（见 `docs/security-audit-p7-p12.md`）：

- 8 项漏洞已修复（1 HIGH、2 MEDIUM、5 LOW）。
- 核心安全属性（命令注入、SSRF、Ed25519、AES-GCM、归档安全、租户隔离、Prompt 注入隔离、
  盲审剥离、判决逻辑、预算 fail-closed）全部通过实际代码验证。
- 依赖供应链审计通过（`pip-audit` 无已知漏洞，CycloneDX SBOM 在 CI 中生成）。
- 3 项防御纵深项保留并记录，非可利用漏洞。

## 技术任务

### 12.1 跨发行版兼容与发布链

- 固定 `docs/compatibility-matrix.md` 中每个发行版的精确 `VERSION_ID`、内核范围、架构和
  镜像/ISO 哈希，替换滚动标签。
- 完成 DEB/RPM/tar.gz 自包含制品构建脚本；Agent 制品包含离线 wheel、CA、systemd unit 和
  安装/卸载脚本。
- 验证每个发行版的 journald/auditd/eBPF/Suricata/Falco 能力探测与降级路径。
- CI 矩阵扩展到至少 Debian/Ubuntu/Rocky/RHEL/Fedora 的 VM 级安装/升级/卸载/采集/降级测试。

### 12.2 性能压测与容量

- 消息积压：在高 EPS 下测量 NormalizeWorker/DetectionWorker 的 watermark、迟到语义和
  DLQ 行为；记录 max sustainable EPS、p99 latency 和积压恢复时间。
- 存储保留：验证 Incident/evidence/normalized event/Agent event 的保留策略和清理；
  测量 PostgreSQL 表大小、索引膨胀和 vacuum 效果。
- AI Review 容量：在 30 reviews/minute 限流下验证 token/cost 预算、Provider 超时/重试和
  熔断行为；记录 p99 review latency 和 cost per review。
- 响应执行：验证 lease claim 并发、执行超时和 rollback 在压力下的正确性。
- 对象存储：测量 quarantine 和 evidence 存储的写入/读取/对账和磁盘容量。

### 12.3 安全测试与供应链

- SAST/DAST：对 API 控制面和控制台做自动化安全扫描。
- 模糊测试：对 ingest mTLS、malware 上传、archive 解析、webhook 投递和 graph query 做
  输入模糊测试。
- 租户隔离渗透：两个真实 tenant credential 通过 HTTP 对 Incident/review/trace/malware/
  response/rule 做 ID substitution、并发和跨租户读写对照。
- Prompt 注入：对 Kimi/GLM/OpenAI-compatible Provider 注入 malicious log/Claim/ToolResult，
  验证无未授权工具、nonexistent evidence=0、secret 不进入错误/日志。
- 供应链：`uv lock --check` 无漂移、`pip-audit` 通过、CycloneDX SBOM 作为制品、
  Rust 依赖审计和 `cargo audit`（CI `rust-extension` job 已加 `cargo audit` 步，读
  `Cargo.lock`）。
- `openat` 加固：quarantine 和 evidence 存储的写入与读取都通过 `openat(dirfd, ...)`
  逐组件遍历；写入使用 `O_EXCL|O_NOFOLLOW`，读取使用 `O_NOFOLLOW|O_NONBLOCK` 并要求单链接普通文件。
  静态实现和 Linux 符号链接回归用例已补齐；仍需在隔离 Linux 服务身份下执行 symlink/FIFO/
  并发 rename 故障注入后关闭门禁。

### 12.4 升级/回滚与备份恢复

- 数据库迁移：验证 `base → head` 和 `head → base` 在线迁移（零停机或最短维护窗口）；
  记录每步迁移的锁、耗时和回滚安全。
- Agent 升级：验证 Agent 制品版本升级、配置迁移、heartbeat 自报版本目录和旧版本退役。
- 规则 lifecycle：验证签名 release/rollback、并发首发/重放、跨租户 Canary Host、
  shadow/detection FK 和 rule-version dedupe。
- 响应回滚：在 Linux 单节点 profile 验证 nftables/firewalld TTL、文件隔离和账号禁用三类
  真实可验证回滚；对 PID 复用、inode/path replacement、账号状态变化、nft set 缺失、
  进程崩溃、租约过期和重复请求做故障注入。
- 备份恢复：PostgreSQL 逻辑/物理备份与恢复验证；对象存储备份与对账；
  记录 RPO/RTO 和一致性报告。

### 12.5 运维就绪

- 运维手册：安装、配置、启动、停止、健康检查、日志、升级、回滚、备份、恢复、
  故障排查和容量规划文档。
- 监控告警：Prometheus metrics（freshness、queue depth、error rate、cost budget、
  lease reclaim）、仪表板和告警规则。
- 控制台 HTTPS 验证：在真实反向代理 + HTTPS 浏览器/API 上验证所有 console 读写操作的
  租户授权、CSRF/Origin、幂等和服务端 RBAC。
- 通知投递：连接真实 HTTPS 接收端，验证双 worker 并发 claim、DNS/证书/超时/429/5xx/
  redirect/超大响应、签名轮换、重放幂等和 DLQ 运营。
- Go/No-Go 评审：全部验收标准对照检查，记录通过/风险接受/阻塞项。

## 交付物

- V1.0 制品：DEB/RPM/tar.gz for each supported distro；容器镜像；SBOM。
- 兼容报告：固定版本的兼容矩阵和每个组合的探测/安装/降级结果。
- 性能报告：EPS、latency、容量、cost per review 和积压恢复基准。
- 安全报告：安全审计报告（已完成）、渗透测试结果、模糊测试结果、供应链审计。
- 运维手册：部署、监控、升级、回滚、备份恢复和故障排查。
- Go/No-Go 决策记录。

## 退出条件

- 全部最终验收标准达到，或有经批准的风险接受。
- 至少三类响应动作可验证回滚。
- 两个真实租户通过 HTTP 验证租户隔离、并发和幂等。
- 安全审计无未修复的 HIGH/MEDIUM 漏洞。
- 兼容矩阵中每个 Certified 组合在持续 CI 中通过。
