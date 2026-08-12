# P5：主机运行时、Falco/audit/eBPF 与行为链

状态：第三个增量已实现真实 audit.log 文件 Collector 代码和跨 worker 回看恢复；原生 Linux
auditd/Falco/eBPF、攻击仿真和发行版门禁仍未动态验证。
计划来源：项目计划书第 18 章“P5 主机运行时与行为链”，以及 §3 能力等级、§8.2 主机检测场景。

## 2026-08-08 已实现的离线增量

- `FalcoNormalizer` 接受 Falco JSON output，将 exec/connect/file 事实映射为版本化 `SecurityEvent`；保留 PID/PPID、父进程名/路径、命令行、用户、网络、文件、Falco rule/priority 和 `raw_ref`。
- 显式事件类型优先于进程附带字段：带进程上下文的 `connect` 仍是 `network.connect`，不会误分类成 `process.exec`。
- `WebProcessShellRule` 只在受信运行时事件表明 nginx/apache/httpd/php-fpm/gunicorn/uwsgi/caddy 直接派生 shell 或解释器时命中。
- 该规则最高只给 `suspected_success`，并要求继续关联触发请求、父 PID、文件写入和外联；单一 Falco 事件不直接产生 `confirmed_compromise`。
- 单元测试覆盖 Falco exec/connect/DLQ、Web→shell 正例、非 Web 父进程和正常 worker 反例；规则已注册到实时 detection worker。
- Agent 侧新增有界 `AuditdSerialAggregator` 与严格 `AuditdSerialGroup` 契约：允许 serial 交错，只有末尾 `EOE` 才标记完成；open-serial/record 超限或关闭 flush 均输出不完整组供 DLQ 审计，不静默丢弃。
- `AuditdNormalizer` 校验 trusted `boot_id`、声明/原文 record type 和每条 serial，合并 `SYSCALL/EXECVE/PATH/CWD/PROCTITLE/SOCKADDR/USER_*`；解析 quoted、十六进制 argv/proctitle、PAM 嵌套字段、相对路径和 IPv4/IPv6 sockaddr。
- `aisoc-agent run` 现在按显式 run-once 循环驱动 `AuditdCollector`，不会依赖隐藏线程。文件 tail
  只接受非链接普通文件，等待完整行，检测 inode rotation/可观察 truncation，并把 cursor 与尚未到
  `EOE` 的 serial 组一起原子 checkpoint；重启测试证明半组可恢复且 sequence 不复用。
- `LocalDiskQueue` 在同一 SQLite 元数据库中持久分配每个 boot 的 sequence 高水位；手工入队会推进
  floor，旧队列还会从保留的 ACK 审计恢复已使用 sequence。分配与入队之间崩溃只产生 gap，不复用。
- 完整 audit serial 作为 P2 规范事件入队；超时、容量淘汰、坏行、解析失败和 boot transition 作为
  P1 `collector.auditd_gap` 入队并保留完整原始行。Heartbeat 能力同时报告 queue/kernel/tail drop、
  kernel/open-serial backlog、parse error 和 incomplete 计数；无法读取 `auditctl -s` 时明确 degraded。
- Falco/auditd 事件记录 `clock_offset_ms` 并对超过 5 分钟的源时钟标记 `skew_detected`；Falco 另保留 process start time 和 file flags。
- 序列规则按 `tenant + host + boot_id + PID + latest exec generation` 处理 PID reuse，并实现下载→写入→chmod→执行、Web→shell→外联、cron/systemd/authorized_keys 持久化和单进程横向扫描。
- 序列信号最高为 `suspected_success`；横向连接扫描为 `attack_attempt`。失败 syscall、缺源、跨 boot、PID reuse、包管理器和低于阈值运维反例均不会被写成确认失陷。
- detection lookback 默认提高到 600 秒并强制覆盖 2×突发窗口与完整 host-chain 窗口；长路径/长 generation ID 使用有界实体键，避免落库前契约失败。
- DetectionWorker 每轮从不可变 normalized DB 读取完整 600 秒窗口，因此新 worker 可重建跨批次
  P5 链；查询按最新事件降序取 `max_events + 1`，默认上限 20000，超限会显式失败而不是用截断窗口
  静默作出规则结论。
- 新增 5 组 P5 哈希固定回放：正常、失败、成功、缺源和超窗口时钟偏差。成功集包含乱序 `1/3/2` 与重复事实，稳定还原 5 个预期检测；其余四组均为 0。

## 当前边界

- 本轮没有启动 Docker，也没有把 Falco、auditd 或 eBPF 探针加载到宿主；AuditdCollector 只在
  临时普通文件和可注入 `auditctl` 状态上验证，不构成原生 Linux auditd 通过证据。
- audit.log 文件 tail 已接入 Agent，但还没有证明真实发行版输出、rotation/copytruncate、EOE/超时、
  kernel lost/backlog、权限、字段变体和高 EPS 行为与当前契约一致；netlink Collector 也未实现。
- 没有 DEB/RPM/systemd、CAP_BPF/CAP_PERFMON、BTF、LSM 或 L1/L2 实机证据；不得声明任何发行版 L2 通过。
- Web 请求与主机 PID 还没有 P6 级实体关联；当前 `suspected_success` 是主机行为信号，不等价于已证明某个 HTTP 请求成功利用。
- 规则仍依赖完整回看窗口中的最新 exec generation 防 PID reuse；当真实 Collector 缺少 exec 时会
  保守地不关联。worker 重启可从 DB 重建窗口，但尚无高 EPS 增量状态；超过 20000 个窗口事件会
  fail closed，真实 PostgreSQL 跨 poll/重启行为留到 Linux VM 验证。

## 下一增量

1. 在 Linux VM 上用原生 auditd/auditctl 动态验证文件权限、EOE/超时、rotation/truncation、重启/换 boot、
   kernel lost/backlog 和上传原文，再决定是否增加 netlink 接口。
2. 在真实 PostgreSQL 高 EPS 窗口验证跨 poll/worker 重启重建、同 PID reuse、迟到/重复事实和 20000
   上限告警；需要更高容量时再引入可恢复增量 generation 状态，不能静默截断。
3. 在授权隔离 VM 中执行成功/失败攻击和正常发布/配置管理，采集原始 Falco/auditd 证据并对照离线回放。
4. 关联 Web request 与 host PID/时间窗，验证具体请求、下载字节/哈希、外联和持久化结果后才允许更高结论。
5. 在 Ubuntu/Rocky/Debian 等真实 Linux VM 上验证 L1 降级、Falco/auditd 接入和至少三种发行版的 L2 能力；记录 drop、CPU/内存和已知限制。

## 阶段退出条件

- [ ] 至少三种发行版 L2 能力通过，且 L1 降级结果明确可审计。
- [ ] 父子进程、文件、账号、cron/systemd 和网络事实均可由真实 Collector 上传。
- [ ] Web→shell、下载执行、持久化和横向扫描的成功攻击链可从原始证据稳定还原。
- [ ] 正常运维、备份、发布和数据源缺失反例不会被写成确认失陷。
