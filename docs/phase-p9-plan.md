# P9 静态恶意文件、隔离存储与独立沙箱接口

## 当前结论

P9 已完成非 Docker 基础实现，但阶段门禁未关闭。当前实现覆盖独立加密隔离区、受限静态
检查、多信号结论、文件上下文关联、租户作用域 API、租约式独立 worker、签名沙箱报告导入
契约及迁移 `20260809_0011`。**YARA-X 已接入真实 `yara-x` Python 包**（`malware_engine/yara_x_scanner.py` 的 `YaraXAdapter`：从配置的规则文件/目录编译、线程内扫描、匹配输出为 `SUSPICIOUS` 单点信号并提取 `family`/`malware_type` 元数据；`__main__` 在 `malware_yara_x_rules_path` 配置时构造该 adapter，未配置时仍回退为 `builtin-yara-x=not_configured`，由 `tests/unit/test_yara_x_scanner.py` 在真实 yara-x 上验证）。ClamAV、真实信誉源、动态沙箱、PostgreSQL 并发、
双租户 HTTP、Linux 不可执行挂载与 Kali 逃逸/外联门禁尚未动态验证。

因此当前 P9 状态仍是 `technical_hit / unrated`，不能把本地单元测试、fake scanner 或离线 DDL
编译解释为恶意程序识别能力已经验收。

## 强制信任边界

```text
authenticated tenant
        |
        v
bounded raw upload API -- hash/encrypt only --> AES-GCM quarantine (D3)
        X                                      |
        | no sample read/export                | internal read_for_scan
        | no static/dynamic interpretation     v
        +-------------------------- standalone static worker
                                                  |
                          structured engine/context report
                                                  v
                                             PostgreSQL

separate VM/isolation cluster -- signed structured report --> verifier/import API
          (not implemented)          ^
                                     untrusted text; Schema/size/scope/signature checks
```

- API server 只接收有界原始 body，计算隔离存储所需 hash 并加密写入；不执行静态解释，不启动
  malware worker，也不提供样本下载/导出路由。
- `blue-team-malware-worker` 是独立进程角色。它在短事务中 claim lease，提交后才解密/检查，
  最后用新事务保存结果；扫描期间不持有数据库锁。
- Endpoint Agent 不读取、不解释、不执行样本。
- 动态执行不属于静态 worker。当前仓库没有样本执行代码、通用 Shell、任意文件/HTTP 工具，
  也没有把动态行为交给 AI 补全的路径。
- 隔离沙箱只能导入 Ed25519 签名的结构化报告。报告必须绑定 tenant/sample/SHA-256，证明任务
  环境已销毁，并通过字段数、字符串长度、artifact 引用和总 body 大小限制；报告文本仍是不可信数据。

## 已实现能力

### 隔离存储

- `LocalQuarantineStore` 使用独立 32-byte base64url 配置密钥和 AES-256-GCM。
- AAD 同时绑定格式版本、tenant、SHA-256 和 object ID；换 key、换 tenant、改 ref 或修改密文均失败。
- `quarantine://` 引用只进入内部持久层，不进入 API response、日志或审计 after 字段。
- 文件独占创建，目录/文件尝试设置为 `0700/0600`，拒绝符号链接根和越界路径。
- 协议只有 `put` 与内部 `read_for_scan`，没有 `get`、download 或 export 方法。

Windows 单元测试只能证明密文、AAD、路径和接口边界，不能证明 Linux mount 的 `noexec/nodev/nosuid`
或服务账号 ACL；这些留待 Kali/部署门禁。

### 静态检查

- SHA-256、大小、声明/检测 MIME、Shannon entropy、有限 ASCII strings。
- ELF/PE header、script shebang、gzip、ZIP 和 raw TAR 识别；不加载二进制、不调用解释器。
- ZIP 在调用标准库 central-directory parser 前先读取 EOCD 并限制 entry count/offset/size；从不解压。
- TAR 只顺序解析 512-byte header；不处理压缩 TAR、不提取文件。
- archive 对 path traversal、绝对/drive path、link、加密 entry、总解包大小、压缩比、entry 数和
  越界元数据给出结构化 violation。

### 扫描与结论

- `SampleScanner`、`YaraXScanner`、`ClamAvScanner` 和 hash-only `ReputationProvider` 是窄接口，
  不暴露通用命令、SQL、文件或 HTTP capability。
- 未配置 YARA-X/ClamAV 时，报告明确记录 `unavailable/not_configured`，不能生成 clean 结论。
- 单一 scanner 命中最多得到 `suspicious` 和 family `candidate`。
- family 或 malware type 必须由至少两个不同 `source_id` 支撑；否则 domain validation 拒绝
  `corroborated`/具体 type。
- `malicious` disposition 至少需要一个 malicious signal 和第二个独立 positive source。
- creator/executor/parent/source URL/destination/persistence 及同 hash 跨 Host/path/domain 参与上下文关联，
  但上下文本身不能命名 family/type。
- 未导入动态报告时，输出固定说明 `Dynamic analysis was not performed; the isolated sandbox is disabled.`

### 持久化与 API

- 迁移 `20260809_0011` 新增：
  - `malware_samples`；
  - `malware_file_contexts`；
  - `malware_scan_tasks`；
  - `malware_scan_engine_results`；
  - `malware_sandbox_reports`。
- scan claim 使用 `FOR UPDATE SKIP LOCKED`、lease token、到期回收、attempt 上限和有界 backoff。
- normalized engine rows 与完整结构化 report 同时保存；完成前重新验证 tenant/task/sample/hash/size。
- API：
  - `POST /api/v1/malware/samples`：raw body 隔离并排队；
  - `GET /api/v1/malware/samples/{sample_id}`：只返回元数据；
  - `POST /api/v1/malware/samples/{sample_id}/scans`：重新排队；
  - `GET /api/v1/malware/scan-tasks/{task_id}`：读取状态/报告；
  - `POST /api/v1/malware/samples/{sample_id}/sandbox-reports`：导入受信签名报告。
- 不存在 sample content、download、export API。

## 配置与进程

默认关闭：

```bash
export BLUE_TEAM_MALWARE_ANALYSIS_ENABLED=true
export BLUE_TEAM_MALWARE_QUARANTINE_ROOT=/var/lib/blue-team/quarantine
export BLUE_TEAM_MALWARE_QUARANTINE_KEY='<32-byte base64url secret>'
export BLUE_TEAM_MALWARE_WORKER_ENABLED=true
uv run blue-team-malware-worker
```

不要在 API 进程中运行 worker。生产部署还必须把 API、静态 worker、quarantine 和动态沙箱拆成
独立 service identity/network/mount；动态沙箱必须使用独立虚拟化集群、默认无外联、逐任务环境
销毁和单独签名 key。

## 本地证据

- quarantine：明文不可见、错误 key、跨 tenant、改密文、无 export 方法。
- static：script/ELF、ZIP entry 上限/高压缩比/traversal/link、raw TAR traversal/link、strings 上限。
- verdict：无 scanner、单 scanner、YARA-X+ClamAV、scanner+context、family/type corroboration。
- sandbox：有效签名、错 sample、未证明环境销毁。
- API：chunked/Content-Length 超限、真实 ASGI raw upload、response 不泄漏 ref、落盘仅密文。
- worker：扫描期间 transaction depth 为 0；integrity failure 只持久化稳定 error code。
- schema：`malware-analysis-v0.1` 和 `signed-sandbox-report-v0.1`。
- migration：single head `20260809_0011`；base→head 和 0011→base offline SQL 成功；五张 P9 表
  PostgreSQL DDL compile 成功。
- `tests/integration/test_malware_persistence.py` 已提交，但没有
  `BLUE_TEAM_TEST_DATABASE_URL` 时按设计跳过。

## 未关闭门禁

1. 在 Kali/PostgreSQL 执行迁移、lease reclaim、两个 worker 并发 claim、失败重试及跨租户 FK/API。
2. 接入明确版本的 YARA-X/ClamAV adapter 和规则/签名更新链；用许可的 known samples 与 safe
   simulations 评估目标，同时证明单一命中不能确认 family/type。
3. 将 quarantine 部署到独立加密、`noexec,nodev,nosuid` mount，使用独立服务账号和 secret manager；
   做 DB/磁盘失败、孤儿对象对账、下载缺省拒绝和审计完整性故障注入。
4. 另建动态 sandbox 集群，完成 escape、默认无 egress、simulated/controlled network、凭据继承、
   资源耗尽、任务销毁和签名报告重放/撤销门禁。
5. 用两个真实租户/Host/hash/path/domain 跑完整 HTTP 与 context correlation；当前结果不能关闭 P9。
