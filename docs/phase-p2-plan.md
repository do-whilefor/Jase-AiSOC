# P2：Linux Agent、能力探测、缓存与身份

状态：进行中（实验主线；P0/P1 尚未正式 Accepted）  
阶段目标：构建可按真实宿主能力启用或降级的 Linux Agent 基础，并使断网、身份和升级
边界可验证。

## 工作包状态

| 工作包 | 当前实现/要求 | 状态 |
|---|---|---|
| 平台事实探测 | 安全解析 `os-release`，识别 init、内核、架构、BTF、cgroup、LSM | 已实现 |
| Collector 能力报告 | journald/auditd/eBPF 显式 enabled/degraded/failed、drop_count、last_error | 初版完成 |
| 诊断 CLI | `blue-team-probe-platform` 输出 CapabilityReport v0.1.0 JSON | 已实现 |
| Agent 框架 | AgentEnvelope、Heartbeat、Batch/ACK；确定性生命周期、真实进程入口、单实例锁和本地 journal | 初版完成 |
| 本地可靠队列 | SQLite 事务缓存、优先级背压、批次租约、重放、损坏隔离和丢弃审计 | 初版完成 |
| Agent 身份 | 一次性注册、P-256 mTLS 证书、轮换/吊销/重注册、软件机器绑定和并发租约 | 初版完成 |
| 策略与升级 | 签名、防降级、灰度、回滚审计、健康门控 tar 事务及有界候选进程 supervisor；下载器/systemd/策略激活未接入 | 部分实现 |
| Linux 制品 | 自包含 tar.gz、DEB、RPM、systemd 与离线依赖 | 待实现 |
| 兼容门禁 | Ubuntu/Debian、Rocky 及后续矩阵的安装/采集/降级报告 | 待验证 |

## 已验证行为（2026-08-04）

- 解析器拒绝重复键、NUL、未引用空白和超限输入，不执行 `$()` 等 shell 表达式。
- Windows 单元测试使用可注入的虚拟 `/etc`、`/proc`、`/sys` 路径验证所有分支。
- Linux 容器 CLI 识别 Debian 13、x86_64、WSL2 内核、cgroup v2 和 BTF。
- 同一容器缺少 journald 与 auditctl 时明确报告 failed；仅发现 BTF 时 eBPF 报告 degraded，
  不把“BTF 文件存在”当成 eBPF Collector 已可用。
- 容器报告保持 L0，并保留 LSM 文件不可读的 probe warning。
- 锁文件安装与非 root 容器构建在新增 CLI 后再次通过。
- Agent、Heartbeat、EventBatch 和 BatchAck v0.1.0 均已导出 Draft 2020-12 JSON Schema，
  `blue-team-export-schemas --check` 会真实检测缺失或漂移，并已加入 CI。
- 队列按单一服务端分配的 tenant/agent/host 身份绑定；事件正文身份、boot_id 或 sequence
  不一致时在入队前被拒绝。
- P0/P1 容量不足时进入 protection mode；P2/P3 的主动淘汰或丢弃记录优先级、输入/
  输出数量、字节数、规则版本、时间窗、数据源和原因。
- 未完整 ACK 的批次不删除任何事件；释放、超时和部分 ACK 后均复用相同 `batch_id`
  和完整性摘要。重复序列仅在规范内容完全一致时幂等，否则报告 sequence conflict。
- 本地损坏内容进入隔离状态并保留完整性审计；不可写数据库不会被误计为“已丢弃”。
- 非 root Linux 容器动态验证：UID 10001、数据库权限 `0600`、进程重启后批次 ID/摘要
  保持一致，完整 ACK 后队列清空且丢弃计数为 0。
- 注册令牌由租户凭据为租户内 Host 签发，仅保存 SHA-256 摘要，具有有效期并在 PostgreSQL
  行锁事务中一次性消费；跨租户 Host 返回 404，无效 CSR 不消费令牌，成功后重放返回 401。
- Agent CSR 必须使用 P-256 并具有有效签名。CA 忽略 CSR 自报的 Subject/SAN，使用服务端记录的
  tenant、host、agent、installation 和 hardware binding 构建 URI SAN；叶证书限制为
  `clientAuth`、`digitalSignature` 和 `CA=false`。
- 真实 Python `ssl` socket 双向 TLS 已验证：CA 签发的客户端证书握手成功，未提供客户端证书
  的连接失败。应用层同时验证 CA 签名、有效期、Subject/SAN、EKU、KeyUsage、序列、指纹、
  公钥摘要和数据库吊销状态。
- 轮换必须用旧证书私钥签署绑定旧证书指纹与新 CSR 摘要的 challenge；成功轮换在同一事务中
  吊销旧证书并清理会话。租户可吊销证书，显式签发新的一次性令牌可重新注册。
- 本地身份文件使用独占创建、P-256 私钥和 `0600` 权限，installation ID 与 machine-id/DMI
  摘要不匹配时报告 clone detected。PostgreSQL 身份行锁会使两个并发会话租约仅一个成功。
- 数据库迁移 head 为 `20260803_0003`，`alembic check` 无漂移。带真实 PostgreSQL 的当前完整
  Windows 门禁为 121 tests passed、8 个 POSIX/链接用例 skipped、总覆盖率 81%；Ruff、mypy、
  Schema 均通过；`cryptography 48.0.1` 的依赖审计无已知漏洞。
- Agent runtime 使用显式 `created → initializing → running/degraded/protection → stopping →
  stopped` 状态机，没有隐藏线程或隐式重启；Collector 只能在初始化前注册，名称重复或运行中
  注册均被拒绝，停止顺序与启动顺序相反。
- 单个 Collector 的 start/health/pause/resume/stop 异常被隔离并进入失败能力报告，不使其他
  Collector 静默消失。Heartbeat 合并平台探测、Collector 动态状态和可靠队列 telemetry。
- 队列进入 protection mode 时，runtime 立即暂停非必要 Collector，保留显式标记为 essential
  的 Collector；队列恢复后再显式 resume。真实 SQLite P0 容量测试证明 P0 未计为丢弃且
  runtime/Heartbeat 同时进入 protection。
- Heartbeat 首次启动立即到期，成功后按固定间隔调度；传输失败不会终止 runtime，而是进入
  degraded 并按短间隔重试。队列 telemetry 读取失败会使用最后一次状态并强制 protection；
  平台探测暂时失败会使用最后一次能力报告并保持 degraded，恢复后才返回 running。
- Linux 锁定环境以 UID 10001、只读源码挂载执行 runtime + queue 测试：18 passed；无权修改
  源码或 Windows `.venv`。
- `blue-team-agent run --config` 现在是真实长运行入口：只读取私有、非链接且有界的 JSON 配置，
  同一状态目录用 `.agent.lock` 阻止第二实例，并将首次 Heartbeat 与 lifecycle 转换以 `0600`、
  fsync-backed JSONL 持久化；SIGTERM 后完成 runtime `stopping → stopped`。
- 候选进程 supervisor 使用绝对可执行路径和固定 `health-probe` argv，`shell=False`、关闭多余
  FD、stdin=`DEVNULL`、清洗环境并新建进程组。候选必须依次输出精确的 started/healthy 协议；
  启动、健康、TERM 和 KILL 分别有独立期限，stdout/stderr 使用合并总量预算。
- Windows 动态负例已覆盖启动/健康超时、崩溃、协议乱序、输出洪泛、argv 字面量和父环境不
  继承。Linux UID 10001 的 43 项相关 pytest 与独立 smoke 进一步证明拒绝 TERM 的进程组会在
  KILL 后被回收、第二 Agent 实例被拒绝、真实 CLI 可干净停止且 journal/队列权限为 `0600`；
  最终镜像为 `blue-team-ai-agent:p2-supervisor-revalidation`，digest
  `sha256:52287cf75a644a8670be48e70765636dacf487ab2297737868945c148fe82e6c`。
- Release manifest 使用确定性 JSON 和 Ed25519 签名；信任键按 artifact kind 授权，payload 的
  SHA-256/长度、manifest 有效期及 Linux 架构/发行版目标均在记录状态前验证。
- 每个 artifact 的 sequence、版本、manifest/payload 摘要和不可降低的安全版本下限跨重启
  持久化；相同 sequence 不同内容、相同版本新 sequence、旧 sequence 和低于安全下限的制品
  均被拒绝。状态写入要求 revision 恰好递增，使用私有临时文件、fsync 和原子替换。
- 灰度选择由 installation ID 与 rollout ID 确定性计算；未选中的制品保持 deferred 且不能
  记录为已应用。降级必须同时存在未过期的 rollback approval，且签名键具有独立回滚权限。
- Windows 动态负例覆盖 payload/签名/manifest/目标篡改、未授权 key/kind、重放、版本复用、
  安全下限、灰度和内存/持久化 stale revision。新构建 Linux 镜像以 UID 10001 完成签名、验证、
  记录和重启加载，状态文件为 `0600`，并真实拒绝根目录和状态文件符号链接。
- 签名 manifest 明确绑定 tar payload format。本地 installer 拒绝绝对/父级/反斜杠/非规范路径、
  大小写碰撞、文件前缀碰撞、空目录、链接和特殊文件，并限制条目数、单文件和总解包大小；
  解包过程不调用 `extractall`，每个普通文件以独占、no-follow 写入并记录独立摘要。
- 安装元数据、内容、进程配置和 JSONL journal 同时拒绝符号链接与多硬链接文件；Linux 动态
  hardlink 对照证明 active 复验会拒绝被第二路径引用的候选内容，journal 不会写入替代目标。
- 候选版本只通过显式 health callback 后才提交 state 与 active pointer；失败恢复旧版本且不触碰
  Agent 队列。install journal 区分 state 提交前后崩溃，恢复时分别删除候选或完成 active 指针；
  孤立 staging/元数据临时文件会在持锁恢复时清理。
- `InstalledReleaseProcessHealthCheck` 从尚未激活的只读 candidate deployment 直接解析清单声明的
  `bin/blue-team-agent`，只调用固定 `health-probe`。Linux 动态升级对照证明健康候选才提交；健康
  超时的下一版本删除候选并保持旧 active/state 与独立队列哨兵不变。
- Release state v2 固定 artifact kind，记录回滚 approval ID、理由和 manifest 摘要，并拒绝审批
  ID 复用。Linux UID 10001 验证跨进程锁、提交前崩溃恢复、归档/安装后/根目录链接拒绝，最终
  可执行文件 `0500`、配置和部署描述符 `0400`、active/state 文件 `0600`。

上述容器结果只证明探测和降级语义可运行，不构成任何发行版的 Certified/Supported 声明。

## 下一批验收任务

1. 将已验证的证书校验和单活会话租约接入后续 mTLS Ingest 的每条认证连接；在接入前，服务层
   不能被表述为端到端的镜像克隆阻断。
2. 将当前文件 Heartbeat journal 接入受超时约束的 mTLS 网络传输，并为 Collector driver 增加独立
   子进程/cgroup supervisor；当前真实 Agent 入口和生命周期审计已接入，但 sink/Collector 调用
   仍是同步接口。
3. 增加批次压缩传输与接入端 ACK/逐事件错误集成；当前仅完成本地逐事件压缩。
4. 将本地 tar installer 接入受超时约束的下载器、systemd 切换和策略激活器；继续验证下载中断、
   kill -9/power-loss during fsync、root-owned updater、签名键轮换/吊销和跨主机灰度停止扩散。
   通用 callback 仍是受信同步接口；生产 Agent 制品路径必须强制使用已验证的进程 health gate。
5. 在磁盘真实接近满、进程强制终止和 SQLite WAL 损坏条件下执行 Linux 故障注入。
6. 在真实 Linux VM 上执行 journald/auditd/eBPF 主动探测，只有真实采集通过后才能将状态
   提升为 enabled 或能力等级 L1/L2。
7. 生成自包含 tar.gz、DEB、RPM、systemd 和离线依赖制品，并在 Ubuntu、Debian、Rocky
   矩阵验证安装、升级、回滚、卸载和能力降级报告。

## 身份边界限制

- 当前硬件绑定是 machine-id 与可用 DMI 字段的软件摘要，不是 TPM/TEE 证明。拥有 root 权限并
  能复制全部硬件标识和私钥的攻击者仍可复刻绑定值；必须依靠短期证书、吊销、重新注册、
  单活租约和异常审计限制其使用。
- 单活租约仅在所有 mTLS Ingest/心跳入口强制获取和续约时才能阻断并发克隆。当前尚无 Ingest
  接口，因此只完成了 PostgreSQL 服务层的并发事务验证，不宣称端到端门禁已经 Accepted。
- CA 文件加载拒绝符号链接和 POSIX 下可被 group/other 访问的私钥；生产环境仍应把 CA 私钥
  移至专用密钥管理/签名服务，并通过 `CertificateSigner` 接口注入。
- runtime 的 `pause/resume` 是受信 Collector driver 契约，不是对恶意同进程代码的强制隔离；
  实际 Collector supervisor 仍必须使用进程/cgroup/权限和超时边界。真实 Agent 进程已把
  RuntimeEvent 写入本地 fsync JSONL，但远端审计传输、轮换/保留与磁盘配额尚未实现。

## 制品验证边界限制

- 当前 installer 只接收已验证的内存 tar payload，完成本地版本目录、process health gate、active
  指针和崩溃 journal；它不负责网络下载、不切换 systemd，也不证明 DEB/RPM 可安装。真实 Agent
  制品可使用有界 supervisor；保留的通用同步 callback 只适用于受信内嵌检查，不能接收不受信代码。
- Installer 对同一安装根使用跨进程文件锁；直接绕过 installer 调用 state store 的其他写者仍
  不共享该锁。本地状态也不能抵抗可修改信任键、程序和状态文件的 root 攻击者；更强边界需要
  服务端状态见证、TPM/不可回退计数器或独立 root-owned updater。
- Linux 冒烟中的 installer 与 Agent 同为 UID 10001，因此 `0400/0500` 只能阻止意外写入，文件
  所有者仍可 `chmod`。生产自保护必须由独立更新身份持有版本树，并让 Agent 仅具读取/执行权。
- `may_authorize_rollback` 是与普通 artifact kind 授权分离的信任能力。生产环境还必须物理分离
  发布键与回滚授权流程，并定义键轮换、撤销、审批 ID 防复用和审计保留策略。

## Ingest 接入（2026-08-04 增补，Docker 级端到端主线）

为关闭黑板中“mTLS Ingest 不存在、租约未在每条连接强制”的唯一 open lead，本轮新增 Agent↔Server
mTLS 接入链路（仍在 P2 实验主线，未改变 P0/P1 尚未 Accepted 的状态）：

- `src/blue_team/ingest_gateway/`：独立 mTLS aiohttp 服务（`blue-team-ingest`），与 `api_server` 共享
  PostgreSQL 与 Agent CA。服务端在每条连接读取客户端证书、调用 `storage/agent_identity.py` 的
  `renew_agent_session` 续期或接管单活租约、再用证书身份重新校验 `EventBatch` 的 tenant/agent/host、
  把每条事件规范字节写入不可覆盖对象存储、登记 `agent_events`/`agent_heartbeats` 与审计、回
  `BatchAck(accepted_sequence=sequence_end)`。身份不符返回带 `identity_mismatch` 的逐事件错误。
- `src/blue_team/agent_core/transport.py`：同步 `httpx` mTLS 客户端，`post_heartbeat`/`post_batch`
  发送 `X-Agent-Session` 并回读续期后的 session value。
- `src/blue_team/agent_core/process.py`：`AgentProcessConfig` 新增可选 transport 配置（ingest_url +
  客户端证书/私钥/CA 路径）；`run_agent_process` 在配置了 transport 时用组合 heartbeat sink（本地
  fsync journal 先写、再走 mTLS）并增加 `reserve_batch→post_batch→acknowledge/release` 上传循环，
  保护模式下暂停上传；未配置 transport 时行为与原先一致（health-probe 与既有测试不受影响）。
- `migrations/versions/20260804_0004_agent_events.py`：`agent_events`（唯一 `(agent_id,boot_id,sequence)`）
  与 `agent_heartbeats` 表。
- 测试：`tests/unit/test_transport.py`（mTLS 客户端 ssl/header/ack/错误，本地通过）；`tests/integration/test_ingest_mtls.py`
  （真实 mTLS + PostgreSQL：enroll→heartbeat→batch→ACK→DB 落库→对象存储→克隆无 session value 被拒 409，需
  `BLUE_TEAM_TEST_DATABASE_URL`，CI/Docker 运行）。

### 仍未完成（P2 退出条件缺口）

- Linux 制品（自包含 tar.gz/DEB/RPM/systemd/离线依赖）与 `scripts/build_agent_artifact.py` 签名制品脚本。**tar.gz + Ed25519 签名脚本已建（`src/blue_team/agent_core/artifact_builder.py` + `scripts/build_agent_artifact.py`），产出可经 `ReleaseVerifier.verify` 通过；DEB/RPM/systemd/离线依赖仍待 VM 矩阵。**
- `deploy/compose/p2.yml` 与 `tests/smoke/linux_ingest_e2e_smoke.py`（Debian + Rocky 容器级端到端）。**compose p2.yml（postgres+migrate+api+ingest）与 smoke 已建；smoke 在 Docker Linux Engine 下已跑通（heartbeat 200、batch_ack 2、clone 409、events 2、sessions 1）。多 agent 容器 + provision enroll 链待后续。**
- 真实 Linux VM 的 journald/auditd/eBPF 主动探测与跨发行版安装/升级/回滚/卸载矩阵。**VM 级 Experimental，留待真 Linux VM。**
- 下载器/systemd 切换/策略激活器接入 installer；批次压缩传输（当前仅本地逐事件压缩）。**下载器（`downloader.py` 流式 + sha256/size 校验）与 install pipeline（`installer_pipeline.py` download→verify→install）已建并单测；批次压缩传输已实现（transport gzip + Content-Encoding，server 经 aiohttp 自动解压）；systemd 切换/策略激活器仍待 VM。**
- gRPC EventStream 按需评估（当前用 mTLS HTTPS + JSON，与 FastAPI/Pydantic 栈一致）。**保持 mTLS HTTPS + JSON；P3 在 stream profile 下接入 NATS JetStream。**

## 批次 B 容器级收尾证据（2026-08-04）

- 批次压缩传输：`transport.py` 发送前 gzip + `Content-Encoding: gzip`；`ingest_gateway/server.py::_read_body` 仅放行 identity/gzip/deflate，其余 415；aiohttp 自动解压 gzip。单测 `test_post_batch_compresses_payload_with_gzip` + 集成 `test_ingest_mtls`（gzip batch + identity clone）绿。
- 自包含制品：`artifact_builder.py`（`build_payload_tar` PAX + 拒绝 symlink/特殊文件、`build_signed_artifact` + Ed25519）+ `scripts/build_agent_artifact.py` CLI；单测 `test_agent_artifact`（产出经 `ReleaseVerifier.verify` READY，symlink 拒绝，Windows skip）。
- 下载器 + pipeline：`downloader.py`（流式 64KiB、超 expected_size 即中止、sha256/size 校验、HTTP 错误包装）+ `installer_pipeline.py`（download→verify→install）；单测 `test_downloader`（happy、sha256/size/exceeds/http 错误、pipeline install + 篡改拒绝）。
- compose + smoke：`deploy/compose/p2.yml`、`tests/smoke/linux_ingest_e2e_smoke.py`；smoke 本地 Docker PG 下跑通（见上）。
- 全门禁：ruff format/check、mypy（86 files）、schema check、pytest（136 passed/9 skipped，skip 全 POSIX/链接/Windows）、pip-audit 无漏洞、SBOM 生成。

### VM 级 Experimental 待验（留真 Linux VM）

- eBPF/auditd/journald 主动探测与 L1/L2 降级、跨发行版安装/升级/回滚/卸载矩阵、全盘克隆跨长窗口验证、DEB/RPM/systemd/离线依赖制品、systemd 切换/策略激活器。

### 安全边界限制（增补）

- 传输用 mTLS HTTPS + JSON 而非 gRPC：与现有 FastAPI/Pydantic 栈一致；serverAuth 叶证书由 CA 在启动时
  签发并写入私有临时目录；客户端 `check_hostname=False`、`CERT_REQUIRED` 校验 CA 链（CA 私有，等同
  pinning）。生产应启用 hostname 校验或固定服务端证书。
- 单活租约仍不能抵抗同时复制了 Agent 私钥与已签发 session value 的全盘克隆；该边界需短期证书、吊销、
  重新注册与真实 VM 克隆验证（见黑板 lead）。
- Agent 传输客户端将私钥临时物化到私有目录以满足 `SSLContext.load_cert_chain` 的文件参数；生产可改用
  专用密钥管理或 in-memory TLS 实现。
