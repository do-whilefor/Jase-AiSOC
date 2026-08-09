# P11 响应、审批与安全运营控制台

## 当前结论

P11 已进入非 Docker 初版开发，但阶段门禁未关闭。当前已具备响应动作的严格类型契约、
确定性策略门控、租户内 RBAC 凭据、审批/拒绝状态机、执行租约与幂等记录、目标重验证 Runner
契约、审计/通知 outbox、独立签名 Webhook 投递 worker、控制台 Snapshot/响应动作 API、
version-bound 规则治理目录与 tenant-scoped rule/intelligence 只读 API，以及 TypeScript 安全运营
控制台中基于固定 seed Incident 的 current P10 跨主机攻击溯源、规则运营、无 secret 模型运营、
auditor/admin 系统运营真相视图、响应详情、审批/拒绝、执行排队和回滚请求工作流。

本阶段仍不能描述为“响应执行已完成”：仓库已有独立 `blue-team-response-worker` 和 nftables/
firewalld 临时封禁、普通文件隔离、精确 allowlist 账号禁用的原生初版，但它被限制为读取本机私有
Agent config 的 `local_single_node` profile，不是多主机远程执行器；三类真实回滚证据仍为 0。
控制台当前覆盖总览、Incident、资产、攻击溯源、恶意文件、模型审核、规则与情报、响应队列、系统运营九个视图，并已实现当前 Incident
revision 下的时间线、evidence index/单条 normalized fact、Claim、可见实体/边调查，以及从已验证 seed
Incident 读取 current trace revision 的有界跨主机技术溯源；恶意文件分析/
同哈希来源上下文、九条规则的版本/owner/source/dataset/误报预期/ATT&CK/suppression/rollback、
租户命中与 Incident feedback，以及响应详情与四类受控写工作流。规则运行时现由 tenant-scoped
Ed25519 manifest 控制 Draft/Shadow/Canary/Released/Deprecated，DetectionWorker 对缺失、过期、版本或
catalog 漂移状态 fail closed；受管 IOC 生命周期仍未实现。
模型运营页只陈述配置状态、角色/预算、review outcome 及调用聚合；主动 Provider health、credential
validation 和带金标的 precision/recall/agreement/FPR 均明确不可用。系统运营页只显示持久化 work state、
最近 Agent queue heartbeat、记录/错误/新鲜度计数、运行/迁移版本、当前 Host-Agent 绑定的 heartbeat
自报 Agent version 聚合和无 secret 的操作凭据；该值明确不证明运行二进制或签名制品完整性。broker backlog
age、物理容量、依赖探测、deployment inventory、human user directory、签名升级编排/自动回滚和备份恢复
证据均明确不可用。对象存储原始字节交互尚未实现。
Webhook 当前是非 Docker 初版，尚未连接真实接收端或运行
PostgreSQL/Kali 故障注入，因此不能视为运营集成已验收。

## 信任与执行边界

```text
authenticated tenant/operator role
              |
              v
typed response request -- exact Incident revision/evidence --> deterministic policy
              |                                               |
              | requester cannot self-approve                  +--> approval count / budget
              | model assurance cannot raise permission        +--> fixed adapter ID
              v
append-only action/events/audit/outbox
              |
              v
lease claim -> target identity revalidation -> fixed adapter -> post-check -> rollback
                         (native only when plan == private local Agent binding)

browser session -- memory-only operator token --> fixed same-origin bounded proxy --> Snapshot/detail/trace/rules/models/system
                         |                         Origin + signed nonce --> approval/queue/rollback
                         +-- nonce HMAC binds exact origin + Bearer; no browser storage

notification outbox -> digest lease -> fixed allowlisted URL -> HMAC Webhook -> retry/DLQ
                                (HTTP outside transaction; no redirects or caller URL)

tenant admin -> Ed25519 manifest -> tenant/rule/version/catalog/dataset/sequence verification
                                      |
                                      +-> current state + append-only event/audit
                                      +-> DetectionWorker effective scope (disabled/shadow/canary/all)
```

- `tenant_id`、角色、Incident revision、Host/Agent 绑定和 evidence membership 全由服务端读取。
- R2/R3 的模型保证等级只能增加审批或拒绝动作，不能提高权限；关键资产需要两名不同审批人。
- 请求人不能审批自己的动作；R3 需要业务确认，且没有已验证回滚的动作会被策略拒绝。
- Action Runner 协议只接收类型化计划和注册 Adapter；固定命令使用绝对路径 argv，不存在 shell
  字符串入口。
- 执行前重新观察完整目标身份哈希，防止 PID 复用、路径/文件替换或 Agent 绑定变化。
- 原生 worker 仅在 Linux/euid 0、execution+worker 双开关、`local_single_node` profile 和私有 Agent
  config 同时满足时启动；plan 的 tenant/host/agent 任一不匹配都在命令前拒绝。多主机远程动作未实现。
- 控制台代理只转发固定 Snapshot、Incident investigation/evidence member、seed Incident attack trace、malware investigation、
  rule/intelligence operations、model operations、system operations、
  response detail、approval、execute 和 rollback 操作，不接受调用方 URL/origin/path；
  `inc_`/`evi_`/`smp_`/`rsa_` ID、JSON 字段、
  8 KiB 请求、1 MiB 响应与 10 秒超时有界，不跟随重定向，
  非 loopback 控制面要求 HTTPS。
- 写请求必须具有匹配请求 URL 的 Origin/Referer 和服务端 HMAC 签发的 write-session nonce；nonce 绑定
  exact origin + Bearer、具有 12 小时 TTL，部署未配置至少 32 bytes 独立 secret 时写入 fail closed。
- 操作员令牌与 write-session nonce 只保存在当前 React 内存，不写入 localStorage、sessionStorage、
  cookie 或前端环境变量；排队/回滚每次生成独立幂等键。
- 浏览器不暴露原生执行开关；服务端租户 RBAC、请求人/审批人隔离、R3 业务确认、状态机和
  `response_execution_enabled` 仍是权威边界。
- 通知 worker 使用独立进程角色；目标 URL/host allowlist 和签名 key 只来自部署配置，outbox/request
  不能改写目标。非 loopback 只允许 HTTPS，拒绝 userinfo/query/fragment/特殊地址和重定向。
- Webhook 使用稳定事件 ID 作为幂等键，HMAC-SHA256 覆盖时间戳与 canonical body；只投递
  `response.action.changed` 的最小字段，不持久化响应 body 或原始异常文本。
- 规则 lifecycle API 只接受受信 Ed25519 key 签名的 tenant-bound manifest；sequence 必须连续并绑定
  previous manifest hash，catalog digest 与完整 validation dataset 集合必须精确匹配。Canary Host 必须
  属于认证租户；trust store 缺失、签名/作用域错误、重放、跳级和旧 hash 均拒绝。

## 已实现能力

### 响应契约、策略与审批

- R1 取证、R2 临时 IP 封禁/文件隔离、R3 进程/账号/主机动作均有闭合的 typed target。
- 策略绑定 Incident 开放状态、确定性 evidence、AttackState、资产关键度、模型审核状态、维护例外、
  action/target 预算、回滚能力和审批数量。
- 响应计划固定到当前 Incident revision 与精确 `incident_evidence`；Host 必须仍绑定请求中的 Agent。
- 审批人必须具有 `approver` 角色、不能是请求人、不能重复决策；关键资产需要两名不同审批人。
- 计划、审批、排队、执行结果、回滚结果和状态事件采用追加写记录，并写入审计与通知 outbox。

### 执行骨架

- `ResponseWorker` 在短事务中领取租约，事务外调用 Adapter，再用租约 token 持久化结果；高权限
  操作期间不持有数据库事务。
- Runner 在执行前验证状态、策略、审批、过期、回滚和 Adapter ID，并比较执行前目标身份哈希。
- `LinuxCommandPlanner` 为 nftables/firewalld、文件隔离、进程、账号动作生成固定 argv；主机隔离
  与证据采集使用结构化 Agent operation。
- 原生命令 runner 使用 `create_subprocess_exec(argv)`、最小环境、绝对 executable、无 stdin/shell、
  10 秒默认 timeout 和 64 KiB stdout/stderr 上限；不持久化命令原始输出。
- nftables/firewalld Adapter 拒绝接管已存在的 block，执行后 query，rollback 对 TTL 已自然到期幂等；
  所需 table/set/daemon 必须由运维预置，worker 不创建或刷新持久防火墙策略。
- 文件 Adapter 仅接受 allowlist root 下的单链接普通文件，使用 O_NOFOLLOW、device/inode/uid/gid/
  mode/hash/size 前后检查、私有 quarantine root 和源/目标占用门禁；账号 Adapter 需要精确 username
  allowlist、最低 UID，显式拒绝 root，并以 getent/passwd 状态验证 shell/lock rollback checkpoint。
- 写入已尝试后遇到 timeout/output/非零状态或 post-check 失败统一记录 `verification_failed`；结果落库
  失败不会再伪造成 action 已知失败，而是保留租约等待过期恢复为未知状态。
- 以上仍是 Windows 上的 stateful fake backend/文件协议测试；没有执行任何 nft、usermod、mv/chown，
  不能替代 Kali 原生故障注入。远程 Host 动作必须另建认证的 Agent-side 固定通道。

### 通知投递

- migration `20260809_0014` 为 outbox 增加 claim lease、next-attempt、稳定 error code、DLQ 时间和
  append-only attempt metadata；领取使用 `FOR UPDATE SKIP LOCKED`。
- 过期投递租约不会在同一 worker cycle 立即重放；先标记失败 attempt，再按有界指数退避重试，
  达到上限或遇到永久 HTTP/redirect 拒绝时进入 `dead_letter`。
- `blue-team-notification-worker` 在短事务内 claim/finalize，在事务外发送 HTTP；默认关闭且必须同时
  配置 32-byte base64url 独立签名 key、固定 URL 和精确 host allowlist 才能启动。
- 当前仅有 fake/loopback HTTP 和仓储单元证据；`tests/integration/test_notification_persistence.py`
  已提交但等待真实 PostgreSQL migration 0014。

### 控制台与依赖安全

- Python API 提供租户有界的 `/api/v1/console/snapshot`，汇总主机、Incident、恶意文件、模型运行、
  响应动作和关键计数。
- `console/` 已替换 starter 占位页，提供九个运营视图、内存令牌连接、30 秒可见页刷新、会话锁定、
  错误/空状态、响应式布局和键盘焦点。
- 响应工作区读取完整计划、typed target、策略门控、evidence refs、审批/执行/回滚记录和不可变状态
  事件；只在状态机允许时呈现审批/拒绝、排队或回滚表单，并要求显式目标/影响确认。
- Incident 工作区在同一事务中对当前 Incident 行持 read lock，数据库查询分别限制 evidence 100、
  timeline/Claim/entity 各 200、visible edge 400；截断范围与 full query ref 明示。单条 normalized fact
  读取再次验证 tenant + Incident + revision + evidence_id + event_id/raw_ref 关系，不将 raw_ref 当 URL。
- 攻击溯源工作区只接受精确 `inc_` seed ID；repository 用 authenticated tenant + seed Incident 对 current
  trace pointer 持 `FOR SHARE`，随后复用 P10 current revision/report scope/canonical snapshot hash 校验。
  source Incident/evidence/key path/impacted Host/cluster/technique/entity/edge 上限为
  50/100/100/100/50/50/200/400，每个引用样本最多 8 条；截断与原始计数闭合，所有可见结论引用可见
  evidence，所有可见 edge 端点保留在可见 entity 中。契约不返回 raw_ref、原始证据字节或 entity
  attributes，identity assertion 固定为 0，任意 graph query 与 investigation export capability 固定为 false。
- 恶意文件工作区对 tenant-scoped sample metadata 持 read lock；扫描任务最多 50、同哈希 context 和
  normalized engine rows 各 8。每个引擎字段最多 4 个值、每个 context 最多 4 个 evidence ID，并保留
  原始计数/截断字段；静态 strings、archive entries、`quarantine_ref` 与样本字节不进入浏览器。
- 规则治理目录在每次读取时校验 runtime registry 的 rule ID、version 与 applicable event source，
  漂移即 fail closed；持久 lifecycle state 记录 sequence、manifest/key/catalog、validation evidence 和
  Canary Host 范围。Draft/缺失、过期、版本漂移、catalog mismatch、Deprecated 均不写 detection；
  Shadow/非 Canary Host 只写独立 observation，Canary/Released detection 绑定精确 stage+manifest hash。
  质量字段保持 `null`，不会用 hit/feedback 伪造 precision、recall、MTTD 或 performance 结论。
- rule/intelligence repository 只聚合 authenticated tenant 的 detection version/hit/open/distinct-host，
  并通过当前 Incident revision membership 统计四类 feedback；最多返回 64 个历史版本和 50 条 cache。
  cache payload value 永不进入契约，只显示最多 16 个已验证字段名；indicator/source URL 均只作文本。
  `lifecycle_enforcement_available=true`、`managed_ioc_lifecycle_available=false`；页面展示 effective scope、
  manifest/key/catalog、Canary/validation 边界和 governed/legacy/shadow 指标，但无 unsigned lifecycle 或
  IOC 写控件。
- model operations repository 只聚合 authenticated tenant 的 review task 和 Provider/model/role run；调用分组
  最多 100，最近运行最多 50，并保留原始总数/截断标记。配置投影只给出 Provider/model、启用角色、能力、
  预算和 key/base URL 的配置状态，不返回 key、URL、Prompt、请求、响应或 evidence package。
- review execution outcome 与 assurance 计数必须分别闭合到 task 总数；调用状态闭合到 run 总数，failure rate
  只由 failed/circuit-open 计算。缺少 audited labeled feedback linkage 时 precision、recall、agreement 和
  false-positive rate 保持 `null`；`provider_health_probe_available`、`credential_validation_available` 和
  `labeled_feedback_linkage_available` 固定为 false，credential/provider 状态分别为 `not_tested`/`not_probed`。
- system operations repository 只读取 authenticated tenant 的租户 metadata、操作凭据 lifecycle、最新 Agent
  heartbeat queue、normalize/malware/response/notification work state、持久记录/错误/事件新鲜度和 migration
  version。凭据最多 100、最新 heartbeat Host 最多 1000，并保留原始总数/截断标记；QueueTelemetry 与各状态
  计数必须闭合，凭据只返回 ID/角色/lifecycle，不返回 token/digest，错误只返回 occurrence count。
- 新 Agent heartbeat 会报告有界 semver，legacy heartbeat 可省略；ingest 仅在重新验证 mTLS certificate 的
  tenant/Agent/Host 绑定后持久化。资产和系统运营目录只选择每个 Host 当前绑定 Agent 的最新 heartbeat，
  排除被替换身份；版本组最多 50，bound/reported/unreported Host 计数必须闭合。来源固定为
  `self_reported_heartbeat`，`binary_integrity_verified=false`。
- persisted row count 不作为数据库/对象存储物理容量，Agent heartbeat queue 不作为 broker depth/backlog age。
  `message_broker_metrics_available`、`backlog_age_metrics_available`、`database_capacity_metrics_available`、
  `object_storage_capacity_metrics_available`、`dependency_health_probes_available`、
  `deployment_inventory_available`、`human_user_directory_available`、
  `agent_rollout_available`、`automatic_rollback_available`、`offline_package_inventory_available`、
  `signed_artifact_inventory_available` 和 `backup_restore_evidence_available` 固定为 false；observed migration
  version 的 compatibility 固定为 `not_evaluated`。`agent_version_inventory_available=true` 只表示存在上述
  current-binding 自报目录，不能解释为 deployment inventory、binary integrity 或 rollout health。
- `write-session` 使用部署 secret HMAC-SHA256 绑定 exact console origin、Bearer credential、签发时间和
  随机 nonce；操作路由重新验证签名/TTL、Origin/Referer、精确 ID、字段白名单和 body bound。
- queue/rollback 请求使用新的浏览器幂等键；代理只构造固定上游 path，不能启用 native worker、选择
  Adapter、改写 tenant 或提供任意上游 URL。
- 同源代理默认连接 `127.0.0.1:8000`，控制面 origin 由服务端环境配置，不接受浏览器提供的目标 URL。
- 移除未使用的 D1/Drizzle starter 代码和 loading-skeleton；升级 Next/React/Vite/Cloudflare 构建链。
  `npm audit --omit=dev` 为 0；`vinext` 的 build-time `image-size` 公告仍无上游修复，当前不处理
  不受信图片并保持为未关闭供应链项。

## 当前非 Docker 证据

- Python：Ruff format/check（260 个文件）、mypy strict（258 个 source files）、Schema check 和 migration
  0016 upgrade/downgrade 离线 SQL 生成全部通过；`pytest` 为 529 passed、22 skipped。
  跳过项是 PostgreSQL、Linux 权限/链接/进程语义，不作为阶段门禁通过证据。
- 真实套接字 mTLS 测试在新版 OpenSSL 下暴露服务端叶证书缺少 AKI；补齐 server leaf 的 SKI/AKI
  后，认证客户端握手通过、无客户端证书仍失败。
- P11 policy/Adapter/Runner/repository/RBAC/API/console tests 覆盖策略降权、双审批、请求人隔离、
  目标身份变化、事务外执行、租户绑定、Snapshot、Incident/恶意文件调查、规则 catalog 漂移、
  tenant rule hit/current-revision feedback/cache value exclusion、tenant+seed trace pointer read lock/current snapshot
  hash/graph-evidence closure/raw-field exclusion、tenant model review/run aggregate、secret/URL
  exclusion、unmeasured quality truth flags、auditor/admin-only system work/queue/storage/error/credential aggregate、
  heartbeat version legacy omission/semver validation、current Host-Agent binding/version group reconciliation、
  token/digest/error-detail exclusion、binary-integrity false/unavailable capability truth flags、响应详情和 mutation
  role separation。
- signed rule lifecycle tests 覆盖 Ed25519 key/tenant/catalog/dataset/time 绑定、完整 transition/rollback/
  deprecate/upgrade 矩阵、sequence/previous-hash 防重放、过期/漂移/corruption fail closure、Canary Host
  tenant scope、worker Shadow/Canary/Released/Deprecated 行为、API trust-store/RBAC 和 console truth flags；
  PostgreSQL 并发/FK 测试已提交但在本轮按环境门禁跳过。
- native response tests 覆盖本机/远端绑定、nftables 临时封禁、文件隔离、账号禁用三类 stateful
  execute/verify/rollback、root/allowlist/UID、argv/output bound、post-write unknown state 和 result commit
  失败；全部是 fake backend，没有 Linux 原生命令证据。
- notification tests 覆盖固定 URL/allowlist、HMAC、字段最小化、redirect/大小/超时、digest lease、
  事务外 HTTP、过期恢复、指数退避、DLQ 和 attempt metadata；真实 PostgreSQL 测试被明确跳过。
- 控制台 `npm run lint`、`npm test` 通过；生产构建包含 `/`、Snapshot、Incident investigation/
  evidence、attack trace、malware investigation、rule/intelligence operations、model operations、system operations、
  write-session 以及四条固定 response route。
  6 项 production worker 测试覆盖 SSR/内存凭据、Origin/nonce/ID 拒绝、固定
  Incident/attack-trace/malware/rule/response path/body、query/path substitution、redirect 和超大响应；production dependency
  audit 为 0。
- 本轮没有启动 Docker、PostgreSQL、Kali 原生命令、Agent 响应后端或站点发布。

## 未关闭门禁

1. 在隔离的 Kali 单节点 profile 部署 `blue-team-response-worker`，验证预置 nftables/firewalld、
   文件隔离和专用测试账号三类 Adapter；对生产多主机 profile，另行实现认证的 Agent-side 固定
   动作通道，中央服务不得代执行远端 Host 动作。
2. 在 Kali 上验证 R2 TTL、执行后健康检查和可重复回滚；对 PID 复用、inode/path replacement、
   账号状态变化、nft set 缺失、进程崩溃、租约过期和重复请求做故障注入。
3. 在真实 PostgreSQL 运行迁移 0013-0016 与 `tests/integration/test_response_persistence.py`、
   `tests/integration/test_notification_persistence.py`、`tests/integration/test_ingest_mtls.py`，使用两个租户、
   responder/requester、两个 approver 和 auditor 做 ID substitution、并发审批/领取/回滚/通知和审计对照；
   另以 Agent A/B rebind、版本省略/畸形/重放/并发验证 current-binding 版本目录。
   并运行 `tests/integration/test_rule_lifecycle_persistence.py`，验证签名 release/rollback、并发首发/重放、
   跨租户 Canary Host、shadow/detection FK 和 rule-version dedupe。
4. 为控制台增加对象存储原始证据的短期授权/审计读取（若产品确认需要）和受管 IOC；另行实现并故障注入
   broker backlog age、数据库/对象存储容量、依赖
   健康、deployment inventory、签名制品/运行二进制验证、签名 rollout/rollback、离线制品和
   backup/restore evidence，并设计审计化
   Provider health/credential validation 与 labeled feedback linkage。控制台的任意交互式 graph query 与
   investigation export 仍是开放产品/授权设计门禁，不得从当前只读投影推断为可用。在真实 HTTPS
   浏览器/API 上复核现有 Incident/attack-trace/rule/intelligence/model/system read
   与响应 write 的租户授权、
   CSRF/Origin、幂等和服务端 RBAC。
5. 将 notification worker 连接真实 HTTPS 接收端与 PostgreSQL，验证双 worker 并发 claim、DNS/
   证书/超时/429/5xx/redirect/超大响应、签名轮换、重放幂等、DLQ 运营和敏感字段最小化。
6. 在 Kali 以 HTTPS/反向代理连接控制台与 API，验证错误令牌、过期/吊销角色、跨租户对象、current
   trace 并发 revision、corrupt snapshot、各 trace section limit+1、超大/慢响应、重定向和控制面故障；
   目前的 Mock、静态/SSR 测试不能替代真实 PostgreSQL 锁、双租户和浏览器动态边界。
7. 完成至少三类动作的真实可验证回滚后，才能评估 P11 退出条件；P12 仍未开始。
