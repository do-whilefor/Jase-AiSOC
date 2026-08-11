# P7–P12 安全审计报告

**审计日期**: 2026-08-09
**审计范围**: P7 AI Review Gate、P8 多模型审核、P9 静态恶意文件、P10 跨主机图谱、
P11 响应/审批/控制台/通知/规则生命周期，以及 P12 硬化前置项。
**方法**: 四个并行审计 Agent 逐行追踪不可信输入到敏感 sink 的数据流，验证每条安全属性
（不依赖 docstring 声明，对照实际实现验证）。

## 审计结论

核心安全属性（命令注入、SSRF、Ed25519 签名、AES-GCM 加密、归档安全、租户隔离、
Prompt 注入隔离、盲审字段剥离、判决逻辑、预算 fail-closed）**全部通过实际代码验证**。
平台整体防御纵深设计良好。发现的问题集中在竞态条件和防御纵深加固，均已修复。

## 已修复漏洞

### 1. [HIGH] 并发 AI Review 双重计费与预算绕过

- **位置**: `api_server/routes/incidents.py` review 路由、
  `ai_review/orchestrator.py`、`storage/ai_review_repository.py`
- **问题**: 路由执行 find(plain SELECT) → if None → billable `orchestrator.review()` → persist。
  两个并发 `POST /review` 请求在 READ COMMITTED 下都通过 `find == None`，
  均执行计费模型调用。DB 唯一约束仅去重最终 INSERT；失败方的 `ai_model_runs` 审计行
  从不持久化，造成计费但无审计。每 Incident 成本预算是每次调用的内存计数器，
  N 个并发可达 N × `max_cost_usd_per_incident`。
- **修复**: 引入 PostgreSQL 会话级 advisory lock（`pg_advisory_lock`），
  key 由 `(tenant_id, incident_id, revision, policy_version)` 派生（与 `review_task_id`
  和唯一约束相同材料）。获取锁后 re-check find；只有 winner 执行模型调用，
  loser 等待后读取 winner 的已提交结果并返回，不产生计费。
- **新增**: `DatabaseReadOnlyToolDataSource`——每次工具调用打开短 session，
  使模型 Provider HTTP 往返期间不持有连接池连接。

### 2. [MEDIUM] AI Review 路由持有 DB 事务跨多秒模型调用 → 连接池耗尽 DoS

- **位置**: `api_server/dependencies.py::get_session`、`incidents.py` review 路由
- **问题**: `get_session` 在整个请求期间持有 `session.begin()` 事务和连接池连接。
  Provider HTTP 调用（含超时+重试）可持续数秒至数十秒，M 个并发 review 可耗尽连接池，
  影响不相关 API 端点的跨租户可用性。
- **修复**: 重构 review 路由为四阶段：(1) 短事务读取上下文并释放连接；
  (2) 专用连接获取 advisory lock；(3) 模型执行——`DatabaseReadOnlyToolDataSource`
  仅为工具调用打开短 session，Provider HTTP 期间无连接；(4) 短事务持久化。
  advisory lock 连接为空闲状态（仅持有锁），不同 Incident 可并行。

### 3. [MEDIUM] 响应 Worker claim 查询缺少租户/主机边界 → 跨主机动作丢失

- **位置**: `storage/response_repository.py::claim_next_response_action`、
  `response_engine/worker.py`、`response_engine/__main__.py`
- **问题**: claim 查询选择任意 QUEUED/ROLLBACK_QUEUED 动作，无 tenant/host 过滤。
  Host A 的 worker 可 claim Host B 的动作，boundary check 在 claim 后才失败，
  将动作终态置为 FAILED——Host B 的 worker 永远无法处理，动作永久丢失。
- **修复**: 为 `claim_next_response_action` 添加可选 `tenant_id`/`host_id` 参数，
  提供时在 claim 查询中过滤。`ResponseWorker` 接受 boundary 参数并传递给 claim；
  `__main__.py` 从 `LocalAgentBoundary` 传递 `tenant_id`/`host_id`。
  不提供时保持向后兼容（无过滤），测试无需修改。

### 4. [LOW] evidence 对象存储缺少 O_NOFOLLOW

- **位置**: `storage/object_store.py::_write_once`
- **问题**: 与 `quarantine.py` 不同，evidence 存储 `_write_once` 未设置 `O_NOFOLLOW`。
  虽然路径组件由 server 生成（uuid4）且 `_safe_path` 先前 `.resolve()` 检查 symlink，
  但 final 组件仍存在 symlink 竞态窗口。
- **修复**: 添加 `os.O_NOFOLLOW` 到 open flags。

### 5. [LOW] quarantine:// 引用可泄漏到 API 错误响应

- **位置**: `api_server/error_handlers.py`、`errors.py`
- **问题**: `app_error_handler` 将 `error.details` 直接序列化到 HTTP body。
  `SampleIntegrityError`/`NotFoundError` 可携带 `quarantine://` 引用。
  当前无请求路径触发这些错误（仅 worker 内部调用），但这是脆弱不变量。
- **修复**: 在 `error_handlers.py` 添加 `_redact_details` 防御纵深函数，
  序列化前将 `quarantine://` 开头的 value 替换为 `[redacted]`。

### 6. [LOW] 不可达的 chatgpt-auth.ts 信任客户端身份 Header

- **位置**: `console/app/chatgpt-auth.ts`（已删除）
- **问题**: vinext starter 模板遗留的 dead code，从 request header 读取
  `oai-authenticated-user-id` 等字段，无上游代理验证。当前无任何文件导入它。
- **修复**: 删除文件，消除潜在 footgun。

### 7. [LOW] YARA-X 扫描未设置超时

- **位置**: `malware_engine/yara_x_scanner.py::_scan_sync`
- **问题**: `scan()` 可捕获 `TimeoutError` 但从未设置超时。病态样本可无限挂起 worker 线程。
  租约到期（300s）和重试上限最终标记 FAILED，但线程池槽位被占用直到进程重启。
- **修复**: 改用 `yara_x.Scanner` 并调用 `set_timeout(30)`（可配置），
  确保 YARA-X 在有界时间内完成或超时。

### 8. [LOW] 控制台 CSRF write-session 接受已知默认/占位密钥

- **位置**: `console/app/api/platform/_proxy.ts::writeSessionKey`、`console/.env.example`
- **问题**: `.env.example` 中的占位值 `replace-with-a-random-secret-of-at-least-32-bytes`
  通过验证（50 字符可打印 ASCII），直接复制 `.env.example` 的部署使用公开密钥。
  虽然 nonce 绑定 exact Bearer token 使实际利用接近不可能，但这是部署卫生问题。
- **修复**: 在 `writeSessionKey` 添加占位值检测（`replace-with`/`change-me`/`your-`/
  `placeholder` 前缀），拒绝已知默认密钥并返回 503。

## 已验证通过的安全属性

### P7/P8 AI Review
- 租户隔离 / 无 IDOR：`require_tenant_principal` 从 DB 凭据记录派生 tenant_id；
  `X-Tenant-ID` 只能限制不能提权。所有读写按 tenant 过滤。
- Prompt 注入隔离：证据/Claim/ToolResult 文本始终在 user message，
  system instructions 仅来自模块级常量。
- Tool Gateway 绑定：每次调用绑定 package tenant/Incident/revision/query_ref，
  限制行数/字节，数据访问前拒绝越界。
- Provider SSRF / Secret 安全：固定 HTTPS 端点（loopback HTTP），不跟随重定向，
  响应字节限制，API key 使用 SecretStr，错误不泄露 key。
- Claim-Evidence 校验 + 盲审：跨 Incident/未知 evidence ID 使输出无效；
  `BlindClaim` 结构性删除 Analyzer score/verdict/provider/reasoning。
- 预算 / 熔断 fail-closed（修复竞态后）。
- `allowed_response` 固定 `recommend_only`。

### P9 Malware
- AES-256-GCM + AAD 绑定（格式版本、tenant、SHA-256、object ID）。
- 归档解析无解压/提取；ZIP 先读 EOCD 限制 entry/offset/size；TAR 顺序解析 512-byte header。
- 沙箱报告 Ed25519 签名验证 + tenant/sample/SHA-256 绑定 + 环境销毁证明。
- 租户隔离 + lease reclaim（FOR UPDATE SKIP LOCKED + lease token + 到期回收 + attempt 上限）。
- 判决逻辑：单 scanner 命中最多 SUSPICIOUS；malicious 需 ≥1 malicious + ≥2 独立 positive source。
- 无样本内容/download/export API。

### P10 Attack Trace
- 租户隔离：所有查询按 authenticated tenant 过滤；client ID 不能覆盖 server tenant。
- identity assertion 固定 0：`assertion_count: Field(ge=0, le=0)`。
- 图查询拒绝 SQL/URL/file/shell 参数；export `raw_content_included: Literal[False]`。
- 技术归因只表示 evidence-backed TTP/observable similarity，不等于同一控制者。

### P11 Response / Notification / Rule Lifecycle
- 命令执行：`create_subprocess_exec`（非 shell），绝对路径，最小 env，无 stdin，
  10s 超时，64KiB 输出限制，不持久化原始输出。`LinuxCommandPlanner` 固定 argv，
  IP/username/path 经规范化/allowlist/正则验证。无命令注入向量。
- 文件隔离：allowlist root、单普通文件、O_NOFOLLOW、前后 device/inode/uid/gid/mode/hash/size 检查。
- nftables/firewalld：固定 table/set，不接管已存在 block，rollback 幂等。
- 账号 Adapter：精确 allowlist、最低 UID、显式拒绝 root、getent/passwd 验证。
- 策略/审批：请求人不能自审批；关键资产需 2 名不同审批人；R3 需业务确认；
  无验证回滚的动作被拒绝；模型保证只能增加审批或拒绝，不能提权。
- Native worker guard：Linux euid 0 + 双开关 + local_single_node + 私有 agent config，
  plan tenant/host/agent 不匹配在命令前拒绝。
- Webhook SSRF：目标 URL + 签名 key 仅来自部署配置；outbox 不能改写目标；
  非 loopback HTTPS；拒绝 userinfo/query/fragment/特殊地址；不跟随重定向；
  HMAC-SHA256 over timestamp + canonical body；稳定 event ID 幂等键；
  不持久化响应 body 或原始异常文本。
- 规则 lifecycle：Ed25519 签名验证在应用前；sequence 连续 + 绑定 previous hash；
  catalog digest + validation dataset 精确匹配；canary host 必须属于认证租户；
  trust store 缺失/签名错误/作用域错误/重放/跳级/旧 hash 均拒绝。

### P11 Console / Auth
- 同源代理：固定上游 origin，不接受调用方 URL/path，ID 正则验证，8KiB/1MiB/10s 限制，
  不跟随重定向，非 loopback HTTPS。无 SSRF/open redirect。
- Write-session nonce：HMAC-SHA256 绑定 exact origin + Bearer + 时间 + nonce，
  12h TTL，部署未配置独立 secret 时写入 fail-closed（含占位值检测）。
- 操作员令牌：仅 React 内存，不写入 localStorage/sessionStorage/cookie。
  每次 queue/rollback 生成独立幂等键。
- CSRF/Origin：写请求必须 Origin/Referer 匹配。Bearer-in-header 模型天然 CSRF 抗性。
- RBAC：所有路由处理器服务端验证角色（auditor/admin/approver/responder）。
- Secret 排除：凭据只返回 ID/角色/lifecycle；模型运营不返回 key/URL/Prompt；
  情报 cache value 不进契约；错误只返回 occurrence count。

## 依赖供应链审计

`pip-audit --skip-editable` 通过，无已知漏洞。CI `supply-chain` job 生成 CycloneDX SBOM。
Rust 依赖（pyo3 0.21、sha2 0.10、hex 0.4）无已知漏洞。

## 未关闭的防御纵深项（非漏洞）

1. **quarantine 中间路径 TOCTOU**：`_write_once` 在 `is_relative_to` check 和 `os.open`
   之间存在微秒级窗口。需要 `openat(dirfd, ...)` 逐组件遍历才能完全消除，
   但要求 0700 root 本地写权限（已 game-over），当前 `O_NOFOLLOW` + `O_EXCL` + server 生成
   uuid 路径使非 API 可利用。留作 P12 `openat` 加固项。
2. **Webhook forbidden-address 未包含 private/CGNAT**：主控制是精确 host allowlist，
   private 地址只能在显式配置 allowlist 时到达。添加 `is_private` 会阻止合法内部 webhook，
   当前保持不变。
3. **`image-size` 供应链公告**：`vinext` 构建 `image-size` 包无上游修复，当前不处理不受信图片，
   保持为未关闭供应链项。
