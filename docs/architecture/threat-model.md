# P0 威胁模型

方法：按数据流信任边界识别资产、攻击者能力、失败结果、预防/检测控制和必须执行的验证。本文是 P0 基线；架构、Collector、工具或响应动作变更时必须增量更新。

## 保护目标

- 事件和证据的真实性、完整性、顺序信息与租户归属；
- Agent 高权限身份、证书、策略和升级链；
- 控制面状态、审批、规则、模型配置和审计日志；
- 恶意样本、凭据、敏感日志、模型输入输出和导出包；
- 响应目标的准确性、动作授权、影响预算和回滚能力；
- 即使可选组件失败，确定性检测和证据留存仍可用。

## 信任边界与验证计划

| 边界 | 主要威胁/失败结果 | 强制控制 | P0/P1 后续验证 |
|---|---|---|---|
| Agent root 进程 ↔ 本地主机 | 本地提权、配置/队列篡改、复制身份、恶意升级 | 最小 capability、签名制品/策略、证书绑定、systemd hardening、完整性事件、防降级 | 篡改配置/制品、复制镜像、旧版本回退和卸载恢复测试 |
| Collector ↔ Agent | 伪造字段、解析器崩溃、事件洪泛、任意 eBPF 源码 | Collector 清单、严格 Schema、大小/速率限制、受限探针、进程隔离、优先级队列 | 畸形/超大/重复事件、探针加载失败和 Collector 独立降级 |
| Agent ↔ Ingest | 伪造 Agent、重放、篡改、跨租户混淆、断网丢失 | mTLS、一次性注册、主机绑定、批次摘要、boot/sequence、ACK、吊销、租户服务端绑定 | 过期/吊销证书、跨租户 body、批次重放、乱序和断点续传 |
| Ingest ↔ 消息/Worker | Schema 绕过、消费越权、毒消息、积压拖垮控制面 | ACL/主题隔离、Schema、DLQ、幂等、有界队列、背压、工作池隔离 | 非法版本、毒消息、重复 ACK、磁盘满、消费者崩溃和重放 |
| Worker ↔ PostgreSQL | SQL/租户越权、事务竞态、跨租户引用 | 参数化访问、仓储层租户谓词、外键/唯一约束、事务、最小 DB 角色 | 同 ID 跨租户对象、并发更新、迁移回滚和权限负向测试 |
| 平台 ↔ 对象证据 | 任意 URL/路径、覆盖、跨租户读取、样本执行、生命周期失控 | 不透明引用、服务端定位、租户二次授权、追加写、哈希、不可执行挂载、短期授权 | 路径穿越、SSRF、跨租户 raw_ref、覆盖、hash mismatch 和过期删除 |
| API ↔ 恶意样本隔离区 | 超大/编码 body、文件名路径、明文泄漏、跨租户读取、控制面解释样本 | raw body 硬上限、独立 key AES-GCM、tenant/hash/ref AAD、API 无 read/export、独立 worker 身份/进程、noexec mount | Content-Length/chunked 绕过、路径/ref/tenant 替换、错误 key/密文、日志/response 泄漏、API 进程 worker 负向验证 |
| 静态 worker ↔ 样本/Scanner | parser bomb、archive traversal/link、任意命令、单信号过度结论、锁/lease 竞态 | 不提取/不执行、有界 header/central-directory、窄 scanner Schema、SKIP LOCKED lease、多源 family/type 门禁、结果 scope/hash 复验 | ZIP/TAR/ELF 畸形、entry/ratio/size/string 上限、scanner 不可用/伪造 identity、并发/过期 lease |
| Incident ↔ AI Review Gate | 全量日志触发模型、预算耗尽、弱信号被提升 | 事件级门控、聚合/采样审计、硬预算、Provider 熔断、确定性结果保留 | 正常日志洪泛、Provider 全故障、预算耗尽、缺失证据 |
| 不可信证据 ↔ Prompt/模型 | Prompt 注入、数据泄露、伪造 Claim、模型覆盖工具事实 | 数据/指令分离、字段白名单、脱敏、结构化输出、Claim-Evidence 校验、未知项 | 日志/URL/文件名注入、虚假 evidence_id、超大输出和冲突工具结果 |
| 模型/分析器 ↔ Tool Gateway | 任意 SQL/HTTP/文件、越权参数、结果伪造 | 注册工具、严格输入/输出 Schema、只读默认、租户再授权、超时/结果上限、审计 | SQL/URL/路径注入、跨租户对象、过量查询、超时和恶意插件输出 |
| 插件/动态沙箱 ↔ 平台 | 供应链植入、逃逸、外联滥用、主机凭据继承、伪造/重放报告 | 签名清单、独立虚拟化集群/服务身份/网络、默认无外联、资源限制、逐任务销毁、Ed25519 结构化报告、结果仍不可信 | 未签名插件、逃逸、默认/controlled egress、凭据继承、资源耗尽、未销毁环境、跨 tenant/sample/hash 与结果 Schema 攻击 |
| Incident evidence ↔ P10 trace/export | 跨租户图边、无证据因果/身份归因、公共基础设施误聚类、图查询资源耗尽、导出越权/泄漏 | current revision + 复合 FK、exact observable、双侧 session+target success、identity count=0、depth/node/source bounds、content hash 和导出审计、不复制 raw/sample bytes | 双租户 ID substitution、missing/late/replayed evidence、one-sided/NAT/proxy 反例、max+1、并发 revision/export、manifest 篡改和字段分级 |
| P10 trace ↔ 控制台溯源工作区 | seed/tenant 替换、读取 stale/corrupt revision、超大图拖垮浏览器、结论引用被截断、悬空 edge、raw_ref/原始字节/entity attributes/身份断言泄漏、fixed proxy 变成任意 graph query/export | authenticated tenant+validated seed Incident、current pointer `FOR SHARE`、revision/scope/canonical hash 复验、section/string/1 MiB response bounds、truncation reconciliation、evidence/graph closure、零身份断言、raw/attributes omission、精确只读 route 且 query/export capability=false | 双租户相同 seed/trace/entity 形状、并发 revision、corrupt snapshot、各 section max+1、悬空 evidence/edge、超长/转义值、raw/identity 字段注入、query/path/export substitution 和真实浏览器网络捕获 |
| Policy/Approval ↔ Action Runner | 审批绕过、模型提权、远端目标在中央主机代执行、目标替换、PID/inode/账号复用、批量破坏 | 固定动作、模型只降权、审批、目标重验证、执行预算、TTL、回滚/验证；原生初版仅 local-single-node 且绑定私有 Agent config | 旧审批重放、tenant/host/agent 替换、PID/path/account 替换、并发动作、超预算、result commit 丢失、回滚失败和关键资产双审 |
| Notification outbox ↔ Webhook receiver | caller URL SSRF、重定向、DNS/TLS 变化、签名重放、超大/慢响应、敏感字段外传、无限重试 | 独立 worker、固定 URL+精确 host allowlist、非 loopback HTTPS、HMAC+幂等 ID、字段最小化、无 redirect、超时/大小、lease/backoff/DLQ | 双 worker claim、DNS/证书/429/5xx/redirect/oversize、key rotation/replay、DLQ 运营和跨租户 payload 对照 |
| 规则目录/情报 cache ↔ 控制台 | Draft 规则被误称 Released、runtime 绕过生命周期、版本/source 漂移、伪造质量、跨租户命中/feedback/cache 泄漏、payload value/XSS/链接执行、cache 冒充 IOC 生命周期 | version-bound 显式 catalog、registry fail-closed 校验、Draft/runtime mismatch 明示、质量 null、tenant SQL+current revision membership、固定 read route、历史/cache/field-name 上限、文本渲染、无 payload value/写控件 | catalog drift、未知 feedback/payload key、双租户 rule version/hit/feedback/cache、limit+1、HTML/URL indicator、query/path substitution；signed Shadow/Canary/Released/rollback 与受管 IOC 在 Linux VM 实现后另验 |
| Provider/review history ↔ 模型运营控制台 | key/base URL/Prompt/response 泄漏、跨租户 review/run 混读、截断后伪造总数、把配置当 credential/health 证明、把成功率/人审/assurance 冒充模型质量 | secret-free 配置投影、tenant-scoped review/run SQL、group/recent 上限与 window 总数、状态计数闭合、固定无 query read route、credential=`not_tested`、health=`not_probed`、无 labeled linkage 时质量 null/availability false | 双租户同 Provider/model/run 形状、wrong-role、limit+1、未知状态/role、query/path substitution、日志/浏览器 secret 检查；真实 Provider timeout/circuit/recovery、key rotation/probe 和金标 linkage 另验 |
| 系统状态/凭据记录 ↔ 系统运营控制台 | responder 越权、跨租户 queue/error/credential 混读、token/digest/error detail 泄漏、未知状态被吞掉、截断后伪造总数、伪造 Agent version、旧/被替换 Agent 污染目录、把 row count/heartbeat/config version 冒充容量/broker health/二进制完整性/兼容/升级证明 | auditor/admin RBAC、tenant SQL、credential/heartbeat 上限与原总数、状态计数闭合、QueueTelemetry 复验、heartbeat tenant/Agent/Host 证书身份复验、只聚合当前 Host-Agent 绑定、有界 semver 与 50 版本组、self-reported 来源及 binary integrity=false、固定无 query route、secret/error-detail exclusion、migration compatibility not_evaluated、缺失 telemetry/capability 固定 false | 双租户同 credential/queue/error/version 形状、wrong-role、limit+1、未知 status/role/queue shape、version 省略/畸形/重放/并发、Agent rebind、query/path substitution、migration row 与日志/浏览器 secret 检查；对照签名安装状态与运行二进制，并对真实 broker/capacity/dependency/upgrade/backup 故障注入另验 |
| 用户/集成 ↔ API/控制台 | IDOR、角色/租户绕过、Incident revision 混读、sample/hash/task 混读、raw_ref/quarantine_ref 任意取数、会话/CSRF、任意上游代理、幂等绕过、审计规避 | 强认证、服务端 RBAC/对象授权、current Incident/sample read lock、evidence/scan membership、raw_ref/source_url 不可执行、quarantine_ref/sample bytes 不出控制台、固定操作代理、exact ID/field/body bound、Origin/Referer、origin+Bearer HMAC nonce、幂等键、内存凭据、不可变审计 | 双账号/双租户对象矩阵、并发 revision/scan、Incident/evidence/event/raw_ref 与 sample/hash/task substitution、wrong-role/self-approval、旧/换 token nonce、ID/path/body substitution、重复/并发写入和审计完整性 |
| CI/发布 ↔ 运行环境 | 依赖投毒、构建篡改、密钥泄露、制品替换 | 锁文件、最小 CI 权限、依赖审计、SBOM、签名、可复现构建、受保护发布 | 锁定安装、已知漏洞门禁、签名/哈希错误、回滚和证书吊销 |

## 攻击者模型

考虑匿名网络攻击者、普通租户用户、恶意/失陷 Agent 主机、被盗分析员会话、恶意日志生产者、恶意样本/插件、供应链攻击者和误操作管理员。P0 不假定平台能够抵御已完全控制中心基础设施与密钥托管系统的攻击者，但必须使该类操作可审计并限制单个服务身份的爆炸半径。

## 必须保持的负向安全属性

- 仅修改请求中的 `tenant_id`、对象 ID、`raw_ref`、角色或状态不能跨越所有权边界。
- 单个 IOC、端口、CPU 峰值、模型置信度或多模型一致不能单独产生“确认失陷”。
- 不存在、其他租户或完整性失败的证据不能支撑 Claim。
- 模型输出、插件输出和客户端声明不能直接进入任意代码/命令/SQL/URL 执行。
- 重放事件、迟到事件或重复审批不能导致响应动作重复执行。
- IP、ASN、语言、基础设施相似性或模型输出不能产生真实攻击者身份；无 verified identity evidence 时
  P10 identity assertion 数量必须为 0。

## 评审触发器

新增高权限 Collector、数据源、外部 Provider、调查工具、插件 capability、动态沙箱、R2/R3 动作、多租户共享缓存或新的部署边界时，必须在合并前更新本模型和相应负向测试。
