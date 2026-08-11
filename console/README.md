# AI-SOC Operator Console

P11 安全运营控制台。当前增量通过固定同源代理连接 Python 控制面，提供九个运营视图，展示
Incident、资产、恶意文件、模型审核和响应状态，并提供：

- 当前 Incident revision 的时间线、证据、Claim、实体和可见关系边调查工作区；
- 重新验证 tenant、Incident、revision 和 evidence membership 的单条 normalized evidence 详情；
- 以一个已验证 seed Incident 定位当前 P10 revision 的跨主机攻击溯源工作区，展示初始入口、关键路径、
  影响 Host、源 Incident、证据闭合的有界实体/边、ATT&CK 和精确 observable cluster；
- tenant/sample/hash/task/engine 绑定且有固定缩减记账的恶意文件分析、同哈希来源上下文与扫描历史；
- version-bound 的九条规则治理目录、租户命中/Incident feedback/历史版本与有界情报 cache 元数据；
- 不暴露 key/URL/Prompt/response 的 Provider 配置状态、role/budget、租户 review outcome、
  cost/latency/failure 聚合与最近模型调用；
- auditor/tenant_admin 专用的租户 work state、最近 Agent queue telemetry、持久记录/错误/新鲜度计数、
  runtime/migration version、当前 Host-Agent 绑定的 heartbeat 自报 Agent version 聚合与无 token/digest
  的操作凭据投影；
- 响应详情、审批/拒绝、执行排队与回滚请求工作流。

调查查询有固定数据库上限并明确显示截断与 `full_query_ref`。证据详情只把 `raw_ref` 作为不透明
引用展示；控制台代理不会按该值取对象存储，也不会把原始证据字节发送到浏览器。
攻击溯源投影与上述单条证据详情不同：它完全不返回 `raw_ref`、原始证据字节或实体 attributes；
source Incident/evidence/key path/impacted Host/cluster/technique/entity/edge 上限分别为
50/100/100/100/50/50/200/400，每个引用样本最多 8 条，并要求所有可见结论引用可见 evidence、
所有可见 edge 端点属于可见 entity。identity assertion 固定为 0，页面不提供任意图查询或调查导出。
恶意文件工作区同样不返回 `quarantine_ref`、样本字节、静态 strings 或 archive entries；来源 URL
只作为不可信文本显示，不会生成可导航链接。
规则页是只读真相面：每条 bundled rule 显示租户当前签名状态、effective emission scope、sequence、
manifest/key/catalog 摘要、验证数据集数量、Canary Host 有界样本，以及 governed/legacy detection 和
Shadow observation 计数。DetectionWorker 对缺失、过期、版本漂移或 catalog 摘要不匹配的状态 fail
closed；Shadow 只写 observation，Canary 仅对签名 Host 范围写 detection，Released 才对租户 Host
写 detection。页面不提供无签名 lifecycle 控件。质量指标仍保持未设置，不从命中或 feedback 猜测
precision/recall；情报区只显示 cache key/field name，不返回 payload value，也不声称已经实现受管 IOC
生命周期。
模型页同样只陈述可验证事实：key/base URL 只显示 configured state，credential validity 和 Provider
health 标为未探测；没有 ground-truth label linkage 时，Precision/Recall/agreement/false-positive rate
保持未测量。模型 Prompt、请求/响应、evidence package 和 secret 不进入浏览器。
系统页把 persisted row/work-state count 与物理容量、broker depth/backlog age 分开。Agent version 只来自
通过 mTLS 身份复验后持久化的 heartbeat，并且只聚合每个 Host 当前绑定的 Agent；它明确标记为
`self_reported_heartbeat` 且 `binary_integrity_verified=false`。页面不声称存在主动 dependency probe、
deployment inventory、human user directory、签名制品/运行二进制验证、升级编排、自动回滚或备份恢复证据。
操作凭据仅显示 ID、角色和生命周期，不返回 token、digest，且 responder/approver 无权读取该页。

## 本地运行

1. 复制 `.env.example` 为 `.env.local`，设置至少 32 bytes 的随机
   `AISOC_CONSOLE_CSRF_SECRET`，并按需修改控制面地址。
2. 启动 Python API；非 loopback 控制面必须使用 HTTPS。
3. 运行 `npm run dev`，在页面中输入具备 `responder`、`approver` 或 `auditor` 角色的令牌；系统运营页
   需要 `auditor` 或 `tenant_admin`。

令牌和 HMAC 绑定的写入 nonce 只保留在当前页面内存，并通过固定同源代理转发；不会写入
localStorage、sessionStorage、cookie 或前端环境变量。写请求同时验证 Origin/Referer、精确动作 ID、
有界 JSON 和 nonce；排队/回滚使用独立幂等键。后端租户 RBAC、自审批隔离、状态机、执行开关和
独立 Action Runner 仍是权威边界。浏览器不提供原生执行开关。

## 验证

```bash
npm run lint
npm run build
node --test tests/rendered-html.test.mjs
```
