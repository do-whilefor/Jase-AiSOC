# P10 跨主机攻击图谱、技术溯源与调查导出

## 当前结论

P10 已完成非 Docker 初版，但阶段门禁未关闭。当前实现从认证租户内的当前 Incident revision
读取 Detection 与 normalized evidence，在有界时间窗内选择 seed Incident 的证据连通分量，构建
跨主机实体/边、初始入口候选、主机内关键步骤、双侧网络会话与目标主机成功活动共同支持的横向
路径、受影响 Host、精确基础设施聚类和 ATT&CK 技术映射。迁移 `20260809_0012` 将每个结论
通过复合外键绑定到精确 Incident revision/evidence。

本地证据来自合成两主机链、Mock 仓储、ASGI 和离线迁移，不是 Linux 原生 Collector、真实
PostgreSQL 双租户/并发或真实攻击回放。因此 P10 相关安全假设仍为 `technical_hit / unrated`，
不能宣称已经达到阶段退出条件。

## 信任与归因边界

```text
authenticated tenant + seed Incident
              |
              v
bounded current Incident revisions -- exact evidence refs --> deterministic trace builder
              |                                               |
              | no cross-tenant/unknown evidence               +--> TTP/ATT&CK mapping
              |                                               +--> exact observable clusters
              v                                               +--> cross-host path
append-only PostgreSQL trace revision
              |
              +--> bounded graph query
              +--> structured investigation export (no raw/sample bytes)

identity attribution = not_attributed / assertion_count=0
```

- 只允许同一认证 `tenant_id`；请求中的对象 ID 不能覆盖服务端租户。
- Source Incident、trace evidence、edge evidence 和 technique evidence 均保存 revision，并以复合
  FK 返回 `incident_revisions` 与 `incident_evidence`。
- `IdentityAttribution` 的 Schema 把 `assertion_count` 固定为 0、`assertions.maxItems` 固定为 0。
  当前实现不提供用 IP、ASN、语言、基础设施或模型输出来填充真实身份的路径。
- 技术归因只表示 evidence-backed TTP/ATT&CK 或精确 observable similarity；同 IP/domain/cert/hash
  不等于同一控制者，代理、NAT、跳板或受害基础设施仍是明确限制。
- 调查导出包含结构化 trace、evidence pointer、raw_ref 与完整性摘要，不复制完整 raw log、PCAP、
  样本内容或 quarantine ref；manifest 对 canonical trace JSON 计算 SHA-256 并记录导出审计。

## 已实现能力

### 实体规范化与边去重

- P10 独立 entity types：Host、User、Process、File、IP、Domain、Certificate、Session、Technique、
  Incident。
- process key 纳入 tenant/Host/boot/PID；path-only file 纳入 Host，SHA-256 file、IP、domain、
  certificate 与 session 保留可跨 Incident 的精确 canonical key。
- edge ID 由 tenant/source/target/relationship 确定性生成，重放合并 evidence，禁止 self-loop，
  endpoint/evidence 必须存在于同一 trace revision。
- source 查询、evidence、entity、edge 均有硬上限；max+1 明确失败，不写部分图。

### 跨主机路径与影响范围

- 两个 Host 对同一精确五元组 Session 有时间邻近观察时只形成 `communicates_with` 技术关联。
- 只有 outbound source、target observation，以及目标 Host 在限定时间内出现与 remote IP 一致的
  成功认证或成功执行，才升级为 `lateral_to` 和 `lateral_movement` step。
- 初始入口只从明确 rule mapping 中选择最早 evidence-backed Detection；未观察到时返回 `null`
  并增加限制说明，不补全理论入口。
- key path 保留每步 event time、source/target Host、AttackState 和 trace evidence IDs；impacted Hosts
  必须真实存在于图中。

### ATT&CK 与基础设施

- `p10-attack-map-v0.1.0` 将当前确定性规则映射到有限 ATT&CK 集合；映射保留 rule IDs、
  observed/inferred 状态和 evidence IDs，不把技术映射变成攻击成功证明。
- 基础设施 cluster 只使用 IP/domain/certificate/file SHA-256 的精确匹配，并要求跨 Incident 或跨
  Host；不使用 ASN、地理、语言、whois 文本或模型相似度。
- Technique 同时作为图实体并通过 evidence-backed edge 关联 Host。

### 查询、版本与导出

- `POST /api/v1/incidents/{incident_id}/attack-trace`：从当前 revision 按 tenant/time bound 构建并
  幂等持久化。
- `GET /api/v1/attack-traces/{trace_id}`：读取当前 append-only revision，并重新验证 Schema、scope
  与 snapshot hash。
- `POST /api/v1/attack-traces/{trace_id}/graph/query`：固定 root、depth≤8、nodes≤1000 和可选
  relationship allowlist 的有界 BFS，不接受 SQL/URL/文件参数。
- `POST /api/v1/attack-traces/{trace_id}/exports`：生成结构化调查包并记录 content hash、evidence
  count、actor 和审计；`raw_content_included=false`、`sample_content_included=false`。
- 相同 snapshot 重放不新增 revision；late evidence 或 source Incident revision 变化追加 revision，
  旧 trace 保留。

## Schema 与持久化

- `attack-trace-report-v0.1.schema.json`
- `attack-trace-graph-query-v0.1.schema.json`
- `attack-trace-graph-result-v0.1.schema.json`
- `investigation-export-v0.1.schema.json`
- `attack_traces`、`attack_trace_revisions`
- `attack_trace_incidents`、`attack_trace_evidence`
- `attack_trace_entities`、`attack_trace_edges`、`attack_trace_edge_evidence`
- `attack_trace_techniques`、`attack_trace_technique_evidence`
- `attack_trace_exports`

## 当前本地证据

- 合成 Web entry → Host A shell → SSH session → Host B success/exec 能恢复两个 Host、entry、shell、
  lateral step、impact scope 和 T1190/T1059.004，全部结论引用 trace evidence。
- 输入顺序反转生成完全相同 report；late evidence 改为 `late_evidence_recompute`。
- 不共享精确 observable/session 的第三 Incident 不进入 seed component。
- cross-tenant input、Incident/evidence bound、非图 root、identity assertion 均 fail closed。
- graph query 在 depth/node 上限停止；export hash 可由 canonical JSON 独立复算且不包含 raw/sample bytes。
- Mock persistence 证明 exact replay 不追加 revision，edge/technique evidence 只引用 trace evidence，
  audit 不复制 evidence index。
- ASGI build/query/export 使用认证 tenant；OpenAPI 明确 identity assertion maximum/maxItems 为 0。
- 真实 PostgreSQL 测试 `tests/integration/test_trace_persistence.py` 已提交，无数据库 URL 时按设计跳过。
- 非 Docker 收尾复核通过：九个 `tests/replay` 数据集逐个符合 manifest，`uv lock --check`
  通过，OSV dependency audit 无已知漏洞，生成的 OpenAPI 180 个本地 `$ref` 全部可解析且 P10
  route/body/response 正确，`git diff --check` 无 whitespace error；计划书 DOCX 与归档 ZIP 未改动。
- P10 路径扫描和动态 ASGI/contract 测试确认 graph query 不接受 SQL/URL/file/shell 参数，export
  仅复制结构化 trace 与 evidence pointer、禁止 raw/sample content，identity assertion 结构上保持为 0。

## 未关闭门禁

1. 在 Linux VM/PostgreSQL 运行迁移 0012、完整 P4/P5→P6→P10 攻击回放、两个真实租户 HTTP ID
   substitution、FK 负向、并发 build/export 和 late revision 测试。
2. 加入版本化真实攻击数据集，覆盖 Web/SSH initial access、成功/失败横向、one-sided telemetry、
   NAT/proxy/jump host、相同公共基础设施反例、时钟偏差、乱序、重复和迟到证据。
3. 校准每个 ATT&CK mapping 的 observed/inferred 语义，记录规则版本和反例；不能把 mapping 当作
   success、identity 或 actor evidence。
4. 对 graph query 做 10k/100k entity/edge PostgreSQL recursive CTE 与当前 bounded in-memory 路径
   对照；只有压测证明需要时才引入独立图数据库。
5. 验证调查导出的下载授权、保留/删除、字段分级、完整性签名或链式 custody、对象存储和大包
   流式策略；当前只提供有界结构化 JSON。
