# P6 Incident、证据、时间线与实体边

## 阶段目标

P6 将 P4/P5 Detection 聚合为稳定、可修订的 Incident，同时保持每个判断都能回到不可变原始
证据。实现遵循计划书的 PostgreSQL-first 路径：先使用关系表表达实体与边，不在 MVP 阶段引入
图数据库。

本阶段的核心不变量：

- 只在相同 trusted tenant、host、归一化 detection subject 和有界时间窗内聚合；共享目标资产
  本身不能把不同攻击主体合并。
- 重放相同 Detection/事实得到相同候选和 snapshot hash，不新增 Incident/revision。
- 新迟到事实保持 normalized event 追加写，并触发受影响 Incident 的新 revision；旧 revision 不覆盖。
- Claim、时间线条目和实体边引用的每个 event ID 必须存在于同 tenant、同 Incident revision 的
  evidence index；index 再引用 `normalized_events` 和 raw reference。
- 任何输入/上下文上限都显式失败；不得用静默截断换取 Incident 结果。
- 数据缩减记录输入、保留、丢弃、样本、规则版本和可执行 `full_query_ref`。

## 已实现的非 Docker 增量

### 聚合与数据契约

- `IncidentCorrelator` 对 Detection/evidence 去重并拒绝冲突 ID、缺失 evidence、跨 tenant/host
  引用、naive timestamp 和配置溢出。
- 输出包含风险分、attack state、Claim、时间线 assurance、实体、边、evidence index、查询规范和
  `data_reductions`。
- 输入顺序、重复重放不影响输出；不同 host 或 source subject 不互相吞并。
- 10,000 条重复网络事实聚合为一个 Incident，主样本固定为 20 条，缩减审计记录 9,980 条丢弃
  并保留完整查询引用；关系边的抽样证据也进入统一 evidence index。

### PostgreSQL 模型与迁移

- Alembic `20260809_0008` 扩展 `incidents`，新增 append-only `incident_revisions`。
- Detection membership、evidence、query、reduction、timeline、Claim、entity、edge 和各 evidence
  link 使用 revision 维度保存。
- 子表通过 tenant 参与的复合外键连接 Incident、Detection、NormalizedEvent 和图节点，数据库
  约束阻止跨租户拼接。
- 新增 merge/split lineage 与 append-only analyst feedback。
- 离线 SQL 已验证 `base → 20260809_0008 → base`，当前只有一个 Alembic head。

### Worker、API 与生命周期

- API lifespan 和 `blue-team-process` 已接入 IncidentWorker；worker 查询完整有界 lookback，关联
  raw integrity hash，遇到坏 payload 或 max+1 溢出即整轮失败。
- `GET /api/v1/incidents/{id}/{evidence,timeline,claims,graph}` 返回当前 revision 的租户作用域结构。
- close 会关闭 Incident 并 resolve 当前 member detections，避免 worker 用同一事实重新打开。
- merge 只接受能重新计算成一个 component 的 Incidents；split 只接受恰好覆盖当前 detections 且
  与重新计算 components 一致的分组。两者均记录 lineage 和明确 revision reason。
- feedback 为追加写，不修改或覆盖检测证据。

## 当前验证

- P6 聚合、repository、worker、生命周期和 API 契约已有单元/Mock 测试。
- 当前完整 Windows 非 Docker 门禁：Ruff、mypy、Schema、lock、offline migration、dependency audit
  全绿，pytest 为 283 passed / 16 个 PostgreSQL、Linux 或符号链接能力相关 skip，9/9 replay 通过。
- 10k 聚合、顺序无关、重放幂等、跨主体/主机隔离、缺失/冲突 evidence、迟到/时钟退化、
  detection/evidence 溢出均有动态内存级结果。
- `tests/integration/test_incident_persistence.py` 已提供真实 PostgreSQL gate，但本轮按要求未启动
  Docker/PostgreSQL，因此保持 skip。

## Kali/真实 PostgreSQL 待办与退出门禁

1. 在迁移到 `20260809_0008` 的 PostgreSQL 上运行 P6 integration test，验证实际复合外键、
   savepoint 竞争、相同 snapshot 重放和 revision 追加。
2. 使用两个 tenant、两个 host、两个 source subject 动态请求/数据库对照，确认 API、membership、
   evidence、query、Claim 和 edge 均不能跨边界。
3. 输入真实 auditd/Falco/Web 攻击链，跨 worker poll/restart 注入乱序与迟到事实，验证同链稳定聚合
   且旧 revision 可查询。
4. 在 PostgreSQL 写入 10,000 条重复上下文，验证只产生一个 Incident，缩减计数为
   10,000/20/9,980，并使用 `full_query_ref` 取回完整范围。
5. 并发两个 IncidentWorker，验证只产生一个 Incident/revision；对 merge/split/close/feedback 做
   API 状态、audit log 和回滚对照。

完成上述动态门禁前，P6 状态保持“进行中”，不得宣称阶段退出或生产可用。
