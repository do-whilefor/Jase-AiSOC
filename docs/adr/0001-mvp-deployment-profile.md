# ADR-0001：MVP 部署剖面

状态：Proposed  
日期：2026-08-03

## 背景

计划书同时给出 All-in-One、Central + Agents 和 HA 形态，以及 Base、Stream、Analytics、Search、HA 组件档位。若开发起点直接引入所有数据组件，会扩大故障面且无法证明每个组件的容量必要性；若始终停留在单体，又无法验证 Agent 背压、重放和服务解耦。

## 决策

采用两级 MVP 剖面：

1. P0/P1 开发基线为 **Base All-in-One**：Python 主服务、PostgreSQL、本地对象目录和进程内有界队列/检查点。
2. P2-P7 集成基线为 **Stream Central + Agents**：PostgreSQL、NATS JetStream、S3 兼容对象存储和可拆分 Worker。
3. ClickHouse、OpenSearch、Redis、图数据库和 HA 不作为 MVP 前置；只有真实容量、查询或 SLO 报告超过当前预算时才启用。

## 结果

优点是开发启动快、基础链路可独立验证，同时保留中心化 MVP 所需的背压和重放。代价是 Base 到 Stream 必须使用稳定的队列/存储抽象并做双剖面集成测试，不能依赖单体进程内对象语义。

## 验证

- Base：迁移、健康、租户/资产/空事件、原始证据写入和依赖失败降级通过。
- Stream：至少两个 Agent 的断网、重放、乱序、重复、DLQ、积压恢复和租户隔离通过。
- 引入额外组件必须附容量公式输入、压测原始结果、瓶颈和回退方案。
