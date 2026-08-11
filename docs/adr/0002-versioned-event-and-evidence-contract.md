# ADR-0002：版本化事件与证据契约

状态：Proposed
日期：2026-08-03

## 背景

多个 Collector、Agent、消息消费者和历史回放会并行演进。若各服务复制 Schema 或把原始日志直接当作事件，租户归属、事件时间、幂等和证据引用会发生漂移，历史结论也无法解释。

## 决策

- 跨边界事件使用统一、版本化契约；P0 起点为 `Security Event 0.1.0`。
- 每个事件必须有 event/schema/type/time/source/tenant/host/raw_ref；Agent 可观察时还应提供 boot/sequence/source event ID。
- 原始证据只追加并独立存储；标准化事件可按版本重算，保存输入引用和转换版本。
- `tenant_id` 由认证上下文绑定，消息字段只作一致性校验。
- `raw_ref` 是不透明对象标识，不能由消费者作为任意 URL/路径直接访问。
- 幂等和排序语义使用 agent/boot/sequence/source identity；迟到数据创建版本化修订，响应动作另有幂等键。

## 结果

消费者可以重放和迁移，确认结论可以追到原始证据；代价是所有契约变化都必须维护兼容测试、转换器和版本支持窗口。

## 验证

正例、缺字段、未知受信字段、不支持版本、重复/乱序、跨租户、hash mismatch 与历史回放必须进入自动测试。
