# P11 Response / 受控响应

状态：Rust 响应控制面和本机 Agent-side Runner 已有初版，但三类真实回滚、远程多主机执行、Linux VM 故障注入与执行后验证尚未达到 V4.0 硬门禁，因此 P11 未退出。
计划来源：V4.0 P11 要求 R0–R3、审批、Agent-side Runner、三类真实回滚和执行后验证。

## 已实现

- `aisoc-policy`/`aisoc-response` 已形成类型化响应请求、R0–R3 策略门控、审批/拒绝状态机、执行租约、幂等记录、审计与通知 outbox。
- 请求人不能自批；高风险动作受审批人数、关键资产、业务确认、回滚能力和执行预算约束。
- Runner 使用固定 Adapter 与绝对路径 argv，不接受任意 shell 字符串；执行前重新观察目标身份，防止 PID 复用、文件替换或 Agent 绑定漂移。
- 本机 Linux 原生初版支持 nftables/firewalld 临时封禁、普通文件隔离、精确 allowlist 账号禁用，并要求 root、执行双开关、`local_single_node` profile 与私有 Agent 配置同时满足。
- API 已暴露响应详情、审批、执行排队和回滚请求所需的固定受控接口；浏览器端写请求仍由服务端 RBAC、nonce、origin 校验和响应状态机约束。

## 尚未达到硬门禁

- 三类真实动作的“执行 -> post-check -> 回滚 -> rollback post-check”Linux 实机证据仍不足，不能宣称 R2/R3 生产可用。
- 当前 Runner 只允许私有本机 Agent 绑定，不是跨主机远程执行器；生产多主机执行通道尚未实现。
- 未完成 PostgreSQL/Linux VM 并发、超时、目标变化、权限丢失、回滚失败、网络分区等故障注入。
- 未完成关键资产无未审批 R3、执行预算、通知/审计完整性和回滚 SLA 的正式验收报告。

## V4.0 P11 退出条件

1. R0–R3 权限与审批矩阵通过越权/重放/自批/跨租户测试。
2. Agent-side Runner 对固定动作实行目标重验证、TTL、执行预算、post-check 和完整审计。
3. 至少三类真实动作在受控 Linux 环境完成可重复的执行与回滚验证。
4. 回滚失败必须 fail closed、进入人工处理并保留证据；模型不能提高响应权限。
5. P11 通过后，Console/Operations 的完整运营验收归属 P12，不再混用阶段编号。

原先将“响应 + 控制台”合并描述的完整历史内容保留在 `docs/p11-response-console-legacy-annex.md`，避免删除有效设计；P12 控制台主阶段见 `docs/phase-p12-plan.md`。
