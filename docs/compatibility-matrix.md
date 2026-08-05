# Linux 兼容与验证矩阵

能力等级描述“能观察什么”，支持等级描述“项目对该组合承担什么责任”。P0 不宣称任何发行版为 Certified；具体版本、内核、架构和镜像摘要必须在执行测试时固定到报告。

## P2 基础矩阵

| 发行版族 | 代表目标 | P0 目标等级 | 安装制品 | 必测差异 | 初始支持状态 |
|---|---|---:|---|---|---|
| Debian | Debian 当前受支持 stable | L1，满足条件时 L2 | DEB + 自包含 tar.gz | journald/auditd、AppArmor、BTF、离线 wheel | Experimental |
| Ubuntu | 当前受支持 LTS | L1/L2 | DEB + 自包含 tar.gz | AppArmor、BTF、systemd、云镜像差异 | Experimental |
| Kali | Kali Rolling 固定日期快照 | L1，L2 实验 | DEB + 自包含 tar.gz | 滚动内核、预装安全工具、升级兼容 | Experimental |
| RHEL | Rocky Linux 当前受支持 major | L1/L2 | RPM + 自包含 tar.gz | SELinux enforcing、audit、firewalld、BTF | Experimental |
| Fedora | Fedora 当前受支持 stable | L1/L2 | RPM + 自包含 tar.gz | 新内核/eBPF 回归、SELinux | Experimental |
| SUSE | openSUSE 当前受支持 stable | L1，满足条件时 L2 | RPM + 自包含 tar.gz | AppArmor/SELinux、zypper、日志路径 | Experimental |

“当前受支持”只用于规划；进入 CI 前必须在清单中替换为精确 `VERSION_ID`、内核范围、架构和镜像/ISO 哈希，避免滚动标签造成不可重复测试。

## 每个组合必须记录

- `/etc/os-release` 的 ID/版本、内核、架构、init、cgroup、LSM、安全模块模式；
- BTF、eBPF hook、journald、auditd、Suricata/Falco 和所需 capability 的探测结果；
- Agent/Collector/策略/Schema 版本以及采集 Profile；
- 安装、启动、心跳、采集、断网恢复、升级、回滚、卸载和失败降级结果；
- 每个 Collector 的 `enabled/degraded/failed`、drop count、last error 和能力缺口；
- CPU、内存、EPS、队列、磁盘和网络基线。

## 支持晋级规则

- **Experimental -> Supported**：正式制品、关键场景、明确降级路径和已知限制通过。
- **Supported -> Certified**：进入持续 VM/CI 矩阵，安装/升级/卸载/采集/降级/恢复和性能持续通过。
- 单次安装成功或 eBPF 对象加载成功不构成晋级证据。
- 滚动发行版和新内核回归失败时保持或降为 Experimental，并明确禁用高风险响应。

## 开发环境说明

当前宿主是 Windows；Docker Linux Engine 已能验证 UID、POSIX mode、单实例/安装文件锁、
符号链接、真实 Agent 子进程、启动/健康/停止超时、进程组 TERM→KILL 和基础崩溃恢复，但不能
替代真实宿主的 systemd、journald、auditd、eBPF、DEB/RPM 和 power-loss。支持声明仍必须以
固定 Linux CI/VM 矩阵为准。
