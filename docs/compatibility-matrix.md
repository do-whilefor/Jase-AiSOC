# Linux 兼容与验证矩阵

能力等级描述“能观察什么”，支持等级描述“项目对该组合承担什么责任”。当前不把任何发行版直接标记为 Certified；进入发布门禁前必须固定 `VERSION_ID`、内核、架构和镜像/ISO 摘要，确保测试可复现。

## 目标矩阵

| 发行版族 | 代表目标 | 目标能力 | 制品方向 | 必测差异 | 当前状态 |
|---|---|---:|---|---|---|
| Debian | 固定 stable 版本 | L1，满足条件时 L2 | DEB + tar.gz | journald/auditd、AppArmor、BTF、离线依赖 | Experimental |
| Ubuntu | 固定 LTS 版本 | L1/L2 | DEB + tar.gz | AppArmor、BTF、systemd、云镜像差异 | Experimental |
| RHEL | 固定受支持 major | L1/L2 | RPM + tar.gz | SELinux enforcing、audit、firewalld、BTF | Experimental |
| Rocky/Alma | 固定受支持 major | L1/L2 | RPM + tar.gz | RHEL 兼容性、SELinux、最小化镜像 | Experimental |
| Fedora | 固定 stable 版本 | L1/L2 | RPM + tar.gz | 新内核/eBPF 回归、SELinux | Experimental |
| openSUSE | 固定 stable 版本 | L1，满足条件时 L2 | RPM + tar.gz | AppArmor/SELinux、zypper、日志路径 | Experimental |
| Arch | 固定 snapshot | L1，L2 实验 | tar.gz | 滚动内核、pacman、systemd 变化 | Experimental |

## 每个组合必须记录

- `/etc/os-release` 的 ID/版本、内核、架构、init、cgroup、LSM 与安全模块模式。
- BTF、eBPF hook、journald、auditd、Suricata/Falco 和所需 capability 的探测结果。
- Agent/Collector/策略/Schema 版本和采集 profile。
- 安装、启动、心跳、采集、断网恢复、升级、回滚、卸载和失败降级结果。
- 每个 Collector 的 `enabled/degraded/failed`、drop count、last error 和能力缺口。
- CPU、内存、EPS、队列、磁盘和网络基线。

## 支持晋级

- **Experimental → Supported**：正式制品、关键场景、明确降级路径和已知限制通过。
- **Supported → Certified**：进入持续 VM/CI 矩阵，安装/升级/卸载/采集/降级/恢复和性能持续通过。
- 单次安装成功或 eBPF 对象加载成功不构成晋级证据。
- 滚动发行版或新内核回归失败时保持或降为 Experimental，并明确禁用无法保证安全边界的能力。

当前沙箱验证不能替代真实宿主的 systemd、journald、auditd、eBPF、SELinux/AppArmor、DEB/RPM 与 power-loss 测试。支持声明必须以固定 Linux VM/CI 矩阵为准。
