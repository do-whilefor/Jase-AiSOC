# Kali Linux 快速部署

本文档给出在 Kali / Debian 系 Linux 上以原生方式（非 Docker）部署 Blue Team AI Agent 平台的最短路径。

> 设计原则：中心服务（API + Ingest 网关）以非特权 `blue-team` 用户运行；端点 Agent 通过 `adm`/`systemd-journal` 补充组只读访问系统日志与 journalctl，不具备写日志目录之外的权限，也不持有任何 Linux capability（§3 能力等级 L0/L1）。

## 前置条件

- Kali Rolling / Debian 12+ / Ubuntu 22.04+，Python 3.12+
- root 权限（`sudo`）
- 可访问 apt 源

## 一键安装

```bash
sudo apt update
sudo apt install -y git
git clone <your-repo-url> blue-team-ai-agent
cd blue-team-ai-agent
sudo bash deploy/kali/install.sh
```

`install.sh` 是幂等的，重复执行只会补齐缺失步骤。它会：

1. 安装 apt 依赖（python3、编译 cryptography 所需的 build-essential/libssl-dev、postgresql 等）
2. 创建非特权服务用户 `blue-team`
3. 在 `/opt/blue-team/.venv` 建立 Python 虚拟环境并安装本包
4. 初始化本地 PostgreSQL 数据库与角色
5. 写入 `/etc/blue-team/blue-team.env`（含 Ingest mTLS CA 路径）并运行 Alembic 迁移
6. 用 openssl 生成本地 mTLS CA
7. 写入 `/etc/blue-team/agent.json`（默认开启 journald + auditd 采集）
8. 通过 `scripts/bootstrap_agent_enrollment.py` 在 PostgreSQL 注册租户/主机/Agent 身份，并签发真实 mTLS 客户端证书（Ingest 网关按 `agent_certificates` 表校验客户端证书，不能使用独立签发的证书）。幂等：已注册则跳过。
9. 安装 systemd 单元并 `daemon-reload`

> 可选采集器：`suricata`、`auditd`、`nginx` 默认不随 `install.sh` 安装。启用对应采集器需先 `sudo apt install suricata auditd nginx` 并在 `/etc/blue-team/agent.json` 打开开关，确认日志文件存在且 `blue-team` 用户可读。

## P0–P6 本地可行性验证（已确认）

在不使用 root 的条件下，以下闭环已在 Kali 上动态验证通过（用户级 PostgreSQL 55432）：

- `blue-team-api` 启动、`/health/live` 200、后台 worker（含 FreshnessMonitor）运行
- `blue-team-ingest` 启动、mTLS 握手成功
- `blue-team-agent health-probe` 输出 STARTED/HEALTHY
- 平台能力探测（`blue-team-probe-platform`）真实报告 Kali L1：journald enabled、auditd failed（auditctl 缺失）、eBPF degraded
- `scripts/bootstrap_agent_enrollment.py` 注册 Agent 并签发证书，用该证书经 mTLS 向 Ingest 网关发送心跳，返回 200 且心跳持久化到 PostgreSQL

## 启动服务

```bash
sudo systemctl enable --now blue-team-api blue-team-ingest
sudo systemctl enable --now blue-team-agent
```

验证：

```bash
curl -s http://127.0.0.1:8000/health/live        # 应返回 200/ok
sudo journalctl -u blue-team-agent -f             # 查看 Agent 心跳与采集器状态
sudo -u blue-team /opt/blue-team/.venv/bin/blue-team-probe-platform --pretty
```

## 启用可选采集器

编辑 `/etc/blue-team/agent.json`，按需打开采集器并指向真实日志路径：

| 采集器 | 开关 | 默认日志路径 | 需要的组件 |
|---|---|---|---|
| journald | `journald_enabled` | systemd journal | `systemd-journal` 补充组（脚本已配置） |
| auditd | `auditd_enabled` | `/var/log/audit/audit.log` | `auditd` 包 |
| suricata | `suricata_enabled` | `/var/log/suricata/eve.json` | `suricata` 包并已配置 EVE 输出 |
| service_log | `service_log_enabled` | `/var/log/nginx/access.log` | `nginx`/`apache2`，使用 Common/Combined 日志格式 |

修改后：

```bash
sudo systemctl restart blue-team-agent
```

## 端口与路径速查

| 项目 | 值 |
|---|---|
| API | `127.0.0.1:8000` |
| Ingest 网关（mTLS） | `127.0.0.1:8001` |
| PostgreSQL | `127.0.0.1:5432`，库/用户 `blue_team` |
| 中心状态 | `/var/lib/blue-team` |
| Agent 状态 | `/var/lib/blue-team-agent`（含本地磁盘队列 `queue.sqlite3`） |
| 配置 | `/etc/blue-team/*.env`、`/etc/blue-team/agent.json` |
| 证书 | `/etc/blue-team/{ca,agent}.{crt,key}` |

## 卸载

```bash
sudo systemctl disable --now blue-team-api blue-team-ingest blue-team-agent
sudo rm /etc/systemd/system/blue-team-*.service && sudo systemctl daemon-reload
sudo rm -rf /opt/blue-team /var/lib/blue-team /var/lib/blue-team-agent /etc/blue-team
sudo -u postgres dropdb blue_team && sudo -u postgres psql -c 'DROP ROLE blue_team;'
sudo userdel blue-team && sudo groupdel blue-team
```

## 故障排查

- **`audit.log is unavailable`**：确认 `auditd` 已安装且 `/var/log/audit/audit.log` 存在；Agent 通过 `adm` 组读取，无需 root。
- **`journalctl exited`**：确认 `blue-team` 用户在 `systemd-journal` 组中（`id blue-team` 应见该组），重新登录或重启服务生效。
- **迁移失败**：先 `sudo -u postgres psql -c '\l'` 确认 `blue_team` 库存在且属主为 `blue_team`，再 `BLUE_TEAM_DATABASE_URL=... alembic upgrade head`。
- **端口冲突**：修改 `/etc/blue-team/blue-team.env` 的 `BLUE_TEAM_API_PORT` / `BLUE_TEAM_INGEST_PORT` 与 `agent.json` 的 `ingest_url` 保持一致。

## 多主机部署

单机安装只覆盖一台主机的采集与中心。多主机场景：在中心机执行 `install.sh`（仅启 `blue-team-api` + `blue-team-ingest`），在各端点机 `git clone` 后执行 `install.sh` 但只启用 `blue-team-agent`，并把各端点 `agent.json` 的 `ingest_url` 指向中心机的 `https://<center>:8001`，将中心机 CA 证书分发到各端点 `/etc/blue-team/ca.crt` 并为每台端点签发独立 Agent 证书。
