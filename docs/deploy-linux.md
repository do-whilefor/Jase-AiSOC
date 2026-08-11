# 通用 Linux 部署

`deploy/linux/install.sh` 是 AI-SOC 的原生 Linux 安装入口。它不把某个发行版、包管理器、init system 或安全工具作为运行前提。

## 支持策略

目标发行版包括 Ubuntu、Debian、RHEL、Rocky Linux、AlmaLinux、Fedora、openSUSE、Arch Linux 以及兼容的主流 Linux Server。当前仓库提供通用安装逻辑，但“支持”不等于“Certified”：正式 Certified 状态必须来自固定版本 VM/镜像的持续兼容测试。

安装器会：

- 检查 Linux 与 Python 3.12+。
- 可选检测 `apt-get`、`dnf`、`yum`、`zypper`、`pacman` 安装基础依赖。
- 创建 `aisoc` 服务账号和 `/opt/aisoc`、`/etc/aisoc`、`/var/lib/aisoc*`。
- 安装 Python 服务层，并默认要求可验证的 `aisoc_rust` bridge；Control role 随后执行 Alembic migration。
- 检测 PID 1 是否为 systemd；若不是，仅给出手动进程命令，不直接失败。
- Agent role 要求已有 enrollment 配置，不自动伪造 tenant/host/agent identity 或证书。

## 前置条件

Control role 至少需要：

- Python 3.12+ 与 `venv`/pip。
- 可访问的 PostgreSQL。
- 正确配置的 `AISOC_DATABASE_URL`。
- 与目标 Python/架构兼容的 `AISOC_RUST_WHEEL`，或 Rust/Cargo 1.82+ 用于源码构建 bridge。

Agent role 至少需要：

- Python 3.12+。
- 与目标 Python/架构兼容的 `AISOC_RUST_WHEEL`，或 Rust/Cargo 1.82+。
- enrollment 后的私有 `agent.json`。
- 若启用 mTLS ingest，配置中必须包含对应证书、私钥与 CA 路径。

journald、auditd、eBPF、Suricata、Falco 都是能力项，不是基础安装前提。Agent 应通过 `aisoc-probe-platform` 报告可用、降级或不可用状态。

## 安装 Control Plane

```bash
export AISOC_DATABASE_URL='postgresql+asyncpg://aisoc:<password>@db.internal:5432/aisoc'
export AISOC_ENVIRONMENT=development
export AISOC_RUST_WHEEL=/secure/release/aisoc_python-0.1.0-cp312-abi3-linux_x86_64.whl
sudo -E bash deploy/linux/install.sh --role control --enable-services
```

如果未提供 `AISOC_RUST_WHEEL`，但系统存在 Cargo，安装器会固定使用 `maturin==1.14.1` 构建 `crates/aisoc-python` 并在安装后执行 `import aisoc_rust` 验证。正常安装缺少 wheel 和 Cargo 时会 fail closed。`--allow-python-core-fallback` 只用于开发/诊断，不属于正式部署路径。

如果机器缺少 Python/CA/OpenSSL 等基础包，可让安装器使用检测到的包管理器：

```bash
sudo -E bash deploy/linux/install.sh \
  --role control \
  --install-system-deps \
  --enable-services
```

`--install-system-deps` 只安装最小通用依赖，不会安装 auditd、Suricata、Falco 或发行版特有安全工具。

## 安装 Agent

先通过平台的 enrollment 流程得到真实 Agent 配置，再执行：

```bash
export AISOC_AGENT_CONFIG_SOURCE=/secure/enrollment/agent.json
export AISOC_RUST_WHEEL=/secure/release/aisoc_python-0.1.0-cp312-abi3-linux_x86_64.whl
sudo -E bash deploy/linux/install.sh --role agent --enable-services
```

配置会以 `aisoc:aisoc`、`0600` 安装到 `/etc/aisoc/agent.json`，与 Agent 的私有配置门禁一致；默认 Agent state 位于 `/var/lib/aisoc-agent`。

不要把 `deploy/agent.example.json` 当成真实身份配置；它只用于字段示例。

## 非 systemd 系统

如果 `/proc/1/comm` 不是 `systemd`，安装器不会假设 `systemctl` 可用。可使用现有 init/supervisor 运行：

```bash
/opt/aisoc/.venv/bin/aisoc-api
/opt/aisoc/.venv/bin/aisoc-ingest
/opt/aisoc/.venv/bin/aisoc-agent run --config /etc/aisoc/agent.json
```

按 role 只启动需要的进程。

## systemd

仓库提供：

```text
deploy/systemd/aisoc-api.service
deploy/systemd/aisoc-ingest.service
deploy/systemd/aisoc-agent.service
```

安装后可检查：

```bash
systemctl status aisoc-api.service
systemctl status aisoc-ingest.service
systemctl status aisoc-agent.service
journalctl -u aisoc-agent.service
```

## 能力探测

```bash
/opt/aisoc/.venv/bin/aisoc-probe-platform --pretty
```

探测结果用于决定 collector 级别和降级策略。缺失 auditd/eBPF 或 systemd 不应使整个 Agent 无条件退出；只有被明确配置为必需的能力失败时才应阻断相关功能。

## IOC feed

可选本地 IOC feed 需要同时配置路径与固定 SHA-256：

```bash
export AISOC_DETECTION_IOC_FEED_PATH=/etc/aisoc/ioc/feed.json
export AISOC_DETECTION_IOC_FEED_SHA256='<sha256>'
```

安装器会把这两个值写入 `/etc/aisoc/aisoc.env`。Feed 本身应由部署系统以只读、非链接、非 group/world-writable 方式下发。

## 目录与权限

默认目录：

```text
/opt/aisoc                  application + virtualenv
/etc/aisoc                 configuration
/var/lib/aisoc             control-plane state/evidence
/var/lib/aisoc-agent       Agent local state
```

不要把模型 API key、CA private key、quarantine key 或 webhook secret 提交进仓库。生产环境应由 secret manager 或受限配置管理系统注入。

## 当前限制

仓库当前只实现 development authentication，并在 `AISOC_ENVIRONMENT=production` 时 fail closed。正式生产部署前必须补齐生产认证，并完成目标发行版固定版本的 VM 级安装/升级/卸载、collector 降级、SELinux/AppArmor、文件权限、响应回滚和高负载验证。
