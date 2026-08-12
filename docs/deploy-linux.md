# 通用 Linux Rust-first 部署

`deploy/linux/install.sh` 是 AI-SOC V4 的原生 Linux 安装入口。正常安装只接受经过校验的 Rust release bundle；Python 仅能通过显式 `--legacy-python` 进入迁移兼容环境，不属于生产主链路。

## 支持策略

目标是兼容 Ubuntu、Debian、RHEL/Rocky/Alma、Fedora、openSUSE、Arch 及兼容的主流 Linux Server。当前仓库具备通用安装器、systemd 单元、能力探测与 release install/upgrade/rollback 机制，但 P13 的固定版本 VM/镜像兼容矩阵尚未执行完成，因此不能把这些发行版标记为 Certified。

安装器会：

- 要求 Linux；正常模式不检查、不安装 Python。
- 可选检测 `apt-get`、`dnf`、`yum`、`zypper`、`pacman`，安装 CA、curl、OpenSSL、Nginx 等基础依赖。
- 创建 `aisoc` 服务账号以及 `/opt/aisoc`、`/etc/aisoc`、Agent/Ingest 状态目录。
- 通过 `deploy/linux/release-manager.sh` 校验 `manifest.sha256`，生产环境默认要求 detached signature，并原子切换 `current`/`previous` release。
- 根据 role 配置 Rust Agent、Ingest、API、Console、Web Guard systemd 服务。
- Agent role 要求外部 enrollment 生成的真实配置，不伪造 tenant/host/agent identity 或证书。

## 正常部署前置条件

至少需要：

- 已构建的 Rust release bundle，包含 `aisoc-agent`、`aisoc-ingest`、`aisoc-api`、`aisoc-console`、`aisoc-web-guard`、`aisoc-db` 和 `manifest.sha256`。
- `openssl`、`sha256sum`；生产环境还需要 release verification public key。
- Control role 首次安装需要长度至少 32 的 bootstrap API token 与合法 `ten_...` tenant id，或提供 `AISOC_API_AUTH_SOURCE`。
- Agent role 需要 enrollment 后的 `agent-rust.json`，启用 mTLS 时还需要证书、私钥、CA 路径。

当前已实现原生 PostgreSQL + SQLx migration plane，生产 Control 安装要求 `AISOC_DATABASE_URL` 并在启动服务前运行 release 内的 `aisoc-db migrate`。API 在 production 也要求数据库连接并把 PostgreSQL health 纳入 `/readyz`。但 Ingest/Detection/Incident 等 central repository 尚未完全从本地 append-only state 切换到 PostgreSQL/Object Store，因此 P1/P3 数据层验收仍未关闭。

## 构建 release bundle

在具备 Rust 1.82 且 `Cargo.lock` 已正确提交的构建机上：

```bash
make rust-first-check
make rust-lock-check
make rust-ci
make rust-release
```

当前 `Cargo.lock` 若未覆盖所有 native workspace package，`make rust-lock-check` 会 fail closed；先在可访问 Rust registry 的可信构建环境执行 `cargo generate-lockfile`，审查并提交锁文件，再继续 release build。

## 安装 Control Plane

```bash
export AISOC_RELEASE_DIR=/secure/release/aisoc-v4
export AISOC_RELEASE_VERSION=v4.0.0-dev.1
export AISOC_BOOTSTRAP_API_TOKEN='replace-with-at-least-32-random-characters'
export AISOC_BOOTSTRAP_TENANT_ID='ten_local001'
export AISOC_ENVIRONMENT=production
export AISOC_RELEASE_VERIFY_KEY=/etc/aisoc-release/release-public.pem
export AISOC_DATABASE_URL='postgresql://aisoc:replace-me@db.internal:5432/aisoc'
sudo -E bash deploy/linux/install.sh --role control --enable-services
```

Control role 会生成 ingest control/proxy secret，并安装 Nginx mTLS 模板；证书 serial 映射和真实 TLS 路径仍必须由部署系统填充后再启用公网/跨主机 Ingest。

## 安装 Agent

```bash
export AISOC_RELEASE_DIR=/secure/release/aisoc-v4
export AISOC_RELEASE_VERSION=v4.0.0-dev.1
export AISOC_AGENT_CONFIG_SOURCE=/secure/enrollment/agent-rust.json
sudo -E bash deploy/linux/install.sh --role agent --enable-services
```

Agent 私有配置安装为 `/etc/aisoc/agent-rust.json`，默认 state 目录是 `/var/lib/aisoc-agent`。journald、auditd、eBPF、Suricata、Falco 属于 capability，不是所有安装的硬前提；实际 collector 取决于 capability probe 和配置。

## Edge / Web Guard

```bash
export AISOC_RELEASE_DIR=/secure/release/aisoc-v4
sudo -E bash deploy/linux/install.sh --role edge --enable-services
```

Web Guard 配置使用 `AISOC_WEB_GUARD_*`。AI 默认关闭；启用时必须显式提供模型 gateway、key、model、预算和 timeout。生产切换顺序仍应是 monitor/shadow -> canary -> enforce，并以 P5/P14 的误报和延迟门禁为准。

## 非 systemd 系统

安装器会完成 release 与配置，但不启用服务。可由现有 supervisor 直接运行 Rust binary：

```bash
/opt/aisoc/current/bin/aisoc-ingest
/opt/aisoc/current/bin/aisoc-api
/opt/aisoc/current/bin/aisoc-console
/opt/aisoc/current/bin/aisoc-web-guard
/opt/aisoc/current/bin/aisoc-agent run /etc/aisoc/agent-rust.json
```

## 回滚

```bash
sudo AISOC_INSTALL_PREFIX=/opt/aisoc deploy/linux/release-manager.sh status
sudo AISOC_INSTALL_PREFIX=/opt/aisoc deploy/linux/release-manager.sh rollback
```

Release manager 只切换已经通过 checksum/signature 验证的不可变 release，并尝试重启已启用的 systemd unit。

## 迁移期 Python 基线

只有明确需要对照旧实现时才使用：

```bash
sudo -E bash deploy/linux/install.sh \
  --role control \
  --release-dir /secure/release/aisoc-v4 \
  --legacy-python
```

它会创建 `/opt/aisoc/legacy-python-venv`。该环境不被 Rust systemd unit、正常 Dockerfile、P1/P2 Rust Compose 或 release bundle引用。Alembic/FastAPI/SQLAlchemy 路径仅用于迁移回归；`make legacy-migrate` 也是同一性质。生产迁移使用 `make migrate AISOC_DATABASE_URL=postgresql://...` 或 release 内的 `aisoc-db migrate`。

## 当前未关闭的部署门禁

- P1 central repository cutover、SQLx migration 的真实 PostgreSQL integration execution，以及稳定 `Cargo.lock`。
- P2 多发行版 VM 上的真实 mTLS enrollment、journald/audit/process/network collector 验证。
- P5 Web Guard TLS/H2/走私差异测试、性能基线和直接 Ingest 事件链路。
- P11 Agent Action Runner 端到端审批、执行、TTL、rollback 验证。
- P13 SELinux/AppArmor、fuzz/DAST、备份恢复、RPO/RTO、灾难演练。
- P14 真实业务 shadow/canary/block 试点和 Go/No-Go 签字。
