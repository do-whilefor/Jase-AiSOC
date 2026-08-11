# AI-SOC 静态安全审计（2026-08-11）

## 审计边界

本轮依据项目计划书、当前工作树、配置、部署脚本、Rust/Python 边界和测试代码执行静态审计。动态 PostgreSQL、多发行版 VM、真实 auditd/eBPF/Suricata/Falco、生产 Provider、动态沙箱和多 Host 响应仍需要独立环境验证；没有把未执行的结果标记为通过。

## 已处理问题

### 文件与证据边界

- evidence/quarantine 等敏感读取路径使用受限打开和类型/链接检查，避免仅依赖路径规范化后再次按路径读取。
- Agent CA 私钥、身份/发布相关私有文件继续要求普通文件、私有权限和有界读取。
- Rust/Python 文件 Hash 均使用 `O_NOFOLLOW`/有界读取，并在读取结束后检查 size/mtime/ctime 变化，降低扫描过程中目标被替换或改写造成的歧义。
- IOC feed 在 JSON 解析前先执行固定 SHA-256 校验，并拒绝 symlink、多 hardlink、group/world-writable 与超限文件。

### 下载与网络

- Agent 发布下载要求 HTTPS 和规范化 host allowlist，拒绝 userinfo/fragment，不依赖环境代理或自动 redirect。
- mTLS transport 校验服务端证书链与 hostname，并限制 TLS 下限；监听地址和证书身份分离。
- HTTP/Webhook/响应命令路径不使用 `shell=True` 或 `os.system`；外部命令保持参数数组和目标重验证。

### Linux-only 运行边界

- runtime 不再维护 Windows 进程、信号、注册表、Service/Event Log 等分支。
- Agent supervisor、文件锁、权限检查和进程组按 Linux/POSIX 语义执行。
- 归档仍拒绝反斜杠、drive-like、绝对路径和 `..`；这是处理不可信归档的路径穿越防护，不是 Windows 平台兼容层。
- PE 样本解析保留，因为 Linux SOC 需要分析跨平台恶意文件格式；这不扩大目标运行平台。
- npm/Cargo lockfile 中可能存在上游包管理器自动生成的 `win32` 可选依赖元数据。该内容不在项目运行分支中，手工删除会破坏 lockfile 的生成一致性，因此保留。

### Rust Core 与 fallback

- `aisoc-core` 明确 Linux-only，并禁止 crate 内 unsafe code。
- PyO3 bridge 暴露 Hash/HMAC、Linux capability、ELF/entropy/strings 与 IOC matcher。
- Python fallback 只用于开发、测试和显式诊断降级；通用 Linux 安装器默认要求预构建 Rust wheel 或 Cargo 1.82+。
- release CI 生成 Rust wheel；`deploy/Dockerfile` 必须安装并成功 import `aisoc_rust`，缺少 wheel 时构建失败，避免发布 Python-only 镜像而不自知。

### Secret 与命名

- 环境变量、CLI、Python 包、systemd unit、schema host 与 webhook header 统一到 `AISOC`/`aisoc` 命名。
- 本地 `.env` 被忽略且不会进入交付包；示例配置不包含真实 token/private key。
- 安装器不会生成假 Agent 身份、假证书或假 enrollment 结果。
- Agent 配置以 `aisoc:aisoc`、`0600` 安装，与运行时私有配置检查一致。

## 静态扫描结论

当前运行源码未发现 `todo!()`、`unimplemented!()`、`TODO/FIXME` 生产占位、`shell=True`、`os.system()`、Windows runtime API 或旧 `blue_team` Python import。代码中存在的普通 `return True` 均属于条件判断/状态检查，不作为“永远成功”的伪实现判断依据。

高置信 secret 模式没有发现真实凭据；本轮不读取或打包本地 `.env`。前端 `package-lock.json` 和根 `Cargo.lock` 由包管理器维护，不通过手工裁剪平台可选条目来制造“无 Windows 字样”的表面结果。

## 仍需动态关闭的安全门禁

1. 在固定 Linux VM 上执行 symlink/hardlink/FIFO/rename race、权限、SELinux/AppArmor 与服务身份验证。
2. 用真实 PostgreSQL 执行双租户 ID substitution、并发、事务/迁移回滚和完整 P3-P11 integration tests。
3. 用受控 HTTPS/DNS/proxy 环境验证下载 allowlist、证书、redirect、慢流、超限与 URL secret 处理。
4. 验证 auditd/eBPF/Suricata/Falco 在不同发行版的真实权限、性能和 graceful degradation。
5. 完成响应动作的真实多 Host 目标重验证、三类 rollback 与失败恢复测试。
6. 完成 fuzz、DAST、性能/容量、备份恢复、RPO/RTO 和正式 Go/No-Go。
