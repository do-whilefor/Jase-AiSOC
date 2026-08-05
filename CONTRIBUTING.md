# 贡献指南

## 分支与变更

- 每个变更必须对应一个明确的阶段交付物、缺陷或 ADR。
- Schema、API、存储格式、信任边界和响应动作发生变化时，必须同时更新契约测试和相关 ADR。
- 禁止把密钥、Token、真实敏感日志、恶意样本或未脱敏模型输入提交到仓库。
- 不允许模型生成的任意 Shell 进入执行路径；响应能力必须使用固定动作 ID、严格参数 Schema 和策略门控。

## Python 约定

- 支持 Python 3.12 和 3.13；异步 I/O 使用 `asyncio`，CPU 密集工作进入进程池或独立 Worker。
- 公共函数和跨模块边界必须有完整类型；跨服务数据使用版本化 Pydantic/Protobuf/JSON Schema 契约。
- 使用结构化日志；禁止记录凭据、完整敏感字段和未经分类的原始证据。
- 外部组件通过 `Protocol`/Adapter 隔离，业务代码不得直接绑定厂商客户端。

## 本地检查

```bash
uv sync --locked --all-groups
uv run ruff format --check .
uv run ruff check .
uv run mypy src tests migrations
uv run blue-team-export-schemas --check
uv run pytest --cov
uv run pip-audit --skip-editable
uv run cyclonedx-py environment --output-format JSON --output-file reports/sbom.json
```

SBOM 文件是 CI 制品，不提交到 Git。涉及 Linux Agent、eBPF、systemd、auditd 或安装包的变更，还必须在目标 Linux VM/CI 矩阵中验证，Windows 本地测试不能替代该门禁。

## 完成定义

变更只有在以下条件同时满足时才可合并：

1. 契约、迁移和回滚策略明确；
2. 单元/集成/回放测试按影响范围补齐；
3. 日志、指标、审计和失败降级可观察；
4. 租户、对象、证据和动作边界经过负向测试；
5. 格式、静态检查、类型检查、测试、依赖审计和 SBOM 构建通过。
