# 数据库迁移

本目录是迁移期保留的 Alembic/Python 数据模型基线。V4 production migration 已转到 `crates/aisoc-storage/migrations` 的 Rust SQLx 路径；旧 Alembic 仅用于 differential/regression。共享 `AISOC_DATABASE_URL` 可使用标准 `postgresql://` DSN，legacy Python Settings 会在进程内规范化为 asyncpg dialect。

```bash
uv run alembic upgrade head
uv run alembic current
uv run alembic downgrade base
```

生产变更采用 expand/contract；迁移不得读取模型 Provider、调用外部网络或静默删除租户数据。
