# 数据库迁移

迁移使用 Alembic，并通过 `AISOC_DATABASE_URL` 读取 PostgreSQL asyncpg DSN。

```bash
uv run alembic upgrade head
uv run alembic current
uv run alembic downgrade base
```

生产变更采用 expand/contract；迁移不得读取模型 Provider、调用外部网络或静默删除租户数据。
