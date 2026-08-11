# Configuration

运行配置通过 `AISOC_*` 环境变量、`/etc/aisoc/aisoc.env` 与 enrollment 生成的 Agent 配置提供。

仓库只保留非敏感示例；真实 token、模型 API key、CA private key、quarantine key、webhook secret 和 Agent identity 不应提交到 Git。

完整环境变量示例见根目录 `.env.example`，Agent 字段示例见 `deploy/agent.example.json`。
