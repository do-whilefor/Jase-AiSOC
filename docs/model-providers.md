# 模型 Provider 接入指南

P7 事件级 AI Review 通过 OpenAI 兼容协议接入大模型。本文说明如何为 Kimi、GLM、
DeepSeek、OpenAI 官方与自定义 OpenAI 兼容端点（含本地 vLLM）配置 API key 与模型。

## 配置入口

所有 Provider 共用三个环境变量（前缀 `BLUE_TEAM_AI_REVIEW_`）：

| 环境变量 | 说明 |
|---|---|
| `BLUE_TEAM_AI_REVIEW_PROVIDER` | `kimi` / `glm` / `deepseek` / `openai` / `openai_compatible` |
| `BLUE_TEAM_AI_REVIEW_API_KEY` | Provider API key（SecretStr，**永不提交 git 或写入 `.env.example`**） |
| `BLUE_TEAM_AI_REVIEW_MODEL_NAME` | 模型名，如 `moonshot-v1-32k` |

固定 base 的预设 Provider（kimi/glm/deepseek/openai）只需上述三项；`openai_compatible`
还需 `BLUE_TEAM_AI_REVIEW_BASE_URL`。默认关闭：设 `BLUE_TEAM_AI_REVIEW_ENABLED=true`
启用。完整预算/熔断/审批项见 `.env.example`。

## Provider 预设

固定 base 的 Provider 由 `src/blue_team/ai_review/providers/openai_compatible.py` 的
`PROVIDER_PRESETS` 集中定义；新增固定 base Provider = 一条预设 + 一个瘦子类。

| Provider | 固定 base | 推荐模型 | API key 获取 |
|---|---|---|---|
| `kimi` | `https://api.moonshot.cn` | `moonshot-v1-32k` | https://platform.moonshot.cn |
| `glm` | `https://open.bigmodel.cn/api/paas/v4` | `glm-4` | https://open.bigmodel.cn |
| `deepseek` | `https://api.deepseek.com` | `deepseek-chat` | https://platform.deepseek.com |
| `openai` | `https://api.openai.com/v1` | `gpt-4o-mini` | https://platform.openai.com |
| `openai_compatible` | 自定义 `BASE_URL` | 自定义 | 见端点文档（本地 vLLM 无需 key） |

### 示例：接入 DeepSeek

```bash
BLUE_TEAM_AI_REVIEW_ENABLED=true
BLUE_TEAM_AI_REVIEW_PROVIDER=deepseek
BLUE_TEAM_AI_REVIEW_MODEL_NAME=deepseek-chat
BLUE_TEAM_AI_REVIEW_API_KEY=sk-从-secret-manager-加载
```

### 示例：接入 OpenAI 官方

```bash
BLUE_TEAM_AI_REVIEW_ENABLED=true
BLUE_TEAM_AI_REVIEW_PROVIDER=openai
BLUE_TEAM_AI_REVIEW_MODEL_NAME=gpt-4o-mini
BLUE_TEAM_AI_REVIEW_API_KEY=sk-从-secret-manager-加载
```

### 示例：本地 vLLM（OpenAI 兼容）

```bash
BLUE_TEAM_AI_REVIEW_ENABLED=true
BLUE_TEAM_AI_REVIEW_PROVIDER=openai_compatible
BLUE_TEAM_AI_REVIEW_BASE_URL=http://127.0.0.1:8000/v1
BLUE_TEAM_AI_REVIEW_MODEL_NAME=Qwen2.5-7B-Instruct
# BLUE_TEAM_AI_REVIEW_API_KEY 可留空或填 vLLM 配置的占位 key
```

> `openai_compatible` 是唯一允许 `http://` 的分支，且**仅限 loopback**
> (`127.0.0.1`/`localhost`/`::1`)，用于本地模型服务器。非 loopback HTTP 一律拒绝。

## 安全边界（已审计验证，不可放宽）

以下属性在 `docs/security-audit-p7-p12.md` 已逐行验证，新增 Provider 不削弱：

- **API key 为 `SecretStr`**：仅在 `Authorization: Bearer {key}` 头发送，从不进入错误消息、
  日志或控制台投影（`api_key_state` 只报 `configured`/`not_configured`，不返回明文）。
- **固定 HTTPS**：四家预设 base 均为 HTTPS；`openai_compatible` 的 `require_safe_base_url`
  仅放行 loopback HTTP，拒绝 userinfo/query/fragment/重定向。
- **禁重定向**：`allow_redirects=False`，3xx 视为 `webhook_redirect_rejected`。
- **响应字节上限**：`max_response_bytes` 默认 2 MiB，防止超大响应耗尽内存。
- **`allowed_response` 固定 `recommend_only`**：模型输出（`Literal["recommend_only"]`）
  永远不能授权自动响应动作；R2/R3 动作仍受策略门控、审批与目标重验证约束（见 P11）。
- **Prompt 注入隔离**：证据/Claim/ToolResult 文本永远在 user message；system 指令仅来自
  模块级常量，不混入不可信数据。

## 运维

- **key 轮换**：改 `BLUE_TEAM_AI_REVIEW_API_KEY` 后重启进程即可；key 不落库，无迁移。
- **健康检查**：`GET /api/v1/models/providers` 与控制台模型运营视图显示 `api_key_state`
  与 Provider 健康（`health_status`）；不可用时不阻塞确定性检测主链路。
- **降级**：模型不可用/预算耗尽时 Review Gate 自动降级为 `Deterministic Only`，
  确定性检测、Incident、证据查询与人工响应仍可用。
