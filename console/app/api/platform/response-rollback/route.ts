import {
  hasExactKeys,
  jsonError,
  proxyControlPlane,
  readJsonObject,
  requireActionId,
  requireString,
  requireWriteBoundary,
} from "../_proxy";

const IDEMPOTENCY_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/;

export const dynamic = "force-dynamic";

export async function POST(request: Request): Promise<Response> {
  const boundaryError = await requireWriteBoundary(request);
  if (boundaryError) return boundaryError;
  const body = await readJsonObject(request);
  if (body instanceof Response) return body;
  if (!hasExactKeys(body, ["action_id", "idempotency_key", "reason"])) {
    return jsonError(400, "回滚请求字段无效。", "console_request_shape_invalid");
  }
  const actionId = requireActionId(typeof body.action_id === "string" ? body.action_id : null);
  if (actionId instanceof Response) return actionId;
  const idempotencyKey = requireString(body, "idempotency_key", 8, 128);
  if (idempotencyKey instanceof Response) return idempotencyKey;
  if (!IDEMPOTENCY_PATTERN.test(idempotencyKey)) {
    return jsonError(400, "idempotency_key 格式无效。", "console_request_invalid");
  }
  const reason = requireString(body, "reason", 1, 512);
  if (reason instanceof Response) return reason;
  return proxyControlPlane({
    request,
    method: "POST",
    path: `/api/v1/response-actions/${actionId}/rollback`,
    body: { reason, idempotency_key: idempotencyKey },
  });
}
