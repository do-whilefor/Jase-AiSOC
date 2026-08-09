import {
  hasExactKeys,
  jsonError,
  proxyControlPlane,
  readJsonObject,
  requireActionId,
  requireString,
  requireWriteBoundary,
} from "../_proxy";

export const dynamic = "force-dynamic";

export async function POST(request: Request): Promise<Response> {
  const boundaryError = await requireWriteBoundary(request);
  if (boundaryError) return boundaryError;
  const body = await readJsonObject(request);
  if (body instanceof Response) return body;
  if (!hasExactKeys(body, ["action_id", "business_confirmation", "comment", "decision"])) {
    return jsonError(400, "审批请求字段无效。", "console_request_shape_invalid");
  }
  const actionId = requireActionId(typeof body.action_id === "string" ? body.action_id : null);
  if (actionId instanceof Response) return actionId;
  if (body.decision !== "approve" && body.decision !== "reject") {
    return jsonError(400, "decision 必须是 approve 或 reject。", "console_request_invalid");
  }
  const comment = requireString(body, "comment", 1, 512);
  if (comment instanceof Response) return comment;
  if (typeof body.business_confirmation !== "boolean") {
    return jsonError(400, "business_confirmation 必须是布尔值。", "console_request_invalid");
  }
  return proxyControlPlane({
    request,
    method: "POST",
    path: `/api/v1/response-actions/${actionId}/approvals`,
    body: {
      decision: body.decision,
      comment,
      business_confirmation: body.business_confirmation,
    },
  });
}
