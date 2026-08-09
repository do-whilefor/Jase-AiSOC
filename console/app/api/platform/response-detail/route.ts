import {
  jsonError,
  proxyControlPlane,
  requireActionId,
} from "../_proxy";

export const dynamic = "force-dynamic";

export async function GET(request: Request): Promise<Response> {
  const incoming = new URL(request.url);
  if ([...incoming.searchParams.keys()].some((key) => key !== "action_id") || incoming.searchParams.getAll("action_id").length !== 1) {
    return jsonError(400, "仅允许一个 action_id 查询参数。", "console_query_invalid");
  }
  const actionId = requireActionId(incoming.searchParams.get("action_id"));
  if (actionId instanceof Response) return actionId;
  return proxyControlPlane({
    request,
    method: "GET",
    path: `/api/v1/response-actions/${actionId}`,
  });
}
