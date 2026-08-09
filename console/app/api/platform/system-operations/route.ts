import { jsonError, proxyControlPlane } from "../_proxy";

export const dynamic = "force-dynamic";

export async function GET(request: Request): Promise<Response> {
  const incoming = new URL(request.url);
  if ([...incoming.searchParams.keys()].length !== 0) {
    return jsonError(400, "系统运营视图不接受查询参数。", "console_query_invalid");
  }

  return proxyControlPlane({
    request,
    method: "GET",
    path: "/api/v1/console/system-operations",
  });
}
