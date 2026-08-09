import {
  jsonError,
  proxyControlPlane,
  requireIncidentId,
} from "../_proxy";

export const dynamic = "force-dynamic";

export async function GET(request: Request): Promise<Response> {
  const incoming = new URL(request.url);
  if ([...incoming.searchParams.keys()].some((key) => key !== "incident_id") || incoming.searchParams.getAll("incident_id").length !== 1) {
    return jsonError(400, "仅允许一个 incident_id 查询参数。", "console_query_invalid");
  }
  const incidentId = requireIncidentId(incoming.searchParams.get("incident_id"));
  if (incidentId instanceof Response) return incidentId;
  return proxyControlPlane({
    request,
    method: "GET",
    path: `/api/v1/console/incidents/${incidentId}`,
  });
}
