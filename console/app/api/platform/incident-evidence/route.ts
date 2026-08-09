import {
  jsonError,
  proxyControlPlane,
  requireEvidenceId,
  requireIncidentId,
} from "../_proxy";

export const dynamic = "force-dynamic";

export async function GET(request: Request): Promise<Response> {
  const incoming = new URL(request.url);
  const allowed = new Set(["incident_id", "evidence_id"]);
  if ([...incoming.searchParams.keys()].some((key) => !allowed.has(key))) {
    return jsonError(400, "证据查询参数无效。", "console_query_invalid");
  }
  if (incoming.searchParams.getAll("incident_id").length !== 1 || incoming.searchParams.getAll("evidence_id").length !== 1) {
    return jsonError(400, "incident_id 和 evidence_id 必须各出现一次。", "console_query_invalid");
  }
  const incidentId = requireIncidentId(incoming.searchParams.get("incident_id"));
  if (incidentId instanceof Response) return incidentId;
  const evidenceId = requireEvidenceId(incoming.searchParams.get("evidence_id"));
  if (evidenceId instanceof Response) return evidenceId;
  return proxyControlPlane({
    request,
    method: "GET",
    path: `/api/v1/console/incidents/${incidentId}/evidence/${evidenceId}`,
  });
}
