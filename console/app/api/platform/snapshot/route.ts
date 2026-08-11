const DEFAULT_CONTROL_PLANE = "http://127.0.0.1:8000";
const MAX_RESPONSE_BYTES = 1024 * 1024;
const REQUEST_TIMEOUT_MS = 10_000;

export const dynamic = "force-dynamic";

export async function GET(request: Request): Promise<Response> {
  const authorization = request.headers.get("authorization");
  if (!authorization || !/^Bearer [\x21-\x7e]{16,4096}$/.test(authorization)) {
    return jsonError(401, "缺少有效的操作员 Bearer 令牌。");
  }

  const incoming = new URL(request.url);
  const requestedLimit = Number(incoming.searchParams.get("limit") ?? "20");
  if (!Number.isInteger(requestedLimit) || requestedLimit < 1 || requestedLimit > 50) {
    return jsonError(400, "limit 必须是 1 到 50 的整数。");
  }

  let baseUrl: URL;
  try {
    baseUrl = validatedControlPlaneUrl(
      process.env.AISOC_API_BASE_URL ?? DEFAULT_CONTROL_PLANE,
    );
  } catch {
    return jsonError(503, "控制面地址配置无效。", "control_plane_configuration_invalid");
  }

  const target = new URL("/api/v1/console/snapshot", baseUrl);
  target.searchParams.set("limit", String(requestedLimit));
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  try {
    const upstream = await fetch(target, {
      method: "GET",
      headers: {
        accept: "application/json",
        authorization,
      },
      cache: "no-store",
      redirect: "manual",
      signal: controller.signal,
    });
    const declaredLength = Number(upstream.headers.get("content-length") ?? "0");
    if (Number.isFinite(declaredLength) && declaredLength > MAX_RESPONSE_BYTES) {
      return jsonError(502, "控制面响应超过安全上限。", "control_plane_response_too_large");
    }
    const contentType = upstream.headers.get("content-type") ?? "";
    if (!contentType.toLowerCase().startsWith("application/json")) {
      return jsonError(502, "控制面返回了非 JSON 响应。", "control_plane_invalid_content_type");
    }
    const body = await upstream.arrayBuffer();
    if (body.byteLength > MAX_RESPONSE_BYTES) {
      return jsonError(502, "控制面响应超过安全上限。", "control_plane_response_too_large");
    }
    return new Response(body, {
      status: upstream.status,
      headers: responseHeaders(),
    });
  } catch (error) {
    const timedOut = error instanceof Error && error.name === "AbortError";
    return jsonError(
      502,
      timedOut ? "控制面请求超时。" : "无法连接控制面。",
      timedOut ? "control_plane_timeout" : "control_plane_unavailable",
    );
  } finally {
    clearTimeout(timer);
  }
}

function validatedControlPlaneUrl(value: string): URL {
  const parsed = new URL(value);
  if (parsed.username || parsed.password || parsed.search || parsed.hash) {
    throw new Error("control plane URL must not contain credentials or parameters");
  }
  if (parsed.pathname !== "/" && parsed.pathname !== "") {
    throw new Error("control plane URL must be an origin");
  }
  const loopback = parsed.hostname === "127.0.0.1" || parsed.hostname === "localhost" || parsed.hostname === "[::1]";
  if (parsed.protocol !== "https:" && !(parsed.protocol === "http:" && loopback)) {
    throw new Error("non-loopback control planes require HTTPS");
  }
  return parsed;
}

function jsonError(status: number, detail: string, code = "operator_authentication_required"): Response {
  return Response.json({ detail, code }, { status, headers: responseHeaders() });
}

function responseHeaders(): HeadersInit {
  return {
    "cache-control": "no-store, max-age=0",
    "content-type": "application/json; charset=utf-8",
    "x-content-type-options": "nosniff",
  };
}
