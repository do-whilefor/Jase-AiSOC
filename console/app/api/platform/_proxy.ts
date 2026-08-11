const DEFAULT_CONTROL_PLANE = "http://127.0.0.1:8000";
const MAX_REQUEST_BYTES = 8 * 1024;
const MAX_RESPONSE_BYTES = 1024 * 1024;
const REQUEST_TIMEOUT_MS = 10_000;
const WRITE_SESSION_TTL_SECONDS = 12 * 60 * 60;
const WRITE_SESSION_CLOCK_SKEW_SECONDS = 60;

const ACTION_ID_PATTERN = /^rsa_[a-f0-9]{32}$/;
const INCIDENT_ID_PATTERN = /^inc_[a-f0-9]{32}$/;
const EVIDENCE_ID_PATTERN = /^evi_[a-f0-9]{24}$/;
const SAMPLE_ID_PATTERN = /^smp_[a-f0-9]{32}$/;
const AUTHORIZATION_PATTERN = /^Bearer [\x21-\x7e]{16,4096}$/;
const CSRF_NONCE_PATTERN = /^v1\.([0-9]{10})\.([a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12})\.([a-f0-9]{64})$/;

type JsonObject = Record<string, unknown>;

type ProxyRequest = {
  request: Request;
  method: "GET" | "POST";
  path: string;
  body?: JsonObject;
};

export function requireAuthorization(request: Request): string | Response {
  const authorization = request.headers.get("authorization");
  if (!authorization || !AUTHORIZATION_PATTERN.test(authorization)) {
    return jsonError(401, "缺少有效的操作员 Bearer 令牌。", "operator_authentication_required");
  }
  return authorization;
}

export function requireActionId(value: string | null): string | Response {
  if (!value || !ACTION_ID_PATTERN.test(value)) {
    return jsonError(400, "action_id 格式无效。", "response_action_id_invalid");
  }
  return value;
}

export function requireIncidentId(value: string | null): string | Response {
  if (!value || !INCIDENT_ID_PATTERN.test(value)) {
    return jsonError(400, "incident_id 格式无效。", "incident_id_invalid");
  }
  return value;
}

export function requireEvidenceId(value: string | null): string | Response {
  if (!value || !EVIDENCE_ID_PATTERN.test(value)) {
    return jsonError(400, "evidence_id 格式无效。", "evidence_id_invalid");
  }
  return value;
}

export function requireSampleId(value: string | null): string | Response {
  if (!value || !SAMPLE_ID_PATTERN.test(value)) {
    return jsonError(400, "sample_id 格式无效。", "malware_sample_id_invalid");
  }
  return value;
}

export async function issueWriteSession(request: Request): Promise<Response> {
  const authorization = requireAuthorization(request);
  if (authorization instanceof Response) return authorization;
  const key = await writeSessionKey();
  if (key instanceof Response) return key;
  const issuedAt = Math.floor(Date.now() / 1000).toString();
  const unsigned = `v1.${issuedAt}.${crypto.randomUUID()}`;
  const signature = await signWriteSession(key, writeSessionMessage(request, authorization, unsigned));
  return Response.json(
    { csrf_nonce: `${unsigned}.${signature}`, expires_in_seconds: WRITE_SESSION_TTL_SECONDS },
    { status: 200, headers: responseHeaders() },
  );
}

export async function requireWriteBoundary(request: Request): Promise<Response | null> {
  const expectedOrigin = new URL(request.url).origin;
  const origin = request.headers.get("origin");
  const referer = request.headers.get("referer");
  if (!origin && !referer) {
    return jsonError(403, "写请求缺少同源证明。", "console_origin_required");
  }
  if (origin && !hasOrigin(origin, expectedOrigin)) {
    return jsonError(403, "写请求来源不匹配。", "console_origin_mismatch");
  }
  if (referer && !hasOrigin(referer, expectedOrigin)) {
    return jsonError(403, "写请求引用来源不匹配。", "console_referer_mismatch");
  }
  const csrfNonce = request.headers.get("x-aisoc-csrf");
  const match = csrfNonce?.match(CSRF_NONCE_PATTERN);
  if (!csrfNonce || !match) {
    return jsonError(403, "写请求缺少有效的控制台 nonce。", "console_csrf_invalid");
  }
  const issuedAt = Number(match[1]);
  const now = Math.floor(Date.now() / 1000);
  if (
    !Number.isSafeInteger(issuedAt)
    || issuedAt > now + WRITE_SESSION_CLOCK_SKEW_SECONDS
    || now - issuedAt > WRITE_SESSION_TTL_SECONDS
  ) {
    return jsonError(403, "控制台写入会话已过期。", "console_csrf_expired");
  }
  const authorization = requireAuthorization(request);
  if (authorization instanceof Response) return authorization;
  const key = await writeSessionKey();
  if (key instanceof Response) return key;
  const unsigned = `v1.${match[1]}.${match[2]}`;
  const signature = hexToBytes(match[3]);
  const valid = await crypto.subtle.verify(
    "HMAC",
    key,
    signature,
    new TextEncoder().encode(writeSessionMessage(request, authorization, unsigned)),
  );
  if (!valid) {
    return jsonError(403, "控制台写入会话验证失败。", "console_csrf_invalid");
  }
  return null;
}

export async function readJsonObject(request: Request): Promise<JsonObject | Response> {
  const contentType = request.headers.get("content-type")?.toLowerCase() ?? "";
  if (!contentType.startsWith("application/json")) {
    return jsonError(415, "写请求必须使用 application/json。", "console_json_required");
  }
  const declaredLength = request.headers.get("content-length");
  if (declaredLength !== null) {
    const parsedLength = Number(declaredLength);
    if (!Number.isSafeInteger(parsedLength) || parsedLength < 0) {
      return jsonError(400, "Content-Length 无效。", "console_content_length_invalid");
    }
    if (parsedLength > MAX_REQUEST_BYTES) {
      return jsonError(413, "控制台写请求超过安全上限。", "console_request_too_large");
    }
  }
  const bytes = await request.arrayBuffer();
  if (bytes.byteLength > MAX_REQUEST_BYTES) {
    return jsonError(413, "控制台写请求超过安全上限。", "console_request_too_large");
  }
  try {
    const parsed: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    if (!isJsonObject(parsed)) {
      return jsonError(400, "控制台写请求必须是 JSON object。", "console_json_object_required");
    }
    return parsed;
  } catch {
    return jsonError(400, "控制台写请求不是有效 JSON。", "console_json_invalid");
  }
}

export function hasExactKeys(body: JsonObject, expected: readonly string[]): boolean {
  const actual = Object.keys(body).sort();
  return actual.length === expected.length && actual.every((key, index) => key === [...expected].sort()[index]);
}

export function requireString(
  body: JsonObject,
  key: string,
  minimum: number,
  maximum: number,
): string | Response {
  const value = body[key];
  if (typeof value !== "string") {
    return jsonError(400, `${key} 必须是字符串。`, "console_request_invalid");
  }
  const normalized = value.trim();
  if (normalized.length < minimum || normalized.length > maximum) {
    return jsonError(400, `${key} 长度无效。`, "console_request_invalid");
  }
  return normalized;
}

export async function proxyControlPlane({ request, method, path, body }: ProxyRequest): Promise<Response> {
  const authorization = requireAuthorization(request);
  if (authorization instanceof Response) return authorization;
  if (!isAllowedControlPlanePath(path)) {
    return jsonError(500, "控制台代理路径配置无效。", "control_plane_path_invalid");
  }

  let baseUrl: URL;
  try {
    baseUrl = validatedControlPlaneUrl(
      process.env.AISOC_API_BASE_URL ?? DEFAULT_CONTROL_PLANE,
    );
  } catch {
    return jsonError(503, "控制面地址配置无效。", "control_plane_configuration_invalid");
  }

  const target = new URL(path, baseUrl);
  if (target.origin !== baseUrl.origin) {
    return jsonError(500, "控制台代理目标越界。", "control_plane_target_invalid");
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    const serialized = body === undefined ? undefined : JSON.stringify(body);
    if (serialized !== undefined && new TextEncoder().encode(serialized).byteLength > MAX_REQUEST_BYTES) {
      return jsonError(413, "控制台写请求超过安全上限。", "console_request_too_large");
    }
    const upstream = await fetch(target, {
      method,
      headers: {
        accept: "application/json",
        authorization,
        ...(serialized === undefined ? {} : { "content-type": "application/json" }),
      },
      body: serialized,
      cache: "no-store",
      redirect: "manual",
      signal: controller.signal,
    });
    if (upstream.status >= 300 && upstream.status < 400) {
      return jsonError(502, "控制面重定向已被拒绝。", "control_plane_redirect_rejected");
    }
    const lengthError = validateDeclaredLength(upstream.headers.get("content-length"));
    if (lengthError) return lengthError;
    const contentType = upstream.headers.get("content-type")?.toLowerCase() ?? "";
    if (!contentType.startsWith("application/json")) {
      return jsonError(502, "控制面返回了非 JSON 响应。", "control_plane_invalid_content_type");
    }
    const bytes = await upstream.arrayBuffer();
    if (bytes.byteLength > MAX_RESPONSE_BYTES) {
      return jsonError(502, "控制面响应超过安全上限。", "control_plane_response_too_large");
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    } catch {
      return jsonError(502, "控制面返回了无效 JSON。", "control_plane_invalid_json");
    }
    return Response.json(parsed, { status: upstream.status, headers: responseHeaders() });
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

export function jsonError(status: number, detail: string, code: string): Response {
  return Response.json({ detail, code }, { status, headers: responseHeaders() });
}

function hasOrigin(value: string, expected: string): boolean {
  try {
    return new URL(value).origin === expected;
  } catch {
    return false;
  }
}

function isAllowedControlPlanePath(path: string): boolean {
  return [
    /^\/api\/v1\/response-actions\/rsa_[a-f0-9]{32}(?:\/approvals|\/execute|\/rollback)?$/,
    /^\/api\/v1\/console\/incidents\/inc_[a-f0-9]{32}$/,
    /^\/api\/v1\/console\/incidents\/inc_[a-f0-9]{32}\/attack-trace$/,
    /^\/api\/v1\/console\/incidents\/inc_[a-f0-9]{32}\/evidence\/evi_[a-f0-9]{24}$/,
    /^\/api\/v1\/console\/malware\/smp_[a-f0-9]{32}$/,
    /^\/api\/v1\/console\/model-operations$/,
    /^\/api\/v1\/console\/rules-intelligence$/,
    /^\/api\/v1\/console\/system-operations$/,
  ].some((pattern) => pattern.test(path));
}

function isJsonObject(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

async function writeSessionKey(): Promise<CryptoKey | Response> {
  const secret = process.env.AISOC_CONSOLE_CSRF_SECRET;
  if (!secret || secret.length < 32 || secret.length > 256 || !/^[\x21-\x7e]+$/.test(secret)) {
    return jsonError(503, "控制台写入会话未配置。", "console_write_session_unavailable");
  }
  // Reject known-default/placeholder secrets from .env.example and similar
  // templates so a verbatim copy of the example does not produce a public key.
  const normalized = secret.toLowerCase();
  if (
    normalized.startsWith("replace-with") ||
    normalized.startsWith("change-me") ||
    normalized.startsWith("your-") ||
    normalized.startsWith("placeholder")
  ) {
    return jsonError(503, "控制台写入会话密钥为占位值。", "console_write_session_unavailable");
  }
  return crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
}

function writeSessionMessage(request: Request, authorization: string, unsigned: string): string {
  return `${new URL(request.url).origin}\n${authorization}\n${unsigned}`;
}

async function signWriteSession(key: CryptoKey, message: string): Promise<string> {
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message));
  return bytesToHex(new Uint8Array(signature));
}

function bytesToHex(value: Uint8Array): string {
  return [...value].map((item) => item.toString(16).padStart(2, "0")).join("");
}

function hexToBytes(value: string): Uint8Array {
  const bytes = new Uint8Array(value.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

function validateDeclaredLength(value: string | null): Response | null {
  if (value === null) return null;
  const length = Number(value);
  if (!Number.isSafeInteger(length) || length < 0) {
    return jsonError(502, "控制面 Content-Length 无效。", "control_plane_content_length_invalid");
  }
  if (length > MAX_RESPONSE_BYTES) {
    return jsonError(502, "控制面响应超过安全上限。", "control_plane_response_too_large");
  }
  return null;
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

function responseHeaders(): HeadersInit {
  return {
    "cache-control": "no-store, max-age=0",
    "content-type": "application/json; charset=utf-8",
    "x-content-type-options": "nosniff",
  };
}
