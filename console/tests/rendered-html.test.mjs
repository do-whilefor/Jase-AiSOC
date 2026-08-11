import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

async function render() {
  const worker = await loadWorker("render");
  return worker.fetch(
    new Request("http://localhost/", { headers: { accept: "text/html" } }),
    { ASSETS: { fetch: async () => new Response("Not found", { status: 404 }) } },
    { waitUntil() {}, passThroughOnException() {} },
  );
}

async function loadWorker(label) {
  const workerUrl = new URL("../dist/server/index.js", import.meta.url);
  workerUrl.searchParams.set("test", `${label}-${process.pid}-${Date.now()}-${Math.random()}`);
  const { default: worker } = await import(workerUrl.href);
  return worker;
}

function dispatch(worker, request) {
  return worker.fetch(
    request,
    { ASSETS: { fetch: async () => new Response("Not found", { status: 404 }) } },
    { waitUntil() {}, passThroughOnException() {} },
  );
}

test("server-renders the AI-SOC operator console", async () => {
  const response = await render();
  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type") ?? "", /^text\/html\b/i);

  const html = await response.text();
  assert.match(html, /<title>AI-SOC \| 安全运营控制台<\/title>/i);
  assert.match(html, /AI-SOC/);
  assert.match(html, /安全运营总览/);
  assert.match(html, /连接租户控制面/);
  assert.match(html, /事件研判/);
  assert.match(html, /攻击溯源/);
  assert.match(html, /响应审批/);
  assert.doesNotMatch(html, /codex-preview|Your site is taking shape|react-loading-skeleton/i);
});

test("keeps operator credentials memory-only and constrains the control-plane proxy", async () => {
  const [client, route, sharedProxy, incidentRoute, evidenceRoute, traceRoute, malwareRoute, modelRoute, systemRoute, rulesRoute, writeSessionRoute, approvalRoute, executeRoute, rollbackRoute, page, layout, packageJson] = await Promise.all([
    readFile(new URL("../app/operations-console.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/api/platform/snapshot/route.ts", import.meta.url), "utf8"),
    readFile(new URL("../app/api/platform/_proxy.ts", import.meta.url), "utf8"),
    readFile(new URL("../app/api/platform/incident-detail/route.ts", import.meta.url), "utf8"),
    readFile(new URL("../app/api/platform/incident-evidence/route.ts", import.meta.url), "utf8"),
    readFile(new URL("../app/api/platform/trace-detail/route.ts", import.meta.url), "utf8"),
    readFile(new URL("../app/api/platform/malware-detail/route.ts", import.meta.url), "utf8"),
    readFile(new URL("../app/api/platform/model-operations/route.ts", import.meta.url), "utf8"),
    readFile(new URL("../app/api/platform/system-operations/route.ts", import.meta.url), "utf8"),
    readFile(new URL("../app/api/platform/rules-intelligence/route.ts", import.meta.url), "utf8"),
    readFile(new URL("../app/api/platform/write-session/route.ts", import.meta.url), "utf8"),
    readFile(new URL("../app/api/platform/response-approval/route.ts", import.meta.url), "utf8"),
    readFile(new URL("../app/api/platform/response-execute/route.ts", import.meta.url), "utf8"),
    readFile(new URL("../app/api/platform/response-rollback/route.ts", import.meta.url), "utf8"),
    readFile(new URL("../app/page.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/layout.tsx", import.meta.url), "utf8"),
    readFile(new URL("../package.json", import.meta.url), "utf8"),
  ]);

  assert.match(client, /useState\(""\)/);
  assert.match(client, /authorization: `Bearer \$\{credential\}`/);
  assert.match(client, /x-aisoc-csrf/);
  assert.match(client, /console-execute-\$\{crypto\.randomUUID\(\)\}/);
  assert.match(client, /console-rollback-\$\{crypto\.randomUUID\(\)\}/);
  assert.doesNotMatch(client, /localStorage|sessionStorage|document\.cookie/);
  assert.match(client, /<code className="untrusted-indicator">\{item\.indicator\}<\/code>/);
  assert.doesNotMatch(client, /href=\{item\.indicator\}/);
  assert.match(client, /lifecycle_enforcement_available/);
  assert.match(client, /managed_ioc_lifecycle_available/);
  assert.match(client, /credential_validation_available/);
  assert.match(client, /labeled_feedback_linkage_available/);
  assert.match(client, /database_capacity_metrics_available/);
  assert.match(client, /human_user_directory_available/);
  assert.doesNotMatch(client, /ai_review_api_key|ai_review_base_url|get_secret_value/);
  assert.doesNotMatch(client, /token_digest/);
  assert.match(route, /\/api\/v1\/console\/snapshot/);
  assert.match(route, /redirect: "manual"/);
  assert.match(route, /MAX_RESPONSE_BYTES/);
  assert.match(route, /non-loopback control planes require HTTPS/);
  assert.doesNotMatch(route, /searchParams\.get\("url"\)|request\.json\(\)/);
  assert.match(sharedProxy, /ACTION_ID_PATTERN = \/\^rsa_/);
  assert.match(sharedProxy, /INCIDENT_ID_PATTERN = \/\^inc_/);
  assert.match(sharedProxy, /EVIDENCE_ID_PATTERN = \/\^evi_/);
  assert.match(sharedProxy, /SAMPLE_ID_PATTERN = \/\^smp_/);
  assert.match(sharedProxy, /request\.headers\.get\("origin"\)/);
  assert.match(sharedProxy, /request\.headers\.get\("referer"\)/);
  assert.match(sharedProxy, /x-aisoc-csrf/);
  assert.match(sharedProxy, /crypto\.subtle\.verify/);
  assert.match(sharedProxy, /AISOC_CONSOLE_CSRF_SECRET/);
  assert.match(sharedProxy, /redirect: "manual"/);
  assert.match(sharedProxy, /MAX_REQUEST_BYTES/);
  assert.match(sharedProxy, /MAX_RESPONSE_BYTES/);
  assert.doesNotMatch(sharedProxy, /searchParams\.get\("url"\)|body\.(url|path|origin)/);
  assert.match(incidentRoute, /\/api\/v1\/console\/incidents/);
  assert.match(evidenceRoute, /\/evidence\//);
  assert.match(traceRoute, /\/attack-trace/);
  assert.doesNotMatch(traceRoute, /request\.json|trace_id/);
  assert.match(malwareRoute, /\/api\/v1\/console\/malware/);
  assert.match(modelRoute, /\/api\/v1\/console\/model-operations/);
  assert.doesNotMatch(modelRoute, /searchParams\.get|request\.json/);
  assert.match(systemRoute, /\/api\/v1\/console\/system-operations/);
  assert.doesNotMatch(systemRoute, /searchParams\.get|request\.json/);
  assert.match(rulesRoute, /\/api\/v1\/console\/rules-intelligence/);
  assert.doesNotMatch(rulesRoute, /searchParams\.get|request\.json/);
  assert.ok(sharedProxy.includes("^\\/api\\/v1\\/console\\/rules-intelligence$/"));
  assert.ok(sharedProxy.includes("^\\/api\\/v1\\/console\\/model-operations$/"));
  assert.ok(sharedProxy.includes("^\\/api\\/v1\\/console\\/system-operations$/"));
  assert.ok(sharedProxy.includes("\\/attack-trace$/"));
  assert.match(writeSessionRoute, /issueWriteSession/);
  assert.match(approvalRoute, /\/approvals/);
  assert.match(executeRoute, /\/execute/);
  assert.match(rollbackRoute, /\/rollback/);
  assert.match(page, /OperationsConsole/);
  assert.match(layout, /lang="zh-CN"/);
  assert.match(packageJson, /"name": "aisoc-operator-console"/);
  assert.doesNotMatch(packageJson, /react-loading-skeleton/);
  assert.doesNotMatch(client, /dangerouslySetInnerHTML/);
  assert.match(client, /self_reported_heartbeat/);
  assert.match(client, /binary_integrity_verified/);
  assert.match(client, /identity_assertion_count: 0/);
  assert.match(client, /raw_ref_included: false/);
  assert.match(client, /interactive_graph_query_available: false/);
  assert.match(client, /agent_version_inventory_available: true/);
  assert.doesNotMatch(client, /agent_version_inventory_available: false/);
});

test("rejects malformed IDs and write requests without same-origin proof before proxying", async () => {
  const worker = await loadWorker("write-rejections");
  const originalFetch = globalThis.fetch;
  const previousCsrfSecret = process.env.AISOC_CONSOLE_CSRF_SECRET;
  let upstreamCalls = 0;
  process.env.AISOC_CONSOLE_CSRF_SECRET = "test-console-csrf-secret-with-at-least-32-bytes";
  globalThis.fetch = async () => {
    upstreamCalls += 1;
    return Response.json({ unexpected: true });
  };
  try {
    const missingOrigin = await dispatch(worker, new Request(
      "https://console.example/api/platform/response-approval",
      {
        method: "POST",
        headers: mutationHeaders({ includeOrigin: false, nonce: "not-required-for-origin-rejection" }),
        body: JSON.stringify({
          action_id: `rsa_${"a".repeat(32)}`,
          decision: "approve",
          comment: "evidence reviewed",
          business_confirmation: false,
        }),
      },
    ));
    assert.equal(missingOrigin.status, 403);
    assert.equal((await missingOrigin.json()).code, "console_origin_required");

    const nonce = await issueNonce(worker);
    const malformedId = await dispatch(worker, new Request(
      "https://console.example/api/platform/response-execute",
      {
        method: "POST",
        headers: mutationHeaders({ nonce }),
        body: JSON.stringify({
          action_id: "../../operators",
          idempotency_key: "console-execute-safe-01",
        }),
      },
    ));
    assert.equal(malformedId.status, 400);
    assert.equal((await malformedId.json()).code, "response_action_id_invalid");

    const wrongSession = await dispatch(worker, new Request(
      "https://console.example/api/platform/response-execute",
      {
        method: "POST",
        headers: { ...mutationHeaders({ nonce }), authorization: `Bearer ${"u".repeat(32)}` },
        body: JSON.stringify({
          action_id: `rsa_${"a".repeat(32)}`,
          idempotency_key: "console-execute-safe-02",
        }),
      },
    ));
    assert.equal(wrongSession.status, 403);
    assert.equal((await wrongSession.json()).code, "console_csrf_invalid");
    assert.equal(upstreamCalls, 0);
  } finally {
    globalThis.fetch = originalFetch;
    if (previousCsrfSecret === undefined) delete process.env.AISOC_CONSOLE_CSRF_SECRET;
    else process.env.AISOC_CONSOLE_CSRF_SECRET = previousCsrfSecret;
  }
});

test("forwards only fixed response operations with bounded JSON and no redirects", async () => {
  const worker = await loadWorker("fixed-response-operations");
  const originalFetch = globalThis.fetch;
  const previousBaseUrl = process.env.AISOC_API_BASE_URL;
  const previousCsrfSecret = process.env.AISOC_CONSOLE_CSRF_SECRET;
  const observed = [];
  process.env.AISOC_API_BASE_URL = "https://control.example";
  process.env.AISOC_CONSOLE_CSRF_SECRET = "test-console-csrf-secret-with-at-least-32-bytes";
  globalThis.fetch = async (input, init) => {
    observed.push({
      url: String(input),
      method: init?.method,
      redirect: init?.redirect,
      body: init?.body ? JSON.parse(String(init.body)) : undefined,
    });
    return Response.json({ plan: { action_id: `rsa_${"a".repeat(32)}` }, approvals: [], executions: [], rollbacks: [], events: [] });
  };
  try {
    const actionId = `rsa_${"a".repeat(32)}`;
    const nonce = await issueNonce(worker);
    const requests = [
      ["response-approval", { action_id: actionId, decision: "reject", comment: "target no longer matches", business_confirmation: false }],
      ["response-execute", { action_id: actionId, idempotency_key: "console-execute-safe-01" }],
      ["response-rollback", { action_id: actionId, reason: "containment no longer required", idempotency_key: "console-rollback-safe-01" }],
    ];
    for (const [operation, body] of requests) {
      const response = await dispatch(worker, new Request(
        `https://console.example/api/platform/${operation}`,
        { method: "POST", headers: mutationHeaders({ nonce }), body: JSON.stringify(body) },
      ));
      assert.equal(response.status, 200);
    }
    assert.deepEqual(observed.map((item) => item.url), [
      `https://control.example/api/v1/response-actions/${actionId}/approvals`,
      `https://control.example/api/v1/response-actions/${actionId}/execute`,
      `https://control.example/api/v1/response-actions/${actionId}/rollback`,
    ]);
    assert.deepEqual(observed.map((item) => item.redirect), ["manual", "manual", "manual"]);
    assert.deepEqual(observed[1].body, { idempotency_key: "console-execute-safe-01" });
    assert.deepEqual(observed[2].body, { reason: "containment no longer required", idempotency_key: "console-rollback-safe-01" });
  } finally {
    globalThis.fetch = originalFetch;
    if (previousBaseUrl === undefined) delete process.env.AISOC_API_BASE_URL;
    else process.env.AISOC_API_BASE_URL = previousBaseUrl;
    if (previousCsrfSecret === undefined) delete process.env.AISOC_CONSOLE_CSRF_SECRET;
    else process.env.AISOC_CONSOLE_CSRF_SECRET = previousCsrfSecret;
  }
});

test("forwards only exact Incident, evidence-member, trace, malware, model, rule, and system operations paths", async () => {
  const worker = await loadWorker("fixed-incident-reads");
  const originalFetch = globalThis.fetch;
  const previousBaseUrl = process.env.AISOC_API_BASE_URL;
  const observed = [];
  process.env.AISOC_API_BASE_URL = "https://control.example";
  globalThis.fetch = async (input, init) => {
    observed.push({ url: String(input), method: init?.method, redirect: init?.redirect });
    return Response.json({ bounded: true });
  };
  try {
    const incidentId = `inc_${"a".repeat(32)}`;
    const evidenceId = `evi_${"b".repeat(24)}`;
    const sampleId = `smp_${"c".repeat(32)}`;
    const detail = await dispatch(worker, new Request(
      `https://console.example/api/platform/incident-detail?incident_id=${incidentId}`,
      { headers: { authorization: `Bearer ${"t".repeat(32)}` } },
    ));
    const evidence = await dispatch(worker, new Request(
      `https://console.example/api/platform/incident-evidence?incident_id=${incidentId}&evidence_id=${evidenceId}`,
      { headers: { authorization: `Bearer ${"t".repeat(32)}` } },
    ));
    const trace = await dispatch(worker, new Request(
      `https://console.example/api/platform/trace-detail?incident_id=${incidentId}`,
      { headers: { authorization: `Bearer ${"t".repeat(32)}` } },
    ));
    const malware = await dispatch(worker, new Request(
      `https://console.example/api/platform/malware-detail?sample_id=${sampleId}`,
      { headers: { authorization: `Bearer ${"t".repeat(32)}` } },
    ));
    const rules = await dispatch(worker, new Request(
      "https://console.example/api/platform/rules-intelligence",
      { headers: { authorization: `Bearer ${"t".repeat(32)}` } },
    ));
    const models = await dispatch(worker, new Request(
      "https://console.example/api/platform/model-operations",
      { headers: { authorization: `Bearer ${"t".repeat(32)}` } },
    ));
    const system = await dispatch(worker, new Request(
      "https://console.example/api/platform/system-operations",
      { headers: { authorization: `Bearer ${"t".repeat(32)}` } },
    ));
    assert.equal(detail.status, 200);
    assert.equal(evidence.status, 200);
    assert.equal(trace.status, 200);
    assert.equal(malware.status, 200);
    assert.equal(rules.status, 200);
    assert.equal(models.status, 200);
    assert.equal(system.status, 200);
    assert.deepEqual(observed.map((item) => item.url), [
      `https://control.example/api/v1/console/incidents/${incidentId}`,
      `https://control.example/api/v1/console/incidents/${incidentId}/evidence/${evidenceId}`,
      `https://control.example/api/v1/console/incidents/${incidentId}/attack-trace`,
      `https://control.example/api/v1/console/malware/${sampleId}`,
      "https://control.example/api/v1/console/rules-intelligence",
      "https://control.example/api/v1/console/model-operations",
      "https://control.example/api/v1/console/system-operations",
    ]);
    assert.deepEqual(observed.map((item) => item.method), ["GET", "GET", "GET", "GET", "GET", "GET", "GET"]);
    assert.deepEqual(observed.map((item) => item.redirect), ["manual", "manual", "manual", "manual", "manual", "manual", "manual"]);

    const invalid = await dispatch(worker, new Request(
      "https://console.example/api/platform/incident-detail?incident_id=../../operators",
      { headers: { authorization: `Bearer ${"t".repeat(32)}` } },
    ));
    assert.equal(invalid.status, 400);
    assert.equal((await invalid.json()).code, "incident_id_invalid");
    const invalidTrace = await dispatch(worker, new Request(
      "https://console.example/api/platform/trace-detail?incident_id=../../attack-traces",
      { headers: { authorization: `Bearer ${"t".repeat(32)}` } },
    ));
    assert.equal(invalidTrace.status, 400);
    assert.equal((await invalidTrace.json()).code, "incident_id_invalid");
    const invalidSample = await dispatch(worker, new Request(
      "https://console.example/api/platform/malware-detail?sample_id=../../samples",
      { headers: { authorization: `Bearer ${"t".repeat(32)}` } },
    ));
    assert.equal(invalidSample.status, 400);
    assert.equal((await invalidSample.json()).code, "malware_sample_id_invalid");
    const invalidRulesQuery = await dispatch(worker, new Request(
      "https://console.example/api/platform/rules-intelligence?path=/api/v1/operators",
      { headers: { authorization: `Bearer ${"t".repeat(32)}` } },
    ));
    assert.equal(invalidRulesQuery.status, 400);
    assert.equal((await invalidRulesQuery.json()).code, "console_query_invalid");
    const invalidModelQuery = await dispatch(worker, new Request(
      "https://console.example/api/platform/model-operations?url=https://attacker.invalid",
      { headers: { authorization: `Bearer ${"t".repeat(32)}` } },
    ));
    assert.equal(invalidModelQuery.status, 400);
    assert.equal((await invalidModelQuery.json()).code, "console_query_invalid");
    const invalidSystemQuery = await dispatch(worker, new Request(
      "https://console.example/api/platform/system-operations?tenant=other",
      { headers: { authorization: `Bearer ${"t".repeat(32)}` } },
    ));
    assert.equal(invalidSystemQuery.status, 400);
    assert.equal((await invalidSystemQuery.json()).code, "console_query_invalid");
    assert.equal(observed.length, 7);
  } finally {
    globalThis.fetch = originalFetch;
    if (previousBaseUrl === undefined) delete process.env.AISOC_API_BASE_URL;
    else process.env.AISOC_API_BASE_URL = previousBaseUrl;
  }
});

test("fails closed on upstream redirects and oversized responses", async () => {
  const worker = await loadWorker("upstream-fail-closed");
  const originalFetch = globalThis.fetch;
  const previousBaseUrl = process.env.AISOC_API_BASE_URL;
  process.env.AISOC_API_BASE_URL = "https://control.example";
  try {
    globalThis.fetch = async () => new Response(null, { status: 302, headers: { location: "https://elsewhere.example" } });
    const redirect = await dispatch(worker, detailRequest());
    assert.equal(redirect.status, 502);
    assert.equal((await redirect.json()).code, "control_plane_redirect_rejected");

    globalThis.fetch = async () => Response.json(
      { unexpected: true },
      { headers: { "content-length": String(1024 * 1024 + 1) } },
    );
    const oversized = await dispatch(worker, detailRequest());
    assert.equal(oversized.status, 502);
    assert.equal((await oversized.json()).code, "control_plane_response_too_large");
  } finally {
    globalThis.fetch = originalFetch;
    if (previousBaseUrl === undefined) delete process.env.AISOC_API_BASE_URL;
    else process.env.AISOC_API_BASE_URL = previousBaseUrl;
  }
});

function mutationHeaders({ includeOrigin = true, nonce } = {}) {
  return {
    authorization: `Bearer ${"t".repeat(32)}`,
    "content-type": "application/json",
    "x-aisoc-csrf": nonce,
    ...(includeOrigin ? { origin: "https://console.example", referer: "https://console.example/response" } : {}),
  };
}

async function issueNonce(worker) {
  const response = await dispatch(worker, new Request(
    "https://console.example/api/platform/write-session",
    { headers: { authorization: `Bearer ${"t".repeat(32)}` } },
  ));
  assert.equal(response.status, 200);
  const payload = await response.json();
  assert.match(payload.csrf_nonce, /^v1\./);
  return payload.csrf_nonce;
}

function detailRequest() {
  return new Request(
    `https://console.example/api/platform/response-detail?action_id=rsa_${"a".repeat(32)}`,
    { headers: { authorization: `Bearer ${"t".repeat(32)}` } },
  );
}
