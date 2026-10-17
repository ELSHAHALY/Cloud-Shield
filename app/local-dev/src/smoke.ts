// `make local-smoke` (plan §14): end-to-end checks against the running
// compose stack through nginx (http://localhost:3000), like a browser would.
import { GetQueueUrlCommand, ReceiveMessageCommand, SQSClient } from "@aws-sdk/client-sqs";
import { isLocalEndpoint } from "./guard";

const BASE = process.env.SMOKE_BASE_URL ?? "http://localhost:3000";
const MOTO = process.env.SMOKE_MOTO_URL ?? "http://localhost:5000";
const ACME_DOC = "0192b3c4-0000-7000-8000-00000000a001";

async function token(username: string): Promise<string> {
  const res = await fetch(`${BASE}/local-idp/token`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ username }) });
  if (!res.ok) throw new Error(`token for ${username}: ${res.status}`);
  return ((await res.json()) as { idToken: string }).idToken;
}

async function api(path: string, user?: string): Promise<{ status: number; body: unknown }> {
  const res = await fetch(`${BASE}/api${path}`, { headers: user ? { Authorization: `Bearer ${await token(user)}` } : {} });
  const text = await res.text();
  let body: unknown = text;
  try {
    body = JSON.parse(text);
  } catch {
    // not JSON
  }
  return { status: res.status, body };
}

function check(name: string, ok: boolean, detail = ""): void {
  console.log(`${ok ? "PASS" : "FAIL"} ${name}${detail ? ` (${detail})` : ""}`);
  if (!ok) process.exitCode = 1;
}

export async function main(): Promise<void> {
  if (!isLocalEndpoint(BASE) || !isLocalEndpoint(MOTO)) throw new Error("smoke only runs against localhost");
  const health = await api("/healthz");
  check("1 /api/healthz", health.status === 200);

  const docs = await api("/documents", "alice");
  const items = (docs.body as { items?: { docId: string }[] }).items ?? [];
  check("2 alice lists acme documents", docs.status === 200 && items.some((d) => d.docId === ACME_DOC), `${items.length} items`);

  const idor = await api(`/documents/${ACME_DOC}`, "mallory");
  check("3 mallory (t-nile-02) gets 404 for an acme document", idor.status === 404);

  const decoy = await api("/admin/smoke-check");
  const platform = await api("/soc/audit?limit=100", "sam");
  const hits = ((platform.body as { items?: { action: string; requestId: string }[] }).items ?? []).filter((e) => e.action === "DECOY_ROUTE_HIT");
  const decoyRequestId = (decoy.body as { requestId?: string }).requestId;
  check("4a decoy answers 403 without a token", decoy.status === 403);
  check("4b decoy hit is in the _platform audit", hits.some((e) => e.requestId === decoyRequestId));
  const sqs = new SQSClient({ region: "us-east-1", endpoint: MOTO, credentials: { accessKeyId: "local-only", secretAccessKey: "local-only" } });
  const { QueueUrl } = await sqs.send(new GetQueueUrlCommand({ QueueName: "cloudshield-local-edge-capture" }));
  let found = false;
  for (let i = 0; i < 5 && !found; i++) {
    const msgs = await sqs.send(new ReceiveMessageCommand({ QueueUrl, MaxNumberOfMessages: 10, WaitTimeSeconds: 1 }));
    found = (msgs.Messages ?? []).some((m) => (m.Body ?? "").includes("CloudShield:IPAddress/DecoyRouteHit") && (m.Body ?? "").includes(decoyRequestId ?? "-"));
  }
  check("4c DecoyRouteHit reached the edge bus (moto)", found);

  const overview = await api("/soc/overview", "sam");
  const ids = ((overview.body as { incidents?: { incidentId: string }[] }).incidents ?? []).map((i) => i.incidentId);
  const evidence = await api("/soc/incidents/local-c-public-bucket/evidence", "sam");
  check("5a sam sees scenario C on /soc/overview", overview.status === 200 && ids.includes("local-c-public-bucket"));
  check("5b scenario C chain of custody is BROKEN", (evidence.body as { chainOfCustodyOk?: unknown }).chainOfCustodyOk === false);
  if (process.exitCode) throw new Error("smoke failed");
  console.log("local smoke: all checks passed");
}

/* istanbul ignore next */
if (require.main === module) {
  main().catch((err: unknown) => {
    console.error(String(err instanceof Error ? err.message : err));
    process.exit(1);
  });
}
