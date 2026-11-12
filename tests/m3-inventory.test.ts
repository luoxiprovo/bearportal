import { integrationDatabases, queryTestDatabase } from "./helpers/database.ts";
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, randomUUID, sign as cryptoSign, type KeyObject } from "node:crypto";
import { mkdtempSync, readFileSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";
import { after, before, beforeEach, describe, it } from "node:test";
import { exportSPKI, generateKeyPair, SignJWT, type CryptoKey } from "jose";
import type { RelayCheckRequest } from "../packages/providers/brevo/src/index.ts";
import type { ZoneReadRequest, ZoneReadResult } from "../packages/providers/dns/src/reader.ts";
import type { HostReport } from "../packages/servers/src/readiness.ts";
import { heartbeatMessage } from "../packages/servers/src/signature.ts";
import { bootstrapAdmin, buildServer, type ApiDeps } from "../apps/api/src/server.ts";
import { migrate } from "../packages/db/src/migrate.ts";

const { databaseUrl, migrationUrl, superDatabaseUrl } = integrationDatabases();
const issuer = "https://test.bearportal.local";
const audience = "bearportal-test";
const secretKeyHex = "ab".repeat(32);
const adminEmail = "admin@recovery-bearportal.com";
const schedulerToken = "scheduler-test-token";
const apiCanary = "BREVO-KEY-CANARY-9f3a";
const smtpCanary = "SMTP-KEY-CANARY-9f3a";

const attestations = {
  osPrepared: true,
  storagePrepared: true,
  firewallAttested: true,
  cleanHost: true,
  externalBackup: true,
};

const readyReport: HostReport = {
  os: "linux",
  init: "systemd",
  architecture: "x64",
  memoryMb: 1024,
  diskGb: 20,
  dataPathMounted: true,
  reachable: true,
  relayReachable: true,
  priorTenantData: false,
  supervisorVersion: "1",
};

type ApiResult = { status: number; text: string; body: Record<string, any>; headers: Headers };
type Device = { publicKey: string; privateKey: KeyObject; fingerprint: string };

const logChunks: Buffer[] = [];
const logStream = new Writable({
  write(chunk, _encoding, callback) {
    logChunks.push(Buffer.from(chunk));
    callback();
  },
});

let privateKey: CryptoKey;
let publicKeyPem = "";
let app: Awaited<ReturnType<typeof buildServer>> | undefined;
let base = "";
let secretsDir = "";
let ipHost = 10;
let step = 0;
let relayHealthy = false;
const zones = new Map<string, ZoneReadResult>();
const zoneCalls: ZoneReadRequest[] = [];
const relayCalls: RelayCheckRequest[] = [];

function logs(): string {
  return Buffer.concat(logChunks).toString("utf8");
}

function key(name: string): string {
  step += 1;
  return `${name}-${step}-${randomUUID()}`;
}

function nextIp(): string {
  ipHost += 1;
  if (ipHost > 250) throw new Error("The test exhausted the documentation address range.");
  return `203.0.113.${ipHost}`;
}

function num(value: unknown): number {
  const parsed = Number(value);
  if (!Number.isInteger(parsed)) throw new Error(`Expected an integer, got ${String(value)}.`);
  return parsed;
}

function sqlText(value: string): string {
  if (!/^[0-9A-Za-z_.:@+-]+$/.test(value)) throw new Error(`Refusing to interpolate ${value}.`);
  return `'${value}'`;
}

async function superQuery(sql: string): Promise<string[][]> {
  return queryTestDatabase(sql, superDatabaseUrl);
}
async function scalar(sql: string): Promise<string> {
  const rows = await superQuery(sql);
  return rows[0]?.[0] ?? "";
}

async function resetDatabase(): Promise<void> {
  await superQuery(`TRUNCATE TABLE
    cancellation_schedules, restore_requests, upgrade_plans, cleanup_reports,
    audit_events, idempotency_keys, outbox_events, backups, jobs, dns_connections,
    deployments, secret_refs, domains, server_assignments, allocation_requests,
    invitations, operator_roles, organizations, relay_connections, servers, users,
    diagnoses, provider_attempts
    RESTART IDENTITY CASCADE`);
  await superQuery("UPDATE control_plane_state SET mode = 'normal' WHERE id = 1");
  await bootstrapAdmin(databaseUrl, "bootstrap-admin", adminEmail);
}

function now(): number {
  return Math.floor(Date.now() / 1000);
}

async function signToken(claims: Record<string, unknown> & { sub: string; email: string }): Promise<string> {
  const { sub, ...rest } = claims;
  return new SignJWT(rest)
    .setProtectedHeader({ alg: "RS256" })
    .setSubject(sub)
    .setIssuer(issuer)
    .setAudience(audience)
    .setIssuedAt()
    .setExpirationTime("2h")
    .sign(privateKey);
}

async function tokenFor(sub: string, email: string, extra: Record<string, unknown> = {}): Promise<string> {
  return signToken({ sub, email, email_verified: true, auth_time: now(), amr: ["pwd"], ...extra });
}

async function adminToken(): Promise<string> {
  return tokenFor("bootstrap-admin", adminEmail, { amr: ["pwd", "totp"], auth_time: now() });
}

async function api(urlBase: string, path: string, init: RequestInit = {}): Promise<ApiResult> {
  const headers = new Headers(init.headers);
  if (init.body && !headers.has("content-type")) headers.set("content-type", "application/json");
  const response = await fetch(`${urlBase}${path}`, { ...init, headers });
  const text = await response.text();
  const eventStream = (response.headers.get("content-type") ?? "").includes("text/event-stream");
  let body: Record<string, any> = {};
  if (text && !eventStream) body = JSON.parse(text) as Record<string, any>;
  return { status: response.status, text, body, headers: response.headers };
}

function expectStatus(response: ApiResult, status: number): void {
  if (response.status !== status) {
    throw new Error(`expected ${status}, got ${response.status}: ${response.text}\n${logs()}`);
  }
}

function auth(token: string, idempotencyKey?: string): Record<string, string> {
  const headers: Record<string, string> = { authorization: `Bearer ${token}` };
  if (idempotencyKey) headers["idempotency-key"] = idempotencyKey;
  return headers;
}

function deviceKey(): Device {
  const { publicKey, privateKey: signingKey } = generateKeyPairSync("ed25519");
  const jwk = publicKey.export({ format: "jwk" }) as { x: string };
  const raw = Buffer.from(jwk.x, "base64url");
  return {
    publicKey: raw.toString("base64url"),
    privateKey: signingKey,
    fingerprint: createHash("sha256").update(raw).digest("hex"),
  };
}

function signHeartbeat(signingKey: KeyObject, body: {
  serverId: string;
  authEpoch: number;
  observedAt: string;
  readiness: HostReport;
}): string {
  return cryptoSign(null, Buffer.from(heartbeatMessage(body)), signingKey).toString("base64url");
}

function goodZone(domain: string, nameservers = ["ns1.gamma-bearportal.com", "ns2.gamma-bearportal.com"]): ZoneReadResult {
  return {
    ok: true,
    snapshot: {
      zone: domain,
      nameservers,
      records: [
        { name: domain, type: "NS", value: nameservers[0] ?? "ns1.gamma-bearportal.com" },
        { name: domain, type: "A", value: "192.0.2.20" },
        { name: `www.${domain}`, type: "A", value: "192.0.2.20" },
        { name: domain, type: "TXT", value: "google-site-verification=alpha" },
      ],
    },
  };
}

async function invite(email: string): Promise<string> {
  const response = await api(base, "/v1/admin/invitations", {
    method: "POST",
    headers: auth(await adminToken(), key("invite")),
    body: JSON.stringify({ boundEmail: email, expiresInHours: 48 }),
  });
  expectStatus(response, 201);
  return response.body.invitationToken as string;
}

async function registerCustomer(local: string, name: string): Promise<{ token: string; email: string; organizationId: string; body: Record<string, any> }> {
  const email = `${local}@recovery-bearportal.com`;
  const invitation = await invite(email);
  const token = await tokenFor(local, email);
  const created = await api(base, "/v1/organizations", {
    method: "POST",
    headers: auth(token, key(`org-${local}`)),
    body: JSON.stringify({ name, invitationToken: invitation }),
  });
  expectStatus(created, 201);
  return { token, email, organizationId: created.body.id as string, body: created.body };
}

async function addDomain(token: string, domain: string): Promise<{ domainId: string; dnsId: string }> {
  const created = await api(base, "/v1/domains", {
    method: "POST",
    headers: auth(token, key("domain")),
    body: JSON.stringify({ domain, existingMail: false }),
  });
  expectStatus(created, 201);
  const dns = await api(base, "/v1/dns-connections", {
    method: "POST",
    headers: auth(token, key("dns")),
    body: JSON.stringify({
      domainId: created.body.id,
      provider: "namecom",
      zoneId: domain,
      credentials: { username: "portal-namecom", token: "namecom-token" },
    }),
  });
  expectStatus(dns, 201);
  return { domainId: created.body.id as string, dnsId: dns.body.id as string };
}

async function enrollReady(options: {
  label: string;
  profileCode?: string;
  providerReference?: string;
  report?: HostReport;
  ip?: string;
}): Promise<{ serverId: string; ip: string; device: Device; version: number; authEpoch: number }> {
  const ip = options.ip ?? nextIp();
  const created = await api(base, "/v1/admin/servers", {
    method: "POST",
    headers: auth(await adminToken(), key("server")),
    body: JSON.stringify({
      label: options.label,
      publicIpv4: ip,
      profileCode: options.profileCode ?? "e2-micro",
      operatorContact: "ops@recovery-bearportal.com",
      ...(options.providerReference ? { providerReference: options.providerReference } : {}),
      preparationAttestations: attestations,
    }),
  });
  expectStatus(created, 201);
  assert.equal(created.body.state, "pending_validation");
  const serverId = created.body.serverId as string;
  const enrollment = await api(base, `/v1/admin/servers/${serverId}/enrollment`, {
    method: "POST",
    headers: auth(await adminToken(), key("enrollment")),
    body: "{}",
  });
  expectStatus(enrollment, 201);
  const device = deviceKey();
  const enrolled = await api(base, "/internal/hosts/enroll", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ serverId, token: enrollment.body.enrollmentToken, publicKey: device.publicKey }),
  });
  expectStatus(enrolled, 200);
  assert.equal(enrolled.body.identityState, "pending_confirmation");
  let view = await api(base, `/v1/admin/servers/${serverId}`, { headers: auth(await adminToken()) });
  expectStatus(view, 200);
  const confirmed = await api(base, `/v1/admin/servers/${serverId}/confirm-identity`, {
    method: "POST",
    headers: auth(await adminToken(), key("confirm")),
    body: JSON.stringify({ fingerprint: device.fingerprint, expectedVersion: num(view.body.version) }),
  });
  expectStatus(confirmed, 200);
  assert.equal(confirmed.body.state, "pending_validation");
  assert.equal(confirmed.body.identityState, "confirmed");
  view = await api(base, `/v1/admin/servers/${serverId}`, { headers: auth(await adminToken()) });
  const observedAt = new Date().toISOString();
  const readiness = options.report ?? readyReport;
  const signed = { serverId, authEpoch: num(view.body.auth_epoch), observedAt, readiness };
  const heart = await api(base, "/internal/hosts/heartbeat", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ ...signed, publicKey: device.publicKey, signature: signHeartbeat(device.privateKey, signed) }),
  });
  expectStatus(heart, 200);
  assert.equal(heart.body.accepted, true);
  view = await api(base, `/v1/admin/servers/${serverId}`, { headers: auth(await adminToken()) });
  return { serverId, ip, device, version: num(view.body.version), authEpoch: num(view.body.auth_epoch) };
}

async function makeAvailable(label: string, profileCode = "e2-micro"): Promise<{ serverId: string; ip: string; device: Device; version: number; authEpoch: number }> {
  const enrolled = await enrollReady({ label, profileCode });
  const validated = await api(base, `/v1/admin/servers/${enrolled.serverId}/validate`, {
    method: "POST",
    headers: auth(await adminToken(), key("validate")),
    body: JSON.stringify({ expectedVersion: enrolled.version }),
  });
  expectStatus(validated, 200);
  assert.equal(validated.body.state, "available");
  const view = await api(base, `/v1/admin/servers/${enrolled.serverId}`, { headers: auth(await adminToken()) });
  return { ...enrolled, version: num(view.body.version), authEpoch: num(view.body.auth_epoch) };
}

async function serverView(serverId: string): Promise<Record<string, any>> {
  const view = await api(base, `/v1/admin/servers/${serverId}`, { headers: auth(await adminToken()) });
  expectStatus(view, 200);
  return view.body;
}

describe("M3 inventory A05-A07 and A27-A30", { concurrency: false }, () => {
  before(async () => {
    await migrate(migrationUrl);
    const pair = await generateKeyPair("RS256", { extractable: true });
    privateKey = pair.privateKey;
    publicKeyPem = await exportSPKI(pair.publicKey);
    secretsDir = mkdtempSync(join(tmpdir(), "bearportal-m3-secrets-"));
    const deps: ApiDeps = {
    billingRequired: false,
      onboardingIntervalMs: 0,
      databaseUrl,
      secretsDir,
      secretKeyHex,
      jwtPublicKeyPem: publicKeyPem,
      issuer,
      audience,
      schedulerToken,
      zoneReader: {
        async readZone(input) {
          zoneCalls.push({ provider: input.provider, zone: input.zone, domain: input.domain });
          assert.deepEqual(Object.keys(input).sort(), ["domain", "provider", "zone"]);
          return zones.get(input.domain) ?? { ok: false, code: "PROOF_REJECTED" };
        },
      },
      relayChecker: {
        async check(input) {
          relayCalls.push({ relayId: input.relayId, smtpLogin: input.smtpLogin });
          assert.deepEqual(Object.keys(input).sort(), ["relayId", "smtpLogin"]);
          return relayHealthy ? { ok: true } : { ok: false, code: "relay.activation_required" };
        },
      },
    };
    app = await buildServer(deps, logStream);
    await app.listen({ host: "127.0.0.1", port: 0 });
    const address = app.server.address();
    if (!address || typeof address === "string") throw new Error("The API did not listen on a TCP port.");
    base = `http://127.0.0.1:${address.port}`;
  });

  beforeEach(async () => {
    ipHost = 10;
    step = 0;
    relayHealthy = false;
    zones.clear();
    zoneCalls.length = 0;
    relayCalls.length = 0;
    logChunks.length = 0;
    await resetDatabase();
  });

  after(async () => {
    await app?.close();
  });

  it("A05 keeps one verified owner and rechecks a nameserver change", async () => {
    const wrongUser = await registerCustomer("a05-wrong", "Wrong Proof");
    const wrongDomain = "proof-wrong.alpha-bearportal.com";
    zones.set(wrongDomain, { ok: false, code: "PROOF_REJECTED" });
    const wrong = await addDomain(wrongUser.token, wrongDomain);
    const rejected = await api(base, `/v1/domains/${wrong.domainId}/verify`, {
      method: "POST",
      headers: auth(wrongUser.token, key("verify-wrong")),
      body: "{}",
    });
    expectStatus(rejected, 422);
    assert.equal(rejected.body.error.code, "PROOF_REJECTED");
    assert.equal(rejected.body.error.retryable, false);
    assert.equal(await scalar(`SELECT state FROM domains WHERE id = ${sqlText(wrong.domainId)}`), "pending");

    const expiredDomain = "proof-expired.alpha-bearportal.com";
    zones.set(expiredDomain, { ok: false, code: "PROOF_EXPIRED" });
    const expiredRef = await addDomain(wrongUser.token, expiredDomain);
    const expired = await api(base, `/v1/domains/${expiredRef.domainId}/verify`, {
      method: "POST",
      headers: auth(wrongUser.token, key("verify-expired")),
      body: "{}",
    });
    expectStatus(expired, 422);
    assert.equal(expired.body.error.code, "PROOF_EXPIRED");
    assert.equal(await scalar(`SELECT state FROM domains WHERE id = ${sqlText(expiredRef.domainId)}`), "pending");

    const shared = "proof-shared.gamma-bearportal.com";
    zones.set(shared, goodZone(shared));
    const ownerA = await registerCustomer("a05-owner-a", "Shared A");
    const ownerB = await registerCustomer("a05-owner-b", "Shared B");
    const domainA = await addDomain(ownerA.token, shared);
    const domainB = await addDomain(ownerB.token, shared);
    const [first, second] = await Promise.all([
      api(base, `/v1/domains/${domainA.domainId}/verify`, {
        method: "POST",
        headers: auth(ownerA.token, key("verify-a")),
        body: "{}",
      }),
      api(base, `/v1/domains/${domainB.domainId}/verify`, {
        method: "POST",
        headers: auth(ownerB.token, key("verify-b")),
        body: "{}",
      }),
    ]);
    const winner = first.status === 200 ? first : second;
    const loser = first.status === 200 ? second : first;
    const winnerToken = first.status === 200 ? ownerA.token : ownerB.token;
    const winnerId = first.status === 200 ? domainA.domainId : domainB.domainId;
    const loserToken = first.status === 200 ? ownerB.token : ownerA.token;
    const loserId = first.status === 200 ? domainB.domainId : domainA.domainId;
    expectStatus(winner, 200);
    expectStatus(loser, 409);
    assert.equal(winner.body.state, "verified");
    assert.equal(winner.body.planState, "read");
    assert.equal(loser.body.error.code, "DOMAIN_OWNED");
    assert.equal(await scalar(`SELECT count(*) FROM domains WHERE normalized_name = ${sqlText(shared)} AND state = 'verified'`), "1");
    assert.equal(await scalar(`SELECT state FROM domains WHERE id = ${sqlText(loserId)}`), "pending");
    const storedPlan = await scalar(`SELECT state || ' ' || desired_records::text FROM dns_plans WHERE domain_id = ${sqlText(winnerId)}`);
    assert.match(storedPlan, /^read /);
    assert.equal(storedPlan.includes('"MX"'), false);
    const seen = zoneCalls.filter((call) => call.domain === shared);
    assert.ok(seen.length >= 1);
    assert.equal(seen[0]?.provider, "namecom");
    assert.equal(JSON.stringify(seen).includes("namecom-token"), false);

    const stolen = await api(base, `/v1/domains/${loserId}/verify`, {
      method: "POST",
      headers: auth(loserToken, key("verify-steal")),
      body: "{}",
    });
    expectStatus(stolen, 409);
    assert.equal(stolen.body.error.code, "DOMAIN_OWNED");

    const hidden = await api(base, `/v1/domains/${winnerId}/verify`, {
      method: "POST",
      headers: auth(loserToken, key("verify-hidden")),
      body: "{}",
    });
    expectStatus(hidden, 404);

    zones.set(shared, goodZone(shared, ["ns3.gamma-bearportal.com", "ns4.gamma-bearportal.com"]));
    const recheck = await api(base, `/v1/domains/${winnerId}/verify`, {
      method: "POST",
      headers: auth(winnerToken, key("verify-recheck")),
      body: "{}",
    });
    expectStatus(recheck, 200);
    assert.equal(recheck.body.state, "verified");
    assert.equal(recheck.body.recheckRequired, true);
    assert.equal(typeof recheck.body.requiredActionId, "string");
    assert.equal(await scalar(`SELECT state || ':' || recheck_required::text FROM domains WHERE id = ${sqlText(winnerId)}`), "verified:true");
    assert.equal(await scalar(`SELECT count(*) FROM required_actions WHERE code = 'domain.nameserver_recheck' AND state = 'open'`), "1");

    const conflictDomain = "proof-conflict.epsilon-bearportal.com";
    const conflictUser = await registerCustomer("a05-conflict", "Conflict");
    const conflictRef = await addDomain(conflictUser.token, conflictDomain);
    const conflictZone = goodZone(conflictDomain);
    if (conflictZone.ok) {
      conflictZone.snapshot.records.push(
        { name: conflictDomain, type: "TXT", value: "v=spf1 include:_spf.google.com ~all" },
        { name: conflictDomain, type: "TXT", value: "v=spf1 include:spf.protection.outlook.com ~all" },
      );
    }
    zones.set(conflictDomain, conflictZone);
    const conflict = await api(base, `/v1/domains/${conflictRef.domainId}/verify`, {
      method: "POST",
      headers: auth(conflictUser.token, key("verify-conflict")),
      body: "{}",
    });
    expectStatus(conflict, 422);
    assert.equal(conflict.body.error.code, "DNS_RECORD_CONFLICT");
    assert.equal(await scalar(`SELECT state FROM domains WHERE id = ${sqlText(conflictRef.domainId)}`), "pending");

    const bareUser = await registerCustomer("a05-bare", "Bare");
    const bare = await api(base, "/v1/domains", {
      method: "POST",
      headers: auth(bareUser.token, key("domain-bare")),
      body: JSON.stringify({ domain: "proof-bare.zeta-bearportal.com", existingMail: false }),
    });
    expectStatus(bare, 201);
    const missing = await api(base, `/v1/domains/${bare.body.id}/verify`, {
      method: "POST",
      headers: auth(bareUser.token, key("verify-bare")),
      body: "{}",
    });
    expectStatus(missing, 422);
    assert.equal(missing.body.error.code, "DNS_CONNECTION_REQUIRED");
  });

  it("A07 refuses an unready host and records the missing check", async () => {
    const customer = await registerCustomer("a07-customer", "No Admin");
    const forbidden = await api(base, "/v1/admin/servers", {
      method: "POST",
      headers: auth(customer.token, key("customer-server")),
      body: JSON.stringify({
        label: "customer",
        publicIpv4: nextIp(),
        profileCode: "e2-micro",
        operatorContact: "ops@recovery-bearportal.com",
        preparationAttestations: attestations,
      }),
    });
    expectStatus(forbidden, 403);

    const privateAddress = await api(base, "/v1/admin/servers", {
      method: "POST",
      headers: auth(await adminToken(), key("private-ip")),
      body: JSON.stringify({
        label: "private",
        publicIpv4: "10.1.2.3",
        profileCode: "e2-micro",
        operatorContact: "ops@recovery-bearportal.com",
        preparationAttestations: attestations,
      }),
    });
    expectStatus(privateAddress, 400);
    assert.equal(privateAddress.body.error.code, "VALIDATION");

    const registered = await api(base, "/v1/admin/servers", {
      method: "POST",
      headers: auth(await adminToken(), key("ip-only")),
      body: JSON.stringify({
        label: "ip-only",
        publicIpv4: nextIp(),
        profileCode: "e2-micro",
        operatorContact: "ops@recovery-bearportal.com",
        preparationAttestations: attestations,
      }),
    });
    expectStatus(registered, 201);
    const ipOnly = registered.body.serverId as string;
    const tooSoon = await api(base, `/v1/admin/servers/${ipOnly}/validate`, {
      method: "POST",
      headers: auth(await adminToken(), key("validate-ip")),
      body: JSON.stringify({ expectedVersion: 1 }),
    });
    expectStatus(tooSoon, 422);
    assert.equal(tooSoon.body.error.code, "server.fingerprint_unconfirmed");
    assert.equal(tooSoon.body.error.retryable, false);
    assert.equal(typeof tooSoon.body.error.requiredActionId, "string");
    assert.doesNotMatch(tooSoon.text, /google|billing|iam|serviceAccount/i);
    assert.equal(await scalar(`SELECT state FROM servers WHERE id = ${sqlText(ipOnly)}`), "pending_validation");
    const codes = (await superQuery(`SELECT code FROM required_actions WHERE server_id = ${sqlText(ipOnly)} AND state = 'open' ORDER BY code`)).map((row) => row[0]);
    assert.deepEqual(codes, ["server.fingerprint_unconfirmed", "server.readiness_missing"]);

    const enrollmentKey = key("enroll-once");
    const enrollment = await api(base, `/v1/admin/servers/${ipOnly}/enrollment`, {
      method: "POST",
      headers: auth(await adminToken(), enrollmentKey),
      body: "{}",
    });
    expectStatus(enrollment, 201);
    const replay = await api(base, `/v1/admin/servers/${ipOnly}/enrollment`, {
      method: "POST",
      headers: auth(await adminToken(), enrollmentKey),
      body: "{}",
    });
    expectStatus(replay, 201);
    assert.equal(replay.body.tokenReplayable, false);
    assert.equal(replay.body.enrollmentToken, undefined);
    const device = deviceKey();
    const earlyHeart = await api(base, "/internal/hosts/heartbeat", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        serverId: ipOnly,
        publicKey: device.publicKey,
        authEpoch: 1,
        observedAt: new Date().toISOString(),
        readiness: readyReport,
        signature: "a".repeat(86),
      }),
    });
    expectStatus(earlyHeart, 409);
    assert.equal(earlyHeart.body.error.code, "IDENTITY_UNCONFIRMED");

    const shell = await api(base, `/v1/admin/servers/${ipOnly}/commands`, {
      method: "POST",
      headers: auth(await adminToken(), key("shell")),
      body: JSON.stringify({ commandType: "bash", expectedEpoch: 1, parameters: {} }),
    });
    expectStatus(shell, 400);
    assert.equal(shell.body.error.code, "UNKNOWN_COMMAND");

    async function reject(label: string, profileCode: string, report: HostReport, code: string): Promise<void> {
      const host = await enrollReady({ label, profileCode, report });
      const validated = await api(base, `/v1/admin/servers/${host.serverId}/validate`, {
        method: "POST",
        headers: auth(await adminToken(), key(`validate-${label}`)),
        body: JSON.stringify({ expectedVersion: host.version }),
      });
      expectStatus(validated, 422);
      assert.equal(validated.body.error.code, code);
      assert.equal(await scalar(`SELECT state FROM servers WHERE id = ${sqlText(host.serverId)}`), "pending_validation");
      assert.equal(
        await scalar(`SELECT count(*) FROM required_actions WHERE server_id = ${sqlText(host.serverId)} AND code = ${sqlText(code)} AND state = 'open'`),
        "1",
      );
    }

    await reject("incompatible", "e2-small", readyReport, "server.incompatible_profile");
    await reject("unreachable", "e2-micro", { ...readyReport, reachable: false }, "server.unreachable");
    await reject("relay", "e2-micro", { ...readyReport, relayReachable: false }, "server.relay_unreachable");
    await reject("prior-data", "e2-micro", { ...readyReport, priorTenantData: true }, "server.readiness_missing");

    const stale = await enrollReady({ label: "stale" });
    await superQuery(`UPDATE servers SET last_heartbeat_at = now() - interval '4 minutes' WHERE id = ${sqlText(stale.serverId)}`);
    const staleResult = await api(base, `/v1/admin/servers/${stale.serverId}/validate`, {
      method: "POST",
      headers: auth(await adminToken(), key("validate-stale")),
      body: JSON.stringify({ expectedVersion: stale.version }),
    });
    expectStatus(staleResult, 422);
    assert.equal(staleResult.body.error.code, "server.heartbeat_stale");
    assert.equal(await scalar(`SELECT state FROM servers WHERE id = ${sqlText(stale.serverId)}`), "pending_validation");

    const ready = await enrollReady({ label: "ready-host" });
    const validated = await api(base, `/v1/admin/servers/${ready.serverId}/validate`, {
      method: "POST",
      headers: auth(await adminToken(), key("validate-ready")),
      body: JSON.stringify({ expectedVersion: ready.version }),
    });
    expectStatus(validated, 200);
    assert.equal(validated.body.state, "reserved");
    const owned = await api(base, "/v1/organization/server", { headers: auth(customer.token) });
    expectStatus(owned, 200);
    assert.equal(owned.body.server.id, ready.serverId);
    assert.equal(owned.body.server.readiness, "ready");
    const actions = await api(base, `/v1/admin/required-actions?serverId=${ready.serverId}`, { headers: auth(await adminToken()) });
    expectStatus(actions, 200);
    assert.equal(actions.body.actions.length, 0);

    const unmounted = await enrollReady({
      label: "unmounted",
      report: { ...readyReport, dataPathMounted: false },
    });
    const unmountedResult = await api(base, `/v1/admin/servers/${unmounted.serverId}/validate`, {
      method: "POST",
      headers: auth(await adminToken(), key("validate-unmounted")),
      body: JSON.stringify({ expectedVersion: unmounted.version }),
    });
    expectStatus(unmountedResult, 200);
    assert.equal(unmountedResult.body.state, "available");
    assert.equal(
      await scalar(`SELECT count(*) FROM required_actions WHERE server_id = ${sqlText(unmounted.serverId)} AND code = 'server.readiness_missing' AND state = 'open'`),
      "0",
    );
  });

  it("A27 gives two servers to two of twenty concurrent registrations", async () => {
    const first = await makeAvailable("race-a");
    const second = await makeAvailable("race-b");
    const racers = await Promise.all(Array.from({ length: 20 }, async (_, index) => {
      const email = `racer-${index}@recovery-bearportal.com`;
      const invitation = await invite(email);
      return { email, invitation, token: await tokenFor(`racer-${index}`, email), index };
    }));
    const results = await Promise.all(racers.map((racer) => api(base, "/v1/organizations", {
      method: "POST",
      headers: auth(racer.token, key(`race-${racer.index}`)),
      body: JSON.stringify({ name: `Racer ${racer.index}`, invitationToken: racer.invitation }),
    })));
    for (const result of results) expectStatus(result, 201);
    const allocated = results.filter((result) => result.body.allocationState === "allocated");
    const waiting = results.filter((result) => result.body.allocationState === "waiting_for_server");
    assert.equal(allocated.length, 2);
    assert.equal(waiting.length, 18);
    const serverIds = allocated.map((result) => result.body.server.id as string);
    assert.deepEqual(new Set(serverIds), new Set([first.serverId, second.serverId]));
    for (const result of allocated) {
      assert.deepEqual(Object.keys(result.body.server).sort(), ["id", "publicIpv4", "readiness", "state"]);
      assert.equal(result.body.server.state, "reserved");
      assert.equal(result.body.server.readiness, "ready");
      assert.equal(result.body.server.publicIpv4 === first.ip || result.body.server.publicIpv4 === second.ip, true);
    }
    for (const result of waiting) {
      assert.equal(result.body.server, null);
      assert.equal(result.body.waitReason, undefined);
    }
    assert.equal(await scalar(`SELECT count(*) FROM server_assignments WHERE released_at IS NULL`), "2");
    assert.equal(await scalar(`SELECT count(*) FROM outbox_events WHERE event_type = 'organization.allocate'`), "2");
    assert.equal(await scalar(`SELECT count(*) FROM required_actions WHERE state = 'open' AND code = 'inventory.shortage'`), "1");

    const waitingOrg = waiting[0]!.body.id as string;
    const extraServer = randomUUID();
    const duplicateServer = await superFails(`INSERT INTO server_assignments (id, organization_id, server_id, reason)
      VALUES (${sqlText(randomUUID())}, ${sqlText(waitingOrg)}, ${sqlText(serverIds[0]!)}, 'forced')`);
    assert.match(duplicateServer, /duplicate key|unique/i);
    await superQuery(`INSERT INTO servers (id, label, public_ipv4, profile_code, operator_contact, state)
      VALUES (${sqlText(extraServer)}, 'extra', '203.0.113.201'::inet, 'e2-micro', 'ops@recovery-bearportal.com', 'pending_validation')`);
    const duplicateOrg = await superFails(`INSERT INTO server_assignments (id, organization_id, server_id, reason)
      VALUES (${sqlText(randomUUID())}, ${sqlText(allocated[0]!.body.id as string)}, ${sqlText(extraServer)}, 'forced')`);
    assert.match(duplicateOrg, /duplicate key|unique/i);
  });

  it("A28 waits without capacity and resumes the oldest customer once", async () => {
    const older = await registerCustomer("a28-older", "Older");
    const younger = await registerCustomer("a28-younger", "Younger");
    assert.equal(older.body.allocationState, "waiting_for_server");
    assert.equal(older.body.server, null);
    assert.equal(younger.body.server, null);
    assert.equal(await scalar(`SELECT count(*) FROM servers`), "0");
    assert.equal(await scalar(`SELECT count(*) FROM outbox_events WHERE event_type = 'organization.allocate'`), "0");
    assert.equal(await scalar(`SELECT count(*) FROM required_actions WHERE state = 'open' AND code = 'inventory.shortage'`), "1");
    const started = Date.now();
    const idle = await api(base, "/internal/allocate", {
      method: "POST",
      headers: { "content-type": "application/json", "x-bearportal-scheduler": schedulerToken },
      body: "{}",
    });
    expectStatus(idle, 200);
    assert.equal(idle.body.assigned, 0);
    assert.ok(Date.now() - started < 1000);

    const host = await enrollReady({ label: "arrived" });
    const validated = await api(base, `/v1/admin/servers/${host.serverId}/validate`, {
      method: "POST",
      headers: auth(await adminToken(), key("validate-arrived")),
      body: JSON.stringify({ expectedVersion: host.version }),
    });
    expectStatus(validated, 200);
    assert.equal(validated.body.state, "reserved");
    const olderView = await api(base, "/v1/organization/server", { headers: auth(older.token) });
    expectStatus(olderView, 200);
    assert.equal(olderView.body.allocationState, "allocated");
    assert.equal(olderView.body.server.id, host.serverId);
    assert.equal(olderView.body.waitReason, null);
    assert.deepEqual(Object.keys(olderView.body.server).sort(), ["id", "publicIpv4", "readiness", "state"]);
    const youngerView = await api(base, "/v1/organization/server", { headers: auth(younger.token) });
    assert.equal(youngerView.body.allocationState, "waiting_for_server");
    assert.equal(youngerView.body.waitReason, "inventory.shortage");
    assert.equal(youngerView.body.server, null);

    const lostId = randomUUID();
    const identityId = randomUUID();
    const lostIp = nextIp();
    const lostKey = deviceKey();
    await superQuery(`
      INSERT INTO servers (id, label, public_ipv4, profile_code, operator_contact, state, available_since, validated_at, last_heartbeat_at, readiness_report)
      VALUES (${sqlText(lostId)}, 'lost-event', ${sqlText(lostIp)}::inet, 'e2-micro', 'ops@recovery-bearportal.com', 'available', now(), now(), now(), '{}'::jsonb);
      INSERT INTO host_identities (id, server_id, public_key, fingerprint, state, confirmed_at)
      VALUES (${sqlText(identityId)}, ${sqlText(lostId)}, ${sqlText(lostKey.publicKey)}, ${sqlText(lostKey.fingerprint)}, 'confirmed', now());
      UPDATE servers SET host_identity_id = ${sqlText(identityId)} WHERE id = ${sqlText(lostId)};
    `);
    const reconciled = await api(base, "/v1/admin/server-waitlist/reconcile", {
      method: "POST",
      headers: auth(await adminToken(), key("reconcile")),
      body: "{}",
    });
    expectStatus(reconciled, 200);
    assert.deepEqual(reconciled.body.assigned, [{ organizationId: younger.organizationId, serverId: lostId }]);
    const again = await api(base, "/internal/allocate", {
      method: "POST",
      headers: { "content-type": "application/json", "x-bearportal-scheduler": schedulerToken },
      body: "{}",
    });
    expectStatus(again, 200);
    assert.equal(again.body.assigned, 0);
    assert.equal(await scalar(`SELECT count(*) FROM server_assignments WHERE released_at IS NULL`), "2");
    assert.equal(await scalar(`SELECT count(*) FROM outbox_events WHERE event_type = 'organization.allocate'`), "2");
    assert.equal(await scalar(`SELECT count(*) FROM required_actions WHERE state = 'open' AND code = 'inventory.shortage'`), "0");
    const override = await api(base, "/internal/allocate", {
      method: "POST",
      headers: { "content-type": "application/json", "x-bearportal-scheduler": schedulerToken },
      body: JSON.stringify({ organizationId: younger.organizationId }),
    });
    expectStatus(override, 400);
    const rejected = await api(base, "/internal/allocate", {
      method: "POST",
      headers: { "content-type": "application/json", "x-bearportal-scheduler": "wrong-token" },
      body: "{}",
    });
    expectStatus(rejected, 401);
    assert.equal(rejected.body.error.code, "UNAUTHENTICATED");
  });

  it("A29 keeps tainted and untouched reservations out of the free pool", async () => {
    const unverified = await tokenFor("a29-unverified", "a29-unverified@recovery-bearportal.com", { email_verified: false });
    const profile = await api(base, "/v1/me", { headers: auth(unverified) });
    expectStatus(profile, 200);
    const denied = await api(base, "/v1/organizations", {
      method: "POST",
      headers: auth(unverified, key("unverified-org")),
      body: JSON.stringify({ name: "Unverified", invitationToken: "x".repeat(24) }),
    });
    expectStatus(denied, 403);
    assert.equal(denied.body.error.code, "EMAIL_UNVERIFIED");
    assert.equal(await scalar(`SELECT count(*) FROM allocation_requests`), "0");
    assert.equal(await scalar(`SELECT count(*) FROM servers`), "0");

    const clean = await makeAvailable("clean");
    const dirty = await makeAvailable("dirty");
    const cleanOrg = await registerCustomer("a29-clean", "Clean");
    const dirtyOrg = await registerCustomer("a29-dirty", "Dirty");
    assert.equal(cleanOrg.body.server.id, clean.serverId);
    assert.equal(dirtyOrg.body.server.id, dirty.serverId);
    const cleanView = await serverView(clean.serverId);
    const dirtyView = await serverView(dirty.serverId);

    const probe = await api(base, `/v1/admin/servers/${clean.serverId}/commands`, {
      method: "POST",
      headers: auth(await adminToken(), key("probe")),
      body: JSON.stringify({ commandType: "probe_readiness", expectedEpoch: num(cleanView.auth_epoch), parameters: {} }),
    });
    expectStatus(probe, 201);
    assert.equal(await scalar(`SELECT tenant_tainted_at IS NULL FROM servers WHERE id = ${sqlText(clean.serverId)}`), "t");
    const dispatched = await api(base, `/v1/admin/servers/${clean.serverId}/commands/${probe.body.commandId}/dispatch`, {
      method: "POST",
      headers: auth(await adminToken(), key("dispatch")),
      body: "{}",
    });
    expectStatus(dispatched, 200);
    assert.equal(dispatched.body.delivered, false);
    assert.equal(dispatched.body.accepted, true);
    assert.equal(dispatched.text.includes("enrollmentToken"), false);

    const staleAuth = await tokenFor("a29-clean", cleanOrg.email, { auth_time: now() - 3600 });
    const staleCancel = await api(base, "/v1/organization/cancel-onboarding", {
      method: "POST",
      headers: auth(staleAuth, key("stale-cancel")),
      body: JSON.stringify({ expectedVersion: num(cleanOrg.body.organizationVersion ?? 1) }),
    });
    expectStatus(staleCancel, 403);
    assert.equal(staleCancel.body.error.code, "RECENT_AUTH_REQUIRED");
    const orgVersion = num((await api(base, "/v1/organization/server", { headers: auth(cleanOrg.token) })).body.organizationVersion);
    const cancelled = await api(base, "/v1/organization/cancel-onboarding", {
      method: "POST",
      headers: auth(cleanOrg.token, key("cancel-clean")),
      body: JSON.stringify({ expectedVersion: orgVersion, reason: "Changed plan" }),
    });
    expectStatus(cancelled, 200);
    assert.equal(cancelled.body.state, "cancellation_requested");
    assert.equal(await scalar(`SELECT state FROM servers WHERE id = ${sqlText(clean.serverId)}`), "reserved");
    const releaseVersion = num((await serverView(clean.serverId)).version);
    const released = await api(base, `/v1/admin/servers/${clean.serverId}/release-reservation`, {
      method: "POST",
      headers: auth(await adminToken(), key("release")),
      body: JSON.stringify({ expectedVersion: releaseVersion, cancellationProof: true }),
    });
    expectStatus(released, 200);
    assert.equal(released.body.state, "pending_validation");
    assert.equal(await scalar(`SELECT state FROM servers WHERE id = ${sqlText(clean.serverId)}`), "pending_validation");
    assert.equal(await scalar(`SELECT count(*) FROM server_assignments WHERE server_id = ${sqlText(clean.serverId)} AND released_at IS NULL`), "0");
    const staleDispatch = await api(base, `/v1/admin/servers/${clean.serverId}/commands/${probe.body.commandId}/dispatch`, {
      method: "POST",
      headers: auth(await adminToken(), key("stale-dispatch")),
      body: "{}",
    });
    expectStatus(staleDispatch, 409);
    assert.equal(staleDispatch.body.error.code, "STALE_EPOCH");
    const observedAt = new Date().toISOString();
    const signed = { serverId: clean.serverId, authEpoch: num(cleanView.auth_epoch), observedAt, readiness: readyReport };
    const staleHeart = await api(base, "/internal/hosts/heartbeat", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ ...signed, publicKey: clean.device.publicKey, signature: signHeartbeat(clean.device.privateKey, signed) }),
    });
    expectStatus(staleHeart, 409);
    assert.equal(staleHeart.body.error.code, "STALE_EPOCH");

    const install = await api(base, `/v1/admin/servers/${dirty.serverId}/commands`, {
      method: "POST",
      headers: auth(await adminToken(), key("install")),
      body: JSON.stringify({
        commandType: "install_release",
        expectedEpoch: num(dirtyView.auth_epoch),
        parameters: { releaseId: "rel-1" },
      }),
    });
    expectStatus(install, 201);
    assert.equal(await scalar(`SELECT tenant_tainted_at IS NOT NULL FROM servers WHERE id = ${sqlText(dirty.serverId)}`), "t");
    const dirtyVersion = num((await api(base, "/v1/organization/server", { headers: auth(dirtyOrg.token) })).body.organizationVersion);
    const blockedCancel = await api(base, "/v1/organization/cancel-onboarding", {
      method: "POST",
      headers: auth(dirtyOrg.token, key("cancel-dirty")),
      body: JSON.stringify({ expectedVersion: dirtyVersion }),
    });
    expectStatus(blockedCancel, 409);
    assert.equal(blockedCancel.body.error.code, "TENANT_ACTIVE");
    const blockedRelease = await api(base, `/v1/admin/servers/${dirty.serverId}/release-reservation`, {
      method: "POST",
      headers: auth(await adminToken(), key("release-dirty")),
      body: JSON.stringify({ expectedVersion: num((await serverView(dirty.serverId)).version), cancellationProof: true }),
    });
    expectStatus(blockedRelease, 409);
    assert.equal(blockedRelease.body.error.code, "TAINTED_SERVER");
    await superQuery(`UPDATE jobs SET lease_expires_at = now() - interval '1 minute' WHERE organization_id = ${sqlText(dirtyOrg.organizationId)} AND state = 'queued'`);
    const expired = await api(base, "/v1/admin/jobs/expire-leases", {
      method: "POST",
      headers: auth(await adminToken(), key("expire")),
      body: "{}",
    });
    expectStatus(expired, 200);
    assert.ok(expired.body.expiredLeases >= 1);
    assert.equal(await scalar(`SELECT state FROM servers WHERE id = ${sqlText(dirty.serverId)}`), "reserved");
    const quarantined = await api(base, `/v1/admin/servers/${dirty.serverId}/quarantine`, {
      method: "POST",
      headers: auth(await adminToken(), key("quarantine")),
      body: JSON.stringify({ expectedVersion: num((await serverView(dirty.serverId)).version), reason: "Install failed" }),
    });
    expectStatus(quarantined, 200);
    assert.equal(quarantined.body.state, "quarantined");
    assert.equal(await scalar(`SELECT count(*) FROM server_assignments WHERE server_id = ${sqlText(dirty.serverId)} AND released_at IS NULL`), "1");

    await superQuery(`UPDATE servers SET state = 'available', validated_at = now(), last_heartbeat_at = now() WHERE id = ${sqlText(clean.serverId)}`);
    const next = await registerCustomer("a29-next", "Next");
    assert.equal(next.body.allocationState, "waiting_for_server");
    assert.equal(next.body.server, null);
    assert.equal(await scalar(`SELECT state FROM servers WHERE id = ${sqlText(dirty.serverId)}`), "quarantined");
  });

  it("A30 blocks duplicate inventory and skips ineligible hosts", async () => {
    const address = nextIp();
    const first = await api(base, "/v1/admin/servers", {
      method: "POST",
      headers: auth(await adminToken(), key("dup-ip-a")),
      body: JSON.stringify({
        label: "dup-a",
        publicIpv4: address,
        profileCode: "e2-micro",
        operatorContact: "ops@recovery-bearportal.com",
        providerReference: "vm-shared",
        preparationAttestations: attestations,
      }),
    });
    expectStatus(first, 201);
    const duplicateIp = await api(base, "/v1/admin/servers", {
      method: "POST",
      headers: auth(await adminToken(), key("dup-ip-b")),
      body: JSON.stringify({
        label: "dup-b",
        publicIpv4: address,
        profileCode: "e2-micro",
        operatorContact: "ops@recovery-bearportal.com",
        preparationAttestations: attestations,
      }),
    });
    expectStatus(duplicateIp, 409);
    assert.equal(duplicateIp.body.error.code, "DUPLICATE_ADDRESS");
    const duplicateRef = await api(base, "/v1/admin/servers", {
      method: "POST",
      headers: auth(await adminToken(), key("dup-ref")),
      body: JSON.stringify({
        label: "dup-ref",
        publicIpv4: nextIp(),
        profileCode: "e2-micro",
        operatorContact: "ops@recovery-bearportal.com",
        providerReference: "vm-shared",
        preparationAttestations: attestations,
      }),
    });
    expectStatus(duplicateRef, 409);
    assert.equal(duplicateRef.body.error.code, "DUPLICATE_PROVIDER_REFERENCE");

    const enrolled = await enrollReady({ label: "device-a" });
    const other = await api(base, "/v1/admin/servers", {
      method: "POST",
      headers: auth(await adminToken(), key("device-b")),
      body: JSON.stringify({
        label: "device-b",
        publicIpv4: nextIp(),
        profileCode: "e2-micro",
        operatorContact: "ops@recovery-bearportal.com",
        preparationAttestations: attestations,
      }),
    });
    expectStatus(other, 201);
    const otherEnrollment = await api(base, `/v1/admin/servers/${other.body.serverId}/enrollment`, {
      method: "POST",
      headers: auth(await adminToken(), key("device-b-token")),
      body: "{}",
    });
    const duplicateDevice = await api(base, "/internal/hosts/enroll", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        serverId: other.body.serverId,
        token: otherEnrollment.body.enrollmentToken,
        publicKey: enrolled.device.publicKey,
      }),
    });
    expectStatus(duplicateDevice, 409);
    assert.equal(duplicateDevice.body.error.code, "DUPLICATE_DEVICE");

    const fresh = await makeAvailable("fresh");
    const stale = await makeAvailable("stale-choice");
    await superQuery(`UPDATE servers SET last_heartbeat_at = now() - interval '10 minutes' WHERE id = ${sqlText(stale.serverId)}`);
    const chooser = await registerCustomer("a30-chooser", "Chooser");
    assert.equal(chooser.body.server.id, fresh.serverId);
    assert.equal(await scalar(`SELECT state FROM servers WHERE id = ${sqlText(stale.serverId)}`), "available");

    const bound = await enrollReady({ label: "restore" });
    const waiting = await registerCustomer("a30-restore", "Restore");
    assert.equal(waiting.body.server, null);
    const boundView = await serverView(bound.serverId);
    const binding = await api(base, `/v1/admin/servers/${bound.serverId}/recovery-binding`, {
      method: "POST",
      headers: auth(await adminToken(), key("binding")),
      body: JSON.stringify({ organizationId: waiting.organizationId, expectedVersion: num(boundView.version) }),
    });
    expectStatus(binding, 201);
    assert.equal(binding.body.state, "quarantined");
    await superQuery(`UPDATE servers SET state = 'available', validated_at = now(), last_heartbeat_at = now() WHERE id = ${sqlText(bound.serverId)}`);
    const skipped = await api(base, "/v1/admin/server-waitlist/reconcile", {
      method: "POST",
      headers: auth(await adminToken(), key("skip-binding")),
      body: "{}",
    });
    expectStatus(skipped, 200);
    assert.deepEqual(skipped.body.assigned, []);
    const replacement = await enrollReady({ label: "replacement" });
    const assigned = await api(base, `/v1/admin/servers/${replacement.serverId}/validate`, {
      method: "POST",
      headers: auth(await adminToken(), key("validate-replacement")),
      body: JSON.stringify({ expectedVersion: replacement.version }),
    });
    expectStatus(assigned, 200);
    assert.equal(assigned.body.state, "reserved");
    assert.equal(await scalar(`SELECT server_id FROM server_assignments WHERE organization_id = ${sqlText(waiting.organizationId)} AND released_at IS NULL`), replacement.serverId);
    assert.equal(await scalar(`SELECT state FROM recovery_bindings WHERE replacement_server_id = ${sqlText(bound.serverId)}`), "pending");

    const beforeCount = await scalar(`SELECT count(*) FROM servers`);
    const current = await serverView(fresh.serverId);
    const movedIp = nextIp();
    const moved = await api(base, `/v1/admin/servers/${fresh.serverId}/ip-change`, {
      method: "POST",
      headers: auth(await adminToken(), key("ip-change")),
      body: JSON.stringify({ publicIpv4: movedIp, reason: "Provider renumbered", expectedVersion: num(current.version) }),
    });
    expectStatus(moved, 200);
    assert.equal(moved.body.serverId, fresh.serverId);
    assert.equal(moved.body.publicIpv4, movedIp);
    assert.equal(moved.body.installerStarted, false);
    assert.equal(typeof moved.body.jobId, "string");
    assert.equal(await scalar(`SELECT count(*) FROM servers`), beforeCount);
    assert.equal(await scalar(`SELECT host(public_ipv4) FROM servers WHERE id = ${sqlText(fresh.serverId)}`), movedIp);
    assert.equal(
      await scalar(`SELECT checkpoint->>'installerStarted' FROM jobs WHERE id = ${sqlText(moved.body.jobId)}`),
      "false",
    );
    const collision = await api(base, `/v1/admin/servers/${fresh.serverId}/ip-change`, {
      method: "POST",
      headers: auth(await adminToken(), key("ip-collision")),
      body: JSON.stringify({
        publicIpv4: stale.ip,
        reason: "Collision",
        expectedVersion: num((await serverView(fresh.serverId)).version),
      }),
    });
    expectStatus(collision, 409);
    assert.equal(collision.body.error.code, "DUPLICATE_ADDRESS");
    assert.equal(await scalar(`SELECT host(public_ipv4) FROM servers WHERE id = ${sqlText(fresh.serverId)}`), movedIp);

    await superQuery(`UPDATE servers SET state = 'available' WHERE id = ${sqlText(fresh.serverId)}`);
    const rivalHost = await makeAvailable("rival");
    const rival = await registerCustomer("a30-rival", "Rival");
    assert.equal(rival.body.server.id, rivalHost.serverId);
    assert.equal(
      await scalar(`SELECT server_id FROM server_assignments WHERE organization_id = ${sqlText(chooser.organizationId)} AND released_at IS NULL`),
      fresh.serverId,
    );
  });

  it("stores relay inventory and assigns one account and one plan", async () => {
    relayHealthy = false;
    const created = await api(base, "/v1/admin/relay-connections", {
      method: "POST",
      headers: auth(await adminToken(), key("relay")),
      body: JSON.stringify({
        label: "Brevo one",
        loginEmail: "relay-one@recovery-bearportal.com",
        apiKey: apiCanary,
        smtpLogin: "smtp-one",
        smtpKey: smtpCanary,
        dailyLimit: 250,
      }),
    });
    expectStatus(created, 201);
    assert.equal(created.body.state, "inactive");
    assert.equal(created.text.includes(apiCanary), false);
    assert.equal(created.text.includes(smtpCanary), false);
    assert.equal(logs().includes(apiCanary), false);
    assert.equal(logs().includes(smtpCanary), false);
    assert.equal(readdirSync(secretsDir).some((file) => readFileSync(join(secretsDir, file)).includes(Buffer.from(apiCanary))), false);
    assert.equal(readdirSync(secretsDir).some((file) => readFileSync(join(secretsDir, file)).includes(Buffer.from(smtpCanary))), false);

    const inactive = await api(base, `/v1/admin/relay-connections/${created.body.id}/validate`, {
      method: "POST",
      headers: auth(await adminToken(), key("relay-inactive")),
      body: "{}",
    });
    expectStatus(inactive, 422);
    assert.equal(inactive.body.error.code, "relay.activation_required");
    assert.equal(typeof inactive.body.error.requiredActionId, "string");
    assert.equal(await scalar(`SELECT state FROM relay_connections WHERE id = ${sqlText(created.body.id)}`), "inactive");
    assert.equal(await scalar(`SELECT count(*) FROM required_actions WHERE code = 'relay.activation_required' AND state = 'open'`), "1");
    assert.equal(JSON.stringify(relayCalls).includes(apiCanary), false);

    relayHealthy = true;
    const activated = await api(base, `/v1/admin/relay-connections/${created.body.id}/validate`, {
      method: "POST",
      headers: auth(await adminToken(), key("relay-active")),
      body: "{}",
    });
    expectStatus(activated, 200);
    assert.equal(activated.body.state, "available");
    const host = await makeAvailable("plan-host");
    const listed = await api(base, "/v1/admin/relay-connections", { headers: auth(await adminToken()) });
    expectStatus(listed, 200);
    assert.equal(listed.text.includes(apiCanary), false);
    const version = num(listed.body.relays.find((relay: { id: string }) => relay.id === created.body.id).version);
    const owner = await registerCustomer("relay-owner", "Relay Owner");
    const other = await registerCustomer("relay-other", "Relay Other");
    assert.equal(owner.body.server.id, host.serverId);
    const assigned = await api(base, `/v1/admin/organizations/${owner.organizationId}/assign-relay`, {
      method: "POST",
      headers: auth(await adminToken(), key("assign-relay")),
      body: JSON.stringify({ relayConnectionId: created.body.id, expectedVersion: version }),
    });
    expectStatus(assigned, 201);
    const second = await api(base, `/v1/admin/organizations/${other.organizationId}/assign-relay`, {
      method: "POST",
      headers: auth(await adminToken(), key("assign-relay-2")),
      body: JSON.stringify({ relayConnectionId: created.body.id, expectedVersion: version + 1 }),
    });
    expectStatus(second, 422);
    assert.equal(second.body.error.code, "RELAY_INACTIVE");
    await superQuery(`UPDATE relay_connections SET state = 'available' WHERE id = ${sqlText(created.body.id)}`);
    const conflicted = await api(base, `/v1/admin/organizations/${other.organizationId}/assign-relay`, {
      method: "POST",
      headers: auth(await adminToken(), key("assign-relay-3")),
      body: JSON.stringify({ relayConnectionId: created.body.id, expectedVersion: version + 1 }),
    });
    expectStatus(conflicted, 409);

    const supportToken = await tokenFor("support-m3", "support-m3@recovery-bearportal.com", { amr: ["pwd", "totp"] });
    const supportMe = await api(base, "/v1/me", { headers: auth(await tokenFor("support-m3", "support-m3@recovery-bearportal.com")) });
    expectStatus(supportMe, 200);
    const supportId = await scalar(`SELECT id FROM users WHERE identity_subject = 'support-m3'`);
    const granted = await api(base, "/v1/admin/operator-roles", {
      method: "POST",
      headers: auth(await adminToken(), key("grant-support")),
      body: JSON.stringify({ userId: supportId, role: "support", reason: "Read inventory" }),
    });
    expectStatus(granted, 201);
    const supportRead = await api(base, "/v1/admin/servers", { headers: auth(supportToken) });
    expectStatus(supportRead, 200);
    const supportRelay = await api(base, "/v1/admin/relay-connections", { headers: auth(supportToken) });
    expectStatus(supportRelay, 403);

    const planned = await api(base, `/v1/admin/organizations/${owner.organizationId}/assign-plan`, {
      method: "POST",
      headers: auth(await adminToken(), key("plan")),
      body: JSON.stringify({ planCode: "beta", planRevision: 1, reason: "Beta plan", expectedVersion: 1 }),
    });
    expectStatus(planned, 200);
    assert.equal(planned.body.requiredActionId, null);
    assert.equal(await scalar(`SELECT plan_id FROM organizations WHERE id = ${sqlText(owner.organizationId)}`), "00000000-0000-4000-8000-000000000001");
    await superQuery(`UPDATE servers SET profile_code = 'e2-small' WHERE id = ${sqlText(host.serverId)}`);
    const mismatch = await api(base, `/v1/admin/organizations/${owner.organizationId}/assign-plan`, {
      method: "POST",
      headers: auth(await adminToken(), key("plan-mismatch")),
      body: JSON.stringify({ planCode: "beta", planRevision: 1, reason: "Profile differs", expectedVersion: 2 }),
    });
    expectStatus(mismatch, 200);
    assert.equal(typeof mismatch.body.requiredActionId, "string");
    assert.equal(await scalar(`SELECT state FROM servers WHERE id = ${sqlText(host.serverId)}`), "reserved");
  });

  it("keeps waits failure-safe and fails closed without a live reader", async () => {
    const waiter = await registerCustomer("wait-safe", "Waiting");
    await superQuery(`
      INSERT INTO jobs (id, organization_id, kind, state, lease_expires_at)
      VALUES (${sqlText(randomUUID())}, ${sqlText(waiter.organizationId)}, 'install_release', 'queued', now() - interval '1 minute');
      INSERT INTO jobs (id, organization_id, kind, state, created_at)
      VALUES (${sqlText(randomUUID())}, ${sqlText(waiter.organizationId)}, 'human', 'waiting_human', now() - interval '8 days');
    `);
    const expired = await api(base, "/v1/admin/jobs/expire-leases", {
      method: "POST",
      headers: auth(await adminToken(), key("expire-waits")),
      body: "{}",
    });
    expectStatus(expired, 200);
    assert.equal(expired.body.expiredLeases, 1);
    assert.equal(expired.body.expiredHumanWaits, 1);
    assert.equal(await scalar(`SELECT state FROM allocation_requests WHERE organization_id = ${sqlText(waiter.organizationId)}`), "waiting_for_server");
    assert.equal(await scalar(`SELECT count(*) FROM servers`), "0");
    assert.equal(await scalar(`SELECT count(*) FROM required_actions WHERE state = 'open' AND code = 'inventory.shortage'`), "1");
    const names = await superQuery(`SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' AND table_name ~ 'vm|gcp|google|harness'`);
    assert.deepEqual(names, []);

    const closedSecrets = mkdtempSync(join(tmpdir(), "bearportal-m3-closed-"));
    const closed = await buildServer({
    billingRequired: false,
      onboardingIntervalMs: 0,
      databaseUrl,
      secretsDir: closedSecrets,
      secretKeyHex,
      jwtPublicKeyPem: publicKeyPem,
      issuer,
      audience,
    }, logStream);
    try {
      await closed.listen({ host: "127.0.0.1", port: 0 });
      const address = closed.server.address();
      if (!address || typeof address === "string") throw new Error("The closed API did not listen.");
      const closedBase = `http://127.0.0.1:${address.port}`;
      const unavailable = await api(closedBase, "/internal/allocate", {
        method: "POST",
        headers: { "content-type": "application/json", "x-bearportal-scheduler": schedulerToken },
        body: "{}",
      });
      expectStatus(unavailable, 503);
      assert.equal(unavailable.body.error.code, "SCHEDULER_UNAVAILABLE");
      assert.equal(unavailable.body.error.retryable, true);

      const domain = "proof-closed.alpha-bearportal.com";
      const stored = await addDomain(waiter.token, domain);
      const unverified = await api(closedBase, `/v1/domains/${stored.domainId}/verify`, {
        method: "POST",
        headers: auth(waiter.token, key("verify-closed")),
        body: "{}",
      });
      expectStatus(unverified, 503);
      assert.equal(unverified.body.error.code, "DNS_READER_UNAVAILABLE");
      assert.equal(unverified.body.error.retryable, true);
      assert.equal(await scalar(`SELECT state FROM domains WHERE id = ${sqlText(stored.domainId)}`), "pending");

      const relay = await api(closedBase, "/v1/admin/relay-connections", {
        method: "POST",
        headers: auth(await adminToken(), key("relay-closed")),
        body: JSON.stringify({
          label: "Closed relay",
          loginEmail: "relay-closed@recovery-bearportal.com",
          apiKey: "closed-api-key",
          smtpLogin: "smtp-closed",
          smtpKey: "closed-smtp-key",
          dailyLimit: 100,
        }),
      });
      expectStatus(relay, 201);
      const closedCheck = await api(closedBase, `/v1/admin/relay-connections/${relay.body.id}/validate`, {
        method: "POST",
        headers: auth(await adminToken(), key("relay-closed-validate")),
        body: "{}",
      });
      expectStatus(closedCheck, 422);
      assert.equal(closedCheck.body.error.code, "relay.activation_required");
      assert.equal(await scalar(`SELECT state FROM relay_connections WHERE id = ${sqlText(relay.body.id)}`), "inactive");
      relayHealthy = true;
      const opened = await api(base, `/v1/admin/relay-connections/${relay.body.id}/validate`, {
        method: "POST",
        headers: auth(await adminToken(), key("relay-opened")),
        body: "{}",
      });
      expectStatus(opened, 200);
      assert.equal(opened.body.state, "available");
    } finally {
      await closed.close();
    }
  });
});

async function superFails(sql: string): Promise<string> {
  try {
    await superQuery(sql);
  } catch (error) {
    return error instanceof Error ? error.message : String(error);
  }
  throw new Error("Expected the SQL statement to fail.");
}
