import { integrationDatabases, queryTestDatabase } from "./helpers/database.ts";
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, randomUUID, sign as cryptoSign, type KeyObject } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";
import { after, before, beforeEach, describe, it } from "node:test";
import { exportSPKI, generateKeyPair, SignJWT, type CryptoKey } from "jose";
import { bootstrapAdmin, buildServer, type ApiDeps } from "../apps/api/src/server.ts";
import type { BrevoDnsRecord } from "../packages/providers/brevo/src/index.ts";
import type { ZoneReadRequest, ZoneReadResult } from "../packages/providers/dns/src/reader.ts";
import { migrate } from "../packages/db/src/migrate.ts";
import { loadSecretKey, open as openSecret } from "../packages/secrets/src/store.ts";
import type { HostReport } from "../packages/servers/src/readiness.ts";
import { heartbeatMessage } from "../packages/servers/src/signature.ts";
import {
  activationAllowed,
  assertMailboxLocalPart,
  assertReleaseLayout,
  compareDns,
  customerMailboxLimit,
  DnsObserverUnavailableError,
  installerFingerprint,
  InstallerUnavailableError,
  isExampleWebmail,
  MailboxNameError,
  parseInstallerResult,
  ReleaseLayoutError,
  unavailableDnsObserver,
  unavailableInstallerRunner,
} from "../packages/servers/src/installer.ts";

const { databaseUrl, migrationUrl, superDatabaseUrl } = integrationDatabases();
const issuer = "https://test.bearportal.local";
const audience = "bearportal-test";
const secretKeyHex = "ab".repeat(32);
const adminEmail = "admin@recovery-bearportal.com";
const schedulerToken = "scheduler-test-token";
const DOMAIN = "mail-m4.alpha-bearportal.com";
const releaseId = "m4fixture";
const dnsCanary = "namecom-token-CANARY-m4";
const apiCanary = "BREVO-KEY-CANARY-m4";
const smtpCanary = "SMTP-KEY-CANARY-m4";
const QUOTA = 1073741824;

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
type RunnerMode = "success" | "partial" | "conflict" | "down";
type ObserverMode = "match" | "missing-mx" | "apex" | "down";
type Ready = {
  token: string;
  organizationId: string;
  domainId: string;
  deploymentId: string;
  mailboxId: string;
  serverId: string;
};

const logChunks: Buffer[] = [];
const logStream = new Writable({
  write(chunk, _encoding, callback) {
    logChunks.push(Buffer.from(chunk));
    callback();
  },
});

const zones = new Map<string, ZoneReadResult>();
const zoneCalls: ZoneReadRequest[] = [];
const runnerCalls: Array<{ mode: string; input: Record<string, unknown> }> = [];
const brevoCreates: string[] = [];
const brevoAuths: string[] = [];

let privateKey: CryptoKey;
let publicKeyPem = "";
let app: Awaited<ReturnType<typeof buildServer>> | undefined;
let base = "";
let secretsDir = "";
let artifactDir = "";
let ipHost = 10;
let step = 0;
let relayHealthy = true;
let runnerMode: RunnerMode = "success";
let observerMode: ObserverMode = "match";
let brevoThrows = false;

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

function recordsFor(domain: string): BrevoDnsRecord[] {
  return [
    { purpose: "brevo_code", type: "TXT", host: "@", value: `brevo-code:${domain}` },
    { purpose: "dkim", type: "TXT", host: "mail._domainkey", value: "k=rsa; p=m4" },
    { purpose: "dmarc", type: "TXT", host: "_dmarc", value: "v=DMARC1; p=none" },
  ];
}

function writeRelease(dir: string): void {
  mkdirSync(dir, { recursive: true });
  const names = ["install.sh", "stalwart", "bearmail-webui.tar.gz", "mcp_install.sh"];
  const lines: string[] = [];
  for (const name of names) {
    const body = `fixture ${name}\n`;
    writeFileSync(join(dir, name), body);
    lines.push(`${createHash("sha256").update(body).digest("hex")}  ${name}`);
  }
  writeFileSync(join(dir, "SHA256SUMS"), `${lines.join("\n")}\n`);
}

function installerResult(mode: string, input: Record<string, unknown>): unknown {
  const domain = String(input.domain);
  const ip = String(input.publicIpv4);
  const dns = {
    previousMx: [{ priority: 10, target: "mx.old-mail.alpha-bearportal.com" }],
    published: [
      { type: "A", host: `mail.${domain}`, value: ip, state: "published" },
      { type: "MX", host: domain, value: `10 mail.${domain}`, state: "published" },
      { type: "TXT", host: "@", value: `brevo-code:${domain}`, state: "published" },
    ],
    minimumTtl: 300,
    engineDkimHost: `default._domainkey.${domain}`,
    engineDkimValue: "v=DKIM1; k=rsa; p=engine",
  };
  if (runnerMode === "conflict") {
    return {
      status: "failed",
      exitCode: 1,
      retryable: false,
      errorCode: "DNS_RECORD_CONFLICT",
      dns: { previousMx: dns.previousMx, published: [], minimumTtl: 300, engineDkimHost: null, engineDkimValue: null },
    };
  }
  if (mode === "dry_run") return { status: "dry_run", exitCode: 0, retryable: false, errorCode: null, dns };
  if (runnerMode === "partial") {
    return { status: "dns_partial", exitCode: 10, retryable: true, errorCode: "DNS_PUBLISH_FAILED", dns };
  }
  return { status: "succeeded", exitCode: 0, retryable: false, errorCode: null, dns };
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
  let body: Record<string, any> = {};
  if (text) body = JSON.parse(text) as Record<string, any>;
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

function goodZone(domain: string): ZoneReadResult {
  const nameservers = ["ns1.gamma-bearportal.com", "ns2.gamma-bearportal.com"];
  return {
    ok: true,
    snapshot: {
      zone: domain,
      nameservers,
      records: [
        { name: domain, type: "NS", value: nameservers[0]! },
        { name: domain, type: "A", value: "192.0.2.20" },
        { name: `www.${domain}`, type: "A", value: "192.0.2.20" },
        { name: domain, type: "TXT", value: "google-site-verification=alpha" },
      ],
    },
  };
}

function ciphertextHas(needle: string): boolean {
  return readdirSync(secretsDir).some((file) => readFileSync(join(secretsDir, file)).includes(Buffer.from(needle)));
}

async function storedText(): Promise<string> {
  const rows = await superQuery(`
    SELECT response::text FROM idempotency_keys
    UNION ALL SELECT checkpoint::text FROM jobs
    UNION ALL SELECT coalesce(payload::text, '') FROM host_commands
    UNION ALL SELECT redacted_diff::text FROM audit_events
    UNION ALL SELECT coalesce(result::text, '') FROM installer_runs
  `);
  return rows.map((row) => row[0] ?? "").join("\n");
}

function assertInstallerInput(input: Record<string, unknown>, ip: string, password = ""): void {
  assert.equal(input.schemaVersion, 1);
  assert.equal(input.mxCutoverAuthorized, true);
  assert.equal(input.dataPath, "/var/lib/stalwart");
  assert.equal(input.domain, DOMAIN);
  assert.equal(input.publicIpv4, ip);
  assert.equal(input.mailHostname, `mail.${DOMAIN}`);
  assert.equal(input.webmailHostname, `bearmail.${DOMAIN}`);
  assert.equal(typeof input.generation, "number");
  assert.ok(Number(input.generation) > 0);
  const dns = input.dns as { provider: string; zone: string; credentialFile: string };
  assert.equal(dns.provider, "namecom");
  assert.equal(dns.zone, DOMAIN);
  assert.match(dns.credentialFile, /^secret:[0-9a-f-]{36}$/i);
  const relay = input.relay as { host: string; port: number; tls: string; login: string; credentialFile: string };
  assert.equal(relay.host, "smtp-relay.brevo.com");
  assert.equal(relay.port, 587);
  assert.equal(relay.tls, "starttls-required");
  assert.equal(relay.login, "smtp-m4");
  assert.match(relay.credentialFile, /^secret:[0-9a-f-]{36}$/i);
  assert.match(String(input.adminCredentialFile), /^secret:[0-9a-f-]{36}$/i);
  assert.deepEqual(input.brevoDnsRecords, recordsFor(DOMAIN));
  assert.equal((input.release as { id: string }).id, releaseId);
  const json = JSON.stringify(input);
  for (const secret of [dnsCanary, apiCanary, smtpCanary, password]) {
    if (secret) assert.equal(json.includes(secret), false);
  }
  assert.equal(json.includes("\"password\""), false);
  assert.equal(json.includes("\"smtpKey\""), false);
  assert.equal(json.includes("\"apiKey\""), false);
  assert.equal(json.includes("\"token\""), false);
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

async function registerCustomer(local: string, name: string): Promise<{ token: string; organizationId: string; body: Record<string, any> }> {
  const email = `${local}@recovery-bearportal.com`;
  const invitation = await invite(email);
  const token = await tokenFor(local, email);
  const created = await api(base, "/v1/organizations", {
    method: "POST",
    headers: auth(token, key(`org-${local}`)),
    body: JSON.stringify({ name, invitationToken: invitation }),
  });
  expectStatus(created, 201);
  return { token, organizationId: created.body.id as string, body: created.body };
}

async function addDomain(token: string, domain: string): Promise<string> {
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
      credentials: { username: "portal-namecom", token: dnsCanary },
    }),
  });
  expectStatus(dns, 201);
  return created.body.id as string;
}

async function verifyDomain(token: string, domain: string): Promise<string> {
  zones.set(domain, goodZone(domain));
  const domainId = await addDomain(token, domain);
  const verified = await api(base, `/v1/domains/${domainId}/verify`, {
    method: "POST",
    headers: auth(token, key("verify")),
    body: "{}",
  });
  expectStatus(verified, 200);
  assert.equal(verified.body.state, "verified");
  return domainId;
}

async function enrollReady(label: string): Promise<{ serverId: string; ip: string; version: number }> {
  const ip = nextIp();
  const created = await api(base, "/v1/admin/servers", {
    method: "POST",
    headers: auth(await adminToken(), key("server")),
    body: JSON.stringify({
      label,
      publicIpv4: ip,
      profileCode: "e2-micro",
      operatorContact: "ops@recovery-bearportal.com",
      preparationAttestations: attestations,
    }),
  });
  expectStatus(created, 201);
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
  let view = await api(base, `/v1/admin/servers/${serverId}`, { headers: auth(await adminToken()) });
  expectStatus(view, 200);
  const confirmed = await api(base, `/v1/admin/servers/${serverId}/confirm-identity`, {
    method: "POST",
    headers: auth(await adminToken(), key("confirm")),
    body: JSON.stringify({ fingerprint: device.fingerprint, expectedVersion: num(view.body.version) }),
  });
  expectStatus(confirmed, 200);
  view = await api(base, `/v1/admin/servers/${serverId}`, { headers: auth(await adminToken()) });
  const observedAt = new Date().toISOString();
  const signed = { serverId, authEpoch: num(view.body.auth_epoch), observedAt, readiness: readyReport };
  const heart = await api(base, "/internal/hosts/heartbeat", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ ...signed, publicKey: device.publicKey, signature: signHeartbeat(device.privateKey, signed) }),
  });
  expectStatus(heart, 200);
  view = await api(base, `/v1/admin/servers/${serverId}`, { headers: auth(await adminToken()) });
  return { serverId, ip, version: num(view.body.version) };
}

async function makeAvailable(label: string): Promise<{ serverId: string; ip: string }> {
  const enrolled = await enrollReady(label);
  const validated = await api(base, `/v1/admin/servers/${enrolled.serverId}/validate`, {
    method: "POST",
    headers: auth(await adminToken(), key("validate")),
    body: JSON.stringify({ expectedVersion: enrolled.version }),
  });
  expectStatus(validated, 200);
  assert.equal(validated.body.state, "available");
  return { serverId: enrolled.serverId, ip: enrolled.ip };
}

async function addRelay(): Promise<void> {
  const created = await api(base, "/v1/admin/relay-connections", {
    method: "POST",
    headers: auth(await adminToken(), key("relay")),
    body: JSON.stringify({
      label: "Brevo m4",
      loginEmail: "relay-m4@recovery-bearportal.com",
      apiKey: apiCanary,
      smtpLogin: "smtp-m4",
      smtpKey: smtpCanary,
      dailyLimit: 250,
    }),
  });
  expectStatus(created, 201);
  assert.equal(created.text.includes(apiCanary), false);
  assert.equal(created.text.includes(smtpCanary), false);
  const validated = await api(base, `/v1/admin/relay-connections/${created.body.id}/validate`, {
    method: "POST",
    headers: auth(await adminToken(), key("relay-validate")),
    body: "{}",
  });
  expectStatus(validated, 200);
  assert.equal(validated.body.state, "available");
}

async function createDeployment(token: string, domainId: string, localPart = "owner"): Promise<{ id: string; mailboxId: string }> {
  const created = await api(base, "/v1/deployments", {
    method: "POST",
    headers: auth(token, key("deployment")),
    body: JSON.stringify({ domainId, firstMailboxLocalPart: localPart, testMailConsent: true }),
  });
  expectStatus(created, 201);
  assert.equal(created.body.mailHostname, `mail.${DOMAIN}`);
  assert.equal(created.body.webmailHostname, `bearmail.${DOMAIN}`);
  assert.equal(created.body.mxAuthorized, false);
  assert.equal(created.body.onboardingStage, "draft");
  assert.equal(created.body.lifecycleState, "onboarding");
  return { id: created.body.id as string, mailboxId: created.body.mailboxId as string };
}

async function readyCustomer(local = "m4-owner"): Promise<Ready> {
  const host = await makeAvailable(`${local}-host`);
  const customer = await registerCustomer(local, "M4 Owner");
  assert.equal(customer.body.server.id, host.serverId);
  const domainId = await verifyDomain(customer.token, DOMAIN);
  await addRelay();
  const deployment = await createDeployment(customer.token, domainId);
  assert.equal(runnerCalls.length, 0);
  assert.equal(brevoCreates.length, 0);
  return {
    token: customer.token,
    organizationId: customer.organizationId,
    domainId,
    deploymentId: deployment.id,
    mailboxId: deployment.mailboxId,
    serverId: host.serverId,
  };
}

async function provision(token: string, deploymentId: string, expectedVersion: number, idempotencyKey = key("provision")): Promise<ApiResult> {
  return api(base, `/v1/deployments/${deploymentId}/provision`, {
    method: "POST",
    headers: auth(token, idempotencyKey),
    body: JSON.stringify({ expectedVersion }),
  });
}

async function serverView(serverId: string): Promise<Record<string, any>> {
  const view = await api(base, `/v1/admin/servers/${serverId}`, { headers: auth(await adminToken()) });
  expectStatus(view, 200);
  return view.body;
}

async function adminPassword(): Promise<string> {
  const fileName = await scalar("SELECT file_name FROM secret_refs WHERE purpose = 'installer-admin' AND state = 'active'");
  const plaintext = openSecret(readFileSync(join(secretsDir, fileName)), loadSecretKey(secretKeyHex));
  const parsed = JSON.parse(plaintext) as { username: string; password: string };
  assert.equal(parsed.username, `admin@${DOMAIN}`);
  assert.ok(parsed.password.length >= 16);
  return parsed.password;
}

describe("M4 installation", { concurrency: false }, () => {
  before(async () => {
    await migrate(migrationUrl);
    const pair = await generateKeyPair("RS256", { extractable: true });
    privateKey = pair.privateKey;
    publicKeyPem = await exportSPKI(pair.publicKey);
    secretsDir = mkdtempSync(join(tmpdir(), "bearportal-m4-secrets-"));
    artifactDir = join(mkdtempSync(join(tmpdir(), "bearportal-m4-release-")), releaseId);
    writeRelease(artifactDir);
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
      release: { id: releaseId, artifactDir },
      zoneReader: {
        async readZone(input) {
          zoneCalls.push({ provider: input.provider, zone: input.zone, domain: input.domain });
          assert.deepEqual(Object.keys(input).sort(), ["domain", "provider", "zone"]);
          return zones.get(input.domain) ?? { ok: false, code: "PROOF_REJECTED" };
        },
      },
      relayChecker: {
        async check(input) {
          assert.deepEqual(Object.keys(input).sort(), ["relayId", "smtpLogin"]);
          return relayHealthy ? { ok: true } : { ok: false, code: "relay.activation_required" };
        },
      },
      brevoClient: {
        async createDomain(domain: string) {
          brevoCreates.push(domain);
          if (brevoThrows) throw new Error("Live Brevo domain creation is not configured.");
          return { domain, authenticated: false, records: recordsFor(domain) };
        },
        async authenticate(domain: string) {
          brevoAuths.push(domain);
          return { authenticated: true, verified: true };
        },
      },
      installerRunner: {
        async run(request) {
          runnerCalls.push({ mode: request.mode, input: request.input });
          if (runnerMode === "down") throw new InstallerUnavailableError();
          return installerResult(request.mode, request.input);
        },
      },
      dnsObserver: {
        async observe(domain: string) {
          if (observerMode === "down") throw new DnsObserverUnavailableError();
          const address = observerMode === "apex" ? "198.51.100.20" : "192.0.2.20";
          const records = [
            { name: domain, type: "A", value: address },
            { name: `www.${domain}`, type: "A", value: address },
          ];
          if (observerMode !== "missing-mx") records.push({ name: domain, type: "MX", value: `10 mail.${domain}` });
          return { records };
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
    relayHealthy = true;
    runnerMode = "success";
    observerMode = "match";
    brevoThrows = false;
    zones.clear();
    zoneCalls.length = 0;
    runnerCalls.length = 0;
    brevoCreates.length = 0;
    brevoAuths.length = 0;
    logChunks.length = 0;
    await resetDatabase();
  });

  after(async () => {
    await app?.close();
  });

  it("checks mailbox names, installer results, and release files without executing them", async () => {
    assert.equal(assertMailboxLocalPart("ada.lovelace"), "ada.lovelace");
    assert.equal(customerMailboxLimit("beta", 5), 4);
    assert.equal(customerMailboxLimit("plus", 20), 20);
    assert.throws(() => assertMailboxLocalPart("Ada"), (error: unknown) => error instanceof MailboxNameError && error.code === "VALIDATION");
    assert.throws(() => assertMailboxLocalPart("postmaster"), (error: unknown) => error instanceof MailboxNameError && error.code === "RESERVED_LOCAL_PART");
    assert.throws(() => assertMailboxLocalPart("bearportal-test"), (error: unknown) => error instanceof MailboxNameError && error.code === "RESERVED_LOCAL_PART");
    assert.throws(() => assertMailboxLocalPart("ada..lovelace"), (error: unknown) => error instanceof MailboxNameError && error.code === "VALIDATION");
    for (const name of ["webmail.example.com", "webmail.example.org", "webmail.example.net", "webmail.example.test", "bearmail.example.com", "bearmail.example.org", "bearmail.example.net", "bearmail.example.test"]) {
      assert.equal(isExampleWebmail(name.toUpperCase()), true);
    }
    assert.equal(isExampleWebmail(`bearmail.${DOMAIN}`), false);

    const fingerprint = {
      domain: DOMAIN,
      mailHostname: `mail.${DOMAIN}`,
      webmailHostname: `bearmail.${DOMAIN}`,
      publicIpv4: "203.0.113.20",
      provider: "namecom",
      zone: DOMAIN,
      brevoRecords: recordsFor(DOMAIN),
      relayHost: "smtp-relay.brevo.com",
    };
    assert.equal(installerFingerprint(fingerprint), installerFingerprint({ ...fingerprint, brevoRecords: recordsFor(DOMAIN) }));
    assert.notEqual(installerFingerprint(fingerprint), installerFingerprint({ ...fingerprint, publicIpv4: "203.0.113.21" }));

    const dns = { previousMx: [], published: [], minimumTtl: 300, engineDkimHost: null, engineDkimValue: null };
    assert.equal(parseInstallerResult({ status: "succeeded", exitCode: 0, retryable: true, errorCode: null, dns }), null);
    const pending = parseInstallerResult({ status: "tls_pending", exitCode: 10, retryable: true, errorCode: "TLS_PENDING", dns });
    assert.equal(pending?.retryable, true);
    assert.equal(pending?.dnsWritesAccepted, true);
    assert.equal(parseInstallerResult({ status: "tls_pending", exitCode: 10, retryable: false, errorCode: "TLS_PENDING", dns }), null);
    assert.equal(parseInstallerResult({ status: "dns_partial", exitCode: 1, retryable: false, errorCode: "DNS_PUBLISH_FAILED", dns })?.dnsWritesAccepted, false);
    assert.equal(parseInstallerResult({ status: "dns_partial", exitCode: 1, retryable: true, errorCode: "DNS_PUBLISH_FAILED", dns }), null);
    assert.equal(parseInstallerResult({ status: "failed", exitCode: 1, retryable: false, errorCode: "DNS_RECORD_CONFLICT", dns })?.retryable, false);

    const flags = {
      installerStatus: "succeeded",
      dnsWritesAccepted: true,
      brevoAuthenticated: true,
      brevoVerified: true,
      backupReported: true,
      mailVerified: true,
    };
    assert.equal(activationAllowed(flags), true);
    assert.equal(activationAllowed({ ...flags, mailVerified: false }), false);
    assert.equal(activationAllowed({ ...flags, installerStatus: "tls_pending" }), true);
    assert.equal(activationAllowed({ ...flags, installerStatus: "dns_partial" }), false);

    const published = [{ type: "MX", host: DOMAIN, value: `10 mail.${DOMAIN}`, state: "published" }];
    const baseline = [
      { name: DOMAIN, type: "A", value: "192.0.2.20" },
      { name: `www.${DOMAIN}`, type: "A", value: "192.0.2.20" },
    ];
    const missing = compareDns({ domain: DOMAIN, published, observed: baseline, baseline });
    assert.deepEqual(missing, { matches: false, mxMismatch: true, apexChanged: false });
    const moved = compareDns({
      domain: DOMAIN,
      published,
      observed: [
        { name: DOMAIN, type: "MX", value: `10 mail.${DOMAIN}` },
        { name: DOMAIN, type: "A", value: "198.51.100.20" },
        { name: `www.${DOMAIN}`, type: "A", value: "192.0.2.20" },
      ],
      baseline,
    });
    assert.equal(moved.apexChanged, true);
    assert.equal(moved.mxMismatch, false);
    const absent = compareDns({
      domain: DOMAIN,
      published,
      observed: [{ name: DOMAIN, type: "MX", value: `mail.${DOMAIN}`, priority: 10 }],
      baseline,
    });
    assert.deepEqual(absent, { matches: true, mxMismatch: false, apexChanged: false });

    assertReleaseLayout(artifactDir, releaseId);
    const tampered = mkdtempSync(join(tmpdir(), "bearportal-m4-tamper-"));
    const tamperedRelease = join(tampered, releaseId);
    writeRelease(tamperedRelease);
    writeFileSync(join(tamperedRelease, "install.sh"), "fixture install.sh\nchanged\n");
    assert.throws(() => assertReleaseLayout(tamperedRelease, releaseId), (error: unknown) => error instanceof ReleaseLayoutError && error.code === "ARTIFACT_CHECKSUM_MISMATCH");
    rmSync(join(tamperedRelease, "stalwart"));
    assert.throws(() => assertReleaseLayout(tamperedRelease, "other-id"), (error: unknown) => error instanceof ReleaseLayoutError && error.code === "ARTIFACT_MISSING");
    await assert.rejects(unavailableInstallerRunner().run({ mode: "dry_run", input: {} }), InstallerUnavailableError);
    await assert.rejects(unavailableDnsObserver().observe(DOMAIN), DnsObserverUnavailableError);

    const mainSource = readFileSync(new URL("../apps/api/src/main.ts", import.meta.url), "utf8");
    assert.equal(mainSource.includes("installerRunner"), false);
    assert.equal(mainSource.includes("brevoClient"), false);
    assert.equal(mainSource.includes("dnsObserver"), false);
    assert.equal(mainSource.includes("release:"), false);
    const installationSource = readFileSync(new URL("../apps/api/src/installation.ts", import.meta.url), "utf8");
    assert.doesNotMatch(installationSource, /\bfetch\s*\(|https?\.request\(|dns\.promises|writeZone|applyZone|publishZone/);
    assert.doesNotMatch(installationSource, /mail_verified\s*=\s*true/);
    assert.doesNotMatch(installationSource, /lifecycle_state\s*=\s*'active'/);
    assert.equal(await scalar("SELECT mailbox_limit::text FROM plans WHERE code = 'beta'"), "5");
  });

  it("does not authorize MX or call the installer for a draft", async () => {
    const customer = await registerCustomer("m4-draft", "Draft");
    const domainId = await addDomain(customer.token, DOMAIN);
    const invalid = await api(base, "/v1/deployments", {
      method: "POST",
      headers: auth(customer.token, key("deployment-bad")),
      body: JSON.stringify({ domainId, firstMailboxLocalPart: "owner", testMailConsent: false }),
    });
    expectStatus(invalid, 400);
    assert.equal(invalid.body.error.code, "VALIDATION");
    const deployment = await createDeployment(customer.token, domainId);
    const rejected = await provision(customer.token, deployment.id, 1);
    expectStatus(rejected, 422);
    assert.equal(rejected.body.error.code, "domain.unverified");
    assert.equal(rejected.body.error.retryable, false);
    const view = await api(base, `/v1/deployments/${deployment.id}`, { headers: auth(customer.token) });
    expectStatus(view, 200);
    assert.equal(view.body.mx_authorized, false);
    assert.equal(runnerCalls.length, 0);
    assert.equal(brevoCreates.length, 0);
    assert.equal(await scalar("SELECT count(*) FROM servers"), "0");
  });

  it("waits for an enrolled server without allocating a machine", async () => {
    const customer = await registerCustomer("m4-wait", "Waiting");
    assert.equal(customer.body.allocationState, "waiting_for_server");
    assert.equal(customer.body.server, null);
    const domainId = await verifyDomain(customer.token, DOMAIN);
    const deployment = await createDeployment(customer.token, domainId);
    const first = await provision(customer.token, deployment.id, 1);
    expectStatus(first, 202);
    assert.equal(first.body.state, "waiting_human");
    assert.equal(typeof first.body.jobId, "string");
    assert.equal(first.body.deploymentVersion, 2);
    const second = await provision(customer.token, deployment.id, 2);
    expectStatus(second, 202);
    assert.equal(second.body.jobId, first.body.jobId);
    assert.equal(await scalar("SELECT count(*) FROM servers"), "0");
    assert.equal(await scalar(`SELECT mx_authorized_at IS NOT NULL FROM deployments WHERE id = ${sqlText(deployment.id)}`), "t");
    assert.equal(await scalar(`SELECT count(*) FROM required_actions WHERE code = 'inventory.server_required' AND state = 'open'`), "1");
    assert.equal(runnerCalls.length, 0);
    assert.equal(brevoCreates.length, 0);
    assert.equal(await scalar("SELECT count(*) FROM host_commands"), "0");
  });

  it("fails closed when the release is unpinned", async () => {
    const host = await makeAvailable("unpinned-host");
    const customer = await registerCustomer("m4-unpinned", "Unpinned");
    assert.equal(customer.body.server.id, host.serverId);
    const domainId = await verifyDomain(customer.token, DOMAIN);
    const deployment = await createDeployment(customer.token, domainId);
    const closedSecrets = mkdtempSync(join(tmpdir(), "bearportal-m4-closed-"));
    const localRuns: unknown[] = [];
    const localBrevo: string[] = [];
    const closed = await buildServer({
    billingRequired: false,
      onboardingIntervalMs: 0,
      databaseUrl,
      secretsDir: closedSecrets,
      secretKeyHex,
      jwtPublicKeyPem: publicKeyPem,
      issuer,
      audience,
      zoneReader: { async readZone() { return { ok: false, code: "PROOF_REJECTED" }; } },
      brevoClient: {
        async createDomain(domain: string) {
          localBrevo.push(domain);
          throw new Error("Live Brevo domain creation is not configured.");
        },
        async authenticate() { return { authenticated: false, verified: false }; },
      },
      installerRunner: {
        async run() {
          localRuns.push(true);
          throw new InstallerUnavailableError();
        },
      },
    }, logStream);
    try {
      await closed.listen({ host: "127.0.0.1", port: 0 });
      const address = closed.server.address();
      if (!address || typeof address === "string") throw new Error("The closed API did not listen.");
      const closedBase = `http://127.0.0.1:${address.port}`;
      const rejected = await api(closedBase, `/v1/deployments/${deployment.id}/provision`, {
        method: "POST",
        headers: auth(customer.token, key("provision-closed")),
        body: JSON.stringify({ expectedVersion: 1 }),
      });
      expectStatus(rejected, 422);
      assert.equal(rejected.body.error.code, "release.unpinned");
      assert.equal(rejected.body.error.retryable, false);
      const expired = await api(closedBase, "/internal/mailbox-credentials/expire", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{}",
      });
      expectStatus(expired, 503);
      assert.equal(expired.body.error.code, "SCHEDULER_UNAVAILABLE");
      assert.equal(expired.body.error.retryable, true);
    } finally {
      await closed.close();
    }
    assert.equal(localRuns.length, 0);
    assert.equal(localBrevo.length, 0);
    assert.equal(runnerCalls.length, 0);
    assert.equal(brevoCreates.length, 0);
    assert.equal(await scalar(`SELECT mx_authorized_at IS NOT NULL FROM deployments WHERE id = ${sqlText(deployment.id)}`), "t");
    assert.equal(await scalar(`SELECT installer_status IS NULL FROM deployments WHERE id = ${sqlText(deployment.id)}`), "t");
    assert.equal(await scalar("SELECT count(*) FROM installer_runs"), "0");
    assert.equal(await scalar(`SELECT state FROM servers WHERE id = ${sqlText(host.serverId)}`), "reserved");
    assert.equal(await scalar(`SELECT tenant_tainted_at IS NULL FROM servers WHERE id = ${sqlText(host.serverId)}`), "t");
    assert.equal(await scalar("SELECT count(*) FROM servers"), "1");
  });

  it("keeps a Brevo or installer outage from tainting the server", async () => {
    const ready = await readyCustomer("m4-outage");
    brevoThrows = true;
    const brevoDown = await provision(ready.token, ready.deploymentId, 1);
    expectStatus(brevoDown, 503);
    assert.equal(brevoDown.body.error.code, "BREVO_UNAVAILABLE");
    assert.equal(brevoDown.body.error.retryable, true);
    assert.equal(brevoCreates.length, 1);
    assert.equal(brevoAuths.length, 0);
    assert.equal(runnerCalls.length, 0);
    assert.equal(await scalar(`SELECT state FROM servers WHERE id = ${sqlText(ready.serverId)}`), "reserved");
    assert.equal(await scalar(`SELECT tenant_tainted_at IS NULL FROM servers WHERE id = ${sqlText(ready.serverId)}`), "t");
    assert.equal(await scalar(`SELECT count(*) FROM relay_assignments WHERE organization_id = ${sqlText(ready.organizationId)} AND released_at IS NULL`), "1");

    const afterBrevo = await api(base, `/v1/deployments/${ready.deploymentId}`, { headers: auth(ready.token) });
    expectStatus(afterBrevo, 200);
    brevoThrows = false;
    brevoCreates.length = 0;
    runnerMode = "down";
    const installerDown = await provision(ready.token, ready.deploymentId, num(afterBrevo.body.version));
    expectStatus(installerDown, 503);
    assert.equal(installerDown.body.error.code, "INSTALLER_UNAVAILABLE");
    assert.equal(installerDown.body.error.retryable, true);
    assert.equal(runnerCalls.length, 1);
    assert.equal(brevoAuths.length, 0);
    assert.equal(await scalar("SELECT count(*) FROM installer_runs"), "0");
    assert.equal(await scalar(`SELECT installer_status IS NULL FROM deployments WHERE id = ${sqlText(ready.deploymentId)}`), "t");
    assert.equal(await scalar(`SELECT state FROM servers WHERE id = ${sqlText(ready.serverId)}`), "reserved");
    assert.equal(await scalar(`SELECT tenant_tainted_at IS NULL FROM servers WHERE id = ${sqlText(ready.serverId)}`), "t");
    assert.equal(await scalar("SELECT count(*) FROM host_commands"), "0");
  });

  it("stops a dry-run conflict before apply and does not taint the server", async () => {
    const ready = await readyCustomer("m4-conflict");
    runnerMode = "conflict";
    const rejected = await provision(ready.token, ready.deploymentId, 1);
    expectStatus(rejected, 422);
    assert.equal(rejected.body.error.code, "DNS_RECORD_CONFLICT");
    assert.equal(rejected.body.error.retryable, false);
    assert.equal(runnerCalls.length, 1);
    assert.equal(runnerCalls[0]?.mode, "dry_run");
    assert.equal(brevoCreates.length, 1);
    assert.equal(brevoAuths.length, 0);
    assert.equal(await scalar(`SELECT state FROM servers WHERE id = ${sqlText(ready.serverId)}`), "reserved");
    assert.equal(await scalar(`SELECT tenant_tainted_at IS NULL FROM servers WHERE id = ${sqlText(ready.serverId)}`), "t");
    assert.equal(await scalar("SELECT count(*) FROM host_commands"), "0");
    assert.equal(await scalar(`SELECT mx_authorized_at IS NOT NULL FROM deployments WHERE id = ${sqlText(ready.deploymentId)}`), "t");
    assert.equal(await scalar(`SELECT mail_verified FROM deployments WHERE id = ${sqlText(ready.deploymentId)}`), "f");
  });

  it("records a partial DNS publish without authenticating Brevo", async () => {
    const ready = await readyCustomer("m4-partial");
    runnerMode = "partial";
    const accepted = await provision(ready.token, ready.deploymentId, 1);
    expectStatus(accepted, 202);
    assert.equal(accepted.body.installerStatus, "dns_partial");
    assert.equal(accepted.body.dnsWritesAccepted, false);
    assert.equal(accepted.body.brevoAuthenticated, false);
    assert.equal(accepted.body.mailVerified, false);
    assert.equal(accepted.body.delivered, false);
    assert.equal(accepted.body.state, "queued");
    assert.deepEqual(runnerCalls.map((call) => call.mode), ["dry_run", "apply"]);
    assert.equal(brevoCreates.length, 1);
    assert.equal(brevoAuths.length, 0);
    assert.equal(await scalar(`SELECT installer_status FROM deployments WHERE id = ${sqlText(ready.deploymentId)}`), "dns_partial");
    assert.equal(await scalar(`SELECT dns_writes_accepted FROM deployments WHERE id = ${sqlText(ready.deploymentId)}`), "f");
    assert.equal(await scalar(`SELECT lifecycle_state FROM deployments WHERE id = ${sqlText(ready.deploymentId)}`), "onboarding");
    assert.equal(await scalar(`SELECT count(*) FROM host_commands WHERE command_type = 'sync_mailboxes'`), "0");
    assert.equal(await scalar(`SELECT count(*) FROM host_commands WHERE command_type = 'install_release'`), "1");
    const payload = await scalar("SELECT payload::text FROM host_commands WHERE command_type = 'install_release'");
    assert.deepEqual(JSON.parse(payload), { releaseId });
  });

  it("preserves a saved legacy webmail hostname during provisioning", async () => {
    const ready = await readyCustomer("m4-legacy-hostname");
    const legacyHostname = `webmail.${DOMAIN}`;
    await superQuery(`UPDATE deployments SET webmail_hostname = ${sqlText(legacyHostname)} WHERE id = ${sqlText(ready.deploymentId)}`);
    const accepted = await provision(ready.token, ready.deploymentId, 1);
    expectStatus(accepted, 202);
    assert.deepEqual(runnerCalls.map((call) => call.input.webmailHostname), [legacyHostname, legacyHostname]);
    assert.equal(await scalar(`SELECT webmail_hostname FROM deployments WHERE id = ${sqlText(ready.deploymentId)}`), legacyHostname);
  });

  it("keeps installer inputs free of secrets and does not activate mail", async () => {
    const ready = await readyCustomer();
    const hostIp = await scalar(`SELECT host(public_ipv4) FROM servers WHERE id = ${sqlText(ready.serverId)}`);
    const provisionKey = key("provision");
    const accepted = await provision(ready.token, ready.deploymentId, 1, provisionKey);
    expectStatus(accepted, 202);
    assert.equal(accepted.body.state, "queued");
    assert.equal(accepted.body.installerStatus, "succeeded");
    assert.equal(accepted.body.dnsWritesAccepted, true);
    assert.equal(accepted.body.brevoAuthenticated, true);
    assert.equal(accepted.body.brevoVerified, true);
    assert.equal(accepted.body.mailVerified, false);
    assert.equal(accepted.body.delivered, false);
    assert.equal(accepted.body.deploymentVersion, 2);
    assert.equal(accepted.text.includes(dnsCanary), false);
    assert.equal(accepted.text.includes(apiCanary), false);
    assert.equal(accepted.text.includes(smtpCanary), false);
    assert.deepEqual(runnerCalls.map((call) => call.mode), ["dry_run", "apply"]);
    const password = await adminPassword();
    for (const call of runnerCalls) assertInstallerInput(call.input, hostIp, password);
    assert.deepEqual(brevoCreates, [DOMAIN]);
    assert.deepEqual(brevoAuths, [DOMAIN]);
    assert.equal(JSON.stringify(zoneCalls).includes(dnsCanary), false);

    const replay = await provision(ready.token, ready.deploymentId, 1, provisionKey);
    expectStatus(replay, 202);
    assert.equal(replay.body.jobId, accepted.body.jobId);
    assert.equal(runnerCalls.length, 2);

    const again = await provision(ready.token, ready.deploymentId, 2);
    expectStatus(again, 202);
    assert.equal(again.body.jobId, accepted.body.jobId);
    assert.equal(runnerCalls.length, 2);
    assert.equal(brevoAuths.length, 1);
    const stale = await provision(ready.token, ready.deploymentId, 1);
    expectStatus(stale, 409);
    assert.equal(stale.body.error.code, "VERSION_CONFLICT");
    assert.equal(runnerCalls.length, 2);

    const view = await api(base, `/v1/deployments/${ready.deploymentId}`, { headers: auth(ready.token) });
    expectStatus(view, 200);
    assert.equal(view.body.lifecycle_state, "onboarding");
    assert.equal(view.body.onboarding_stage, "verifying_mail");
    assert.equal(view.body.installer_status, "succeeded");
    assert.equal(view.body.dns_writes_accepted, true);
    assert.equal(view.body.mail_verified, false);
    assert.equal(view.body.mx_authorized, true);
    assert.equal(view.body.version, 2);
    assert.equal(view.body.previous_mx[0].target, "mx.old-mail.alpha-bearportal.com");
    assert.equal(view.body.observed_ip, hostIp);
    assert.equal(JSON.stringify(view.body).includes("admin_secret"), false);
    assert.ok(view.body.requiredActions.some((action: { code: string }) => action.code === "mail.verification_required"));

    const plans = await api(base, `/v1/deployments/${ready.deploymentId}/dns-plans`, { headers: auth(ready.token) });
    expectStatus(plans, 200);
    assert.equal(plans.body.approvalGate, false);
    assert.equal(plans.body.previousMx[0].target, "mx.old-mail.alpha-bearportal.com");
    assert.equal(plans.body.propagation, "unchecked");
    assert.equal(plans.body.installerStatus, "succeeded");

    const mailboxes = await api(base, `/v1/deployments/${ready.deploymentId}/mailboxes`, { headers: auth(ready.token) });
    expectStatus(mailboxes, 200);
    assert.equal(mailboxes.body.mailboxes.length, 4);
    assert.ok(mailboxes.body.mailboxes.every((mailbox: { loginEnabled: boolean }) => mailbox.loginEnabled === false));
    const owner = mailboxes.body.mailboxes.find((mailbox: { localPart: string }) => mailbox.localPart === "owner");
    assert.equal(owner.quotaBytes, QUOTA);
    assert.equal(owner.kind, "customer");

    const backup = await api(base, `/v1/admin/deployments/${ready.deploymentId}/backup-report`, {
      method: "POST",
      headers: auth(await adminToken(), key("backup")),
      body: JSON.stringify({ evidenceRef: "ops-backup-m4", expectedVersion: num(view.body.version) }),
    });
    expectStatus(backup, 200);
    assert.equal(backup.body.activated, false);
    assert.equal(backup.body.reason, "mail.verification_required");
    assert.equal(backup.body.lifecycleState, "onboarding");
    assert.equal(await scalar(`SELECT lifecycle_state || ':' || mail_verified::text FROM deployments WHERE id = ${sqlText(ready.deploymentId)}`), "onboarding:false");
    assert.equal(await scalar(`SELECT state FROM backups WHERE deployment_id = ${sqlText(ready.deploymentId)}`), "recorded");

    const recordsBefore = await scalar(`SELECT brevo_records::text FROM deployments WHERE id = ${sqlText(ready.deploymentId)}`);
    const mailboxCount = await scalar(`SELECT count(*) FROM mailboxes WHERE deployment_id = ${sqlText(ready.deploymentId)}`);
    const current = await serverView(ready.serverId);
    const movedIp = nextIp();
    const moved = await api(base, `/v1/admin/servers/${ready.serverId}/ip-change`, {
      method: "POST",
      headers: auth(await adminToken(), key("ip-change")),
      body: JSON.stringify({ publicIpv4: movedIp, reason: "Provider renumbered", expectedVersion: num(current.version) }),
    });
    expectStatus(moved, 200);
    assert.equal(moved.body.installerStarted, true);
    assert.equal(moved.body.publicIpv4, movedIp);
    assert.equal(await scalar("SELECT count(*) FROM servers"), "1");
    assert.equal(runnerCalls.length, 4);
    assert.deepEqual(runnerCalls.slice(2).map((call) => call.mode), ["dry_run", "apply"]);
    for (const call of runnerCalls.slice(2)) assertInstallerInput(call.input, movedIp, password);
    assert.equal(brevoCreates.length, 1);
    assert.equal(brevoAuths.length, 1);
    assert.equal(await scalar(`SELECT count(*) FROM mailboxes WHERE deployment_id = ${sqlText(ready.deploymentId)}`), mailboxCount);
    assert.equal(await scalar(`SELECT brevo_records::text FROM deployments WHERE id = ${sqlText(ready.deploymentId)}`), recordsBefore);
    assert.equal(await scalar(`SELECT host(observed_ip) FROM deployments WHERE id = ${sqlText(ready.deploymentId)}`), movedIp);
    assert.equal(await scalar(`SELECT mail_verified::text FROM deployments WHERE id = ${sqlText(ready.deploymentId)}`), "false");
    assert.equal(
      await scalar(`SELECT (checkpoint->>'installerStarted') || ':' || (checkpoint->>'ipProof') FROM jobs WHERE id = ${sqlText(moved.body.jobId)}`),
      "true:not_performed",
    );
    assert.equal(await scalar(`SELECT state FROM servers WHERE id = ${sqlText(ready.serverId)}`), "assigned");
    assert.equal(await scalar(`SELECT tenant_tainted_at IS NOT NULL FROM servers WHERE id = ${sqlText(ready.serverId)}`), "t");
    assert.equal(await scalar(`SELECT deployment_id::text FROM server_assignments WHERE server_id = ${sqlText(ready.serverId)} AND released_at IS NULL`), ready.deploymentId);
    const commands = await superQuery("SELECT command_type, payload::text FROM host_commands ORDER BY command_type");
    assert.deepEqual(commands.map((row) => row[0]), ["install_release", "sync_mailboxes"]);
    assert.deepEqual(JSON.parse(commands[0]?.[1] ?? "{}"), { releaseId });
    assert.deepEqual(JSON.parse(commands[1]?.[1] ?? "{}"), {});
    assert.equal(await scalar("SELECT state FROM jobs WHERE kind = 'install_release'"), "queued");
    assert.equal(await scalar("SELECT checkpoint->>'ipProof' FROM jobs WHERE kind = 'install_release'"), "not_performed");
    assert.equal(await scalar(`SELECT count(*) FROM relay_assignments WHERE released_at IS NULL`), "1");

    const stored = await storedText();
    for (const secret of [dnsCanary, apiCanary, smtpCanary, password]) {
      assert.equal(stored.includes(secret), false);
      assert.equal(logs().includes(secret), false);
      assert.equal(ciphertextHas(secret), false);
    }
  });

  it("caps beta mailboxes at four and keeps login disabled", async () => {
    const customer = await registerCustomer("m4-boxes", "Boxes");
    const domainId = await verifyDomain(customer.token, DOMAIN);
    const deployment = await createDeployment(customer.token, domainId);
    const over = await api(base, `/v1/deployments/${deployment.id}/mailboxes`, {
      method: "POST",
      headers: auth(customer.token, key("quota")),
      body: JSON.stringify({ localPart: "ada", quotaBytes: QUOTA + 1 }),
    });
    expectStatus(over, 422);
    assert.equal(over.body.error.code, "QUOTA_EXCEEDED");
    const upper = await api(base, `/v1/deployments/${deployment.id}/mailboxes`, {
      method: "POST",
      headers: auth(customer.token, key("upper")),
      body: JSON.stringify({ localPart: "Ada" }),
    });
    expectStatus(upper, 400);
    assert.equal(upper.body.error.code, "VALIDATION");
    const reserved = await api(base, `/v1/deployments/${deployment.id}/mailboxes`, {
      method: "POST",
      headers: auth(customer.token, key("reserved")),
      body: JSON.stringify({ localPart: "postmaster" }),
    });
    expectStatus(reserved, 422);
    assert.equal(reserved.body.error.code, "RESERVED_LOCAL_PART");
    for (const localPart of ["byron", "grace", "ada.lovelace"]) {
      const created = await api(base, `/v1/deployments/${deployment.id}/mailboxes`, {
        method: "POST",
        headers: auth(customer.token, key(localPart)),
        body: JSON.stringify({ localPart }),
      });
      expectStatus(created, 202);
      assert.equal(created.body.applied, false);
      assert.equal(created.body.state, "queued");
    }
    const limited = await api(base, `/v1/deployments/${deployment.id}/mailboxes`, {
      method: "POST",
      headers: auth(customer.token, key("helen")),
      body: JSON.stringify({ localPart: "helen" }),
    });
    expectStatus(limited, 422);
    assert.equal(limited.body.error.code, "PLAN_LIMIT");
    assert.equal(await scalar(`SELECT count(*) FROM mailboxes WHERE deployment_id = ${sqlText(deployment.id)} AND kind = 'customer'`), "4");
    assert.equal(await scalar(`SELECT count(*) FROM mailboxes WHERE deployment_id = ${sqlText(deployment.id)}`), "7");
    assert.equal(await scalar(`SELECT count(*) FROM mailboxes WHERE deployment_id = ${sqlText(deployment.id)} AND kind = 'system_alias' AND quota_bytes IS NULL AND credential_reset_required = false`), "2");
    assert.equal(await scalar("SELECT mailbox_limit::text FROM plans WHERE code = 'beta'"), "5");

    const denied = await api(base, `/v1/mailboxes/${deployment.mailboxId}`, {
      method: "PATCH",
      headers: auth(customer.token, key("login-on")),
      body: JSON.stringify({ loginEnabled: true, expectedVersion: 1 }),
    });
    expectStatus(denied, 422);
    assert.equal(denied.body.error.code, "CREDENTIAL_REQUIRED");
    const disabled = await api(base, `/v1/mailboxes/${deployment.mailboxId}`, {
      method: "PATCH",
      headers: auth(customer.token, key("login-off")),
      body: JSON.stringify({ loginEnabled: false, sendEnabled: false, expectedVersion: 1 }),
    });
    expectStatus(disabled, 202);
    assert.equal(disabled.body.applied, false);
    assert.equal(disabled.body.loginEnabled, false);
    const listed = await api(base, `/v1/deployments/${deployment.id}/mailboxes`, { headers: auth(customer.token) });
    expectStatus(listed, 200);
    const owner = listed.body.mailboxes.find((mailbox: { id: string }) => mailbox.id === deployment.mailboxId);
    assert.equal(owner.loginEnabled, false);
    assert.equal(await scalar(`SELECT count(*) FROM mailboxes WHERE login_enabled`), "0");
    assert.equal(runnerCalls.length, 0);
  });

  it("stores a mailbox password only in a sealed file and expires it", async () => {
    const host = await makeAvailable("credential-host");
    const customer = await registerCustomer("m4-secret", "Secret");
    assert.equal(customer.body.server.id, host.serverId);
    const domainId = await verifyDomain(customer.token, DOMAIN);
    const deployment = await createDeployment(customer.token, domainId);
    const listed = await api(base, `/v1/deployments/${deployment.id}/mailboxes`, { headers: auth(customer.token) });
    expectStatus(listed, 200);
    const postmaster = listed.body.mailboxes.find((mailbox: { localPart: string }) => mailbox.localPart === "postmaster");
    const system = await api(base, `/v1/mailboxes/${postmaster.id}/credential`, {
      method: "POST",
      headers: auth(customer.token, key("system-password")),
      body: JSON.stringify({ newPassword: "Mailbox-Password-Canary-0" }),
    });
    expectStatus(system, 422);
    assert.equal(system.body.error.code, "RESERVED_LOCAL_PART");

    const password = "Mailbox-Password-Canary-1";
    const credentialKey = key("credential");
    const first = await api(base, `/v1/mailboxes/${deployment.mailboxId}/credential`, {
      method: "POST",
      headers: auth(customer.token, credentialKey),
      body: JSON.stringify({ newPassword: password }),
    });
    expectStatus(first, 202);
    assert.equal(first.body.state, "queued");
    assert.equal(first.body.credentialApplied, false);
    assert.equal(first.text.includes(password), false);
    const replay = await api(base, `/v1/mailboxes/${deployment.mailboxId}/credential`, {
      method: "POST",
      headers: auth(customer.token, credentialKey),
      body: JSON.stringify({ newPassword: password }),
    });
    expectStatus(replay, 202);
    assert.equal(replay.body.jobId, first.body.jobId);
    assert.equal(await scalar("SELECT count(*) FROM secret_refs WHERE purpose = 'mailbox-credential'"), "1");
    const conflict = await api(base, `/v1/mailboxes/${deployment.mailboxId}/credential`, {
      method: "POST",
      headers: auth(customer.token, credentialKey),
      body: JSON.stringify({ newPassword: "Mailbox-Password-Canary-2" }),
    });
    expectStatus(conflict, 409);
    assert.equal(conflict.body.error.code, "IDEMPOTENCY_CONFLICT");
    assert.equal(await scalar("SELECT count(*) FROM secret_refs WHERE purpose = 'mailbox-credential'"), "1");

    let latest = password;
    for (let index = 2; index <= 10; index += 1) {
      latest = `Mailbox-Password-Canary-${index}`;
      const created = await api(base, `/v1/mailboxes/${deployment.mailboxId}/credential`, {
        method: "POST",
        headers: auth(customer.token, key(`credential-${index}`)),
        body: JSON.stringify({ newPassword: latest }),
      });
      expectStatus(created, 202);
      assert.equal(created.text.includes(latest), false);
    }
    const fileName = await scalar("SELECT file_name FROM secret_refs WHERE purpose = 'mailbox-credential' AND state = 'active' ORDER BY created_at DESC LIMIT 1");
    const opened = openSecret(readFileSync(join(secretsDir, fileName)), loadSecretKey(secretKeyHex));
    assert.equal(JSON.parse(opened).password, latest);
    assert.equal(existsSync(join(secretsDir, fileName)), true);
    const version = await scalar(`SELECT version::text FROM mailboxes WHERE id = ${sqlText(deployment.mailboxId)}`);
    const limited = await api(base, `/v1/mailboxes/${deployment.mailboxId}/credential`, {
      method: "POST",
      headers: auth(customer.token, key("credential-11")),
      body: JSON.stringify({ newPassword: "Mailbox-Password-Canary-11" }),
    });
    expectStatus(limited, 429);
    assert.equal(limited.body.error.code, "RATE_LIMITED");
    assert.equal(limited.body.error.retryable, true);
    assert.equal(await scalar(`SELECT version::text FROM mailboxes WHERE id = ${sqlText(deployment.mailboxId)}`), version);
    assert.equal(await scalar("SELECT count(*) FROM secret_refs WHERE purpose = 'mailbox-credential'"), "10");
    assert.equal(await scalar(`SELECT login_enabled::text FROM mailboxes WHERE id = ${sqlText(deployment.mailboxId)}`), "false");
    const command = await scalar("SELECT payload::text FROM host_commands WHERE command_type = 'set_mailbox_credential' LIMIT 1");
    assert.equal(command, "{}");
    assert.equal(await scalar("SELECT count(*) FROM jobs WHERE kind = 'set_mailbox_credential' AND checkpoint->>'outcome' = 'pending'"), "10");

    const wrong = await api(base, "/internal/mailbox-credentials/expire", {
      method: "POST",
      headers: { "content-type": "application/json", "x-bearportal-scheduler": "wrong-token" },
      body: "{}",
    });
    expectStatus(wrong, 401);
    assert.equal(wrong.body.error.code, "UNAUTHENTICATED");
    await superQuery(`UPDATE mailboxes SET credential_expires_at = now() - interval '1 minute' WHERE id = ${sqlText(deployment.mailboxId)}`);
    const expired = await api(base, "/internal/mailbox-credentials/expire", {
      method: "POST",
      headers: { "content-type": "application/json", "x-bearportal-scheduler": schedulerToken },
      body: "{}",
    });
    expectStatus(expired, 200);
    assert.equal(expired.body.expired, 1);
    assert.equal(existsSync(join(secretsDir, fileName)), false);
    assert.equal(await scalar(`SELECT state FROM secret_refs WHERE file_name = ${sqlText(fileName)}`), "retired");
    assert.equal(await scalar(`SELECT credential_secret_ref IS NULL AND login_enabled = false FROM mailboxes WHERE id = ${sqlText(deployment.mailboxId)}`), "t");

    await superQuery("UPDATE jobs SET lease_expires_at = now() - interval '1 minute' WHERE kind = 'set_mailbox_credential' AND state = 'queued'");
    const leases = await api(base, "/v1/admin/jobs/expire-leases", {
      method: "POST",
      headers: auth(await adminToken(), key("expire-leases")),
      body: "{}",
    });
    expectStatus(leases, 200);
    assert.equal(leases.body.expiredLeases, 10);
    assert.equal(await scalar("SELECT count(*) FROM jobs WHERE kind = 'set_mailbox_credential' AND state = 'failed' AND error_code = 'LEASE_EXPIRED' AND checkpoint->>'outcome' = 'outcome_unknown'"), "10");

    const stored = await storedText();
    for (let index = 0; index <= 11; index += 1) {
      const secret = `Mailbox-Password-Canary-${index}`;
      assert.equal(stored.includes(secret), false);
      assert.equal(logs().includes(secret), false);
      assert.equal(ciphertextHas(secret), false);
    }
    assert.equal(ciphertextHas(dnsCanary), false);
    assert.equal(await scalar(`SELECT tenant_tainted_at IS NOT NULL FROM servers WHERE id = ${sqlText(host.serverId)}`), "t");
    assert.equal(runnerCalls.length, 0);
  });

  it("compares observed DNS without writing records", async () => {
    const ready = await readyCustomer("m4-recheck");
    const accepted = await provision(ready.token, ready.deploymentId, 1);
    expectStatus(accepted, 202);
    const before = await scalar(`SELECT published_records::text FROM deployments WHERE id = ${sqlText(ready.deploymentId)}`);
    async function recheck(idempotencyKey: string): Promise<ApiResult> {
      return api(base, `/v1/deployments/${ready.deploymentId}/dns-recheck`, {
        method: "POST",
        headers: auth(ready.token, idempotencyKey),
        body: "{}",
      });
    }
    observerMode = "match";
    const matched = await recheck(key("recheck-match"));
    expectStatus(matched, 200);
    assert.equal(matched.body.matches, true);
    assert.equal(matched.body.mxMismatch, false);
    assert.equal(matched.body.apexChanged, false);
    assert.equal(matched.body.writesDns, false);
    assert.equal(matched.body.requiredActionId, null);

    observerMode = "down";
    const down = await recheck(key("recheck-down"));
    expectStatus(down, 503);
    assert.equal(down.body.error.code, "DNS_OBSERVER_UNAVAILABLE");
    assert.equal(down.body.error.retryable, true);

    observerMode = "missing-mx";
    const missingKey = key("recheck-missing");
    const missing = await recheck(missingKey);
    expectStatus(missing, 200);
    assert.equal(missing.body.matches, false);
    assert.equal(missing.body.mxMismatch, true);
    assert.equal(missing.body.apexChanged, false);
    const replay = await recheck(missingKey);
    expectStatus(replay, 200);
    assert.equal(await scalar(`SELECT count(*) FROM dns_observations WHERE deployment_id = ${sqlText(ready.deploymentId)}`), "2");

    observerMode = "apex";
    const apex = await recheck(key("recheck-apex"));
    expectStatus(apex, 200);
    assert.equal(apex.body.matches, false);
    assert.equal(apex.body.mxMismatch, false);
    assert.equal(apex.body.apexChanged, true);
    assert.equal(typeof apex.body.requiredActionId, "string");
    assert.equal(await scalar("SELECT count(*) FROM required_actions WHERE code = 'dns.apex_changed' AND state = 'open'"), "1");

    observerMode = "missing-mx";
    for (let index = 0; index < 8; index += 1) {
      const extra = await recheck(key(`recheck-extra-${index}`));
      expectStatus(extra, 200);
    }
    const limited = await recheck(key("recheck-limit"));
    expectStatus(limited, 429);
    assert.equal(limited.body.error.code, "RATE_LIMITED");
    assert.equal(limited.body.error.retryable, true);
    assert.equal(await scalar(`SELECT count(*) FROM dns_observations WHERE deployment_id = ${sqlText(ready.deploymentId)}`), "11");
    assert.equal(await scalar(`SELECT published_records::text FROM deployments WHERE id = ${sqlText(ready.deploymentId)}`), before);
    assert.equal(runnerCalls.length, 2);
    assert.equal(logs().includes(dnsCanary), false);
  });

  it("hides a deployment from another organization", async () => {
    const ready = await readyCustomer("m4-owner-iso");
    const accepted = await provision(ready.token, ready.deploymentId, 1);
    expectStatus(accepted, 202);
    const other = await registerCustomer("m4-other", "Other");
    const paths = [
      `/v1/deployments/${ready.deploymentId}`,
      `/v1/deployments/${ready.deploymentId}/dns-plans`,
      `/v1/deployments/${ready.deploymentId}/mailboxes`,
    ];
    for (const path of paths) {
      const hidden = await api(base, path, { headers: auth(other.token) });
      expectStatus(hidden, 404);
    }
    const hiddenProvision = await provision(other.token, ready.deploymentId, 2);
    expectStatus(hiddenProvision, 404);
    const hiddenRecheck = await api(base, `/v1/deployments/${ready.deploymentId}/dns-recheck`, {
      method: "POST",
      headers: auth(other.token, key("recheck-other")),
      body: "{}",
    });
    expectStatus(hiddenRecheck, 404);
    const hiddenMailbox = await api(base, `/v1/mailboxes/${ready.mailboxId}`, {
      method: "PATCH",
      headers: auth(other.token, key("patch-other")),
      body: JSON.stringify({ loginEnabled: false, expectedVersion: 1 }),
    });
    expectStatus(hiddenMailbox, 404);
    const hiddenCredential = await api(base, `/v1/mailboxes/${ready.mailboxId}/credential`, {
      method: "POST",
      headers: auth(other.token, key("credential-other")),
      body: JSON.stringify({ newPassword: "Mailbox-Password-Canary-9" }),
    });
    expectStatus(hiddenCredential, 404);
    assert.equal(await scalar("SELECT count(*) FROM secret_refs WHERE purpose = 'mailbox-credential'"), "0");
    assert.equal(runnerCalls.length, 2);
    const owner = await api(base, `/v1/deployments/${ready.deploymentId}`, { headers: auth(ready.token) });
    expectStatus(owner, 200);
    assert.equal(owner.body.mail_verified, false);
    assert.equal(ciphertextHas("Mailbox-Password-Canary-9"), false);
    assert.equal(logs().includes("Mailbox-Password-Canary-9"), false);
  });

  it("rejects a credential when no server is assigned", async () => {
    const customer = await registerCustomer("m4-noserver", "No Server");
    const domainId = await verifyDomain(customer.token, DOMAIN);
    const deployment = await createDeployment(customer.token, domainId);
    const rejected = await api(base, `/v1/mailboxes/${deployment.mailboxId}/credential`, {
      method: "POST",
      headers: auth(customer.token, key("credential-wait")),
      body: JSON.stringify({ newPassword: "Mailbox-Password-Canary-4" }),
    });
    expectStatus(rejected, 422);
    assert.equal(rejected.body.error.code, "inventory.server_required");
    assert.equal(rejected.text.includes("Mailbox-Password-Canary-4"), false);
    assert.equal(await scalar("SELECT count(*) FROM secret_refs WHERE purpose = 'mailbox-credential'"), "0");
    assert.equal(ciphertextHas("Mailbox-Password-Canary-4"), false);
    assert.equal(logs().includes("Mailbox-Password-Canary-4"), false);
  });
});
