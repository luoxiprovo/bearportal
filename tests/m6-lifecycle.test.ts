import { integrationDatabases, queryTestDatabase } from "./helpers/database.ts";
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, randomUUID, sign as cryptoSign, type KeyObject } from "node:crypto";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";
import { after, before, beforeEach, describe, it } from "node:test";
import { exportPKCS8, exportSPKI, generateKeyPair, SignJWT, type CryptoKey } from "jose";
import { bootstrapAdmin, buildServer, type ApiDeps } from "../apps/api/src/server.ts";
import { deriveSetup, renderBrevoAccountResult, renderBrevoDomainResult, renderCustomerPortal, renderHome, renderOperatorPortal } from "../apps/api/src/portal.ts";
import { BrevoRequestError } from "../packages/providers/brevo/src/index.ts";
import { migrate } from "../packages/db/src/migrate.ts";
import {
  BACKUP_FRESH_MS,
  backupFreshness,
  cancellationSchedule,
  cancellationTiming,
  classifyBackupReport,
  cleanupDecision,
  evidenceReferenceAccepted,
  fencingAllowsPromotion,
  upgradePolicy,
} from "../packages/operations/src/lifecycle.ts";
import type { ZoneReadResult } from "../packages/providers/dns/src/reader.ts";
import type { HostReport } from "../packages/servers/src/readiness.ts";
import { heartbeatMessage } from "../packages/servers/src/signature.ts";

const { databaseUrl, migrationUrl, superDatabaseUrl } = integrationDatabases();
const issuer = "https://test.bearportal.local";
const audience = "bearportal-test";
const secretKeyHex = "ab".repeat(32);
const adminEmail = "admin@recovery-bearportal.com";
const schedulerToken = "scheduler-test-token";
const DOMAIN = "mail-m6.alpha-bearportal.com";
const DOMAIN_B = "mail-m6b.beta-bearportal.com";
const HOUR = 60 * 60 * 1000;
const DAY = 24 * HOUR;

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
type Customer = { token: string; organizationId: string; deploymentId: string; domainId: string };

const logChunks: Buffer[] = [];
const logStream = new Writable({
  write(chunk, _encoding, callback) {
    logChunks.push(Buffer.from(chunk));
    callback();
  },
});

const zones = new Map<string, ZoneReadResult>();
let privateKey: CryptoKey;
let app: Awaited<ReturnType<typeof buildServer>> | undefined;
let operatorBrevoMode: "pending" | "verified" | "incomplete" = "pending";
let brevoCalls = 0;
let base = "";
let step = 0;
let ipHost = 10;

function logs(): string {
  return Buffer.concat(logChunks).toString("utf8");
}

function key(name: string): string {
  step += 1;
  return `${name}-${step}-${randomUUID()}`;
}

function nextIp(): string {
  ipHost += 1;
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
  let body: Record<string, any> = {};
  if (text) body = JSON.parse(text) as Record<string, any>;
  return { status: response.status, text, body, headers: response.headers };
}

async function page(path: string, token?: string): Promise<{ status: number; text: string }> {
  const headers = new Headers();
  if (token) headers.set("authorization", `Bearer ${token}`);
  const response = await fetch(`${base}${path}`, { headers });
  return { status: response.status, text: await response.text() };
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

function scheduler(): Record<string, string> {
  return { "content-type": "application/json", "x-bearportal-scheduler": schedulerToken };
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

async function invite(email: string): Promise<string> {
  const response = await api(base, "/v1/admin/invitations", {
    method: "POST",
    headers: auth(await adminToken(), key("invite")),
    body: JSON.stringify({ boundEmail: email, expiresInHours: 48 }),
  });
  expectStatus(response, 201);
  return response.body.invitationToken as string;
}

async function registerCustomer(local: string, name: string): Promise<{ token: string; organizationId: string }> {
  const email = `${local}@recovery-bearportal.com`;
  const invitation = await invite(email);
  const token = await tokenFor(local, email);
  const created = await api(base, "/v1/organizations", {
    method: "POST",
    headers: auth(token, key(`org-${local}`)),
    body: JSON.stringify({ name, invitationToken: invitation }),
  });
  expectStatus(created, 201);
  return { token, organizationId: created.body.id as string };
}

async function verifyDomain(token: string, domain: string): Promise<string> {
  zones.set(domain, goodZone(domain));
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
      credentials: { username: "portal-namecom", token: "portal-dns-token" },
    }),
  });
  expectStatus(dns, 201);
  const verified = await api(base, `/v1/domains/${created.body.id}/verify`, {
    method: "POST",
    headers: auth(token, key("verify")),
    body: "{}",
  });
  expectStatus(verified, 200);
  assert.equal(verified.body.state, "verified");
  return created.body.id as string;
}

async function createDeployment(token: string, domainId: string): Promise<string> {
  const created = await api(base, "/v1/deployments", {
    method: "POST",
    headers: auth(token, key("deployment")),
    body: JSON.stringify({ domainId, firstMailboxLocalPart: "owner", testMailConsent: true }),
  });
  expectStatus(created, 201);
  return created.body.id as string;
}

async function customerWithDeployment(local: string, domain: string): Promise<Customer> {
  const customer = await registerCustomer(local, "M6 Owner");
  const domainId = await verifyDomain(customer.token, domain);
  const deploymentId = await createDeployment(customer.token, domainId);
  return { ...customer, domainId, deploymentId };
}

async function deploymentVersion(token: string, deploymentId: string): Promise<number> {
  const view = await api(base, `/v1/deployments/${deploymentId}`, { headers: auth(token) });
  expectStatus(view, 200);
  return num(view.body.version);
}

async function serverVersion(serverId: string): Promise<number> {
  const view = await api(base, `/v1/admin/servers/${serverId}`, { headers: auth(await adminToken()) });
  expectStatus(view, 200);
  return num(view.body.version);
}

async function createServer(label: string): Promise<{ serverId: string; version: number }> {
  const created = await api(base, "/v1/admin/servers", {
    method: "POST",
    headers: auth(await adminToken(), key("server")),
    body: JSON.stringify({
      label,
      publicIpv4: nextIp(),
      profileCode: "e2-micro",
      operatorContact: "ops@recovery-bearportal.com",
      preparationAttestations: attestations,
    }),
  });
  expectStatus(created, 201);
  return { serverId: created.body.serverId as string, version: num(created.body.version) };
}

async function enrollReady(label: string): Promise<{ serverId: string; device: Device; authEpoch: number }> {
  const created = await createServer(label);
  const enrollment = await api(base, `/v1/admin/servers/${created.serverId}/enrollment`, {
    method: "POST",
    headers: auth(await adminToken(), key("enrollment")),
    body: "{}",
  });
  expectStatus(enrollment, 201);
  const device = deviceKey();
  const enrolled = await api(base, "/internal/hosts/enroll", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ serverId: created.serverId, token: enrollment.body.enrollmentToken, publicKey: device.publicKey }),
  });
  expectStatus(enrolled, 200);
  let view = await api(base, `/v1/admin/servers/${created.serverId}`, { headers: auth(await adminToken()) });
  expectStatus(view, 200);
  const confirmed = await api(base, `/v1/admin/servers/${created.serverId}/confirm-identity`, {
    method: "POST",
    headers: auth(await adminToken(), key("confirm")),
    body: JSON.stringify({ fingerprint: device.fingerprint, expectedVersion: num(view.body.version) }),
  });
  expectStatus(confirmed, 200);
  view = await api(base, `/v1/admin/servers/${created.serverId}`, { headers: auth(await adminToken()) });
  expectStatus(view, 200);
  const observedAt = new Date().toISOString();
  const signed = { serverId: created.serverId, authEpoch: num(view.body.auth_epoch), observedAt, readiness: readyReport };
  const heart = await api(base, "/internal/hosts/heartbeat", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ ...signed, publicKey: device.publicKey, signature: signHeartbeat(device.privateKey, signed) }),
  });
  expectStatus(heart, 200);
  return { serverId: created.serverId, device, authEpoch: signed.authEpoch };
}

async function assignServer(label: string): Promise<{ serverId: string; publicIpv4: string }> {
  const host = await enrollReady(label);
  const version = await serverVersion(host.serverId);
  const validated = await api(base, `/v1/admin/servers/${host.serverId}/validate`, {
    method: "POST",
    headers: auth(await adminToken(), key("validate")),
    body: JSON.stringify({ expectedVersion: version }),
  });
  expectStatus(validated, 200);
  assert.equal(validated.body.state, "reserved");
  const publicIpv4 = await scalar(`SELECT host(public_ipv4) FROM servers WHERE id = ${sqlText(host.serverId)}`);
  return { serverId: host.serverId, publicIpv4 };
}

async function reportBackup(token: string, deploymentId: string, extra: Record<string, unknown>): Promise<ApiResult> {
  const version = await deploymentVersion(token, deploymentId);
  return api(base, `/v1/admin/deployments/${deploymentId}/backup-report`, {
    method: "POST",
    headers: auth(await adminToken(), key("backup")),
    body: JSON.stringify({ expectedVersion: version, ...extra }),
  });
}

async function approve(token: string, approvalId: string, planHash: string): Promise<void> {
  const decision = await api(base, `/v1/approvals/${approvalId}/decision`, {
    method: "POST",
    headers: auth(token, key("approve")),
    body: JSON.stringify({ decision: "approve", planHash, expectedVersion: 1 }),
  });
  expectStatus(decision, 200);
  assert.equal(decision.body.executed, false);
  assert.equal(decision.body.mailVerified, false);
}

async function executeCancellation(scheduleId: string): Promise<ApiResult> {
  return api(base, "/internal/cancellation/execute", {
    method: "POST",
    headers: scheduler(),
    body: JSON.stringify({ scheduleId }),
  });
}

function assertHonestPage(html: string): void {
  assert.equal(html.includes("Create VM"), false);
  assert.ok(html.includes('name="viewport"'));
  if (process.env.BEARPORTAL_ENV !== "production") assert.ok(html.includes("Development preview"));
}

describe("M6 lifecycle policy", () => {
  it("classifies backup evidence without treating a reference as restore proof", () => {
    assert.deepEqual(classifyBackupReport({}), { ok: true, state: "recorded", restoreVerified: false });
    assert.equal(classifyBackupReport({ outcome: "reported_complete" }).ok, false);
    assert.equal(classifyBackupReport({ outcome: "reported_complete", consistency: "failed" }).ok, false);
    assert.deepEqual(classifyBackupReport({ outcome: "reported_complete", consistency: "consistent" }), {
      ok: true,
      state: "reported_complete",
      restoreVerified: false,
    });
    assert.equal(classifyBackupReport({ outcome: "restore_verified" }).ok, false);
    assert.equal(classifyBackupReport({ outcome: "restore_verified", restoreAttestation: "short" }).ok, false);
    const attested = classifyBackupReport({ outcome: "restore_verified", restoreAttestation: "operator checked the mailbox" });
    assert.deepEqual(attested, { ok: true, state: "restore_verified", restoreVerified: true });
    assert.equal(evidenceReferenceAccepted("ops-backup-m6"), true);
    assert.equal(evidenceReferenceAccepted("http://ops.alpha-bearportal.com/snap"), false);
    assert.equal(evidenceReferenceAccepted("ops <script>"), false);
    const nowMs = Date.parse("2026-11-02T00:00:00.000Z");
    assert.equal(backupFreshness(null, nowMs), "missing");
    assert.equal(backupFreshness(new Date(nowMs - BACKUP_FRESH_MS), nowMs), "fresh");
    assert.equal(backupFreshness(new Date(nowMs - BACKUP_FRESH_MS - 1), nowMs), "stale");
    assert.equal(BACKUP_FRESH_MS, 26 * HOUR);
  });

  it("keeps upgrade, fencing, cancellation, and cleanup from inventing execution", () => {
    const start = Date.parse("2026-11-02T00:00:00.000Z");
    const schedule = cancellationSchedule(start);
    assert.equal(schedule.executeAt.getTime() - start, 7 * DAY);
    assert.equal(schedule.windowEndsAt.getTime() - schedule.executeAt.getTime(), DAY);
    assert.equal(cancellationTiming({ nowMs: start, executeAt: schedule.executeAt, windowEndsAt: schedule.windowEndsAt, state: "scheduled" }), "early");
    assert.equal(cancellationTiming({ nowMs: schedule.executeAt.getTime(), executeAt: schedule.executeAt, windowEndsAt: schedule.windowEndsAt, state: "scheduled" }), "due");
    assert.equal(cancellationTiming({ nowMs: schedule.windowEndsAt.getTime() + 1, executeAt: schedule.executeAt, windowEndsAt: schedule.windowEndsAt, state: "scheduled" }), "stale");
    assert.equal(cancellationTiming({ nowMs: schedule.executeAt.getTime(), executeAt: schedule.executeAt, windowEndsAt: schedule.windowEndsAt, state: "revoked" }), "closed");
    assert.equal(fencingAllowsPromotion("missing_heartbeat"), false);
    assert.equal(fencingAllowsPromotion("application_stop"), true);
    assert.equal(fencingAllowsPromotion("external_isolation"), true);
    assert.deepEqual(upgradePolicy({ compatible: true, irreversible: false, newMailAccepted: false, checksFailed: false, freshBackup: false }), {
      state: "blocked",
      rollbackPolicy: "blocked",
      dataRollback: false,
      binariesExecuted: false,
      executed: false,
    });
    assert.equal(upgradePolicy({ compatible: false, irreversible: true, newMailAccepted: true, checksFailed: false, freshBackup: true }).state, "preserve_required");
    assert.equal(upgradePolicy({ compatible: true, irreversible: false, newMailAccepted: false, checksFailed: true, freshBackup: true }).state, "rollback_required");
    assert.equal(upgradePolicy({ compatible: true, irreversible: false, newMailAccepted: false, checksFailed: false, freshBackup: true }).binariesExecuted, false);
    const stopped = new Date(start);
    assert.equal(cleanupDecision({ serviceStoppedAt: null, dataRemovedAt: new Date(start), nowMs: start, backupRetentionSatisfied: true, credentialsRevoked: true }).ok, false);
    assert.equal(cleanupDecision({ serviceStoppedAt: stopped, dataRemovedAt: new Date(start + 8 * DAY), nowMs: start + 8 * DAY, backupRetentionSatisfied: false, credentialsRevoked: true }).ok, false);
    assert.equal(cleanupDecision({ serviceStoppedAt: stopped, dataRemovedAt: new Date(start + 8 * DAY), nowMs: start + 6 * DAY, backupRetentionSatisfied: true, credentialsRevoked: true }).ok, false);
    assert.deepEqual(cleanupDecision({ serviceStoppedAt: stopped, dataRemovedAt: new Date(start + 8 * DAY), nowMs: start + 8 * DAY, backupRetentionSatisfied: true, credentialsRevoked: true }), { ok: true });
  });

  it("renders portals from inventory and keeps lifecycle source free of live side effects", () => {
    const customer = renderCustomerPortal({
      organizationId: "org",
      deploymentId: "dep",
      lifecycleState: "onboarding",
      onboardingStage: "draft",
      healthState: "unknown",
      serverId: "srv",
      serverState: "reserved",
      publicIpv4: "203.0.113.11",
      webmailHostname: "webmail.mail-m6.alpha-bearportal.com",
      mailHostname: "mail.mail-m6.alpha-bearportal.com",
      backupState: "reported_complete",
      backupFreshness: "fresh",
      requiredActions: ["mail.verification_required"],
      mailVerified: false,
      cloudVerified: false,
    });
    assertHonestPage(customer);
    assert.ok(customer.includes("Your account & service details"));
    assert.ok(customer.includes("webmail.mail-m6.alpha-bearportal.com"));
    assert.ok(customer.includes("separate"));




    const mailStep = deriveSetup({
      organizationId: "org",
      deploymentId: "dep",
      lifecycleState: "onboarding",
      onboardingStage: "verifying_mail",
      healthState: "unknown",
      serverId: "srv",
      serverState: "assigned",
      publicIpv4: "203.0.113.11",
      webmailHostname: null,
      mailHostname: "mail.mail-m6.alpha-bearportal.com",
      backupState: null,
      backupFreshness: "missing",
      requiredActions: ["mail.verification_required"],
      mailVerified: false,
      cloudVerified: false,
      installerStatus: "succeeded",
      dnsWritesAccepted: true,
    }).find((step) => step.name === "Live mail verification");
    assert.equal(mailStep?.state, "waiting_for_operator");
    const failedInstall = deriveSetup({
      organizationId: "org",
      deploymentId: "dep",
      lifecycleState: "onboarding",
      onboardingStage: "installing",
      healthState: "unknown",
      serverId: "srv",
      serverState: "assigned",
      publicIpv4: "203.0.113.11",
      webmailHostname: null,
      mailHostname: null,
      backupState: null,
      backupFreshness: "missing",
      requiredActions: [],
      mailVerified: false,
      cloudVerified: false,
      installerStatus: "dns_partial",
      dnsWritesAccepted: false,
    }).find((step) => step.name === "BearMail installation");
    assert.equal(failedInstall?.state, "failed");
    const operator = renderOperatorPortal({
      canManageServers: true, canManageBrevo: true, canViewBrevo: true,
      counts: [{ state: "reserved", count: 1 }],
      servers: [{ id: "srv", state: "reserved", publicIpv4: "203.0.113.11", label: "alpha <script>alert(1)</script>", ownerId: "org" }],
      requiredActions: ["cancellation.cleanup"],
      cloudVerified: false,
    });
    assertHonestPage(operator);
    assert.ok(operator.includes("alpha &lt;script&gt;alert(1)&lt;/script&gt;"));
    assert.ok(operator.includes("org"));
    assert.ok(operator.includes("Add server"));
    assert.ok(operator.includes("Linux, systemd and SSH are ready"));
    assert.ok(operator.includes("Brevo accounts"));
    assert.ok(operator.includes('action="/operator/inventory/brevo"'));
    assert.equal(operator.includes('name="domain"'), false);
    assert.ok(operator.includes("SMTP key"));
    assert.ok(operator.includes("API key"));
    assert.ok(operator.includes("Daily allowance"));
    assert.ok(operator.includes("Cloud servers and provider accounts are managed separately"));
    const accountResult = renderBrevoAccountResult({
      loginEmail: "relay@recovery-bearportal.com",
      stored: true,
      state: "inactive",
    });
    assertHonestPage(accountResult);
    assert.ok(accountResult.includes("This page did not call Brevo."));
    assert.ok(accountResult.includes("does not publish DNS"));
    assert.equal(accountResult.includes('name="domain"'), false);
    const brevoResult = renderBrevoDomainResult({
      domain: DOMAIN,
      authenticated: false,
      verified: true,
      recordsSaved: true,
      records: [{ purpose: "dkim", type: "TXT", host: "mail._domainkey", value: "k=rsa;p=shown" }],
    });
    assertHonestPage(brevoResult);
    assert.ok(brevoResult.includes('action="/portal/domain"'));
    assert.equal(brevoResult.includes('name="apiKey"'), false);





    assert.ok(operator.includes("binaries executed false"));
    const homePage = renderHome();
    assertHonestPage(homePage);
    assert.ok(homePage.includes("Your domain."));
    assert.ok(homePage.includes('id="register"'));
    assert.ok(homePage.includes('action="/register"'));
    assert.ok(homePage.includes("dedicated"));
    assert.ok(homePage.includes("your domain"));
    assert.ok(homePage.includes("Your email address"));
    assert.equal(homePage.includes('name="invitation"'), false);
    const identityHome = renderHome({ mode: "identity" });
    assert.equal(identityHome.includes('action="/register"'), false);
    assert.equal(identityHome.includes('name="invitation"'), false);
    assert.ok(identityHome.includes("sign-in provider"));
    assert.ok(identityHome.includes("Your domain."));
    assertHonestPage(identityHome);
    const failedHome = renderHome({ error: "Enter your email address.", email: "owner@recovery-bearportal.com" });
    assert.ok(failedHome.includes("Enter your email address."));
    assert.ok(failedHome.includes("owner@recovery-bearportal.com"));
    assert.equal(failedHome.includes("<script"), false);
    const waiting = renderCustomerPortal({
      organizationId: "org",
      deploymentId: null,
      lifecycleState: null,
      onboardingStage: null,
      healthState: null,
      serverId: null,
      serverState: null,
      publicIpv4: null,
      webmailHostname: null,
      mailHostname: null,
      backupState: null,
      backupFreshness: "missing",
      requiredActions: [],
      mailVerified: false,
      cloudVerified: false,
      allocationState: "waiting_for_server",
    });
    assertHonestPage(waiting);
    assert.ok(waiting.includes("Let’s make it yours."));
    assert.ok(waiting.includes("your domain"));
    assert.ok(waiting.includes('action="/portal/domain"'));
    assert.equal(waiting.includes('name="apiKey"'), false);
    const lifecycleSource = readFileSync(new URL("../apps/api/src/lifecycle.ts", import.meta.url), "utf8");
    const portalSource = readFileSync(new URL("../apps/api/src/portal.ts", import.meta.url), "utf8");
    const installationSource = readFileSync(new URL("../apps/api/src/installation.ts", import.meta.url), "utf8");
    const mainSource = readFileSync(new URL("../apps/api/src/main.ts", import.meta.url), "utf8");
    // Browser form submission uses fetch; server-side renderers still have no provider effects.
    const inventoryFormSource = readFileSync(new URL("../apps/api/src/inventory-form-script.ts", import.meta.url), "utf8");
    assert.ok(inventoryFormSource.includes("fetch(form.action"));
    for (const source of [lifecycleSource, portalSource.replace(/const ADMIN_LOGIN_SCRIPT=`[\s\S]*?`;/, "").split("const INVENTORY_SCRIPT")[0], installationSource, mainSource]) {
      assert.equal(source.includes("generate("), false);
      assert.doesNotMatch(source, /child_process|\bfetch\s*\(|mail_verified\s*=\s*true|writeZone|applyZone|publishZone/);
    }
    assert.equal(mainSource.includes("installerRunner"), false);
    assert.equal(mainSource.includes("brevoClient"), false);
    assert.equal(mainSource.includes("dnsObserver"), false);
    assert.equal(mainSource.includes("zoneReader"), false);
    assert.equal(mainSource.includes("release:"), false);
    assert.equal(mainSource.includes("scheduler-test-token"), false);
    assert.match(mainSource, /schedulerToken: config\.schedulerToken/);
  });
});

describe("M6 lifecycle API", { concurrency: false }, () => {
  before(async () => {
    await migrate(migrationUrl);
    const pair = await generateKeyPair("RS256", { extractable: true });
    privateKey = pair.privateKey;
    const deps: ApiDeps = {
      onboardingIntervalMs: 0,
      databaseUrl,
      secretsDir: mkdtempSync(join(tmpdir(), "bearportal-m6-secrets-")),
      secretKeyHex,
      jwtPublicKeyPem: await exportSPKI(pair.publicKey),
      issuer,
      audience,
      schedulerToken,
      zoneReader: {
        async readZone(input) {
          assert.deepEqual(Object.keys(input).sort(), ["domain", "provider", "zone"]);
          return zones.get(input.domain) ?? { ok: false, code: "PROOF_REJECTED" };
        },
      },
      operatorBrevo: {
        async requestDomain(apiKey, domain) {
          brevoCalls += 1;
          if (apiKey.includes("reject")) throw new BrevoRequestError("Brevo rejected the API key.");
          const yes = operatorBrevoMode === "verified";
          const records = operatorBrevoMode === "incomplete"
            ? []
            : [
              { purpose: "brevo_code" as const, type: "TXT" as const, host: "@", value: `brevo-code:${domain}` },
              { purpose: "dkim" as const, type: "TXT" as const, host: "mail._domainkey", value: "k=rsa;p=m6" },
              { purpose: "dmarc" as const, type: "TXT" as const, host: "_dmarc", value: "v=DMARC1; p=none" },
            ];
          return { domain, authenticated: yes, verified: yes, records };
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
    step = 0;
    ipHost = 10;
    zones.clear();
    operatorBrevoMode = "pending";
    brevoCalls = 0;
    await resetDatabase();
  });

  after(async () => {
    await superQuery("UPDATE control_plane_state SET mode = 'normal' WHERE id = 1");
    await app?.close();
  });

  it("A20 records operator backup evidence and transfers one assignment after fencing", async () => {
    const owner = await customerWithDeployment("m6-a20", DOMAIN);
    const assigned = await assignServer("alpha <script>alert(1)</script>");
    const owned = await api(base, "/v1/organization/server", { headers: auth(owner.token) });
    expectStatus(owned, 200);
    assert.equal(owned.body.server.publicIpv4, assigned.publicIpv4);
    assert.equal(owned.body.server.id, assigned.serverId);

    const other = await customerWithDeployment("m6-other", DOMAIN_B);
    const hidden = await api(base, `/v1/deployments/${owner.deploymentId}/backups`, { headers: auth(other.token) });
    expectStatus(hidden, 404);
    const otherPage = await page("/portal", other.token);
    assert.equal(otherPage.status, 200);
    assert.equal(otherPage.text.includes(assigned.publicIpv4), false);
    assert.equal(otherPage.text.includes(DOMAIN), false);
    assert.equal(otherPage.text.includes(owner.organizationId), false);
    assert.equal(otherPage.text.includes("portal-dns-token"), false);

    const remote = await reportBackup(owner.token, owner.deploymentId, { evidenceRef: "http://ops.alpha-bearportal.com/snap" });
    expectStatus(remote, 422);
    assert.equal(remote.body.error.code, "EVIDENCE_REF");
    const mismatch = await api(base, `/v1/admin/servers/${randomUUID()}/backups`, {
      method: "POST",
      headers: auth(await adminToken(), key("backup-mismatch")),
      body: JSON.stringify({
        deploymentId: owner.deploymentId,
        evidenceRef: "ops-wrong-server",
        expectedVersion: await deploymentVersion(owner.token, owner.deploymentId),
      }),
    });
    expectStatus(mismatch, 409);
    assert.equal(mismatch.body.error.code, "SERVER_MISMATCH");
    const reference = await api(base, `/v1/admin/servers/${assigned.serverId}/backups`, {
      method: "POST",
      headers: auth(await adminToken(), key("backup-server")),
      body: JSON.stringify({
        deploymentId: owner.deploymentId,
        evidenceRef: "ops-backup-m6",
        expectedVersion: await deploymentVersion(owner.token, owner.deploymentId),
      }),
    });
    expectStatus(reference, 200);
    assert.equal(reference.body.activated, false);
    assert.equal(reference.body.reason, "mail.verification_required");
    assert.equal(reference.body.lifecycleState, "onboarding");
    assert.equal(await scalar(`SELECT state FROM backups WHERE deployment_id = ${sqlText(owner.deploymentId)}`), "recorded");
    assert.equal(await scalar(`SELECT restore_verified_at IS NULL AND cloud_verified = false FROM backups WHERE deployment_id = ${sqlText(owner.deploymentId)}`), "t");
    assert.equal(await scalar(`SELECT backup_reported_at IS NULL FROM deployments WHERE id = ${sqlText(owner.deploymentId)}`), "t");

    const failed = await reportBackup(owner.token, owner.deploymentId, { evidenceRef: "ops-failed-m6", outcome: "reported_failed" });
    expectStatus(failed, 200);
    assert.equal(failed.body.state, "reported_failed");
    assert.equal(failed.body.activated, false);
    assert.equal(failed.body.cloudVerified, false);
    assert.equal(failed.body.provenance, "operator-reported");
    const inconsistent = await reportBackup(owner.token, owner.deploymentId, { evidenceRef: "ops-inconsistent-m6", outcome: "reported_complete" });
    expectStatus(inconsistent, 422);
    assert.equal(inconsistent.body.error.code, "CONSISTENCY_REQUIRED");
    const stale = await reportBackup(owner.token, owner.deploymentId, {
      evidenceRef: "ops-stale-m6",
      outcome: "reported_complete",
      consistency: "consistent",
      completedAt: new Date(Date.now() - 27 * HOUR).toISOString(),
    });
    expectStatus(stale, 200);
    assert.equal(stale.body.activated, false);
    const fresh = await reportBackup(owner.token, owner.deploymentId, {
      evidenceRef: "ops-fresh-m6",
      outcome: "reported_complete",
      consistency: "consistent",
      completedAt: new Date().toISOString(),
    });
    expectStatus(fresh, 200);
    assert.equal(fresh.body.state, "reported_complete");
    assert.equal(fresh.body.activated, false);
    assert.equal(fresh.body.reason, "mail.verification_required");
    assert.equal(fresh.body.cloudVerified, false);
    const bareRestore = await reportBackup(owner.token, owner.deploymentId, { evidenceRef: "ops-restore-missing", outcome: "restore_verified" });
    expectStatus(bareRestore, 422);
    assert.equal(bareRestore.body.error.code, "RESTORE_UNVERIFIED");
    const attested = await reportBackup(owner.token, owner.deploymentId, {
      evidenceRef: "ops-restore-m6",
      outcome: "restore_verified",
      restoreAttestation: "operator checked the restored mailbox",
    });
    expectStatus(attested, 200);
    assert.equal(attested.body.state, "restore_verified");
    assert.equal(attested.body.activated, false);
    assert.equal(attested.body.cloudVerified, false);
    assert.equal(await scalar(`SELECT mail_verified::text FROM deployments WHERE id = ${sqlText(owner.deploymentId)}`), "false");

    const listed = await api(base, `/v1/deployments/${owner.deploymentId}/backups`, { headers: auth(owner.token) });
    expectStatus(listed, 200);
    const complete = listed.body.backups.find((row: { state: string; freshness: string }) => row.state === "reported_complete" && row.freshness === "fresh");
    const old = listed.body.backups.find((row: { evidence_source: string; freshness: string; state: string }) => row.state === "reported_complete" && row.freshness === "stale");
    assert.ok(complete);
    assert.equal(complete.provenance, "operator-reported");
    assert.equal(complete.cloudVerified, false);
    assert.equal(complete.restoreVerifiedAt, null);
    assert.ok(old);
    const attestedRow = listed.body.backups.find((row: { state: string }) => row.state === "restore_verified");
    assert.ok(attestedRow.restoreVerifiedAt);
    const backupId = complete.id as string;

    const replacement = await enrollReady("replacement-m6");
    const tooSoon = await api(base, `/v1/admin/deployments/${owner.deploymentId}/replacement-plan`, {
      method: "POST",
      headers: auth(await adminToken(), key("replace-early")),
      body: JSON.stringify({ replacementServerId: replacement.serverId, reason: "Owner requested restore", expectedVersion: await deploymentVersion(owner.token, owner.deploymentId) }),
    });
    expectStatus(tooSoon, 422);
    assert.equal(tooSoon.body.error.code, "RESTORE_REQUEST_REQUIRED");
    const requested = await api(base, `/v1/deployments/${owner.deploymentId}/restore-requests`, {
      method: "POST",
      headers: auth(owner.token, key("restore")),
      body: JSON.stringify({ backupId, acknowledgePotentialDataLoss: true, expectedVersion: await deploymentVersion(owner.token, owner.deploymentId) }),
    });
    expectStatus(requested, 202);
    assert.equal(requested.body.state, "requested");
    assert.equal(requested.body.automaticRestore, false);
    assert.equal(requested.body.cloudVerified, false);
    assert.equal(requested.body.mailVerified, false);
    const duplicate = await api(base, `/v1/deployments/${owner.deploymentId}/restore-requests`, {
      method: "POST",
      headers: auth(owner.token, key("restore-again")),
      body: JSON.stringify({ backupId, acknowledgePotentialDataLoss: true, expectedVersion: await deploymentVersion(owner.token, owner.deploymentId) }),
    });
    expectStatus(duplicate, 409);
    assert.equal(duplicate.body.error.code, "RESTORE_OPEN");

    const unavailable = await api(base, `/v1/admin/deployments/${owner.deploymentId}/replacement-plan`, {
      method: "POST",
      headers: auth(await adminToken(), key("replace-pending")),
      body: JSON.stringify({ replacementServerId: replacement.serverId, backupId, reason: "Owner requested restore", expectedVersion: await deploymentVersion(owner.token, owner.deploymentId) }),
    });
    expectStatus(unavailable, 409);
    assert.equal(unavailable.body.error.code, "INVALID_STATE");
    await superQuery(`UPDATE servers SET state = 'available', available_since = now(), validated_at = now(), updated_at = now() WHERE id = ${sqlText(replacement.serverId)}`);
    const reserved = await api(base, `/v1/admin/deployments/${owner.deploymentId}/replacement-plan`, {
      method: "POST",
      headers: auth(await adminToken(), key("replace")),
      body: JSON.stringify({ replacementServerId: replacement.serverId, backupId, reason: "Owner requested restore", expectedVersion: await deploymentVersion(owner.token, owner.deploymentId) }),
    });
    expectStatus(reserved, 201);
    assert.equal(reserved.body.state, "quarantined");
    assert.equal(reserved.body.liveAssignmentCreated, false);
    assert.equal(reserved.body.cloudApiCalled, false);
    assert.equal(await scalar("SELECT count(*) FROM server_assignments WHERE released_at IS NULL"), "1");
    assert.equal(await scalar(`SELECT state FROM recovery_bindings WHERE replacement_server_id = ${sqlText(replacement.serverId)}`), "pending");

    const heartbeat = await api(base, `/v1/admin/deployments/${owner.deploymentId}/restore-ready`, {
      method: "POST",
      headers: auth(await adminToken(), key("fence-heart")),
      body: JSON.stringify({
        backupId,
        fencing: "missing_heartbeat",
        evidenceRef: "ops-fence-heart",
        expectedVersion: await deploymentVersion(owner.token, owner.deploymentId),
      }),
    });
    expectStatus(heartbeat, 422);
    assert.equal(heartbeat.body.error.code, "FENCING_INSUFFICIENT");
    assert.equal(await scalar(`SELECT state FROM restore_requests WHERE id = ${sqlText(requested.body.restoreRequestId)}`), "requested");
    const ready = await api(base, `/v1/admin/deployments/${owner.deploymentId}/restore-ready`, {
      method: "POST",
      headers: auth(await adminToken(), key("fence")),
      body: JSON.stringify({
        backupId,
        fencing: "application_stop",
        evidenceRef: "ops-fence-m6",
        expectedVersion: await deploymentVersion(owner.token, owner.deploymentId),
      }),
    });
    expectStatus(ready, 202);
    assert.equal(ready.body.ready, true);
    assert.equal(ready.body.promoted, false);
    assert.equal(ready.body.heartbeatIsFencing, false);
    assert.equal(ready.body.jobState, "queued");
    assert.equal(ready.body.restoreVerified, false);
    assert.equal(ready.body.dnsWrite, false);
    assert.equal(ready.body.mailVerified, false);
    const unapproved = await api(base, `/v1/admin/deployments/${owner.deploymentId}/restore-promote`, {
      method: "POST",
      headers: auth(await adminToken(), key("promote-early")),
      body: JSON.stringify({ expectedVersion: await deploymentVersion(owner.token, owner.deploymentId) }),
    });
    expectStatus(unapproved, 409);
    assert.equal(unapproved.body.error.code, "APPROVAL_REQUIRED");
    await approve(owner.token, requested.body.approvalId, requested.body.planHash);
    const promoted = await api(base, `/v1/admin/deployments/${owner.deploymentId}/restore-promote`, {
      method: "POST",
      headers: auth(await adminToken(), key("promote")),
      body: JSON.stringify({ expectedVersion: await deploymentVersion(owner.token, owner.deploymentId) }),
    });
    expectStatus(promoted, 200);
    assert.equal(promoted.body.promoted, true);
    assert.equal(promoted.body.hostRestoreExecuted, false);
    assert.equal(promoted.body.dnsWrite, false);
    assert.equal(promoted.body.mailVerified, false);
    assert.equal(promoted.body.cloudVerified, false);
    assert.equal(promoted.body.restoreVerified, false);
    assert.equal(promoted.body.liveAssignments, 1);
    assert.equal(promoted.body.oldServerState, "quarantined");
    assert.equal(promoted.body.replacementState, "assigned");
    assert.equal(await scalar("SELECT count(*) FROM server_assignments WHERE released_at IS NULL"), "1");
    assert.equal(await scalar(`SELECT state || ':' || (tenant_tainted_at IS NOT NULL)::text FROM servers WHERE id = ${sqlText(assigned.serverId)}`), "quarantined:true");
    assert.equal(await scalar(`SELECT state || ':' || (tenant_tainted_at IS NOT NULL)::text FROM servers WHERE id = ${sqlText(replacement.serverId)}`), "assigned:true");
    assert.equal(await scalar(`SELECT mail_verified::text FROM deployments WHERE id = ${sqlText(owner.deploymentId)}`), "false");
    assert.equal(await scalar("SELECT count(*) FROM jobs WHERE state = 'succeeded'"), "0");
    assert.equal(await scalar("SELECT state FROM jobs WHERE kind = 'restore.validation'"), "queued");
    assert.equal(await scalar("SELECT count(*) FROM host_commands WHERE command_type IN ('upgrade_release', 'install_release')"), "0");

    const customerPage = await page("/portal", owner.token);
    assert.equal(customerPage.status, 200);
    assertHonestPage(customerPage.text);
    const replacementIp = await scalar(`SELECT host(public_ipv4) FROM servers WHERE id = ${sqlText(replacement.serverId)}`);
    assert.ok(customerPage.text.includes(replacementIp));
    assert.equal(customerPage.text.includes(assigned.publicIpv4), false);
    assert.ok(customerPage.text.includes(`bearmail.${DOMAIN}`));
    assert.ok(customerPage.text.includes("Your account & service details"));
    assert.ok(customerPage.text.includes("Connection settings"));
    assert.ok(customerPage.text.includes("Live mail verified"));
    assert.ok(customerPage.text.includes("beta"));
    assert.ok(customerPage.text.includes("owner@"));
    assert.ok(customerPage.text.includes("Name.com"));
    assert.equal(customerPage.text.includes("portal-dns-token"), false);
    assert.equal(customerPage.text.includes("portal-namecom"), false);
    assert.equal(customerPage.text.includes(other.organizationId), false);
    const overview = await api(base, "/v1/portal/overview", { headers: auth(owner.token) });
    expectStatus(overview, 200);
    assert.equal(overview.body.publicIpv4, replacementIp);
    assert.equal(overview.body.mailVerified, false);
    assert.equal(overview.body.cloudVerified, false);
    assert.equal(overview.body.backupState, "restore_verified");
    assert.equal(overview.body.backupFreshness, "missing");
    assert.equal(overview.body.acceptedMailIsDelivery, false);
    assert.equal(overview.body.manualDns, false);
    assert.equal(overview.body.domainName, DOMAIN);
    const operatorPage = await page("/operator", await adminToken());
    assert.equal(operatorPage.status, 200);
    assertHonestPage(operatorPage.text);
    assert.ok(operatorPage.text.includes("alpha &lt;script&gt;alert(1)&lt;/script&gt;"));
    assert.ok(operatorPage.text.includes(owner.organizationId));
    assert.ok(operatorPage.text.includes(other.organizationId));
    assert.ok(operatorPage.text.includes("ops@recovery-bearportal.com"));
    assert.ok(operatorPage.text.includes("Last successful SSH check"));
    assert.ok(operatorPage.text.includes("Brevo accounts"));
    assert.ok(operatorPage.text.includes('action="/operator/inventory/brevo"'));
    assert.equal(operatorPage.text.includes('name="domain"'), false);
    assert.ok(operatorPage.text.includes("SMTP key"));
    const home = await page("/");
    assert.equal(home.status, 200);
    assertHonestPage(home.text);
    assert.ok(home.text.includes("Your domain."));
    assert.ok(home.text.includes('id="register"'));
    assert.ok(home.text.includes("dedicated"));
    assert.ok(home.text.includes("sign-in provider"));
    assert.equal(home.text.includes('action="/register"'), false);
  });

  it("registers from the development home page and opens the portal", async () => {
    const pair = await generateKeyPair("RS256", { extractable: true });
    const local = await buildServer({
      onboardingIntervalMs: 0,
      databaseUrl,
      secretsDir: mkdtempSync(join(tmpdir(), "bearportal-m6-register-")),
      secretKeyHex,
      jwtPublicKeyPem: await exportSPKI(pair.publicKey),
      issuer,
      audience,
      devJwtPrivateKeyPem: await exportPKCS8(pair.privateKey),
    }, logStream);
    try {
      await local.listen({ host: "127.0.0.1", port: 0 });
      const address = local.server.address();
      if (!address || typeof address === "string") throw new Error("The registration API did not listen on a TCP port.");
      const origin = `http://127.0.0.1:${address.port}`;
      const home = await fetch(`${origin}/`);
      const homeText = await home.text();
      assert.equal(home.status, 200);
      assert.ok(homeText.includes("Your domain."));
      assert.ok(homeText.includes('id="register"'));
      assert.ok(homeText.includes('action="/register"'));
      assert.ok(homeText.includes("dedicated"));
      assert.ok(homeText.includes("Your email address"));
      assert.equal(homeText.includes('name="invitation"'), false);
      assert.ok(homeText.includes('type="submit"'));
      assert.equal(homeText.includes("<script"), false);
      const email = "register-m6@recovery-bearportal.com";
      const missing = await fetch(`${origin}/register`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ email, organization: "" }).toString(),
        redirect: "manual",
      });
      assert.equal(missing.status, 303);
      assert.equal(missing.headers.get("location"), "/portal");
      assert.equal(await scalar(`SELECT count(*) FROM users WHERE verified_email = ${sqlText(email)}`), "1");
      const created = await fetch(`${origin}/register`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ email, organization: "Register Co" }).toString(),
        redirect: "manual",
      });
      assert.equal(created.status, 303);
      assert.equal(created.headers.get("location"), "/portal");
      const setCookie = created.headers.get("set-cookie") ?? "";
      assert.match(setCookie, /bp_session=/);
      assert.match(setCookie, /HttpOnly/i);
      const portal = await fetch(`${origin}/portal`, { headers: { cookie: setCookie.split(";")[0] ?? "" } });
      assert.equal(portal.status, 200);
      const portalText = await portal.text();
      assert.ok(portalText.includes("Let’s make it yours."));
      assert.ok(portalText.includes("Waiting for capacity"));
      assert.ok(portalText.includes("operator-reported"));
      assert.ok(portalText.includes('<script src="/assets/customer-session.js" defer></script>'));
      assert.equal(portalText.includes("<script>"), false);
      const again = await fetch(`${origin}/register`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ email, organization: "" }).toString(),
        redirect: "manual",
      });
      assert.equal(again.status, 303);
      assert.equal(again.headers.get("location"), "/portal");
      const second = await fetch(`${origin}/register`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ email: "register-m6b@recovery-bearportal.com", organization: "Other Co" }).toString(),
        redirect: "manual",
      });
      assert.equal(second.status, 303);
      assert.equal(await scalar("SELECT count(*) FROM organizations WHERE name = 'register-m6'"), "1");
      assert.equal(await scalar("SELECT count(*) FROM organizations WHERE name = 'Other Co'"), "1");
      assert.equal(await scalar(`SELECT email_verified::text FROM users WHERE verified_email = ${sqlText(email)}`), "true");
      assert.equal(await scalar(`SELECT count(*) FROM invitations WHERE bound_email = ${sqlText(email)}`), "0");
      assert.equal(await scalar("SELECT count(*) FROM deployments"), "0");
    } finally {
      await local.close();
    }
  });

  it("A21 records upgrade plans and does not run binaries or roll back data", async () => {
    const owner = await customerWithDeployment("m6-a21", DOMAIN);
    const missing = await api(base, `/v1/admin/deployments/${owner.deploymentId}/upgrade-plan`, {
      method: "POST",
      headers: auth(await adminToken(), key("upgrade-none")),
      body: JSON.stringify({
        releaseId: "m6-release",
        compatible: true,
        irreversible: false,
        newMailAccepted: false,
        checksFailed: false,
        expectedVersion: await deploymentVersion(owner.token, owner.deploymentId),
      }),
    });
    expectStatus(missing, 422);
    assert.equal(missing.body.error.code, "BACKUP_REQUIRED");
    assert.equal(await scalar("SELECT state || ':' || rollback_policy || ':' || binaries_executed::text || ':' || executed::text FROM upgrade_plans"), "blocked:blocked:false:false");
    await reportBackup(owner.token, owner.deploymentId, {
      evidenceRef: "ops-stale-upgrade",
      outcome: "reported_complete",
      consistency: "consistent",
      completedAt: new Date(Date.now() - 27 * HOUR).toISOString(),
    });
    const staleId = await scalar(`SELECT id FROM backups WHERE evidence_ref = 'ops-stale-upgrade'`);
    const fresh = await reportBackup(owner.token, owner.deploymentId, {
      evidenceRef: "ops-fresh-upgrade",
      outcome: "reported_complete",
      consistency: "consistent",
      completedAt: new Date().toISOString(),
    });
    expectStatus(fresh, 200);
    const freshId = await scalar(`SELECT id FROM backups WHERE evidence_ref = 'ops-fresh-upgrade'`);
    const stalePlan = await api(base, `/v1/admin/deployments/${owner.deploymentId}/upgrade-plan`, {
      method: "POST",
      headers: auth(await adminToken(), key("upgrade-stale")),
      body: JSON.stringify({
        releaseId: "m6-release",
        compatible: true,
        irreversible: false,
        newMailAccepted: false,
        checksFailed: false,
        preUpgradeBackupId: staleId,
        expectedVersion: await deploymentVersion(owner.token, owner.deploymentId),
      }),
    });
    expectStatus(stalePlan, 422);
    assert.equal(stalePlan.body.error.code, "BACKUP_REQUIRED");
    const irreversible = await api(base, `/v1/admin/deployments/${owner.deploymentId}/upgrade-plan`, {
      method: "POST",
      headers: auth(await adminToken(), key("upgrade-keep")),
      body: JSON.stringify({
        releaseId: "m6-release",
        compatible: false,
        irreversible: true,
        newMailAccepted: true,
        checksFailed: false,
        preUpgradeBackupId: freshId,
        expectedVersion: await deploymentVersion(owner.token, owner.deploymentId),
      }),
    });
    expectStatus(irreversible, 200);
    assert.equal(irreversible.body.state, "preserve_required");
    assert.equal(irreversible.body.rollbackPolicy, "preserve_new_mail");
    assert.equal(irreversible.body.dataRollback, false);
    assert.equal(irreversible.body.binariesExecuted, false);
    assert.equal(irreversible.body.executed, false);
    assert.equal(irreversible.body.upgradeSucceeded, false);
    assert.equal(irreversible.body.recordedOnly, true);
    const rollback = await api(base, `/v1/admin/deployments/${owner.deploymentId}/upgrade-plan`, {
      method: "POST",
      headers: auth(await adminToken(), key("upgrade-check")),
      body: JSON.stringify({
        releaseId: "m6-release",
        compatible: true,
        irreversible: false,
        newMailAccepted: false,
        checksFailed: true,
        preUpgradeBackupId: freshId,
        expectedVersion: await deploymentVersion(owner.token, owner.deploymentId),
      }),
    });
    expectStatus(rollback, 200);
    assert.equal(rollback.body.state, "rollback_required");
    assert.equal(rollback.body.rollbackPolicy, "binary_rollback");
    assert.equal(rollback.body.binariesExecuted, false);
    assert.equal(rollback.body.dataRollback, false);
    const pending = await api(base, `/v1/admin/deployments/${owner.deploymentId}/upgrade-plan`, {
      method: "POST",
      headers: auth(await adminToken(), key("upgrade-pending")),
      body: JSON.stringify({
        releaseId: "m6-release",
        compatible: true,
        irreversible: false,
        newMailAccepted: false,
        checksFailed: false,
        preUpgradeBackupId: freshId,
        expectedVersion: await deploymentVersion(owner.token, owner.deploymentId),
      }),
    });
    expectStatus(pending, 202);
    assert.equal(pending.body.state, "pending");
    assert.ok(pending.body.approvalId);
    assert.equal(pending.body.binariesExecuted, false);
    assert.equal(pending.body.executed, false);
    assert.equal(pending.body.upgradeSucceeded, false);
    assert.equal(pending.body.dnsWrite, false);
    assert.equal(pending.body.mailVerified, false);
    assert.equal(await scalar("SELECT count(*) FROM host_commands WHERE command_type = 'upgrade_release'"), "0");
    assert.equal(await scalar("SELECT count(*) FROM jobs WHERE state = 'succeeded'"), "0");
    assert.equal(await scalar("SELECT count(*) FROM upgrade_plans WHERE binaries_executed OR executed OR data_rollback"), "0");
  });

  it("A22 keeps cancellation inside the grace window and retires only after retention", async () => {
    const owner = await customerWithDeployment("m6-a22", DOMAIN);
    const assigned = await assignServer("cancel-host");
    const version = await deploymentVersion(owner.token, owner.deploymentId);
    const planned = await api(base, `/v1/deployments/${owner.deploymentId}/cancellation-plan`, {
      method: "POST",
      headers: auth(owner.token, key("cancel-plan")),
      body: JSON.stringify({ reason: "owner leaving", expectedVersion: version }),
    });
    expectStatus(planned, 202);
    assert.equal(planned.body.state, "proposed");
    assert.equal(planned.body.retentionDays, 7);
    assert.equal(planned.body.approvalWindowMinutes, 30);
    assert.equal(planned.body.executionWindowHours, 24);
    assert.equal(planned.body.dnsWrite, false);
    assert.equal(planned.body.cloudApiCalled, false);
    assert.equal(planned.body.billingStopped, false);
    const executeAt = Date.parse(planned.body.executeAt);
    assert.ok(executeAt - Date.now() > 6 * DAY);
    const proposed = await executeCancellation(planned.body.scheduleId);
    expectStatus(proposed, 409);
    assert.equal(proposed.body.error.code, "INVALID_STATE");
    await approve(owner.token, planned.body.approvalId, planned.body.planHash);
    assert.equal(await scalar(`SELECT state FROM cancellation_schedules WHERE id = ${sqlText(planned.body.scheduleId)}`), "scheduled");
    const early = await executeCancellation(planned.body.scheduleId);
    expectStatus(early, 422);
    assert.equal(early.body.error.code, "NOT_DUE");
    await superQuery(`UPDATE cancellation_schedules SET execute_at = now() - interval '1 hour', window_ends_at = now() + interval '12 hours' WHERE id = ${sqlText(planned.body.scheduleId)}`);
    const needsBackup = await executeCancellation(planned.body.scheduleId);
    expectStatus(needsBackup, 422);
    assert.equal(needsBackup.body.error.code, "FINAL_BACKUP_REQUIRED");
    assert.equal(await scalar("SELECT count(*) FROM host_commands WHERE command_type = 'stop_mail_services'"), "0");
    const waiver = await api(base, `/v1/deployments/${owner.deploymentId}/cancellation-waiver`, {
      method: "POST",
      headers: auth(owner.token, key("waiver")),
      body: JSON.stringify({ acknowledgeNoFinalBackup: true, expectedVersion: await deploymentVersion(owner.token, owner.deploymentId) }),
    });
    expectStatus(waiver, 200);
    assert.equal(waiver.body.waived, true);
    assert.equal(waiver.body.serviceStopped, false);
    const queued = await executeCancellation(planned.body.scheduleId);
    expectStatus(queued, 202);
    assert.equal(queued.body.state, "queued");
    assert.equal(queued.body.serviceStopped, false);
    assert.equal(queued.body.delivered, false);
    assert.equal(queued.body.cloudApiCalled, false);
    assert.equal(queued.body.hostObserved, false);
    const duplicate = await executeCancellation(planned.body.scheduleId);
    expectStatus(duplicate, 200);
    assert.equal(duplicate.body.duplicate, true);
    assert.equal(duplicate.body.jobId, queued.body.jobId);
    assert.equal(await scalar("SELECT count(*) FROM host_commands WHERE command_type = 'stop_mail_services'"), "1");
    assert.equal(await scalar("SELECT payload::text FROM host_commands WHERE command_type = 'stop_mail_services'"), "{}");
    assert.equal(await scalar(`SELECT (tenant_tainted_at IS NOT NULL)::text FROM servers WHERE id = ${sqlText(assigned.serverId)}`), "true");
    assert.equal(await scalar(`SELECT service_stopped::text FROM cancellation_schedules WHERE id = ${sqlText(planned.body.scheduleId)}`), "false");

    const isolated = await api(base, `/v1/admin/deployments/${owner.deploymentId}/isolation-report`, {
      method: "POST",
      headers: auth(await adminToken(), key("isolate")),
      body: JSON.stringify({
        evidenceRef: "ops-isolation-m6",
        externallyIsolated: true,
        expectedVersion: await deploymentVersion(owner.token, owner.deploymentId),
      }),
    });
    expectStatus(isolated, 200);
    assert.equal(isolated.body.serviceStopped, true);
    assert.equal(isolated.body.evidence, "operator");
    assert.equal(isolated.body.hostObserved, false);
    assert.equal(isolated.body.cloudApiCalled, false);
    assert.equal(isolated.body.assignmentReleased, false);
    assert.equal(isolated.body.serverState, "quarantined");
    assert.equal(isolated.body.lifecycleState, "deleting");
    assert.equal(isolated.body.billingStopped, false);
    assert.equal(isolated.body.delivered, false);
    assert.equal(await scalar(`SELECT lifecycle_state || ':' || mail_verified::text FROM deployments WHERE id = ${sqlText(owner.deploymentId)}`), "deleting:false");

    const supportSubject = "support-m6";
    const supportEmail = "support-m6@recovery-bearportal.com";
    const supportMe = await api(base, "/v1/me", { headers: auth(await tokenFor(supportSubject, supportEmail)) });
    expectStatus(supportMe, 200);
    const supportId = await scalar(`SELECT id FROM users WHERE identity_subject = ${sqlText(supportSubject)}`);
    const grant = await api(base, "/v1/admin/operator-roles", {
      method: "POST",
      headers: auth(await adminToken(), key("grant-support")),
      body: JSON.stringify({ userId: supportId, role: "support", reason: "Read-only lifecycle check" }),
    });
    expectStatus(grant, 201);
    const supportToken = await tokenFor(supportSubject, supportEmail, { amr: ["pwd", "totp"], auth_time: now() });
    const cleanupBody = {
      outcome: "deleted",
      dataRemovedAt: new Date().toISOString(),
      backupRetentionSatisfied: false,
      credentialsRevoked: false,
      evidenceRef: "ops-cleanup-m6",
      operatorAttestation: "operator removed tenant data after retention",
      expectedVersion: await serverVersion(assigned.serverId),
    };
    const supportCleanup = await api(base, `/v1/admin/servers/${assigned.serverId}/cleanup-report`, {
      method: "POST",
      headers: auth(supportToken, key("support-cleanup")),
      body: JSON.stringify(cleanupBody),
    });
    expectStatus(supportCleanup, 403);
    assert.equal(supportCleanup.body.error.code, "FORBIDDEN");
    const flags = await api(base, `/v1/admin/servers/${assigned.serverId}/cleanup-report`, {
      method: "POST",
      headers: auth(await adminToken(), key("cleanup-flags")),
      body: JSON.stringify(cleanupBody),
    });
    expectStatus(flags, 422);
    assert.equal(flags.body.error.code, "RETENTION_OPEN");
    const earlyCleanup = await api(base, `/v1/admin/servers/${assigned.serverId}/cleanup-report`, {
      method: "POST",
      headers: auth(await adminToken(), key("cleanup-early")),
      body: JSON.stringify({ ...cleanupBody, backupRetentionSatisfied: true, credentialsRevoked: true, expectedVersion: await serverVersion(assigned.serverId) }),
    });
    expectStatus(earlyCleanup, 422);
    assert.equal(earlyCleanup.body.error.code, "RETENTION_OPEN");
    assert.equal(await scalar(`SELECT state FROM servers WHERE id = ${sqlText(assigned.serverId)}`), "quarantined");
    assert.equal(await scalar("SELECT count(*) FROM server_assignments WHERE released_at IS NULL"), "1");
    await superQuery(`UPDATE cancellation_schedules SET service_stopped_at = now() - interval '8 days' WHERE id = ${sqlText(planned.body.scheduleId)}`);
    const removed = await api(base, `/v1/admin/servers/${assigned.serverId}/cleanup-report`, {
      method: "POST",
      headers: auth(await adminToken(), key("cleanup")),
      body: JSON.stringify({
        ...cleanupBody,
        backupRetentionSatisfied: true,
        credentialsRevoked: true,
        dataRemovedAt: new Date().toISOString(),
        expectedVersion: await serverVersion(assigned.serverId),
      }),
    });
    expectStatus(removed, 200);
    assert.equal(removed.body.state, "retired");
    assert.equal(removed.body.returnedAvailable, false);
    assert.equal(removed.body.reusable, false);
    assert.equal(removed.body.cloudVerified, false);
    assert.equal(removed.body.billingStopped, false);
    assert.equal(removed.body.lifecycleState, "deleted");
    assert.equal(removed.body.mailVerified, false);
    assert.equal(await scalar(`SELECT state || ':' || (tenant_tainted_at IS NOT NULL)::text FROM servers WHERE id = ${sqlText(assigned.serverId)}`), "retired:true");
    assert.equal(await scalar("SELECT count(*) FROM server_assignments WHERE released_at IS NULL"), "0");
    assert.equal(await scalar(`SELECT lifecycle_state FROM deployments WHERE id = ${sqlText(owner.deploymentId)}`), "deleted");
    assert.equal(await scalar(`SELECT state FROM cancellation_schedules WHERE id = ${sqlText(planned.body.scheduleId)}`), "completed");
    assert.equal(await scalar(`SELECT state FROM host_identities WHERE server_id = ${sqlText(assigned.serverId)}`), "revoked");
    const reuse = await api(base, `/v1/admin/servers/${assigned.serverId}/validate`, {
      method: "POST",
      headers: auth(await adminToken(), key("reuse")),
      body: JSON.stringify({ expectedVersion: await serverVersion(assigned.serverId) }),
    });
    expectStatus(reuse, 409);
    assert.equal(reuse.body.error.code, "INVALID_STATE");
  });

  it("A22 leaves a reimaged server quarantined and tainted", async () => {
    const owner = await customerWithDeployment("m6-reimage", DOMAIN);
    const assigned = await assignServer("reimage-host");
    const planned = await api(base, `/v1/deployments/${owner.deploymentId}/cancellation-plan`, {
      method: "POST",
      headers: auth(owner.token, key("reimage-plan")),
      body: JSON.stringify({ expectedVersion: await deploymentVersion(owner.token, owner.deploymentId) }),
    });
    expectStatus(planned, 202);
    await approve(owner.token, planned.body.approvalId, planned.body.planHash);
    await superQuery(`UPDATE cancellation_schedules SET execute_at = now() - interval '1 hour', window_ends_at = now() + interval '12 hours' WHERE id = ${sqlText(planned.body.scheduleId)}`);
    const waiver = await api(base, `/v1/deployments/${owner.deploymentId}/cancellation-waiver`, {
      method: "POST",
      headers: auth(owner.token, key("reimage-waiver")),
      body: JSON.stringify({ acknowledgeNoFinalBackup: true, expectedVersion: await deploymentVersion(owner.token, owner.deploymentId) }),
    });
    expectStatus(waiver, 200);
    const queued = await executeCancellation(planned.body.scheduleId);
    expectStatus(queued, 202);
    const isolated = await api(base, `/v1/admin/deployments/${owner.deploymentId}/isolation-report`, {
      method: "POST",
      headers: auth(await adminToken(), key("reimage-isolate")),
      body: JSON.stringify({
        evidenceRef: "ops-isolation-reimage",
        externallyIsolated: true,
        expectedVersion: await deploymentVersion(owner.token, owner.deploymentId),
      }),
    });
    expectStatus(isolated, 200);
    await superQuery(`UPDATE cancellation_schedules SET service_stopped_at = now() - interval '8 days' WHERE id = ${sqlText(planned.body.scheduleId)}`);
    const reimaged = await api(base, `/v1/admin/servers/${assigned.serverId}/cleanup-report`, {
      method: "POST",
      headers: auth(await adminToken(), key("reimage-cleanup")),
      body: JSON.stringify({
        outcome: "reimaged",
        dataRemovedAt: new Date().toISOString(),
        backupRetentionSatisfied: true,
        credentialsRevoked: true,
        evidenceRef: "ops-reimage-m6",
        operatorAttestation: "operator reimaged the disk after retention",
        expectedVersion: await serverVersion(assigned.serverId),
      }),
    });
    expectStatus(reimaged, 200);
    assert.equal(reimaged.body.state, "quarantined");
    assert.equal(reimaged.body.returnedAvailable, false);
    assert.equal(reimaged.body.reusable, false);
    assert.equal(reimaged.body.cloudVerified, false);
    assert.equal(await scalar(`SELECT state || ':' || (tenant_tainted_at IS NOT NULL)::text FROM servers WHERE id = ${sqlText(assigned.serverId)}`), "quarantined:true");
    assert.equal(await scalar(`SELECT state FROM host_identities WHERE server_id = ${sqlText(assigned.serverId)}`), "revoked");
    const validate = await api(base, `/v1/admin/servers/${assigned.serverId}/validate`, {
      method: "POST",
      headers: auth(await adminToken(), key("reimage-validate")),
      body: JSON.stringify({ expectedVersion: await serverVersion(assigned.serverId) }),
    });
    expectStatus(validate, 409);
    assert.equal(validate.body.error.code, "INVALID_STATE");
  });

  it("A22 revocation, recovery mode, mailbox deletion, and the release checklist stay closed", async () => {
    const owner = await customerWithDeployment("m6-revoke", DOMAIN);
    const mailbox = await api(base, `/v1/deployments/${owner.deploymentId}/mailboxes`, {
      method: "POST",
      headers: auth(owner.token, key("mailbox")),
      body: JSON.stringify({ localPart: "ada" }),
    });
    expectStatus(mailbox, 202);
    const deletePlan = await api(base, `/v1/mailboxes/${mailbox.body.mailboxId}/delete-plan`, {
      method: "POST",
      headers: auth(owner.token, key("delete-plan")),
      body: JSON.stringify({ expectedVersion: 1 }),
    });
    expectStatus(deletePlan, 202);
    assert.equal(deletePlan.body.executed, false);
    assert.equal(deletePlan.body.deleted, false);
    assert.equal(deletePlan.body.mailboxState, "pending");
    assert.equal(await scalar(`SELECT state FROM mailboxes WHERE id = ${sqlText(mailbox.body.mailboxId)}`), "pending");
    assert.equal(await scalar(`SELECT count(*) FROM mailboxes WHERE id = ${sqlText(mailbox.body.mailboxId)}`), "1");

    const planned = await api(base, `/v1/deployments/${owner.deploymentId}/cancellation-plan`, {
      method: "POST",
      headers: auth(owner.token, key("revoke-plan")),
      body: JSON.stringify({ expectedVersion: await deploymentVersion(owner.token, owner.deploymentId) }),
    });
    expectStatus(planned, 202);
    const revoked = await api(base, `/v1/deployments/${owner.deploymentId}/cancel-deletion`, {
      method: "POST",
      headers: auth(owner.token, key("revoke")),
      body: JSON.stringify({ expectedVersion: await deploymentVersion(owner.token, owner.deploymentId) }),
    });
    expectStatus(revoked, 200);
    assert.equal(revoked.body.state, "revoked");
    assert.equal(revoked.body.serviceStopped, false);
    assert.equal(revoked.body.assignmentReleased, false);
    assert.equal(revoked.body.cloudApiCalled, false);
    const late = await executeCancellation(planned.body.scheduleId);
    expectStatus(late, 409);
    assert.equal(late.body.error.code, "INVALID_STATE");
    assert.equal(await scalar("SELECT count(*) FROM host_commands"), "0");

    const entered = await api(base, "/internal/recovery/enter", {
      method: "POST",
      headers: scheduler(),
      body: JSON.stringify({ reason: "lifecycle pause" }),
    });
    expectStatus(entered, 200);
    assert.equal(entered.body.scheduledDeletionPaused, true);
    const paused = await api(base, `/v1/deployments/${owner.deploymentId}/cancellation-plan`, {
      method: "POST",
      headers: auth(owner.token, key("paused-plan")),
      body: JSON.stringify({ expectedVersion: await deploymentVersion(owner.token, owner.deploymentId) }),
    });
    expectStatus(paused, 409);
    assert.equal(paused.body.error.code, "RECOVERY_MODE");
    assert.equal(await scalar("SELECT count(*) FROM cancellation_schedules WHERE state IN ('proposed', 'scheduled', 'stopped')"), "0");

    const checklist = await api(base, "/v1/admin/release-checklist", { headers: auth(await adminToken()) });
    expectStatus(checklist, 200);
    assert.equal(checklist.body.document, "local-control-plane");
    assert.equal(checklist.body.liveEvidence, false);
    assert.equal(checklist.body.soakExecuted, false);
    assert.equal(checklist.body.restoreDrillExecuted, false);
    assert.equal(checklist.body.upgradeBinariesExecuted, false);
    assert.equal(checklist.body.cancellationHostStopObserved, false);
    assert.equal(checklist.body.cloudApiCalled, false);
    assert.equal(checklist.body.mailVerifiedDeployments, 0);
    for (const gate of ["A07-A16", "A19", "A20", "A21", "A22", "A25", "A31"]) {
      assert.ok(checklist.body.openGates.includes(gate));
    }
    assert.ok(String(checklist.body.notes.join(" ")).includes("24 hour"));
    assert.equal(String(checklist.body.notes.join(" ")).includes("generate("), false);
  });

  it("stores a Brevo account without a domain and checks the domain from the portal", async () => {
    const apiKey = "api-key-m6-canary";
    const smtpKey = "smtp-key-m6-pending";
    const rejectedKey = "reject-api-key-m6-canary";
    const rejectedSmtp = "smtp-key-m6-canary";
    const loginEmail = "relay-m6@recovery-bearportal.com";
    const earlyDomain = "wait-m6.alpha-bearportal.com";
    const accountFields = {
      csrf: "1",
      domain: DOMAIN,
      loginEmail,
      apiKey,
      smtpLogin: "smtp-m6@smtp-brevo.com",
      smtpKey,
      dailyLimit: "",
    };
    const session = await fetch(`${base}/v1/session`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ idToken: await adminToken() }),
    });
    assert.equal(session.status, 200);
    const cookie = (session.headers.get("set-cookie") ?? "").split(";")[0] ?? "";
    assert.ok(cookie.startsWith("bp_session="));
    const denied = await postForm("/operator/brevo-account", "", { ...accountFields, csrf: "" }, cookie);
    assert.equal(denied.status, 403);
    assert.ok(denied.type.includes("text/html"));
    assert.ok(denied.text.includes("CSRF"));
    assert.equal(denied.text.includes(apiKey), false);
    assert.equal(await scalar("SELECT count(*) FROM relay_connections"), "0");
    assert.equal(brevoCalls, 0);

    const early = await registerCustomer("m6-brevo-early", "Early Co");
    const customerPost = await postForm("/operator/brevo-account", early.token, accountFields);
    assert.equal(customerPost.status, 403);
    assert.ok(customerPost.text.includes("An operator role is required."));
    assert.equal(await scalar("SELECT count(*) FROM relay_connections"), "0");
    assert.equal(brevoCalls, 0);

    const recovery = await postForm("/portal/domain", early.token, { csrf: "1", domain: "recovery-bearportal.com", existingMail: "" });
    assert.equal(recovery.status, 422);
    assert.ok(recovery.text.includes("recovery email"));
    assert.equal(brevoCalls, 0);
    assert.equal(await scalar("SELECT count(*) FROM domains"), "0");

    const waiting = await postForm("/portal/domain", early.token, { csrf: "1", domain: earlyDomain, existingMail: "1" });
    assert.equal(waiting.status, 200);
    assertHonestPage(waiting.text);
    assert.ok(waiting.text.includes("Resources are tight right now."));
    assert.ok(waiting.text.includes("save your setup"));
    assert.equal(waiting.text.includes("Brevo reports verified"), false);
    assert.equal(brevoCalls, 0);
    assert.equal(await scalar(`SELECT state || ':' || existing_mail::text FROM domains WHERE normalized_name = ${sqlText(earlyDomain)}`), "pending:true");
    const domainId = await scalar(`SELECT id FROM domains WHERE normalized_name = ${sqlText(earlyDomain)}`);

    const stored = await postForm("/operator/brevo-account", await adminToken(), accountFields);
    assert.equal(stored.status, 200);
    assertHonestPage(stored.text);
    assert.ok(stored.text.includes("This page did not call Brevo."));
    assert.ok(stored.text.includes("does not publish DNS"));
    assert.ok(stored.text.includes("state is inactive"));
    assert.equal(stored.text.includes("Brevo reports"), false);
    assert.equal(stored.text.includes(apiKey), false);
    assert.equal(stored.text.includes(smtpKey), false);
    assert.equal(brevoCalls, 0);
    assert.equal(await scalar("SELECT state FROM relay_connections"), "inactive");
    assert.equal(await scalar("SELECT count(*) FROM relay_assignments WHERE released_at IS NULL"), "0");
    const again = await postForm("/operator/brevo-account", await adminToken(), accountFields);
    assert.equal(again.status, 200);
    assert.equal(await scalar("SELECT count(*) FROM relay_connections"), "1");
    assert.equal(await scalar("SELECT state FROM relay_connections"), "inactive");

    const checked = await postForm("/portal/domain", early.token, { csrf: "1", domain: earlyDomain, existingMail: "1" });
    assert.equal(checked.status, 200);




    assert.equal(checked.text.includes(apiKey), false);
    assert.equal(checked.text.includes(smtpKey), false);
    assert.equal(brevoCalls, 1);
    assert.equal(await scalar("SELECT state FROM relay_connections"), "assigned");
    assert.equal(await scalar(`SELECT count(*) FROM relay_assignments WHERE organization_id = ${sqlText(early.organizationId)} AND released_at IS NULL`), "1");
    assert.equal(await scalar(`SELECT state FROM domains WHERE normalized_name = ${sqlText(earlyDomain)}`), "pending");
    const report = await scalar("SELECT validation_report::text FROM relay_connections");
    assert.ok(report.includes("brevo_code"));
    assert.ok(report.includes("dkim"));
    assert.ok(report.includes("dmarc"));
    assert.equal(report.includes(apiKey), false);
    assert.equal(report.includes(smtpKey), false);
    const portal = await page("/portal", early.token);
    assert.equal(portal.status, 200);
    assert.ok(portal.text.includes(earlyDomain));
    assert.ok(portal.text.includes("Your account"));
    const beforeDeployment = await api(base, "/v1/portal/overview", { headers: auth(early.token) });
    expectStatus(beforeDeployment, 200);
    assert.equal(beforeDeployment.body.domainName, earlyDomain);
    assert.equal(beforeDeployment.body.domainState, "pending");
    assert.equal(beforeDeployment.body.brevoAuthenticated, false);
    assert.equal(beforeDeployment.body.mailVerified, false);
    assert.equal(beforeDeployment.body.deploymentId, null);

    const deploymentId = await createDeployment(early.token, domainId);
    assert.equal(await scalar(`SELECT version::text FROM deployments WHERE id = ${sqlText(deploymentId)}`), "1");
    assert.equal(await scalar(`SELECT mail_verified::text FROM deployments WHERE id = ${sqlText(deploymentId)}`), "false");
    const copied = await scalar(`SELECT brevo_records::text FROM deployments WHERE id = ${sqlText(deploymentId)}`);
    assert.ok(copied.includes("brevo_code"));
    assert.ok(copied.includes("dkim"));
    assert.ok(copied.includes("dmarc"));
    assert.equal(copied.includes(apiKey), false);
    assert.equal(await scalar(`SELECT brevo_authenticated::text || ':' || brevo_verified::text FROM deployments WHERE id = ${sqlText(deploymentId)}`), "false:false");
    assert.equal(await scalar(`SELECT (relay_connection_id IS NOT NULL)::text FROM deployments WHERE id = ${sqlText(deploymentId)}`), "true");
    const stage = await scalar(`SELECT onboarding_stage || ':' || lifecycle_state FROM deployments WHERE id = ${sqlText(deploymentId)}`);

    operatorBrevoMode = "incomplete";
    const incomplete = await postForm("/portal/domain", early.token, { csrf: "1", domain: earlyDomain, existingMail: "1" });
    assert.equal(incomplete.status, 200);
    assert.equal(brevoCalls, 2);
    const kept = await scalar(`SELECT brevo_records::text FROM deployments WHERE id = ${sqlText(deploymentId)}`);
    assert.ok(kept.includes("brevo_code"));
    assert.ok(kept.includes("dkim"));
    assert.ok(kept.includes("dmarc"));
    assert.equal(await scalar(`SELECT brevo_authenticated::text || ':' || brevo_verified::text || ':' || mail_verified::text FROM deployments WHERE id = ${sqlText(deploymentId)}`), "false:false:false");
    assert.equal(await scalar(`SELECT state FROM domains WHERE normalized_name = ${sqlText(earlyDomain)}`), "pending");

    const replaced = await postForm("/operator/brevo-account", await adminToken(), { ...accountFields, apiKey: rejectedKey, smtpKey: rejectedSmtp });
    assert.equal(replaced.status, 200);
    assert.equal(brevoCalls, 2);
    assert.equal(await scalar("SELECT state FROM relay_connections"), "assigned");
    const rejected = await postForm("/portal/domain", early.token, { csrf: "1", domain: earlyDomain, existingMail: "1" });
    assert.equal(rejected.status, 422);
    assert.ok(rejected.text.includes("Brevo rejected the API key."));
    assert.equal(rejected.text.includes(rejectedKey), false);
    assert.equal(rejected.text.includes(rejectedSmtp), false);
    assert.equal(rejected.text.includes("Brevo reports verified"), false);
    assert.equal(brevoCalls, 3);
    assert.equal(await scalar(`SELECT mail_verified::text FROM deployments WHERE id = ${sqlText(deploymentId)}`), "false");
    assert.equal(await scalar("SELECT count(*) FROM relay_connections"), "1");
    assert.equal(await scalar("SELECT count(*) FROM relay_assignments WHERE released_at IS NULL"), "1");

    operatorBrevoMode = "verified";
    const restored = await postForm("/operator/brevo-account", await adminToken(), { ...accountFields, smtpKey: "smtp-key-m6-again" });
    assert.equal(restored.status, 200);
    assert.equal(brevoCalls, 3);
    const verified = await postForm("/portal/domain", early.token, { csrf: "1", domain: earlyDomain, existingMail: "1" });
    assert.equal(verified.status, 200);
    assert.ok(verified.text.includes("Your domain is saved"));
    assert.ok(verified.text.includes(earlyDomain));

    assert.equal(verified.text.includes("smtp-key-m6-again"), false);
    assert.equal(verified.text.includes(apiKey), false);
    assert.equal(brevoCalls, 4);
    assert.equal(await scalar(`SELECT brevo_authenticated::text || ':' || brevo_verified::text || ':' || mail_verified::text FROM deployments WHERE id = ${sqlText(deploymentId)}`), "true:true:false");
    assert.equal(await scalar(`SELECT state FROM domains WHERE normalized_name = ${sqlText(earlyDomain)}`), "pending");
    assert.equal(await scalar("SELECT state FROM relay_connections"), "assigned");
    assert.equal(await scalar("SELECT count(*) FROM relay_connections"), "1");
    assert.equal(await scalar("SELECT count(*) FROM secret_refs WHERE purpose IN ('brevo-api', 'brevo-smtp')"), "2");
    const repeat = await postForm("/operator/brevo-account", await adminToken(), { ...accountFields, smtpKey: "smtp-key-m6-again" });
    assert.equal(repeat.status, 200);
    assert.equal(brevoCalls, 4);
    assert.equal(await scalar("SELECT count(*) FROM relay_connections"), "1");
    assert.equal(await scalar("SELECT state FROM relay_connections"), "assigned");
    assert.equal(await scalar(`SELECT onboarding_stage || ':' || lifecycle_state FROM deployments WHERE id = ${sqlText(deploymentId)}`), stage);

    const conflict = await postForm("/portal/domain", early.token, { csrf: "1", domain: "other-m6.beta-bearportal.com", existingMail: "" });
    assert.equal(conflict.status, 409);
    assert.ok(conflict.text.includes("This organization already has a domain."));
    assert.equal(brevoCalls, 4);

    const other = await registerCustomer("m6-brevo-other", "Other Co");
    const callsBefore = brevoCalls;
    const jsonDomain = await api(base, "/v1/domains", {
      method: "POST",
      headers: auth(other.token, key("json-domain")),
      body: JSON.stringify({ domain: "json-m6.gamma-bearportal.com", existingMail: false }),
    });
    expectStatus(jsonDomain, 201);
    assert.equal(jsonDomain.body.state, "pending");
    assert.equal(brevoCalls, callsBefore);
    const noAccount = await postForm("/portal/domain", other.token, { csrf: "1", domain: "json-m6.gamma-bearportal.com", existingMail: "" });
    assert.equal(noAccount.status, 200);
    assert.ok(noAccount.text.includes("Resources are tight right now."));
    assert.equal(brevoCalls, callsBefore);
    assert.equal(await scalar(`SELECT count(*) FROM relay_assignments WHERE organization_id = ${sqlText(other.organizationId)} AND released_at IS NULL`), "0");

    const trail = logs();
    for (const secret of [apiKey, smtpKey, rejectedKey, rejectedSmtp, "smtp-key-m6-again"]) {
      assert.equal(trail.includes(secret), false);
    }
  });
});

async function postForm(
  path: string,
  token: string,
  fields: Record<string, string>,
  cookie?: string,
): Promise<{ status: number; text: string; type: string }> {
  const headers: Record<string, string> = { "content-type": "application/x-www-form-urlencoded" };
  if (token) headers.authorization = `Bearer ${token}`;
  if (cookie) headers.cookie = cookie;
  const response = await fetch(`${base}${path}`, {
    method: "POST",
    headers,
    body: new URLSearchParams(fields),
  });
  return { status: response.status, text: await response.text(), type: response.headers.get("content-type") ?? "" };
}
