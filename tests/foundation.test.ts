import { integrationDatabases, queryTestDatabase } from "./helpers/database.ts";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { mkdtempSync, readFileSync, readdirSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";
import { after, before, describe, it } from "node:test";
import { exportSPKI, generateKeyPair, SignJWT, type CryptoKey } from "jose";
import pg from "pg";
import { errorBodySchema } from "../packages/contracts/src/index.ts";
import { migrate } from "../packages/db/src/migrate.ts";
import { SecretStore, loadSecretKey } from "../packages/secrets/src/store.ts";
import { bootstrapAdmin, buildServer, type ApiDeps } from "../apps/api/src/server.ts";

const { databaseUrl, migrationUrl, superDatabaseUrl } = integrationDatabases();
const issuer = "https://test.bearportal.local";
const audience = "bearportal-test";
const secretKeyHex = "ab".repeat(32);
const canary = "CANARY-dns-7QjW";
const adminEmail = "admin@recovery-bearportal.com";
const ownerEmail = "owner-a@recovery-bearportal.com";
const otherEmail = "owner-b@recovery-bearportal.com";
const hosted = "mail-a.alpha-bearportal.com";

const logChunks: Buffer[] = [];
const logStream = new Writable({
  write(chunk, _encoding, callback) {
    logChunks.push(Buffer.from(chunk));
    callback();
  },
});

type ApiResult = { status: number; text: string; body: Record<string, any>; headers: Headers };
type Ids = {
  orgA: string;
  domainA: string;
  dnsA: string;
  secretId: string;
  fileName: string;
  fileBefore: Buffer;
  deploymentA: string;
  jobA: string;
  backupA: string;
  userA: string;
  orgB: string;
  supportId: string;
  invitationToken: string;
};

const ids = {} as Ids;
const issuedTokens: string[] = [];
const responses: string[] = [];

let privateKey: CryptoKey;
let app: Awaited<ReturnType<typeof buildServer>> | undefined;
let base = "";
const pool = new pg.Pool({ connectionString: databaseUrl, max: 4 });

function logs(): string {
  return Buffer.concat(logChunks).toString("utf8");
}

function quoteIdent(name: string): string {
  if (!/^[a-z_][a-z0-9_]*$/.test(name)) throw new Error(`Unsafe identifier ${name}.`);
  return `"${name}"`;
}

async function superQuery(sql: string): Promise<string[][]> {
  return queryTestDatabase(sql, superDatabaseUrl);
}
async function sign(claims: Record<string, unknown> & { sub: string; email: string }): Promise<string> {
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

function now(): number {
  return Math.floor(Date.now() / 1000);
}

async function api(path: string, init: RequestInit = {}): Promise<ApiResult> {
  const headers = new Headers(init.headers);
  if (init.body && !headers.has("content-type")) headers.set("content-type", "application/json");
  const response = await fetch(`${base}${path}`, { ...init, headers });
  const text = await response.text();
  responses.push(text);
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

async function tokenFor(sub: string, email: string, extra: Record<string, unknown> = {}): Promise<string> {
  return sign({
    sub,
    email,
    email_verified: true,
    auth_time: now(),
    amr: ["pwd"],
    ...extra,
  });
}

async function adminToken(): Promise<string> {
  return tokenFor("bootstrap-admin", adminEmail, { amr: ["pwd", "totp"], auth_time: now() });
}

async function invite(email: string, key: string): Promise<string> {
  const response = await api("/v1/admin/invitations", {
    method: "POST",
    headers: auth(await adminToken(), key),
    body: JSON.stringify({ boundEmail: email, expiresInHours: 48 }),
  });
  expectStatus(response, 201);
  assert.equal(typeof response.body.invitationToken, "string");
  issuedTokens.push(response.body.invitationToken);
  return response.body.invitationToken;
}

async function withSettings<T>(settings: Record<string, string>, fn: (db: pg.PoolClient) => Promise<T>): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    for (const [key, value] of Object.entries(settings)) {
      await client.query("SELECT set_config($1, $2, true)", [key, value]);
    }
    const result = await fn(client);
    await client.query("COMMIT");
    return result;
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    await client.query("DISCARD ALL").catch(() => undefined);
    client.release();
  }
}

function customerSettings(userId: string, organizationId: string, email: string, subject: string): Record<string, string> {
  return {
    "bearportal.actor": "customer",
    "bearportal.subject": subject,
    "bearportal.email": email,
    "bearportal.user_id": userId,
    "bearportal.organization_id": organizationId,
    "bearportal.bootstrap": "",
  };
}

describe("M2 foundation A01-A04", { concurrency: false }, () => {
  before(async () => {
    await migrate(migrationUrl);
    await migrate(migrationUrl);
    await superQuery(`TRUNCATE TABLE
      cancellation_schedules, restore_requests, upgrade_plans, cleanup_reports,
      audit_events, idempotency_keys, outbox_events, backups, jobs, dns_connections,
      deployments, secret_refs, domains, server_assignments, allocation_requests,
      invitations, operator_roles, organizations, relay_connections, servers, users,
      diagnoses, provider_attempts
      RESTART IDENTITY CASCADE`);
    await superQuery("UPDATE control_plane_state SET mode = 'normal' WHERE id = 1");
    const pair = await generateKeyPair("RS256", { extractable: true });
    privateKey = pair.privateKey;
    const secretsDir = mkdtempSync(join(tmpdir(), "bearportal-secrets-"));
    const deps: ApiDeps = {
    billingRequired: false,
      databaseUrl,
      secretsDir,
      secretKeyHex,
      jwtPublicKeyPem: await exportSPKI(pair.publicKey),
      issuer,
      audience,
    };
    await bootstrapAdmin(databaseUrl, "bootstrap-admin", adminEmail);
    app = await buildServer(deps, logStream);
    await app.listen({ host: "127.0.0.1", port: 0 });
    const address = app.server.address();
    if (!address || typeof address === "string") throw new Error("The API did not listen on a TCP port.");
    base = `http://127.0.0.1:${address.port}`;
  });

  after(async () => {
    await app?.close();
    await pool.end();
  });

  it("A01 rejects unverified mutation and creates one invited organization", async () => {
    const unverified = await tokenFor("unverified-user", "pending@recovery-bearportal.com", { email_verified: false, amr: ["pwd"] });
    const unverifiedInvite = await invite("pending@recovery-bearportal.com", "invite-unverified");
    const me = await api("/v1/me", { headers: auth(unverified) });
    expectStatus(me, 200);
    assert.equal(me.body.identity.emailVerified, false);
    assert.deepEqual(me.body.roles, []);
    const denied = await api("/v1/organizations", {
      method: "POST",
      headers: auth(unverified, "org-unverified"),
      body: JSON.stringify({ name: "Pending", invitationToken: unverifiedInvite }),
    });
    expectStatus(denied, 403);
    assert.equal(denied.body.error.code, "EMAIL_UNVERIFIED");
    errorBodySchema.parse(denied.body);
    assert.equal(denied.headers.get("x-request-id"), denied.body.requestId);

    const owner = await tokenFor("owner-a", ownerEmail);
    const escalated = await api("/v1/organizations", {
      method: "POST",
      headers: auth(owner, "org-a-bad-body"),
      body: JSON.stringify({ name: "Alpha", invitationToken: "x".repeat(20), role: "platform_administrator" }),
    });
    expectStatus(escalated, 400);
    assert.equal(escalated.body.error.code, "VALIDATION");

    const invitation = await invite(ownerEmail, "invite-owner-a");
    const wrong = await api("/v1/organizations", {
      method: "POST",
      headers: auth(owner, "org-a-wrong-invite"),
      body: JSON.stringify({ name: "Alpha", invitationToken: unverifiedInvite }),
    });
    expectStatus(wrong, 403);
    assert.equal(wrong.body.error.code, "INVITATION_INVALID");

    const created = await api("/v1/organizations", {
      method: "POST",
      headers: auth(owner, "org-a-create"),
      body: JSON.stringify({ name: "Alpha Mail", invitationToken: invitation }),
    });
    expectStatus(created, 201);
    assert.equal(created.body.allocationState, "waiting_for_server");
    assert.equal(created.body.server, null);
    ids.orgA = created.body.id;

    const replay = await api("/v1/organizations", {
      method: "POST",
      headers: auth(owner, "org-a-create"),
      body: JSON.stringify({ name: "Alpha Mail", invitationToken: invitation }),
    });
    expectStatus(replay, 201);
    assert.equal(replay.body.id, ids.orgA);

    const conflict = await api("/v1/organizations", {
      method: "POST",
      headers: auth(owner, "org-a-create"),
      body: JSON.stringify({ name: "Different", invitationToken: invitation }),
    });
    expectStatus(conflict, 409);
    assert.equal(conflict.body.error.code, "IDEMPOTENCY_CONFLICT");

    const second = await api("/v1/organizations", {
      method: "POST",
      headers: auth(owner, "org-a-second"),
      body: JSON.stringify({ name: "Alpha Again", invitationToken: invitation }),
    });
    expectStatus(second, 409);
    assert.equal(second.body.error.code, "ORGANIZATION_EXISTS");

    const profile = await api("/v1/me", { headers: auth(owner) });
    expectStatus(profile, 200);
    assert.deepEqual(profile.body.roles, []);
    assert.equal(profile.body.organizationId, ids.orgA);
    assert.equal(profile.body.allocationState, "waiting_for_server");
    ids.userA = await userId("owner-a");

    const inside = await api("/v1/domains", {
      method: "POST",
      headers: auth(owner, "domain-inside"),
      body: JSON.stringify({ domain: "recovery-bearportal.com", existingMail: false }),
    });
    expectStatus(inside, 422);
    assert.equal(inside.body.error.code, "RECOVERY_EMAIL_INSIDE_DOMAIN");

    const child = await tokenFor("child-owner", "person@box.mail-a.alpha-bearportal.com");
    const childInvite = await invite("person@box.mail-a.alpha-bearportal.com", "invite-child");
    const childOrg = await api("/v1/organizations", {
      method: "POST",
      headers: auth(child, "org-child"),
      body: JSON.stringify({ name: "Child", invitationToken: childInvite }),
    });
    expectStatus(childOrg, 201);
    const nested = await api("/v1/domains", {
      method: "POST",
      headers: auth(child, "domain-nested"),
      body: JSON.stringify({ domain: hosted, existingMail: true }),
    });
    expectStatus(nested, 422);
    assert.equal(nested.body.error.code, "RECOVERY_EMAIL_INSIDE_DOMAIN");

    const domain = await api("/v1/domains", {
      method: "POST",
      headers: auth(owner, "domain-a"),
      body: JSON.stringify({ domain: "Mail-A.Alpha-Bearportal.com.", existingMail: false }),
    });
    expectStatus(domain, 201);
    assert.equal(domain.body.domain, hosted);
    ids.domainA = domain.body.id;
    const orgs = await withSettings(customerSettings(ids.userA, ids.orgA, ownerEmail, "owner-a"), async (db) => {
      const result = await db.query("SELECT count(*)::int AS n FROM organizations");
      return result.rows[0].n as number;
    });
    assert.equal(orgs, 1);
  });

  it("A02 hides the first tenant and rejects cross-tenant associations", async () => {
    const owner = await tokenFor("owner-a", ownerEmail);
    const stored = await api("/v1/dns-connections", {
      method: "POST",
      headers: auth(owner, "dns-a-canary"),
      body: JSON.stringify({
        domainId: ids.domainA,
        provider: "namecom",
        zoneId: "alpha-bearportal.com",
        credentials: { username: "portal-namecom", token: canary },
      }),
    });
    expectStatus(stored, 201);
    assert.equal(stored.text.includes(canary), false);
    ids.dnsA = stored.body.id;
    const secret = await withSettings(customerSettings(ids.userA, ids.orgA, ownerEmail, "owner-a"), async (db) => {
      const result = await db.query<{ secret_ref: string; file_name: string }>(
        "SELECT secret_ref, file_name FROM dns_connections c JOIN secret_refs s ON s.id = c.secret_ref WHERE c.id = $1",
        [ids.dnsA],
      );
      return result.rows[0]!;
    });
    ids.secretId = secret.secret_ref;
    ids.fileName = secret.file_name;
    const storeDir = findSecretsDir(ids.fileName);
    ids.fileBefore = readFileSync(join(storeDir, ids.fileName));
    assert.equal(ids.fileBefore.includes(Buffer.from(canary)), false);
    assert.equal(statSync(join(storeDir, ids.fileName)).mode & 0o777, 0o600);
    assert.equal(statSync(storeDir).mode & 0o777, 0o700);

    const seeded = await withSettings(customerSettings(ids.userA, ids.orgA, ownerEmail, "owner-a"), async (db) => {
      const deploymentId = randomUUID();
      const jobId = randomUUID();
      const backupId = randomUUID();
      await db.query(
        `INSERT INTO deployments (id, organization_id, domain_id, desired_state, onboarding_stage, lifecycle_state, health_state)
         VALUES ($1, $2, $3, 'draft', 'draft', 'draft', 'unknown')`,
        [deploymentId, ids.orgA, ids.domainA],
      );
      await db.query(
        `INSERT INTO jobs (id, organization_id, deployment_id, kind, state) VALUES ($1, $2, $3, 'install', 'pending')`,
        [jobId, ids.orgA, deploymentId],
      );
      await db.query(
        `INSERT INTO backups (id, organization_id, deployment_id, evidence_source, state) VALUES ($1, $2, $3, 'operator', 'recorded')`,
        [backupId, ids.orgA, deploymentId],
      );
      return { deploymentId, jobId, backupId };
    });
    ids.deploymentA = seeded.deploymentId;
    ids.jobA = seeded.jobId;
    ids.backupA = seeded.backupId;

    const otherInvite = await invite(otherEmail, "invite-owner-b");
    const other = await tokenFor("owner-b", otherEmail);
    const otherOrg = await api("/v1/organizations", {
      method: "POST",
      headers: auth(other, "org-b-create"),
      body: JSON.stringify({ name: "Beta Mail", invitationToken: otherInvite }),
    });
    expectStatus(otherOrg, 201);
    ids.orgB = otherOrg.body.id;
    const otherDomain = await api("/v1/domains", {
      method: "POST",
      headers: auth(other, "domain-b"),
      body: JSON.stringify({ domain: "mail-b.beta-bearportal.com", existingMail: false }),
    });
    expectStatus(otherDomain, 201);
    const userB = await userId("owner-b");

    for (const path of [
      `/v1/domains/${ids.domainA}`,
      `/v1/dns-connections/${ids.dnsA}`,
      `/v1/jobs/${ids.jobA}`,
      `/v1/deployments/${ids.deploymentA}`,
      `/v1/deployments/${ids.deploymentA}/events`,
      `/v1/deployments/${ids.deploymentA}/backups`,
    ]) {
      const hidden = await api(path, { headers: auth(other) });
      expectStatus(hidden, 404);
      assert.equal(hidden.body.error.code, "NOT_FOUND");
    }
    const stream = await api(`/v1/deployments/${ids.deploymentA}/events/stream`, { headers: auth(other) });
    expectStatus(stream, 404);
    assert.equal(stream.headers.get("content-type")?.includes("text/event-stream"), false);
    const ownStream = await api(`/v1/deployments/${ids.deploymentA}/events/stream`, { headers: auth(owner) });
    expectStatus(ownStream, 200);
    assert.match(ownStream.headers.get("content-type") ?? "", /text\/event-stream/);
    assert.match(ownStream.text, /event: ready/);

    const rotate = await api(`/v1/dns-connections/${ids.dnsA}/rotate`, {
      method: "POST",
      headers: auth(other, "rotate-cross-tenant"),
      body: JSON.stringify({ credentials: { username: "portal-namecom", token: "other-token" }, expectedVersion: 1 }),
    });
    expectStatus(rotate, 404);

    const visibleToB = await withSettings(customerSettings(userB, ids.orgB, otherEmail, "owner-b"), async (db) => {
      const domains = await db.query("SELECT id FROM domains WHERE id = $1", [ids.domainA]);
      const secrets = await db.query("SELECT id FROM secret_refs WHERE id = $1", [ids.secretId]);
      const jobs = await db.query("SELECT id FROM jobs WHERE id = $1", [ids.jobA]);
      const updated = await db.query("UPDATE domains SET state = 'verified' WHERE id = $1", [ids.domainA]);
      return { domains: domains.rowCount, secrets: secrets.rowCount, jobs: jobs.rowCount, updated: updated.rowCount };
    });
    assert.deepEqual(visibleToB, { domains: 0, secrets: 0, jobs: 0, updated: 0 });

    await assert.rejects(
      () => withSettings(customerSettings(userB, ids.orgB, otherEmail, "owner-b"), (db) => db.query(
        `INSERT INTO jobs (id, organization_id, deployment_id, kind, state) VALUES ($1, $2, $3, 'install', 'pending')`,
        [randomUUID(), ids.orgB, ids.deploymentA],
      )),
      (error: unknown) => (error as { code?: string }).code === "23503",
    );
    const ownSecret = await withSettings(customerSettings(userB, ids.orgB, otherEmail, "owner-b"), async (db) => {
      const secretId = randomUUID();
      await db.query(
        `INSERT INTO secret_refs (id, organization_id, purpose, file_name, key_id, state)
         VALUES ($1, $2, 'dns', $3, 'local-1', 'active')`,
        [secretId, ids.orgB, `${randomUUID()}.bin`],
      );
      return secretId;
    });
    await assert.rejects(
      () => withSettings(customerSettings(userB, ids.orgB, otherEmail, "owner-b"), (db) => db.query(
        `INSERT INTO dns_connections (id, organization_id, domain_id, provider, zone_id, secret_ref, state)
         VALUES ($1, $2, $3, 'namecom', 'beta-bearportal.com', $4, 'stored')`,
        [randomUUID(), ids.orgB, ids.domainA, ownSecret],
      )),
      (error: unknown) => (error as { code?: string }).code === "23503",
    );
    await assert.rejects(
      () => withSettings(customerSettings(userB, ids.orgB, otherEmail, "owner-b"), (db) => db.query(
        `INSERT INTO domains (id, organization_id, normalized_name, existing_mail, state)
         VALUES ($1, $2, 'stolen.alpha-bearportal.com', false, 'pending')`,
        [randomUUID(), ids.orgA],
      )),
      (error: unknown) => (error as { code?: string }).code === "42501",
    );
  });

  it("A03 takes roles from the database and keeps support away from credentials", async () => {
    const claimed = await tokenFor("owner-a", ownerEmail, { role: "platform_administrator", roles: ["platform_administrator"], amr: ["pwd", "totp"] });
    const me = await api("/v1/me", { headers: auth(claimed) });
    expectStatus(me, 200);
    assert.deepEqual(me.body.roles, []);
    const customerAdmin = await api("/v1/admin/invitations", {
      method: "POST",
      headers: auth(claimed, "customer-cannot-invite"),
      body: JSON.stringify({ boundEmail: "nobody@recovery-bearportal.com" }),
    });
    expectStatus(customerAdmin, 403);

    const stale = await tokenFor("bootstrap-admin", adminEmail, { amr: ["pwd", "totp"], auth_time: now() - 16 * 60 });
    const staleInvite = await api("/v1/admin/invitations", {
      method: "POST",
      headers: auth(stale, "invite-stale-mfa"),
      body: JSON.stringify({ boundEmail: "stale@recovery-bearportal.com" }),
    });
    expectStatus(staleInvite, 403);
    assert.equal(staleInvite.body.error.code, "MFA_REQUIRED");
    const noMfa = await tokenFor("bootstrap-admin", adminEmail, { amr: ["pwd"], auth_time: now() });
    const noMfaRead = await api(`/v1/admin/secret-refs/${ids.secretId}`, { headers: auth(noMfa) });
    expectStatus(noMfaRead, 403);
    assert.equal(noMfaRead.body.error.code, "MFA_REQUIRED");

    const firstInvite = await api("/v1/admin/invitations", {
      method: "POST",
      headers: auth(await adminToken(), "invite-replay"),
      body: JSON.stringify({ boundEmail: "replay@recovery-bearportal.com", expiresInHours: 24 }),
    });
    expectStatus(firstInvite, 201);
    issuedTokens.push(firstInvite.body.invitationToken);
    const replayInvite = await api("/v1/admin/invitations", {
      method: "POST",
      headers: auth(await adminToken(), "invite-replay"),
      body: JSON.stringify({ boundEmail: "replay@recovery-bearportal.com", expiresInHours: 24 }),
    });
    expectStatus(replayInvite, 201);
    assert.equal(replayInvite.body.invitationToken, undefined);
    assert.equal(replayInvite.body.tokenReplayable, false);
    assert.equal(replayInvite.body.id, firstInvite.body.id);

    const supportEmail = "support-operator@recovery-bearportal.com";
    const support = await tokenFor("support-user", supportEmail, { role: "platform_administrator" });
    const supportMe = await api("/v1/me", { headers: auth(support) });
    expectStatus(supportMe, 200);
    assert.deepEqual(supportMe.body.roles, []);
    ids.supportId = await userId("support-user");
    const granted = await api("/v1/admin/operator-roles", {
      method: "POST",
      headers: auth(await adminToken(), "grant-support"),
      body: JSON.stringify({ userId: ids.supportId, role: "support", reason: "beta support desk" }),
    });
    expectStatus(granted, 201);
    const supportAgain = await api("/v1/me", { headers: auth(support) });
    assert.deepEqual(supportAgain.body.roles, ["support"]);
    const supportSecret = await api(`/v1/admin/secret-refs/${ids.secretId}`, {
      headers: auth(await tokenFor("support-user", supportEmail, { amr: ["pwd", "totp"], auth_time: now() })),
    });
    expectStatus(supportSecret, 403);
    assert.equal(supportSecret.body.error.code, "FORBIDDEN");
    const supportInvite = await api("/v1/admin/invitations", {
      method: "POST",
      headers: auth(await tokenFor("support-user", supportEmail, { amr: ["pwd", "totp"], auth_time: now() }), "support-invite"),
      body: JSON.stringify({ boundEmail: "another@recovery-bearportal.com" }),
    });
    expectStatus(supportInvite, 403);

    const hidden = await withSettings({
      "bearportal.actor": "support",
      "bearportal.subject": "support-user",
      "bearportal.email": supportEmail,
      "bearportal.user_id": ids.supportId,
      "bearportal.organization_id": "",
      "bearportal.bootstrap": "",
    }, async (db) => {
      const read = await db.query("SELECT id FROM secret_refs WHERE id = $1", [ids.secretId]);
      const updated = await db.query("UPDATE secret_refs SET state = 'retired' WHERE id = $1", [ids.secretId]);
      return { read: read.rowCount, updated: updated.rowCount };
    });
    assert.deepEqual(hidden, { read: 0, updated: 0 });
    await assert.rejects(
      () => withSettings({
        "bearportal.actor": "support",
        "bearportal.subject": "support-user",
        "bearportal.email": supportEmail,
        "bearportal.user_id": ids.supportId,
        "bearportal.organization_id": "",
        "bearportal.bootstrap": "",
      }, (db) => db.query(
        `INSERT INTO secret_refs (id, organization_id, purpose, file_name, key_id, state)
         VALUES ($1, NULL, 'dns', $2, 'local-1', 'active')`,
        [randomUUID(), `${randomUUID()}.bin`],
      )),
      (error: unknown) => (error as { code?: string }).code === "42501",
    );

    const metadata = await api(`/v1/admin/secret-refs/${ids.secretId}`, { headers: auth(await adminToken()) });
    expectStatus(metadata, 200);
    assert.deepEqual(Object.keys(metadata.body).sort(), ["id", "purpose", "requestId", "state", "version"]);
    assert.equal(metadata.text.includes(canary), false);
    assert.equal(metadata.text.includes(ids.fileName), false);
  });

  it("A04 keeps the canary out of ordinary records and preserves a rejected rotation", async () => {
    const owner = await tokenFor("owner-a", ownerEmail);
    const rejected = await api(`/v1/dns-connections/${ids.dnsA}/rotate`, {
      method: "POST",
      headers: auth(owner, "rotate-reject"),
      body: JSON.stringify({ credentials: { username: "portal-namecom", token: "reject:replacement" }, expectedVersion: 1 }),
    });
    expectStatus(rejected, 200);
    assert.equal(rejected.body.rotated, false);
    assert.equal(rejected.body.version, 1);
    assert.equal(rejected.text.includes(canary), false);
    assert.equal(rejected.text.includes("reject:replacement"), false);
    const current = await api(`/v1/dns-connections/${ids.dnsA}`, { headers: auth(owner) });
    expectStatus(current, 200);
    assert.equal(current.body.version, 1);
    const storeDir = findSecretsDir(ids.fileName);
    const afterBytes = readFileSync(join(storeDir, ids.fileName));
    assert.deepEqual(afterBytes, ids.fileBefore);
    const opened = new SecretStore(storeDir, loadSecretKey(secretKeyHex)).read(ids.fileName);
    assert.equal(JSON.parse(opened).token, canary);

    for (const response of responses) assert.equal(response.includes(canary), false, response.slice(0, 180));
    const logText = logs();
    assert.equal(logText.includes(canary), false);
    assert.equal(logText.includes("reject:replacement"), false);
    for (const token of issuedTokens) assert.equal(logText.includes(token), false);

    const hits = await scanText(canary);
    assert.deepEqual(hits, []);
    for (const token of issuedTokens) {
      assert.deepEqual(await scanText(token), [], token);
    }
    assert.equal(existsDockerfile(), false);
  });

  it("enforces CSRF, RLS, and the credential rate limit", async () => {
    const roles = await superQuery(`SELECT rolname || ':' || rolsuper::text || ':' || rolbypassrls::text || ':' || rolcanlogin::text
      FROM pg_roles WHERE rolname IN ('bearportal', 'bearportal_app') ORDER BY rolname`);
    assert.deepEqual(roles.map((row) => row[0]), [
      "bearportal:false:false:true",
      "bearportal_app:false:false:true",
    ]);
    const forced = await superQuery(`SELECT c.relname FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = 'public' AND c.relkind = 'r' AND NOT (c.relrowsecurity AND c.relforcerowsecurity)
      ORDER BY 1`);
    assert.deepEqual(forced.map((row) => row[0]), ["schema_migrations"]);

    const owner = new pg.Client({ connectionString: migrationUrl });
    await owner.connect();
    try {
      const visible = await owner.query("SELECT count(*)::int AS n FROM users");
      assert.equal(visible.rows[0].n, 0);
      await owner.query("BEGIN");
      await owner.query("SET LOCAL row_security = off");
      await assert.rejects(
        () => owner.query("SELECT count(*)::int AS n FROM users"),
        (error: unknown) => (error as { code?: string }).code === "42501",
      );
      await owner.query("ROLLBACK");
    } finally {
      await owner.end();
    }
    const bare = new pg.Client({ connectionString: databaseUrl });
    await bare.connect();
    try {
      const count = await bare.query("SELECT count(*)::int AS n FROM users");
      assert.equal(count.rows[0].n, 0);
      await assert.rejects(() => bare.query("ALTER TABLE users DISABLE ROW LEVEL SECURITY"));
    } finally {
      await bare.end();
    }

    const cookieUser = await tokenFor("cookie-user", "cookie@recovery-bearportal.com");
    const invitation = await invite("cookie@recovery-bearportal.com", "invite-cookie");
    const session = await api("/v1/session", { method: "POST", body: JSON.stringify({ idToken: cookieUser }) });
    expectStatus(session, 200);
    const setCookie = session.headers.getSetCookie?.() ?? [];
    const cookie = setCookie.find((value) => value.startsWith("bp_session="));
    assert.ok(cookie);
    assert.match(cookie, /HttpOnly/i);
    assert.match(cookie, /SameSite=Lax/i);
    const denied = await api("/v1/organizations", {
      method: "POST",
      headers: { cookie: cookie.split(";")[0]!, "idempotency-key": "cookie-org" },
      body: JSON.stringify({ name: "Cookie Org", invitationToken: invitation }),
    });
    expectStatus(denied, 403);
    assert.equal(denied.body.error.code, "CSRF");
    const allowed = await api("/v1/organizations", {
      method: "POST",
      headers: { cookie: cookie.split(";")[0]!, "idempotency-key": "cookie-org", "x-bearportal-csrf": "1" },
      body: JSON.stringify({ name: "Cookie Org", invitationToken: invitation }),
    });
    expectStatus(allowed, 201);

    await assert.rejects(() => bootstrapAdmin(databaseUrl, "second-admin", "second@recovery-bearportal.com"), /already exists/);

    const limitedEmail = "owner-c@recovery-bearportal.com";
    const limited = await tokenFor("owner-c", limitedEmail);
    const limitedInvite = await invite(limitedEmail, "invite-owner-c");
    const limitedOrg = await api("/v1/organizations", {
      method: "POST",
      headers: auth(limited, "org-c-create"),
      body: JSON.stringify({ name: "Gamma", invitationToken: limitedInvite }),
    });
    expectStatus(limitedOrg, 201);
    const limitedDomain = await api("/v1/domains", {
      method: "POST",
      headers: auth(limited, "domain-c"),
      body: JSON.stringify({ domain: "mail-c.gamma-bearportal.com", existingMail: false }),
    });
    expectStatus(limitedDomain, 201);
    const first = await api("/v1/dns-connections", {
      method: "POST",
      headers: auth(limited, "dns-c-create"),
      body: JSON.stringify({
        domainId: limitedDomain.body.id,
        provider: "hostinger",
        zoneId: "gamma-bearportal.com",
        credentials: { token: "ordinary-token" },
      }),
    });
    expectStatus(first, 201);
    for (let attempt = 0; attempt < 9; attempt += 1) {
      const rotate = await api(`/v1/dns-connections/${first.body.id}/rotate`, {
        method: "POST",
        headers: auth(limited, `rotate-c-${attempt}`),
        body: JSON.stringify({ credentials: { token: "reject:limit" }, expectedVersion: 1 }),
      });
      expectStatus(rotate, 200);
      assert.equal(rotate.body.rotated, false);
    }
    const blocked = await api(`/v1/dns-connections/${first.body.id}/rotate`, {
      method: "POST",
      headers: auth(limited, "rotate-c-blocked"),
      body: JSON.stringify({ credentials: { token: "reject:limit" }, expectedVersion: 1 }),
    });
    expectStatus(blocked, 429);
    assert.equal(blocked.body.error.code, "RATE_LIMITED");
    assert.equal(blocked.body.error.retryable, true);
    const still = await api(`/v1/dns-connections/${first.body.id}`, { headers: auth(limited) });
    expectStatus(still, 200);
    assert.equal(still.body.version, 1);
  });
});

async function userId(subject: string): Promise<string> {
  const rows = await superQuery(`SELECT id::text FROM users WHERE identity_subject = '${subject}'`);
  const id = rows[0]?.[0];
  if (!id) throw new Error(`No user for ${subject}.`);
  return id;
}

function findSecretsDir(fileName: string): string {
  const root = tmpdir();
  const matches = readdirSync(root).filter((name) => name.startsWith("bearportal-secrets-"));
  for (const name of matches) {
    const dir = join(root, name);
    if (readdirSync(dir).includes(fileName)) return dir;
  }
  throw new Error(`Secret file ${fileName} was not found.`);
}

let textColumns: Array<[string, string]> | undefined;

async function scanText(needle: string): Promise<string[]> {
  if (!/^[A-Za-z0-9:-]+$/.test(needle)) throw new Error("Refusing to scan an unsafe needle.");
  if (!textColumns) {
    textColumns = (await superQuery(`
      SELECT table_name, column_name
      FROM information_schema.columns
      WHERE table_schema = 'public'
        AND data_type IN ('text', 'character varying', 'jsonb', 'json')
      ORDER BY table_name, column_name`)).map((row) => [row[0]!, row[1]!]);
  }
  const query = textColumns.map(([table, column]) =>
    `SELECT '${table}.${column}' WHERE EXISTS (SELECT 1 FROM public.${quoteIdent(table)} WHERE strpos(${quoteIdent(column)}::text, '${needle}') > 0)`,
  ).join("\nUNION ALL\n");
  const found = await superQuery(query);
  return found.map((row) => row[0]!).filter((name) => name.length > 0);
}

function existsDockerfile(): boolean {
  try {
    statSync(new URL("../Dockerfile", import.meta.url));
    return true;
  } catch {
    return false;
  }
}
