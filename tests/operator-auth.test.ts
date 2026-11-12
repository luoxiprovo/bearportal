import assert from "node:assert/strict";
import { test } from "node:test";
import { randomUUID } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";
import { generateKeyPair, exportSPKI, SignJWT } from "jose";
import { buildServer, bootstrapAdmin } from "../apps/api/src/server.ts";
import {
  createIdentityVerifier,
  type IdentityPlatformClient,
  type IdentityTokens,
} from "../apps/api/src/identity-platform-client.ts";
import {
  newAuthenticator,
  verifyAuthenticator,
  hashToken,
} from "../apps/api/src/operator-totp.ts";
import { authorizeOperator } from "../scripts/operator-access.ts";
import { migrate } from "../packages/db/src/migrate.ts";
import { integrationDatabases, queryTestDatabase } from "./helpers/database.ts";
const { databaseUrl, migrationUrl, superDatabaseUrl } = integrationDatabases();
const query = (sql: string) => queryTestDatabase(sql, superDatabaseUrl);
const q = (s: string) => "'" + s.replaceAll("'", "''") + "'";

test("production operator identity authorization, encrypted enrollment, MFA session binding, lockouts, replay protection and recovery", async () => {
  await migrate(migrationUrl);
  await query(
    "TRUNCATE users,organizations,servers,relay_connections,domains,secret_refs,deployments,jobs,operator_roles,allocation_requests,invitations,idempotency_keys,audit_events,outbox_events,operator_authorizations CASCADE",
  );
  await query("UPDATE control_plane_state SET mode='normal' WHERE id=1");
  const legacy = await bootstrapAdmin(
    databaseUrl,
    "old-bootstrap-admin",
    "old-admin@example.org",
  );
  const keys = await generateKeyPair("RS256", { extractable: true });
  const remote = await generateKeyPair("RS256", { extractable: true });
  const config = {
    projectId: "bearportal-operator-test",
    apiKey: "operator-test-public-api-key",
    googleClientId: "operator-client.apps.googleusercontent.com",
    origins: ["https://portal.example.org"],
  };
  const issuer = "https://securetoken.google.com/" + config.projectId;
  const refresh = new Map<string, IdentityTokens>();
  async function issue(
    uid: string,
    email: string,
    verified = true,
    provider = "google.com",
  ) {
    const idToken = await new SignJWT({
      email,
      email_verified: verified,
      auth_time: Math.floor(Date.now() / 1000),
      firebase: { sign_in_provider: provider },
      amr: ["totp"],
    })
      .setSubject(uid)
      .setProtectedHeader({ alg: "RS256" })
      .setIssuer(issuer)
      .setAudience(config.projectId)
      .setIssuedAt()
      .setExpirationTime("1h")
      .sign(remote.privateKey);
    const tokens = { idToken, refreshToken: "refresh-" + randomUUID() };
    refresh.set(tokens.refreshToken, tokens);
    return tokens;
  }
  const identity: IdentityPlatformClient = {
    verify: createIdentityVerifier(config, remote.publicKey),
    google: async (credential) => ({
      ...(await issue(credential, credential + "@example.org")),
      authoritativeEmail: true,
    }),
    password: async (email, _password) =>
      issue(email.split("@")[0]!, email, true, "password"),
    refresh: async (token) => refresh.get(token)!,
    sendVerification: async () => {},
    resetPassword: async () => {},
  };
  const logs: Buffer[] = [];
  const app = await buildServer(
    {
      databaseUrl,
      secretKeyHex: "ab".repeat(32),
      secretsDir: mkdtempSync(join(tmpdir(), "bearportal-operator-auth-")),
      jwtPublicKeyPem: await exportSPKI(keys.publicKey),
      issuer: "https://old.test",
      audience: "old",
      identityPlatform: config,
      identityPlatformClient: identity,
      onboardingIntervalMs: 0,
      billingRequired: true,
    },
    new Writable({
      write(chunk, _enc, done) {
        logs.push(Buffer.from(chunk));
        done();
      },
    }),
  );
  function browser() {
    const jar = new Map<string, string>();
    async function request(
      method: "GET" | "POST",
      url: string,
      body?: Record<string, unknown>,
      extra: Record<string, string> = {},
    ) {
      const response = await app.inject({
        method,
        url,
        headers: {
          cookie: [...jar].map(([k, v]) => k + "=" + v).join("; "),
          ...extra,
        },
        ...(body === undefined ? {} : { payload: body }),
      });
      const cookies = response.headers["set-cookie"];
      for (const raw of Array.isArray(cookies)
        ? cookies
        : cookies
          ? [cookies]
          : []) {
        const entry = String(raw).split(";")[0]!;
        const i = entry.indexOf("=");
        const key = entry.slice(0, i),
          value = entry.slice(i + 1);
        if (value) jar.set(key, value);
        else jar.delete(key);
      }
      return response;
    }
    async function post(url: string, body: Record<string, unknown>) {
      const opts = await request("GET", "/auth/options");
      assert.equal(opts.statusCode, 200);
      return request("POST", url, body, {
        origin: config.origins[0]!,
        "x-bearportal-auth-csrf": opts.json().csrf,
      });
    }
    return { jar, request, post };
  }
  try {
    assert.equal(
      (await app.inject("/operator")).headers.location,
      "/operator/login",
    );
    const ordinary = browser();
    assert.equal(
      (await ordinary.post("/auth/google", { credential: "ordinary" })).json()
        .redirect,
      "/portal",
    );
    assert.equal(
      (await ordinary.post("/auth/operator/enroll", {})).statusCode,
      403,
    );
    await authorizeOperator(migrationUrl, issuer, {
      email: "owner@example.org",
      role: "platform_administrator",
      reason: "Initial production setup",
      reuseBootstrapAdmin: true,
    });
    assert.deepEqual(
      await query(
        "SELECT count(*) FROM operator_roles WHERE revoked_at IS NULL",
      ),
      [["1"]],
    );
    const owner = browser();
    const login = await owner.post("/auth/google", { credential: "owner" });
    assert.equal(login.statusCode, 200, login.body);
    assert.equal(login.json().redirect, "/operator/security");
    assert.deepEqual(
      await query(
        "SELECT user_id FROM identity_accounts WHERE subject='owner'",
      ),
      [[legacy.userId]],
    );
    assert.deepEqual(
      await query(
        "SELECT count(*) FROM organizations WHERE owner_user_id=" +
          q(legacy.userId),
      ),
      [["0"]],
    );
    assert.equal(
      (await owner.request("GET", "/operator")).headers.location,
      "/operator/security",
    );
    assert.equal(
      (await owner.request("GET", "/v1/admin/portal")).statusCode,
      403,
      "signed upstream amr cannot grant MFA",
    );
    assert.equal(
      (await owner.request("GET", "/auth/operator/status")).json().enrolled,
      false,
    );
    assert.equal(
      (await owner.request("POST", "/auth/operator/enroll", {})).statusCode,
      403,
      "CSRF required",
    );
    const started = await owner.post("/auth/operator/enroll", {});
    assert.equal(started.statusCode, 200, started.body);
    assert.match(started.headers["cache-control"] as string, /no-store/);
    const seed = started.json().secret as string;
    assert.match(started.json().qrDataUrl, /^data:image\/svg\+xml;base64,/);
    const stored = (
      await query(
        "SELECT encode(secret,'hex') FROM operator_totp WHERE user_id=" +
          q(legacy.userId),
      )
    )[0]![0]!;
    assert.equal(
      Buffer.from(stored, "hex").includes(Buffer.from(seed)),
      false,
      "TOTP seed is encrypted at rest",
    );
    const otherBrowser = browser();
    await otherBrowser.post("/auth/google", { credential: "owner" });
    assert.equal(
      (await otherBrowser.post("/auth/operator/enroll", {})).statusCode,
      409,
    );
    const code = newAuthenticator("", seed).generate();
    assert.equal(
      (await otherBrowser.post("/auth/operator/verify", { code })).statusCode,
      409,
      "enrollment belongs to the original browser",
    );
    let invalid = "000000";
    while (verifyAuthenticator(seed, invalid, -1) !== null)
      invalid = String(Number(invalid) + 1).padStart(6, "0");
    for (let i = 0; i < 5; i++)
      assert.equal(
        (await owner.post("/auth/operator/verify", { code: invalid }))
          .statusCode,
        i === 4 ? 429 : 400,
      );
    assert.deepEqual(
      await query(
        "SELECT failed_attempts FROM operator_totp WHERE user_id=" +
          q(legacy.userId),
      ),
      [["5"]],
    );
    assert.equal(
      (await owner.post("/auth/operator/verify", { code })).statusCode,
      429,
      "lockout persists for valid codes too",
    );
    await query(
      "UPDATE operator_totp SET locked_until=now()-interval '1 second' WHERE user_id=" +
        q(legacy.userId),
    );
    const confirmed = await owner.post("/auth/operator/verify", {
      code: newAuthenticator("", seed).generate(),
    });
    assert.equal(confirmed.statusCode, 200, confirmed.body);
    const codes = confirmed.json().recoveryCodes as string[];
    assert.equal(codes.length, 10);
    assert.match(String(confirmed.headers["set-cookie"]), /Secure/);
    assert.match(String(confirmed.headers["set-cookie"]), /HttpOnly/);
    const inventory = await owner.request("GET", "/operator");
    assert.equal(inventory.statusCode, 200, inventory.body);
    assert.match(inventory.body, /Add server/);
    assert.match(inventory.body, /Add Brevo account/);
    assert.equal(
      (await owner.post("/auth/operator/enroll", {})).statusCode,
      409,
      "cannot replace an enrolled factor",
    );
    const replay = await otherBrowser.post("/auth/operator/verify", {
      code: newAuthenticator("", seed).generate(),
    });
    assert.equal(replay.statusCode, 400, "TOTP cannot be replayed");
    const recovery = await otherBrowser.post("/auth/operator/verify", {
      code: codes[0],
    });
    assert.equal(recovery.statusCode, 200, recovery.body);
    assert.deepEqual(
      await query(
        "SELECT cardinality(recovery_hashes) FROM operator_totp WHERE user_id=" +
          q(legacy.userId),
      ),
      [["9"]],
    );
    assert.equal(
      (await otherBrowser.post("/auth/operator/verify", { code: codes[0] }))
        .statusCode,
      400,
      "recovery code cannot be reused",
    );
    // Session is identity-bound, cannot be passed to another authorized operator.
    await authorizeOperator(migrationUrl, issuer, {
      email: "second@example.org",
      role: "infrastructure_operator",
      reason: "Second operator test",
    });
    const second = browser();
    assert.equal(
      (await second.post("/auth/google", { credential: "second" })).json()
        .redirect,
      "/operator/security",
    );
    second.jar.set("bp_operator_mfa", owner.jar.get("bp_operator_mfa")!);
    assert.equal(
      (await second.request("GET", "/v1/admin/portal")).statusCode,
      403,
    );
    // A refreshed ID token retains its independent MFA session.
    assert.equal((await owner.post("/auth/refresh", {})).statusCode, 200);
    assert.equal((await owner.request("GET", "/operator")).statusCode, 200);
    const sessionHash = hashToken(
      decodeURIComponent(owner.jar.get("bp_operator_mfa")!),
    );
    await query(
      "UPDATE operator_mfa_sessions SET authenticated_at=now()-interval '20 minutes' WHERE token_hash=" +
        q(sessionHash),
    );
    assert.equal(
      (await owner.request("GET", "/operator")).statusCode,
      200,
      "inventory uses the existing two-hour MFA window",
    );
    const sensitive = await owner.request(
      "POST",
      "/v1/admin/invitations",
      { boundEmail: "guest@example.org" },
      { "x-bearportal-csrf": "1", "idempotency-key": randomUUID() },
    );
    assert.equal(sensitive.statusCode, 403, sensitive.body);
    assert.equal(sensitive.json().error.code, "MFA_REQUIRED");
    await query(
      "UPDATE operator_mfa_sessions SET expires_at=now()-interval '1 second' WHERE token_hash=" +
        q(sessionHash),
    );
    assert.equal(
      (await owner.request("GET", "/operator")).headers.location,
      "/operator/security",
    );
    const beforeLogout = otherBrowser.jar.get("bp_operator_mfa")!;
    assert.equal((await otherBrowser.post("/auth/logout", {})).statusCode, 200);
    assert.deepEqual(
      await query(
        "SELECT count(*) FROM operator_mfa_sessions WHERE token_hash=" +
          q(hashToken(decodeURIComponent(beforeLogout))),
      ),
      [["0"]],
    );
    // Reset revokes every session, recovery code and seed, and requires a new enrollment.
    await authorizeOperator(migrationUrl, issuer, {
      email: "owner@example.org",
      reason: "Lost authenticator recovery",
      resetMfa: true,
    });
    assert.deepEqual(
      await query(
        "SELECT count(*) FROM operator_totp WHERE user_id=" + q(legacy.userId),
      ),
      [["0"]],
    );
    assert.deepEqual(
      await query(
        "SELECT count(*) FROM operator_mfa_sessions WHERE user_id=" +
          q(legacy.userId),
      ),
      [["0"]],
    );
    assert.equal(
      (await owner.request("GET", "/auth/operator/status")).statusCode,
      401,
      "a pre-reset first-factor session cannot re-enroll MFA",
    );
    const audit = JSON.stringify(
      await query("SELECT redacted_diff::text FROM audit_events"),
    );
    const log = Buffer.concat(logs).toString();
    for (const secret of [seed, ...codes]) {
      assert.equal(audit.includes(secret), false);
      assert.equal(log.includes(secret), false);
    }
  } finally {
    await app.close();
  }
});
