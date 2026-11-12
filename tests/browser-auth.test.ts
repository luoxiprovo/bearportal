import assert from "node:assert/strict";
import { test } from "node:test";
import { randomUUID } from "node:crypto";
import { mkdtempSync, readFileSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";
import { exportSPKI, generateKeyPair, SignJWT } from "jose";
import { buildServer, bootstrapAdmin } from "../apps/api/src/server.ts";
import {
  createIdentityVerifier,
  type IdentityPlatformClient,
  type IdentityTokens,
} from "../apps/api/src/identity-platform-client.ts";
import type { IdentityPlatformConfig } from "../apps/api/src/identity-platform-config.ts";
import { HttpError } from "../apps/api/src/errors.ts";
import { migrate } from "../packages/db/src/migrate.ts";
import { integrationDatabases, queryTestDatabase } from "./helpers/database.ts";

const { databaseUrl, migrationUrl, superDatabaseUrl } = integrationDatabases();
const query = (text: string) => queryTestDatabase(text, superDatabaseUrl);
const q = (value: string) => "'" + value.replaceAll("'", "''") + "'";
const config: IdentityPlatformConfig = {
  projectId: "bearportal-auth-test",
  apiKey: "identity-api-key-test-public",
  googleClientId: "test-client.apps.googleusercontent.com",
  origins: ["http://localhost:8088"],
};

test("Identity Platform Google and password signup verify email, preserve legacy allocations and isolate operators and tenants", async () => {
  await migrate(migrationUrl);
  await query(
    "TRUNCATE users,organizations,servers,relay_connections,domains,secret_refs,deployments,jobs,operator_roles,allocation_requests,invitations,idempotency_keys,audit_events,outbox_events CASCADE",
  );
  await query("UPDATE control_plane_state SET mode='normal' WHERE id=1");
  const local = await generateKeyPair("RS256", { extractable: true });
  const remote = await generateKeyPair("RS256", { extractable: true });
  await bootstrapAdmin(
    databaseUrl,
    "bootstrap-admin",
    "admin@recovery.example.org",
  );
  const legacyUser = randomUUID(),
    legacyOrg = randomUUID(),
    server = randomUUID(),
    relay = randomUUID(),
    domain = randomUUID(),
    operator = randomUUID();
  await query(`INSERT INTO users(id,identity_subject,verified_email,email_verified,status) VALUES(${q(legacyUser)},'local:owner@gmail.com','owner@gmail.com',true,'active'),(${q(operator)},'local:operator@gmail.com','operator@gmail.com',true,'active');
    INSERT INTO operator_roles(id,user_id,role,reason) VALUES(${q(randomUUID())},${q(operator)},'support','Test legacy role');
    INSERT INTO organizations(id,owner_user_id,name,status) VALUES(${q(legacyOrg)},${q(legacyUser)},'Existing organization','active');
    INSERT INTO domains(id,organization_id,normalized_name,existing_mail,state) VALUES(${q(domain)},${q(legacyOrg)},'legacy.example.org',false,'pending');
    INSERT INTO servers(id,label,public_ipv4,profile_code,operator_contact,state,tenant_tainted_at) VALUES(${q(server)},'Existing mail server','9.9.9.9','e2-micro','ops@example.org','assigned',now());
    INSERT INTO server_assignments(id,organization_id,server_id,reason) VALUES(${q(randomUUID())},${q(legacyOrg)},${q(server)},'Existing installation');
    INSERT INTO relay_connections(id,provider,label,provider_account_id,smtp_login,daily_limit,state) VALUES(${q(relay)},'brevo','Existing Brevo','relay@example.org','smtp-login',300,'assigned');
    INSERT INTO relay_assignments(id,organization_id,relay_connection_id) VALUES(${q(randomUUID())},${q(legacyOrg)},${q(relay)});`);
  let verified = false;
  let sends = 0;
  let googleCalls = 0;
  const calls: string[] = [];
  const password = "user-password-canary-long";
  const refreshSecret = "managed-refresh-secret-canary";
  const googleCredential = "google-credential-canary";
  const issue = async (
    uid: string,
    email: string,
    emailVerified: boolean,
    provider: "google.com" | "password",
    project = config.projectId,
  ): Promise<IdentityTokens> => ({
    idToken: await new SignJWT({
      email,
      email_verified: emailVerified,
      auth_time: Math.floor(Date.now() / 1000),
      firebase: { sign_in_provider: provider },
    })
      .setSubject(uid)
      .setIssuer("https://securetoken.google.com/" + project)
      .setAudience(project)
      .setProtectedHeader({ alg: "RS256" })
      .setIssuedAt()
      .setExpirationTime("1h")
      .sign(remote.privateKey),
    refreshToken: refreshSecret,
  });
  const client: IdentityPlatformClient = {
    verify: createIdentityVerifier(config, remote.publicKey),
    password: async (email, value, signup) => {
      calls.push(signup ? "signup" : "signin");
      if (value !== password)
        throw new HttpError(
          401,
          "SIGN_IN_FAILED",
          "Sign-in could not be completed.",
        );
      return issue(
        "password-user",
        email,
        verified,
        "password",
        email === "wrong-project@example.org"
          ? "other-project"
          : config.projectId,
      );
    },
    google: async (credential, nonce, origin) => {
      googleCalls++;
      assert.ok(nonce);
      assert.equal(origin, config.origins[0]);
      assert.ok([googleCredential, "operator-google"].includes(credential));
      return {
        ...(await issue(
          credential === googleCredential ? "google-owner" : "google-operator",
          credential === googleCredential
            ? "owner@gmail.com"
            : "operator@gmail.com",
          true,
          "google.com",
        )),
        authoritativeEmail: true,
      };
    },
    refresh: async (token) => {
      assert.equal(token, refreshSecret);
      return issue("password-user", "new@example.org", verified, "password");
    },
    sendVerification: async () => {
      sends++;
    },
    resetPassword: async () => {
      calls.push("reset");
    },
  };
  const logs: Buffer[] = [];
  const secretsDir = mkdtempSync(join(tmpdir(), "bearportal-auth-"));
  const app = await buildServer(
    {
      billingRequired: false,
      databaseUrl,
      secretsDir,
      secretKeyHex: "ab".repeat(32),
      jwtPublicKeyPem: await exportSPKI(local.publicKey),
      issuer: "https://test.legacy.local",
      audience: "legacy-test",
      identityPlatform: config,
      identityPlatformClient: client,
      onboardingIntervalMs: 0,
      lookupNameservers: async () => [],
    },
    new Writable({
      write(chunk, _encoding, next) {
        logs.push(Buffer.from(chunk));
        next();
      },
    }),
  );
  const jar = new Map<string, string>();
  const keep = (response: { headers: Record<string, unknown> }) => {
    const values = response.headers["set-cookie"];
    for (const line of Array.isArray(values)
      ? values
      : values
        ? [values]
        : []) {
      const part = String(line).split(";")[0];
      const i = part.indexOf("=");
      jar.set(part.slice(0, i), part.slice(i + 1));
    }
  };
  const cookie = () =>
    [...jar].map(([key, value]) => key + "=" + value).join("; ");
  const options = await app.inject("/auth/options");
  keep(options);
  const csrf = options.json().csrf as string;
  const post = async (
    url: string,
    payload: Record<string, unknown>,
    headers: Record<string, string> = {},
  ) => {
    const response = await app.inject({
      method: "POST",
      url,
      headers: {
        cookie: cookie(),
        origin: config.origins[0],
        "x-bearportal-auth-csrf": csrf,
        ...headers,
      },
      payload,
    });
    keep(response);
    return response;
  };
  try {
    assert.equal(options.statusCode, 200);
    assert.ok(options.headers["cache-control"]?.includes("no-store"));
    assert.equal(options.body.includes(config.apiKey), false);
    const home = await app.inject("/");
    assert.ok(home.body.includes("data-managed-auth"));
    assert.ok(home.body.includes('type="password"'));
    assert.equal(home.body.includes('action="/register"'), false);
    assert.equal(home.body.includes("Firebase"), false);
    assert.equal((await app.inject("/login")).statusCode, 200);
    assert.equal(
      (
        await app.inject({
          method: "POST",
          url: "/register",
          payload: { email: "owner@gmail.com" },
        })
      ).statusCode,
      403,
      "email-only development login cannot bypass configured authentication",
    );
    const noCsrf = await post(
      "/auth/google",
      { credential: googleCredential },
      { "x-bearportal-auth-csrf": "" },
    );
    assert.equal(noCsrf.statusCode, 403);
    assert.equal(googleCalls, 0);
    assert.equal(
      (
        await post(
          "/auth/google",
          { credential: googleCredential },
          { origin: "https://attacker.example.org" },
        )
      ).statusCode,
      403,
    );
    assert.equal(
      (
        await post("/auth/signup", {
          email: "new@example.org",
          password: "short",
        })
      ).statusCode,
      400,
    );
    const signupCallsBefore = calls.filter(call => call === "signup").length;
    for (const confirmation of [undefined, "a-different-password"]) {
      const mismatch = await post("/auth/signup", {
        email: "new@example.org", password,
        ...(confirmation === undefined ? {} : { confirmPassword: confirmation }),
      });
      assert.equal(mismatch.statusCode, 400, mismatch.body);
      if (confirmation !== undefined) assert.equal(mismatch.json().error.code, "PASSWORD_MISMATCH");
    }
    assert.equal(calls.filter(call => call === "signup").length, signupCallsBefore, "mismatched or missing confirmation must not create an upstream account");
    const signup = await post("/auth/signup", {
      email: "new@example.org",
      password,
      confirmPassword: password,
    });
    assert.equal(signup.statusCode, 200, signup.body);
    assert.equal(signup.json().state, "verify_email");
    assert.equal(sends, 1);
    assert.equal(signup.body.includes(password), false);
    assert.equal(signup.body.includes(refreshSecret), false);
    assert.match(String(signup.headers["set-cookie"]), /HttpOnly/);
    assert.equal(
      (
        await query(
          "SELECT count(*) FROM users WHERE verified_email='new@example.org'",
        )
      )[0][0],
      "0",
      "unverified identities cannot claim an application account or inventory",
    );
    const stillUnverified = await post("/auth/verified", {});
    assert.equal(stillUnverified.json().state, "verify_email");
    const resent = await post("/auth/resend-verification", {});
    assert.equal(resent.statusCode, 200);
    assert.equal(sends, 2);
    verified = true;
    const completed = await post("/auth/verified", {});
    assert.equal(completed.statusCode, 200, completed.body);
    assert.equal(completed.json().redirect, "/portal");
    const account = (
      await query(
        "SELECT u.id,o.id FROM users u JOIN organizations o ON o.owner_user_id=u.id WHERE u.verified_email='new@example.org'",
      )
    )[0];
    assert.ok(account);
    const passwordSession = decodeURIComponent(jar.get("bp_session")!);
    const overview = await app.inject({
      url: "/v1/portal/overview",
      headers: { cookie: cookie() },
    });
    assert.equal(overview.statusCode, 200, overview.body);
    assert.equal(overview.json().organizationId, account[1]);
    const wrongPassword = await post("/auth/signin", {
      email: "new@example.org",
      password: "wrong-password",
    });
    assert.equal(wrongPassword.statusCode, 401);
    const reSignin = await post("/auth/signin", {
      email: "new@example.org",
      password,
    });
    assert.equal(reSignin.statusCode, 200);
    assert.equal(
      (
        await query(
          "SELECT count(*) FROM organizations WHERE owner_user_id=" +
            q(account[0]),
        )
      )[0][0],
      "1",
    );
    const refresh = await post("/auth/refresh", {});
    assert.equal(refresh.statusCode, 200);
    const directSession = await app.inject({
      method: "POST",
      url: "/v1/session",
      payload: { idToken: passwordSession },
    });
    assert.equal(directSession.statusCode, 403);
    assert.equal(
      (
        await post("/auth/signin", {
          email: "wrong-project@example.org",
          password,
        })
      ).statusCode,
      401,
    );
    const resetExisting = await post("/auth/password-reset", {
      email: "new@example.org",
    });
    const resetUnknown = await post("/auth/password-reset", {
      email: "missing@example.org",
    });
    assert.deepEqual(resetExisting.json(), resetUnknown.json());
    assert.equal(resetUnknown.statusCode, 200);
    const beforeDuplicate = calls.filter(call=>call === "signup").length;
    const duplicateSignup = await post("/auth/signup", { email: "NEW@example.org", password, confirmPassword: password });
    assert.equal(duplicateSignup.statusCode, 409, duplicateSignup.body);
    assert.equal(duplicateSignup.json().error.code, "ACCOUNT_EXISTS");
    assert.equal(calls.filter(call=>call === "signup").length, beforeDuplicate);
    const google = await post("/auth/google", { credential: googleCredential });
    assert.equal(google.statusCode, 200, google.body);
    assert.equal(google.json().state, "signed_in");
    const linkedOverview = await app.inject({
      url: "/v1/portal/overview",
      headers: { cookie: cookie() },
    });
    assert.equal(linkedOverview.statusCode, 200, linkedOverview.body);
    assert.equal(linkedOverview.json().organizationId, legacyOrg);
    assert.equal(linkedOverview.json().domainName, "legacy.example.org");
    assert.equal(
      (
        await query(
          `SELECT user_id FROM identity_accounts WHERE subject='google-owner'`,
        )
      )[0][0],
      legacyUser,
    );
    assert.equal(
      (
        await query(
          `SELECT server_id FROM server_assignments WHERE organization_id=${q(legacyOrg)} AND released_at IS NULL`,
        )
      )[0][0],
      server,
    );
    assert.equal(
      (
        await query(
          `SELECT relay_connection_id FROM relay_assignments WHERE organization_id=${q(legacyOrg)} AND released_at IS NULL`,
        )
      )[0][0],
      relay,
    );
    assert.equal(
      (await post("/auth/google", { credential: googleCredential })).statusCode,
      200,
    );
    assert.equal(
      (
        await query(
          `SELECT count(*) FROM identity_accounts WHERE subject='google-owner'`,
        )
      )[0][0],
      "1",
    );
    const operatorGoogle = await post("/auth/google", {
      credential: "operator-google",
    });
    assert.equal(operatorGoogle.statusCode, 409);
    assert.equal(operatorGoogle.json().error.code, "ACCOUNT_EXISTS");
    assert.deepEqual(await query("SELECT user_id FROM identity_accounts WHERE subject='google-operator'"), []);
    assert.deepEqual(await query("SELECT count(*) FROM users WHERE verified_email='operator@gmail.com'"), [["1"]]);
    const noRole = await app.inject({
      url: "/v1/admin/portal",
      headers: { cookie: cookie() },
    });
    assert.equal(noRole.statusCode, 403);
    await query("UPDATE users SET status='disabled' WHERE id=" + q(account[0]));
    const disabled = await post("/auth/signin", {
      email: "new@example.org",
      password,
    });
    assert.equal(disabled.statusCode, 403);
    const disabledBearer = await app.inject({
      url: "/v1/portal/overview",
      headers: { authorization: "Bearer " + passwordSession },
    });
    assert.equal(disabledBearer.statusCode, 401);
    const logout = await post("/auth/logout", {});
    assert.equal(logout.statusCode, 200);
    assert.match(String(logout.headers["set-cookie"]), /Max-Age=0/);
    assert.equal((await app.inject("/portal")).statusCode, 303);
    // Clients behind Caddy must not share one loopback rate-limit bucket.
    const limitedClient = { "x-forwarded-for": "198.51.100.80" };
    for (let i = 0; i < 60; i++) {
      assert.equal((await app.inject({ url: "/auth/options", headers: limitedClient })).statusCode, 200);
    }
    assert.equal((await app.inject({ url: "/auth/options", headers: limitedClient })).statusCode, 429);
    assert.equal((await app.inject({ url: "/auth/options", headers: { "x-forwarded-for": "198.51.100.81" } })).statusCode, 200);
    // Direct remote connections cannot impersonate a client using forwarded headers.
    assert.equal((await app.inject({ url: "/auth/options", remoteAddress: "203.0.113.50", headers: limitedClient })).statusCode, 200);
    for (const canary of [password, refreshSecret, googleCredential]) {
      assert.equal(Buffer.concat(logs).toString().includes(canary), false);
      assert.equal(
        JSON.stringify(
          await query("SELECT redacted_diff::text FROM audit_events"),
        ).includes(canary),
        false,
      );
    }
    assert.deepEqual(
      readdirSync(secretsDir),
      [],
      "identity passwords and refresh tokens are not stored in the local secret directory",
    );
  } finally {
    await app.close();
  }
});
