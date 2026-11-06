import assert from "node:assert/strict";
import { test } from "node:test";
import { randomUUID } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { exportPKCS8, exportSPKI, generateKeyPair, SignJWT } from "jose";
import {
  buildServer,
  bootstrapAdmin,
  type ApiDeps,
} from "../apps/api/src/server.ts";
import { migrate } from "../packages/db/src/migrate.ts";
import { integrationDatabases, queryTestDatabase } from "./helpers/database.ts";

const { databaseUrl, migrationUrl, superDatabaseUrl } = integrationDatabases();
const sql = (value: string) => "'" + value.replaceAll("'", "''") + "'";
const query = (text: string) => queryTestDatabase(text, superDatabaseUrl);

test("email onboarding persists consent, waits for capacity, verifies the provider, and installs once after restart", async () => {
  await migrate(migrationUrl);
  await query(
    "TRUNCATE users,organizations,servers,relay_connections,domains,secret_refs,deployments,jobs,operator_roles,allocation_requests,invitations,idempotency_keys,audit_events,outbox_events CASCADE",
  );
  await query("UPDATE control_plane_state SET mode='normal' WHERE id=1");
  const pair = await generateKeyPair("RS256", { extractable: true });
  const issuer = "https://test.onboarding.local",
    audience = "onboarding-test";
  const adminEmail = "admin@recovery-bearportal.com";
  await bootstrapAdmin(databaseUrl, "onboarding-admin", adminEmail);
  const token = await new SignJWT({
    email: adminEmail,
    email_verified: true,
    auth_time: Math.floor(Date.now() / 1000),
    amr: ["pwd", "totp"],
  })
    .setSubject("onboarding-admin")
    .setProtectedHeader({ alg: "RS256" })
    .setIssuer(issuer)
    .setAudience(audience)
    .setIssuedAt()
    .setExpirationTime("1h")
    .sign(pair.privateKey);
  const calls: string[] = [];
  const credentials = "test-dns-pat-private";
  let verified = false;
  let failProvider = false;
  const records = [
    {
      purpose: "brevo_code" as const,
      type: "TXT" as const,
      host: "@",
      value: "brevo-code:test",
    },
    {
      purpose: "dmarc" as const,
      type: "TXT" as const,
      host: "_dmarc",
      value: "v=DMARC1; p=none",
    },
  ];
  const report = () => ({
    domain: "company.site",
    authenticated: verified,
    verified,
    records,
    publishRecords: [
      ...records.map(({ type, host, value }) => ({ type, host, value })),
      {
        type: "CNAME" as const,
        host: "brevo1._domainkey",
        value: "b1.dkim.brevo.com",
      },
    ],
  });
  const deps: ApiDeps = {
    databaseUrl,
    secretsDir: mkdtempSync(join(tmpdir(), "bearportal-onboarding-")),
    secretKeyHex: "ab".repeat(32),
    jwtPublicKeyPem: await exportSPKI(pair.publicKey),
    devJwtPrivateKeyPem: await exportPKCS8(pair.privateKey),
    issuer,
    audience,
    schedulerToken: "onboarding-test-scheduler",
    onboardingIntervalMs: 0,
    lookupNameservers: async () => [
      "ns01.domaincontrol.com",
      "ns02.domaincontrol.com",
    ],
    publishBrevoRecords: async (input) => {
      calls.push("publish");
      assert.equal(input.credential.provider, "godaddy");
      assert.equal(input.credential.token, credentials);
      assert.ok(input.records.some((r) => r.type === "CNAME"));
      return { written: 3, unchanged: 0 };
    },
    operatorBrevo: {
      requestDomain: async () => {
        calls.push("domain");
        if (failProvider) throw new Error("provider unavailable");
        return report();
      },
      authenticateDomain: async () => {
        calls.push("authenticate");
        return report();
      },
    },
    resolveInstallerCommit: async () => "a".repeat(40),
    mailInstall: (hooks) => ({
      run: async ({ mode, input }) => {
        calls.push(mode);
        assert.equal(input.webmailHostname, "bearmail.company.site");
        assert.equal(input.mailHostname, "mail.company.site");
        assert.equal(input.mxCutoverAuthorized, true);
        const secret = JSON.parse(
          await hooks.readSecret(String(input.adminCredentialFile).slice(7)),
        );
        assert.equal(secret.username, "admin@company.site");
        assert.ok(
          secret.password.length >= 12,
          "new admin secret must be committed before the live runner reads it",
        );
        return {
          status: mode === "dry_run" ? "dry_run" : "succeeded",
          exitCode: 0,
          retryable: false,
          errorCode: null,
          dns: { previousMx: [], published: [] },
        };
      },
    }),
  };
  let app = await buildServer(deps);
  const form = async (
    url: string,
    fields: Record<string, string>,
    cookie?: string,
    bearer?: string,
  ) =>
    app.inject({
      method: "POST",
      url,
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        ...(cookie ? { cookie } : {}),
        ...(bearer ? { authorization: "Bearer " + bearer } : {}),
      },
      payload: new URLSearchParams(fields).toString(),
    });
  const run = () =>
    app.inject({
      method: "POST",
      url: "/internal/onboarding/run",
      headers: { "x-bearportal-scheduler": deps.schedulerToken! },
      payload: {},
    });
  const due = () =>
    query("UPDATE onboarding_requests SET next_attempt_at=now()");
  try {
    const home = await app.inject("/");
    assert.ok(home.body.includes('name="email"'));
    assert.equal(home.body.includes('name="organization"'), false);
    const registered = await form("/register", {
      email: "owner@recovery.example.org",
    });
    assert.equal(registered.statusCode, 303);
    const cookie = String(registered.headers["set-cookie"]).split(";")[0];
    const welcome = await app.inject({ url: "/portal", headers: { cookie } });
    assert.ok(welcome.body.includes("What’s your domain?"));
    const saved = await form(
      "/portal/domain",
      { csrf: "1", onboarding: "1", domain: "company.site" },
      cookie,
    );
    assert.equal(saved.statusCode, 200);
    assert.ok(saved.body.includes("DNS provider detected"));
    assert.ok(saved.body.includes("GoDaddy"));
    assert.ok(saved.body.includes('name="dnsToken"'));
    assert.equal(
      calls.length,
      0,
      "domain discovery must not run external mail setup before consent",
    );
    const noConsent = await form(
      "/portal/dns-credential",
      {
        csrf: "1",
        onboarding: "1",
        domain: "company.site",
        dnsToken: credentials,
      },
      cookie,
    );
    assert.equal(noConsent.statusCode, 400);
    assert.equal(
      (await query("SELECT count(*) FROM onboarding_requests"))[0][0],
      "0",
    );
    const accepted = await form(
      "/portal/dns-credential",
      {
        csrf: "1",
        onboarding: "1",
        deployConsent: "1",
        domain: "company.site",
        dnsToken: credentials,
      },
      cookie,
    );
    assert.equal(accepted.statusCode, 303);
    await run();
    assert.equal(
      (
        await query("SELECT state,missing_resource FROM onboarding_requests")
      )[0].join(","),
      "waiting_resources,server_and_relay",
    );
    const waiting = await app.inject({ url: "/portal", headers: { cookie } });
    assert.ok(waiting.body.includes("Resources are tight right now"));
    assert.ok(waiting.body.includes("You don’t need to submit it again"));
    assert.equal(waiting.body.includes(credentials), false);
    await app.close();
    app = await buildServer(deps);
    // Capacity arrives later; no customer re-submission is needed.
    const serverId = randomUUID();
    await query(
      `INSERT INTO servers(id,label,public_ipv4,profile_code,operator_contact,state,validated_at,available_since,readiness_report) VALUES(${sql(serverId)},'test-capacity','8.8.4.4','e2-micro','ops@example.org','available',now(),now(),'{"source":"ssh"}')`,
    );
    await due();
    await run();
    assert.equal(
      (await query("SELECT missing_resource FROM onboarding_requests"))[0][0],
      "relay",
    );
    const account = await form(
      "/operator/brevo-account",
      {
        loginEmail: "test-account@example.org",
        apiKey: "private-api-test-key",
        smtpLogin: "smtp-test-login",
        smtpKey: "private-smtp-test-key",
        dailyLimit: "300",
      },
      undefined,
      token,
    );
    assert.equal(account.statusCode, 200);
    await query("UPDATE control_plane_state SET mode='recovery'");
    await due();
    await run();
    assert.equal(calls.length, 0, "recovery mode pauses automatic setup");
    await query("UPDATE control_plane_state SET mode='normal'");
    await due();
    failProvider = true;
    await run();
    assert.equal(
      (await query("SELECT last_error_code FROM onboarding_requests"))[0][0],
      "PROVIDER_RETRY",
    );
    failProvider = false;
    await due();
    await run();
    assert.equal(
      (await query("SELECT last_error_code FROM onboarding_requests"))[0][0],
      "DNS_PROPAGATION",
    );
    assert.equal(
      calls.includes("apply"),
      false,
      "do not install before Brevo authentication succeeds",
    );
    verified = true;
    await due();
    await Promise.all([run(), run()]);
    assert.deepEqual(
      calls.filter((x) => x === "dry_run" || x === "apply"),
      ["dry_run", "apply"],
    );
    assert.equal(
      (await query("SELECT state FROM onboarding_requests"))[0][0],
      "installed",
    );
    assert.equal(
      (
        await query(
          "SELECT count(*) FROM server_assignments WHERE released_at IS NULL",
        )
      )[0][0],
      "1",
    );
    assert.equal(
      (
        await query(
          "SELECT count(*) FROM relay_assignments WHERE released_at IS NULL",
        )
      )[0][0],
      "1",
    );
    await run();
    assert.equal(calls.filter((x) => x === "apply").length, 1);
    const portal = await app.inject({ url: "/portal", headers: { cookie } });
    assert.ok(portal.body.includes("Open Bearmail"));
    assert.ok(portal.body.includes("https://bearmail.company.site"));
    for (const secret of [
      credentials,
      "private-api-test-key",
      "private-smtp-test-key",
    ])
      assert.equal(portal.body.includes(secret), false);
    const second = await form("/register", {
      email: "other@recovery.example.org",
    });
    const otherCookie = String(second.headers["set-cookie"]).split(";")[0];
    const other = await app.inject({
      url: "/v1/portal/overview",
      headers: { cookie: otherCookie },
    });
    assert.equal(other.json().onboardingState, null);
    assert.equal(other.body.includes("company.site"), false);
    await query(
      "UPDATE onboarding_requests SET state='installing',lease_expires_at=now()-interval '1 second' WHERE state='installed'",
    );
    await run();
    assert.equal(
      (
        await query(
          "SELECT state,last_error_code FROM onboarding_requests WHERE domain_id=(SELECT id FROM domains WHERE normalized_name='company.site')",
        )
      )[0].join(","),
      "attention,OUTCOME_UNKNOWN",
    );
    assert.equal(
      calls.filter((x) => x === "apply").length,
      1,
      "an expired install lease must not replay unknown host changes",
    );
    const unsafeRetry = await form(
      "/portal/onboarding",
      { csrf: "1", deployConsent: "1" },
      cookie,
    );
    assert.equal(
      unsafeRetry.statusCode,
      409,
      "an unknown host outcome requires operator review",
    );
    assert.equal(
      (
        await query(
          "SELECT count(*) FROM required_actions WHERE code='onboarding.outcome_unknown' AND state='open'",
        )
      )[0][0],
      "1",
    );
    const unauthorized = await app.inject({
      method: "POST",
      url: "/internal/onboarding/run",
      payload: {},
    });
    assert.equal(unauthorized.statusCode, 401);
  } finally {
    await app.close();
  }
});
