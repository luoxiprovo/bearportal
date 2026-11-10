import assert from "node:assert/strict";
import { test } from "node:test";
import {
  mkdtempSync,
  readFileSync,
  readdirSync,
  statSync,
  writeFileSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeyPair, SignJWT } from "jose";
import {
  createIdentityVerifier,
  createIdentityPlatformClient,
} from "../apps/api/src/identity-platform-client.ts";
import { readIdentityPlatformConfig } from "../apps/api/src/identity-platform-config.ts";
import {
  writeIdentitySettings,
  identityEnvironment,
} from "../scripts/configure-identity.ts";
import { HttpError } from "../apps/api/src/errors.ts";
const config = {
  projectId: "bearportal-auth-test",
  apiKey: "project-api-key-abcdefghijkl",
  googleClientId: "test-client.apps.googleusercontent.com",
  origins: ["http://localhost:8088"],
};

test("Identity Platform configuration rejects unsafe origins and preserves existing private environment keys", () => {
  assert.equal(readIdentityPlatformConfig({}), undefined);
  assert.throws(
    () =>
      readIdentityPlatformConfig({
        BEARPORTAL_IDENTITY_PROJECT_ID: config.projectId,
      }),
    /Missing configuration/,
  );
  assert.throws(
    () =>
      readIdentityPlatformConfig({
        ...identityEnvironment(config),
        BEARPORTAL_AUTH_ORIGINS: "https://attacker.example.org/path",
      }),
    /origins/,
  );
  assert.throws(
    () =>
      readIdentityPlatformConfig({
        ...identityEnvironment(config),
        BEARPORTAL_ENV: "production",
      }),
    /HTTPS/,
  );
  assert.throws(
    () =>
      readIdentityPlatformConfig({
        ...identityEnvironment(config),
        BEARPORTAL_IDENTITY_API_KEY: "must-not-leak",
      }),
    (error) =>
      error instanceof Error && !error.message.includes("must-not-leak"),
  );
  assert.deepEqual(
    readIdentityPlatformConfig(identityEnvironment(config)),
    config,
  );
  const dir = mkdtempSync(join(tmpdir(), "bearportal-identity-settings-"));
  const path = join(dir, "env");
  try {
    const before =
      "DATABASE_URL=preserved-private-db\nBEARPORTAL_SECRET_KEY=preserved-encryption-key\nBEARPORTAL_JWT_PRIVATE_KEY_FILE=/preserved/signing-key.pem\n";
    writeFileSync(path, before, { mode: 0o600 });
    writeIdentitySettings(path, config);
    const after = readFileSync(path, "utf8");
    for (const line of before.trim().split("\n"))
      assert.ok(after.includes(line));
    assert.equal(statSync(path).mode & 0o777, 0o600);
    const backup = readdirSync(dir).find((name) =>
      name.startsWith("env.before-identity-"),
    )!;
    assert.equal(readFileSync(join(dir, backup), "utf8"), before);
    assert.equal(statSync(join(dir, backup)).mode & 0o777, 0o600);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("managed tokens require the configured project, signature, supported provider and current authentication claims", async () => {
  const pair = await generateKeyPair("RS256");
  const other = await generateKeyPair("RS256");
  const base = {
    sub: "uid-1",
    email: "person@example.org",
    email_verified: true,
    auth_time: Math.floor(Date.now() / 1000),
    firebase: { sign_in_provider: "password" },
    iss: "https://securetoken.google.com/" + config.projectId,
    aud: config.projectId,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600,
  };
  const sign = (changes: Record<string, unknown> = {}, key = pair.privateKey) =>
    new SignJWT({ ...base, ...changes })
      .setProtectedHeader({ alg: "RS256" })
      .sign(key);
  const verify = createIdentityVerifier(config, pair.publicKey);
  assert.equal((await verify(await sign())).sub, "uid-1");
  for (const token of [
    await sign({}, other.privateKey),
    await sign({ iss: "https://accounts.google.com" }),
    await sign({ aud: "other-project" }),
    await sign({ exp: 1 }),
    await sign({ auth_time: Math.floor(Date.now() / 1000) + 3600 }),
    await sign({ firebase: { sign_in_provider: "anonymous" } }),
    await sign({
      firebase: { sign_in_provider: "password", tenant: "another-tenant" },
    }),
    await sign({ email_verified: "true" }),
    "not-a-token",
  ])
    await assert.rejects(
      verify(token),
      (error) => error instanceof HttpError && error.status === 401,
    );
});

test("Identity Platform REST client validates Google nonce/audience, brokers password and refresh, and redacts provider failures", async () => {
  const pair = await generateKeyPair("RS256");
  let providerError = "";
  const requests: Array<{ url: string; body: Record<string, unknown> }> = [];
  const managed = await new SignJWT({
    sub: "uid-1",
    email: "person@gmail.com",
    email_verified: true,
    auth_time: Math.floor(Date.now() / 1000),
    firebase: { sign_in_provider: "google.com" },
  })
    .setIssuer("https://securetoken.google.com/" + config.projectId)
    .setAudience(config.projectId)
    .setIssuedAt()
    .setExpirationTime("1h")
    .setProtectedHeader({ alg: "RS256" })
    .sign(pair.privateKey);
  const transport: typeof fetch = async (input, options) => {
    const url = String(input);
    const body = url.includes("securetoken.googleapis.com")
      ? Object.fromEntries(new URLSearchParams(String(options?.body)))
      : JSON.parse(String(options?.body));
    requests.push({ url, body });
    if (providerError)
      return new Response(
        JSON.stringify({ error: { message: providerError } }),
        { status: 400 },
      );
    return new Response(
      JSON.stringify(
        url.includes("securetoken.googleapis.com")
          ? { id_token: managed, refresh_token: "refresh-canary" }
          : { idToken: managed, refreshToken: "refresh-canary" },
      ),
      { status: 200 },
    );
  };
  const client = createIdentityPlatformClient(config, transport, {
    identity: pair.publicKey,
    google: pair.publicKey,
  });
  const google = (nonce: string, audience = config.googleClientId) =>
    new SignJWT({ email: "person@gmail.com", email_verified: true, nonce })
      .setSubject("google-sub")
      .setIssuer("https://accounts.google.com")
      .setAudience(audience)
      .setIssuedAt()
      .setExpirationTime("1h")
      .setProtectedHeader({ alg: "RS256" })
      .sign(pair.privateKey);
  await assert.rejects(
    client.google(
      await google("bad-nonce"),
      "expected-nonce",
      config.origins[0],
    ),
    /could not be verified/,
  );
  assert.equal(requests.length, 0);
  await assert.rejects(
    client.google(
      await google("expected-nonce", "other.apps.googleusercontent.com"),
      "expected-nonce",
      config.origins[0],
    ),
    /could not be verified/,
  );
  const signed = await client.google(
    await google("expected-nonce"),
    "expected-nonce",
    config.origins[0],
  );
  assert.equal(signed.authoritativeEmail, true);
  assert.equal((await client.verify(signed.idToken)).email, "person@gmail.com");
  assert.ok(requests[0].url.includes("accounts:signInWithIdp"));
  assert.equal(requests[0].body.requestUri, config.origins[0]);
  await client.password("person@example.org", "password-canary", true);
  assert.ok(requests.at(-1)!.url.includes("accounts:signUp"));
  await client.password("person@example.org", "password-canary", false);
  assert.ok(requests.at(-1)!.url.includes("accounts:signInWithPassword"));
  await client.refresh("refresh-canary");
  assert.equal(requests.at(-1)!.body.grant_type, "refresh_token");
  await client.sendVerification(managed, config.origins[0]);
  assert.equal(requests.at(-1)!.body.requestType, "VERIFY_EMAIL");
  providerError='PASSWORD_LOGIN_DISABLED';
  await assert.rejects(client.password('person@example.org','password-canary',false),error=>error instanceof HttpError&&error.status===503&&error.code==='PASSWORD_LOGIN_DISABLED');
  for (const [providerCode, expectedCode, message] of [
    ["EMAIL_EXISTS", "SIGN_UP_FAILED", /including with Google/],
    ["WEAK_PASSWORD : password-canary", "PASSWORD_REQUIREMENTS", /stronger password/],
    ["PASSWORD_DOES_NOT_MEET_REQUIREMENTS", "PASSWORD_REQUIREMENTS", /stronger password/],
    ["INVALID_EMAIL", "INVALID_EMAIL", /valid email/],
    ["ADMIN_ONLY_OPERATION", "SIGN_UP_DISABLED", /registration is not enabled/],
    ["UNKNOWN : password-canary", "SIGN_UP_FAILED", /Account creation/],
  ] as const) {
    providerError = providerCode;
    await assert.rejects(client.password("person@example.org", "password-canary", true), error =>
      error instanceof HttpError && error.code === expectedCode && message.test(error.message) && !error.message.includes("password-canary"));
  }
  providerError = "EMAIL_NOT_FOUND";
  await client.resetPassword("missing@example.org", config.origins[0]);
  providerError = "INVALID_PASSWORD : password-canary";
  await assert.rejects(
    client.password("person@example.org", "password-canary", false),
    (error) =>
      error instanceof HttpError &&
      error.status === 401 &&
      !error.message.includes("password-canary"),
  );
});
