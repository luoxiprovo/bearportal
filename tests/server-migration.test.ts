import assert from "node:assert/strict";
import { test } from "node:test";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomUUID } from "node:crypto";
import { generateKeyPair, exportSPKI } from "jose";
import { migrate } from "../packages/db/src/migrate.ts";
import {
  SecretStore,
  seal,
  loadSecretKey,
} from "../packages/secrets/src/store.ts";
import { integrationDatabases, queryTestDatabase } from "./helpers/database.ts";
const { databaseUrl, migrationUrl, superDatabaseUrl } = integrationDatabases();
const query = (text: string) => queryTestDatabase(text, superDatabaseUrl);
const q = (value: string) => "'" + value.replaceAll("'", "''") + "'";

test("migration scripts reject unsafe bundles and split-brain rollback; PostgreSQL restore retains data and RLS", () => {
  const result = spawnSync("python3", ["tests/server_migration_checks.py"], {
    encoding: "utf8",
    maxBuffer: 8 * 1024 * 1024,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stderr, /OK/);
});

test("restored credentials and operator authenticator ciphertext require the unchanged encryption key and files", async () => {
  await migrate(migrationUrl);
  await query(
    "TRUNCATE users,organizations,servers,relay_connections,domains,secret_refs,deployments,jobs,operator_roles,allocation_requests,invitations,idempotency_keys,audit_events,outbox_events CASCADE",
  );
  const temp = mkdtempSync(join(tmpdir(), "bearportal-restored-key-")),
    secrets = join(temp, "secrets"),
    key = "ef".repeat(32);
  const store = new SecretStore(secrets, loadSecretKey(key));
  const file = store.write(
    JSON.stringify({ apiKey: "synthetic-provider-credential" }),
  );
  const user = randomUUID(),
    factor = seal("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", loadSecretKey(key));
  await query(`INSERT INTO users(id,identity_subject,verified_email,email_verified,status) VALUES(${q(user)},'migration-operator','operator@example.org',true,'active');
 INSERT INTO secret_refs(id,purpose,file_name,key_id,state) VALUES(${q(randomUUID())},'brevo-api',${q(file)},'local-1','active');
 INSERT INTO operator_totp(user_id,secret,enrolled_at) VALUES(${q(user)},decode(${q(factor.toString("hex"))},'hex'),now());`);
  const keys = await generateKeyPair("RS256", { extractable: true });
  writeFileSync(join(temp, "public.pem"), await exportSPKI(keys.publicKey));
  const env = {
    ...process.env,
    DATABASE_URL: databaseUrl,
    BEARPORTAL_ENV: "production",
    BEARPORTAL_ALLOW_TEST_ISSUER: "0",
    BEARPORTAL_SECRET_KEY: key,
    BEARPORTAL_JWT_ISSUER: "https://securetoken.google.com/migration-test",
    BEARPORTAL_JWT_AUDIENCE: "migration-test",
    BEARPORTAL_JWT_PUBLIC_KEY_FILE: join(temp, "public.pem"),
    BEARPORTAL_SECRETS_DIR: secrets,
  };
  const run = (extra: Record<string, string> = {}) =>
    spawnSync(
      process.execPath,
      ["--import", "tsx", "scripts/migration-verify.ts"],
      { env: { ...env, ...extra }, encoding: "utf8" },
    );
  try {
    const good = run();
    assert.equal(good.status, 0, good.stderr);
    assert.deepEqual(JSON.parse(good.stdout), {
      ok: true,
      activeCredentials: 1,
      authenticators: 1,
    });
    const bad = run({ BEARPORTAL_SECRET_KEY: "12".repeat(32) });
    assert.equal(bad.status, 1);
    assert.equal((bad.stderr + bad.stdout).includes(key), false);
    rmSync(join(secrets, file));
    assert.equal(run().status, 1, "Missing encrypted files prevent activation");
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }
});
