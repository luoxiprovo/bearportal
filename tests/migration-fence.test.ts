import assert from "node:assert/strict";
import { test } from "node:test";
import { mkdtempSync, writeFileSync, unlinkSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { Writable } from "node:stream";
import { generateKeyPair, exportSPKI } from "jose";
import { buildServer } from "../apps/api/src/server.ts";
import { assertMigrationStartup } from "../apps/api/src/migration-fence.ts";
import { registerOnboarding } from "../apps/api/src/onboarding.ts";
import { integrationDatabases } from "./helpers/database.ts";
const { databaseUrl } = integrationDatabases();

test("source fence rejects restart, blocks mutations and presents a recoverable maintenance page", async () => {
  const dir = mkdtempSync(join(tmpdir(), "bearportal-fence-")),
    file = join(dir, "fence.json");
  assert.doesNotThrow(() => assertMigrationStartup(file));
  writeFileSync(file, JSON.stringify({ role: "source", id: "fixture" }));
  assert.throws(() => assertMigrationStartup(file), /fenced/);
  writeFileSync(file, "invalid");
  assert.throws(() => assertMigrationStartup(file), /fenced/);
  writeFileSync(file, JSON.stringify({ role: "target", id: "fixture" }));
  assert.doesNotThrow(() => assertMigrationStartup(file));
  const keys = await generateKeyPair("RS256", { extractable: true });
  const app = await buildServer(
    {
      databaseUrl,
      secretKeyHex: "ab".repeat(32),
      secretsDir: join(dir, "secrets"),
      jwtPublicKeyPem: await exportSPKI(keys.publicKey),
      issuer: "https://test.migration.local",
      audience: "migration",
      onboardingIntervalMs: 0,
      migrationFenceFile: file,
    },
    new Writable({
      write(_c, _e, done) {
        done();
      },
    }),
  );
  try {
    const health = await app.inject("/healthz");
    assert.equal(health.statusCode, 503);
    assert.equal(health.json().maintenance, true);
    const html = await app.inject({
      url: "/login",
      headers: { accept: "text/html" },
    });
    assert.equal(html.statusCode, 503);
    assert.match(html.body, /Your progress is saved/);
    assert.equal(html.headers["retry-after"], "30");
    const mutation = await app.inject({
      method: "POST",
      url: "/auth/signup",
      payload: {},
    });
    assert.equal(mutation.statusCode, 503);
    assert.equal(mutation.json().error.code, "MIGRATION_IN_PROGRESS");
    unlinkSync(file);
    const live = await app.inject("/healthz");
    assert.equal(live.statusCode, 200);
    assert.equal(live.json().migrationProtocol, 1);
    assert.equal((await app.inject("/login")).statusCode, 200);
  } finally {
    await app.close();
  }
});

test("the migration fence pauses the background worker before any database or provider activity", async () => {
  const hooks = new Map<string, () => Promise<void>>();
  let paused = true,
    attempts = 0;
  const app = {
    addHook: (name: string, fn: () => Promise<void>) => hooks.set(name, fn),
    post() {},
    log: { error() {} },
  };
  const inventory = {
    withSystem: async () => {
      attempts++;
      throw Error("fixture stop");
    },
    setActor: async () => {},
  };
  const wake = registerOnboarding(
    app as any,
    inventory as any,
    {} as any,
    60_000,
    undefined,
    () => paused,
  );
  await hooks.get("onReady")!();
  wake();
  await new Promise((resolve) => setTimeout(resolve, 10));
  assert.equal(attempts, 0);
  paused = false;
  wake();
  await new Promise((resolve) => setTimeout(resolve, 10));
  assert.ok(attempts > 0);
  await hooks.get("onClose")!();
});
