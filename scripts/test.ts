import { spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { readdirSync } from "node:fs";
import { integrationDatabases } from "../tests/helpers/database.ts";

const keys = ["DATABASE_URL", "MIGRATION_DATABASE_URL", "BEARPORTAL_SUPER_DATABASE_URL"];
const supplied = keys.some((key) => process.env[key]);
const database = `bearportal_test_${randomUUID().replaceAll("-", "")}`;
let created = false;
const env = { ...process.env };
function postgres(sql: string) {
  const result = spawnSync("sudo", ["-n", "-u", "postgres", "psql", "-v", "ON_ERROR_STOP=1", "-c", sql], { encoding: "utf8" });
  if (result.status !== 0) throw new Error("Could not manage the isolated test database. Configure all three test database URLs to use an existing dedicated test database.");
}
try {
  if (!supplied) {
    postgres(`CREATE DATABASE ${database} OWNER bearportal`);
    created = true;
    env.DATABASE_URL = `postgres://bearportal_app:bearportal_app@127.0.0.1:5432/${database}`;
    env.MIGRATION_DATABASE_URL = `postgres://bearportal:bearportal@127.0.0.1:5432/${database}`;
    const admin = new URL(env.MIGRATION_DATABASE_URL);
    admin.searchParams.set("options", "-c bearportal.actor=platform_administrator");
    env.BEARPORTAL_SUPER_DATABASE_URL = admin.href;
    env.BEARPORTAL_TEST_USE_LOCAL_PSQL = "1";
  }
  integrationDatabases(env);
  const files = readdirSync("tests").filter((name) => name.endsWith(".test.ts")).sort().map((name) => `tests/${name}`);
  const result = spawnSync("pnpm", ["exec", "tsx", "--test", "--test-concurrency=1", ...files], { env, stdio: "inherit" });
  process.exitCode = result.status ?? 1;
} catch (error) {
  console.error(error instanceof Error ? error.message : "Test setup failed.");
  process.exitCode = 1;
} finally {
  if (created) {
    try { postgres(`DROP DATABASE ${database} WITH (FORCE)`); }
    catch { console.error(`Could not remove isolated test database ${database}.`); process.exitCode = 1; }
  }
}
