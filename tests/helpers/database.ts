import pg from "pg";
import { execFileSync } from "node:child_process";

const URL_KEYS = ["DATABASE_URL", "MIGRATION_DATABASE_URL", "BEARPORTAL_SUPER_DATABASE_URL"] as const;
const TEST_DATABASE = /^bearportal_test_[a-z0-9_]+$/;

/** Destructive suites must use three explicit connections to one dedicated test database. */
export function integrationDatabases(env: NodeJS.ProcessEnv = process.env) {
  const targets = URL_KEYS.map((key) => {
    const value = env[key];
    if (!value) throw new Error(`Integration tests require ${key}. Run pnpm test to create an isolated database.`);
    let url: URL;
    try {
      url = new URL(value);
    } catch {
      throw new Error(`Integration test ${key} is not a valid database URL.`);
    }
    const database = decodeURIComponent(url.pathname.slice(1));
    if (!['postgres:', 'postgresql:'].includes(url.protocol) || !TEST_DATABASE.test(database)) {
      throw new Error(`Integration test ${key} must target a database named bearportal_test_<name>.`);
    }
    for (const parameter of url.searchParams.keys()) {
      if (parameter !== "options" && parameter !== "sslmode") {
        throw new Error(`Integration test ${key} contains an unsupported connection parameter.`);
      }
    }
    return { value, target: `${url.hostname}:${url.port || "5432"}/${database}` };
  });
  if (targets.some((entry) => entry.target !== targets[0].target)) {
    throw new Error("All integration test database URLs must target the same host, port, and database.");
  }
  return {
    databaseUrl: targets[0].value,
    migrationUrl: targets[1].value,
    superDatabaseUrl: targets[2].value,
  };
}

export async function queryTestDatabase(sql: string, connectionString: string, useLocalPsql = process.env.BEARPORTAL_TEST_USE_LOCAL_PSQL === "1"): Promise<string[][]> {
  // Validate even when this helper is called independently of a suite's startup.
  integrationDatabases({ DATABASE_URL: connectionString, MIGRATION_DATABASE_URL: connectionString, BEARPORTAL_SUPER_DATABASE_URL: connectionString });
  if (useLocalPsql) {
    const url = new URL(connectionString);
    if (url.hostname !== "127.0.0.1" || (url.port && url.port !== "5432")) {
      throw new Error("Local test administration requires the local PostgreSQL cluster.");
    }
    const database = decodeURIComponent(url.pathname.slice(1));
    const output = execFileSync("sudo", ["-n", "-u", "postgres", "psql", "-h", "/var/run/postgresql", "-p", "5432", "-d", database, "-v", "ON_ERROR_STOP=1", "-tA", "-F", "\t"], {
      input: sql,
      encoding: "utf8",
    });
    return output.split("\n").filter(Boolean).map((line) => line.split("\t"));
  }
  const client = new pg.Client({ connectionString });
  await client.connect();
  try {
    const expected = decodeURIComponent(new URL(connectionString).pathname.slice(1));
    const actual = await client.query<{ name: string }>("SELECT current_database() AS name");
    if (actual.rows[0]?.name !== expected) throw new Error("Integration test connection resolved to an unexpected database.");
    const result = await client.query({ text: sql, rowMode: "array" });
    const results: pg.QueryResult[] = Array.isArray(result) ? result : [result];
    return results.flatMap((entry) => (entry.rows ?? []).map((row) => Object.values(row).map((value) =>
      value == null ? "" : typeof value === "boolean" ? (value ? "t" : "f") : String(value),
    )));
  } finally {
    await client.end();
  }
}
