/** Run only against a restored, fenced target. Never starts workers or prints credentials. */
import { readFileSync } from "node:fs";
import { importSPKI } from "jose";
import pg from "pg";
import { loadConfig } from "../apps/api/src/config.ts";
import {
  SecretStore,
  loadSecretKey,
  open,
} from "../packages/secrets/src/store.ts";
async function main() {
  const config = loadConfig(process.env);
  await importSPKI(readFileSync(config.jwtPublicKeyFile, "utf8"), "RS256");
  const key = loadSecretKey(config.secretKeyHex),
    secrets = new SecretStore(config.secretsDir, key);
  const db = new pg.Client({ connectionString: config.databaseUrl });
  await db.connect();
  try {
    await db.query("BEGIN");
    await db.query(
      "SELECT set_config('bearportal.actor','platform_administrator',true)",
    );
    const files = (
      await db.query<{ file_name: string }>(
        "SELECT file_name FROM secret_refs WHERE state='active'",
      )
    ).rows;
    for (const file of files) secrets.read(file.file_name);
    const factors = (
      await db.query<{ secret: Buffer }>("SELECT secret FROM operator_totp")
    ).rows;
    for (const row of factors)
      if (!/^[A-Z2-7]+$/.test(open(row.secret, key)))
        throw Error("Invalid encrypted authenticator");
    await db.query("ROLLBACK");
    console.log(
      JSON.stringify({
        ok: true,
        activeCredentials: files.length,
        authenticators: factors.length,
      }),
    );
  } finally {
    await db.end();
  }
}
main().catch(() => {
  console.error(
    "Restored configuration, database access, or encrypted credential verification failed. No credential values were logged.",
  );
  process.exitCode = 1;
});
