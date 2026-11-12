import { readFileSync, existsSync } from "node:fs";
import { parseArgs } from "node:util";
import { randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";
import pg from "pg";
import { z } from "zod";

type Options = {
  email: string;
  role?: string;
  reason: string;
  reuseBootstrapAdmin?: boolean;
  resetMfa?: boolean;
};
/** Administrative access only: this command uses the migration owner, never a browser claim. */
export async function authorizeOperator(
  databaseUrl: string,
  issuer: string,
  options: Options,
) {
  const email = z
    .string()
    .trim()
    .email()
    .max(200)
    .parse(options.email)
    .toLowerCase();
  const role = z
    .enum(["support", "infrastructure_operator", "platform_administrator"])
    .parse(options.role ?? "infrastructure_operator");
  if (!issuer.startsWith("https://securetoken.google.com/"))
    throw Error("The managed Identity Platform issuer is required.");
  if (options.reason.trim().length < 5)
    throw Error("Give a meaningful reason for this authorization.");
  const db = new pg.Client({ connectionString: databaseUrl });
  await db.connect();
  try {
    await db.query("BEGIN");
    await db.query(
      "SELECT set_config('bearportal.actor','platform_administrator',true)",
    );
    await db.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", [
      "bearportal.email." + email,
    ]);
    let target = (
      await db.query<{ id: string; status: string }>(
        "SELECT id,status FROM users WHERE lower(verified_email)=$1 FOR UPDATE",
        [email],
      )
    ).rows[0];
    if (target?.status === "disabled")
      throw Error(
        "This account is disabled; authorization does not reactivate it.",
      );
    if (!target && options.reuseBootstrapAdmin) {
      const candidates = (
        await db.query<{ id: string; status: string }>(
          `SELECT u.id,u.status FROM users u WHERE u.status='active' AND EXISTS(SELECT 1 FROM operator_roles r WHERE r.user_id=u.id AND r.role='platform_administrator' AND r.revoked_at IS NULL) AND NOT EXISTS(SELECT 1 FROM identity_accounts a WHERE a.user_id=u.id) FOR UPDATE`,
        )
      ).rows;
      if (candidates.length !== 1)
        throw Error(
          "Expected exactly one unlinked bootstrap administrator. Specify an existing account email instead.",
        );
      target = candidates[0];
    }
    if (options.resetMfa) {
      if (!target) throw Error("MFA reset requires an existing account.");
      const hasRole = (
        await db.query(
          "SELECT 1 FROM operator_roles WHERE user_id=$1 AND revoked_at IS NULL",
          [target.id],
        )
      ).rows[0];
      if (!hasRole) throw Error("This account has no operator role.");
      await db.query("DELETE FROM operator_mfa_sessions WHERE user_id=$1", [
        target.id,
      ]);
      await db.query("DELETE FROM operator_totp WHERE user_id=$1", [target.id]);
      await db.query(
        "UPDATE users SET operator_mfa_reset_at=now() WHERE id=$1",
        [target.id],
      );
      await db.query(
        `INSERT INTO audit_events(id,actor_type,action,target,request_id,redacted_diff) VALUES($1,'server_administrator','operator.mfa.reset',$2,$3,$4)`,
        [
          randomUUID(),
          target.id,
          randomUUID(),
          JSON.stringify({ reason: options.reason }),
        ],
      );
      await db.query("COMMIT");
      return { userId: target.id, reset: true };
    }
    const id = randomUUID();
    await db.query(
      `UPDATE operator_authorizations SET expires_at=now(),consumed_at=now() WHERE issuer=$1 AND email=$2 AND consumed_at IS NULL`,
      [issuer, email],
    );
    await db.query(
      `INSERT INTO operator_authorizations(id,issuer,email,target_user_id,role,reason,expires_at) VALUES($1,$2,$3,$4,$5,$6,now()+interval '24 hours')`,
      [id, issuer, email, target?.id ?? null, role, options.reason],
    );
    await db.query(
      `INSERT INTO audit_events(id,actor_type,action,target,request_id,redacted_diff) VALUES($1,'server_administrator','operator.authorization.created',$2,$3,$4)`,
      [
        randomUUID(),
        id,
        randomUUID(),
        JSON.stringify({
          role,
          email,
          reason: options.reason,
          targetUserId: target?.id ?? null,
        }),
      ],
    );
    await db.query("COMMIT");
    return { userId: target?.id ?? null, authorizationId: id, reset: false };
  } catch (error) {
    await db.query("ROLLBACK");
    throw error;
  } finally {
    await db.end();
  }
}
async function main() {
  const { values } = parseArgs({
    options: {
      email: { type: "string" },
      role: { type: "string" },
      reason: { type: "string" },
      "env-file": { type: "string", default: ".data/trial/env" },
      "reuse-bootstrap-admin": { type: "boolean" },
      "reset-mfa": { type: "boolean" },
      help: { type: "boolean" },
    },
  });
  if (values.help) {
    console.log(
      'pnpm operator:authorize --email you@example.com --role platform_administrator --reason "Initial production administrator" [--reuse-bootstrap-admin]\nUse --reset-mfa with an existing operator email and a recovery reason to revoke all MFA sessions and require new enrollment.\nAn approval lasts 24 hours and requires a new verified sign-in. Emails are stored in the database, not application code.',
    );
    return;
  }
  if (!values.email || !values.reason)
    throw Error("--email and --reason are required; use --help.");
  const file = values["env-file"]!;
  const fromFile = existsSync(file)
    ? Object.fromEntries(
        readFileSync(file, "utf8")
          .split(/\r?\n/)
          .filter((l) => l && !l.startsWith("#") && l.includes("="))
          .map((l) => {
            const i = l.indexOf("=");
            return [l.slice(0, i), l.slice(i + 1)];
          }),
      )
    : {};
  const env = { ...process.env, ...fromFile };
  if (!env.MIGRATION_DATABASE_URL || !env.BEARPORTAL_IDENTITY_PROJECT_ID)
    throw Error(
      "MIGRATION_DATABASE_URL and BEARPORTAL_IDENTITY_PROJECT_ID must be configured.",
    );
  const result = await authorizeOperator(
    env.MIGRATION_DATABASE_URL,
    "https://securetoken.google.com/" + env.BEARPORTAL_IDENTITY_PROJECT_ID,
    {
      email: values.email,
      role: values.role,
      reason: values.reason,
      reuseBootstrapAdmin: values["reuse-bootstrap-admin"],
      resetMfa: values["reset-mfa"],
    },
  );
  console.log(
    result.reset
      ? "Authenticator reset and existing MFA sessions revoked. Sign in again and enroll a new authenticator."
      : "Operator authorization saved for 24 hours. Sign in at /operator/login, then enroll or verify your authenticator.",
  );
}
if (process.argv[1] === fileURLToPath(import.meta.url))
  main().catch((error) => {
    console.error(
      error instanceof Error ? error.message : "Operator setup failed.",
    );
    process.exitCode = 1;
  });
