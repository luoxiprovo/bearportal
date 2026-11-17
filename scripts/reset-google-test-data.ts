/** Explicit development reset. Never enumerates/deletes the whole Identity project. */
import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync, renameSync, existsSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs, parseEnv } from "node:util";
import pg from "pg";
import { z } from "zod";
import type { Queryable } from "../packages/servers/src/allocate.ts";
import { resetTestData } from "./reset-test-data.ts";

export class IdentityCleanupError extends Error {}
export type IdentityUser = { uid: string; email: string; providers: string[] };
export type CleanupPlan = {
  project: string;
  emails: string[];
  users: IdentityUser[];
  missing: string[];
};
export type AdminIdentity = {
  permissions: (project: string) => Promise<void>;
  lookup: (project: string, email: string) => Promise<IdentityUser[]>;
  remove: (project: string, uid: string) => Promise<void>;
};
export function createAdminIdentity(
  transport: typeof fetch = fetch,
  token: () => string = () => {
    const result = spawnSync("gcloud", ["auth", "print-access-token"], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
    if (result.status !== 0 || !result.stdout.trim())
      throw new IdentityCleanupError(
        "Google admin credentials are unavailable. Run gcloud auth login with an administrator of the configured Identity Platform project.",
      );
    return result.stdout.trim();
  },
): AdminIdentity & {
  list: (project: string) => Promise<IdentityUser[]>;
  lookupUid: (project: string, uid: string) => Promise<IdentityUser | null>;
} {
  async function call(
    url: string,
    body: Record<string, unknown> | undefined,
    project: string,
  ): Promise<Record<string, any>> {
    let response: Response;
    try {
      response = await transport(url, {
        method: body === undefined ? "GET" : "POST",
        headers: {
          authorization: "Bearer " + token(),
          "content-type": "application/json",
          "x-goog-user-project": project,
        },
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: AbortSignal.timeout(15000),
        redirect: "error",
      });
    } catch (error) {
      if (error instanceof IdentityCleanupError) throw error;
      throw new IdentityCleanupError(
        "Google admin request failed or timed out. No local data was cleared; rerun the preview before retrying.",
      );
    }
    if (!response.ok) {
      if (response.status === 401 || response.status === 403)
        throw new IdentityCleanupError(
          "Google admin access was denied. Run gcloud auth login using an account with Firebase Authentication Admin access on this Identity Platform project. The VM's default credentials may have insufficient OAuth scopes. No local data was cleared.",
        );
      throw new IdentityCleanupError(
        "Google admin request failed (HTTP " +
          response.status +
          "). No local data was cleared; check the cleanup receipt and rerun the preview.",
      );
    }
    try {
      return (await response.json()) as Record<string, any>;
    } catch {
      throw new IdentityCleanupError(
        "Google returned an invalid admin response. No local data was cleared.",
      );
    }
  }
  const endpoint = (project: string, method: string) =>
    "https://identitytoolkit.googleapis.com/v1/projects/" +
    encodeURIComponent(project) +
    "/accounts:" +
    method;
  function safeUser(user: any): IdentityUser {
    if (typeof user.localId !== "string" || !user.localId || user.tenantId ||
        (user.email !== undefined && typeof user.email !== "string"))
      throw new IdentityCleanupError("Invalid default-tenant Google user response.");
    return {
      uid: user.localId,
      email: (user.email ?? "").toLowerCase(),
      providers: (user.providerUserInfo ?? []).map((p: any) => String(p.providerId)),
    };
  }
  return {
    list: async (project) => {
      const users: IdentityUser[] = [];
      const pages = new Set<string>();
      let page = "";
      do {
        const query = new URLSearchParams({ maxResults: "1000" });
        if (page) query.set("nextPageToken", page);
        const result = await call(endpoint(project, "batchGet") + "?" + query, undefined, project);
        if (result.users !== undefined && !Array.isArray(result.users))
          throw new IdentityCleanupError("Invalid Google user list response.");
        users.push(...(result.users ?? []).map(safeUser));
        page = result.nextPageToken ?? "";
        if (typeof page !== "string" || (page && pages.has(page)))
          throw new IdentityCleanupError("Invalid Google pagination token.");
        if (page) pages.add(page);
      } while (page);
      if (new Set(users.map(u => u.uid)).size !== users.length)
        throw new IdentityCleanupError("Duplicate Google UIDs; rerun preview.");
      return users;
    },
    lookupUid: async (project, uid) => {
      const result = await call(endpoint(project, "lookup"), { localId: [uid] }, project);
      if (result.users === undefined) return null;
      if (!Array.isArray(result.users) || result.users.length > 1)
        throw new IdentityCleanupError("Invalid Google UID lookup response.");
      if (!result.users.length) return null;
      const user = safeUser(result.users[0]);
      if (user.uid !== uid) throw new IdentityCleanupError("Google UID lookup mismatch.");
      return user;
    },
    permissions: async (project) => {
      const required = ["firebaseauth.users.get", "firebaseauth.users.delete"];
      const result = await call(
        "https://cloudresourcemanager.googleapis.com/v1/projects/" +
          encodeURIComponent(project) +
          ":testIamPermissions",
        { permissions: required },
        project,
      );
      if (
        !Array.isArray(result.permissions) ||
        required.some((permission) => !result.permissions.includes(permission))
      )
        throw new IdentityCleanupError(
          "Google credentials need firebaseauth.users.get and firebaseauth.users.delete on the configured project (Firebase Authentication Admin). No accounts were deleted.",
        );
    },
    lookup: async (project, email) => {
      const result = await call(endpoint(project, "lookup"), {
        email: [email],
      }, project);
      if (result.users !== undefined && !Array.isArray(result.users))
        throw new IdentityCleanupError(
          "Invalid Google account lookup response.",
        );
      return (result.users ?? []).map((user: any) => {
        if (
          typeof user.localId !== "string" ||
          !user.localId ||
          typeof user.email !== "string" ||
          user.email.toLowerCase() !== email ||
          user.tenantId
        )
          throw new IdentityCleanupError(
            "Google account lookup did not match the requested email or default tenant. No local data was cleared.",
          );
        // Discard password hashes, salts, tokens, MFA secrets and all other provider fields.
        return {
          uid: user.localId,
          email: user.email.toLowerCase(),
          providers: (user.providerUserInfo ?? [])
            .map((provider: any) => String(provider.providerId))
            .filter((id: string) => id === "password" || id === "google.com"),
        };
      });
    },
    remove: async (project, uid) => {
      await call(endpoint(project, "delete"), { localId: uid }, project);
    },
  };
}
async function system<T>(db: Queryable, work: () => Promise<T>): Promise<T> {
  await db.query("BEGIN");
  try {
    await db.query(
      "SELECT set_config('bearportal.actor','platform_administrator',true)",
    );
    const result = await work();
    await db.query("ROLLBACK");
    return result;
  } catch (error) {
    await db.query("ROLLBACK");
    throw error;
  }
}
export async function identityTargets(
  db: Queryable,
  env: NodeJS.ProcessEnv,
  requested: string[] = [],
) {
  if (
    env.BEARPORTAL_ENV !== "development" ||
    process.env.BEARPORTAL_ENV === "production"
  )
    throw new IdentityCleanupError(
      "Google test cleanup requires development mode.",
    );
  if (
    env.BEARPORTAL_STRIPE_MODE === "live" ||
    (env.STRIPE_SECRET_KEY && !/^(sk|rk)_test_/.test(env.STRIPE_SECRET_KEY))
  )
    throw new IdentityCleanupError(
      "Google test cleanup refuses live Stripe configuration.",
    );
  const project = env.BEARPORTAL_IDENTITY_PROJECT_ID;
  if (!project || !/^[a-z][a-z0-9-]{4,61}[a-z0-9]$/.test(project))
    throw new IdentityCleanupError(
      "A valid BEARPORTAL_IDENTITY_PROJECT_ID is required.",
    );
  const issuer = "https://securetoken.google.com/" + project;
  return system(db, async () => {
    const protectedRows = (
      await db.query<{ email: string; uid: string | null }>(
        `SELECT lower(u.verified_email) AS email,a.subject AS uid FROM users u LEFT JOIN identity_accounts a ON a.user_id=u.id AND a.issuer=$1 WHERE EXISTS(SELECT 1 FROM operator_roles r WHERE r.user_id=u.id)
      UNION SELECT lower(email),NULL::text FROM operator_authorizations`,
        [issuer],
      )
    ).rows;
    if (
      !(
        await db.query(
          "SELECT 1 FROM operator_roles r JOIN users u ON u.id=r.user_id WHERE r.revoked_at IS NULL AND u.status='active' LIMIT 1",
        )
      ).rows.length
    )
      throw new IdentityCleanupError(
        "An active operator is required before Google test cleanup.",
      );
    const protectedEmails = new Set(protectedRows.map((row) => row.email));
    if (env.BOOTSTRAP_ADMIN_EMAIL)
      protectedEmails.add(env.BOOTSTRAP_ADMIN_EMAIL.toLowerCase());
    const protectedUids = new Set(
      protectedRows.flatMap((row) => (row.uid ? [row.uid] : [])),
    );
    const emails = [
      ...new Set(
        requested.length
          ? requested.map((email) =>
              z.string().trim().email().max(200).parse(email).toLowerCase(),
            )
          : (
              await db.query<{ email: string }>(
                "SELECT lower(verified_email) AS email FROM users WHERE NOT EXISTS(SELECT 1 FROM operator_roles r WHERE r.user_id=users.id)",
              )
            ).rows.map((row) => row.email),
      ),
    ];
    if (emails.some((email) => protectedEmails.has(email)))
      throw new IdentityCleanupError(
        "An operator or operator-authorized email was selected. Operator identities are protected; no accounts were deleted.",
      );
    return { project, emails, protectedEmails, protectedUids };
  });
}
export async function planIdentityCleanup(
  db: Queryable,
  admin: AdminIdentity,
  env: NodeJS.ProcessEnv,
  emails: string[] = [],
): Promise<CleanupPlan> {
  const targets = await identityTargets(db, env, emails);
  try {
    await admin.permissions(targets.project);
  } catch (error) {
    if (error instanceof IdentityCleanupError)
      throw new IdentityCleanupError(
        `${error.message} Identity Platform project: ${targets.project}.`,
      );
    throw error;
  }
  const users: IdentityUser[] = [],
    missing: string[] = [];
  for (const email of targets.emails) {
    const found = await admin.lookup(targets.project, email);
    if (!found.length) missing.push(email);
    for (const user of found) {
      if (
        user.email !== email ||
        targets.protectedUids.has(user.uid) ||
        targets.protectedEmails.has(user.email)
      )
        throw new IdentityCleanupError(
          "A protected operator UID or mismatched account was found. No accounts were deleted.",
        );
      users.push(user);
    }
  }
  if (new Set(users.map((user) => user.uid)).size !== users.length)
    throw new IdentityCleanupError(
      "Google lookup returned duplicate account identifiers. No accounts were deleted.",
    );
  return { project: targets.project, emails: targets.emails, users, missing };
}
export async function deleteIdentityPlan(
  db: Queryable,
  admin: AdminIdentity,
  env: NodeJS.ProcessEnv,
  plan: CleanupPlan,
  backup: string,
) {
  // Recheck operator protection and email-to-UID bindings immediately before the first deletion.
  const current = await planIdentityCleanup(db, admin, env, plan.emails);
  if (JSON.stringify(current.users) !== JSON.stringify(plan.users))
    throw new IdentityCleanupError(
      "Google accounts changed since preflight. Rerun the preview; nothing was deleted by this run.",
    );
  const receipt = {
    project: plan.project,
    planned: plan.users,
    deleted: [] as string[],
    missing: plan.missing,
    complete: false,
  };
  const path = join(backup, "google-identity-cleanup.json");
  const save = () => {
    writeFileSync(path + ".tmp", JSON.stringify(receipt, null, 2), {
      mode: 0o600,
    });
    renameSync(path + ".tmp", path);
  };
  save();
  for (const user of plan.users) {
    await admin.remove(plan.project, user.uid);
    receipt.deleted.push(user.uid);
    save();
    console.log("Deleted test Identity Platform account: " + user.email);
  }
  receipt.complete = true;
  save();
}
async function main() {
  const { values } = parseArgs({
    options: {
      email: { type: "string", multiple: true },
      project: { type: "string" },
      "env-file": { type: "string", default: ".data/trial/env" },
      "confirm-clear-test-data": { type: "boolean" },
      "confirm-delete-google-users": { type: "boolean" },
      help: { type: "boolean" },
    },
  });
  if (values.help) {
    console.log(
      "pnpm reset:test-data:google [--email user@example.com ...]\nDefault: preview only. Without --email, selects local customer emails only; never every Google project user.\nTo delete selected Identity accounts AND clear all local test data: add --project PROJECT_ID --confirm-delete-google-users --confirm-clear-test-data\nPreserves operators. Cancel test subscriptions and stop the API before confirmation. Requires gcloud admin login. Does not delete a person's Google/Gmail account.",
    );
    return;
  }
  const root = fileURLToPath(new URL("..", import.meta.url));
  const env = {
    ...process.env,
    ...parseEnv(readFileSync(values["env-file"]!, "utf8")),
  };
  if (existsSync(join(root, ".data/server-migration-source.lock")))
    throw new IdentityCleanupError(
      "Google cleanup is blocked during server migration.",
    );
  if (!env.MIGRATION_DATABASE_URL)
    throw new IdentityCleanupError("MIGRATION_DATABASE_URL is required.");
  const database = new URL(env.MIGRATION_DATABASE_URL);
  if (
    !["127.0.0.1", "localhost", "[::1]"].includes(database.hostname) ||
    !/^bearportal(?:_test_[a-z0-9_]+)?$/.test(database.pathname.slice(1))
  )
    throw new IdentityCleanupError(
      "Google test cleanup requires the local BearPortal development database.",
    );
  const confirmed =
    values["confirm-delete-google-users"] || values["confirm-clear-test-data"];
  if (
    confirmed &&
    (!values["confirm-delete-google-users"] ||
      !values["confirm-clear-test-data"] ||
      values.project !== env.BEARPORTAL_IDENTITY_PROJECT_ID)
  )
    throw new IdentityCleanupError(
      "Both confirmation flags and --project matching BEARPORTAL_IDENTITY_PROJECT_ID are required. No data was cleared.",
    );
  if (values.project && values.project !== env.BEARPORTAL_IDENTITY_PROJECT_ID)
    throw new IdentityCleanupError(
      "The requested Google project does not match this deployment.",
    );
  const db = new pg.Client({ connectionString: env.MIGRATION_DATABASE_URL });
  await db.connect();
  try {
    const admin = createAdminIdentity();
    const plan = await planIdentityCleanup(db, admin, env, values.email);
    console.log(
      JSON.stringify(
        {
          preview: !confirmed,
          ...plan,
          localReset: confirmed
            ? "All local customers and inventory will be cleared; operator access is preserved."
            : "Confirmation clears ALL local customers and inventory, even when --email restricts Google deletion.",
        },
        null,
        2,
      ),
    );
    if (!confirmed) return;
    await resetTestData(
      env as Record<string, string>,
      root,
      ["--confirm-clear-test-data"],
      {
        beforeClear: async (backup) =>
          deleteIdentityPlan(db, admin, env, plan, backup),
      },
    );
  } finally {
    await db.end();
  }
}
if (process.argv[1] === fileURLToPath(import.meta.url))
  main().catch((error) => {
    console.error(
      error instanceof IdentityCleanupError
        ? error.message
        : "Reset stopped. Check development configuration, canceled subscriptions, stopped API, Google admin credentials and database access. Local data is preserved unless the local reset committed; earlier Google deletions cannot be rolled back. Check the private backup receipt and rerun the preview before retrying.",
    );
    process.exitCode = 1;
  });
