/** Delete default-tenant Google test users, preserving BearPortal operators. */
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync, renameSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs, parseEnv } from "node:util";
import pg from "pg";
import { createAdminIdentity, identityTargets, IdentityCleanupError, type IdentityUser } from "./reset-google-test-data.ts";

type Protection = { project: string; protectedEmails: Set<string>; protectedUids: Set<string> };
export function isProtected(user: IdentityUser, protection: Protection) {
  return protection.protectedUids.has(user.uid) || protection.protectedEmails.has(user.email.toLowerCase());
}
export async function deleteNonOperators(
  users: IdentityUser[],
  protection: () => Promise<Protection>,
  admin: Pick<ReturnType<typeof createAdminIdentity>, "lookupUid" | "remove">,
  record: (uid: string, status: "deleted" | "missing" | "protected") => void,
) {
  const initial = await protection();
  for (const planned of users) {
    const currentProtection = await protection();
    if (currentProtection.project !== initial.project)
      throw new IdentityCleanupError("Identity project changed; deletion stopped.");
    const current = await admin.lookupUid(initial.project, planned.uid);
    if (!current) { record(planned.uid, "missing"); continue; }
    if (isProtected(planned, currentProtection) || isProtected(current, currentProtection)) {
      record(planned.uid, "protected"); continue;
    }
    if (current.email !== planned.email)
      throw new IdentityCleanupError("Google account changed since preview; rerun preview.");
    await admin.remove(initial.project, current.uid);
    record(current.uid, "deleted");
  }
}
async function main() {
  const { values } = parseArgs({ options: {
    "env-file": { type: "string", default: ".data/trial/env" },
    project: { type: "string" },
    "confirm-delete-non-operators": { type: "boolean" },
    help: { type: "boolean" },
  } });
  if (values.help) {
    console.log("pnpm google:delete-users [--env-file PATH]\nDefault: preview ALL default-tenant Google users, preserving operators.\nDelete: --project PROJECT_ID --confirm-delete-non-operators\nDevelopment only. Does not clear local data, cancel subscriptions or delete personal Google accounts. Stop the API and pause signups before confirmation.");
    return;
  }
  const root = fileURLToPath(new URL("..", import.meta.url));
  const env = { ...process.env, ...parseEnv(readFileSync(values["env-file"]!, "utf8")) };
  if (existsSync(join(root, ".data/server-migration-source.lock")))
    throw new IdentityCleanupError("Deletion blocked during server migration.");
  const confirmed = !!values["confirm-delete-non-operators"];
  if ((confirmed || values.project) && values.project !== env.BEARPORTAL_IDENTITY_PROJECT_ID)
    throw new IdentityCleanupError("Specify --project matching BEARPORTAL_IDENTITY_PROJECT_ID.");
  if (!env.MIGRATION_DATABASE_URL) throw new IdentityCleanupError("MIGRATION_DATABASE_URL is required to protect operators.");
  const url = new URL(env.MIGRATION_DATABASE_URL);
  if (!["127.0.0.1", "localhost", "[::1]"].includes(url.hostname) || !/^bearportal(?:_test_[a-z0-9_]+)?$/.test(url.pathname.slice(1)))
    throw new IdentityCleanupError("Requires the local BearPortal development database.");
  const db = new pg.Client({ connectionString: env.MIGRATION_DATABASE_URL });
  await db.connect();
  try {
    const protection = () => identityTargets(db, env);
    const protectedAccounts = await protection();
    const admin = createAdminIdentity();
    await admin.permissions(protectedAccounts.project);
    const users = await admin.list(protectedAccounts.project);
    const preserved = users.filter(u => isProtected(u, protectedAccounts));
    const selected = users.filter(u => !isProtected(u, protectedAccounts));
    // Fail closed if configured protection cannot be matched to any cloud identity.
    if (!preserved.length) throw new IdentityCleanupError("No protected operator account found in Google. Resolve operator identity configuration before deleting.");
    console.log(JSON.stringify({ preview: !confirmed, project: protectedAccounts.project, preserved, selected, localData: "Unchanged; subscriptions and resources remain unchanged." }, null, 2));
    if (!confirmed || !selected.length) return;
    const backups = join(root, ".data/backups");
    mkdirSync(backups, { recursive: true, mode: 0o700 });
    const directory = mkdtempSync(join(backups, "google-users-delete-"));
    const path = join(directory, "receipt.json");
    const receipt = { project: protectedAccounts.project, planned: selected, results: [] as { uid: string; status: string }[], complete: false };
    const save = () => {
      writeFileSync(path + ".tmp", JSON.stringify(receipt, null, 2), { mode: 0o600 });
      renameSync(path + ".tmp", path);
    };
    save();
    console.log("Private deletion receipt: " + path);
    await deleteNonOperators(selected, protection, admin, (uid, status) => {
      receipt.results.push({ uid, status }); save();
      console.log(status + ": " + uid);
    });
    receipt.complete = true; save();
    console.log("Finished. Local BearPortal records were not cleared.");
  } finally { await db.end(); }
}
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main().catch(error => {
    console.error(error instanceof IdentityCleanupError ? error.message : "Google user deletion stopped. Check credentials, project and database access.");
    console.error("Earlier deletions cannot be rolled back. Check any receipt and rerun preview before retrying.");
    process.exitCode = 1;
  });
}
