import assert from "node:assert/strict";
import { test } from "node:test";
import { randomUUID } from "node:crypto";
import pg from "pg";
import { migrate } from "../packages/db/src/migrate.ts";
import { allocateProfile } from "../packages/servers/src/allocate.ts";
import {
  assertInstallDomainAvailable,
  requestInstallationAllocation,
} from "../apps/api/src/installation-request.ts";
import { HttpError } from "../apps/api/src/errors.ts";
import { integrationDatabases, queryTestDatabase } from "./helpers/database.ts";
const { databaseUrl, migrationUrl, superDatabaseUrl } = integrationDatabases();
const query = (sql: string) => queryTestDatabase(sql, superDatabaseUrl);
const q = (s: string) => "'" + s.replaceAll("'", "''") + "'";
test("inventory is allocated by install-request time; unstarted legacy and paused accounts cannot consume capacity", async () => {
  await migrate(migrationUrl);
  await query(
    "TRUNCATE users,organizations,servers,relay_connections,domains,secret_refs,deployments,jobs,operator_roles,allocation_requests,invitations,idempotency_keys,audit_events,outbox_events CASCADE",
  );
  const entries = ["unstarted", "younger-first", "older-second", "paused"].map(
    (name) => ({
      name,
      user: randomUUID(),
      org: randomUUID(),
      domain: randomUUID(),
    }),
  );
  for (const [index, row] of entries.entries()) {
    const requested =
      index === 0
        ? "NULL"
        : index === 1
          ? "now()-interval '20 minutes'"
          : index === 2
            ? "now()-interval '10 minutes'"
            : "now()-interval '30 minutes'";
    await query(`INSERT INTO users(id,identity_subject,verified_email,email_verified,status) VALUES(${q(row.user)},${q(row.name)},${q(row.name + "@example.org")},true,'active');
  INSERT INTO organizations(id,owner_user_id,name,status,billing_required) VALUES(${q(row.org)},${q(row.user)},${q(row.name)},'active',false);
  INSERT INTO allocation_requests(id,organization_id,profile_code,verified_registered_at,state,install_requested_at) VALUES(${q(randomUUID())},${q(row.org)},'e2-micro',now()-interval '${index === 1 ? 1 : 3} days','waiting_for_server',${requested});
  INSERT INTO domains(id,organization_id,normalized_name,existing_mail,state) VALUES(${q(row.domain)},${q(row.org)},${q(row.name + ".site")},false,'pending');`);
  }
  const paused = entries[3]!;
  await query(
    `INSERT INTO onboarding_requests(organization_id,domain_id,state,last_error_code) VALUES(${q(paused.org)},${q(paused.domain)},'attention','DOMAIN_ALREADY_IN_USE')`,
  );
  for (let i = 0; i < 2; i++)
    await query(
      `INSERT INTO servers(id,label,public_ipv4,profile_code,operator_contact,state,validated_at,available_since,readiness_report) VALUES(${q(randomUUID())},${q("capacity-" + i)},${q("9.9.9." + (9 + i))},'e2-micro','','available',now(),now(),'{"source":"ssh"}')`,
    );
  const db = new pg.Client({ connectionString: databaseUrl });
  await db.connect();
  try {
    await db.query("BEGIN");
    await db.query("SELECT set_config('bearportal.actor','allocator',true)");
    const result = await allocateProfile(db, "e2-micro", 100);
    assert.deepEqual(
      result.assigned.map((item) => item.organizationId),
      [entries[1]!.org, entries[2]!.org],
    );
    await db.query("COMMIT");
    assert.deepEqual(
      await query(
        `SELECT count(*) FROM server_assignments WHERE organization_id=${q(entries[0]!.org)} AND released_at IS NULL`,
      ),
      [["0"]],
    );
    assert.deepEqual(
      await query(
        `SELECT count(*) FROM server_assignments WHERE organization_id=${q(paused.org)} AND released_at IS NULL`,
      ),
      [["0"]],
    );
    assert.deepEqual(
      await query(
        "SELECT count(*) FROM required_actions WHERE state='open' AND code='inventory.shortage'",
      ),
      [["0"]],
      "Unstarted/paused accounts are not a capacity shortage",
    );
    const legacy = entries[0]!;
    await db.query("BEGIN");
    await db.query(
      "SELECT set_config('bearportal.actor','platform_administrator',true)",
    );
    await requestInstallationAllocation(db, legacy.org, legacy.domain);
    const first = (
      await db.query(
        "SELECT install_requested_at FROM allocation_requests WHERE organization_id=$1",
        [legacy.org],
      )
    ).rows[0].install_requested_at;
    await requestInstallationAllocation(db, legacy.org, legacy.domain);
    assert.equal(
      (
        await db.query(
          "SELECT install_requested_at FROM allocation_requests WHERE organization_id=$1",
          [legacy.org],
        )
      ).rows[0].install_requested_at.getTime(),
      first.getTime(),
      "Retry keeps the original queue time",
    );
    await db.query("COMMIT");
    // The cross-account ownership check must work even when customer RLS hides the other deployment.
    await query(`UPDATE domains SET normalized_name='occupied.site' WHERE id IN (${q(legacy.domain)},${q(entries[1]!.domain)});
  INSERT INTO deployments(id,organization_id,domain_id,desired_state,onboarding_stage,lifecycle_state,health_state,test_mail_consent) VALUES(${q(randomUUID())},${q(entries[1]!.org)},${q(entries[1]!.domain)},'active','verifying_mail','onboarding','unknown',true);`);
    await db.query("BEGIN");
    await db.query(
      "SELECT set_config('bearportal.actor','customer',true),set_config('bearportal.user_id',$1,true),set_config('bearportal.organization_id',$2,true)",
      [legacy.user, legacy.org],
    );
    assert.equal(
      (
        await db.query(
          "SELECT count(*) FROM deployments WHERE organization_id=$1",
          [entries[1]!.org],
        )
      ).rows[0].count,
      "0",
    );
    await assert.rejects(
      assertInstallDomainAvailable(db, legacy.org, legacy.domain),
      (error: unknown) =>
        error instanceof HttpError && error.code === "DOMAIN_ALREADY_IN_USE",
    );
    assert.equal(
      (await db.query("SELECT current_setting('bearportal.actor') AS actor"))
        .rows[0].actor,
      "customer",
      "Ownership check restores the caller permissions",
    );
    await db.query("ROLLBACK");
  } finally {
    await db.end();
  }
});
