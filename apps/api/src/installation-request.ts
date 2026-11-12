import { randomUUID } from "node:crypto";
import type { Queryable } from "../../../packages/servers/src/allocate.ts";
import { HttpError } from "./errors.ts";

export async function assertInstallDomainAvailable(
  db: Queryable,
  organizationId: string,
  domainId: string,
) {
  const domain = (
    await db.query<{ normalized_name: string }>(
      "SELECT normalized_name FROM domains WHERE id=$1 AND organization_id=$2 AND state<>'retired'",
      [domainId, organizationId],
    )
  ).rows[0];
  if (!domain)
    throw new HttpError(404, "NOT_FOUND", "The domain was not found.");
  await db.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", [
    "bearportal.install-domain." + domain.normalized_name,
  ]);
  const previous =
    (
      await db.query<{ actor: string }>(
        "SELECT current_setting('bearportal.actor',true) AS actor",
      )
    ).rows[0]?.actor ?? "";
  await db.query(
    "SELECT set_config('bearportal.actor','platform_administrator',true)",
  );
  let occupied;
  try {
    occupied = (
      await db.query(
        `SELECT 1 FROM domains d WHERE d.normalized_name=$1 AND d.organization_id<>$2 AND (EXISTS(SELECT 1 FROM deployments p WHERE p.domain_id=d.id AND p.lifecycle_state<>'deleted') OR EXISTS(SELECT 1 FROM onboarding_requests r JOIN organizations o ON o.id=r.organization_id WHERE r.domain_id=d.id AND r.consented_at IS NOT NULL AND o.status='active')) LIMIT 1`,
        [domain.normalized_name, organizationId],
      )
    ).rows[0];
  } finally {
    await db.query("SELECT set_config('bearportal.actor',$1,true)", [previous]);
  }
  if (occupied)
    throw new HttpError(
      409,
      "DOMAIN_ALREADY_IN_USE",
      "This domain already has a setup or installation under another account. Ask the operator to review its ownership before installing it again.",
    );
}
export async function requestInstallationAllocation(
  db: Queryable,
  organizationId: string,
  domainId: string,
) {
  await assertInstallDomainAvailable(db, organizationId, domainId);
  await db.query(
    `INSERT INTO allocation_requests(id,organization_id,profile_code,verified_registered_at,state,install_requested_at)
 VALUES($1,$2,'e2-micro',now(),'waiting_for_server',now())
 ON CONFLICT(organization_id) WHERE state<>'cancelled' DO UPDATE SET install_requested_at=coalesce(allocation_requests.install_requested_at,EXCLUDED.install_requested_at),updated_at=now(),version=allocation_requests.version+1`,
    [randomUUID(), organizationId],
  );
}
export async function installationRequested(
  db: Queryable,
  organizationId: string,
): Promise<boolean> {
  return Boolean(
    (
      await db.query(
        `SELECT 1 FROM allocation_requests WHERE organization_id=$1 AND install_requested_at IS NOT NULL AND cancelled_at IS NULL AND state<>'cancelled' AND NOT EXISTS(SELECT 1 FROM onboarding_requests r WHERE r.organization_id=$1 AND r.state='attention')`,
        [organizationId],
      )
    ).rows[0],
  );
}
