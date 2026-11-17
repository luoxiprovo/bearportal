import {requestInstallationAllocation} from "./installation-request.ts";
import { HttpError } from "./errors.ts";
import type { Queryable } from "../../../packages/servers/src/allocate.ts";

export async function requireSetupConsent(
  db: Queryable,
  organizationId: string,
  domainId: string,
  supplied: boolean,
): Promise<void> {
  if (supplied) return;
  const existing = await db.query(
    "SELECT 1 FROM onboarding_requests WHERE organization_id=$1 AND domain_id=$2 AND consented_at IS NOT NULL",
    [organizationId, domainId],
  );
  if (!existing.rows[0])
    throw new HttpError(
      400,
      "CONSENT_REQUIRED",
      "Authorize domain verification, mail routing and installation when connecting your provider.",
    );
}

export async function enqueueOnboarding(
  db: Queryable,
  organizationId: string,
  domainId: string,
): Promise<void> {
  const current = await db.query<{
    state: string;
    last_error_code: string | null;
  }>(
    "SELECT state,last_error_code FROM onboarding_requests WHERE organization_id=$1 FOR UPDATE",
    [organizationId],
  );
  if (current.rows[0]?.state === "installing")
    throw new HttpError(
      409,
      "SETUP_IN_PROGRESS",
      "Your setup is already running. Check its progress in your account.",
    );
  if (current.rows[0]?.last_error_code === "OUTCOME_UNKNOWN")
    throw new HttpError(
      409,
      "REVIEW_REQUIRED",
      "Our team needs to review the interrupted setup before restarting it.",
    );
  await requestInstallationAllocation(db,organizationId,domainId);
  // Check capacity in the credential submission transaction so the first page is accurate.
  const previous = (await db.query<{ actor: string }>(
    "SELECT current_setting('bearportal.actor',true) AS actor",
  )).rows[0]?.actor ?? "";
  let missing: string | null = null;
  await db.query("SELECT set_config('bearportal.actor','platform_administrator',true)");
  try {
    const capacity = (await db.query<{ server: boolean; relay: boolean }>(
      `SELECT
       (EXISTS(SELECT 1 FROM server_assignments a JOIN servers s ON s.id=a.server_id
         WHERE a.organization_id=$1 AND a.released_at IS NULL AND s.state IN ('reserved','assigned'))
        OR EXISTS(SELECT 1 FROM servers s WHERE s.state='available' AND s.profile_code='e2-micro'
         AND s.tenant_tainted_at IS NULL AND s.validated_at>now()-interval '5 minutes'
         AND ((s.last_heartbeat_at>now()-interval '3 minutes' AND EXISTS(
           SELECT 1 FROM host_identities h WHERE h.id=s.host_identity_id AND h.state='confirmed' AND h.revoked_at IS NULL))
           OR s.readiness_report->>'source'='ssh')
         AND NOT EXISTS(SELECT 1 FROM server_assignments a WHERE a.server_id=s.id AND a.released_at IS NULL)
         AND NOT EXISTS(SELECT 1 FROM recovery_bindings b WHERE b.replacement_server_id=s.id AND b.state='pending'))) AS server,
       EXISTS(SELECT 1 FROM relay_connections r WHERE r.state IN ('inactive','available')
         AND r.api_secret_ref IS NOT NULL AND r.smtp_secret_ref IS NOT NULL
         AND NOT EXISTS(SELECT 1 FROM relay_assignments a WHERE a.relay_connection_id=r.id AND a.released_at IS NULL))
       OR EXISTS(SELECT 1 FROM relay_assignments a JOIN relay_connections r ON r.id=a.relay_connection_id
         WHERE a.organization_id=$1 AND a.released_at IS NULL AND r.state<>'disabled') AS relay`,
      [organizationId],
    )).rows[0];
    missing = !capacity?.server && !capacity?.relay ? "server_and_relay"
      : !capacity?.server ? "server" : !capacity?.relay ? "relay" : null;
  } finally {
    await db.query("SELECT set_config('bearportal.actor',$1,true)", [previous]);
  }
  await db.query(
    `INSERT INTO onboarding_requests (organization_id, domain_id, state, missing_resource)
    VALUES ($1, $2, $3, $4)
    ON CONFLICT (organization_id) DO UPDATE SET domain_id = EXCLUDED.domain_id,
      state = CASE WHEN onboarding_requests.state = 'installing' THEN 'installing' ELSE EXCLUDED.state END,
      missing_resource = EXCLUDED.missing_resource, last_error_code = NULL, consented_at = CASE WHEN onboarding_requests.domain_id=EXCLUDED.domain_id THEN onboarding_requests.consented_at ELSE now() END,
      attempts = CASE WHEN onboarding_requests.state = 'installing' THEN onboarding_requests.attempts ELSE 0 END,
      next_attempt_at = now(), updated_at = now()`,
    [organizationId, domainId, missing ? "waiting_resources" : "queued", missing],
  );
}
