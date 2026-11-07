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
  await db.query(
    `INSERT INTO onboarding_requests (organization_id, domain_id)
    VALUES ($1, $2)
    ON CONFLICT (organization_id) DO UPDATE SET domain_id = EXCLUDED.domain_id,
      state = CASE WHEN onboarding_requests.state = 'installing' THEN 'installing' ELSE 'queued' END,
      missing_resource = NULL, last_error_code = NULL, consented_at = CASE WHEN onboarding_requests.domain_id=EXCLUDED.domain_id THEN onboarding_requests.consented_at ELSE now() END,
      attempts = CASE WHEN onboarding_requests.state = 'installing' THEN onboarding_requests.attempts ELSE 0 END,
      next_attempt_at = now(), updated_at = now()`,
    [organizationId, domainId],
  );
}
