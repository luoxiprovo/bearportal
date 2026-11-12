-- Migration-owner tables use FORCE RLS. Backfill through the existing control-plane
-- actor within this migration transaction; the prior actor is restored at commit.
SELECT set_config('bearportal.actor','platform_administrator',true);
UPDATE allocation_requests a SET install_requested_at=r.consented_at
FROM onboarding_requests r
WHERE r.organization_id=a.organization_id AND r.consented_at IS NOT NULL
  AND a.install_requested_at IS NULL AND a.state<>'cancelled';
UPDATE allocation_requests a SET install_requested_at=d.requested_at
FROM (SELECT organization_id,min(created_at) AS requested_at FROM deployments WHERE test_mail_consent=true GROUP BY organization_id) d
WHERE d.organization_id=a.organization_id AND a.install_requested_at IS NULL AND a.state<>'cancelled';
