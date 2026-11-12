-- Registration/subscription/domain entry never authorizes inventory reservation.
ALTER TABLE allocation_requests ADD COLUMN install_requested_at timestamptz;
UPDATE allocation_requests a SET install_requested_at=r.consented_at
FROM onboarding_requests r WHERE r.organization_id=a.organization_id AND r.consented_at IS NOT NULL;
UPDATE allocation_requests a SET install_requested_at=d.requested_at
FROM (SELECT organization_id,min(created_at) AS requested_at FROM deployments WHERE test_mail_consent=true GROUP BY organization_id) d
WHERE d.organization_id=a.organization_id AND a.install_requested_at IS NULL;
CREATE INDEX allocation_install_queue ON allocation_requests(profile_code,install_requested_at,id)
 WHERE state='waiting_for_server' AND cancelled_at IS NULL AND install_requested_at IS NOT NULL;

-- The allocator must see paused requests from every organization before assigning capacity.
CREATE POLICY onboarding_allocator_read ON onboarding_requests FOR SELECT USING (bearportal_actor()='allocator');
