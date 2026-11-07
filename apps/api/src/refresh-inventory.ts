import { randomUUID } from "node:crypto";
import type { InventoryContext } from "./inventory.ts";
import type { SshProbeOutcome } from "../../../packages/servers/src/ssh-probe.ts";
import { mutationsPaused } from "./oversight.ts";

// Probe outside database transactions; compare the snapshot before publishing the result.
// Failed, assigned, tainted and recovery-reserved machines are never automatically recycled.
export async function refreshWaitingInventory(
  inventory: InventoryContext,
): Promise<void> {
  if (!inventory.sshProbe) return;
  const eligibility = `s.state='available' AND s.profile_code='e2-micro' AND s.tenant_tainted_at IS NULL
    AND s.readiness_report->>'source'='ssh'
    AND NOT EXISTS(SELECT 1 FROM server_assignments a WHERE a.server_id=s.id AND a.released_at IS NULL)
    AND NOT EXISTS(SELECT 1 FROM recovery_bindings b WHERE b.replacement_server_id=s.id AND b.state='pending')`;
  const candidate = await inventory.withSystem(
    "inventory_worker",
    async (db) => {
      await inventory.setActor(db, "platform_administrator");
      if (await mutationsPaused(db)) return null;
      const rows = await db.query<{
        id: string;
        version: number;
        public_ipv4: string;
      }>(`SELECT s.id,s.version,host(s.public_ipv4) AS public_ipv4 FROM servers s
      WHERE ${eligibility} AND (s.validated_at IS NULL OR s.validated_at <= now()-interval '5 minutes')
      AND EXISTS(SELECT 1 FROM onboarding_requests r JOIN organizations o ON o.id=r.organization_id JOIN users u ON u.id=o.owner_user_id
        WHERE r.state IN ('queued','waiting_resources') AND r.next_attempt_at <= now() AND o.status='active' AND u.status='active' AND u.email_verified
        AND NOT EXISTS(SELECT 1 FROM server_assignments a WHERE a.organization_id=r.organization_id AND a.released_at IS NULL))
      ORDER BY s.available_since,s.id LIMIT 1`);
      return rows.rows[0] ?? null;
    },
  );
  if (!candidate) return;
  let outcome: SshProbeOutcome;
  try {
    outcome = await inventory.sshProbe(candidate.public_ipv4);
  } catch {
    outcome = { ok: false, failures: ["server.ssh_unavailable"], report: null };
  }
  await inventory.withSystem("inventory_worker", async (db) => {
    await inventory.setActor(db, "platform_administrator");
    if (await mutationsPaused(db)) return;
    const result = await db.query(
      `UPDATE servers s SET state=$4,validated_at=CASE WHEN $5 THEN now() ELSE NULL END,
      available_since=CASE WHEN $5 THEN coalesce(s.available_since,now()) ELSE NULL END,
      readiness_report=$6::jsonb,version=s.version+1,updated_at=now()
      WHERE s.id=$1 AND s.version=$2 AND s.public_ipv4=$3::inet AND ${eligibility} RETURNING s.id`,
      [
        candidate.id,
        candidate.version,
        candidate.public_ipv4,
        outcome.ok ? "available" : "pending_validation",
        outcome.ok,
        JSON.stringify({
          ...outcome.report,
          source: "ssh",
          reachable: outcome.report?.reachable ?? outcome.ok,
          failures: outcome.failures,
        }),
      ],
    );
    if (!result.rows[0]) return;
    const jobId = randomUUID();
    const summary = {
      automatic: true,
      ok: outcome.ok,
      failures: outcome.failures,
    };
    await db.query(
      "INSERT INTO inventory_jobs(id,server_id,kind,state,result) VALUES($1,$2,'readiness',$3,$4::jsonb)",
      [
        jobId,
        candidate.id,
        outcome.ok ? "succeeded" : "failed",
        JSON.stringify(summary),
      ],
    );
    await db.query(
      "INSERT INTO audit_events(id,actor_type,action,target,job_id,request_id,redacted_diff) VALUES($1,'system','server.validate',$2,$3,$4,$5::jsonb)",
      [
        randomUUID(),
        candidate.id,
        jobId,
        randomUUID(),
        JSON.stringify(summary),
      ],
    );
  });
}
