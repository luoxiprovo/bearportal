import { randomUUID } from "node:crypto";

export type Queryable = {
  query<T extends Record<string, unknown> = Record<string, unknown>>(
    sql: string,
    params?: unknown[],
  ): Promise<{ rows: T[]; rowCount: number | null }>;
};

export type AssignedServer = {
  organizationId: string;
  allocationId: string;
  assignmentId: string;
  serverId: string;
  publicIpv4: string;
};

export type CustomerServerSummary = {
  id: string;
  publicIpv4: string;
  state: string;
  readiness: "ready" | "not_ready";
};

/**
 * FIFO allocation for one profile. The caller holds the surrounding transaction.
 * Exclusivity is the advisory lock plus the partial unique indexes, not an application mutex.
 */
export async function allocateProfile(db: Queryable, profileCode: string, limit: number): Promise<{ assigned: AssignedServer[] }> {
  await db.query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0::bigint))", [`bearportal.allocate.${profileCode}`]);
  const assigned: AssignedServer[] = [];
  const cap = Math.min(Math.max(limit, 0), 100);
  for (let step = 0; step < cap; step += 1) {
    const one = await assignOldest(db, profileCode);
    if (!one) break;
    assigned.push(one);
  }
  const waiting = await db.query<{ n: number }>(
    `SELECT count(*)::int AS n
     FROM allocation_requests r
     JOIN organizations o ON o.id = r.organization_id
     WHERE r.state = 'waiting_for_server'
       AND r.profile_code = $1
       AND r.install_requested_at IS NOT NULL
       AND NOT EXISTS(SELECT 1 FROM onboarding_requests setup WHERE setup.organization_id=r.organization_id AND setup.state='attention')
       AND r.cancelled_at IS NULL
       AND o.status = 'active'
       AND (NOT o.billing_required OR EXISTS(SELECT 1 FROM billing_subscriptions b WHERE b.organization_id=o.id AND b.status IN ('trialing','active') AND b.access_until>now() AND b.cancel_requested_at IS NULL AND b.invoice_issue_code IS NULL))`,
    [profileCode],
  );
  if ((waiting.rows[0]?.n ?? 0) > 0) await ensureShortage(db);
  else await resolveShortage(db);
  return { assigned };
}

async function assignOldest(db: Queryable, profileCode: string): Promise<AssignedServer | null> {
  const waiter = await db.query<{ id: string; organization_id: string }>(
    `SELECT r.id, r.organization_id
     FROM allocation_requests r
     JOIN organizations o ON o.id = r.organization_id
     WHERE r.state = 'waiting_for_server'
       AND r.profile_code = $1
       AND r.install_requested_at IS NOT NULL
       AND NOT EXISTS(SELECT 1 FROM onboarding_requests setup WHERE setup.organization_id=r.organization_id AND setup.state='attention')
       AND r.cancelled_at IS NULL
       AND o.status = 'active'
       AND (NOT o.billing_required OR EXISTS(SELECT 1 FROM billing_subscriptions b WHERE b.organization_id=o.id AND b.status IN ('trialing','active') AND b.access_until>now() AND b.cancel_requested_at IS NULL AND b.invoice_issue_code IS NULL))
       AND NOT EXISTS (
         SELECT 1 FROM server_assignments a
         WHERE a.organization_id = r.organization_id AND a.released_at IS NULL
       )
     ORDER BY r.install_requested_at, r.id
     LIMIT 1
     FOR UPDATE OF r`,
    [profileCode],
  );
  const request = waiter.rows[0];
  if (!request) return null;
  const candidate = await db.query<{ id: string }>(
    `SELECT s.id
     FROM servers s
     WHERE s.state = 'available'
       AND s.profile_code = $1
       AND s.tenant_tainted_at IS NULL
       AND s.validated_at > now() - interval '5 minutes'
       AND (
         (
           s.last_heartbeat_at > now() - interval '3 minutes'
           AND EXISTS (
             SELECT 1 FROM host_identities h
             WHERE h.id = s.host_identity_id AND h.state = 'confirmed' AND h.revoked_at IS NULL
           )
         )
         OR coalesce(s.readiness_report->>'source', '') = 'ssh'
       )
       AND NOT EXISTS (
         SELECT 1 FROM server_assignments a
         WHERE a.server_id = s.id AND a.released_at IS NULL
       )
       AND NOT EXISTS (
         SELECT 1 FROM recovery_bindings b
         WHERE b.replacement_server_id = s.id AND b.state = 'pending'
       )
     ORDER BY s.available_since, s.id
     LIMIT 1
     FOR UPDATE OF s`,
    [profileCode],
  );
  const server = candidate.rows[0];
  if (!server) return null;
  const reserved = await db.query<{ id: string; public_ipv4: string }>(
    `UPDATE servers
     SET state = 'reserved', auth_epoch = auth_epoch + 1, updated_at = now(), version = version + 1
     WHERE id = $1
       AND state = 'available'
       AND tenant_tainted_at IS NULL
       AND validated_at > now() - interval '5 minutes'
       AND (
         (
           last_heartbeat_at > now() - interval '3 minutes'
           AND EXISTS (
             SELECT 1 FROM host_identities h
             WHERE h.id = host_identity_id AND h.state = 'confirmed' AND h.revoked_at IS NULL
           )
         )
         OR coalesce(readiness_report->>'source', '') = 'ssh'
       )
       AND NOT EXISTS (
         SELECT 1 FROM server_assignments a
         WHERE a.server_id = $1 AND a.released_at IS NULL
       )
       AND NOT EXISTS (
         SELECT 1 FROM recovery_bindings b
         WHERE b.replacement_server_id = $1 AND b.state = 'pending'
       )
     RETURNING id, host(public_ipv4) AS public_ipv4`,
    [server.id],
  );
  const reservedRow = reserved.rows[0];
  if (!reservedRow) return null;
  const assignmentId = randomUUID();
  await db.query(
    `INSERT INTO server_assignments (id, organization_id, server_id, reason, generation)
     VALUES ($1, $2, $3, 'fifo', 1)`,
    [assignmentId, request.organization_id, reservedRow.id],
  );
  await db.query(
    `UPDATE allocation_requests
     SET state = 'allocated', assignment_id = $2, updated_at = now(), version = version + 1
     WHERE id = $1 AND state = 'waiting_for_server'`,
    [request.id, assignmentId],
  );
  await db.query(
    `INSERT INTO outbox_events (id, event_type, aggregate_id, payload, dedupe_key)
     VALUES ($1, 'organization.allocate', $2, $3::jsonb, $4)`,
    [
      randomUUID(),
      request.organization_id,
      JSON.stringify({
        organizationId: request.organization_id,
        allocationId: request.id,
        assignmentId,
        serverId: reservedRow.id,
      }),
      `allocate:${request.organization_id}`,
    ],
  );
  return {
    organizationId: request.organization_id,
    allocationId: request.id,
    assignmentId,
    serverId: reservedRow.id,
    publicIpv4: reservedRow.public_ipv4,
  };
}

async function ensureShortage(db: Queryable): Promise<void> {
  await db.query(
    `INSERT INTO required_actions (id, scope, audience, code, instructions, state)
     SELECT $1::uuid, 'inventory', 'operator', 'inventory.shortage', 'No compatible server is available.', 'open'
     WHERE NOT EXISTS (
       SELECT 1 FROM required_actions WHERE state = 'open' AND code = 'inventory.shortage'
     )`,
    [randomUUID()],
  );
}

async function resolveShortage(db: Queryable): Promise<void> {
  await db.query(
    `UPDATE required_actions
     SET state = 'resolved', resolved_at = now(), updated_at = now(), version = version + 1
     WHERE state = 'open' AND code = 'inventory.shortage'`,
  );
}

export async function readCustomerServer(db: Queryable, organizationId: string): Promise<CustomerServerSummary | null> {
  const row = await db.query<{ id: string; public_ipv4: string; state: string }>(
    `SELECT s.id, host(s.public_ipv4) AS public_ipv4, s.state
     FROM server_assignments a
     JOIN servers s ON s.id = a.server_id
     WHERE a.organization_id = $1 AND a.released_at IS NULL`,
    [organizationId],
  );
  const server = row.rows[0];
  if (!server) return null;
  const ready = server.state === "reserved" || server.state === "assigned";
  return {
    id: server.id,
    publicIpv4: server.public_ipv4,
    state: server.state,
    readiness: ready ? "ready" : "not_ready",
  };
}
