import { billingView } from "./billing.ts";
import { createHash, randomUUID } from "node:crypto";
import type { FastifyInstance, FastifyRequest } from "fastify";
import {
  cancellationExecuteSchema,
  cancellationPlanSchema,
  cancellationWaiverSchema,
  cleanupReportSchema,
  isolationReportSchema,
  replacementPlanSchema,
  restoreReadySchema,
  restoreRequestSchema,
  serverBackupSchema,
  upgradePlanSchema,
  versionedSchema,
} from "../../../packages/contracts/src/index.ts";
import {
  backupFreshness,
  cancellationSchedule,
  cancellationTiming,
  cleanupDecision,
  evidenceReferenceAccepted,
  fencingAllowsPromotion,
  upgradePolicy,
  type FencingKind,
} from "../../../packages/operations/src/lifecycle.ts";
import { detectDnsProvider, type DetectedDnsProvider } from "../../../packages/providers/dns/src/detect.ts";
import { parseCommand } from "../../../packages/servers/src/commands.ts";
import type { Queryable } from "../../../packages/servers/src/allocate.ts";
import { HEARTBEAT_MAX_AGE_MS } from "../../../packages/servers/src/readiness.ts";
import { HttpError } from "./errors.ts";
import { recordBackupReport } from "./installation.ts";
import {
  brevoPurposes,
  recordLines,
  renderCustomerPortal,
  renderOperatorPortal,
  renderOperatorAuth,
  type ActivityLine,
  type BackupLine,
  type CustomerPortalView,
  type MailboxLine,
  type OperatorPortalView,
} from "./portal.ts";

type Db = Queryable;
type OperatorRole = "support" | "infrastructure_operator" | "platform_administrator";
type Actor = {
  subject: string;
  email: string;
  emailVerified: boolean;
  authTime: number;
  amr: string[];
  userId: string;
  organizationId: string | null;
  roles: OperatorRole[];
};
type Replay = { status: number; body: Record<string, unknown> } | null;
type ErrorBody = { error: { code: string; message: string; retryable: boolean; requiredActionId: string | null } };
type DeploymentRow = {
  id: string;
  organization_id: string;
  version: number;
  generation: number;
  lifecycle_state: string;
  server_id: string | null;
};

export type LifecycleContext = {
  refreshBilling?: (organizationId: string) => Promise<void>;
  billingRequired?: boolean;
  billingConfigured?: boolean;
  browserAuthEnabled?:boolean;
  withActor: <T>(request: FastifyRequest, mode: "customer" | "operator", fn: (db: Db, actor: Actor) => Promise<T>) => Promise<T>;
  withSystem: <T>(actor: "allocator" | "inventory_worker", fn: (db: Db) => Promise<T>) => Promise<T>;
  demandIdempotency: (request: FastifyRequest) => string;
  requireVerified: (actor: Actor) => void;
  requireMfa: (actor: Actor) => void;
  replay: (db: Db, principalId: string, route: string, key: string, body: unknown) => Promise<Replay>;
  remember: (db: Db, principalId: string, route: string, key: string, body: unknown, status: number, response: unknown) => Promise<void>;
  audit: (
    db: Db,
    request: FastifyRequest,
    actorId: string,
    organizationId: string | null,
    action: string,
    target: string,
    redacted: Record<string, unknown>,
  ) => Promise<void>;
  lookupNameservers: (domain: string) => Promise<string[]>;
  schedulerToken?: string;
};

const RECENT_AUTH_SECONDS = 15 * 60;

const RELEASE_NOTES = [
  "Local backup, restore, upgrade, and cancellation state is recorded without cloud API calls.",
  "A real backup drill, binary rollback, observed host stop, and 24 hour e2-micro soak were not run.",
  "The Grok model loop stays disabled. Live Brevo, DNS, and the BearMail installer were not run from this process.",
];

export function registerLifecycleRoutes(app: FastifyInstance, ctx: LifecycleContext): void {
  app.post("/v1/deployments/:id/restore-requests", async (request, reply) => {
    const idempotencyKey = ctx.demandIdempotency(request);
    const { id } = request.params as { id: string };
    const body = restoreRequestSchema.parse(request.body);
    const created = await ctx.withActor(request, "customer", async (db, actor) => {
      const route = "POST /v1/deployments/:id/restore-requests";
      const replayed = await ctx.replay(db, actor.userId, route, idempotencyKey, { id, ...body });
      if (replayed) return replayed;
      requireCustomer(ctx, actor);
      await assertMutable(db);
      const deployment = await loadDeployment(db, id, actor.organizationId);
      if (deployment.version !== body.expectedVersion) throw new HttpError(409, "VERSION_CONFLICT", "The deployment changed.");
      const backup = await db.query<{ id: string }>(
        "SELECT id FROM backups WHERE id = $1 AND organization_id = $2 AND deployment_id = $3",
        [body.backupId, actor.organizationId, id],
      );
      if (!backup.rows[0]) throw new HttpError(404, "NOT_FOUND", "The backup was not found.");
      const open = await db.query("SELECT id FROM restore_requests WHERE deployment_id = $1 AND state IN ('requested', 'ready')", [id]);
      if (open.rows[0]) throw new HttpError(409, "RESTORE_OPEN", "A restore request is already open.");
      await bumpDeployment(db, id, actor.organizationId, deployment.version);
      const approvalId = randomUUID();
      const requestId = randomUUID();
      const planHash = sha256(`restore\n${id}\n${body.backupId}\n${deployment.generation}`);
      await insertApproval(db, approvalId, deployment.organization_id, id, "restore", planHash, deployment.generation, requestId);
      await db.query(
        `INSERT INTO restore_requests (
           id, organization_id, deployment_id, backup_id, approval_id, plan_hash, state, acknowledge_data_loss
         ) VALUES ($1, $2, $3, $4, $5, $6, 'requested', true)`,
        [requestId, deployment.organization_id, id, body.backupId, approvalId, planHash],
      );
      const actionId = await openAction(db, deployment.organization_id, id, null, "restore.operator_required", "The owner requested a restore. This does not restore a disk or create a second server.");
      await ctx.audit(db, request, actor.userId, deployment.organization_id, "restore.request", id, { backupId: body.backupId, automatic: false });
      const response = {
        restoreRequestId: requestId,
        approvalId,
        planHash,
        state: "requested",
        automaticRestore: false,
        requiredActionId: actionId,
        mailVerified: false,
        cloudVerified: false,
      };
      await ctx.remember(db, actor.userId, route, idempotencyKey, { id, ...body }, 202, response);
      return { status: 202 as const, body: response };
    });
    return reply.code(created.status).send({ ...created.body, requestId: request.id });
  });

  app.post("/v1/deployments/:id/cancellation-plan", async (request, reply) => {
    const idempotencyKey = ctx.demandIdempotency(request);
    const { id } = request.params as { id: string };
    const body = cancellationPlanSchema.parse(request.body);
    const created = await ctx.withActor(request, "customer", async (db, actor) => {
      const route = "POST /v1/deployments/:id/cancellation-plan";
      const replayed = await ctx.replay(db, actor.userId, route, idempotencyKey, { id, ...body });
      if (replayed) return replayed;
      requireCustomer(ctx, actor);
      await assertMutable(db);
      const deployment = await loadDeployment(db, id, actor.organizationId);
      if (deployment.version !== body.expectedVersion) throw new HttpError(409, "VERSION_CONFLICT", "The deployment changed.");
      const open = await db.query("SELECT id FROM cancellation_schedules WHERE deployment_id = $1 AND state IN ('proposed', 'scheduled', 'stopped')", [id]);
      if (open.rows[0]) throw new HttpError(409, "CANCELLATION_OPEN", "A cancellation is already open.");
      const timing = cancellationSchedule(Date.now());
      const planHash = sha256(`cancellation\n${id}\n${deployment.generation}\n${timing.executeAt.toISOString()}\n7\n${body.reason ?? ""}`);
      await bumpDeployment(db, id, actor.organizationId, deployment.version);
      const approvalId = randomUUID();
      const scheduleId = randomUUID();
      await insertApproval(db, approvalId, deployment.organization_id, id, "cancellation", planHash, deployment.generation, scheduleId);
      await db.query(
        `INSERT INTO cancellation_schedules (
           id, organization_id, deployment_id, approval_id, reason, plan_hash, generation, state, execute_at, window_ends_at
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, 'proposed', $8, $9)`,
        [scheduleId, deployment.organization_id, id, approvalId, body.reason ?? null, planHash, deployment.generation, timing.executeAt.toISOString(), timing.windowEndsAt.toISOString()],
      );
      await ctx.audit(db, request, actor.userId, deployment.organization_id, "cancellation.plan", id, { scheduleId, retentionDays: 7 });
      const response = {
        scheduleId,
        approvalId,
        planHash,
        state: "proposed",
        executeAt: timing.executeAt.toISOString(),
        windowEndsAt: timing.windowEndsAt.toISOString(),
        retentionDays: 7,
        approvalWindowMinutes: 30,
        executionWindowHours: 24,
        dnsWrite: false,
        cloudApiCalled: false,
        billingStopped: false,
        mailVerified: false,
      };
      await ctx.remember(db, actor.userId, route, idempotencyKey, { id, ...body }, 202, response);
      return { status: 202 as const, body: response };
    });
    return reply.code(created.status).send({ ...created.body, requestId: request.id });
  });

  app.post("/v1/deployments/:id/cancel-deletion", async (request, reply) => {
    const idempotencyKey = ctx.demandIdempotency(request);
    const { id } = request.params as { id: string };
    const body = versionedSchema.parse(request.body);
    const created = await ctx.withActor(request, "customer", async (db, actor) => {
      const route = "POST /v1/deployments/:id/cancel-deletion";
      const replayed = await ctx.replay(db, actor.userId, route, idempotencyKey, { id, ...body });
      if (replayed) return replayed;
      requireCustomer(ctx, actor);
      await assertMutable(db);
      const deployment = await loadDeployment(db, id, actor.organizationId);
      if (deployment.version !== body.expectedVersion) throw new HttpError(409, "VERSION_CONFLICT", "The deployment changed.");
      const schedule = await db.query<{ id: string; state: string }>(
        `SELECT id, state FROM cancellation_schedules
         WHERE deployment_id = $1 AND organization_id = $2
         ORDER BY created_at DESC LIMIT 1`,
        [id, actor.organizationId],
      );
      const row = schedule.rows[0];
      if (!row) throw new HttpError(404, "NOT_FOUND", "No cancellation schedule was found.");
      if (row.state === "stopped" || row.state === "completed") {
        throw new HttpError(409, "CANCELLATION_STARTED", "Service stop has already been recorded.");
      }
      if (row.state !== "proposed" && row.state !== "scheduled") {
        throw new HttpError(409, "INVALID_STATE", "The cancellation cannot be revoked from its current state.");
      }
      await db.query(
        `UPDATE cancellation_schedules SET state = 'revoked', updated_at = now(), version = version + 1
         WHERE id = $1 AND state IN ('proposed', 'scheduled')`,
        [row.id],
      );
      await bumpDeployment(db, id, actor.organizationId, deployment.version);
      await ctx.audit(db, request, actor.userId, actor.organizationId, "cancellation.revoke", id, { scheduleId: row.id });
      const response = { scheduleId: row.id, state: "revoked", serviceStopped: false, cloudApiCalled: false, assignmentReleased: false, mailVerified: false };
      await ctx.remember(db, actor.userId, route, idempotencyKey, { id, ...body }, 200, response);
      return { status: 200 as const, body: response };
    });
    return reply.code(created.status).send({ ...created.body, requestId: request.id });
  });

  app.post("/v1/deployments/:id/cancellation-waiver", async (request, reply) => {
    const idempotencyKey = ctx.demandIdempotency(request);
    const { id } = request.params as { id: string };
    const body = cancellationWaiverSchema.parse(request.body);
    const created = await ctx.withActor(request, "customer", async (db, actor) => {
      const route = "POST /v1/deployments/:id/cancellation-waiver";
      const replayed = await ctx.replay(db, actor.userId, route, idempotencyKey, { id, ...body });
      if (replayed) return replayed;
      requireCustomer(ctx, actor);
      await assertMutable(db);
      const deployment = await loadDeployment(db, id, actor.organizationId);
      if (deployment.version !== body.expectedVersion) throw new HttpError(409, "VERSION_CONFLICT", "The deployment changed.");
      const schedule = await db.query<{ id: string }>(
        `SELECT id FROM cancellation_schedules
         WHERE deployment_id = $1 AND organization_id = $2 AND state = 'scheduled'`,
        [id, actor.organizationId],
      );
      if (!schedule.rows[0]) throw new HttpError(409, "INVALID_STATE", "A scheduled cancellation is required before waiving the final backup.");
      await db.query(
        `UPDATE cancellation_schedules
         SET proceed_without_final_backup = true, updated_at = now(), version = version + 1
         WHERE id = $1`,
        [schedule.rows[0].id],
      );
      await bumpDeployment(db, id, actor.organizationId, deployment.version);
      await ctx.audit(db, request, actor.userId, actor.organizationId, "cancellation.waiver", id, { scheduleId: schedule.rows[0].id });
      const response = { scheduleId: schedule.rows[0].id, waived: true, serviceStopped: false, cloudApiCalled: false, mailVerified: false };
      await ctx.remember(db, actor.userId, route, idempotencyKey, { id, ...body }, 200, response);
      return { status: 200 as const, body: response };
    });
    return reply.code(created.status).send({ ...created.body, requestId: request.id });
  });

  app.post("/v1/mailboxes/:id/delete-plan", async (request, reply) => {
    const idempotencyKey = ctx.demandIdempotency(request);
    const { id } = request.params as { id: string };
    const body = versionedSchema.parse(request.body);
    const created = await ctx.withActor(request, "customer", async (db, actor) => {
      const route = "POST /v1/mailboxes/:id/delete-plan";
      const replayed = await ctx.replay(db, actor.userId, route, idempotencyKey, { id, ...body });
      if (replayed) return replayed;
      requireCustomer(ctx, actor);
      await assertMutable(db);
      const mailbox = await db.query<{ version: number; deployment_id: string; state: string }>(
        "SELECT version, deployment_id, state FROM mailboxes WHERE id = $1 AND organization_id = $2",
        [id, actor.organizationId],
      );
      const row = mailbox.rows[0];
      if (!row) throw new HttpError(404, "NOT_FOUND", "The mailbox was not found.");
      if (row.version !== body.expectedVersion) throw new HttpError(409, "VERSION_CONFLICT", "The mailbox changed.");
      const approvalId = randomUUID();
      const planHash = sha256(`mailbox\n${id}\n${row.version}`);
      await insertApproval(db, approvalId, actor.organizationId ?? "", row.deployment_id, "mailbox.delete", planHash, row.version, id);
      await ctx.audit(db, request, actor.userId, actor.organizationId, "mailbox.delete_plan", id, { deleted: false });
      const response = { approvalId, planHash, executed: false, deleted: false, mailboxState: row.state, mailVerified: false };
      await ctx.remember(db, actor.userId, route, idempotencyKey, { id, ...body }, 202, response);
      return { status: 202 as const, body: response };
    });
    return reply.code(created.status).send({ ...created.body, requestId: request.id });
  });

  async function setupView(db: Db, organizationId: string): Promise<CustomerPortalView> {
    let view=await customerView(db,organizationId,ctx.billingRequired===true,ctx.billingConfigured===true);
    if(view.billing?.status === "invalid_plan" && ctx.refreshBilling){
      await ctx.refreshBilling(organizationId);
      view=await customerView(db,organizationId,ctx.billingRequired===true,ctx.billingConfigured===true);
    }
    return view;
  }

  app.get("/v1/portal/overview", async (request) => {
    return ctx.withActor(request, "customer", async (db, actor) => {
      ctx.requireVerified(actor);
      if (!actor.organizationId) throw new HttpError(422, "ORGANIZATION_REQUIRED", "Create an organization first.");
      return { ...(await setupView(db, actor.organizationId)), requestId: request.id };
    });
  });

  app.get("/portal", async (request, reply) => {
    let view:CustomerPortalView;
    try { view = await ctx.withActor(request, "customer", async (db, actor) => {
      ctx.requireVerified(actor);
      if (!actor.organizationId) throw new HttpError(422, "ORGANIZATION_REQUIRED", "Create an organization first.");
      return setupView(db, actor.organizationId);
    }); } catch(error){if(ctx.browserAuthEnabled&&error instanceof HttpError&&error.status===401)return reply.code(303).header('location','/login?resume=1').send('');throw error;}
    const detected = await detectedDns(ctx, view.domainName);
    reply.type("text/html; charset=utf-8");
    return reply.send(renderCustomerPortal({ ...view, ...detected, browserAuthEnabled:ctx.browserAuthEnabled }));
  });

  app.get("/v1/admin/portal", async (request) => {
    return ctx.withActor(request, "operator", async (db, actor) => {
      ctx.requireVerified(actor);
      return { ...(await operatorView(db, actor.roles)), requestId: request.id };
    });
  });

  app.get("/operator", async (request, reply) => {
    try {
    const html = await ctx.withActor(request, "operator", async (db, actor) => {
      ctx.requireVerified(actor);
      const query = request.query as {tab?:string;notice?:string};
      return renderOperatorPortal({...await operatorView(db, actor.roles),browserAuthEnabled:ctx.browserAuthEnabled,activeTab:query.tab === "users"?"users":query.tab === "brevo"?"brevo":"servers",notice:query.notice});
    });
    reply.type("text/html; charset=utf-8");
    return reply.header("cache-control","no-store").send(html);
    }catch(error){
      if(ctx.browserAuthEnabled&&error instanceof HttpError){
        if(error.status===401)return reply.code(303).header("location","/operator/login").send("");
        if(error.code==="MFA_REQUIRED")return reply.code(303).header("location","/operator/security").send("");
        if(error.code==="FORBIDDEN")return reply.code(403).type("text/html").header("cache-control","no-store").send(renderOperatorAuth(false,true));
      }
      throw error;
    }
  });

  app.get("/v1/admin/release-checklist", async (request) => {
    return ctx.withActor(request, "operator", async (db, actor) => {
      ctx.requireVerified(actor);
      const verified = await db.query<{ n: number }>("SELECT count(*)::int AS n FROM deployments WHERE mail_verified IS TRUE");
      return {
        document: "local-control-plane",
        liveEvidence: false,
        soakExecuted: false,
        restoreDrillExecuted: false,
        upgradeBinariesExecuted: false,
        cancellationHostStopObserved: false,
        cloudApiCalled: false,
        mailVerifiedDeployments: verified.rows[0]?.n ?? 0,
        openGates: ["A07-A16", "A19", "A20", "A21", "A22", "A25", "A31"],
        notes: RELEASE_NOTES,
        requestId: request.id,
      };
    });
  });

  app.post("/v1/admin/servers/:id/backups", async (request, reply) => {
    const idempotencyKey = ctx.demandIdempotency(request);
    const { id } = request.params as { id: string };
    const body = serverBackupSchema.parse(request.body);
    const created = await ctx.withActor(request, "operator", async (db, actor) => {
      const route = "POST /v1/admin/servers/:id/backups";
      const replayed = await ctx.replay(db, actor.userId, route, idempotencyKey, { id, ...body });
      if (replayed) return replayed;
      assertWriter(ctx, actor);
      await assertMutable(db);
      const deployment = await db.query<{ organization_id: string; server_id: string | null }>(
        "SELECT organization_id, server_id FROM deployments WHERE id = $1 AND lifecycle_state <> 'deleted'",
        [body.deploymentId],
      );
      const row = deployment.rows[0];
      if (!row) throw new HttpError(404, "NOT_FOUND", "The deployment was not found.");
      const live = await db.query<{ server_id: string }>(
        `SELECT server_id FROM server_assignments
         WHERE released_at IS NULL AND organization_id = $2
           AND (deployment_id = $1 OR deployment_id IS NULL)`,
        [body.deploymentId, row.organization_id],
      );
      const ownerServer = live.rows[0]?.server_id ?? row.server_id;
      if (!ownerServer || ownerServer !== id) throw new HttpError(409, "SERVER_MISMATCH", "That server is not the deployment owner.");
      const recorded = await recordBackupReport(db, actor.userId, body.deploymentId, body);
      await ctx.audit(db, request, actor.userId, recorded.organizationId, "server.backup_report", id, { evidenceRef: body.evidenceRef });
      await ctx.remember(db, actor.userId, route, idempotencyKey, { id, ...body }, 200, recorded.response);
      return { status: 200 as const, body: recorded.response };
    });
    return reply.code(created.status).send({ ...created.body, requestId: request.id });
  });

  app.post("/v1/admin/deployments/:id/replacement-plan", async (request, reply) => {
    const idempotencyKey = ctx.demandIdempotency(request);
    const { id } = request.params as { id: string };
    const body = replacementPlanSchema.parse(request.body);
    const created = await ctx.withActor(request, "operator", async (db, actor) => {
      const route = "POST /v1/admin/deployments/:id/replacement-plan";
      const replayed = await ctx.replay(db, actor.userId, route, idempotencyKey, { id, ...body });
      if (replayed) return replayed;
      assertWriter(ctx, actor);
      await assertMutable(db);
      const deployment = await loadDeployment(db, id, null);
      if (deployment.version !== body.expectedVersion) throw new HttpError(409, "VERSION_CONFLICT", "The deployment changed.");
      const requestRow = await db.query<{ id: string; backup_id: string }>(
        `SELECT id, backup_id FROM restore_requests
         WHERE deployment_id = $1 AND state IN ('requested', 'ready')
         ORDER BY created_at DESC LIMIT 1`,
        [id],
      );
      const restore = requestRow.rows[0];
      if (!restore) throw new HttpError(422, "RESTORE_REQUEST_REQUIRED", "The owner must request the restore before a replacement is reserved.");
      if (body.backupId && body.backupId !== restore.backup_id) throw new HttpError(409, "BACKUP_MISMATCH", "The replacement backup does not match the owner request.");
      const current = await db.query<{ server_id: string; profile_code: string }>(
        `SELECT a.server_id, s.profile_code
         FROM server_assignments a
         JOIN servers s ON s.id = a.server_id
         WHERE a.organization_id = $1 AND a.released_at IS NULL`,
        [deployment.organization_id],
      );
      const owner = current.rows[0];
      if (!owner) throw new HttpError(422, "SERVER_REQUIRED", "The deployment has no server to replace.");
      if (owner.server_id === body.replacementServerId) throw new HttpError(422, "SERVER_MISMATCH", "The replacement must be a different server.");
      const replacement = await db.query<{ version: number; profile_code: string; state: string; tenant_tainted_at: Date | null }>(
        "SELECT version, profile_code, state, tenant_tainted_at FROM servers WHERE id = $1",
        [body.replacementServerId],
      );
      const host = replacement.rows[0];
      if (!host) throw new HttpError(404, "NOT_FOUND", "The replacement server was not found.");
      if (host.tenant_tainted_at) throw new HttpError(409, "TAINTED_SERVER", "A tainted server cannot be reserved for restore.");
      if (host.state !== "available") throw new HttpError(409, "INVALID_STATE", "The replacement server is not available.");
      if (host.profile_code !== owner.profile_code) throw new HttpError(422, "PROFILE_MISMATCH", "The replacement profile does not match.");
      const reserved = await db.query(
        `UPDATE servers SET state = 'quarantined', version = version + 1, updated_at = now()
         WHERE id = $1 AND version = $2 AND state = 'available' AND tenant_tainted_at IS NULL
         RETURNING id`,
        [body.replacementServerId, host.version],
      );
      if (!reserved.rows[0]) throw new HttpError(409, "INVALID_STATE", "The replacement server changed.");
      const bindingId = randomUUID();
      await db.query(
        `INSERT INTO recovery_bindings (id, organization_id, deployment_id, replacement_server_id, state)
         VALUES ($1, $2, $3, $4, 'pending')`,
        [bindingId, deployment.organization_id, id, body.replacementServerId],
      );
      await bumpDeployment(db, id, deployment.organization_id, deployment.version);
      await ctx.audit(db, request, actor.userId, deployment.organization_id, "restore.replacement", id, { bindingId, liveAssignmentCreated: false });
      const response = { bindingId, serverId: body.replacementServerId, state: "quarantined", liveAssignmentCreated: false, cloudApiCalled: false, mailVerified: false };
      await ctx.remember(db, actor.userId, route, idempotencyKey, { id, ...body }, 201, response);
      return { status: 201 as const, body: response };
    });
    return reply.code(created.status).send({ ...created.body, requestId: request.id });
  });

  app.post("/v1/admin/deployments/:id/restore-ready", async (request, reply) => {
    const idempotencyKey = ctx.demandIdempotency(request);
    const { id } = request.params as { id: string };
    const body = restoreReadySchema.parse(request.body);
    const created = await ctx.withActor(request, "operator", async (db, actor) => {
      const route = "POST /v1/admin/deployments/:id/restore-ready";
      const replayed = await ctx.replay(db, actor.userId, route, idempotencyKey, { id, ...body });
      if (replayed) return replayed;
      assertWriter(ctx, actor);
      await assertMutable(db);
      if (!evidenceReferenceAccepted(body.evidenceRef)) throw new HttpError(422, "EVIDENCE_REF", "Evidence must be an internal reference.");
      const deployment = await loadDeployment(db, id, null);
      if (deployment.version !== body.expectedVersion) throw new HttpError(409, "VERSION_CONFLICT", "The deployment changed.");
      if (!fencingAllowsPromotion(body.fencing)) {
        throw new HttpError(422, "FENCING_INSUFFICIENT", "A missing heartbeat is not fencing and does not promote a replacement.");
      }
      const binding = await db.query<{ id: string }>(
        "SELECT id FROM recovery_bindings WHERE deployment_id = $1 AND state = 'pending'",
        [id],
      );
      if (!binding.rows[0]) throw new HttpError(409, "INVALID_STATE", "A pending replacement binding is required.");
      const restore = await db.query<{ id: string; backup_id: string }>(
        "SELECT id, backup_id FROM restore_requests WHERE deployment_id = $1 AND state IN ('requested', 'ready')",
        [id],
      );
      if (!restore.rows[0] || restore.rows[0].backup_id !== body.backupId) {
        throw new HttpError(409, "BACKUP_MISMATCH", "The readiness report does not match the owner restore request.");
      }
      const evidence = { kind: body.fencing, evidenceRef: body.evidenceRef, heartbeatIsFencing: false };
      await db.query(
        `UPDATE recovery_bindings SET fencing_evidence = $2::jsonb, updated_at = now(), version = version + 1 WHERE id = $1`,
        [binding.rows[0].id, JSON.stringify(evidence)],
      );
      await db.query(
        `UPDATE restore_requests SET state = 'ready', updated_at = now(), version = version + 1 WHERE id = $1`,
        [restore.rows[0].id],
      );
      const jobId = randomUUID();
      await db.query(
        `INSERT INTO jobs (id, organization_id, deployment_id, generation, kind, state, checkpoint)
         VALUES ($1, $2, $3, $4, 'restore.validation', 'queued', $5::jsonb)`,
        [jobId, deployment.organization_id, id, deployment.generation, JSON.stringify({ installerStarted: false, delivered: false, hostRestoreExecuted: false })],
      );
      await bumpDeployment(db, id, deployment.organization_id, deployment.version);
      await ctx.audit(db, request, actor.userId, deployment.organization_id, "restore.ready", id, { promoted: false, fencing: body.fencing });
      const response = {
        ready: true,
        promoted: false,
        fencing: body.fencing,
        heartbeatIsFencing: false,
        jobId,
        jobState: "queued",
        mailVerified: false,
        dnsWrite: false,
        restoreVerified: false,
        cloudVerified: false,
      };
      await ctx.remember(db, actor.userId, route, idempotencyKey, { id, ...body }, 202, response);
      return { status: 202 as const, body: response };
    });
    return reply.code(created.status).send({ ...created.body, requestId: request.id });
  });

  app.post("/v1/admin/deployments/:id/restore-promote", async (request, reply) => {
    const idempotencyKey = ctx.demandIdempotency(request);
    const { id } = request.params as { id: string };
    const body = versionedSchema.parse(request.body);
    const created = await ctx.withActor(request, "operator", async (db, actor) => {
      const route = "POST /v1/admin/deployments/:id/restore-promote";
      const replayed = await ctx.replay(db, actor.userId, route, idempotencyKey, { id, ...body });
      if (replayed) return replayed;
      assertWriter(ctx, actor);
      await assertMutable(db);
      const deployment = await loadDeployment(db, id, null);
      if (deployment.version !== body.expectedVersion) throw new HttpError(409, "VERSION_CONFLICT", "The deployment changed.");
      const binding = await db.query<{ id: string; replacement_server_id: string; fencing_evidence: { kind?: FencingKind } | null }>(
        `SELECT id, replacement_server_id, fencing_evidence
         FROM recovery_bindings WHERE deployment_id = $1 AND state = 'pending' FOR UPDATE`,
        [id],
      );
      const held = binding.rows[0];
      if (!held) throw new HttpError(409, "INVALID_STATE", "A pending replacement binding is required.");
      const kind = held.fencing_evidence?.kind;
      if (kind !== "application_stop" && kind !== "external_isolation") {
        throw new HttpError(422, "FENCING_INSUFFICIENT", "Promotion requires application stop or external isolation. A missing heartbeat is not fencing.");
      }
      const restore = await db.query<{ id: string; approval_id: string | null }>(
        "SELECT id, approval_id FROM restore_requests WHERE deployment_id = $1 AND state = 'ready' FOR UPDATE",
        [id],
      );
      const requestRow = restore.rows[0];
      if (!requestRow?.approval_id) throw new HttpError(409, "APPROVAL_REQUIRED", "The owner has not approved this restore.");
      const approval = await db.query<{ state: string; expires_at: Date }>(
        "SELECT state, expires_at FROM approvals WHERE id = $1 AND organization_id = $2",
        [requestRow.approval_id, deployment.organization_id],
      );
      if (approval.rows[0]?.state !== "approved" || approval.rows[0].expires_at.getTime() <= Date.now()) {
        throw new HttpError(409, "APPROVAL_REQUIRED", "The restore approval is not active.");
      }
      const assignments = await db.query<{ id: string; server_id: string; generation: number }>(
        `SELECT id, server_id, generation FROM server_assignments
         WHERE organization_id = $1 AND released_at IS NULL FOR UPDATE`,
        [deployment.organization_id],
      );
      if (assignments.rows.length !== 1) throw new HttpError(409, "INVALID_STATE", "Promotion requires exactly one live assignment.");
      const current = assignments.rows[0]!;
      if (current.server_id === held.replacement_server_id) throw new HttpError(409, "INVALID_STATE", "The replacement is already the live assignment.");
      await db.query("UPDATE server_assignments SET released_at = now() WHERE id = $1 AND released_at IS NULL", [current.id]);
      const generation = current.generation + 1;
      await db.query(
        `INSERT INTO server_assignments (id, organization_id, server_id, deployment_id, reason, generation)
         VALUES ($1, $2, $3, $4, 'restore_promotion', $5)`,
        [randomUUID(), deployment.organization_id, held.replacement_server_id, id, generation],
      );
      await db.query(
        `UPDATE servers
         SET state = 'quarantined', tenant_tainted_at = coalesce(tenant_tainted_at, now()),
             auth_epoch = auth_epoch + 1, version = version + 1, updated_at = now()
         WHERE id = $1`,
        [current.server_id],
      );
      await db.query(
        `UPDATE servers
         SET state = 'assigned', auth_epoch = auth_epoch + 1, tenant_tainted_at = coalesce(tenant_tainted_at, now()),
             version = version + 1, updated_at = now()
         WHERE id = $1`,
        [held.replacement_server_id],
      );
      await db.query(
        "UPDATE recovery_bindings SET state = 'promoted', updated_at = now(), version = version + 1 WHERE id = $1",
        [held.id],
      );
      await db.query(
        "UPDATE restore_requests SET state = 'promoted', updated_at = now(), version = version + 1 WHERE id = $1",
        [requestRow.id],
      );
      const moved = await db.query(
        `UPDATE deployments
         SET server_id = $2, generation = generation + 1, version = version + 1, updated_at = now()
         WHERE id = $1 AND version = $3
         RETURNING id`,
        [id, held.replacement_server_id, deployment.version],
      );
      if (!moved.rows[0]) throw new HttpError(409, "VERSION_CONFLICT", "The deployment changed.");
      await ctx.audit(db, request, actor.userId, deployment.organization_id, "restore.promote", id, { hostRestoreExecuted: false, dnsWrite: false });
      const response = {
        promoted: true,
        hostRestoreExecuted: false,
        dnsWrite: false,
        mailVerified: false,
        cloudVerified: false,
        restoreVerified: false,
        liveAssignments: 1,
        oldServerState: "quarantined",
        replacementState: "assigned",
        fencing: kind,
      };
      await ctx.remember(db, actor.userId, route, idempotencyKey, { id, ...body }, 200, response);
      return { status: 200 as const, body: response };
    });
    return reply.code(created.status).send({ ...created.body, requestId: request.id });
  });

  app.post("/v1/admin/deployments/:id/upgrade-plan", async (request, reply) => {
    const idempotencyKey = ctx.demandIdempotency(request);
    const { id } = request.params as { id: string };
    const body = upgradePlanSchema.parse(request.body);
    const created = await ctx.withActor(request, "operator", async (db, actor) => {
      const route = "POST /v1/admin/deployments/:id/upgrade-plan";
      const replayed = await ctx.replay(db, actor.userId, route, idempotencyKey, { id, ...body });
      if (replayed) return replayed;
      assertWriter(ctx, actor);
      await assertMutable(db);
      const deployment = await loadDeployment(db, id, null);
      if (deployment.version !== body.expectedVersion) throw new HttpError(409, "VERSION_CONFLICT", "The deployment changed.");
      const fresh = await db.query<{ id: string }>(
        `SELECT id FROM backups
         WHERE deployment_id = $1 AND organization_id = $2
           AND state = 'reported_complete' AND consistency_state = 'consistent'
           AND completed_at > now() - interval '26 hours'`,
        [id, deployment.organization_id],
      );
      const freshIds = new Set(fresh.rows.map((row) => row.id));
      const freshBackup = body.preUpgradeBackupId ? freshIds.has(body.preUpgradeBackupId) : freshIds.size > 0;
      const policy = upgradePolicy({
        compatible: body.compatible,
        irreversible: body.irreversible,
        newMailAccepted: body.newMailAccepted,
        checksFailed: body.checksFailed,
        freshBackup,
      });
      const planId = randomUUID();
      let approvalId: string | null = null;
      if (policy.state === "pending") {
        approvalId = randomUUID();
        const planHash = sha256(`upgrade\n${id}\n${body.releaseId}\n${deployment.generation}`);
        await insertApproval(db, approvalId, deployment.organization_id, id, "upgrade", planHash, deployment.generation, planId);
      }
      await db.query(
        `INSERT INTO upgrade_plans (
           id, organization_id, deployment_id, approval_id, to_release_id, compatible, irreversible,
           new_mail_accepted, checks_failed, pre_upgrade_backup_id, rollback_policy, state
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
        [
          planId,
          deployment.organization_id,
          id,
          approvalId,
          body.releaseId,
          body.compatible,
          body.irreversible,
          body.newMailAccepted,
          body.checksFailed,
          body.preUpgradeBackupId ?? null,
          policy.rollbackPolicy,
          policy.state,
        ],
      );
      await bumpDeployment(db, id, deployment.organization_id, deployment.version);
      await ctx.audit(db, request, actor.userId, deployment.organization_id, "upgrade.plan", id, { state: policy.state, binariesExecuted: false });
      if (policy.state === "blocked") {
        const response = errorBody("BACKUP_REQUIRED", "A fresh operator-reported consistent backup is required before an upgrade plan.");
        await ctx.remember(db, actor.userId, route, idempotencyKey, { id, ...body }, 422, response);
        return { status: 422 as const, body: response };
      }
      const response = {
        upgradePlanId: planId,
        approvalId,
        state: policy.state,
        rollbackPolicy: policy.rollbackPolicy,
        dataRollback: false,
        binariesExecuted: false,
        executed: false,
        upgradeSucceeded: false,
        recordedOnly: true,
        mailVerified: false,
        dnsWrite: false,
      };
      const status = policy.state === "pending" ? 202 : 200;
      await ctx.remember(db, actor.userId, route, idempotencyKey, { id, ...body }, status, response);
      return { status: status as 200 | 202, body: response };
    });
    return reply.code(created.status).send({ ...created.body, requestId: request.id });
  });

  app.post("/v1/admin/deployments/:id/isolation-report", async (request, reply) => {
    const idempotencyKey = ctx.demandIdempotency(request);
    const { id } = request.params as { id: string };
    const body = isolationReportSchema.parse(request.body);
    const created = await ctx.withActor(request, "operator", async (db, actor) => {
      const route = "POST /v1/admin/deployments/:id/isolation-report";
      const replayed = await ctx.replay(db, actor.userId, route, idempotencyKey, { id, ...body });
      if (replayed) return replayed;
      assertWriter(ctx, actor);
      await assertMutable(db);
      if (!evidenceReferenceAccepted(body.evidenceRef)) throw new HttpError(422, "EVIDENCE_REF", "Evidence must be an internal reference.");
      const deployment = await loadDeployment(db, id, null);
      if (deployment.version !== body.expectedVersion) throw new HttpError(409, "VERSION_CONFLICT", "The deployment changed.");
      const schedule = await db.query<{
        id: string;
        state: string;
        stop_queued: boolean;
        isolation_required: boolean;
        execute_at: Date;
        window_ends_at: Date;
      }>(
        `SELECT id, state, stop_queued, isolation_required, execute_at, window_ends_at
         FROM cancellation_schedules WHERE deployment_id = $1 AND state = 'scheduled'`,
        [id],
      );
      const row = schedule.rows[0];
      if (!row || (!row.stop_queued && !row.isolation_required)) {
        throw new HttpError(409, "INVALID_STATE", "Isolation evidence is accepted only after the cancellation is due.");
      }
      const timing = cancellationTiming({ nowMs: Date.now(), executeAt: row.execute_at, windowEndsAt: row.window_ends_at, state: row.state });
      if (!row.stop_queued && timing !== "due") throw new HttpError(409, "STALE_AUTHORIZATION", "The cancellation window is not open.");
      const assignment = await db.query<{ server_id: string }>(
        "SELECT server_id FROM server_assignments WHERE organization_id = $1 AND released_at IS NULL",
        [deployment.organization_id],
      );
      if (assignment.rows[0]) {
        await db.query(
          `UPDATE server_assignments
           SET deployment_id = $2
           WHERE organization_id = $1 AND released_at IS NULL AND deployment_id IS NULL`,
          [deployment.organization_id, id],
        );
        await db.query(
          `UPDATE servers
           SET state = 'quarantined', tenant_tainted_at = coalesce(tenant_tainted_at, now()),
               version = version + 1, updated_at = now()
           WHERE id = $1`,
          [assignment.rows[0].server_id],
        );
      }
      await db.query(
        `UPDATE cancellation_schedules
         SET state = 'stopped', service_stopped = true, service_stopped_at = now(), isolation_evidence = $2,
             updated_at = now(), version = version + 1
         WHERE id = $1`,
        [row.id, body.evidenceRef],
      );
      const stopped = await db.query(
        `UPDATE deployments
         SET lifecycle_state = 'deleting', desired_state = 'stopped', version = version + 1, updated_at = now()
         WHERE id = $1 AND version = $2
         RETURNING id`,
        [id, deployment.version],
      );
      if (!stopped.rows[0]) throw new HttpError(409, "VERSION_CONFLICT", "The deployment changed.");
      await openAction(db, deployment.organization_id, id, assignment.rows[0]?.server_id ?? null, "cancellation.cleanup", "Service stop is operator-reported. Keep the server quarantined until retention and cleanup evidence are complete.");
      await ctx.audit(db, request, actor.userId, deployment.organization_id, "cancellation.isolation", id, { cloudApiCalled: false, hostObserved: false });
      const response = {
        serviceStopped: true,
        evidence: "operator",
        hostObserved: false,
        cloudApiCalled: false,
        assignmentReleased: false,
        serverState: assignment.rows[0] ? "quarantined" : null,
        lifecycleState: "deleting",
        delivered: false,
        billingStopped: false,
        mailVerified: false,
      };
      await ctx.remember(db, actor.userId, route, idempotencyKey, { id, ...body }, 200, response);
      return { status: 200 as const, body: response };
    });
    return reply.code(created.status).send({ ...created.body, requestId: request.id });
  });

  app.post("/v1/admin/servers/:id/cleanup-report", async (request, reply) => {
    const idempotencyKey = ctx.demandIdempotency(request);
    const { id } = request.params as { id: string };
    const body = cleanupReportSchema.parse(request.body);
    const created = await ctx.withActor(request, "operator", async (db, actor) => {
      const route = "POST /v1/admin/servers/:id/cleanup-report";
      const replayed = await ctx.replay(db, actor.userId, route, idempotencyKey, { id, ...body });
      if (replayed) return replayed;
      assertWriter(ctx, actor);
      await assertMutable(db);
      if (!evidenceReferenceAccepted(body.evidenceRef) || body.operatorAttestation.includes("://")) {
        throw new HttpError(422, "EVIDENCE_REF", "Cleanup evidence must be an internal reference.");
      }
      const server = await db.query<{ version: number; state: string }>("SELECT version, state FROM servers WHERE id = $1", [id]);
      const host = server.rows[0];
      if (!host) throw new HttpError(404, "NOT_FOUND", "The server was not found.");
      if (host.version !== body.expectedVersion) throw new HttpError(409, "VERSION_CONFLICT", "The server changed.");
      const owner = await db.query<{ organization_id: string; deployment_id: string; schedule_id: string | null; service_stopped_at: Date | null }>(
        `SELECT a.organization_id, c.deployment_id, c.id AS schedule_id, c.service_stopped_at
         FROM server_assignments a
         JOIN cancellation_schedules c
           ON c.organization_id = a.organization_id
          AND c.state = 'stopped'
          AND (a.deployment_id IS NULL OR a.deployment_id = c.deployment_id)
         WHERE a.server_id = $1 AND a.released_at IS NULL
         LIMIT 1`,
        [id],
      );
      const row = owner.rows[0];
      if (!row) throw new HttpError(422, "SERVICE_NOT_STOPPED", "Cleanup requires the server to still be owned by a stopped service.");
      const decision = cleanupDecision({
        serviceStoppedAt: row.service_stopped_at,
        dataRemovedAt: new Date(body.dataRemovedAt),
        nowMs: Date.now(),
        backupRetentionSatisfied: body.backupRetentionSatisfied,
        credentialsRevoked: body.credentialsRevoked,
      });
      if (!decision.ok) throw new HttpError(422, decision.code, "Retention, credential revocation, or a stopped service is still incomplete.");
      const nextState = body.outcome === "deleted" ? "retired" : "quarantined";
      const reportId = randomUUID();
      await db.query(
        `INSERT INTO cleanup_reports (
           id, organization_id, deployment_id, server_id, outcome, data_removed_at, backup_retention_satisfied,
           credentials_revoked, evidence_ref, operator_attestation, reported_by
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
        [
          reportId,
          row.organization_id,
          row.deployment_id,
          id,
          body.outcome,
          body.dataRemovedAt,
          body.backupRetentionSatisfied,
          body.credentialsRevoked,
          body.evidenceRef,
          body.operatorAttestation,
          actor.userId,
        ],
      );
      await db.query("UPDATE server_assignments SET released_at = now() WHERE server_id = $1 AND released_at IS NULL", [id]);
      await db.query(
        `UPDATE servers
         SET state = $2, available_since = NULL, validated_at = NULL, auth_epoch = auth_epoch + 1,
             cleanup_evidence = $3::jsonb, version = version + 1, updated_at = now()
         WHERE id = $1`,
        [id, nextState, JSON.stringify({ reportId, outcome: body.outcome, returnedAvailable: false, cloudVerified: false })],
      );
      await db.query(
        `UPDATE host_identities SET state = 'revoked', revoked_at = now(), updated_at = now(), version = version + 1
         WHERE server_id = $1 AND state <> 'revoked'`,
        [id],
      );
      await db.query(
        `UPDATE deployments SET lifecycle_state = 'deleted', version = version + 1, updated_at = now() WHERE id = $1`,
        [row.deployment_id],
      );
      if (row.schedule_id) {
        await db.query(
          "UPDATE cancellation_schedules SET state = 'completed', updated_at = now(), version = version + 1 WHERE id = $1",
          [row.schedule_id],
        );
      }
      await ctx.audit(db, request, actor.userId, row.organization_id, "server.cleanup_report", id, { outcome: body.outcome, returnedAvailable: false });
      const response = {
        reportId,
        state: nextState,
        returnedAvailable: false,
        cloudVerified: false,
        reusable: false,
        lifecycleState: "deleted",
        billingStopped: false,
        mailVerified: false,
      };
      await ctx.remember(db, actor.userId, route, idempotencyKey, { id, ...body }, 200, response);
      return { status: 200 as const, body: response };
    });
    return reply.code(created.status).send({ ...created.body, requestId: request.id });
  });

  app.post("/internal/cancellation/execute", async (request, reply) => {
    requireScheduler(request, ctx.schedulerToken);
    const body = cancellationExecuteSchema.parse(request.body ?? {});
    const created = await ctx.withSystem("inventory_worker", async (db) => {
      await assertMutable(db);
      const schedule = await db.query<{
        id: string;
        organization_id: string;
        deployment_id: string;
        approval_id: string | null;
        generation: number;
        state: string;
        execute_at: Date;
        window_ends_at: Date;
        proceed_without_final_backup: boolean;
        stop_queued: boolean;
        stop_job_id: string | null;
      }>(
        `SELECT id, organization_id, deployment_id, approval_id, generation, state, execute_at, window_ends_at,
                proceed_without_final_backup, stop_queued, stop_job_id
         FROM cancellation_schedules WHERE id = $1`,
        [body.scheduleId],
      );
      const row = schedule.rows[0];
      if (!row) throw new HttpError(404, "NOT_FOUND", "The cancellation schedule was not found.");
      if (row.stop_queued) {
        return {
          status: 200 as const,
          body: { duplicate: true, jobId: row.stop_job_id, serviceStopped: false, delivered: false, cloudApiCalled: false, mailVerified: false },
        };
      }
      if (row.state !== "scheduled") throw new HttpError(409, "INVALID_STATE", "The cancellation is not scheduled.");
      const timing = cancellationTiming({
        nowMs: Date.now(),
        executeAt: new Date(row.execute_at),
        windowEndsAt: new Date(row.window_ends_at),
        state: row.state,
      });
      if (timing === "early") throw new HttpError(422, "NOT_DUE", "The seven-day cancellation is not due.");
      if (timing === "closed") throw new HttpError(409, "INVALID_STATE", "The cancellation is not scheduled.");
      if (timing === "stale") {
        await db.query("UPDATE cancellation_schedules SET state = 'revoked', updated_at = now(), version = version + 1 WHERE id = $1", [row.id]);
        if (row.approval_id) {
          await db.query("UPDATE approvals SET state = 'expired', updated_at = now(), version = version + 1 WHERE id = $1", [row.approval_id]);
        }
        const actionId = await openAction(db, row.organization_id, row.deployment_id, null, "cancellation.renew", "The cancellation window expired. A new approval is required.");
        return { status: 409 as const, body: errorBody("STALE_AUTHORIZATION", "The cancellation window expired before execution.", false, actionId) };
      }
      const deployment = await db.query<{ generation: number }>("SELECT generation FROM deployments WHERE id = $1", [row.deployment_id]);
      if (deployment.rows[0]?.generation !== row.generation) {
        await db.query("UPDATE cancellation_schedules SET state = 'revoked', updated_at = now(), version = version + 1 WHERE id = $1", [row.id]);
        const actionId = await openAction(db, row.organization_id, row.deployment_id, null, "cancellation.renew", "The deployment generation changed. Renew the cancellation.");
        return { status: 409 as const, body: errorBody("STALE_AUTHORITY", "The cancellation no longer matches the deployment generation.", false, actionId) };
      }
      const freshBackup = await db.query(
        `SELECT id FROM backups
         WHERE organization_id = $1 AND deployment_id = $2
           AND state = 'reported_complete' AND consistency_state = 'consistent'
           AND completed_at > now() - interval '26 hours'
         LIMIT 1`,
        [row.organization_id, row.deployment_id],
      );
      if (!freshBackup.rows[0] && !row.proceed_without_final_backup) {
        const actionId = await openAction(db, row.organization_id, row.deployment_id, null, "cancellation.final_backup", "A final operator-reported backup, or an owner waiver, is required before service stop.");
        return { status: 422 as const, body: errorBody("FINAL_BACKUP_REQUIRED", "Cancellation is due, and no final backup or owner waiver is recorded.", false, actionId) };
      }
      const assignment = await db.query<{ server_id: string; generation: number; auth_epoch: number }>(
        `SELECT a.server_id, a.generation, s.auth_epoch
         FROM server_assignments a
         JOIN servers s ON s.id = a.server_id
         WHERE a.organization_id = $1 AND a.released_at IS NULL`,
        [row.organization_id],
      );
      const host = assignment.rows[0];
      if (!host) {
        await db.query(
          "UPDATE cancellation_schedules SET isolation_required = true, updated_at = now(), version = version + 1 WHERE id = $1",
          [row.id],
        );
        const actionId = await openAction(db, row.organization_id, row.deployment_id, null, "cancellation.isolation_required", "No assigned host was found. Operator isolation evidence is required before service stop is claimed.");
        return { status: 422 as const, body: errorBody("ISOLATION_REQUIRED", "The host is not assigned. Queuing a stop would not show that mail stopped.", false, actionId) };
      }
      const parsed = parseCommand("stop_mail_services", {});
      if (!parsed) throw new HttpError(400, "UNKNOWN_COMMAND", "That command is not allowed.");
      const jobId = randomUUID();
      await db.query(
        `INSERT INTO jobs (id, organization_id, deployment_id, generation, kind, state, checkpoint, lease_expires_at)
         VALUES ($1, $2, $3, $4, 'cancel_service', 'queued', $5::jsonb, now() + interval '120 seconds')`,
        [jobId, row.organization_id, row.deployment_id, row.generation, JSON.stringify({ installerStarted: false, delivered: false, cloudApiCalled: false })],
      );
      const payloadHash = createHash("sha256").update(JSON.stringify(parsed.parameters)).digest("hex");
      await db.query(
        `INSERT INTO host_commands (
           id, server_id, job_id, organization_id, deployment_id, generation, auth_epoch, command_type, payload, payload_hash, state, expires_at
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10, 'queued', now() + interval '15 minutes')`,
        [randomUUID(), host.server_id, jobId, row.organization_id, row.deployment_id, host.generation, host.auth_epoch, parsed.commandType, JSON.stringify(parsed.parameters), payloadHash],
      );
      await db.query(
        "UPDATE cancellation_schedules SET stop_queued = true, stop_job_id = $2, updated_at = now(), version = version + 1 WHERE id = $1",
        [row.id, jobId],
      );
      await db.query(
        `UPDATE servers
         SET tenant_tainted_at = coalesce(tenant_tainted_at, now()), version = version + 1, updated_at = now()
         WHERE id = $1`,
        [host.server_id],
      );
      return {
        status: 202 as const,
        body: { jobId, state: "queued", serviceStopped: false, delivered: false, cloudApiCalled: false, hostObserved: false, mailVerified: false },
      };
    });
    return reply.code(created.status).send({ ...created.body, requestId: request.id });
  });
}

function requireCustomer(ctx: LifecycleContext, actor: Actor): void {
  ctx.requireVerified(actor);
  if (!actor.organizationId) throw new HttpError(422, "ORGANIZATION_REQUIRED", "Create an organization first.");
  const fresh = actor.authTime > 0 && Math.floor(Date.now() / 1000) - actor.authTime <= RECENT_AUTH_SECONDS;
  if (!fresh) throw new HttpError(403, "RECENT_AUTH_REQUIRED", "Sign in again before this change.");
}

function assertWriter(ctx: LifecycleContext, actor: Actor): void {
  if (!actor.roles.includes("platform_administrator") && !actor.roles.includes("infrastructure_operator")) {
    throw new HttpError(403, "FORBIDDEN", "An infrastructure operator is required.");
  }
  ctx.requireVerified(actor);
  ctx.requireMfa(actor);
}

async function assertMutable(db: Db): Promise<void> {
  const row = await db.query<{ mode: string }>("SELECT mode FROM control_plane_state WHERE id = 1");
  if (row.rows[0]?.mode === "recovery") {
    throw new HttpError(409, "RECOVERY_MODE", "Control-plane recovery has paused lifecycle changes.");
  }
}

async function loadDeployment(db: Db, id: string, organizationId: string | null): Promise<DeploymentRow> {
  const result = await db.query<DeploymentRow>(
    `SELECT id, organization_id, version, generation, lifecycle_state, server_id
     FROM deployments
     WHERE id = $1 AND ($2::uuid IS NULL OR organization_id = $2::uuid) AND lifecycle_state <> 'deleted'`,
    [id, organizationId],
  );
  const row = result.rows[0];
  if (!row) throw new HttpError(404, "NOT_FOUND", "The deployment was not found.");
  return row;
}

async function bumpDeployment(db: Db, id: string, organizationId: string | null, version: number): Promise<void> {
  const updated = await db.query(
    `UPDATE deployments SET version = version + 1, updated_at = now()
     WHERE id = $1 AND version = $2 AND ($3::uuid IS NULL OR organization_id = $3::uuid)`,
    [id, version, organizationId],
  );
  if (updated.rowCount !== 1) throw new HttpError(409, "VERSION_CONFLICT", "The deployment changed.");
}

async function insertApproval(
  db: Db,
  id: string,
  organizationId: string,
  deploymentId: string,
  actionCode: string,
  planHash: string,
  generation: number,
  resourceId: string,
): Promise<void> {
  await db.query(
    `INSERT INTO approvals (
       id, organization_id, deployment_id, action_code, plan_hash, generation, resource_id, dns_fingerprint, state, expires_at
     ) VALUES ($1, $2, $3, $4, $5, $6, $7, 'unobserved', 'pending', now() + interval '30 minutes')`,
    [id, organizationId, deploymentId, actionCode, planHash, generation, resourceId],
  );
}

async function openAction(db: Db, organizationId: string, deploymentId: string | null, serverId: string | null, code: string, instructions: string): Promise<string> {
  const existing = await db.query<{ id: string }>(
    `SELECT id FROM required_actions
     WHERE state = 'open' AND code = $1 AND organization_id IS NOT DISTINCT FROM $2
     LIMIT 1`,
    [code, organizationId],
  );
  if (existing.rows[0]) return existing.rows[0].id;
  const id = randomUUID();
  await db.query(
    `INSERT INTO required_actions (id, scope, organization_id, server_id, deployment_id, audience, code, instructions, state)
     VALUES ($1, 'tenant', $2, $3, $4, 'operator', $5, $6, 'open')`,
    [id, organizationId, serverId, deploymentId, code, instructions],
  );
  return id;
}

async function detectedDns(
  ctx: LifecycleContext,
  domainName: string | null | undefined,
): Promise<{ detectedProvider: DetectedDnsProvider | null; detectedNameservers?: string[] }> {
  if (!domainName) return { detectedProvider: null };
  const detectedNameservers = await ctx.lookupNameservers(domainName);
  return { detectedProvider: detectDnsProvider(detectedNameservers), detectedNameservers };
}

async function customerView(db: Db, organizationId: string, billingRequired = false, billingConfigured = false): Promise<CustomerPortalView> {
  const deployment = await db.query<{
    id: string;
    admin_credentials_available:boolean;
    lifecycle_state: string;
    onboarding_stage: string;
    health_state: string;
    mail_hostname: string | null;
    webmail_hostname: string | null;
    mail_verified: boolean;
    domain_id: string | null;
    updated_at: Date;
    installer_status: string | null;
    dns_writes_accepted: boolean;
    brevo_authenticated: boolean;
    brevo_verified: boolean;
    previous_mx: unknown;
    published_records: unknown;
    brevo_records: unknown;
    plan_snapshot: unknown;
    server_id: string | null;
    server_state: string | null;
    public_ipv4: string | null;
    domain_name: string | null;
    domain_state: string | null;
    existing_mail: boolean | null;
    nameservers: string[] | null;
    recheck_required: boolean | null;
  }>(
    `SELECT d.id, (d.admin_secret_ref IS NOT NULL AND d.installer_status IN ('succeeded','tls_pending')) AS admin_credentials_available, d.lifecycle_state, d.onboarding_stage, d.health_state, d.mail_hostname, d.webmail_hostname,
            d.mail_verified, d.domain_id, d.updated_at, d.installer_status, d.dns_writes_accepted,
            d.brevo_authenticated, d.brevo_verified, d.previous_mx, d.published_records, d.brevo_records, d.plan_snapshot,
            s.id AS server_id, s.state AS server_state, host(s.public_ipv4) AS public_ipv4,
            dom.normalized_name AS domain_name, dom.state AS domain_state, dom.existing_mail, dom.nameservers, dom.recheck_required
     FROM deployments d
     LEFT JOIN server_assignments a ON a.organization_id = d.organization_id AND a.released_at IS NULL
     LEFT JOIN servers s ON s.id = a.server_id
     LEFT JOIN domains dom ON dom.id = d.domain_id AND dom.organization_id = d.organization_id
     WHERE d.organization_id = $1 AND d.lifecycle_state <> 'deleted'
     ORDER BY d.created_at DESC
     LIMIT 1`,
    [organizationId],
  );
  const row = deployment.rows[0];
  const savedDomain = (await db.query<{id:string;normalized_name:string;state:string;existing_mail:boolean;nameservers:string[]}>(
    `SELECT id,normalized_name,state,existing_mail,nameservers FROM domains WHERE organization_id=$1 AND state <> 'retired' ORDER BY created_at DESC LIMIT 1`,[organizationId]
  )).rows[0];
  const domainId = row?.domain_id ?? savedDomain?.id;
  const onboarding = (await db.query<{state:CustomerPortalView['onboardingState'];missing_resource:string|null;last_error_code:string|null}>(
    'SELECT state,missing_resource,last_error_code FROM onboarding_requests WHERE organization_id=$1',[organizationId]
  )).rows[0];
  const backups = row
    ? await db.query<{ state: string; completed_at: Date | null; evidence_source: string; evidence_ref: string | null }>(
      `SELECT state, completed_at, evidence_source, evidence_ref FROM backups
       WHERE organization_id = $1 AND deployment_id = $2
       ORDER BY created_at DESC LIMIT 20`,
      [organizationId, row.id],
    )
    : { rows: [] as Array<{ state: string; completed_at: Date | null; evidence_source: string; evidence_ref: string | null }> };
  const actions = await db.query<{ code: string }>(
    `SELECT code FROM required_actions
     WHERE organization_id = $1 AND state = 'open'
     ORDER BY created_at DESC LIMIT 20`,
    [organizationId],
  );
  const allocation = await db.query<{ state: string }>(
    `SELECT state FROM allocation_requests
     WHERE organization_id = $1 AND state <> 'cancelled'
     ORDER BY created_at DESC LIMIT 1`,
    [organizationId],
  );
  const plan = await db.query<{ code: string | null; mailbox_limit: number | null; daily_send_limit: number | null }>(
    `SELECT p.code, p.mailbox_limit, p.daily_send_limit
     FROM organizations o
     LEFT JOIN plans p ON p.id = o.plan_id
     WHERE o.id = $1`,
    [organizationId],
  );
  const recovery = await db.query<{ verified_email: string | null }>(
    `SELECT u.verified_email
     FROM organizations o
     JOIN users u ON u.id = o.owner_user_id
     WHERE o.id = $1`,
    [organizationId],
  );
  const dns = domainId
    ? await db.query<{ provider: string; zone_id: string; state: string }>(
      `SELECT provider, zone_id, state FROM dns_connections
       WHERE organization_id = $1 AND domain_id = $2
       ORDER BY created_at DESC LIMIT 1`,
      [organizationId, domainId],
    )
    : { rows: [] as Array<{ provider: string; zone_id: string; state: string }> };
  const relay = await db.query<{ id: string }>(
    "SELECT id FROM relay_assignments WHERE organization_id = $1 AND released_at IS NULL LIMIT 1",
    [organizationId],
  );
  const mailboxes = row
    ? await db.query<{ local_part: string; kind: string; state: string; login_enabled: boolean; quota_bytes: string | null; usage_bytes: string }>(
      `SELECT local_part, kind, state, login_enabled, quota_bytes::text, usage_bytes::text
       FROM mailboxes WHERE organization_id = $1 AND deployment_id = $2
       ORDER BY local_part`,
      [organizationId, row.id],
    )
    : { rows: [] as Array<{ local_part: string; kind: string; state: string; login_enabled: boolean; quota_bytes: string | null; usage_bytes: string }> };
  const plans = row?.domain_id
    ? await db.query<{ purpose: string; state: string; desired_records: unknown }>(
      `SELECT purpose, state, desired_records FROM dns_plans
       WHERE organization_id = $1 AND domain_id = $2
       ORDER BY created_at DESC LIMIT 5`,
      [organizationId, row.domain_id],
    )
    : { rows: [] as Array<{ purpose: string; state: string; desired_records: unknown }> };
  const cancellation = row
    ? await db.query<{ state: string; execute_at: Date; service_stopped: boolean }>(
      `SELECT state, execute_at, service_stopped FROM cancellation_schedules
       WHERE organization_id = $1 AND deployment_id = $2
       ORDER BY created_at DESC LIMIT 1`,
      [organizationId, row.id],
    )
    : { rows: [] as Array<{ state: string; execute_at: Date; service_stopped: boolean }> };
  const health = row
    ? await db.query<{ observed_at: Date | null }>(
      "SELECT max(observed_at) AS observed_at FROM health_observations WHERE organization_id = $1 AND deployment_id = $2",
      [organizationId, row.id],
    )
    : { rows: [] as Array<{ observed_at: Date | null }> };
  const jobs = row
    ? await db.query<{ kind: string; state: string; updated_at: Date }>(
      `SELECT kind, state, updated_at FROM jobs
       WHERE organization_id = $1 AND deployment_id = $2
       ORDER BY created_at DESC LIMIT 10`,
      [organizationId, row.id],
    )
    : { rows: [] as Array<{ kind: string; state: string; updated_at: Date }> };
  const events = await db.query<{ action: string; occurred_at: Date }>(
    `SELECT action, occurred_at FROM audit_events
     WHERE organization_id = $1
     ORDER BY occurred_at DESC LIMIT 15`,
    [organizationId],
  );
  const domainName = row?.domain_name ?? savedDomain?.normalized_name ?? null;
  const domainState = row?.domain_state ?? savedDomain?.state ?? null;
  const existingMail = (row?.existing_mail ?? savedDomain?.existing_mail) === true;
  let brevoAuthenticated = row?.brevo_authenticated === true;
  let brevoVerified = row?.brevo_verified === true;
  let purposes = brevoPurposes(row?.brevo_records);
  if (!row && domainName) {
    const checked = await db.query<{ redacted_diff: unknown }>(
      `SELECT redacted_diff
       FROM audit_events
       WHERE organization_id = $1 AND action IN ('brevo.domain_check', 'brevo.authenticate')
       ORDER BY occurred_at DESC
       LIMIT 1`,
      [organizationId],
    );
    const diff = checked.rows[0]?.redacted_diff;
    if (diff && typeof diff === "object" && !Array.isArray(diff)) {
      const report = diff as { domain?: unknown; authenticated?: unknown; verified?: unknown; purposes?: unknown };
      if (report.domain === domainName) {
        brevoAuthenticated = report.authenticated === true;
        brevoVerified = report.verified === true;
        if (Array.isArray(report.purposes)) {
          purposes = report.purposes.filter((item): item is string => typeof item === "string" && item.length > 0 && item.length <= 40);
        }
      }
    }
  }
  const snapshot = snapshotPlan(row?.plan_snapshot);
  const assignedPlan = plan.rows[0]?.code ?? null;
  const latest = backups.rows[0];
  const backupRows: BackupLine[] = backups.rows.map((item) => ({
    state: item.state,
    freshness: backupFreshness(item.completed_at, Date.now()),
    completedAt: isoTime(item.completed_at),
    provenance: item.evidence_source === "operator" ? "operator-reported" : item.evidence_source,
    evidenceRef: item.evidence_ref,
  }));
  const mailboxRows: MailboxLine[] = mailboxes.rows.map((item) => ({
    localPart: item.local_part,
    kind: item.kind,
    state: item.state,
    loginEnabled: item.login_enabled,
    quotaBytes: item.quota_bytes == null ? null : Number(item.quota_bytes),
    usageBytes: Number(item.usage_bytes),
  }));
  const jobRows: ActivityLine[] = jobs.rows.map((item) => ({ kind: item.kind, state: item.state, at: isoTime(item.updated_at) }));
  const eventRows: ActivityLine[] = events.rows.map((item) => ({ kind: item.action, state: "recorded", at: isoTime(item.occurred_at) }));
  return {
    billing: billingRequired ? await billingView(db, organizationId, billingConfigured) : undefined,
    adminCredentialsAvailable:row?.admin_credentials_available===true,
    onboardingState: onboarding?.state ?? null,
    missingResource: onboarding?.missing_resource ?? null,
    onboardingError: onboarding?.last_error_code ?? null,
    organizationId,
    deploymentId: row?.id ?? null,
    lifecycleState: row?.lifecycle_state ?? null,
    onboardingStage: row?.onboarding_stage ?? null,
    healthState: row?.health_state ?? null,
    serverId: row?.server_id ?? null,
    serverState: row?.server_state ?? null,
    publicIpv4: row?.public_ipv4 ?? null,
    webmailHostname: row?.webmail_hostname ?? null,
    mailHostname: row?.mail_hostname ?? null,
    backupState: latest?.state ?? null,
    backupFreshness: backupFreshness(latest?.completed_at ?? null, Date.now()),
    requiredActions: actions.rows.map((item) => item.code),
    mailVerified: row?.mail_verified === true,
    cloudVerified: false,
    allocationState: allocation.rows[0]?.state ?? null,
    planCode: assignedPlan ?? snapshot?.code ?? null,
    planMailboxLimit: plan.rows[0]?.mailbox_limit == null ? snapshot?.mailboxLimit ?? null : Number(plan.rows[0].mailbox_limit),
    planDailySend: plan.rows[0]?.daily_send_limit == null ? null : Number(plan.rows[0].daily_send_limit),
    planSource: assignedPlan ? "assigned" : snapshot ? "deployment_snapshot" : null,
    domainName,
    domainState,
    existingMail,
    nameservers: row?.nameservers ?? savedDomain?.nameservers ?? [],
    dnsProvider: dns.rows[0]?.provider ?? null,
    dnsZone: dns.rows[0]?.zone_id ?? null,
    dnsState: dns.rows[0]?.state ?? null,
    recheckRequired: row?.recheck_required === true,
    dnsPlans: plans.rows.map((item) => ({ purpose: item.purpose, state: item.state, records: recordLines(item.desired_records) })),
    publishedRecords: recordLines(row?.published_records),
    previousMx: recordLines(row?.previous_mx),
    brevoAuthenticated,
    brevoVerified,
    brevoPurposes: purposes,
    dnsWritesAccepted: row?.dns_writes_accepted === true,
    installerStatus: row?.installer_status ?? null,
    relayAssigned: Boolean(relay.rows[0]),
    mailboxes: mailboxRows,
    backups: backupRows,
    events: eventRows,
    jobs: jobRows,
    cancellationState: cancellation.rows[0]?.state ?? null,
    cancellationExecuteAt: isoTime(cancellation.rows[0]?.execute_at),
    serviceStopped: cancellation.rows[0]?.service_stopped === true,
    recoveryEmail: recovery.rows[0]?.verified_email ?? null,
    lastCheckedAt: isoTime(health.rows[0]?.observed_at),
    updatedAt: isoTime(row?.updated_at),
    acceptedMailIsDelivery: false,
    manualDns: false,
  };
}

async function operatorView(db: Db, roles: OperatorRole[]): Promise<OperatorPortalView> {
  const counts = await db.query<{ state: string; count: number }>("SELECT state, count(*)::int AS count FROM servers GROUP BY state ORDER BY state");
  const servers = await db.query<{
    id: string;
    version: number;
    owner_name: string | null;
    recovery_reserved: boolean;
    state: string;
    label: string;
    public_ipv4: string | null;
    owner_id: string | null;
    operator_contact: string | null;
    provider_reference: string | null;
    profile_code: string;
    last_heartbeat_at: Date | null;
    validated_at: Date | null;
    tainted: boolean;
    identity_state: string | null;
    fingerprint: string | null;
    os: string | null;
    init: string | null;
    architecture: string | null;
    data_path_mounted: string | null;
    reachable: string | null;
    relay_reachable: string | null;
    prior_tenant_data: string | null;
    memory_mb: string | null;
    disk_gb: string | null;
    failures: string | null;
  }>(
    `SELECT s.id, s.version, o.name AS owner_name,
            EXISTS(SELECT 1 FROM recovery_bindings r WHERE r.replacement_server_id=s.id AND r.state='pending') AS recovery_reserved,
            s.state, s.label, host(s.public_ipv4) AS public_ipv4, a.organization_id AS owner_id,
            s.operator_contact, s.provider_reference, s.profile_code, s.last_heartbeat_at, s.validated_at,
            s.tenant_tainted_at IS NOT NULL AS tainted,
            (SELECT h.state FROM host_identities h WHERE h.server_id = s.id AND h.state <> 'revoked' ORDER BY h.created_at DESC LIMIT 1) AS identity_state,
            coalesce((SELECT h.fingerprint FROM host_identities h WHERE h.server_id = s.id AND h.state <> 'revoked' ORDER BY h.created_at DESC LIMIT 1),s.readiness_report->>'hostKeyFingerprint') AS fingerprint,
            s.readiness_report->>'os' AS os,
            s.readiness_report->>'init' AS init,
            s.readiness_report->>'architecture' AS architecture,
            s.readiness_report->>'dataPathMounted' AS data_path_mounted,
            s.readiness_report->>'reachable' AS reachable,
            s.readiness_report->>'relayReachable' AS relay_reachable,
            s.readiness_report->>'priorTenantData' AS prior_tenant_data,
            s.readiness_report->>'memoryMb' AS memory_mb,
            s.readiness_report->>'diskGb' AS disk_gb,
            s.readiness_report->>'failures' AS failures
     FROM servers s
     LEFT JOIN server_assignments a ON a.server_id = s.id AND a.released_at IS NULL
     LEFT JOIN organizations o ON o.id=a.organization_id
     ORDER BY s.created_at`,
  );
  const actions = await db.query<{ code: string }>(
    "SELECT code FROM required_actions WHERE state = 'open' ORDER BY created_at DESC LIMIT 50",
  );
  const waitlist = await db.query<{ organization_id: string; profile_code: string; verified_registered_at: Date }>(
    `SELECT organization_id, profile_code, verified_registered_at
     FROM allocation_requests
     WHERE state = 'waiting_for_server'
     ORDER BY verified_registered_at, id
     LIMIT 50`,
  );
  const relays = await db.query<{ id: string; version: number; archived_at:Date|null; owner_name:string|null; label: string; provider_account_id: string; smtp_login: string; daily_limit: number; state: string; assigned: boolean }>(
    `SELECT r.id,r.version,r.archived_at,
            (SELECT o.name FROM relay_assignments a JOIN organizations o ON o.id=a.organization_id WHERE a.relay_connection_id=r.id AND a.released_at IS NULL LIMIT 1) AS owner_name,
            r.label, r.provider_account_id, r.smtp_login, r.daily_limit, r.state,
            EXISTS (SELECT 1 FROM relay_assignments a WHERE a.relay_connection_id = r.id AND a.released_at IS NULL) AS assigned
     FROM relay_connections r
     ORDER BY r.created_at`,
  );
  const deployments = await db.query<{
    id: string;
    organization_id: string;
    lifecycle_state: string;
    onboarding_stage: string;
    health_state: string;
    mail_verified: boolean;
    installer_status: string | null;
    brevo_authenticated: boolean;
    brevo_verified: boolean;
    dns_writes_accepted: boolean;
    server_id: string | null;
    public_ipv4: string | null;
    relay_assigned: boolean;
  }>(
    `SELECT d.id, d.organization_id, d.lifecycle_state, d.onboarding_stage, d.health_state, d.mail_verified,
            d.installer_status, d.brevo_authenticated, d.brevo_verified, d.dns_writes_accepted,
            s.id AS server_id, host(s.public_ipv4) AS public_ipv4,
            EXISTS (
              SELECT 1 FROM relay_assignments ra
              WHERE ra.organization_id = d.organization_id AND ra.released_at IS NULL
            ) AS relay_assigned
     FROM deployments d
     LEFT JOIN server_assignments a ON a.organization_id = d.organization_id AND a.released_at IS NULL
     LEFT JOIN servers s ON s.id = a.server_id
     WHERE d.lifecycle_state <> 'deleted'
     ORDER BY d.created_at DESC
     LIMIT 20`,
  );
  const estimates = await db.query<{ server_id: string; amount_minor: number; currency: string; source: string; billing_system: string }>(
    `SELECT DISTINCT ON (server_id) server_id, amount_minor, currency, source, billing_system
     FROM hosting_estimates
     ORDER BY server_id, recorded_at DESC`,
  );
  const upgrades = await db.query<{ deployment_id: string; state: string }>(
    "SELECT deployment_id, state FROM upgrade_plans ORDER BY created_at DESC LIMIT 20",
  );
  const users = await db.query<{
    id:string; email:string|null; email_verified:boolean; status:string; created_at:Date;
    organization_id:string|null; organization_name:string|null; organization_status:string|null;
    domains:string|null; server_id:string|null; server_label:string|null; public_ipv4:string|null;
    relay_id:string|null; relay_label:string|null; relay_account:string|null;
    lifecycle_state:string|null; onboarding_state:string|null;
  }>(`SELECT u.id,u.verified_email AS email,u.email_verified,u.status,u.created_at,
      o.id AS organization_id,o.name AS organization_name,o.status AS organization_status,
      (SELECT string_agg(d.normalized_name, ', ' ORDER BY d.normalized_name) FROM domains d WHERE d.organization_id=o.id AND d.state <> 'retired') AS domains,
      s.id AS server_id,s.label AS server_label,host(s.public_ipv4) AS public_ipv4,
      r.id AS relay_id,r.label AS relay_label,r.provider_account_id AS relay_account,
      (SELECT d.lifecycle_state FROM deployments d WHERE d.organization_id=o.id ORDER BY d.created_at DESC LIMIT 1) AS lifecycle_state,
      (SELECT q.state FROM onboarding_requests q WHERE q.organization_id=o.id ORDER BY q.created_at DESC LIMIT 1) AS onboarding_state
    FROM users u
    LEFT JOIN organizations o ON o.owner_user_id=u.id
    LEFT JOIN server_assignments sa ON sa.organization_id=o.id AND sa.released_at IS NULL
    LEFT JOIN servers s ON s.id=sa.server_id
    LEFT JOIN relay_assignments ra ON ra.organization_id=o.id AND ra.released_at IS NULL
    LEFT JOIN relay_connections r ON r.id=ra.relay_connection_id
    ORDER BY u.created_at DESC,o.created_at DESC`);
  const estimateByServer = new Map(estimates.rows.map((row) => [
    row.server_id,
    `${Number(row.amount_minor)} ${row.currency} ${row.source} ${row.billing_system}`,
  ]));
  const billingCleanup = await db.query<{ organization_id: string; email: string; server_id: string | null; public_ipv4: string | null; relay_id: string | null }>(
    `SELECT b.organization_id,u.verified_email AS email,a.server_id,host(s.public_ipv4) AS public_ipv4,r.relay_connection_id AS relay_id
     FROM billing_subscriptions b JOIN organizations o ON o.id=b.organization_id JOIN users u ON u.id=o.owner_user_id
     LEFT JOIN server_assignments a ON a.organization_id=o.id AND a.released_at IS NULL LEFT JOIN servers s ON s.id=a.server_id
     LEFT JOIN relay_assignments r ON r.organization_id=o.id AND r.released_at IS NULL WHERE b.cleanup_required
     AND EXISTS(SELECT 1 FROM required_actions x WHERE x.organization_id=o.id AND x.code='billing.manual_release' AND x.state='open') ORDER BY b.updated_at`);
  return {
    billingCleanup: billingCleanup.rows.map(row=>({organizationId:row.organization_id,email:row.email,serverId:row.server_id,publicIpv4:row.public_ipv4,relayId:roles.includes("support") ? null : row.relay_id})),
    canManageServers:roles.includes("platform_administrator")||roles.includes("infrastructure_operator"),
    canManageBrevo:roles.includes("platform_administrator"),
    canViewBrevo:roles.includes("platform_administrator")||roles.includes("infrastructure_operator"),
    users:users.rows.map(row=>({id:row.id,email:row.email,emailVerified:row.email_verified,status:row.status,createdAt:isoTime(row.created_at),organizationId:row.organization_id,organizationName:row.organization_name,organizationStatus:row.organization_status,domains:row.domains,serverId:row.server_id,serverLabel:row.server_label,publicIpv4:row.public_ipv4,relayId:row.relay_id,relayLabel:row.relay_label,relayAccount:row.relay_account,lifecycleState:row.lifecycle_state,onboardingState:row.onboarding_state})),
    counts: counts.rows.map((row) => ({ state: row.state, count: Number(row.count) })),
    servers: servers.rows.map((server) => ({
      id: server.id,
      version: server.version,
      ownerName: server.owner_name,
      recoveryReserved: server.recovery_reserved,
      state: server.state,
      publicIpv4: server.public_ipv4,
      label: server.label,
      ownerId: server.owner_id,
      operatorContact: server.operator_contact,
      providerReference: server.provider_reference,
      profileCode: server.profile_code,
      lastHeartbeatAt: heartbeatLabel(server.last_heartbeat_at),
      validatedAt: isoTime(server.validated_at),
      identityState: server.identity_state,
      fingerprint: server.fingerprint,
      readiness: readinessLabel(server),
      readinessFailures: server.failures ? JSON.parse(server.failures) as string[] : [],
      tainted: server.tainted,
      hostingEstimate: estimateByServer.get(server.id) ?? null,
    })),
    requiredActions: actions.rows.map((row) => row.code),
    cloudVerified: false,
    waitlist: waitlist.rows.map((row) => ({
      organizationId: row.organization_id,
      profileCode: row.profile_code,
      registeredAt: isoTime(row.verified_registered_at),
    })),
    relays: relays.rows.map((row) => ({
      id: row.id,
      version: row.version,
      archivedAt: isoTime(row.archived_at),
      ownerName: row.owner_name,
      label: row.label,
      account: row.provider_account_id,
      smtpLogin: row.smtp_login,
      dailyLimit: Number(row.daily_limit),
      state: row.state,
      assigned: row.assigned,
    })),
    deployments: deployments.rows.map((row) => ({
      id: row.id,
      organizationId: row.organization_id,
      lifecycleState: row.lifecycle_state,
      onboardingStage: row.onboarding_stage,
      healthState: row.health_state,
      serverId: row.server_id,
      publicIpv4: row.public_ipv4,
      installerStatus: row.installer_status,
      relayAssigned: row.relay_assigned,
      brevoAuthenticated: row.brevo_authenticated,
      brevoVerified: row.brevo_verified,
      dnsWritesAccepted: row.dns_writes_accepted,
      mailVerified: row.mail_verified === true,
    })),
    upgrades: upgrades.rows.map((row) => ({ deploymentId: row.deployment_id, state: row.state })),
  };
}

function snapshotPlan(value: unknown): { code: string; mailboxLimit: number | null } | null {
  if (!value || typeof value !== "object") return null;
  const row = value as { code?: unknown; mailboxLimit?: unknown };
  if (typeof row.code !== "string" || row.code.length === 0 || row.code.length > 40) return null;
  const limit = typeof row.mailboxLimit === "number" ? row.mailboxLimit : null;
  return { code: row.code, mailboxLimit: limit };
}

function isoTime(value: Date | string | null | undefined): string | null {
  if (!value) return null;
  const parsed = value instanceof Date ? value : new Date(value);
  return Number.isNaN(parsed.getTime()) ? null : parsed.toISOString();
}

function heartbeatLabel(value: Date | null): string | null {
  const text = isoTime(value);
  if (!text || !value) return null;
  return Date.now() - value.getTime() >= HEARTBEAT_MAX_AGE_MS ? `${text} stale` : text;
}

function readinessLabel(row: {
  os: string | null;
  init: string | null;
  architecture: string | null;
  memory_mb: string | null;
  disk_gb: string | null;
  data_path_mounted: string | null;
  reachable: string | null;
  relay_reachable: string | null;
  prior_tenant_data: string | null;
  failures: string | null;
}): string {
  if (!row.os && !row.init && !row.memory_mb && !row.reachable) return "No readiness report.";
  return [
    row.os,
    row.init,
    row.architecture,
    row.memory_mb ? `${row.memory_mb} MB` : null,
    row.disk_gb ? `${row.disk_gb} GB` : null,
    `data path mounted ${row.data_path_mounted ?? "unknown"} (not a validation check)`,
    `reachable ${row.reachable ?? "unknown"}`,
    `relay ${row.relay_reachable ?? "unknown"}`,
    `prior tenant data ${row.prior_tenant_data ?? "unknown"}`,
    row.failures && row.failures !== "[]" ? `failures ${row.failures}` : null,
  ].filter((part): part is string => Boolean(part)).join(", ");
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function errorBody(code: string, message: string, retryable = false, requiredActionId: string | null = null): ErrorBody {
  return { error: { code, message, retryable, requiredActionId } };
}

function requireScheduler(request: FastifyRequest, expected: string | undefined): void {
  if (!expected) throw new HttpError(503, "SCHEDULER_UNAVAILABLE", "The scheduler identity is not configured.", true);
  const header = request.headers["x-bearportal-scheduler"];
  const provided = typeof header === "string" ? header : "";
  if (provided.length !== expected.length || !timingSafeEqualText(provided, expected)) {
    throw new HttpError(401, "UNAUTHENTICATED", "The scheduler identity was rejected.");
  }
}

function timingSafeEqualText(left: string, right: string): boolean {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  if (a.length !== b.length) return false;
  let mismatch = 0;
  for (let i = 0; i < a.length; i += 1) mismatch |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return mismatch === 0;
}
