import { createHash, randomUUID, timingSafeEqual } from "node:crypto";
import type { FastifyInstance, FastifyRequest } from "fastify";
import {
  adminOperationSchema,
  approvalDecisionSchema,
  emptyObjectSchema,
  healthObserveSchema,
  hostingEstimateSchema,
  oversightToolSchema,
  providerFaultSchema,
  recoveryEnterSchema,
  stepCompleteSchema,
  usageReportSchema,
  versionedSchema,
  watchdogSchema,
} from "../../../packages/contracts/src/index.ts";
import { completeVerifiedStep, invocationAllowed, requestOperation, type GatewayDecision, type SessionAuthority } from "../../../packages/operations/src/gateway.ts";
import {
  applyProbeResult,
  deriveHealth,
  NETWORK_PROBES,
  nextRetry,
  recordUsage,
  recoveryPosture,
  watchdogThaw,
  type HealthObservation,
} from "../../../packages/operations/src/policy.ts";
import type { Queryable } from "../../../packages/servers/src/allocate.ts";
import { HttpError } from "./errors.ts";

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

export type OversightContext = {
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
  schedulerToken?: string;
};

const RECENT_AUTH_SECONDS = 15 * 60;
const COMMAND_FIELDS = new Set(["command", "shell", "code", "codeBody", "executable", "executablePath", "script", "scriptUrl", "scriptPath", "argv", "env"]);

type SessionRow = {
  id: string;
  organization_id: string | null;
  deployment_id: string | null;
  server_id: string | null;
  scope: "tenant" | "inventory";
  generation: number;
  auth_epoch: number;
  lease_fencing_token: string;
  state: "open" | "terminated";
  tool_requests: number;
  invocations: number;
  usage_tokens: number | null;
  usage_provenance: "reported" | "unknown";
  started_at: Date;
};

export async function mutationsPaused(db: Db): Promise<boolean> {
  const row = await db.query<{ mode: string }>("SELECT mode FROM control_plane_state WHERE id = 1");
  return row.rows[0]?.mode === "recovery";
}

export function registerOversightRoutes(app: FastifyInstance, ctx: OversightContext): void {
  app.post("/v1/deployments/:id/oversight/sessions", async (request, reply) => {
    const idempotencyKey = ctx.demandIdempotency(request);
    const { id } = request.params as { id: string };
    const body = versionedSchema.parse(request.body);
    const created = await ctx.withActor(request, "customer", async (db, actor) => {
      ctx.requireVerified(actor);
      if (!actor.organizationId) throw new HttpError(422, "ORGANIZATION_REQUIRED", "Create an organization first.");
      const route = "POST /v1/deployments/:id/oversight/sessions";
      const replayed = await ctx.replay(db, actor.userId, route, idempotencyKey, { id, ...body });
      if (replayed) return replayed;
      const deployment = await db.query<{ version: number; generation: number }>(
        "SELECT version, generation FROM deployments WHERE id = $1 AND organization_id = $2 AND lifecycle_state <> 'deleted'",
        [id, actor.organizationId],
      );
      const row = deployment.rows[0];
      if (!row) throw new HttpError(404, "NOT_FOUND", "The deployment was not found.");
      if (row.version !== body.expectedVersion) throw new HttpError(409, "VERSION_CONFLICT", "The deployment changed.");
      const host = await currentHost(db, actor.organizationId);
      const sessionId = randomUUID();
      await insertSession(db, {
        id: sessionId,
        organizationId: actor.organizationId,
        deploymentId: id,
        serverId: host?.serverId ?? null,
        scope: "tenant",
        generation: row.generation,
        authEpoch: host?.authEpoch ?? 0,
        lease: randomUUID(),
      });
      const response = sessionResponse(sessionId, "tenant", row.generation, host?.authEpoch ?? 0);
      await ctx.remember(db, actor.userId, route, idempotencyKey, { id, ...body }, 201, response);
      return { status: 201 as const, body: response };
    });
    return reply.code(created.status).send({ ...created.body, requestId: request.id });
  });

  app.post("/v1/admin/servers/:id/oversight/sessions", async (request, reply) => {
    const idempotencyKey = ctx.demandIdempotency(request);
    const { id } = request.params as { id: string };
    const body = versionedSchema.parse(request.body);
    const created = await ctx.withActor(request, "operator", async (db, actor) => {
      assertWriter(ctx, actor);
      const route = "POST /v1/admin/servers/:id/oversight/sessions";
      const replayed = await ctx.replay(db, actor.userId, route, idempotencyKey, { id, ...body });
      if (replayed) return replayed;
      const server = await db.query<{ version: number; auth_epoch: number }>(
        "SELECT version, auth_epoch FROM servers WHERE id = $1",
        [id],
      );
      const row = server.rows[0];
      if (!row) throw new HttpError(404, "NOT_FOUND", "The server was not found.");
      if (row.version !== body.expectedVersion) throw new HttpError(409, "VERSION_CONFLICT", "The server changed.");
      const sessionId = randomUUID();
      await insertSession(db, {
        id: sessionId,
        organizationId: null,
        deploymentId: null,
        serverId: id,
        scope: "inventory",
        generation: 0,
        authEpoch: row.auth_epoch,
        lease: randomUUID(),
      });
      const response = sessionResponse(sessionId, "inventory", 0, row.auth_epoch);
      await ctx.remember(db, actor.userId, route, idempotencyKey, { id, ...body }, 201, response);
      return { status: 201 as const, body: response };
    });
    return reply.code(created.status).send({ ...created.body, requestId: request.id });
  });

  app.get("/v1/oversight/sessions/:id", async (request) => {
    const { id } = request.params as { id: string };
    return ctx.withActor(request, "customer", async (db, actor) => {
      ctx.requireVerified(actor);
      const session = await loadSession(db, id);
      if (!session || session.organization_id !== actor.organizationId) throw new HttpError(404, "NOT_FOUND", "The oversight session was not found.");
      return { ...(await sessionView(db, session)), requestId: request.id };
    });
  });

  app.post("/v1/oversight/sessions/:id/resume", async (request, reply) => {
    const idempotencyKey = ctx.demandIdempotency(request);
    const { id } = request.params as { id: string };
    const body = emptyObjectSchema.parse(request.body ?? {});
    const created = await ctx.withActor(request, "customer", async (db, actor) => {
      ctx.requireVerified(actor);
      const route = "POST /v1/oversight/sessions/:id/resume";
      const replayed = await ctx.replay(db, actor.userId, route, idempotencyKey, { id, ...body });
      if (replayed) return replayed;
      const session = await loadSession(db, id);
      if (!session || session.organization_id !== actor.organizationId || !session.deployment_id) {
        throw new HttpError(404, "NOT_FOUND", "The oversight session was not found.");
      }
      const current = await authorityNow(db, session);
      if (!current || current.generation !== session.generation || current.authEpoch !== session.auth_epoch) {
        await db.query(
          `UPDATE oversight_sessions
           SET state = 'terminated', terminated_reason = 'stale_authority', updated_at = now(), version = version + 1
           WHERE id = $1`,
          [id],
        );
        const response = errorBody("STALE_AUTHORITY", "The session authority is no longer current.");
        await ctx.remember(db, actor.userId, route, idempotencyKey, { id, ...body }, 409, response);
        return { status: 409 as const, body: response };
      }
      const response = { sessionId: id, rebound: true, generation: session.generation, authEpoch: session.auth_epoch, duplicateOperations: false };
      await ctx.remember(db, actor.userId, route, idempotencyKey, { id, ...body }, 200, response);
      return { status: 200 as const, body: response };
    });
    return reply.code(created.status).send({ ...created.body, requestId: request.id });
  });

  app.post("/v1/oversight/sessions/:id/assess", async (request, reply) => {
    const idempotencyKey = ctx.demandIdempotency(request);
    const { id } = request.params as { id: string };
    emptyObjectSchema.parse(request.body ?? {});
    await ctx.withActor(request, "customer", async (db, actor) => {
      ctx.requireVerified(actor);
      const session = await loadSession(db, id);
      if (!session || session.organization_id !== actor.organizationId) throw new HttpError(404, "NOT_FOUND", "The oversight session was not found.");
      throw new HttpError(503, "HARNESS_UNAVAILABLE", "Live Grok Build is not configured.", true);
    });
    return reply.code(503).send({ ...errorBody("HARNESS_UNAVAILABLE", "Live Grok Build is not configured.", true), requestId: request.id, idempotencyKey });
  });

  app.post("/v1/deployments/:id/oversight/wait", async (request, reply) => {
    const idempotencyKey = ctx.demandIdempotency(request);
    const { id } = request.params as { id: string };
    const body = versionedSchema.parse(request.body);
    const created = await ctx.withActor(request, "customer", async (db, actor) => {
      ctx.requireVerified(actor);
      if (!actor.organizationId) throw new HttpError(422, "ORGANIZATION_REQUIRED", "Create an organization first.");
      const route = "POST /v1/deployments/:id/oversight/wait";
      const replayed = await ctx.replay(db, actor.userId, route, idempotencyKey, { id, ...body });
      if (replayed) return replayed;
      const deployment = await db.query<{ version: number }>(
        "SELECT version FROM deployments WHERE id = $1 AND organization_id = $2 AND lifecycle_state <> 'deleted'",
        [id, actor.organizationId],
      );
      if (!deployment.rows[0]) throw new HttpError(404, "NOT_FOUND", "The deployment was not found.");
      if (deployment.rows[0].version !== body.expectedVersion) throw new HttpError(409, "VERSION_CONFLICT", "The deployment changed.");
      const existing = await db.query<{ id: string }>(
        `SELECT id FROM jobs
         WHERE organization_id = $1 AND deployment_id = $2 AND kind = 'oversight.wait' AND state = 'waiting_human'
         LIMIT 1`,
        [actor.organizationId, id],
      );
      const jobId = existing.rows[0]?.id ?? randomUUID();
      if (!existing.rows[0]) {
        await db.query(
          `INSERT INTO jobs (id, organization_id, deployment_id, kind, state, checkpoint)
           VALUES ($1, $2, $3, 'oversight.wait', 'waiting_human', '{"modelLoop":false}'::jsonb)`,
          [jobId, actor.organizationId, id],
        );
      }
      const response = { jobId, state: "waiting_human", modelInvocations: 0, harnessCalled: false };
      await ctx.remember(db, actor.userId, route, idempotencyKey, { id, ...body }, 202, response);
      return { status: 202 as const, body: response };
    });
    return reply.code(created.status).send({ ...created.body, requestId: request.id });
  });

  app.get("/v1/deployments/:id/health", async (request) => {
    const { id } = request.params as { id: string };
    return ctx.withActor(request, "customer", async (db, actor) => {
      ctx.requireVerified(actor);
      if (!actor.organizationId) throw new HttpError(404, "NOT_FOUND", "The deployment was not found.");
      const deployment = await db.query<{ mail_verified: boolean }>(
        "SELECT mail_verified FROM deployments WHERE id = $1 AND organization_id = $2 AND lifecycle_state <> 'deleted'",
        [id, actor.organizationId],
      );
      if (!deployment.rows[0]) throw new HttpError(404, "NOT_FOUND", "The deployment was not found.");
      const view = await healthView(db, actor.organizationId, id);
      return { ...view, mailVerified: deployment.rows[0].mail_verified, requestId: request.id };
    });
  });

  app.post("/v1/approvals/:id/decision", async (request, reply) => {
    const idempotencyKey = ctx.demandIdempotency(request);
    const { id } = request.params as { id: string };
    const body = approvalDecisionSchema.parse(request.body);
    const created = await ctx.withActor(request, "customer", async (db, actor) => {
      ctx.requireVerified(actor);
      if (!actor.organizationId) throw new HttpError(422, "ORGANIZATION_REQUIRED", "Create an organization first.");
      const fresh = actor.authTime > 0 && Math.floor(Date.now() / 1000) - actor.authTime <= RECENT_AUTH_SECONDS;
      if (!fresh) throw new HttpError(403, "RECENT_AUTH_REQUIRED", "Sign in again before deciding an approval.");
      const route = "POST /v1/approvals/:id/decision";
      const replayed = await ctx.replay(db, actor.userId, route, idempotencyKey, { id, ...body });
      if (replayed) return replayed;
      const approval = await db.query<{
        version: number;
        plan_hash: string;
        action_code: string;
        state: string;
        expires_at: Date;
        in_flight: boolean;
      }>(
        `SELECT version, plan_hash, action_code, state, expires_at, in_flight
         FROM approvals WHERE id = $1 AND organization_id = $2`,
        [id, actor.organizationId],
      );
      const row = approval.rows[0];
      if (!row) throw new HttpError(404, "NOT_FOUND", "The approval was not found.");
      if (row.version !== body.expectedVersion) throw new HttpError(409, "VERSION_CONFLICT", "The approval changed.");
      if (row.plan_hash !== body.planHash) {
        await db.query(
          `UPDATE approvals SET state = 'invalidated', updated_at = now(), version = version + 1 WHERE id = $1`,
          [id],
        );
        const response = errorBody("PLAN_STALE", "The approval plan no longer matches.");
        await ctx.remember(db, actor.userId, route, idempotencyKey, { id, ...body }, 409, response);
        return { status: 409 as const, body: response };
      }
      if (row.expires_at.getTime() <= Date.now() && !row.in_flight) {
        await db.query(`UPDATE approvals SET state = 'expired', updated_at = now(), version = version + 1 WHERE id = $1`, [id]);
        const response = errorBody("APPROVAL_EXPIRED", "The approval window has ended.");
        await ctx.remember(db, actor.userId, route, idempotencyKey, { id, ...body }, 409, response);
        return { status: 409 as const, body: response };
      }
      if (forbiddenAction(row.action_code)) {
        await db.query(`UPDATE approvals SET state = 'rejected', executed = false, updated_at = now(), version = version + 1 WHERE id = $1`, [id]);
        const response = errorBody("FORBIDDEN", "Approval cannot enable that capability.");
        await ctx.remember(db, actor.userId, route, idempotencyKey, { id, ...body }, 422, response);
        return { status: 422 as const, body: response };
      }
      const state = body.decision === "approve" ? "approved" : "rejected";
      await db.query(
        `UPDATE approvals
         SET state = $2, approver_id = $3, executed = false, updated_at = now(), version = version + 1
         WHERE id = $1`,
        [id, state, actor.userId],
      );
      if (row.action_code === "cancellation") {
        await db.query(
          `UPDATE cancellation_schedules
           SET state = $3, updated_at = now(), version = version + 1
           WHERE approval_id = $1 AND organization_id = $2 AND state = 'proposed'`,
          [id, actor.organizationId, state === "approved" ? "scheduled" : "revoked"],
        );
      }
      const response = { id, state, executed: false, dnsWrite: false, mailVerified: false };
      await ctx.remember(db, actor.userId, route, idempotencyKey, { id, ...body }, 200, response);
      return { status: 200 as const, body: response };
    });
    return reply.code(created.status).send({ ...created.body, requestId: request.id });
  });

  app.post("/v1/admin/deployments/:id/operations", async (request, reply) => {
    const idempotencyKey = ctx.demandIdempotency(request);
    const { id } = request.params as { id: string };
    const body = adminOperationSchema.parse(request.body);
    const created = await ctx.withActor(request, "operator", async (db, actor) => {
      assertWriter(ctx, actor);
      const route = "POST /v1/admin/deployments/:id/operations";
      const parameters = body.parameters ?? {};
      const replayed = await ctx.replay(db, actor.userId, route, idempotencyKey, { id, kind: body.kind, parameters, expectedVersion: body.expectedVersion });
      if (replayed) return replayed;
      if (commandFields(parameters).size > 0) {
        const response = errorBody("COMMAND_REJECTED", "Oversight cannot supply a command or script.");
        await ctx.remember(db, actor.userId, route, idempotencyKey, { id, kind: body.kind, parameters, expectedVersion: body.expectedVersion }, 422, response);
        return { status: 422 as const, body: response };
      }
      const deployment = await db.query<{ version: number; organization_id: string; generation: number }>(
        "SELECT version, organization_id, generation FROM deployments WHERE id = $1 AND lifecycle_state <> 'deleted'",
        [id],
      );
      const row = deployment.rows[0];
      if (!row) throw new HttpError(404, "NOT_FOUND", "The deployment was not found.");
      if (row.version !== body.expectedVersion) throw new HttpError(409, "VERSION_CONFLICT", "The deployment changed.");
      if (body.kind === "diagnose") {
        const summary = typeof parameters.summary === "string" && parameters.summary.length > 0 && parameters.summary.length <= 500
          ? parameters.summary
          : "Operator diagnosis.";
        const diagnosisId = randomUUID();
        await db.query(
          `INSERT INTO diagnoses (id, organization_id, deployment_id, summary, evidence_ids)
           VALUES ($1, $2, $3, $4, '[]'::jsonb)`,
          [diagnosisId, row.organization_id, id, summary],
        );
        const response = { outcome: "succeeded", diagnosisId, mailVerified: false, deliveryProven: false, executed: false };
        await ctx.remember(db, actor.userId, route, idempotencyKey, { id, kind: body.kind, parameters, expectedVersion: body.expectedVersion }, 200, response);
        return { status: 200 as const, body: response };
      }
      if (body.kind === "reconcile_ip") {
        const observed = await db.query<{ registered_ip: string | null; observed_ip: string | null }>(
          `SELECT host(s.public_ipv4) AS registered_ip, host(d.observed_ip) AS observed_ip
           FROM deployments d
           LEFT JOIN server_assignments a ON a.organization_id = d.organization_id AND a.released_at IS NULL
           LEFT JOIN servers s ON s.id = a.server_id
           WHERE d.id = $1`,
          [id],
        );
        const response = {
          outcome: "succeeded",
          code: "ip.operator_required",
          installerStarted: false,
          dnsWrite: false,
          inventedIp: false,
          registeredIp: observed.rows[0]?.registered_ip ?? null,
          observedIp: observed.rows[0]?.observed_ip ?? null,
          mailVerified: false,
        };
        await ctx.remember(db, actor.userId, route, idempotencyKey, { id, kind: body.kind, parameters, expectedVersion: body.expectedVersion }, 200, response);
        return { status: 200 as const, body: response };
      }
      const approvalId = randomUUID();
      const planHash = createHash("sha256").update(`${body.kind}\n${id}\n${row.generation}`).digest("hex");
      await db.query(
        `INSERT INTO approvals (
           id, organization_id, deployment_id, action_code, plan_hash, generation, resource_id, dns_fingerprint, state, expires_at
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, 'unobserved', 'pending', now() + interval '30 minutes')`,
        [approvalId, row.organization_id, id, body.kind, planHash, row.generation, id],
      );
      const response = { approvalId, outcome: "pending", executed: false, planHash, mailVerified: false };
      await ctx.remember(db, actor.userId, route, idempotencyKey, { id, kind: body.kind, parameters, expectedVersion: body.expectedVersion }, 202, response);
      return { status: 202 as const, body: response };
    });
    return reply.code(created.status).send({ ...created.body, requestId: request.id });
  });

  app.get("/v1/admin/servers/:id/hosting-estimate", async (request) => {
    const { id } = request.params as { id: string };
    return ctx.withActor(request, "operator", async (db, actor) => {
      ctx.requireVerified(actor);
      const row = await db.query<{ amount_minor: number; currency: string; source: string; billing_system: string; recorded_at: Date }>(
        `SELECT amount_minor, currency, source, billing_system, recorded_at
         FROM hosting_estimates WHERE server_id = $1 ORDER BY recorded_at DESC LIMIT 1`,
        [id],
      );
      const estimate = row.rows[0];
      if (!estimate) throw new HttpError(404, "NOT_FOUND", "No operator hosting estimate is recorded.");
      return {
        serverId: id,
        amountMinor: estimate.amount_minor,
        currency: estimate.currency,
        source: estimate.source,
        billingSystem: estimate.billing_system,
        recordedAt: estimate.recorded_at,
        requestId: request.id,
        actor: actor.userId,
      };
    });
  });

  app.post("/v1/admin/servers/:id/hosting-estimate", async (request, reply) => {
    const idempotencyKey = ctx.demandIdempotency(request);
    const { id } = request.params as { id: string };
    const body = hostingEstimateSchema.parse(request.body);
    const created = await ctx.withActor(request, "operator", async (db, actor) => {
      assertWriter(ctx, actor);
      const route = "POST /v1/admin/servers/:id/hosting-estimate";
      const replayed = await ctx.replay(db, actor.userId, route, idempotencyKey, { id, ...body });
      if (replayed) return replayed;
      const updated = await db.query(
        "UPDATE servers SET hosting_estimate_minor = $2, version = version + 1, updated_at = now() WHERE id = $1 AND version = $3",
        [id, body.amountMinor, body.expectedVersion],
      );
      if ((updated.rowCount ?? 0) === 0) throw new HttpError(409, "VERSION_CONFLICT", "The server changed.");
      const estimateId = randomUUID();
      await db.query(
        `INSERT INTO hosting_estimates (id, server_id, amount_minor, currency, source, billing_system, recorded_by)
         VALUES ($1, $2, $3, $4, 'operator', 'not_google_billing', $5)`,
        [estimateId, id, body.amountMinor, body.currency, actor.userId],
      );
      const response = {
        id: estimateId,
        amountMinor: body.amountMinor,
        currency: body.currency,
        source: "operator",
        billingSystem: "not_google_billing",
      };
      await ctx.audit(db, request, actor.userId, null, "server.hosting_estimate", id, { source: "operator", currency: body.currency });
      await ctx.remember(db, actor.userId, route, idempotencyKey, { id, ...body }, 201, response);
      return { status: 201 as const, body: response };
    });
    return reply.code(created.status).send({ ...created.body, requestId: request.id });
  });

  app.post("/internal/agent-runs/:id/tools/:tool", async (request, reply) => {
    requireScheduler(request, ctx.schedulerToken);
    const { id, tool } = request.params as { id: string; tool: string };
    const body = oversightToolSchema.parse(request.body ?? {});
    const created = await ctx.withSystem("inventory_worker", async (db) => {
      if (await mutationsPaused(db)) {
        return { status: 409 as const, body: errorBody("RECOVERY_MODE", "Control-plane recovery has paused agent requests.") };
      }
      const session = await loadSession(db, id);
      if (!session) throw new HttpError(404, "NOT_FOUND", "The oversight session was not found.");
      if (session.state !== "open") {
        return { status: 409 as const, body: errorBody("SESSION_CLOSED", "The oversight session is closed.") };
      }
      const current = await authorityNow(db, session);
      const authorityMatches = current != null && current.generation === session.generation && current.authEpoch === session.auth_epoch;
      const existingId = authorityMatches ? decisionStepId(session, tool, body.version, body.arguments) : null;
      if (existingId) {
        const existing = await db.query<{ id: string; state: string; operation_key: string; operation_version: string; handler: string; digest: string }>(
          "SELECT id, state, operation_key, operation_version, handler, digest FROM operation_steps WHERE id = $1 AND session_id = $2",
          [existingId, id],
        );
        const step = existing.rows[0];
        if (step) {
          return {
            status: 202 as const,
            body: {
              outcome: "pending",
              stepId: step.id,
              operationKey: step.operation_key,
              version: step.operation_version,
              handler: step.handler,
              digest: step.digest,
              code: "ACCEPTED",
              duplicate: true,
              productionInvoked: true,
              mailVerified: false,
            },
          };
        }
      }
      const decision = requestOperation({
        tool,
        version: body.version,
        claimedDigest: body.claimedDigest,
        arguments: body.arguments,
        session: toAuthority(session),
        context: toContext(session, current),
        recovery: false,
        nowMs: Date.now(),
        approval: null,
      });
      await applyDecision(db, session, decision);
      if (decision.outcome === "pending" && decision.stepId) {
        return { status: 202 as const, body: pendingBody(decision) };
      }
      const actionId = decision.code === "BUDGET_EXHAUSTED" && session.organization_id
        ? await openAction(db, session.organization_id, session.deployment_id, "agent.budget", "The oversight run reached its budget.")
        : null;
      return {
        status: decision.httpStatus as 400 | 404 | 409 | 422 | 429,
        body: { ...errorBody(decision.code, decision.message, false, actionId), productionInvoked: false },
      };
    });
    return reply.code(created.status).send({ ...created.body, requestId: request.id });
  });

  app.post("/internal/agent-runs/:id/complete", async (request, reply) => {
    requireScheduler(request, ctx.schedulerToken);
    const { id } = request.params as { id: string };
    const body = stepCompleteSchema.parse(request.body);
    const created = await ctx.withSystem("inventory_worker", async (db) => {
      const session = await loadSession(db, id);
      if (!session) throw new HttpError(404, "NOT_FOUND", "The oversight session was not found.");
      const step = await db.query<{
        id: string;
        operation_key: string;
        operation_version: string;
        handler: string;
        digest: string;
        state: "pending" | "succeeded" | "blocked" | "retryable_error" | "permanent_error";
        code: string;
        arguments: Record<string, unknown>;
        requested_key: string | null;
        requested_version: string | null;
        requested_handler: string | null;
        requested_digest: string | null;
        job_id: string | null;
        organization_id: string | null;
      }>(
        `SELECT id, operation_key, operation_version, handler, digest, state, code, arguments,
                requested_key, requested_version, requested_handler, requested_digest, job_id, organization_id
         FROM operation_steps WHERE id = $1 AND session_id = $2`,
        [body.stepId, id],
      );
      const row = step.rows[0];
      if (!row) throw new HttpError(404, "NOT_FOUND", "The operation step was not found.");
      if (row.state === "succeeded") {
        return { status: 200 as const, body: { outcome: "succeeded", stepId: row.id, code: row.code, duplicate: true, mailVerified: false, deliveryProven: false } };
      }
      const current = await authorityNow(db, session);
      const decision = completeVerifiedStep({
        operationKey: row.operation_key,
        state: row.state,
        digest: row.digest,
        handler: row.handler,
        claimedDigest: body.claimedDigest,
        sessionState: session.state,
        sessionGeneration: session.generation,
        currentGeneration: current?.generation ?? session.generation,
        sessionEpoch: session.auth_epoch,
        currentEpoch: current?.authEpoch ?? session.auth_epoch,
      });
      if (decision.code === "STALE_AUTHORITY") {
        await db.query(
          `UPDATE oversight_sessions SET state = 'terminated', terminated_reason = 'stale_authority', updated_at = now(), version = version + 1 WHERE id = $1`,
          [id],
        );
        return { status: 409 as const, body: errorBody(decision.code, decision.message) };
      }
      if (decision.code === "DIGEST_MISMATCH") {
        return { status: 409 as const, body: errorBody(decision.code, decision.message) };
      }
      if (row.operation_key === "checkpoint.request" && row.job_id) {
        return { status: 202 as const, body: { outcome: "pending", stepId: row.id, code: "ACCEPTED", duplicate: true, jobState: "queued", mailVerified: false } };
      }
      if (decision.outcome === "pending") {
        if (row.operation_key === "checkpoint.request" && row.requested_key && session.organization_id && session.deployment_id) {
          const jobId = randomUUID();
          await db.query(
            `INSERT INTO jobs (id, organization_id, deployment_id, generation, kind, state, checkpoint, lease_owner, lease_expires_at, fencing_token)
             VALUES ($1, $2, $3, $4, 'oversight.checkpoint', 'queued', $5::jsonb, 'oversight', now() + interval '120 seconds', 1)`,
            [jobId, session.organization_id, session.deployment_id, session.generation, JSON.stringify({
              operationKey: row.requested_key,
              version: row.requested_version,
              handler: row.requested_handler,
              digest: row.requested_digest,
              installerStarted: false,
            })],
          );
          await db.query("UPDATE operation_steps SET job_id = $2 WHERE id = $1", [row.id, jobId]);
          return { status: 202 as const, body: { outcome: "pending", stepId: row.id, code: "ACCEPTED", jobId, jobState: "queued", mailVerified: false } };
        }
        return { status: 202 as const, body: { outcome: "pending", stepId: row.id, code: decision.code, mailVerified: false } };
      }
      const evidence = await finishReadStep(db, session, row);
      await db.query(
        `UPDATE operation_steps SET state = 'succeeded', code = $2, message = $3, completed_at = now() WHERE id = $1 AND state = 'pending'`,
        [row.id, evidence.code, evidence.message],
      );
      return { status: 200 as const, body: { outcome: "succeeded", stepId: row.id, code: evidence.code, ...evidence.body, mailVerified: false } };
    });
    return reply.code(created.status).send({ ...created.body, requestId: request.id });
  });

  app.post("/internal/agent-runs/:id/usage", async (request, reply) => {
    requireScheduler(request, ctx.schedulerToken);
    const { id } = request.params as { id: string };
    const body = usageReportSchema.parse(request.body);
    const created = await ctx.withSystem("inventory_worker", async (db) => {
      const session = await loadSession(db, id);
      if (!session) throw new HttpError(404, "NOT_FOUND", "The oversight session was not found.");
      const usage = recordUsage(body.tokens);
      if (usage.provenance === "reported") {
        await db.query(
          `UPDATE oversight_sessions SET usage_tokens = $2, usage_provenance = 'reported', updated_at = now(), version = version + 1 WHERE id = $1`,
          [id, usage.tokens],
        );
      }
      const current = usage.provenance === "reported" ? usage : { tokens: session.usage_tokens, provenance: session.usage_provenance };
      return { status: 200 as const, body: { usageTokens: current.tokens, usageProvenance: current.provenance } };
    });
    return reply.code(created.status).send({ ...created.body, requestId: request.id });
  });

  app.post("/internal/agent-runs/:id/invocation", async (request, reply) => {
    requireScheduler(request, ctx.schedulerToken);
    const { id } = request.params as { id: string };
    emptyObjectSchema.parse(request.body ?? {});
    const created = await ctx.withSystem("inventory_worker", async (db) => {
      const session = await loadSession(db, id);
      if (!session) throw new HttpError(404, "NOT_FOUND", "The oversight session was not found.");
      if (!invocationAllowed(session.invocations)) {
        if (session.organization_id) await openAction(db, session.organization_id, session.deployment_id, "agent.invocations", "The failing checkpoint needs an operator.");
        return { status: 429 as const, body: errorBody("BUDGET_EXHAUSTED", "The oversight run reached its invocation budget.") };
      }
      const invocations = session.invocations + 1;
      await db.query(
        "UPDATE oversight_sessions SET invocations = $2, updated_at = now(), version = version + 1 WHERE id = $1",
        [id, invocations],
      );
      return { status: 202 as const, body: { invocations, modelCalled: false } };
    });
    return reply.code(created.status).send({ ...created.body, requestId: request.id });
  });

  app.post("/internal/health/observe", async (request, reply) => {
    requireScheduler(request, ctx.schedulerToken);
    const body = healthObserveSchema.parse(request.body);
    if (body.probe === "disk" && body.diskPercent == null) {
      throw new HttpError(400, "VALIDATION", "A disk observation needs a percent.");
    }
    const created = await ctx.withSystem("inventory_worker", async (db) => {
      const deployment = await db.query<{ organization_id: string }>(
        "SELECT organization_id FROM deployments WHERE id = $1 AND lifecycle_state <> 'deleted'",
        [body.deploymentId],
      );
      const owner = deployment.rows[0];
      if (!owner) throw new HttpError(404, "NOT_FOUND", "The deployment was not found.");
      await db.query(
        `INSERT INTO health_observations (id, organization_id, deployment_id, probe, state, disk_percent, observed_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        [randomUUID(), owner.organization_id, body.deploymentId, body.probe, body.state, body.diskPercent ?? null, body.observedAt],
      );
      if ((NETWORK_PROBES as readonly string[]).includes(body.probe) && (body.state === "pass" || body.state === "fail")) {
        await recordIncident(db, owner.organization_id, body.deploymentId, body.probe, body.state);
      }
      if (body.probe === "disk" && (body.diskPercent ?? 0) >= 90) {
        await openAction(db, owner.organization_id, body.deploymentId, "capacity.disk", "Disk use needs an operator. Mail is not deleted.");
      }
      const view = await healthView(db, owner.organization_id, body.deploymentId);
      await db.query(
        "UPDATE deployments SET health_state = $2, version = version + 1, updated_at = now() WHERE id = $1",
        [body.deploymentId, view.health],
      );
      return { status: 200 as const, body: { ...view, mailVerified: false, observationRecorded: true } };
    });
    return reply.code(created.status).send({ ...created.body, requestId: request.id });
  });

  app.post("/internal/recovery/enter", async (request, reply) => {
    requireScheduler(request, ctx.schedulerToken);
    const body = recoveryEnterSchema.parse(request.body);
    const created = await ctx.withSystem("inventory_worker", async (db) => {
      await db.query(
        `UPDATE control_plane_state
         SET mode = 'recovery', reason = $1, entered_at = now(), version = version + 1, updated_at = now()
         WHERE id = 1`,
        [body.reason],
      );
      const invalidated = await db.query(
        `UPDATE approvals
         SET state = 'invalidated', updated_at = now(), version = version + 1
         WHERE state IN ('pending', 'approved') AND in_flight = false`,
      );
      return {
        status: 200 as const,
        body: { ...recoveryPosture(), invalidated: invalidated.rowCount ?? 0, resumed: false, replayed: 0 },
      };
    });
    return reply.code(created.status).send({ ...created.body, requestId: request.id });
  });

  app.post("/internal/recovery/reconcile", async (request, reply) => {
    requireScheduler(request, ctx.schedulerToken);
    emptyObjectSchema.parse(request.body ?? {});
    const created = await ctx.withSystem("inventory_worker", async (db) => {
      const mode = await db.query<{ mode: string }>("SELECT mode FROM control_plane_state WHERE id = 1");
      return {
        status: 200 as const,
        body: {
          mode: mode.rows[0]?.mode ?? "recovery",
          resumed: false,
          replayed: 0,
          mutationsPaused: mode.rows[0]?.mode === "recovery",
          localMailPolicy: "unchanged",
        },
      };
    });
    return reply.code(created.status).send({ ...created.body, requestId: request.id });
  });

  app.post("/internal/recovery/watchdog", async (request, reply) => {
    requireScheduler(request, ctx.schedulerToken);
    const body = watchdogSchema.parse(request.body);
    const decision = watchdogThaw({
      frozenAtMs: new Date(body.frozenAt).getTime(),
      nowMs: Date.now(),
      thawAck: body.thawAck,
      journalWritable: body.journalWritable,
    });
    const created = await ctx.withSystem("inventory_worker", async (db) => {
      if (decision.thaw) {
        const dedupe = `watchdog:${body.frozenAt}`;
        const existing = await db.query("SELECT id FROM outbox_events WHERE dedupe_key = $1", [dedupe]);
        if (!existing.rows[0]) {
          await db.query(
            `INSERT INTO outbox_events (id, event_type, aggregate_id, payload, dedupe_key)
             VALUES ($1, 'watchdog.thaw', $2, $3::jsonb, $4)`,
            [randomUUID(), randomUUID(), JSON.stringify({ waitedForJournal: false }), dedupe],
          );
        }
      }
      return { status: 200 as const, body: { ...decision, hostCommandIssued: false } };
    });
    return reply.code(created.status).send({ ...created.body, requestId: request.id });
  });

  app.post("/internal/provider-faults", async (request, reply) => {
    requireScheduler(request, ctx.schedulerToken);
    const body = providerFaultSchema.parse(request.body);
    const decision = nextRetry({
      status: body.status,
      retryAfterMs: body.retryAfterMs,
      attempt: body.attempt,
      accepted: body.accepted,
      random: 0.5,
    });
    const created = await ctx.withSystem("inventory_worker", async (db) => {
      await db.query(
        `INSERT INTO provider_attempts (id, organization_id, operation_key, attempt, status, accepted, reconciled, next_delay_ms, action)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
        [randomUUID(), body.organizationId, body.operationKey, body.attempt, body.status, body.accepted, decision.reconcile, decision.delayMs, decision.action],
      );
      if (body.accepted) {
        const dedupe = `provider-fault:${body.organizationId}:${body.operationKey}:${body.attempt}`;
        const existing = await db.query("SELECT id FROM outbox_events WHERE dedupe_key = $1", [dedupe]);
        if (!existing.rows[0]) {
          await db.query(
            `INSERT INTO outbox_events (id, event_type, aggregate_id, payload, dedupe_key)
             VALUES ($1, 'provider.fault', $2, $3::jsonb, $4)`,
            [randomUUID(), body.organizationId, JSON.stringify({ operationKey: body.operationKey, attempt: body.attempt, reconcile: decision.reconcile }), dedupe],
          );
        }
      }
      return { status: 202 as const, body: { ...decision, succeeded: false, modelInvocations: 0 } };
    });
    return reply.code(created.status).send({ ...created.body, requestId: request.id });
  });
}

function requireScheduler(request: FastifyRequest, expected: string | undefined): void {
  if (!expected) throw new HttpError(503, "SCHEDULER_UNAVAILABLE", "The scheduler identity is not configured.", true);
  const header = request.headers["x-bearportal-scheduler"];
  if (!schedulerAuthorized(typeof header === "string" ? header : undefined, expected)) {
    throw new HttpError(401, "UNAUTHENTICATED", "The scheduler identity was rejected.");
  }
}

function schedulerAuthorized(header: string | undefined, expected: string | undefined): boolean {
  if (!expected || !header) return false;
  const left = Buffer.from(header);
  const right = Buffer.from(expected);
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}

function assertWriter(ctx: OversightContext, actor: Actor): void {
  if (!actor.roles.includes("platform_administrator") && !actor.roles.includes("infrastructure_operator")) {
    throw new HttpError(403, "FORBIDDEN", "An infrastructure operator is required.");
  }
  ctx.requireVerified(actor);
  ctx.requireMfa(actor);
}

function errorBody(code: string, message: string, retryable = false, requiredActionId: string | null = null): ErrorBody {
  return { error: { code, message, retryable, requiredActionId } };
}

function forbiddenAction(code: string): boolean {
  return code.startsWith("cloud.") || code.startsWith("iam.") || code.startsWith("shell") || code.includes("firewall") || code.includes("disk.resize") || code === "dns.write" || code === "mail.read_body" || code === "plan.assign" || code === "allocation.override";
}

function commandFields(value: unknown, found = new Set<string>()): Set<string> {
  if (!value || typeof value !== "object") return found;
  if (Array.isArray(value)) {
    for (const item of value) commandFields(item, found);
    return found;
  }
  for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
    if (COMMAND_FIELDS.has(key)) found.add(key);
    commandFields(item, found);
  }
  return found;
}

function sessionResponse(sessionId: string, scope: string, generation: number, authEpoch: number): Record<string, unknown> {
  return {
    sessionId,
    scope,
    generation,
    authEpoch,
    harness: "unavailable",
    usageTokens: null,
    usageProvenance: "unknown",
    modelCalled: false,
  };
}

async function insertSession(db: Db, input: {
  id: string;
  organizationId: string | null;
  deploymentId: string | null;
  serverId: string | null;
  scope: "tenant" | "inventory";
  generation: number;
  authEpoch: number;
  lease: string;
}): Promise<void> {
  await db.query(
    `INSERT INTO oversight_sessions (
       id, organization_id, deployment_id, server_id, scope, generation, auth_epoch, lease_fencing_token, state
     ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'open')`,
    [input.id, input.organizationId, input.deploymentId, input.serverId, input.scope, input.generation, input.authEpoch, input.lease],
  );
}

async function loadSession(db: Db, id: string): Promise<SessionRow | null> {
  const row = await db.query<SessionRow>(
    `SELECT id, organization_id, deployment_id, server_id, scope, generation, auth_epoch, lease_fencing_token,
            state, tool_requests, invocations, usage_tokens, usage_provenance, started_at
     FROM oversight_sessions WHERE id = $1`,
    [id],
  );
  return row.rows[0] ?? null;
}

async function currentHost(db: Db, organizationId: string): Promise<{ serverId: string; authEpoch: number; assignmentId: string } | null> {
  const row = await db.query<{ server_id: string; auth_epoch: number; assignment_id: string }>(
    `SELECT a.server_id, s.auth_epoch, a.id AS assignment_id
     FROM server_assignments a
     JOIN servers s ON s.id = a.server_id
     WHERE a.organization_id = $1 AND a.released_at IS NULL
     LIMIT 1`,
    [organizationId],
  );
  const host = row.rows[0];
  if (!host) return null;
  return { serverId: host.server_id, authEpoch: host.auth_epoch, assignmentId: host.assignment_id };
}

async function authorityNow(db: Db, session: SessionRow): Promise<{ generation: number; authEpoch: number } | null> {
  if (session.scope === "inventory") {
    if (!session.server_id) return null;
    const server = await db.query<{ auth_epoch: number }>("SELECT auth_epoch FROM servers WHERE id = $1", [session.server_id]);
    if (!server.rows[0]) return null;
    return { generation: 0, authEpoch: server.rows[0].auth_epoch };
  }
  if (!session.deployment_id || !session.organization_id) return null;
  const deployment = await db.query<{ generation: number }>(
    "SELECT generation FROM deployments WHERE id = $1 AND organization_id = $2",
    [session.deployment_id, session.organization_id],
  );
  if (!deployment.rows[0]) return null;
  const host = await currentHost(db, session.organization_id);
  return { generation: deployment.rows[0].generation, authEpoch: host?.authEpoch ?? 0 };
}

function toAuthority(session: SessionRow): SessionAuthority {
  return {
    sessionId: session.id,
    scope: session.scope,
    organizationId: session.organization_id,
    deploymentId: session.deployment_id,
    serverId: session.server_id,
    assignmentId: null,
    generation: session.generation,
    authEpoch: session.auth_epoch,
    leaseFencingToken: session.lease_fencing_token,
    toolRequests: session.tool_requests,
    invocations: session.invocations,
    startedAtMs: new Date(session.started_at).getTime(),
    state: session.state,
  };
}

function toContext(session: SessionRow, current: { generation: number; authEpoch: number } | null): SessionAuthority extends never ? never : Parameters<typeof requestOperation>[0]["context"] {
  if (session.scope === "inventory") {
    return {
      scope: "inventory",
      serverId: session.server_id ?? "",
      authEpoch: current?.authEpoch ?? session.auth_epoch,
      generation: current?.generation ?? 0,
      leaseFencingToken: session.lease_fencing_token,
      actor: "oversight",
    };
  }
  return {
    scope: "tenant",
    organizationId: session.organization_id ?? "",
    deploymentId: session.deployment_id ?? "",
    serverId: session.server_id,
    assignmentId: null,
    generation: current?.generation ?? session.generation,
    authEpoch: current?.authEpoch ?? session.auth_epoch,
    leaseFencingToken: session.lease_fencing_token,
    actor: "oversight",
  };
}

function decisionStepId(session: SessionRow, tool: string, version: string | undefined, args: Record<string, unknown>): string | null {
  const preview = requestOperation({
    tool,
    version,
    arguments: args,
    session: toAuthority(session),
    context: toContext(session, { generation: session.generation, authEpoch: session.auth_epoch }),
    recovery: false,
    nowMs: new Date(session.started_at).getTime(),
  });
  return preview.stepId;
}

function pendingBody(decision: GatewayDecision): Record<string, unknown> {
  return {
    outcome: "pending",
    stepId: decision.stepId,
    operationKey: decision.operationKey,
    version: decision.version,
    handler: decision.handler,
    digest: decision.digest,
    requestedKey: decision.requested?.key ?? null,
    requestedVersion: decision.requested?.version ?? null,
    requestedDigest: decision.requested?.digest ?? null,
    code: decision.code,
    duplicate: false,
    productionInvoked: decision.productionInvoked,
    mailVerified: false,
  };
}

async function applyDecision(db: Db, session: SessionRow, decision: GatewayDecision): Promise<void> {
  await db.query(
    `UPDATE oversight_sessions
     SET tool_requests = $2,
         state = $3,
         terminated_reason = $4,
         updated_at = now(),
         version = version + 1
     WHERE id = $1`,
    [session.id, decision.toolRequests, decision.terminate ? "terminated" : session.state, decision.terminate ? decision.code : null],
  );
  if (decision.outcome !== "pending" || !decision.stepId || !decision.operationKey || !decision.version || !decision.handler || !decision.digest) return;
  await db.query(
    `INSERT INTO operation_steps (
       id, session_id, organization_id, operation_key, operation_version, handler, digest,
       requested_key, requested_version, requested_handler, requested_digest, arguments, state, code, message
     ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::jsonb, 'pending', $13, $14)`,
    [
      decision.stepId,
      session.id,
      session.organization_id,
      decision.operationKey,
      decision.version,
      decision.handler,
      decision.digest,
      decision.requested?.key ?? null,
      decision.requested?.version ?? null,
      decision.requested?.handler ?? null,
      decision.requested?.digest ?? null,
      JSON.stringify(decision.arguments ?? {}),
      decision.code,
      decision.message,
    ],
  );
}

async function finishReadStep(db: Db, session: SessionRow, step: {
  operation_key: string;
  arguments: Record<string, unknown>;
  organization_id: string | null;
}): Promise<{ code: string; message: string; body: Record<string, unknown> }> {
  if (step.operation_key === "deployment.read_state" && session.deployment_id && session.organization_id) {
    const row = await db.query<{ health_state: string; lifecycle_state: string; desired_state: string; mail_verified: boolean }>(
      `SELECT health_state, lifecycle_state, desired_state, mail_verified
       FROM deployments WHERE id = $1 AND organization_id = $2`,
      [session.deployment_id, session.organization_id],
    );
    const deployment = row.rows[0];
    return {
      code: "VERIFIED",
      message: "Redacted deployment state was read.",
      body: {
        healthState: deployment?.health_state ?? "unknown",
        lifecycleState: deployment?.lifecycle_state ?? null,
        desiredState: deployment?.desired_state ?? null,
        deliveryProven: false,
      },
    };
  }
  if (step.operation_key === "repair.propose" && session.organization_id && session.deployment_id) {
    const repairType = String(step.arguments.repairType ?? "health");
    const evidenceIds = Array.isArray(step.arguments.evidenceIds) ? step.arguments.evidenceIds : [];
    const planHash = createHash("sha256").update(JSON.stringify({ repairType, deploymentId: session.deployment_id, generation: session.generation, evidenceIds })).digest("hex");
    const approvalId = randomUUID();
    await db.query(
      `INSERT INTO approvals (
         id, organization_id, deployment_id, action_code, plan_hash, generation, resource_id, dns_fingerprint, state, expires_at, executed
       ) VALUES ($1, $2, $3, $4, $5, $6, $7, 'unobserved', 'pending', now() + interval '30 minutes', false)`,
      [approvalId, session.organization_id, session.deployment_id, `repair.${repairType}`, planHash, session.generation, session.deployment_id],
    );
    return { code: "PLAN_RECORDED", message: "An immutable repair plan was recorded.", body: { approvalId, planHash, executed: false, dnsWrite: false, deliveryProven: false } };
  }
  if (step.operation_key === "human_action.request" && session.organization_id) {
    const actionCode = String(step.arguments.actionCode ?? "operator.review");
    const actionId = await openAction(db, session.organization_id, session.deployment_id, actionCode, "An operator needs to continue this step.");
    return { code: "HUMAN_REQUIRED", message: "A human action was recorded.", body: { requiredActionId: actionId, modelInvocations: 0, deliveryProven: false } };
  }
  if (step.operation_key === "diagnosis.record" && session.organization_id) {
    const diagnosisId = randomUUID();
    await db.query(
      `INSERT INTO diagnoses (id, organization_id, deployment_id, session_id, summary, evidence_ids)
       VALUES ($1, $2, $3, $4, $5, $6::jsonb)`,
      [diagnosisId, session.organization_id, session.deployment_id, session.id, String(step.arguments.summary ?? ""), JSON.stringify(step.arguments.evidenceIds ?? [])],
    );
    return { code: "DIAGNOSIS_RECORDED", message: "The diagnosis was stored as data.", body: { diagnosisId, deliveryProven: false } };
  }
  if (step.operation_key === "assignment.reconcile") {
    return { code: "ip.operator_required", message: "BearPortal does not invent an address.", body: { installerStarted: false, dnsWrite: false, inventedIp: false, deliveryProven: false } };
  }
  if (step.operation_key === "dns.inspect") {
    return { code: "DNS_OBSERVED", message: "DNS text was stored as data. BearPortal did not write DNS.", body: { dnsWrite: false, deliveryProven: false } };
  }
  return { code: "VERIFIED", message: "Live provider validation is not claimed.", body: { providerCalled: false, deliveryProven: false } };
}

async function sessionView(db: Db, session: SessionRow): Promise<Record<string, unknown>> {
  const steps = await db.query(
    `SELECT id, operation_key, operation_version, handler, digest, state, code, arguments, requested_key, requested_digest
     FROM operation_steps WHERE session_id = $1 ORDER BY created_at`,
    [session.id],
  );
  return {
    sessionId: session.id,
    scope: session.scope,
    state: session.state,
    generation: session.generation,
    authEpoch: session.auth_epoch,
    toolRequests: session.tool_requests,
    invocations: session.invocations,
    usageTokens: session.usage_tokens,
    usageProvenance: session.usage_provenance,
    harness: "unavailable",
    steps: steps.rows,
  };
}

async function healthView(db: Db, organizationId: string, deploymentId: string): Promise<{
  health: string;
  reasons: string[];
  deliveryProven: boolean;
  acceptedMailIsDelivery: false;
  diskLevel: string;
  incidents: Array<{ probe: string; state: string }>;
  notifications: number;
}> {
  const observations = await db.query<{ probe: string; state: HealthObservation["state"]; observed_at: Date; disk_percent: number | null }>(
    `SELECT DISTINCT ON (probe) probe, state, observed_at, disk_percent
     FROM health_observations
     WHERE organization_id = $1 AND deployment_id = $2
     ORDER BY probe, observed_at DESC`,
    [organizationId, deploymentId],
  );
  const derived = deriveHealth(observations.rows.map((row) => ({
    probe: row.probe,
    state: row.state,
    observedAt: new Date(row.observed_at).getTime(),
    diskPercent: row.disk_percent,
  })), Date.now());
  const incidents = await db.query<{ probe: string; state: string }>(
    "SELECT probe, state FROM incidents WHERE organization_id = $1 AND deployment_id = $2 ORDER BY probe",
    [organizationId, deploymentId],
  );
  const notifications = await db.query<{ n: string }>(
    "SELECT count(*)::text AS n FROM notifications WHERE organization_id = $1 AND deployment_id = $2",
    [organizationId, deploymentId],
  );
  return {
    health: derived.health,
    reasons: derived.reasons,
    deliveryProven: derived.deliveryProven,
    acceptedMailIsDelivery: false,
    diskLevel: derived.diskLevel,
    incidents: incidents.rows,
    notifications: Number(notifications.rows[0]?.n ?? 0),
  };
}

async function recordIncident(db: Db, organizationId: string, deploymentId: string, probe: string, result: "pass" | "fail"): Promise<void> {
  const existing = await db.query<{ id: string; state: string; consecutive_failures: number; consecutive_successes: number }>(
    "SELECT id, state, consecutive_failures, consecutive_successes FROM incidents WHERE organization_id = $1 AND deployment_id = $2 AND probe = $3",
    [organizationId, deploymentId, probe],
  );
  const current = existing.rows[0];
  const next = applyProbeResult({
    consecutiveFailures: current?.consecutive_failures ?? 0,
    consecutiveSuccesses: current?.consecutive_successes ?? 0,
    open: current?.state === "open",
  }, result);
  const state = next.open ? "open" : "closed";
  let incidentId = current?.id;
  if (!current) {
    incidentId = randomUUID();
    await db.query(
      `INSERT INTO incidents (id, organization_id, deployment_id, probe, state, consecutive_failures, consecutive_successes, opened_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, CASE WHEN $5 = 'open' THEN now() ELSE NULL END)`,
      [incidentId, organizationId, deploymentId, probe, state, next.consecutiveFailures, next.consecutiveSuccesses],
    );
  } else {
    await db.query(
      `UPDATE incidents
       SET state = $2, consecutive_failures = $3, consecutive_successes = $4,
           opened_at = CASE WHEN $2 = 'open' AND opened_at IS NULL THEN now() ELSE opened_at END,
           closed_at = CASE WHEN $2 = 'closed' THEN now() ELSE NULL END,
           updated_at = now(), version = version + 1
       WHERE id = $1`,
      [current.id, state, next.consecutiveFailures, next.consecutiveSuccesses],
    );
  }
  if (!next.notify || !incidentId) return;
  const dedupe = `${deploymentId}:${probe}:${next.notify}`;
  const prior = await db.query("SELECT id FROM notifications WHERE dedupe_key = $1", [dedupe]);
  if (prior.rows[0]) return;
  await db.query(
    `INSERT INTO notifications (id, organization_id, deployment_id, incident_id, kind, dedupe_key, recipient_source)
     VALUES ($1, $2, $3, $4, $5, $6, 'owner_recovery')`,
    [randomUUID(), organizationId, deploymentId, incidentId, next.notify, dedupe],
  );
}

async function openAction(db: Db, organizationId: string, deploymentId: string | null, code: string, instructions: string): Promise<string> {
  const existing = await db.query<{ id: string }>(
    `SELECT id FROM required_actions
     WHERE state = 'open' AND code = $1 AND organization_id IS NOT DISTINCT FROM $2
     LIMIT 1`,
    [code, organizationId],
  );
  if (existing.rows[0]) return existing.rows[0].id;
  const id = randomUUID();
  await db.query(
    `INSERT INTO required_actions (id, scope, organization_id, deployment_id, audience, code, instructions, state)
     VALUES ($1, 'tenant', $2, $3, 'operator', $4, $5, 'open')`,
    [id, organizationId, deploymentId, code, instructions],
  );
  return id;
}
