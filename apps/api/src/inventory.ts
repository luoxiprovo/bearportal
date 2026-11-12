import { createHash, createPublicKey, randomBytes, randomUUID, timingSafeEqual, verify } from "node:crypto";
import type { FastifyInstance, FastifyRequest } from "fastify";
import { DomainError, normalizeDomain, recoveryIsOutsideDomain } from "../../../packages/domain/src/domain.ts";
import { requireOperation } from "../../../packages/operations/src/registry.ts";
import {
  authenticateBrevoDomain,
  BrevoRequestError,
  type BrevoDnsRecord,
  type BrevoDomainCheck,
  type BrevoPublishRecord,
  type OperatorBrevo,
  type RelayChecker,
} from "../../../packages/providers/brevo/src/index.ts";
import { assessZoneRead, detectDnsProvider, publishBrevoRecords, type DetectedDnsProvider, type DnsCredentialMaterial, type ZoneReader } from "../../../packages/providers/dns/src/index.ts";
import { SecretStore } from "../../../packages/secrets/src/store.ts";
import { assertPublicUnicastIpv4, AddressError } from "../../../packages/servers/src/address.ts";
import type { SshProbeOutcome } from "../../../packages/servers/src/ssh-probe.ts";
import { allocateProfile, readCustomerServer, type Queryable } from "../../../packages/servers/src/allocate.ts";
import { parseCommand } from "../../../packages/servers/src/commands.ts";
import { readinessFailures, type HostReport } from "../../../packages/servers/src/readiness.ts";
import { heartbeatMessage } from "../../../packages/servers/src/signature.ts";
import {
  assignPlanSchema,
  assignRelaySchema,
  cancelOnboardingSchema,
  confirmIdentitySchema,
  emptyObjectSchema,
  heartbeatSchema,
  hostCommandSchema,
  hostEnrollSchema,
  ipChangeSchema,
  quarantineSchema,
  recoveryBindingSchema,
  relayConnectionCreateSchema,
  releaseReservationSchema,
  serverCreateSchema,
  versionedSchema,
} from "../../../packages/contracts/src/index.ts";
import { enqueueOnboarding, requireSetupConsent } from "./onboarding-queue.ts";
import { HttpError } from "./errors.ts";
import { mutationsPaused } from "./oversight.ts";
import {
  renderBrevoAccountResult,
  renderBrevoDomainResult,
  renderDnsCredentialResult,
  type BrevoAccountResultView,
  type BrevoDomainResultView,
  type DnsCredentialResultView,
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

export type InventoryContext = {
  billingRequired?: boolean;
  requireSubscription?: (db: Queryable, organizationId: string) => Promise<void>;
  withActor: <T>(request: FastifyRequest, mode: "customer" | "operator", fn: (db: Db, actor: Actor) => Promise<T>) => Promise<T>;
  withSystem: <T>(actor: "allocator" | "inventory_worker", fn: (db: Db) => Promise<T>) => Promise<T>;
  demandIdempotency: (request: FastifyRequest) => string;
  requireVerified: (actor: Actor) => void;
  requireMfa: (actor: Actor) => void;
  consumeLimit: (actorId: string, bucket: string, limit: number, windowMs: number) => void;
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
  setActor: (db: Db, actor: string) => Promise<void>;
  secrets: SecretStore;
  zoneReader: ZoneReader;
  relayChecker: RelayChecker;
  operatorBrevo: OperatorBrevo;
  lookupNameservers: (domain: string) => Promise<string[]>;
  publishBrevoRecords: typeof publishBrevoRecords;
  onboardingRequested?: () => void;
  sshProbe?: (publicIpv4: string) => Promise<SshProbeOutcome>;
  schedulerToken?: string;
  addressRepair?: (
    db: Db,
    input: { serverId: string; organizationId: string; publicIpv4: string },
  ) => Promise<{ jobId: string; installerStarted: boolean } | null>;
};

const ATTESTATIONS = ["osPrepared", "storagePrepared", "firewallAttested", "cleanHost", "externalBackup"] as const;

export function registerInventoryRoutes(app: FastifyInstance, ctx: InventoryContext): void {
  function assertWriter(actor: Actor): void {
    if (!actor.roles.includes("platform_administrator") && !actor.roles.includes("infrastructure_operator")) {
      throw new HttpError(403, "FORBIDDEN", "An infrastructure operator is required.");
    }
    ctx.requireVerified(actor);
    ctx.requireMfa(actor);
  }

  function restoreActor(actor: Actor): string {
    return actor.roles.includes("platform_administrator") ? "platform_administrator" : "infrastructure_operator";
  }

  async function recordSshValidation(
    db: Db,
    request: FastifyRequest,
    actor: Actor,
    serverId: string,
    outcome: SshProbeOutcome,
  ): Promise<{ serverId: string; state: string; version: number; validation: { ok: boolean; failures: string[] } }> {
    const state = outcome.ok ? "available" : "pending_validation";
    const report = {
      ...(outcome.report ?? { source: "ssh", reachable: false }),
      failures: outcome.failures,
    };
    const updated = await db.query<{ version: number; state: string }>(
      `UPDATE servers
       SET state = $2,
           available_since = CASE WHEN $2 = 'available' THEN coalesce(available_since, now()) ELSE NULL END,
           validated_at = CASE WHEN $2 = 'available' THEN now() ELSE NULL END,
           readiness_report = $3::jsonb,
           version = version + 1,
           updated_at = now()
       WHERE id = $1 AND state IN ('pending_validation', 'available') AND tenant_tainted_at IS NULL
       RETURNING version, state`,
      [serverId, state, JSON.stringify(report)],
    );
    const row = updated.rows[0];
    if (!row) throw new HttpError(409, "INVALID_STATE", "This server cannot be validated from its current state.");
    const jobId = randomUUID();
    await db.query(
      `INSERT INTO inventory_jobs (id, server_id, kind, state, result)
       VALUES ($1, $2, 'readiness', $3, $4::jsonb)`,
      [jobId, serverId, outcome.ok ? "succeeded" : "failed", JSON.stringify({ failures: outcome.failures })],
    );
    await ctx.audit(db, request, actor.userId, null, "server.validate", serverId, {
      ok: outcome.ok,
      failures: outcome.failures,
      inventoryJobId: jobId,
    });
    if (outcome.ok) {
      await ctx.setActor(db, "allocator");
      const allocation = await allocateProfile(db, "e2-micro", 100);
      await ctx.setActor(db, restoreActor(actor));
      for (const item of allocation.assigned) {
        await ctx.audit(db, request, actor.userId, item.organizationId, "server.allocate", item.serverId, { assignmentId: item.assignmentId });
      }
    }
    const after = await db.query<{ version: number; state: string }>(
      "SELECT version, state FROM servers WHERE id = $1",
      [serverId],
    );
    const finalRow = after.rows[0] ?? row;
    return {
      serverId,
      state: finalRow.state,
      version: finalRow.version,
      validation: { ok: outcome.ok, failures: outcome.failures },
    };
  }

  app.get("/v1/organization/server", async (request) => {
    return ctx.withActor(request, "customer", async (db, actor) => {
      if (!actor.organizationId) return { allocationState: null, waitReason: null, server: null, organizationVersion: null, requestId: request.id };
      const view = await organizationServer(db, actor.organizationId);
      return { ...view, requestId: request.id };
    });
  });

  app.post("/v1/organization/cancel-onboarding", async (request, reply) => {
    const idempotencyKey = ctx.demandIdempotency(request);
    const body = cancelOnboardingSchema.parse(request.body);
    const created = await ctx.withActor(request, "customer", async (db, actor) => {
      ctx.requireVerified(actor);
      const fresh = actor.authTime > 0 && Math.floor(Date.now() / 1000) - actor.authTime <= 15 * 60;
      if (!fresh) throw new HttpError(403, "RECENT_AUTH_REQUIRED", "Sign in again before cancelling onboarding.");
      if (!actor.organizationId) throw new HttpError(422, "ORGANIZATION_REQUIRED", "Create an organization first.");
      const route = "POST /v1/organization/cancel-onboarding";
      const replayed = await ctx.replay(db, actor.userId, route, idempotencyKey, body);
      if (replayed) return replayed;
      const org = await db.query<{ version: number }>("SELECT version FROM organizations WHERE id = $1", [actor.organizationId]);
      if (!org.rows[0] || org.rows[0].version !== body.expectedVersion) {
        throw new HttpError(409, "VERSION_CONFLICT", "The organization changed.");
      }
      const allocation = await db.query<{ id: string; state: string }>(
        `SELECT id, state FROM allocation_requests WHERE organization_id = $1 AND state <> 'cancelled' ORDER BY created_at DESC LIMIT 1`,
        [actor.organizationId],
      );
      const current = allocation.rows[0];
      if (!current) throw new HttpError(422, "ALLOCATION_REQUIRED", "There is no onboarding reservation to cancel.");
      const server = await readCustomerServer(db, actor.organizationId);
      let outcome = "cancelled";
      if (server) {
        const tainted = await db.query<{ tenant_tainted_at: Date | null }>(
          "SELECT tenant_tainted_at FROM servers WHERE id = $1",
          [server.id],
        );
        if (tainted.rows[0]?.tenant_tainted_at) {
          throw new HttpError(409, "TENANT_ACTIVE", "Tenant commands already exist. Cancel the deployment instead.");
        }
        await db.query(
          `UPDATE allocation_requests
           SET cancellation_requested_at = coalesce(cancellation_requested_at, now()), updated_at = now(), version = version + 1
           WHERE id = $1`,
          [current.id],
        );
        outcome = "cancellation_requested";
      } else {
        await db.query(
          `UPDATE allocation_requests
           SET state = 'cancelled', cancelled_at = now(), updated_at = now(), version = version + 1
           WHERE id = $1 AND state = 'waiting_for_server'`,
          [current.id],
        );
      }
      await db.query("UPDATE organizations SET version = version + 1, updated_at = now() WHERE id = $1", [actor.organizationId]);
      await ctx.audit(db, request, actor.userId, actor.organizationId, "organization.cancel_onboarding", actor.organizationId, { outcome });
      const response = { organizationId: actor.organizationId, state: outcome };
      await ctx.remember(db, actor.userId, route, idempotencyKey, body, 200, response);
      return { status: 200 as const, body: response };
    });
    return reply.code(created.status).send({ ...created.body, requestId: request.id });
  });

  app.post("/v1/domains/:id/verify", async (request, reply) => {
    const idempotencyKey = ctx.demandIdempotency(request);
    const { id } = request.params as { id: string };
    const body = emptyObjectSchema.parse(request.body ?? {});
    const created = await ctx.withActor(request, "customer", async (db, actor) => {
      ctx.requireVerified(actor);
      if (!actor.organizationId) throw new HttpError(422, "ORGANIZATION_REQUIRED", "Create an organization first.");
      const route = "POST /v1/domains/:id/verify";
      const replayed = await ctx.replay(db, actor.userId, route, idempotencyKey, { id, ...body });
      if (replayed) return replayed;
      ctx.consumeLimit(actor.userId, "domain", 10, 60 * 60 * 1000);
      const response = await proveControl(ctx, db, request, actor, id, null);
      await ctx.remember(db, actor.userId, route, idempotencyKey, { id, ...body }, response.status, response.body);
      return response;
    });
    return reply.code(created.status).send({ ...created.body, requestId: request.id });
  });

  app.post("/v1/dns-connections/:id/validate", async (request, reply) => {
    const idempotencyKey = ctx.demandIdempotency(request);
    const { id } = request.params as { id: string };
    const body = emptyObjectSchema.parse(request.body ?? {});
    const created = await ctx.withActor(request, "customer", async (db, actor) => {
      ctx.requireVerified(actor);
      if (!actor.organizationId) throw new HttpError(422, "ORGANIZATION_REQUIRED", "Create an organization first.");
      const route = "POST /v1/dns-connections/:id/validate";
      const replayed = await ctx.replay(db, actor.userId, route, idempotencyKey, { id, ...body });
      if (replayed) return replayed;
      ctx.consumeLimit(actor.userId, "domain", 10, 60 * 60 * 1000);
      const connection = await db.query<{ domain_id: string }>(
        "SELECT domain_id FROM dns_connections WHERE id = $1 AND organization_id = $2",
        [id, actor.organizationId],
      );
      if (!connection.rows[0]) throw new HttpError(404, "NOT_FOUND", "The DNS connection was not found.");
      const response = await proveControl(ctx, db, request, actor, connection.rows[0].domain_id, id);
      await ctx.remember(db, actor.userId, route, idempotencyKey, { id, ...body }, response.status, response.body);
      return response;
    });
    return reply.code(created.status).send({ ...created.body, requestId: request.id });
  });

  app.get("/v1/admin/servers", async (request) => {
    return ctx.withActor(request, "operator", async (db) => {
      const counts = await db.query<{ state: string; n: number }>(
        "SELECT state, count(*)::int AS n FROM servers GROUP BY state",
      );
      const summary: Record<string, number> = {
        pending_validation: 0, available: 0, reserved: 0, assigned: 0, quarantined: 0, retired: 0, total: 0,
      };
      for (const row of counts.rows) {
        summary[row.state] = row.n;
        summary.total += row.n;
      }
      const servers = await db.query(
        `SELECT id, label, host(public_ipv4) AS public_ipv4, profile_code, state, version, auth_epoch,
                operator_contact, provider_reference, last_heartbeat_at, validated_at
         FROM servers ORDER BY created_at DESC LIMIT 100`,
      );
      return { counts: summary, servers: servers.rows, requestId: request.id };
    });
  });

  app.post("/v1/admin/servers", async (request, reply) => {
    const idempotencyKey = ctx.demandIdempotency(request);
    const body = serverCreateSchema.parse(request.body);
    const created = await ctx.withActor(request, "operator", async (db, actor) => {
      assertWriter(actor);
      const route = "POST /v1/admin/servers";
      const replayed = await ctx.replay(db, actor.userId, route, idempotencyKey, body);
      if (replayed) return replayed;
      const publicIpv4 = publicAddress(body.publicIpv4);
      if (!ATTESTATIONS.every((key) => body.preparationAttestations[key] === true)) {
        throw new HttpError(422, "ATTESTATION_REQUIRED", "Preparation attestations are required before registration.");
      }
      const duplicateIp = await db.query("SELECT id FROM servers WHERE public_ipv4 = $1::inet AND state <> 'retired'", [publicIpv4]);
      if (duplicateIp.rows[0]) throw new HttpError(409, "DUPLICATE_ADDRESS", "That address is already in inventory.");
      if (body.providerReference) {
        const duplicateRef = await db.query(
          "SELECT id FROM servers WHERE provider_reference = $1 AND state <> 'retired'",
          [body.providerReference],
        );
        if (duplicateRef.rows[0]) throw new HttpError(409, "DUPLICATE_PROVIDER_REFERENCE", "That provider reference is already in inventory.");
      }
      const label = body.label ?? await nextInventoryLabel(db, "s");
      const id = randomUUID();
      await db.query(
        `INSERT INTO servers (
           id, label, public_ipv4, profile_code, provider_reference, operator_contact, state, preparation_attestations, auth_epoch
         ) VALUES ($1, $2, $3::inet, $4, $5, $6, 'pending_validation', $7::jsonb, 1)`,
        [
          id,
          label,
          publicIpv4,
          body.profileCode,
          body.providerReference ?? null,
          body.operatorContact ?? null,
          JSON.stringify(body.preparationAttestations),
        ],
      );
      await ctx.audit(db, request, actor.userId, null, "server.register", id, {
        label,
        publicIpv4,
        profileCode: body.profileCode,
      });
      if (!ctx.sshProbe) {
        const response = { serverId: id, state: "pending_validation", version: 1 };
        await ctx.remember(db, actor.userId, route, idempotencyKey, body, 201, response);
        return { status: 201 as const, body: response };
      }
      return { status: 201 as const, body: { serverId: id, state: "pending_validation", version: 1 }, probe: { serverId: id, publicIpv4 } };
    });
    const probeTarget = "probe" in created ? created.probe : undefined;
    if (!probeTarget || !ctx.sshProbe) {
      return reply.code(created.status).send({ ...created.body, requestId: request.id });
    }
    const outcome = await capturedProbe(ctx.sshProbe, probeTarget.publicIpv4);
    const saved = await ctx.withActor(request, "operator", async (db, actor) => {
      assertWriter(actor);
      const response = await recordSshValidation(db, request, actor, probeTarget.serverId, outcome);
      await ctx.remember(db, actor.userId, "POST /v1/admin/servers", idempotencyKey, body, 201, response);
      return { status: 201 as const, body: response };
    });
    return reply.code(saved.status).send({ ...saved.body, requestId: request.id });
  });

  app.get("/v1/admin/servers/:id", async (request) => {
    const { id } = request.params as { id: string };
    return ctx.withActor(request, "operator", async (db) => {
      const row = await loadServer(db, id);
      return { ...row, requestId: request.id };
    });
  });

  app.post("/v1/admin/servers/:id/enrollment", async (request, reply) => {
    const idempotencyKey = ctx.demandIdempotency(request);
    const { id } = request.params as { id: string };
    const body = emptyObjectSchema.parse(request.body ?? {});
    const created = await ctx.withActor(request, "operator", async (db, actor) => {
      assertWriter(actor);
      const route = "POST /v1/admin/servers/:id/enrollment";
      const replayed = await ctx.replay(db, actor.userId, route, idempotencyKey, { id, ...body });
      if (replayed) return replayed;
      const server = await db.query("SELECT id FROM servers WHERE id = $1 AND state <> 'retired'", [id]);
      if (!server.rows[0]) throw new HttpError(404, "NOT_FOUND", "The server was not found.");
      await db.query(
        "UPDATE host_enrollments SET consumed_at = coalesce(consumed_at, now()) WHERE server_id = $1 AND consumed_at IS NULL",
        [id],
      );
      const token = randomBytes(32).toString("base64url");
      const enrollmentId = randomUUID();
      const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();
      await db.query(
        `INSERT INTO host_enrollments (id, server_id, token_hash, expires_at, requested_by)
         VALUES ($1, $2, $3, $4, $5)`,
        [enrollmentId, id, hashToken(token), expiresAt, actor.userId],
      );
      await ctx.audit(db, request, actor.userId, null, "server.enrollment", id, { enrollmentId });
      const stored = { enrollmentId, serverId: id, expiresAt, tokenReplayable: false };
      await ctx.remember(db, actor.userId, route, idempotencyKey, { id, ...body }, 201, stored);
      return { status: 201 as const, body: { ...stored, enrollmentToken: token } };
    });
    return reply.code(created.status).send({ ...created.body, requestId: request.id });
  });

  app.post("/v1/admin/servers/:id/confirm-identity", async (request, reply) => {
    const idempotencyKey = ctx.demandIdempotency(request);
    const { id } = request.params as { id: string };
    const body = confirmIdentitySchema.parse(request.body);
    const created = await ctx.withActor(request, "operator", async (db, actor) => {
      assertWriter(actor);
      const route = "POST /v1/admin/servers/:id/confirm-identity";
      const replayed = await ctx.replay(db, actor.userId, route, idempotencyKey, { id, ...body });
      if (replayed) return replayed;
      const bumped = await db.query(
        "UPDATE servers SET version = version + 1, updated_at = now() WHERE id = $1 AND version = $2 RETURNING version",
        [id, body.expectedVersion],
      );
      if (!bumped.rows[0]) throw new HttpError(409, "VERSION_CONFLICT", "The server changed.");
      const identity = await db.query<{ fingerprint: string; state: string }>(
        `SELECT fingerprint, state FROM host_identities WHERE server_id = $1 AND state <> 'revoked'`,
        [id],
      );
      const row = identity.rows[0];
      if (!row) throw new HttpError(422, "IDENTITY_MISSING", "Enroll the host before confirming it.");
      if (row.fingerprint !== body.fingerprint) throw new HttpError(422, "FINGERPRINT_MISMATCH", "The fingerprint does not match the enrolled key.");
      if (row.state === "pending_confirmation") {
        await db.query(
          `UPDATE host_identities
           SET state = 'confirmed', confirmed_by = $2, confirmed_at = now(), updated_at = now(), version = version + 1
           WHERE server_id = $1 AND state = 'pending_confirmation'`,
          [id, actor.userId],
        );
      }
      await ctx.audit(db, request, actor.userId, null, "server.confirm_identity", id, { fingerprint: body.fingerprint });
      const response = { serverId: id, state: "pending_validation", identityState: "confirmed", version: bumped.rows[0].version };
      await ctx.remember(db, actor.userId, route, idempotencyKey, { id, ...body }, 200, response);
      return { status: 200 as const, body: response };
    });
    return reply.code(created.status).send({ ...created.body, requestId: request.id });
  });

  app.post("/v1/admin/servers/:id/validate", async (request, reply) => {
    const idempotencyKey = ctx.demandIdempotency(request);
    const { id } = request.params as { id: string };
    const body = versionedSchema.parse(request.body);
    const created = await ctx.withActor(request, "operator", async (db, actor) => {
      assertWriter(actor);
      const route = "POST /v1/admin/servers/:id/validate";
      const replayed = await ctx.replay(db, actor.userId, route, idempotencyKey, { id, ...body });
      if (replayed) return replayed;
      requireOperation("inventory.validate");
      const server = await db.query<{
        state: string;
        version: number;
        profile_code: string;
        last_heartbeat_at: Date | null;
        readiness_report: HostReport | null;
        tenant_tainted_at: Date | null;
      }>(
        `SELECT state, version, profile_code, last_heartbeat_at, readiness_report, tenant_tainted_at FROM servers WHERE id = $1`,
        [id],
      );
      const row = server.rows[0];
      if (!row) throw new HttpError(404, "NOT_FOUND", "The server was not found.");
      if (row.version !== body.expectedVersion) throw new HttpError(409, "VERSION_CONFLICT", "The server changed.");
      if (row.state !== "pending_validation" && row.state !== "available") {
        throw new HttpError(409, "INVALID_STATE", "This server cannot be validated from its current state.");
      }
      if (ctx.sshProbe && !row.tenant_tainted_at) {
        const address = await db.query<{ public_ipv4: string }>(
          "SELECT host(public_ipv4) AS public_ipv4 FROM servers WHERE id = $1",
          [id],
        );
        const publicIpv4 = address.rows[0]?.public_ipv4;
        if (!publicIpv4) throw new HttpError(404, "NOT_FOUND", "The server was not found.");
        return { status: 200 as const, body: { serverId: id }, probe: { serverId: id, publicIpv4 } };
      }
      const identity = await db.query<{ state: string }>(
        "SELECT state FROM host_identities WHERE server_id = $1 AND state <> 'revoked'",
        [id],
      );
      const failures = readinessFailures({
        profileCode: row.profile_code,
        identityConfirmed: identity.rows[0]?.state === "confirmed",
        lastHeartbeatAt: row.last_heartbeat_at,
        report: row.readiness_report,
      });
      const jobId = randomUUID();
      if (failures.length > 0 || row.tenant_tainted_at) {
        const codes = row.tenant_tainted_at ? [...failures, "server.readiness_missing"] : failures;
        const actionId = await openServerActions(db, id, codes);
        if (row.state === "available") {
          await db.query(
            `UPDATE servers SET state = 'quarantined', version = version + 1, updated_at = now() WHERE id = $1`,
            [id],
          );
        }
        await db.query(
          `INSERT INTO inventory_jobs (id, server_id, kind, state, result) VALUES ($1, $2, 'readiness', 'failed', $3::jsonb)`,
          [jobId, id, JSON.stringify({ failures: codes })],
        );
        const response = {
          error: {
            code: codes[0] ?? "server.readiness_missing",
            message: `The server cannot become available: ${codes.join(", ")}.`,
            retryable: false,
            requiredActionId: actionId,
          },
        };
        await ctx.remember(db, actor.userId, route, idempotencyKey, { id, ...body }, 422, response);
        return { status: 422 as const, body: response };
      }
      const available = await db.query(
        `UPDATE servers
         SET state = 'available', available_since = coalesce(available_since, now()), validated_at = now(),
             version = version + 1, updated_at = now()
         WHERE id = $1 AND version = $2 AND state IN ('pending_validation', 'available')
         RETURNING state`,
        [id, body.expectedVersion],
      );
      if (!available.rows[0]) throw new HttpError(409, "VERSION_CONFLICT", "The server changed.");
      await db.query(
        `UPDATE required_actions SET state = 'resolved', resolved_at = now(), updated_at = now(), version = version + 1
         WHERE server_id = $1 AND state = 'open' AND code LIKE 'server.%'`,
        [id],
      );
      await ctx.setActor(db, "allocator");
      const allocation = await allocateProfile(db, "e2-micro", 100);
      await ctx.setActor(db, restoreActor(actor));
      for (const item of allocation.assigned) {
        await ctx.audit(db, request, actor.userId, item.organizationId, "server.allocate", item.serverId, { assignmentId: item.assignmentId });
      }
      await db.query(
        `INSERT INTO inventory_jobs (id, server_id, kind, state, result) VALUES ($1, $2, 'readiness', 'succeeded', '{}'::jsonb)`,
        [jobId, id],
      );
      const after = await db.query<{ state: string }>("SELECT state FROM servers WHERE id = $1", [id]);
      await ctx.audit(db, request, actor.userId, null, "server.validate", id, { inventoryJobId: jobId });
      const response = { serverId: id, state: after.rows[0]?.state ?? "available", inventoryJobId: jobId };
      await ctx.remember(db, actor.userId, route, idempotencyKey, { id, ...body }, 200, response);
      return { status: 200 as const, body: response };
    });
    const validateTarget = "probe" in created ? created.probe : undefined;
    if (validateTarget && ctx.sshProbe) {
      const outcome = await capturedProbe(ctx.sshProbe, validateTarget.publicIpv4);
      const saved = await ctx.withActor(request, "operator", async (db, actor) => {
        assertWriter(actor);
        const response = await recordSshValidation(db, request, actor, validateTarget.serverId, outcome);
        await ctx.remember(db, actor.userId, "POST /v1/admin/servers/:id/validate", idempotencyKey, { id, ...body }, outcome.ok ? 200 : 422, response);
        return { status: outcome.ok ? 200 as const : 422 as const, body: response };
      });
      return reply.code(saved.status).send({ ...saved.body, requestId: request.id });
    }
    return reply.code(created.status).send({ ...created.body, requestId: request.id });
  });

  app.post("/v1/admin/servers/:id/quarantine", async (request, reply) => {
    const idempotencyKey = ctx.demandIdempotency(request);
    const { id } = request.params as { id: string };
    const body = quarantineSchema.parse(request.body);
    const created = await ctx.withActor(request, "operator", async (db, actor) => {
      assertWriter(actor);
      const route = "POST /v1/admin/servers/:id/quarantine";
      const replayed = await ctx.replay(db, actor.userId, route, idempotencyKey, { id, ...body });
      if (replayed) return replayed;
      const updated = await db.query(
        `UPDATE servers
         SET state = 'quarantined', version = version + 1, updated_at = now(), cleanup_evidence = $3::jsonb
         WHERE id = $1 AND version = $2 AND state <> 'retired'
         RETURNING state`,
        [id, body.expectedVersion, JSON.stringify({ reason: body.reason })],
      );
      if (!updated.rows[0]) throw new HttpError(409, "VERSION_CONFLICT", "The server changed.");
      await ctx.audit(db, request, actor.userId, null, "server.quarantine", id, { reason: body.reason });
      const response = { serverId: id, state: "quarantined" };
      await ctx.remember(db, actor.userId, route, idempotencyKey, { id, ...body }, 200, response);
      return { status: 200 as const, body: response };
    });
    return reply.code(created.status).send({ ...created.body, requestId: request.id });
  });

  app.post("/v1/admin/servers/:id/ip-change", async (request, reply) => {
    const idempotencyKey = ctx.demandIdempotency(request);
    const { id } = request.params as { id: string };
    const body = ipChangeSchema.parse(request.body);
    const created = await ctx.withActor(request, "operator", async (db, actor) => {
      assertWriter(actor);
      const route = "POST /v1/admin/servers/:id/ip-change";
      const replayed = await ctx.replay(db, actor.userId, route, idempotencyKey, { id, ...body });
      if (replayed) return replayed;
      const publicIpv4 = publicAddress(body.publicIpv4);
      const current = await db.query<{ version: number; public_ipv4: string; state: string }>(
        "SELECT version, host(public_ipv4) AS public_ipv4, state FROM servers WHERE id = $1",
        [id],
      );
      const row = current.rows[0];
      if (!row) throw new HttpError(404, "NOT_FOUND", "The server was not found.");
      if (row.version !== body.expectedVersion) throw new HttpError(409, "VERSION_CONFLICT", "The server changed.");
      const collision = await db.query(
        "SELECT id FROM servers WHERE public_ipv4 = $1::inet AND id <> $2 AND state <> 'retired'",
        [publicIpv4, id],
      );
      if (collision.rows[0]) throw new HttpError(409, "DUPLICATE_ADDRESS", "That address is already in inventory.");
      await db.query(
        `UPDATE servers SET public_ipv4 = $2::inet, version = version + 1, updated_at = now() WHERE id = $1`,
        [id, publicIpv4],
      );
      let jobId: string | null = null;
      let installerStarted = false;
      if (row.state === "reserved" || row.state === "assigned" || row.state === "quarantined") {
        const owner = await db.query<{ organization_id: string }>(
          "SELECT organization_id FROM server_assignments WHERE server_id = $1 AND released_at IS NULL",
          [id],
        );
        if (owner.rows[0]) {
          const repair = ctx.addressRepair
            ? await ctx.addressRepair(db, { serverId: id, organizationId: owner.rows[0].organization_id, publicIpv4 })
            : null;
          if (repair) {
            jobId = repair.jobId;
            installerStarted = repair.installerStarted;
          } else {
            jobId = randomUUID();
            await db.query(
              `INSERT INTO jobs (id, organization_id, kind, state, checkpoint)
               VALUES ($1, $2, 'dns.address_update', 'queued', '{"installerStarted":false}'::jsonb)`,
              [jobId, owner.rows[0].organization_id],
            );
          }
        }
      }
      await ctx.audit(db, request, actor.userId, null, "server.ip_change", id, { from: row.public_ipv4, to: publicIpv4 });
      const response = { serverId: id, publicIpv4, installerStarted, jobId };
      await ctx.remember(db, actor.userId, route, idempotencyKey, { id, ...body }, 200, response);
      return { status: 200 as const, body: response };
    });
    return reply.code(created.status).send({ ...created.body, requestId: request.id });
  });

  app.post("/v1/admin/servers/:id/release-reservation", async (request, reply) => {
    const idempotencyKey = ctx.demandIdempotency(request);
    const { id } = request.params as { id: string };
    const body = releaseReservationSchema.parse(request.body);
    const created = await ctx.withActor(request, "operator", async (db, actor) => {
      assertWriter(actor);
      const route = "POST /v1/admin/servers/:id/release-reservation";
      const replayed = await ctx.replay(db, actor.userId, route, idempotencyKey, { id, ...body });
      if (replayed) return replayed;
      const server = await db.query<{ state: string; version: number; tenant_tainted_at: Date | null; auth_epoch: number }>(
        "SELECT state, version, tenant_tainted_at, auth_epoch FROM servers WHERE id = $1",
        [id],
      );
      const row = server.rows[0];
      if (!row) throw new HttpError(404, "NOT_FOUND", "The server was not found.");
      if (row.version !== body.expectedVersion) throw new HttpError(409, "VERSION_CONFLICT", "The server changed.");
      if (row.tenant_tainted_at) throw new HttpError(409, "TAINTED_SERVER", "A tainted server cannot return to inventory.");
      const commands = await db.query(
        "SELECT id FROM host_commands WHERE server_id = $1 AND organization_id IS NOT NULL LIMIT 1",
        [id],
      );
      if (commands.rows[0]) throw new HttpError(409, "TAINTED_SERVER", "A tenant command was issued for this server.");
      const assignment = await db.query<{ organization_id: string }>(
        "SELECT organization_id FROM server_assignments WHERE server_id = $1 AND released_at IS NULL",
        [id],
      );
      const owner = assignment.rows[0];
      if (!owner) throw new HttpError(409, "INVALID_STATE", "This server has no reservation to release.");
      const cancellation = await db.query(
        `SELECT id FROM allocation_requests
         WHERE organization_id = $1 AND cancellation_requested_at IS NOT NULL AND state = 'allocated'`,
        [owner.organization_id],
      );
      if (!cancellation.rows[0]) throw new HttpError(409, "CANCELLATION_REQUIRED", "The customer has not cancelled this reservation.");
      if (row.state !== "reserved") throw new HttpError(409, "INVALID_STATE", "Only an untouched reservation can be released.");
      await db.query("UPDATE server_assignments SET released_at = now() WHERE server_id = $1 AND released_at IS NULL", [id]);
      await db.query(
        `UPDATE allocation_requests
         SET state = 'cancelled', cancelled_at = now(), updated_at = now(), version = version + 1
         WHERE organization_id = $1 AND state = 'allocated'`,
        [owner.organization_id],
      );
      await db.query(
        `UPDATE servers
         SET state = 'pending_validation', available_since = NULL, validated_at = NULL,
             auth_epoch = auth_epoch + 1, version = version + 1, updated_at = now()
         WHERE id = $1`,
        [id],
      );
      await db.query(
        `UPDATE host_identities SET state = 'revoked', revoked_at = now(), updated_at = now(), version = version + 1
         WHERE server_id = $1 AND state <> 'revoked'`,
        [id],
      );
      await db.query(
        "UPDATE host_auth_challenges SET consumed_at = coalesce(consumed_at, now()) WHERE server_id = $1 AND consumed_at IS NULL",
        [id],
      );
      await ctx.audit(db, request, actor.userId, owner.organization_id, "server.release_reservation", id, { previousEpoch: row.auth_epoch });
      const response = { serverId: id, state: "pending_validation", authEpoch: row.auth_epoch + 1 };
      await ctx.remember(db, actor.userId, route, idempotencyKey, { id, ...body }, 200, response);
      return { status: 200 as const, body: response };
    });
    return reply.code(created.status).send({ ...created.body, requestId: request.id });
  });

  app.post("/v1/admin/servers/:id/recovery-binding", async (request, reply) => {
    const idempotencyKey = ctx.demandIdempotency(request);
    const { id } = request.params as { id: string };
    const body = recoveryBindingSchema.parse(request.body);
    const created = await ctx.withActor(request, "operator", async (db, actor) => {
      assertWriter(actor);
      const route = "POST /v1/admin/servers/:id/recovery-binding";
      const replayed = await ctx.replay(db, actor.userId, route, idempotencyKey, { id, ...body });
      if (replayed) return replayed;
      const server = await db.query<{ version: number }>("SELECT version FROM servers WHERE id = $1", [id]);
      if (!server.rows[0]) throw new HttpError(404, "NOT_FOUND", "The server was not found.");
      if (server.rows[0].version !== body.expectedVersion) throw new HttpError(409, "VERSION_CONFLICT", "The server changed.");
      const bindingId = randomUUID();
      await db.query(
        `INSERT INTO recovery_bindings (id, organization_id, replacement_server_id, state)
         VALUES ($1, $2, $3, 'pending')`,
        [bindingId, body.organizationId, id],
      );
      await db.query(
        "UPDATE servers SET state = 'quarantined', version = version + 1, updated_at = now() WHERE id = $1",
        [id],
      );
      await ctx.audit(db, request, actor.userId, body.organizationId, "server.recovery_binding", id, { bindingId });
      const response = { bindingId, serverId: id, state: "quarantined" };
      await ctx.remember(db, actor.userId, route, idempotencyKey, { id, ...body }, 201, response);
      return { status: 201 as const, body: response };
    });
    return reply.code(created.status).send({ ...created.body, requestId: request.id });
  });

  app.post("/v1/admin/servers/:id/commands", async (request, reply) => {
    const idempotencyKey = ctx.demandIdempotency(request);
    const { id } = request.params as { id: string };
    const body = hostCommandSchema.parse(request.body);
    const created = await ctx.withActor(request, "operator", async (db, actor) => {
      assertWriter(actor);
      const route = "POST /v1/admin/servers/:id/commands";
      const parsed = parseCommand(body.commandType, body.parameters ?? {});
      const replayed = await ctx.replay(db, actor.userId, route, idempotencyKey, { id, commandType: body.commandType, expectedEpoch: body.expectedEpoch, parameters: parsed?.parameters ?? body.parameters ?? {} });
      if (replayed) return replayed;
      if (await mutationsPaused(db)) {
        throw new HttpError(409, "RECOVERY_MODE", "Control-plane recovery has paused host commands.");
      }
      if (!parsed) throw new HttpError(400, "UNKNOWN_COMMAND", "That command is not allowed.");
      const server = await db.query<{ auth_epoch: number; tenant_tainted_at: Date | null }>(
        "SELECT auth_epoch, tenant_tainted_at FROM servers WHERE id = $1",
        [id],
      );
      if (!server.rows[0]) throw new HttpError(404, "NOT_FOUND", "The server was not found.");
      if (server.rows[0].auth_epoch !== body.expectedEpoch) {
        throw new HttpError(409, "STALE_EPOCH", "The host authorization epoch is stale.");
      }
      const assignment = await db.query<{ organization_id: string; generation: number }>(
        "SELECT organization_id, generation FROM server_assignments WHERE server_id = $1 AND released_at IS NULL",
        [id],
      );
      const owner = assignment.rows[0];
      if (parsed.scope === "tenant" && !owner) throw new HttpError(409, "NO_ASSIGNMENT", "Tenant commands require the current assignment.");
      const commandId = randomUUID();
      const payloadHash = createHash("sha256").update(JSON.stringify(parsed.parameters)).digest("hex");
      if (parsed.scope === "inventory") {
        const inventoryJobId = randomUUID();
        await db.query(
          "INSERT INTO inventory_jobs (id, server_id, kind, state) VALUES ($1, $2, 'command', 'queued')",
          [inventoryJobId, id],
        );
        await db.query(
          `INSERT INTO host_commands (
             id, server_id, inventory_job_id, generation, auth_epoch, command_type, payload, payload_hash, state, expires_at
           ) VALUES ($1, $2, $3, 1, $4, $5, $6::jsonb, $7, 'queued', now() + interval '15 minutes')`,
          [commandId, id, inventoryJobId, body.expectedEpoch, parsed.commandType, JSON.stringify(parsed.parameters), payloadHash],
        );
      } else if (owner) {
        const jobId = randomUUID();
        await db.query(
          `INSERT INTO jobs (id, organization_id, kind, state, lease_owner, lease_expires_at, fencing_token)
           VALUES ($1, $2, $3, 'queued', 'api', now() + interval '120 seconds', 1)`,
          [jobId, owner.organization_id, parsed.commandType],
        );
        await db.query(
          `INSERT INTO host_commands (
             id, server_id, job_id, organization_id, generation, auth_epoch, command_type, payload, payload_hash, state, expires_at
           ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9, 'queued', now() + interval '15 minutes')`,
          [commandId, id, jobId, owner.organization_id, owner.generation, body.expectedEpoch, parsed.commandType, JSON.stringify(parsed.parameters), payloadHash],
        );
        await db.query(
          "UPDATE servers SET tenant_tainted_at = coalesce(tenant_tainted_at, now()), updated_at = now(), version = version + 1 WHERE id = $1",
          [id],
        );
      }
      await ctx.audit(db, request, actor.userId, owner?.organization_id ?? null, "server.command", commandId, { commandType: parsed.commandType });
      const response = { commandId, commandType: parsed.commandType, state: "queued", authEpoch: body.expectedEpoch };
      await ctx.remember(db, actor.userId, route, idempotencyKey, { id, commandType: body.commandType, expectedEpoch: body.expectedEpoch, parameters: parsed.parameters }, 201, response);
      return { status: 201 as const, body: response };
    });
    return reply.code(created.status).send({ ...created.body, requestId: request.id });
  });

  app.post("/v1/admin/servers/:id/commands/:commandId/dispatch", async (request, reply) => {
    const idempotencyKey = ctx.demandIdempotency(request);
    const { id, commandId } = request.params as { id: string; commandId: string };
    const body = emptyObjectSchema.parse(request.body ?? {});
    const created = await ctx.withActor(request, "operator", async (db, actor) => {
      assertWriter(actor);
      const route = "POST /v1/admin/servers/:id/commands/:commandId/dispatch";
      const replayed = await ctx.replay(db, actor.userId, route, idempotencyKey, { id, commandId, ...body });
      if (replayed) return replayed;
      if (await mutationsPaused(db)) {
        throw new HttpError(409, "RECOVERY_MODE", "Control-plane recovery has paused dispatch.");
      }
      const command = await db.query<{ auth_epoch: number; command_type: string }>(
        "SELECT auth_epoch, command_type FROM host_commands WHERE id = $1 AND server_id = $2",
        [commandId, id],
      );
      if (!command.rows[0]) throw new HttpError(404, "NOT_FOUND", "The command was not found.");
      const server = await db.query<{ auth_epoch: number }>("SELECT auth_epoch FROM servers WHERE id = $1", [id]);
      if (!server.rows[0] || server.rows[0].auth_epoch !== command.rows[0].auth_epoch) {
        throw new HttpError(409, "STALE_EPOCH", "The host authorization epoch is stale.");
      }
      await db.query(
        "UPDATE host_commands SET state = 'accepted', updated_at = now(), version = version + 1 WHERE id = $1",
        [commandId],
      );
      const response = { commandId, accepted: true, delivered: false, commandType: command.rows[0].command_type };
      await ctx.remember(db, actor.userId, route, idempotencyKey, { id, commandId, ...body }, 200, response);
      return { status: 200 as const, body: response };
    });
    return reply.code(created.status).send({ ...created.body, requestId: request.id });
  });

  app.get("/v1/admin/server-waitlist", async (request) => {
    return ctx.withActor(request, "operator", async (db) => {
      const rows = await db.query(
        `SELECT r.id, r.organization_id, r.profile_code, r.verified_registered_at, r.state
         FROM allocation_requests r
         WHERE r.state = 'waiting_for_server'
         ORDER BY r.verified_registered_at, r.id
         LIMIT 100`,
      );
      return { waitlist: rows.rows, requestId: request.id };
    });
  });

  app.post("/v1/admin/server-waitlist/reconcile", async (request, reply) => {
    const idempotencyKey = ctx.demandIdempotency(request);
    const body = emptyObjectSchema.parse(request.body ?? {});
    const created = await ctx.withActor(request, "operator", async (db, actor) => {
      assertWriter(actor);
      const route = "POST /v1/admin/server-waitlist/reconcile";
      const replayed = await ctx.replay(db, actor.userId, route, idempotencyKey, body);
      if (replayed) return replayed;
      requireOperation("organization.allocate");
      await ctx.setActor(db, "allocator");
      const allocation = await allocateProfile(db, "e2-micro", 100);
      await ctx.setActor(db, restoreActor(actor));
      for (const item of allocation.assigned) {
        await ctx.audit(db, request, actor.userId, item.organizationId, "server.allocate", item.serverId, { assignmentId: item.assignmentId });
      }
      const response = { assigned: allocation.assigned.map((item) => ({ organizationId: item.organizationId, serverId: item.serverId })) };
      await ctx.remember(db, actor.userId, route, idempotencyKey, body, 200, response);
      return { status: 200 as const, body: response };
    });
    return reply.code(created.status).send({ ...created.body, requestId: request.id });
  });

  app.get("/v1/admin/relay-connections", async (request) => {
    return ctx.withActor(request, "operator", async (db, actor) => {
      assertWriter(actor);
      const rows = await db.query(
        `SELECT id, label, provider_account_id, smtp_login, daily_limit, state, version, archived_at
         FROM relay_connections ORDER BY created_at DESC LIMIT 100`,
      );
      return { relays: rows.rows, requestId: request.id };
    });
  });

  app.post("/v1/admin/relay-connections", async (request, reply) => {
    const idempotencyKey = ctx.demandIdempotency(request);
    const body = relayConnectionCreateSchema.parse(request.body);
    const created = await ctx.withActor(request, "operator", async (db, actor) => {
      assertWriter(actor);
      const route = "POST /v1/admin/relay-connections";
      const replayed = await ctx.replay(db, actor.userId, route, idempotencyKey, body);
      if (replayed) return replayed;
      const label = body.label ?? await nextInventoryLabel(db, "b");
      const apiFile = ctx.secrets.write(JSON.stringify({ apiKey: body.apiKey }));
      const smtpFile = ctx.secrets.write(JSON.stringify({ smtpKey: body.smtpKey }));
      const apiRef = randomUUID();
      const smtpRef = randomUUID();
      await db.query(
        `INSERT INTO secret_refs (id, purpose, file_name, key_id, state) VALUES ($1, 'brevo-api', $2, 'local-1', 'active')`,
        [apiRef, apiFile],
      );
      await db.query(
        `INSERT INTO secret_refs (id, purpose, file_name, key_id, state) VALUES ($1, 'brevo-smtp', $2, 'local-1', 'active')`,
        [smtpRef, smtpFile],
      );
      const id = randomUUID();
      await db.query(
        `INSERT INTO relay_connections (
           id, provider, label, provider_account_id, api_secret_ref, smtp_secret_ref, smtp_login, daily_limit, state
         ) VALUES ($1, 'brevo', $2, $3, $4, $5, $6, $7, 'inactive')`,
        [id, label, body.loginEmail.toLowerCase(), apiRef, smtpRef, body.smtpLogin, body.dailyLimit],
      );
      await ctx.audit(db, request, actor.userId, null, "relay.create", id, { label, loginEmail: body.loginEmail.toLowerCase() });
      const response = {
        id,
        label,
        loginEmail: body.loginEmail.toLowerCase(),
        smtpLogin: body.smtpLogin,
        dailyLimit: body.dailyLimit,
        state: "inactive",
        version: 1,
      };
      await ctx.remember(db, actor.userId, route, idempotencyKey, body, 201, response);
      return { status: 201 as const, body: response };
    });
    return reply.code(created.status).send({ ...created.body, requestId: request.id });
  });

  app.post("/v1/admin/relay-connections/:id/validate", async (request, reply) => {
    const idempotencyKey = ctx.demandIdempotency(request);
    const { id } = request.params as { id: string };
    const body = emptyObjectSchema.parse(request.body ?? {});
    const created = await ctx.withActor(request, "operator", async (db, actor) => {
      assertWriter(actor);
      const route = "POST /v1/admin/relay-connections/:id/validate";
      const replayed = await ctx.replay(db, actor.userId, route, idempotencyKey, { id, ...body });
      if (replayed) return replayed;
      requireOperation("relay.validate");
      const relay = await db.query<{ smtp_login: string; state: string }>(
        "SELECT smtp_login, state FROM relay_connections WHERE id = $1",
        [id],
      );
      if (!relay.rows[0]) throw new HttpError(404, "NOT_FOUND", "The relay was not found.");
      const result = await ctx.relayChecker.check({ relayId: id, smtpLogin: relay.rows[0].smtp_login });
      if (!result.ok) {
        const actionId = await openAction(db, {
          scope: "inventory",
          audience: "operator",
          code: "relay.activation_required",
          instructions: `Activate relay ${id}.`,
          serverId: null,
          organizationId: null,
        });
        await db.query(
          `UPDATE relay_connections SET validation_report = $2::jsonb, updated_at = now(), version = version + 1 WHERE id = $1`,
          [id, JSON.stringify({ code: result.code })],
        );
        const response = {
          error: {
            code: "relay.activation_required",
            message: "The relay is not activated.",
            retryable: false,
            requiredActionId: actionId,
          },
        };
        await ctx.remember(db, actor.userId, route, idempotencyKey, { id, ...body }, 422, response);
        return { status: 422 as const, body: response };
      }
      await db.query(
        `UPDATE relay_connections
         SET state = CASE WHEN state = 'inactive' THEN 'available' ELSE state END,
             validation_report = '{"ok":true}'::jsonb, updated_at = now(), version = version + 1
         WHERE id = $1`,
        [id],
      );
      const response = { id, state: "available" };
      await ctx.remember(db, actor.userId, route, idempotencyKey, { id, ...body }, 200, response);
      return { status: 200 as const, body: response };
    });
    return reply.code(created.status).send({ ...created.body, requestId: request.id });
  });

  app.post("/v1/admin/organizations/:id/assign-plan", async (request, reply) => {
    const idempotencyKey = ctx.demandIdempotency(request);
    const { id } = request.params as { id: string };
    const body = assignPlanSchema.parse(request.body);
    const created = await ctx.withActor(request, "operator", async (db, actor) => {
      assertWriter(actor);
      const route = "POST /v1/admin/organizations/:id/assign-plan";
      const replayed = await ctx.replay(db, actor.userId, route, idempotencyKey, { id, ...body });
      if (replayed) return replayed;
      const plan = await db.query<{ id: string; server_profile_code: string }>(
        "SELECT id, server_profile_code FROM plans WHERE code = $1 AND revision = $2",
        [body.planCode, body.planRevision],
      );
      if (!plan.rows[0]) throw new HttpError(404, "NOT_FOUND", "The plan revision was not found.");
      const updated = await db.query(
        "UPDATE organizations SET plan_id = $2, version = version + 1, updated_at = now() WHERE id = $1 AND version = $3 RETURNING id",
        [id, plan.rows[0].id, body.expectedVersion],
      );
      if (!updated.rows[0]) throw new HttpError(409, "VERSION_CONFLICT", "The organization changed.");
      const assigned = await db.query<{ profile_code: string; server_id: string }>(
        `SELECT s.profile_code, s.id AS server_id
         FROM server_assignments a JOIN servers s ON s.id = a.server_id
         WHERE a.organization_id = $1 AND a.released_at IS NULL`,
        [id],
      );
      let requiredActionId: string | null = null;
      if (assigned.rows[0] && assigned.rows[0].profile_code !== plan.rows[0].server_profile_code) {
        requiredActionId = await openAction(db, {
          scope: "tenant",
          audience: "operator",
          organizationId: id,
          serverId: assigned.rows[0].server_id,
          code: "plan.profile_mismatch",
          instructions: "The plan profile does not match the reserved server. Do not move the customer.",
        });
      }
      await ctx.audit(db, request, actor.userId, id, "plan.assign", id, { planCode: body.planCode, planRevision: body.planRevision });
      const response = { organizationId: id, planId: plan.rows[0].id, requiredActionId };
      await ctx.remember(db, actor.userId, route, idempotencyKey, { id, ...body }, 200, response);
      return { status: 200 as const, body: response };
    });
    return reply.code(created.status).send({ ...created.body, requestId: request.id });
  });

  app.post("/v1/admin/organizations/:id/assign-relay", async (request, reply) => {
    const idempotencyKey = ctx.demandIdempotency(request);
    const { id } = request.params as { id: string };
    const body = assignRelaySchema.parse(request.body);
    const created = await ctx.withActor(request, "operator", async (db, actor) => {
      assertWriter(actor);
      const route = "POST /v1/admin/organizations/:id/assign-relay";
      const replayed = await ctx.replay(db, actor.userId, route, idempotencyKey, { id, ...body });
      if (replayed) return replayed;
      const org = await db.query("SELECT id FROM organizations WHERE id = $1 AND status = 'active'", [id]);
      if (!org.rows[0]) throw new HttpError(404, "NOT_FOUND", "The organization was not found.");
      const relay = await db.query(
        `UPDATE relay_connections
         SET state = 'assigned', version = version + 1, updated_at = now()
         WHERE id = $1 AND state = 'available' AND version = $2
         RETURNING id`,
        [body.relayConnectionId, body.expectedVersion],
      );
      if (!relay.rows[0]) {
        const existing = await db.query<{ state: string; version: number }>(
          "SELECT state, version FROM relay_connections WHERE id = $1",
          [body.relayConnectionId],
        );
        if (!existing.rows[0]) throw new HttpError(404, "NOT_FOUND", "The relay was not found.");
        if (existing.rows[0].version !== body.expectedVersion) throw new HttpError(409, "VERSION_CONFLICT", "The relay changed.");
        throw new HttpError(422, "RELAY_INACTIVE", "Only an available relay can be assigned.");
      }
      const assignmentId = randomUUID();
      await db.query(
        `INSERT INTO relay_assignments (id, organization_id, relay_connection_id) VALUES ($1, $2, $3)`,
        [assignmentId, id, body.relayConnectionId],
      );
      await ctx.audit(db, request, actor.userId, id, "relay.assign", assignmentId, { relayConnectionId: body.relayConnectionId });
      const response = { assignmentId, organizationId: id, relayConnectionId: body.relayConnectionId };
      await ctx.remember(db, actor.userId, route, idempotencyKey, { id, ...body }, 201, response);
      return { status: 201 as const, body: response };
    });
    return reply.code(created.status).send({ ...created.body, requestId: request.id });
  });

  app.get("/v1/admin/required-actions", async (request) => {
    const query = request.query as { serverId?: string };
    return ctx.withActor(request, "operator", async (db) => {
      const rows = query.serverId
        ? await db.query(
          `SELECT id, scope, code, instructions, state, server_id, organization_id
           FROM required_actions WHERE state = 'open' AND server_id = $1 ORDER BY created_at DESC LIMIT 100`,
          [query.serverId],
        )
        : await db.query(
          `SELECT id, scope, code, instructions, state, server_id, organization_id
           FROM required_actions WHERE state = 'open' ORDER BY created_at DESC LIMIT 100`,
        );
      return { actions: rows.rows, requestId: request.id };
    });
  });

  app.get("/v1/admin/inventory-jobs/:id", async (request) => {
    const { id } = request.params as { id: string };
    return ctx.withActor(request, "operator", async (db) => {
      const row = await db.query(
        "SELECT id, server_id, kind, state, result FROM inventory_jobs WHERE id = $1",
        [id],
      );
      if (!row.rows[0]) throw new HttpError(404, "NOT_FOUND", "The inventory job was not found.");
      return { ...row.rows[0], requestId: request.id };
    });
  });

  app.post("/v1/admin/jobs/expire-leases", async (request, reply) => {
    const idempotencyKey = ctx.demandIdempotency(request);
    const body = emptyObjectSchema.parse(request.body ?? {});
    const created = await ctx.withActor(request, "operator", async (db, actor) => {
      assertWriter(actor);
      const route = "POST /v1/admin/jobs/expire-leases";
      const replayed = await ctx.replay(db, actor.userId, route, idempotencyKey, body);
      if (replayed) return replayed;
      const leases = await db.query<{ id: string; kind: string }>(
        `UPDATE jobs
         SET state = 'failed', error_code = 'LEASE_EXPIRED', updated_at = now(), version = version + 1
         WHERE lease_expires_at IS NOT NULL AND lease_expires_at < now()
           AND state IN ('queued', 'running', 'retry_scheduled', 'waiting_external')
         RETURNING id, kind`,
      );
      const credentialIds = leases.rows.filter((row) => row.kind === "set_mailbox_credential").map((row) => row.id);
      if (credentialIds.length > 0) {
        await db.query(
          `UPDATE jobs
           SET checkpoint = jsonb_set(coalesce(checkpoint, '{}'::jsonb), '{outcome}', '"outcome_unknown"'::jsonb)
           WHERE id = ANY($1::uuid[])`,
          [credentialIds],
        );
      }
      const human = await db.query(
        `UPDATE jobs
         SET state = 'failed', error_code = 'HUMAN_WAIT_EXPIRED', updated_at = now(), version = version + 1
         WHERE state = 'waiting_human' AND created_at < now() - interval '7 days'
         RETURNING id`,
      );
      const response = { expiredLeases: leases.rows.length, expiredHumanWaits: human.rows.length };
      await ctx.remember(db, actor.userId, route, idempotencyKey, body, 200, response);
      return { status: 200 as const, body: response };
    });
    return reply.code(created.status).send({ ...created.body, requestId: request.id });
  });

  app.post("/internal/hosts/enroll", async (request, reply) => {
    const body = hostEnrollSchema.parse(request.body);
    ctx.consumeLimit(`host:${body.serverId}`, "enroll", 30, 60_000);
    const created = await ctx.withSystem("inventory_worker", async (db) => {
      const raw = rawPublicKey(body.publicKey);
      const tokenHash = hashToken(body.token);
      const enrollment = await db.query<{ id: string; server_id: string; expires_at: Date; consumed_at: Date | null }>(
        "SELECT id, server_id, expires_at, consumed_at FROM host_enrollments WHERE token_hash = $1",
        [tokenHash],
      );
      const row = enrollment.rows[0];
      if (!row || row.server_id !== body.serverId) throw new HttpError(403, "ENROLLMENT_INVALID", "The enrollment token is not valid.");
      if (row.consumed_at) throw new HttpError(409, "ENROLLMENT_USED", "The enrollment token was already used.");
      if (row.expires_at.getTime() <= Date.now()) throw new HttpError(422, "ENROLLMENT_EXPIRED", "The enrollment token has expired.");
      const consumed = await db.query(
        `UPDATE host_enrollments SET consumed_at = now()
         WHERE id = $1 AND consumed_at IS NULL AND expires_at > now() RETURNING id`,
        [row.id],
      );
      if (!consumed.rows[0]) throw new HttpError(409, "ENROLLMENT_USED", "The enrollment token was already used.");
      const existing = await db.query(
        "SELECT id FROM host_identities WHERE server_id = $1 AND state <> 'revoked'",
        [body.serverId],
      );
      if (existing.rows[0]) throw new HttpError(409, "IDENTITY_EXISTS", "This server already has a device key.");
      const identityId = randomUUID();
      const fingerprint = fingerprintOf(raw);
      try {
        await db.query(
          `INSERT INTO host_identities (id, server_id, public_key, fingerprint, state)
           VALUES ($1, $2, $3, $4, 'pending_confirmation')`,
          [identityId, body.serverId, raw.toString("base64url"), fingerprint],
        );
      } catch (error) {
        if (pgCode(error) === "23505") throw new HttpError(409, "DUPLICATE_DEVICE", "This device key is already enrolled.");
        throw error;
      }
      await db.query(
        `UPDATE servers SET host_identity_id = $2, version = version + 1, updated_at = now() WHERE id = $1`,
        [body.serverId, identityId],
      );
      return { status: 200 as const, body: { serverId: body.serverId, fingerprint, identityState: "pending_confirmation" } };
    });
    return reply.code(created.status).send({ ...created.body, requestId: request.id });
  });

  app.post("/internal/hosts/heartbeat", async (request, reply) => {
    const body = heartbeatSchema.parse(request.body);
    ctx.consumeLimit(`host:${body.serverId}`, "heartbeat", 120, 60_000);
    const observed = Date.parse(body.observedAt);
    if (!Number.isFinite(observed) || Math.abs(Date.now() - observed) > 3 * 60 * 1000) {
      throw new HttpError(401, "STALE_HEARTBEAT", "The heartbeat is outside the allowed clock window.");
    }
    const created = await ctx.withSystem("inventory_worker", async (db) => {
      const server = await db.query<{ auth_epoch: number; host_identity_id: string | null }>(
        "SELECT auth_epoch, host_identity_id FROM servers WHERE id = $1",
        [body.serverId],
      );
      if (!server.rows[0]) throw new HttpError(404, "NOT_FOUND", "The server was not found.");
      if (server.rows[0].auth_epoch !== body.authEpoch) throw new HttpError(409, "STALE_EPOCH", "The host authorization epoch is stale.");
      const identity = await db.query<{ public_key: string; state: string }>(
        "SELECT public_key, state FROM host_identities WHERE server_id = $1 AND state <> 'revoked'",
        [body.serverId],
      );
      const key = identity.rows[0];
      if (!key || key.state !== "confirmed" || key.public_key !== body.publicKey) {
        throw new HttpError(409, "IDENTITY_UNCONFIRMED", "The device key is not confirmed for this server.");
      }
      const message = heartbeatMessage({
        serverId: body.serverId,
        authEpoch: body.authEpoch,
        observedAt: body.observedAt,
        readiness: body.readiness,
      });
      if (!verifyDevice(rawPublicKey(body.publicKey), message, body.signature)) {
        throw new HttpError(401, "BAD_SIGNATURE", "The heartbeat signature is not valid.");
      }
      await db.query(
        `UPDATE servers
         SET last_heartbeat_at = now(), readiness_report = $2::jsonb, version = version + 1, updated_at = now()
         WHERE id = $1`,
        [body.serverId, JSON.stringify(body.readiness)],
      );
      return { status: 200 as const, body: { serverId: body.serverId, accepted: true } };
    });
    return reply.code(created.status).send({ ...created.body, requestId: request.id });
  });

  app.post("/internal/allocate", async (request, reply) => {
    if (!ctx.schedulerToken) {
      throw new HttpError(503, "SCHEDULER_UNAVAILABLE", "The scheduler identity is not configured.", true);
    }
    const header = request.headers["x-bearportal-scheduler"];
    if (!schedulerAuthorized(typeof header === "string" ? header : undefined, ctx.schedulerToken)) {
      throw new HttpError(401, "UNAUTHENTICATED", "The scheduler identity was rejected.");
    }
    emptyObjectSchema.parse(request.body ?? {});
    const created = await ctx.withSystem("allocator", async (db) => {
      if (await mutationsPaused(db)) {
        throw new HttpError(409, "RECOVERY_MODE", "Control-plane recovery has paused allocation.");
      }
      requireOperation("organization.allocate");
      const allocation = await allocateProfile(db, "e2-micro", 100);
      return { status: 200 as const, body: { assigned: allocation.assigned.length } };
    });
    return reply.code(created.status).send({ assigned: created.body.assigned, requestId: request.id });
  });

  app.post("/operator/brevo-account", async (request, reply) => {
    const form = request.body;
    const loginEmail = formText(form, "loginEmail").trim().toLowerCase();
    const apiKey = formText(form, "apiKey").trim();
    const smtpLogin = formText(form, "smtpLogin").trim();
    const smtpKey = formText(form, "smtpKey").trim();
    const send = (status: number, view: BrevoAccountResultView) => {
      reply.code(status).type("text/html; charset=utf-8");
      return reply.send(renderBrevoAccountResult(view));
    };
    try {
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(loginEmail) || loginEmail.length > 200) {
        return send(400, { error: "Enter the Brevo login email.", loginEmail });
      }
      if (apiKey.length < 1) return send(400, { error: "Enter the Brevo API key.", loginEmail });
      if (apiKey.length > 400) return send(400, { error: "The Brevo API key is too long.", loginEmail });
      if (smtpLogin.length < 1 || smtpLogin.length > 200) {
        return send(400, { error: "Enter the SMTP login.", loginEmail });
      }
      if (smtpKey.length < 1) return send(400, { error: "Enter the SMTP key.", loginEmail });
      if (smtpKey.length > 400) return send(400, { error: "The SMTP key is too long.", loginEmail });
      const dailyLimit = dailyLimitOf(formText(form, "dailyLimit"));
      if (dailyLimit === null) {
        return send(400, { error: "Enter a daily send limit from 1 to 100000.", loginEmail });
      }
      const stored = await ctx.withActor(request, "operator", async (db, actor) => {
        assertWriter(actor);
        if (!actor.roles.includes("platform_administrator")) {
          throw new HttpError(403, "FORBIDDEN", "A platform administrator is required.");
        }
        const account = await storeBrevoAccount(ctx, db, {
          label: loginEmail.slice(0, 120),
          loginEmail,
          apiKey,
          smtpLogin,
          smtpKey,
          dailyLimit,
        });
        await ctx.audit(db, request, actor.userId, null, "brevo.account_store", account.relayId, { loginEmail });
        return account;
      });
      return send(200, { loginEmail, stored: true, state: stored.state });
    } catch (error) {
      if (error instanceof HttpError) return send(error.status, { error: error.message, loginEmail });
      if (pgCode(error) === "23505") {
        return send(409, { error: "That Brevo login is already stored. Submit it again to replace the keys.", loginEmail });
      }
      request.log.error({ err: { name: error instanceof Error ? error.name : "Error" } }, "brevo account store failed");
      return send(500, { error: "The Brevo account could not be stored.", loginEmail });
    }
  });

  app.post("/portal/domain", async (request, reply) => {
    const form = request.body;
    const domainInput = formText(form, "domain").trim();
    const existingMail = formFlag(form, "existingMail");
    const send = (status: number, view: BrevoDomainResultView) => {
      reply.code(status).type("text/html; charset=utf-8");
      return reply.send(renderBrevoDomainResult(view));
    };
    try {
      const domain = normalizeDomain(domainInput);
      const saved = await ctx.withActor(request, "customer", async (db, actor) => {
        ctx.requireVerified(actor);
        ctx.consumeLimit(actor.userId, "domain", 10, 60 * 60 * 1000);
        if (!actor.organizationId) throw new HttpError(422, "ORGANIZATION_REQUIRED", "Create an organization first.");
        if (!recoveryIsOutsideDomain(actor.email, domain)) {
          throw new HttpError(422, "RECOVERY_EMAIL_INSIDE_DOMAIN", "The recovery email must be outside the domain being hosted.");
        }
        const domainId = await saveCustomerDomain(ctx, db, request, actor, domain, existingMail, formFlag(form, "onboarding"));
        const claimed = await claimBrevoAccount(ctx, db, actor.organizationId);
        return { domainId, organizationId: actor.organizationId, claimed };
      });
      const detected = await detectDomainProvider(ctx, domain);
      if (formFlag(form, "onboarding")) {
        return send(200, { domain, saved: true, unavailable: !saved.claimed, ...detected });
      }
      if (!saved.claimed) return send(200, { domain, saved: true, unavailable: true, ...detected });
      let check: BrevoDomainCheck;
      try {
        const apiKey = readStoredApiKey(ctx.secrets, saved.claimed.fileName);
        requireOperation("brevo.create_domain");
        requireOperation("brevo.authenticate");
        check = await ctx.operatorBrevo.requestDomain(apiKey, domain);
        const authenticated = check.authenticated === true;
        const verified = check.verified === true;
        const records = visibleRecords(Array.isArray(check.records) ? check.records : [], apiKey);
        const recordsSaved = completeBrevoRecords(records);
        try {
          await ctx.withActor(request, "customer", async (db, actor) => {
            if (actor.organizationId !== saved.organizationId) {
              throw new HttpError(403, "FORBIDDEN", "The organization does not match.");
            }
            await ctx.setActor(db, "platform_administrator");
            await db.query(
              `UPDATE relay_connections
               SET validation_report = $2::jsonb, updated_at = now(), version = version + 1
               WHERE id = $1`,
              [saved.claimed!.relayId, JSON.stringify({ domain, authenticated, verified, records, publishRecords: check.publishRecords ?? [] })],
            );
            await db.query(
              `UPDATE deployments
               SET brevo_records = CASE WHEN $1::jsonb IS NULL THEN brevo_records ELSE $1::jsonb END,
                   brevo_authenticated = $2,
                   brevo_verified = $3,
                   relay_connection_id = COALESCE(relay_connection_id, $4::uuid),
                   version = version + 1,
                   updated_at = now()
               WHERE organization_id = $5 AND domain_id = $6 AND lifecycle_state <> 'deleted'`,
              [
                recordsSaved ? JSON.stringify(records) : null,
                authenticated,
                verified,
                saved.claimed!.relayId,
                saved.organizationId,
                saved.domainId,
              ],
            );
            await ctx.audit(db, request, actor.userId, saved.organizationId, "brevo.domain_check", saved.claimed!.relayId, {
              domain,
              authenticated,
              verified,
              purposes: records.map((record) => record.purpose),
            });
          });
        } catch (error) {
          const message = error instanceof HttpError ? error.message : "Brevo could not verify the domain.";
          return send(error instanceof HttpError ? error.status : 500, {
            error: message,
            domain,
            saved: true,
            linked: true,
            authenticated,
            verified,
            records,
            recordsSaved: false,
            ...detected,
          });
        }
        return send(200, { domain, saved: true, linked: true, authenticated, verified, records, recordsSaved, ...detected });
      } catch (error) {
        return send(422, { error: safeBrevoMessage(error), domain, saved: true, linked: true, ...detected });
      }
    } catch (error) {
      if (error instanceof HttpError) return send(error.status, { error: error.message, domain: domainInput });
      if (error instanceof DomainError) return send(400, { error: error.message, domain: domainInput });
      request.log.error({ err: { name: error instanceof Error ? error.name : "Error" } }, "customer domain check failed");
      return send(500, { error: "Brevo could not verify the domain.", domain: domainInput });
    }
  });

  app.post("/portal/dns-credential", async (request, reply) => {
    const form = request.body;
    const domainInput = formText(form, "domain").trim();
    const send = (status: number, view: DnsCredentialResultView) => {
      reply.code(status).type("text/html; charset=utf-8");
      return reply.send(renderDnsCredentialResult(view));
    };
    let credentialStored = false;
    try {
      const domain = normalizeDomain(domainInput);
      const automatic = formFlag(form, "onboarding");
      await ctx.withActor(request, "customer", async (db, actor) => {
        ctx.requireVerified(actor);
        ctx.consumeLimit(actor.userId, "credential", 10, 60 * 60 * 1000);
        if (!actor.organizationId) throw new HttpError(422, "ORGANIZATION_REQUIRED", "Create an organization first.");
        const domainRow = await db.query<{ id: string }>(
          `SELECT id FROM domains WHERE organization_id = $1 AND normalized_name = $2 AND state <> 'retired'`,
          [actor.organizationId, domain],
        );
        if (!domainRow.rows[0]) throw new HttpError(404, "NOT_FOUND", "Save the company domain first.");
        if(automatic) await ctx.requireSubscription?.(db, actor.organizationId);
        if(automatic) await requireSetupConsent(db,actor.organizationId,domainRow.rows[0].id,formFlag(form,"deployConsent"));
      });
      const detected = await detectDomainProvider(ctx, domain);
      if (!detected.detectedProvider) {
        return send(422, { error: "BearPortal cannot match these nameservers to Name.com, Hostinger, or GoDaddy.", domain });
      }
      const provider = detected.detectedProvider;
      const credential = credentialFromForm(provider, form);
      if (!credential) {
        const message = provider === "godaddy"
          ? "Enter the GoDaddy personal access token."
          : "Enter the DNS credential for the detected provider.";
        return send(400, { error: message, domain, provider });
      }
      if (JSON.stringify(credential).includes("reject:")) {
        return send(422, { error: "The DNS credential was rejected.", domain, provider });
      }
      const stored = await ctx.withActor(request, "customer", async (db, actor) => {
        ctx.requireVerified(actor);
        if (!actor.organizationId) throw new HttpError(422, "ORGANIZATION_REQUIRED", "Create an organization first.");
        requireOperation("dns.store_credentials");
        const domainRow = await db.query<{ id: string }>(
          `SELECT id FROM domains WHERE organization_id = $1 AND normalized_name = $2 AND state <> 'retired'`,
          [actor.organizationId, domain],
        );
        const found = domainRow.rows[0];
        if (!found) throw new HttpError(404, "NOT_FOUND", "Save the company domain first.");
        const material = credentialMaterial(credential);
        const fileName = ctx.secrets.write(JSON.stringify(material));
        const secretId = randomUUID();
        await db.query(
          `INSERT INTO secret_refs (id, organization_id, purpose, file_name, key_id, state)
           VALUES ($1, $2, 'dns', $3, 'local-1', 'active')`,
          [secretId, actor.organizationId, fileName],
        );
        const current = await db.query<{ id: string; secret_ref: string }>(
          `SELECT id, secret_ref FROM dns_connections
           WHERE organization_id = $1 AND domain_id = $2
           ORDER BY created_at DESC LIMIT 1`,
          [actor.organizationId, found.id],
        );
        const existing = current.rows[0];
        let connectionId = existing?.id;
        if (existing) {
          await db.query(`UPDATE secret_refs SET state = 'retired', retired_at = now() WHERE id = $1`, [existing.secret_ref]);
          await db.query(
            `UPDATE dns_connections
             SET provider = $2, zone_id = $3, secret_ref = $4, state = 'stored', updated_at = now(), version = version + 1
             WHERE id = $1`,
            [existing.id, provider, domain, secretId],
          );
        } else {
          connectionId = randomUUID();
          await db.query(
            `INSERT INTO dns_connections
               (id, organization_id, domain_id, provider, zone_id, secret_ref, state)
             VALUES ($1, $2, $3, $4, $5, $6, 'stored')`,
            [connectionId, actor.organizationId, found.id, provider, domain, secretId],
          );
        }
        await ctx.audit(db, request, actor.userId, actor.organizationId, "dns.store", connectionId ?? secretId, {
          provider,
          zoneId: domain,
        });
        await ctx.setActor(db, "platform_administrator");
        const report = await db.query<{ id: string; validation_report: { publishRecords?: BrevoPublishRecord[] } | null; file_name: string | null }>(
          `SELECT r.id, r.validation_report, s.file_name
           FROM relay_assignments a
           JOIN relay_connections r ON r.id = a.relay_connection_id
           LEFT JOIN secret_refs s ON s.id = r.api_secret_ref
           WHERE a.organization_id = $1 AND a.released_at IS NULL
           LIMIT 1`,
          [actor.organizationId],
        );
        const rawRecords = report.rows[0]?.validation_report?.publishRecords;
        if (automatic) {
          await enqueueOnboarding(db, actor.organizationId, found.id);
        }
        return {
          provider,
          credential,
          organizationId: actor.organizationId,
          relayId: report.rows[0]?.id ?? null,
          publishRecords: Array.isArray(rawRecords) ? rawRecords : [],
          apiFile: report.rows[0]?.file_name ?? null,
        };
      });
      credentialStored = true;
      if (automatic) {
        ctx.onboardingRequested?.();
        return reply.code(303).header("location", "/portal").send("");
      }
      let records = stored.publishRecords.filter(isPublishRecord);
      if (records.length === 0 && stored.apiFile) {
        const apiKey = readStoredApiKey(ctx.secrets, stored.apiFile);
        const check = await ctx.operatorBrevo.requestDomain(apiKey, domain);
        records = check.publishRecords ?? [];
      }
      if (records.length === 0) {
        return send(200, {
          domain,
          provider: stored.provider,
          stored: true,
          error: "The DNS credential is stored. Brevo has not returned records to publish.",
        });
      }
      const published = await ctx.publishBrevoRecords({
        provider: stored.provider,
        zone: domain,
        credential: stored.credential,
        records,
      });
      let authenticated: boolean | undefined;
      let verified: boolean | undefined;
      if (stored.apiFile && stored.relayId) {
        const apiKey = readStoredApiKey(ctx.secrets, stored.apiFile);
        requireOperation("brevo.authenticate");
        const authenticate = ctx.operatorBrevo.authenticateDomain ?? authenticateBrevoDomain;
        const auth = await authenticate(apiKey, domain);
        authenticated = auth.authenticated === true;
        verified = auth.verified === true;
        await ctx.withActor(request, "customer", async (db, actor) => {
          if (actor.organizationId !== stored.organizationId) {
            throw new HttpError(403, "FORBIDDEN", "The organization does not match.");
          }
          await ctx.setActor(db, "platform_administrator");
          await db.query(
            `UPDATE relay_connections
             SET validation_report = jsonb_set(
                   jsonb_set(coalesce(validation_report, '{}'::jsonb), '{authenticated}', to_jsonb($2::boolean), true),
                   '{verified}', to_jsonb($3::boolean), true
                 ),
                 updated_at = now(),
                 version = version + 1
             WHERE id = $1`,
            [stored.relayId, authenticated, verified],
          );
          await db.query(
            `UPDATE deployments AS d
             SET brevo_authenticated = $2, brevo_verified = $3, version = d.version + 1, updated_at = now()
             FROM domains AS dom
             WHERE d.domain_id = dom.id
               AND d.organization_id = $1
               AND dom.normalized_name = $4
               AND d.lifecycle_state <> 'deleted'`,
            [stored.organizationId, authenticated, verified, domain],
          );
          await ctx.audit(db, request, actor.userId, stored.organizationId, "brevo.authenticate", stored.relayId ?? domain, {
            domain,
            authenticated,
            verified,
          });
        });
      }
      return send(200, {
        domain,
        provider: stored.provider,
        stored: true,
        written: published.written,
        authenticated,
        verified,
      });
    } catch (error) {
      if (error instanceof HttpError) return send(error.status, { error: error.message, domain: domainInput });
      if (error instanceof DomainError) return send(400, { error: error.message, domain: domainInput });
      const message = error instanceof Error ? error.message : "";
      const allowed = new Set([
        "The DNS provider rejected the credential.",
        "The DNS zone was not found.",
        "The DNS provider rejected the record update.",
        "The DNS provider could not be reached.",
        "The DNS credential was rejected.",
        "Brevo did not return records to publish.",
        "Brevo rejected the API key.",
        "Brevo could not be reached.",
        "Brevo did not accept the domain.",
        "Brevo could not verify the domain.",
      ]);
      const fallback = credentialStored
        ? "The DNS credential is stored, but the records were not published."
        : "The DNS credential could not be stored.";
      if (!allowed.has(message)) {
        request.log.error({ err: { name: error instanceof Error ? error.name : "Error" } }, "dns credential store failed");
      }
      return send(422, { error: allowed.has(message) ? message : fallback, domain: domainInput, stored: credentialStored });
    }
  });
}

async function detectDomainProvider(ctx: InventoryContext, domain: string): Promise<{ nameservers: string[]; detectedProvider: DetectedDnsProvider | null }> {
  const nameservers = await ctx.lookupNameservers(domain);
  return { nameservers, detectedProvider: detectDnsProvider(nameservers) };
}

function credentialFromForm(provider: DetectedDnsProvider, form: unknown): DnsCredentialMaterial | null {
  if (provider === "namecom") {
    const username = formText(form, "dnsUsername").trim();
    const token = formText(form, "dnsToken").trim();
    if (!username || !token || username.length > 200 || token.length > 400) return null;
    return { provider, username, token };
  }
  if (provider === "hostinger") {
    const token = formText(form, "dnsToken").trim();
    if (!token || token.length > 400) return null;
    return { provider, token };
  }
  const token = formText(form, "dnsToken").trim();
  if (!token || token.length > 4000) return null;
  return { provider, token };
}

function credentialMaterial(credential: DnsCredentialMaterial): Record<string, string> {
  if (credential.provider === "namecom") return { username: credential.username, token: credential.token };
  return { token: credential.token };
}

function isPublishRecord(value: BrevoPublishRecord): boolean {
  return (value.type === "TXT" || value.type === "CNAME")
    && typeof value.host === "string"
    && value.host.length > 0
    && typeof value.value === "string"
    && value.value.length > 0;
}

async function organizationServer(db: Db, organizationId: string): Promise<Record<string, unknown>> {
  const allocation = await db.query<{ state: string }>(
    `SELECT state FROM allocation_requests WHERE organization_id = $1 AND state <> 'cancelled' ORDER BY created_at DESC LIMIT 1`,
    [organizationId],
  );
  const org = await db.query<{ version: number }>("SELECT version FROM organizations WHERE id = $1", [organizationId]);
  const allocationState = allocation.rows[0]?.state ?? "waiting_for_server";
  const server = allocationState === "allocated" ? await readCustomerServer(db, organizationId) : null;
  return {
    allocationState,
    waitReason: allocationState === "waiting_for_server" ? "inventory.shortage" : null,
    server,
    organizationVersion: org.rows[0]?.version ?? null,
  };
}

async function proveControl(
  ctx: InventoryContext,
  db: Db,
  request: FastifyRequest,
  actor: Actor,
  domainId: string,
  connectionId: string | null,
): Promise<{ status: number; body: Record<string, unknown> }> {
  requireOperation("dns.dry_run");
  const domain = await db.query<{ id: string; normalized_name: string; state: string; nameservers: string[]; recheck_required: boolean }>(
    "SELECT id, normalized_name, state, nameservers, recheck_required FROM domains WHERE id = $1 AND organization_id = $2",
    [domainId, actor.organizationId],
  );
  const row = domain.rows[0];
  if (!row) throw new HttpError(404, "NOT_FOUND", "The domain was not found.");
  const connection = connectionId
    ? await db.query<{ id: string; provider: string; zone_id: string }>(
      "SELECT id, provider, zone_id FROM dns_connections WHERE id = $1 AND organization_id = $2 AND domain_id = $3",
      [connectionId, actor.organizationId, domainId],
    )
    : await db.query<{ id: string; provider: string; zone_id: string }>(
      `SELECT id, provider, zone_id FROM dns_connections
       WHERE domain_id = $1 AND organization_id = $2 ORDER BY created_at DESC LIMIT 1`,
      [domainId, actor.organizationId],
    );
  const link = connection.rows[0];
  if (!link) throw new HttpError(422, "DNS_CONNECTION_REQUIRED", "Store a DNS credential before proving control.");
  const read = await ctx.zoneReader.readZone({ provider: link.provider, zone: link.zone_id, domain: row.normalized_name });
  if (!read.ok && read.code === "DNS_READER_UNAVAILABLE") {
    throw new HttpError(503, "DNS_READER_UNAVAILABLE", "The zone reader is not available.", true);
  }
  if (!read.ok) {
    await db.query(
      `UPDATE dns_connections SET state = 'rejected', last_error_code = $2, updated_at = now(), version = version + 1 WHERE id = $1`,
      [link.id, read.code],
    );
    const status = read.code === "PROOF_EXPIRED" ? "PROOF_EXPIRED" : "PROOF_REJECTED";
    throw new HttpError(422, status, "The zone read did not prove control of this domain.");
  }
  const assessed = assessZoneRead(row.normalized_name, read.snapshot.records);
  if (!assessed.ok) {
    await db.query(
      `UPDATE dns_connections SET state = 'rejected', last_error_code = 'DNS_RECORD_CONFLICT', updated_at = now(), version = version + 1 WHERE id = $1`,
      [link.id],
    );
    throw new HttpError(422, "DNS_RECORD_CONFLICT", assessed.message);
  }
  const nameservers = read.snapshot.nameservers.map((name) => name.toLowerCase().replace(/\.$/, "")).sort();
  if (row.state === "verified") {
    const previous = [...row.nameservers].map((name) => name.toLowerCase()).sort().join(",");
    if (previous !== nameservers.join(",")) {
      await db.query(
        `UPDATE domains SET nameservers = $2, recheck_required = true, updated_at = now(), version = version + 1 WHERE id = $1`,
        [row.id, nameservers],
      );
      const requiredActionId = await openAction(db, {
        scope: "tenant",
        audience: "operator",
        organizationId: actor.organizationId,
        serverId: null,
        code: "domain.nameserver_recheck",
        instructions: "Authoritative nameservers changed. Recheck domain control before installation.",
      });
      await ctx.audit(db, request, actor.userId, actor.organizationId, "domain.recheck", row.id, { nameservers });
      return { status: 200, body: { id: row.id, domain: row.normalized_name, state: "verified", recheckRequired: true, requiredActionId } };
    }
    return { status: 200, body: { id: row.id, domain: row.normalized_name, state: "verified", recheckRequired: row.recheck_required, nameservers } };
  }
  const owned = await db.query<{ organization_id: string }>(
    "SELECT organization_id FROM domains WHERE normalized_name = $1 AND state = 'verified'",
    [row.normalized_name],
  );
  if (owned.rows[0] && owned.rows[0].organization_id !== actor.organizationId) {
    throw new HttpError(409, "DOMAIN_OWNED", "This domain is already verified by another organization.");
  }
  try {
    const updated = await db.query(
      `UPDATE domains
       SET state = 'verified', verified_at = now(), nameservers = $2, dns_connection_id = $3,
           recheck_required = false, updated_at = now(), version = version + 1
       WHERE id = $1 AND organization_id = $4 AND state = 'pending'
       RETURNING id`,
      [row.id, nameservers, link.id, actor.organizationId],
    );
    if (!updated.rows[0]) throw new HttpError(409, "DOMAIN_OWNED", "This domain is already verified.");
  } catch (error) {
    if (error instanceof HttpError) throw error;
    if (pgCode(error) === "23505") throw new HttpError(409, "DOMAIN_OWNED", "This domain is already verified.");
    throw error;
  }
  const fingerprint = createHash("sha256").update(JSON.stringify(read.snapshot.records)).digest("hex");
  await db.query(
    `INSERT INTO dns_plans (
       id, organization_id, domain_id, purpose, base_fingerprint, desired_records, operations, plan_hash, state
     ) VALUES ($1, $2, $3, 'dry_run', $4, $5::jsonb, '[{"op":"read"}]'::jsonb, $4, 'read')`,
    [randomUUID(), actor.organizationId, row.id, fingerprint, JSON.stringify(read.snapshot.records)],
  );
  await db.query(
    `UPDATE dns_connections
     SET state = 'validated', validated_at = now(), last_error_code = NULL, updated_at = now(), version = version + 1
     WHERE id = $1`,
    [link.id],
  );
  await ctx.audit(db, request, actor.userId, actor.organizationId, "domain.verify", row.id, { nameservers });
  return {
    status: 200,
    body: { id: row.id, domain: row.normalized_name, state: "verified", nameservers, recheckRequired: false, planState: "read" },
  };
}

async function loadServer(db: Db, id: string): Promise<Record<string, unknown>> {
  const row = await db.query(
    `SELECT s.id, s.label, host(s.public_ipv4) AS public_ipv4, s.profile_code, s.provider_reference, s.operator_contact,
            s.state, s.version, s.auth_epoch, s.last_heartbeat_at, s.validated_at, s.tenant_tainted_at,
            h.fingerprint, h.state AS identity_state
     FROM servers s
     LEFT JOIN host_identities h ON h.id = s.host_identity_id
     WHERE s.id = $1`,
    [id],
  );
  if (!row.rows[0]) throw new HttpError(404, "NOT_FOUND", "The server was not found.");
  return row.rows[0];
}

async function capturedProbe(
  probe: (publicIpv4: string) => Promise<SshProbeOutcome>,
  publicIpv4: string,
): Promise<SshProbeOutcome> {
  try {
    return await probe(publicIpv4);
  } catch {
    return { ok: false, failures: ["server.unreachable"], report: null };
  }
}

async function openServerActions(db: Db, serverId: string, codes: string[]): Promise<string> {
  let first = "";
  for (const code of codes) {
    const id = await openAction(db, {
      scope: "inventory",
      audience: "operator",
      serverId,
      organizationId: null,
      code,
      instructions: actionInstructions(code),
    });
    if (!first) first = id;
  }
  return first;
}

function actionInstructions(code: string): string {
  if (code === "server.fingerprint_unconfirmed") return "Confirm the enrolled host fingerprint.";
  if (code === "server.heartbeat_stale") return "The host heartbeat is stale.";
  if (code === "server.incompatible_profile") return "The host profile or capacity is below the beta plan.";
  if (code === "server.unreachable") return "The host failed the inbound reachability check.";
  if (code === "server.sudo_failed") return "The mail account could not run sudo without a password.";
  if (code === "server.relay_unreachable") return "The host cannot reach the outbound mail relay.";
  return "Host readiness is incomplete.";
}

async function openAction(db: Db, input: {
  scope: "tenant" | "inventory";
  audience: "operator" | "customer";
  code: string;
  instructions: string;
  serverId: string | null;
  organizationId: string | null;
}): Promise<string> {
  const existing = await db.query<{ id: string }>(
    `SELECT id FROM required_actions
     WHERE state = 'open' AND code = $1
       AND organization_id IS NOT DISTINCT FROM $2
       AND server_id IS NOT DISTINCT FROM $3
       AND instructions = $4
     LIMIT 1`,
    [input.code, input.organizationId, input.serverId, input.instructions],
  );
  if (existing.rows[0]) return existing.rows[0].id;
  const id = randomUUID();
  await db.query(
    `INSERT INTO required_actions (id, scope, organization_id, server_id, audience, code, instructions, state)
     VALUES ($1, $2, $3, $4, $5, $6, $7, 'open')`,
    [id, input.scope, input.organizationId, input.serverId, input.audience, input.code, input.instructions],
  );
  return id;
}

function publicAddress(value: string): string {
  try {
    return assertPublicUnicastIpv4(value);
  } catch (error) {
    if (error instanceof AddressError) throw new HttpError(400, "VALIDATION", error.message);
    throw error;
  }
}

function rawPublicKey(value: string): Buffer {
  const raw = Buffer.from(value, "base64url");
  if (raw.length !== 32) throw new HttpError(400, "VALIDATION", "The device public key must be a raw Ed25519 key.");
  return raw;
}

function fingerprintOf(raw: Buffer): string {
  return createHash("sha256").update(raw).digest("hex");
}

function verifyDevice(raw: Buffer, message: string, signature: string): boolean {
  try {
    const spki = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), raw]);
    const key = createPublicKey({ key: spki, format: "der", type: "spki" });
    const sig = Buffer.from(signature, "base64url");
    if (sig.length !== 64) return false;
    return verify(null, Buffer.from(message), key, sig);
  } catch {
    return false;
  }
}

function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

function schedulerAuthorized(header: string | undefined, expected: string | undefined): boolean {
  if (!expected || !header) return false;
  const left = Buffer.from(header);
  const right = Buffer.from(expected);
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}

function pgCode(error: unknown): string | undefined {
  if (!error || typeof error !== "object") return undefined;
  const code = (error as { code?: unknown }).code;
  if (typeof code === "string") return code;
  return pgCode((error as { cause?: unknown }).cause);
}

function formText(body: unknown, name: string): string {
  if (!body || typeof body !== "object" || Array.isArray(body)) return "";
  const value = (body as Record<string, unknown>)[name];
  if (typeof value === "string") return value;
  if (typeof value === "number" && Number.isFinite(value)) return String(value);
  return "";
}

function formFlag(body: unknown, name: string): boolean {
  const value = formText(body, name).trim().toLowerCase();
  return value === "1" || value === "true" || value === "on";
}

function dailyLimitOf(raw: string): number | null {
  const text = raw.trim();
  if (text === "") return 300;
  if (!/^[0-9]+$/.test(text)) return null;
  const value = Number(text);
  if (!Number.isInteger(value) || value < 1 || value > 100000) return null;
  return value;
}

function safeBrevoMessage(error: unknown): string {
  const allowed = new Set([
    "Brevo rejected the API key.",
    "Brevo could not be reached.",
    "Brevo did not accept the domain.",
    "Brevo could not verify the domain.",
  ]);
  if (error instanceof BrevoRequestError && allowed.has(error.message)) return error.message;
  return "Brevo could not verify the domain.";
}

function visibleRecords(records: BrevoDnsRecord[], apiKey: string): BrevoDnsRecord[] {
  const purposes = new Set(["brevo_code", "dkim", "dmarc"]);
  return records.flatMap((record) => {
    if (record.type !== "TXT" || !purposes.has(record.purpose)) return [];
    const value = record.value.trim();
    const host = record.host.trim();
    if (!value || value.length > 4000 || !host || host.length > 253) return [];
    if (apiKey.length >= 8 && value.includes(apiKey)) return [];
    return [{ purpose: record.purpose, type: "TXT" as const, host, value }];
  });
}

function completeBrevoRecords(records: BrevoDnsRecord[]): boolean {
  const purposes = new Set(records.map((record) => record.purpose));
  return records.length === 3 && purposes.has("brevo_code") && purposes.has("dkim") && purposes.has("dmarc");
}

async function saveCustomerDomain(
  ctx: InventoryContext,
  db: Db,
  request: FastifyRequest,
  actor: Actor,
  domain: string,
  existingMail: boolean,
  allowCorrection = false,
): Promise<string> {
  if (!actor.organizationId) throw new HttpError(422, "ORGANIZATION_REQUIRED", "Create an organization first.");
  const found = await db.query<{ id: string; normalized_name: string }>(
    `SELECT id, normalized_name
     FROM domains
     WHERE organization_id = $1 AND state <> 'retired'
     ORDER BY created_at, id`,
    [actor.organizationId],
  );
  const same = found.rows.find((row) => row.normalized_name === domain);
  if (!same && found.rows.length > 0) {
    const started = await db.query(`SELECT 1 FROM deployments WHERE organization_id=$1
      UNION ALL SELECT 1 FROM onboarding_requests WHERE organization_id=$1
      UNION ALL SELECT 1 FROM dns_connections WHERE organization_id=$1 LIMIT 1`,[actor.organizationId]);
    if (!allowCorrection || started.rows.length > 0) {
      throw new HttpError(409, "CONFLICT", "This organization already has a domain.");
    }
    await db.query("UPDATE domains SET state='retired',updated_at=now(),version=version+1 WHERE organization_id=$1 AND state='pending'",[actor.organizationId]);
    if (found.rows.some(row => row.normalized_name !== domain) && (await db.query("SELECT 1 FROM domains WHERE organization_id=$1 AND state <> 'retired'",[actor.organizationId])).rows.length) {
      throw new HttpError(409, "CONFLICT", "This organization already has a verified domain.");
    }
  }
  if (same) {
    await db.query(
      `UPDATE domains
       SET existing_mail = $2, updated_at = now(), version = version + 1
       WHERE id = $1 AND organization_id = $3 AND state <> 'retired'`,
      [same.id, existingMail, actor.organizationId],
    );
    return same.id;
  }
  const id = randomUUID();
  await db.query(
    `INSERT INTO domains (id, organization_id, normalized_name, existing_mail, state)
     VALUES ($1, $2, $3, $4, 'pending')`,
    [id, actor.organizationId, domain, existingMail],
  );
  await ctx.audit(db, request, actor.userId, actor.organizationId, "domain.create", id, { domain });
  return id;
}

export async function claimBrevoAccount(
  ctx: InventoryContext,
  db: Db,
  organizationId: string,
): Promise<{ relayId: string; fileName: string } | null> {
  await ctx.setActor(db, "platform_administrator");
  const existing = await db.query<{ id: string; file_name: string }>(
    `SELECT r.id, s.file_name
     FROM relay_assignments a
     JOIN relay_connections r ON r.id = a.relay_connection_id
     JOIN secret_refs s ON s.id = r.api_secret_ref
     WHERE a.organization_id = $1 AND a.released_at IS NULL
     LIMIT 1`,
    [organizationId],
  );
  const current = existing.rows[0];
  if (current) return { relayId: current.id, fileName: current.file_name };
  const locked = await db.query<{ id: string; file_name: string }>(
    `SELECT r.id, s.file_name
     FROM relay_connections r
     JOIN secret_refs s ON s.id = r.api_secret_ref
     WHERE r.provider = 'brevo'
       AND r.state IN ('inactive', 'available')
       AND NOT EXISTS (
         SELECT 1 FROM relay_assignments a
         WHERE a.relay_connection_id = r.id AND a.released_at IS NULL
       )
     ORDER BY r.created_at, r.id
     LIMIT 1
     FOR UPDATE OF r`,
  );
  const row = locked.rows[0];
  if (!row) return null;
  const updated = await db.query(
    `UPDATE relay_connections
     SET state = 'assigned', version = version + 1, updated_at = now()
     WHERE id = $1 AND state IN ('inactive', 'available')
     RETURNING id`,
    [row.id],
  );
  if (!updated.rows[0]) return null;
  await db.query(
    `INSERT INTO relay_assignments (id, organization_id, relay_connection_id) VALUES ($1, $2, $3)`,
    [randomUUID(), organizationId, row.id],
  );
  return { relayId: row.id, fileName: row.file_name };
}

function readStoredApiKey(secrets: SecretStore, fileName: string): string {
  let parsed: { apiKey?: unknown };
  try {
    parsed = JSON.parse(secrets.read(fileName)) as { apiKey?: unknown };
  } catch {
    throw new BrevoRequestError("Brevo could not verify the domain.");
  }
  if (!parsed || typeof parsed.apiKey !== "string" || parsed.apiKey.length < 1 || parsed.apiKey.length > 400) {
    throw new BrevoRequestError("Brevo could not verify the domain.");
  }
  return parsed.apiKey;
}

async function storeBrevoAccount(
  ctx: InventoryContext,
  db: Db,
  input: { label: string; loginEmail: string; apiKey: string; smtpLogin: string; smtpKey: string; dailyLimit: number },
): Promise<{ relayId: string; state: string }> {
  const apiFile = ctx.secrets.write(JSON.stringify({ apiKey: input.apiKey }));
  const smtpFile = ctx.secrets.write(JSON.stringify({ smtpKey: input.smtpKey }));
  const existing = await db.query<{ id: string; api_secret_ref: string | null; smtp_secret_ref: string | null }>(
    `SELECT id, api_secret_ref, smtp_secret_ref
     FROM relay_connections
     WHERE provider = 'brevo' AND provider_account_id = $1`,
    [input.loginEmail],
  );
  const current = existing.rows[0];
  if (current) {
    const apiRef = await replaceSecret(db, current.api_secret_ref, "brevo-api", apiFile);
    const smtpRef = await replaceSecret(db, current.smtp_secret_ref, "brevo-smtp", smtpFile);
    await db.query(
      `UPDATE relay_connections
       SET label = $2, smtp_login = $3, daily_limit = $4, api_secret_ref = $5, smtp_secret_ref = $6,
           updated_at = now(), version = version + 1
       WHERE id = $1`,
      [current.id, input.label, input.smtpLogin, input.dailyLimit, apiRef, smtpRef],
    );
    const state = await db.query<{ state: string }>("SELECT state FROM relay_connections WHERE id = $1", [current.id]);
    return { relayId: current.id, state: state.rows[0]?.state ?? "inactive" };
  }
  const apiRef = randomUUID();
  const smtpRef = randomUUID();
  const relayId = randomUUID();
  await db.query(
    `INSERT INTO secret_refs (id, purpose, file_name, key_id, state) VALUES ($1, 'brevo-api', $2, 'local-1', 'active')`,
    [apiRef, apiFile],
  );
  await db.query(
    `INSERT INTO secret_refs (id, purpose, file_name, key_id, state) VALUES ($1, 'brevo-smtp', $2, 'local-1', 'active')`,
    [smtpRef, smtpFile],
  );
  await db.query(
    `INSERT INTO relay_connections (
       id, provider, label, provider_account_id, api_secret_ref, smtp_secret_ref, smtp_login, daily_limit, state
     ) VALUES ($1, 'brevo', $2, $3, $4, $5, $6, $7, 'inactive')`,
    [relayId, input.label, input.loginEmail, apiRef, smtpRef, input.smtpLogin, input.dailyLimit],
  );
  return { relayId, state: "inactive" };
}

async function replaceSecret(db: Db, existingId: string | null, purpose: string, fileName: string): Promise<string> {
  if (!existingId) {
    const id = randomUUID();
    await db.query(
      `INSERT INTO secret_refs (id, purpose, file_name, key_id, state) VALUES ($1, $2, $3, 'local-1', 'active')`,
      [id, purpose, fileName],
    );
    return id;
  }
  await db.query(`UPDATE secret_refs SET file_name = $2, version = version + 1 WHERE id = $1`, [existingId, fileName]);
  return existingId;
}

// The row update serializes concurrent additions and rolls back with a failed creation.
async function nextInventoryLabel(db: Db, prefix: "s" | "b"): Promise<string> {
  const result = await db.query<{ value: string }>(
    "UPDATE inventory_name_counters SET value=value+1 WHERE prefix=$1 RETURNING value::text",
    [prefix],
  );
  return `${prefix}-${result.rows[0].value}`;
}
