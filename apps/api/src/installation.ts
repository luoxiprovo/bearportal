import {requestInstallationAllocation,installationRequested} from "./installation-request.ts";
import {allocateProfile} from "../../../packages/servers/src/allocate.ts";
import { createHash, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import type { FastifyInstance, FastifyRequest } from "fastify";
import { classifyBackupReport, evidenceReferenceAccepted } from "../../../packages/operations/src/lifecycle.ts";
import { requireOperation } from "../../../packages/operations/src/registry.ts";
import type { BrevoClient, BrevoDnsRecord } from "../../../packages/providers/brevo/src/index.ts";
import { installerInputSchema } from "../../../packages/contracts/src/index.ts";
import {
  backupReportSchema,
  deploymentCreateSchema,
  emptyObjectSchema,
  mailboxCreateSchema,
  mailboxCredentialSchema,
  mailboxPatchSchema,
  versionedSchema,
} from "../../../packages/contracts/src/index.ts";
import { SecretStore } from "../../../packages/secrets/src/store.ts";
import { assertPublicUnicastIpv4, AddressError } from "../../../packages/servers/src/address.ts";
import { parseCommand } from "../../../packages/servers/src/commands.ts";
import type { Queryable } from "../../../packages/servers/src/allocate.ts";
import {
  activationAllowed,
  assertMailboxLocalPart,
  assertReleaseLayout,
  compareDns,
  customerMailboxLimit,
  DnsObserverUnavailableError,
  installerFingerprint,
  installDomainBlock,
  InstallerUnavailableError,
  isExampleWebmail,
  MailboxNameError,
  parseInstallerResult,
  ReleaseLayoutError,
  sshIdentityAllowsInstall,
  type DnsObserver,
  type InstallerRunner,
  type ObservedRecord,
  type ParsedInstallerResult,
} from "../../../packages/servers/src/installer.ts";
import { BearmailArtifactError } from "../../../packages/servers/src/mail-install.ts";
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
type ReleasePin = { id: string; artifactDir: string };

export type InstallationContext = {
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
  brevoClient: BrevoClient;
  installerRunner: InstallerRunner;
  dnsObserver: DnsObserver;
  release?: ReleasePin;
  installFromSource?: { resolveCommit(): Promise<string> };
  schedulerToken?: string;
};

type SavedDeployment = {
  id: string;
  version: number;
  generation: number;
  domain_id: string | null;
  webmail_hostname: string | null;
  onboarding_stage: string;
  lifecycle_state: string;
  installer_operation_id: string | null;
  installer_input_hash: string | null;
  installer_status: string | null;
  brevo_records: BrevoDnsRecord[] | null;
  brevo_authenticated: boolean;
  brevo_verified: boolean;
  dns_writes_accepted: boolean;
  mx_authorized_at: Date | null;
  admin_secret_ref: string | null;
  relay_connection_id: string | null;
  active_job_id: string | null;
  mail_verified: boolean;
  backup_reported_at: Date | null;
  previous_mx: unknown;
  published_records: unknown;
};

const RECENT_AUTH_SECONDS = 15 * 60;

export function registerInstallationRoutes(app: FastifyInstance, ctx: InstallationContext): void {
  app.post("/v1/deployments", async (request, reply) => {
    const idempotencyKey = ctx.demandIdempotency(request);
    const body = deploymentCreateSchema.parse(request.body);
    const created = await ctx.withActor(request, "customer", (db, actor) =>
      createDeploymentForActor(ctx, db, actor, request, body, idempotencyKey),
    );
    return reply.code(created.status).send({ ...created.body, requestId: request.id });
  });

  app.post("/v1/deployments/:id/provision", async (request, reply) => {
    const idempotencyKey = ctx.demandIdempotency(request);
    const { id } = request.params as { id: string };
    const body = versionedSchema.parse(request.body);
    const created = await ctx.withActor(request, "customer", (db, actor) =>
      provisionDeploymentForActor(ctx, db, actor, request, id, body, idempotencyKey),
    );
    return reply.code(created.status).send({ ...created.body, requestId: request.id });
  });

  app.get("/v1/deployments/:id/dns-plans", async (request) => {
    const { id } = request.params as { id: string };
    return ctx.withActor(request, "customer", async (db, actor) => {
      if (!actor.organizationId) throw new HttpError(404, "NOT_FOUND", "The deployment was not found.");
      const deployment = await db.query<{ previous_mx: unknown; published_records: unknown }>(
        `SELECT previous_mx, published_records FROM deployments WHERE id = $1 AND organization_id = $2`,
        [id, actor.organizationId],
      );
      if (!deployment.rows[0]) throw new HttpError(404, "NOT_FOUND", "The deployment was not found.");
      const plans = await db.query<{ mode: string; previous_mx: unknown; published_records: unknown; status: string }>(
        `SELECT mode, previous_mx, published_records, status FROM installer_runs
         WHERE deployment_id = $1 AND organization_id = $2
         ORDER BY created_at DESC`,
        [id, actor.organizationId],
      );
      const observation = await db.query<{ matches: boolean }>(
        `SELECT matches FROM dns_observations
         WHERE deployment_id = $1 AND organization_id = $2
         ORDER BY created_at DESC LIMIT 1`,
        [id, actor.organizationId],
      );
      const dryRun = plans.rows.find((row) => row.mode === "dry_run");
      const applied = plans.rows.find((row) => row.mode === "apply");
      return {
        approvalGate: false,
        previousMx: applied?.previous_mx ?? dryRun?.previous_mx ?? deployment.rows[0].previous_mx ?? [],
        planned: dryRun?.published_records ?? [],
        published: applied?.published_records ?? deployment.rows[0].published_records ?? [],
        installerStatus: applied?.status ?? dryRun?.status ?? null,
        propagation: observation.rows[0] ? (observation.rows[0].matches ? "matches" : "differs") : "unchecked",
        requestId: request.id,
      };
    });
  });

  app.post("/v1/deployments/:id/dns-recheck", async (request, reply) => {
    const idempotencyKey = ctx.demandIdempotency(request);
    const { id } = request.params as { id: string };
    const body = emptyObjectSchema.parse(request.body ?? {});
    const created = await ctx.withActor(request, "customer", async (db, actor) => {
      ctx.requireVerified(actor);
      if (!actor.organizationId) throw new HttpError(404, "NOT_FOUND", "The deployment was not found.");
      const route = "POST /v1/deployments/:id/dns-recheck";
      const replayed = await ctx.replay(db, actor.userId, route, idempotencyKey, { id, ...body });
      if (replayed) return replayed;
      ctx.consumeLimit(actor.userId, `recheck:${id}`, 12, 60 * 60 * 1000);
      const deployment = await db.query<{ published_records: unknown; domain_id: string | null }>(
        "SELECT published_records, domain_id FROM deployments WHERE id = $1 AND organization_id = $2",
        [id, actor.organizationId],
      );
      const row = deployment.rows[0];
      if (!row) throw new HttpError(404, "NOT_FOUND", "The deployment was not found.");
      const published = Array.isArray(row.published_records) ? row.published_records as Array<{ type: string; host: string; value: string; state: string }> : [];
      if (published.length === 0) {
        return persist(db, ctx, actor, route, idempotencyKey, { id, ...body }, 422, await actionError(db, {
          organizationId: actor.organizationId,
          deploymentId: id,
          serverId: null,
          code: "INSTALLER_RESULT_REQUIRED",
          message: "There is no installer result to compare.",
        }));
      }
      const domain = await db.query<{ normalized_name: string }>(
        "SELECT normalized_name FROM domains WHERE id = $1 AND organization_id = $2",
        [row.domain_id, actor.organizationId],
      );
      if (!domain.rows[0]) throw new HttpError(404, "NOT_FOUND", "The domain was not found.");
      let observed: { records: ObservedRecord[] };
      try {
        observed = await ctx.dnsObserver.observe(domain.rows[0].normalized_name);
      } catch (error) {
        if (error instanceof DnsObserverUnavailableError) {
          return persist(db, ctx, actor, route, idempotencyKey, { id, ...body }, 503, await actionError(db, {
            organizationId: actor.organizationId,
            deploymentId: id,
            serverId: null,
            code: "DNS_OBSERVER_UNAVAILABLE",
            message: "Public DNS observation is not configured.",
            retryable: true,
          }));
        }
        throw error;
      }
      const baselineRow = await db.query<{ desired_records: unknown }>(
        `SELECT desired_records FROM dns_plans
         WHERE domain_id = $1 AND organization_id = $2 AND state = 'read'
         ORDER BY created_at DESC LIMIT 1`,
        [row.domain_id, actor.organizationId],
      );
      const baseline = Array.isArray(baselineRow.rows[0]?.desired_records)
        ? baselineRow.rows[0]!.desired_records as ObservedRecord[]
        : [];
      const compared = compareDns({
        domain: domain.rows[0].normalized_name,
        published,
        observed: observed.records,
        baseline,
      });
      await db.query(
        `INSERT INTO dns_observations (id, organization_id, deployment_id, matches, mx_mismatch, apex_changed, observed)
         VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)`,
        [randomUUID(), actor.organizationId, id, compared.matches, compared.mxMismatch, compared.apexChanged, JSON.stringify(observed.records)],
      );
      let requiredActionId: string | null = null;
      if (compared.apexChanged) {
        requiredActionId = await openAction(db, {
          organizationId: actor.organizationId,
          deploymentId: id,
          serverId: null,
          code: "dns.apex_changed",
          audience: "operator",
          instructions: "A probe shows the apex or www address changed. BearPortal does not repair DNS.",
        });
      }
      const response = {
        matches: compared.matches,
        mxMismatch: compared.mxMismatch,
        apexChanged: compared.apexChanged,
        writesDns: false,
        requiredActionId,
      };
      await ctx.remember(db, actor.userId, route, idempotencyKey, { id, ...body }, 200, response);
      return { status: 200 as const, body: response };
    });
    return reply.code(created.status).send({ ...created.body, requestId: request.id });
  });

  app.get("/v1/deployments/:id/mailboxes", async (request) => {
    const { id } = request.params as { id: string };
    return ctx.withActor(request, "customer", async (db, actor) => {
      if (!actor.organizationId) throw new HttpError(404, "NOT_FOUND", "The deployment was not found.");
      const deployment = await db.query("SELECT id FROM deployments WHERE id = $1 AND organization_id = $2", [id, actor.organizationId]);
      if (!deployment.rows[0]) throw new HttpError(404, "NOT_FOUND", "The deployment was not found.");
      const rows = await db.query(
        `SELECT id, local_part, address, kind, state, receive_enabled, login_enabled, send_enabled,
                credential_reset_required, quota_bytes, usage_bytes, version
         FROM mailboxes WHERE deployment_id = $1 AND organization_id = $2
         ORDER BY created_at, local_part`,
        [id, actor.organizationId],
      );
      return {
        mailboxes: rows.rows.map((mailbox) => ({
          id: mailbox.id,
          localPart: mailbox.local_part,
          address: mailbox.address,
          kind: mailbox.kind,
          state: mailbox.state,
          receiveEnabled: mailbox.receive_enabled,
          loginEnabled: mailbox.login_enabled,
          sendEnabled: mailbox.send_enabled,
          credentialSetupRequired: mailbox.credential_reset_required === true || mailbox.login_enabled !== true,
          quotaBytes: mailbox.quota_bytes == null ? null : Number(mailbox.quota_bytes),
          usageBytes: Number(mailbox.usage_bytes),
          version: mailbox.version,
        })),
        requestId: request.id,
      };
    });
  });

  app.post("/v1/deployments/:id/mailboxes", async (request, reply) => {
    const idempotencyKey = ctx.demandIdempotency(request);
    const { id } = request.params as { id: string };
    const body = mailboxCreateSchema.parse(request.body);
    const created = await ctx.withActor(request, "customer", async (db, actor) => {
      ctx.requireVerified(actor);
      if (!actor.organizationId) throw new HttpError(422, "ORGANIZATION_REQUIRED", "Create an organization first.");
      const route = "POST /v1/deployments/:id/mailboxes";
      const replayed = await ctx.replay(db, actor.userId, route, idempotencyKey, { id, ...body });
      if (replayed) return replayed;
      let localPart: string;
      try {
        localPart = assertMailboxLocalPart(body.localPart);
      } catch (error) {
        if (error instanceof MailboxNameError) throw mailboxHttp(error);
        throw error;
      }
      const deployment = await loadDeployment(db, id, actor.organizationId);
      if (!deployment) throw new HttpError(404, "NOT_FOUND", "The deployment was not found.");
      const domain = await db.query<{ normalized_name: string }>(
        "SELECT normalized_name FROM domains WHERE id = $1 AND organization_id = $2",
        [deployment.domain_id, actor.organizationId],
      );
      if (!domain.rows[0]) throw new HttpError(404, "NOT_FOUND", "The domain was not found.");
      const plan = await loadPlan(db, actor.organizationId);
      const limit = customerMailboxLimit(plan.code, plan.mailbox_limit);
      const count = await db.query<{ n: string }>(
        "SELECT count(*)::text AS n FROM mailboxes WHERE deployment_id = $1 AND kind = 'customer'",
        [id],
      );
      if (Number(count.rows[0]?.n ?? 0) >= limit) {
        return persist(db, ctx, actor, route, idempotencyKey, { id, ...body }, 422, await actionError(db, {
          organizationId: actor.organizationId,
          deploymentId: id,
          serverId: null,
          code: "PLAN_LIMIT",
          message: "The plan has no room for another mailbox.",
        }));
      }
      const quota = body.quotaBytes ?? plan.quota;
      if (quota > plan.quota) {
        return persist(db, ctx, actor, route, idempotencyKey, { id, ...body }, 422, await actionError(db, {
          organizationId: actor.organizationId,
          deploymentId: id,
          serverId: null,
          code: "QUOTA_EXCEEDED",
          message: "The mailbox quota is above the plan.",
        }));
      }
      const disk = await db.query<{ disk_percent: number | null }>(
        `SELECT disk_percent
         FROM health_observations
         WHERE deployment_id = $1 AND organization_id = $2 AND probe = 'disk'
         ORDER BY observed_at DESC
         LIMIT 1`,
        [id, actor.organizationId],
      );
      const diskAction = await db.query<{ id: string }>(
        `SELECT id FROM required_actions
         WHERE state = 'open' AND code = 'capacity.disk' AND organization_id = $1
         LIMIT 1`,
        [actor.organizationId],
      );
      const diskPercent = disk.rows[0]?.disk_percent;
      if ((diskPercent == null ? 0 : Number(diskPercent)) >= 90 || diskAction.rows[0]) {
        return persist(db, ctx, actor, route, idempotencyKey, { id, ...body }, 422, await actionError(db, {
          organizationId: actor.organizationId,
          deploymentId: id,
          serverId: null,
          code: "capacity.disk",
          message: "Disk use needs an operator. Mail is not deleted.",
        }));
      }
      const mailboxId = randomUUID();
      await insertMailbox(db, {
        id: mailboxId,
        organizationId: actor.organizationId,
        deploymentId: id,
        localPart,
        domain: domain.rows[0].normalized_name,
        kind: "customer",
        quotaBytes: quota,
        aliasFor: null,
      });
      const jobId = randomUUID();
      await db.query(
        `INSERT INTO jobs (id, organization_id, deployment_id, kind, state, checkpoint, lease_owner, lease_expires_at, fencing_token)
         VALUES ($1, $2, $3, 'sync_mailboxes', 'queued', '{"applied":false}'::jsonb, 'api', now() + interval '120 seconds', 1)`,
        [jobId, actor.organizationId, id],
      );
      const response = { jobId, state: "queued", mailboxId, applied: false };
      await ctx.remember(db, actor.userId, route, idempotencyKey, { id, ...body }, 202, response);
      return { status: 202 as const, body: response };
    });
    return reply.code(created.status).send({ ...created.body, requestId: request.id });
  });

  app.patch("/v1/mailboxes/:id", async (request, reply) => {
    const idempotencyKey = ctx.demandIdempotency(request);
    const { id } = request.params as { id: string };
    const body = mailboxPatchSchema.parse(request.body);
    const created = await ctx.withActor(request, "customer", async (db, actor) => {
      ctx.requireVerified(actor);
      if (!actor.organizationId) throw new HttpError(422, "ORGANIZATION_REQUIRED", "Create an organization first.");
      const route = "PATCH /v1/mailboxes/:id";
      const replayed = await ctx.replay(db, actor.userId, route, idempotencyKey, { id, ...body });
      if (replayed) return replayed;
      const mailbox = await db.query<{
        version: number;
        deployment_id: string;
        credential_reset_required: boolean;
        receive_enabled: boolean;
        kind: string;
      }>(
        `SELECT version, deployment_id, credential_reset_required, receive_enabled, kind
         FROM mailboxes WHERE id = $1 AND organization_id = $2`,
        [id, actor.organizationId],
      );
      const row = mailbox.rows[0];
      if (!row) throw new HttpError(404, "NOT_FOUND", "The mailbox was not found.");
      if (row.version !== body.expectedVersion) throw new HttpError(409, "VERSION_CONFLICT", "The mailbox changed.");
      if (body.loginEnabled === true) {
        return persist(db, ctx, actor, route, idempotencyKey, { id, ...body }, 422, await actionError(db, {
          organizationId: actor.organizationId,
          deploymentId: row.deployment_id,
          serverId: null,
          code: "CREDENTIAL_REQUIRED",
          message: "Public login stays disabled until credential setup succeeds.",
        }));
      }
      const plan = await loadPlan(db, actor.organizationId);
      if (body.quotaBytes != null && body.quotaBytes > plan.quota) {
        return persist(db, ctx, actor, route, idempotencyKey, { id, ...body }, 422, await actionError(db, {
          organizationId: actor.organizationId,
          deploymentId: row.deployment_id,
          serverId: null,
          code: "QUOTA_EXCEEDED",
          message: "The mailbox quota is above the plan.",
        }));
      }
      await db.query(
        `UPDATE mailboxes
         SET login_enabled = COALESCE($2, login_enabled),
             send_enabled = COALESCE($3, send_enabled),
             receive_enabled = COALESCE($4, receive_enabled),
             quota_bytes = COALESCE($5, quota_bytes),
             version = version + 1,
             updated_at = now()
         WHERE id = $1`,
        [id, body.loginEnabled ?? null, body.sendEnabled ?? null, body.receiveEnabled ?? null, body.quotaBytes ?? null],
      );
      const jobId = randomUUID();
      await db.query(
        `INSERT INTO jobs (id, organization_id, deployment_id, kind, state, checkpoint, lease_owner, lease_expires_at, fencing_token)
         VALUES ($1, $2, $3, 'sync_mailboxes', 'queued', '{"applied":false}'::jsonb, 'api', now() + interval '120 seconds', 1)`,
        [jobId, actor.organizationId, row.deployment_id],
      );
      const response = {
        jobId,
        state: "queued",
        applied: false,
        inbound: body.receiveEnabled == null ? "unchanged" : body.receiveEnabled ? "enabled" : "disabled",
        loginEnabled: false,
      };
      await ctx.remember(db, actor.userId, route, idempotencyKey, { id, ...body }, 202, response);
      return { status: 202 as const, body: response };
    });
    return reply.code(created.status).send({ ...created.body, requestId: request.id });
  });

  app.post("/v1/mailboxes/:id/credential", async (request, reply) => {
    const idempotencyKey = ctx.demandIdempotency(request);
    const { id } = request.params as { id: string };
    const body = mailboxCredentialSchema.parse(request.body);
    const created = await ctx.withActor(request, "customer", async (db, actor) => {
      ctx.requireVerified(actor);
      if (!actor.organizationId) throw new HttpError(422, "ORGANIZATION_REQUIRED", "Create an organization first.");
      const route = "POST /v1/mailboxes/:id/credential";
      const replayed = await ctx.replay(db, actor.userId, route, idempotencyKey, { id, ...body });
      if (replayed) return replayed;
      const fresh = actor.authTime > 0 && Math.floor(Date.now() / 1000) - actor.authTime <= RECENT_AUTH_SECONDS;
      if (!fresh) throw new HttpError(403, "RECENT_AUTH_REQUIRED", "Sign in again before choosing a mailbox password.");
      requireOperation("mailbox.credential");
      const mailbox = await db.query<{ deployment_id: string; kind: string }>(
        "SELECT deployment_id, kind FROM mailboxes WHERE id = $1 AND organization_id = $2",
        [id, actor.organizationId],
      );
      const row = mailbox.rows[0];
      if (!row) throw new HttpError(404, "NOT_FOUND", "The mailbox was not found.");
      if (row.kind !== "customer") throw new HttpError(422, "RESERVED_LOCAL_PART", "That mailbox does not take a customer password.");
      const host = await loadHost(db, actor.organizationId);
      if (!host) {
        return persist(db, ctx, actor, route, idempotencyKey, { id, ...body }, 422, await actionError(db, {
          organizationId: actor.organizationId,
          deploymentId: row.deployment_id,
          serverId: null,
          code: "inventory.server_required",
          message: "An assigned server is required before a password can be delivered.",
        }));
      }
      ctx.consumeLimit(actor.userId, "mailbox-credential", 10, 60 * 60 * 1000);
      const fileName = ctx.secrets.write(JSON.stringify({ password: body.newPassword }));
      const secretId = randomUUID();
      await db.query(
        `INSERT INTO secret_refs (id, organization_id, purpose, file_name, key_id, state)
         VALUES ($1, $2, 'mailbox-credential', $3, 'local-1', 'active')`,
        [secretId, actor.organizationId, fileName],
      );
      await db.query(
        `UPDATE mailboxes
         SET credential_secret_ref = $2, credential_expires_at = now() + interval '15 minutes',
             login_enabled = false, credential_reset_required = true, updated_at = now(), version = version + 1
         WHERE id = $1`,
        [id, secretId],
      );
      const jobId = randomUUID();
      await db.query(
        `INSERT INTO jobs (
           id, organization_id, deployment_id, kind, state, checkpoint, lease_owner, lease_expires_at, fencing_token
         ) VALUES ($1, $2, $3, 'set_mailbox_credential', 'queued', $4::jsonb, 'api', now() + interval '120 seconds', 1)`,
        [jobId, actor.organizationId, row.deployment_id, JSON.stringify({ secretRef: secretId, outcome: "pending" })],
      );
      await ctx.setActor(db, "platform_administrator");
      await queueCommand(db, {
        serverId: host.id,
        organizationId: actor.organizationId,
        deploymentId: row.deployment_id,
        jobId,
        generation: host.assignment_generation,
        authEpoch: host.auth_epoch,
        commandType: "set_mailbox_credential",
        parameters: {},
      });
      await db.query(
        "UPDATE servers SET tenant_tainted_at = coalesce(tenant_tainted_at, now()), updated_at = now(), version = version + 1 WHERE id = $1",
        [host.id],
      );
      await ctx.setActor(db, "customer");
      await ctx.audit(db, request, actor.userId, actor.organizationId, "mailbox.credential", id, { mailboxId: id });
      const response = { jobId, state: "queued", credentialApplied: false };
      await ctx.remember(db, actor.userId, route, idempotencyKey, { id, ...body }, 202, response);
      return { status: 202 as const, body: response };
    });
    return reply.code(created.status).send({ ...created.body, requestId: request.id });
  });

  app.post("/v1/admin/deployments/:id/backup-report", async (request, reply) => {
    const idempotencyKey = ctx.demandIdempotency(request);
    const { id } = request.params as { id: string };
    const body = backupReportSchema.parse(request.body);
    const created = await ctx.withActor(request, "operator", async (db, actor) => {
      assertWriter(ctx, actor);
      const route = "POST /v1/admin/deployments/:id/backup-report";
      const replayed = await ctx.replay(db, actor.userId, route, idempotencyKey, { id, ...body });
      if (replayed) return replayed;
      const recorded = await recordBackupReport(db, actor.userId, id, body);
      await ctx.audit(db, request, actor.userId, recorded.organizationId, "deployment.backup_report", id, { evidenceRef: body.evidenceRef, state: recorded.response.state ?? "recorded" });
      await ctx.remember(db, actor.userId, route, idempotencyKey, { id, ...body }, 200, recorded.response);
      return { status: 200 as const, body: recorded.response };
    });
    return reply.code(created.status).send({ ...created.body, requestId: request.id });
  });

  app.post("/internal/mailbox-credentials/expire", async (request, reply) => {
    if (!ctx.schedulerToken) {
      throw new HttpError(503, "SCHEDULER_UNAVAILABLE", "The scheduler identity is not configured.", true);
    }
    const header = request.headers["x-bearportal-scheduler"];
    if (!schedulerAuthorized(typeof header === "string" ? header : undefined, ctx.schedulerToken)) {
      throw new HttpError(401, "UNAUTHENTICATED", "The scheduler identity was rejected.");
    }
    emptyObjectSchema.parse(request.body ?? {});
    const created = await ctx.withSystem("inventory_worker", async (db) => {
      const rows = await db.query<{ id: string; file_name: string; mailbox_id: string }>(
        `SELECT s.id, s.file_name, m.id AS mailbox_id
         FROM mailboxes m
         JOIN secret_refs s ON s.id = m.credential_secret_ref
         WHERE m.credential_expires_at < now() AND s.state = 'active' AND s.purpose = 'mailbox-credential'`,
      );
      for (const row of rows.rows) {
        ctx.secrets.destroy(row.file_name);
        await db.query(
          `UPDATE secret_refs SET state = 'retired', retired_at = now(), version = version + 1
           WHERE id = $1 AND purpose = 'mailbox-credential'`,
          [row.id],
        );
        await db.query(
          `UPDATE mailboxes
           SET credential_secret_ref = NULL, credential_expires_at = NULL, login_enabled = false, updated_at = now(), version = version + 1
           WHERE id = $1`,
          [row.mailbox_id],
        );
      }
      return { status: 200 as const, body: { expired: rows.rows.length } };
    });
    return reply.code(created.status).send({ ...created.body, requestId: request.id });
  });
}

export async function repairAssignedAddress(
  ctx: InstallationContext,
  db: Db,
  input: { serverId: string; organizationId: string; publicIpv4: string },
): Promise<{ jobId: string; installerStarted: boolean } | null> {
  const deployment = await db.query<SavedDeployment & { normalized_name: string; provider: string; zone_id: string; secret_ref: string }>(
    `SELECT d.id, d.version, d.generation, d.domain_id, d.webmail_hostname, d.onboarding_stage, d.lifecycle_state,
            d.installer_operation_id, d.installer_input_hash, d.installer_status, d.brevo_records,
            d.brevo_authenticated, d.brevo_verified, d.dns_writes_accepted, d.mx_authorized_at,
            d.admin_secret_ref, d.relay_connection_id, d.active_job_id, d.mail_verified,
            d.backup_reported_at, d.previous_mx, d.published_records,
            domains.normalized_name, c.provider, c.zone_id, c.secret_ref
     FROM deployments d
     JOIN domains ON domains.id = d.domain_id AND domains.organization_id = d.organization_id
     JOIN dns_connections c ON c.domain_id = d.domain_id AND c.organization_id = d.organization_id
     WHERE d.organization_id = $1 AND d.lifecycle_state <> 'deleted'
       AND d.mx_authorized_at IS NOT NULL AND d.brevo_records IS NOT NULL
     ORDER BY d.created_at DESC
     LIMIT 1`,
    [input.organizationId],
  );
  const row = deployment.rows[0];
  if (!row || !row.brevo_records || !row.admin_secret_ref || !row.relay_connection_id) return null;
  const relay = await db.query<{ smtp_login: string; smtp_secret_ref: string }>(
    "SELECT smtp_login, smtp_secret_ref FROM relay_connections WHERE id = $1",
    [row.relay_connection_id],
  );
  if (!relay.rows[0]) return null;
  let publicIpv4 = input.publicIpv4;
  try {
    publicIpv4 = assertPublicUnicastIpv4(input.publicIpv4);
  } catch (error) {
    if (error instanceof AddressError) return null;
    throw error;
  }
  const operationId = randomUUID();
  const generation = row.generation + 1;
  const jobId = randomUUID();
  const records = row.brevo_records;
  const inputHash = installerFingerprint({
    domain: row.normalized_name,
    mailHostname: `mail.${row.normalized_name}`,
    webmailHostname: row.webmail_hostname ?? `bearmail.${row.normalized_name}`,
    publicIpv4,
    provider: row.provider,
    zone: row.zone_id,
    brevoRecords: records,
    relayHost: "smtp-relay.brevo.com",
  });
  await db.query(
    `INSERT INTO jobs (id, organization_id, deployment_id, generation, kind, state, checkpoint, lease_owner, lease_expires_at, fencing_token)
     VALUES ($1, $2, $3, $4, 'dns.address_update', 'queued', $5::jsonb, 'api', now() + interval '120 seconds', 1)`,
    [jobId, input.organizationId, row.id, generation, JSON.stringify({ installerStarted: false, operationId, ipProof: "not_performed" })],
  );
  await db.query(
    `UPDATE deployments
     SET installer_operation_id = $2, generation = $3, installer_input_hash = $4, active_job_id = $5, version = version + 1, updated_at = now()
     WHERE id = $1`,
    [row.id, operationId, generation, inputHash, jobId],
  );
  const releasePin = await sourceRelease(ctx, operationId);
  if (!releasePin) return { jobId, installerStarted: false };
  if (ctx.release) {
    try {
      assertReleaseLayout(ctx.release.artifactDir, ctx.release.id);
    } catch {
      return { jobId, installerStarted: false };
    }
  }
  const plan = await loadPlan(db, input.organizationId);
  const inputJson = installerInput(releasePin, {
    operationId,
    deploymentId: row.id,
    generation,
    domain: row.normalized_name,
    webmailHostname: row.webmail_hostname ?? `bearmail.${row.normalized_name}`,
    publicIpv4,
    provider: row.provider as "namecom" | "hostinger" | "godaddy",
    zone: row.zone_id,
    dnsSecretId: row.secret_ref,
    brevoRecords: records,
    smtpLogin: relay.rows[0].smtp_login,
    smtpSecretId: relay.rows[0].smtp_secret_ref,
    adminSecretId: row.admin_secret_ref,
    quotaBytes: plan.quota,
    adminPassword: "",
  });
  const ran = await executeInstaller(ctx, db, {
    organizationId: input.organizationId,
    deploymentId: row.id,
    operationId,
    generation,
    modeStop: "apply",
    input: inputJson,
  });
  if (ran.unavailable || !ran.apply) {
    if (ran.dryRun && (ran.dryRun.errorCode === "DNS_RECORD_CONFLICT" || ran.dryRun.status === "failed")) {
      await openAction(db, {
        organizationId: input.organizationId,
        deploymentId: row.id,
        serverId: input.serverId,
        code: "dns.address_drift",
        audience: "operator",
        instructions: "The address dry-run found a conflict. BearPortal did not publish DNS.",
      });
    }
    return { jobId, installerStarted: false };
  }
  await db.query(
    `UPDATE jobs SET checkpoint = $2::jsonb, updated_at = now(), version = version + 1 WHERE id = $1`,
    [jobId, JSON.stringify({
      installerStarted: true,
      operationId,
      status: ran.apply.status,
      dnsWritesAccepted: ran.apply.dnsWritesAccepted,
      ipProof: "not_performed",
    })],
  );
  await db.query(
    `UPDATE deployments
     SET installer_status = $2, previous_mx = $3::jsonb, published_records = $4::jsonb,
         dns_writes_accepted = $5, observed_ip = CASE WHEN $5 THEN $6::inet ELSE observed_ip END,
         ip_observed_at = CASE WHEN $5 THEN now() ELSE ip_observed_at END,
         mail_verified = false, updated_at = now()
     WHERE id = $1`,
    [row.id, ran.apply.status, JSON.stringify(ran.apply.previousMx), JSON.stringify(ran.apply.published), ran.apply.dnsWritesAccepted, publicIpv4],
  );
  if (ran.apply.dnsWritesAccepted && !row.brevo_authenticated) {
    try {
      requireOperation("brevo.authenticate");
      const auth = await ctx.brevoClient.authenticate(row.normalized_name);
      await db.query(
        "UPDATE deployments SET brevo_authenticated = $2, brevo_verified = $3, updated_at = now() WHERE id = $1",
        [row.id, auth.authenticated === true, auth.verified === true],
      );
    } catch {
      await openAction(db, {
        organizationId: input.organizationId,
        deploymentId: row.id,
        serverId: input.serverId,
        code: "brevo.authenticate_pending",
        audience: "operator",
        instructions: "Brevo authentication did not complete after the address update.",
      });
    }
  }
  return { jobId, installerStarted: true };
}

type InstallerCall = {
  organizationId: string;
  deploymentId: string;
  operationId: string;
  generation: number;
  modeStop: "dry_run" | "apply";
  input: Record<string, unknown>;
};

async function executeInstaller(
  ctx: InstallationContext,
  db: Db,
  call: InstallerCall,
): Promise<{ dryRun: ParsedInstallerResult | null; apply: ParsedInstallerResult | null; unavailable: boolean }> {
  requireOperation("installer.run");
  let dryRun: ParsedInstallerResult | null;
  try {
    dryRun = await oneRun(ctx, db, call, "dry_run");
  } catch (error) {
    if (error instanceof InstallerUnavailableError) return { dryRun: null, apply: null, unavailable: true };
    throw error;
  }
  if (!dryRun || dryRun.status !== "dry_run" || dryRun.errorCode) return { dryRun, apply: null, unavailable: false };
  if (call.modeStop === "dry_run") {
    let apply: ParsedInstallerResult | null;
    try {
      apply = await oneRun(ctx, db, call, "apply");
    } catch (error) {
      if (error instanceof InstallerUnavailableError) return { dryRun, apply: null, unavailable: true };
      throw error;
    }
    return { dryRun, apply, unavailable: false };
  }
  let apply: ParsedInstallerResult | null;
  try {
    apply = await oneRun(ctx, db, call, "apply");
  } catch (error) {
    if (error instanceof InstallerUnavailableError) return { dryRun, apply: null, unavailable: true };
    throw error;
  }
  return { dryRun, apply, unavailable: false };
}

async function oneRun(
  ctx: InstallationContext,
  db: Db,
  call: InstallerCall,
  mode: "dry_run" | "apply",
): Promise<ParsedInstallerResult | null> {
  const raw = await ctx.installerRunner.run({ mode, input: call.input });
  const parsed = parseInstallerResult(raw);
  const stored = parsed ?? {
    status: "failed" as const,
    exitCode: 1,
    retryable: false,
    errorCode: "INVALID_INPUT",
    previousMx: [],
    published: [],
    dnsWritesAccepted: false,
    minimumTtl: null,
    engineDkimHost: null,
    engineDkimValue: null,
  };
  if (JSON.stringify(raw).includes("\"password\"") || JSON.stringify(raw).includes("\"smtpKey\"") || JSON.stringify(raw).includes("\"apiKey\"")) {
    stored.status = "failed";
    stored.errorCode = "SECRET_LEAK";
    stored.dnsWritesAccepted = false;
    stored.published = [];
  }
  await db.query(
    `INSERT INTO installer_runs (
       id, organization_id, deployment_id, operation_id, generation, mode, status, exit_code, retryable,
       error_code, previous_mx, published_records, dns_writes_accepted, result
     ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb, $12::jsonb, $13, $14::jsonb)
     ON CONFLICT (deployment_id, operation_id, mode) DO UPDATE SET
       status = EXCLUDED.status,
       exit_code = EXCLUDED.exit_code,
       retryable = EXCLUDED.retryable,
       error_code = EXCLUDED.error_code,
       previous_mx = EXCLUDED.previous_mx,
       published_records = EXCLUDED.published_records,
       dns_writes_accepted = EXCLUDED.dns_writes_accepted,
       result = EXCLUDED.result,
       updated_at = now(),
       version = installer_runs.version + 1`,
    [
      randomUUID(),
      call.organizationId,
      call.deploymentId,
      call.operationId,
      call.generation,
      mode,
      stored.status,
      stored.exitCode,
      stored.retryable,
      stored.errorCode,
      JSON.stringify(stored.previousMx),
      JSON.stringify(stored.published),
      stored.dnsWritesAccepted,
      JSON.stringify({
        schemaVersion: 1,
        status: stored.status,
        exitCode: stored.exitCode,
        retryable: stored.retryable,
        errorCode: stored.errorCode,
        dns: {
          previousMx: stored.previousMx,
          published: stored.published,
          minimumTtl: stored.minimumTtl,
          engineDkimHost: stored.engineDkimHost,
          engineDkimValue: stored.engineDkimValue,
        },
      }),
    ],
  );
  return stored;
}

function installerInput(release: ReleasePin, fields: {
  webmailHostname: string;
  operationId: string;
  deploymentId: string;
  generation: number;
  domain: string;
  publicIpv4: string;
  provider: "namecom" | "hostinger" | "godaddy";
  zone: string;
  dnsSecretId: string;
  brevoRecords: BrevoDnsRecord[];
  smtpLogin: string;
  smtpSecretId: string;
  adminSecretId: string;
  quotaBytes: number;
  adminPassword: string;
}): Record<string, unknown> {
  const input = {
    schemaVersion: 1,
    operationId: fields.operationId,
    deploymentId: fields.deploymentId,
    generation: fields.generation,
    mxCutoverAuthorized: true,
    domain: fields.domain,
    mailHostname: `mail.${fields.domain}`,
    webmailHostname: fields.webmailHostname,
    publicIpv4: fields.publicIpv4,
    publicIpv6: null,
    dataPath: "/var/lib/stalwart",
    dns: { provider: fields.provider, zone: fields.zone, credentialFile: `secret:${fields.dnsSecretId}` },
    ...(fields.brevoRecords.length > 0 ? { brevoDnsRecords: fields.brevoRecords } : {}),
    relay: {
      host: "smtp-relay.brevo.com",
      port: 587,
      tls: "starttls-required",
      login: fields.smtpLogin,
      credentialFile: `secret:${fields.smtpSecretId}`,
    },
    adminCredentialFile: `secret:${fields.adminSecretId}`,
    mailboxQuotaBytes: fields.quotaBytes,
    release: {
      id: release.id,
      artifactDir: release.artifactDir,
      checksumFile: `${release.artifactDir}/SHA256SUMS`,
    },
  };
  if (fields.adminPassword && JSON.stringify(input).includes(fields.adminPassword)) {
    throw new Error("Installer input included the admin password.");
  }
  return installerInputSchema.parse(input);
}

export async function ensureAdminSecret(
  db: Db,
  ctx: InstallationContext,
  organizationId: string,
  deploymentId: string,
  existing: string | null,
  domain: string,
): Promise<{ secretId: string; password: string }> {
  if (existing) return { secretId: existing, password: "" };
  const password = randomBytes(24).toString("base64url");
  const fileName = ctx.secrets.write(JSON.stringify({ username: `admin@${domain}`, password }));
  const secretId = randomUUID();
  await db.query(
    `INSERT INTO secret_refs (id, organization_id, purpose, file_name, key_id, state)
     VALUES ($1, $2, 'installer-admin', $3, 'local-1', 'active')`,
    [secretId, organizationId, fileName],
  );
  await db.query("UPDATE deployments SET admin_secret_ref = $2, updated_at = now() WHERE id = $1", [deploymentId, secretId]);
  return { secretId, password };
}

async function assignRelay(db: Db, organizationId: string): Promise<{ id: string; smtp_login: string; smtp_secret_ref: string } | null> {
  if(!await installationRequested(db,organizationId))return null;
  const existing = await db.query<{ id: string; smtp_login: string; smtp_secret_ref: string }>(
    `SELECT r.id, r.smtp_login, r.smtp_secret_ref
     FROM relay_assignments a
     JOIN relay_connections r ON r.id = a.relay_connection_id
     WHERE a.organization_id = $1 AND a.released_at IS NULL
     LIMIT 1`,
    [organizationId],
  );
  if (existing.rows[0]) return existing.rows[0];
  const available = await db.query<{ id: string; smtp_login: string; smtp_secret_ref: string }>(
    `SELECT id, smtp_login, smtp_secret_ref
     FROM relay_connections
     WHERE state = 'available' AND provider = 'brevo'
     ORDER BY created_at, id
     LIMIT 1`,
  );
  const relay = available.rows[0];
  if (!relay) return null;
  const updated = await db.query(
    `UPDATE relay_connections
     SET state = 'assigned', version = version + 1, updated_at = now()
     WHERE id = $1 AND state = 'available'
     RETURNING id`,
    [relay.id],
  );
  if (!updated.rows[0]) return null;
  await db.query(
    "INSERT INTO relay_assignments (id, organization_id, relay_connection_id) VALUES ($1, $2, $3)",
    [randomUUID(), organizationId, relay.id],
  );
  return relay;
}

async function loadHost(db: Db, organizationId: string): Promise<{
  id: string;
  public_ipv4: string;
  state: string;
  auth_epoch: number;
  profile_code: string;
  assignment_id: string;
  assignment_generation: number;
  identity_state: string | null;
  readiness_source: string | null;
} | null> {
  const rows = await db.query<{
    id: string;
    public_ipv4: string;
    state: string;
    auth_epoch: number;
    profile_code: string;
    assignment_id: string;
    assignment_generation: number;
    identity_state: string | null;
    readiness_source: string | null;
  }>(
    `SELECT s.id, host(s.public_ipv4) AS public_ipv4, s.state, s.auth_epoch, s.profile_code,
            a.id AS assignment_id, a.generation AS assignment_generation, i.state AS identity_state,
            s.readiness_report->>'source' AS readiness_source
     FROM server_assignments a
     JOIN servers s ON s.id = a.server_id
     LEFT JOIN host_identities i ON i.id = s.host_identity_id
     WHERE a.organization_id = $1 AND a.released_at IS NULL
     LIMIT 1`,
    [organizationId],
  );
  return rows.rows[0] ?? null;
}

async function sourceRelease(ctx: InstallationContext, operationId: string): Promise<ReleasePin | null> {
  if (ctx.release) return ctx.release;
  if (!ctx.installFromSource) return null;
  try {
    const commit = await ctx.installFromSource.resolveCommit();
    if (!/^[0-9a-f]{40}$/.test(commit)) return null;
    return { id: commit, artifactDir: `/var/lib/bearportal/install/${operationId}/${commit}` };
  } catch (error) {
    if (error instanceof BearmailArtifactError || error instanceof InstallerUnavailableError) return null;
    throw error;
  }
}

async function loadDeployment(db: Db, id: string, organizationId: string): Promise<SavedDeployment | null> {
  const rows = await db.query<SavedDeployment>(
    `SELECT id, version, generation, domain_id, webmail_hostname, onboarding_stage, lifecycle_state, installer_operation_id,
            installer_input_hash, installer_status, brevo_records, brevo_authenticated, brevo_verified,
            dns_writes_accepted, mx_authorized_at, admin_secret_ref, relay_connection_id, active_job_id,
            mail_verified, backup_reported_at, previous_mx, published_records
     FROM deployments WHERE id = $1 AND organization_id = $2`,
    [id, organizationId],
  );
  return rows.rows[0] ?? null;
}

async function loadDomainLink(db: Db, domainId: string | null, organizationId: string): Promise<{
  normalized_name: string;
  state: string;
  provider: "namecom" | "hostinger" | "godaddy";
  zone_id: string;
  secret_ref: string | null;
} | null> {
  if (!domainId) return null;
  const rows = await db.query<{
    normalized_name: string;
    state: string;
    provider: "namecom" | "hostinger" | "godaddy" | null;
    zone_id: string | null;
    secret_ref: string | null;
  }>(
    `SELECT d.normalized_name, d.state, c.provider, c.zone_id, c.secret_ref
     FROM domains d
     LEFT JOIN dns_connections c ON c.domain_id = d.id AND c.organization_id = d.organization_id
     WHERE d.id = $1 AND d.organization_id = $2
     ORDER BY c.created_at DESC NULLS LAST
     LIMIT 1`,
    [domainId, organizationId],
  );
  const row = rows.rows[0];
  if (!row || !row.provider || !row.zone_id) {
    return row ? { normalized_name: row.normalized_name, state: row.state, provider: "namecom", zone_id: "", secret_ref: null } : null;
  }
  return {
    normalized_name: row.normalized_name,
    state: row.state,
    provider: row.provider,
    zone_id: row.zone_id,
    secret_ref: row.secret_ref,
  };
}

async function loadPlan(db: Db, organizationId: string): Promise<{
  id: string;
  code: string;
  revision: number;
  mailbox_limit: number;
  quota: number;
  server_profile_code: string;
}> {
  const assigned = await db.query<{ plan_id: string | null }>("SELECT plan_id FROM organizations WHERE id = $1", [organizationId]);
  const rows = assigned.rows[0]?.plan_id
    ? await db.query<{ id: string; code: string; revision: number; mailbox_limit: number; mailbox_quota_bytes: string; server_profile_code: string }>(
      "SELECT id, code, revision, mailbox_limit, mailbox_quota_bytes, server_profile_code FROM plans WHERE id = $1",
      [assigned.rows[0].plan_id],
    )
    : await db.query<{ id: string; code: string; revision: number; mailbox_limit: number; mailbox_quota_bytes: string; server_profile_code: string }>(
      "SELECT id, code, revision, mailbox_limit, mailbox_quota_bytes, server_profile_code FROM plans WHERE code = 'beta' AND revision = 1",
    );
  const plan = rows.rows[0];
  if (!plan) throw new HttpError(422, "PLAN_REQUIRED", "No plan is available for this organization.");
  return {
    id: plan.id,
    code: plan.code,
    revision: plan.revision,
    mailbox_limit: plan.mailbox_limit,
    quota: Number(plan.mailbox_quota_bytes),
    server_profile_code: plan.server_profile_code,
  };
}

async function insertMailbox(db: Db, input: {
  id: string;
  organizationId: string;
  deploymentId: string;
  localPart: string;
  domain: string;
  kind: "customer" | "system_test" | "system_admin" | "system_alias";
  quotaBytes: number | null;
  aliasFor: string | null;
}): Promise<void> {
  await db.query(
    `INSERT INTO mailboxes (
       id, organization_id, deployment_id, local_part, address, kind, state,
       receive_enabled, login_enabled, send_enabled, credential_reset_required, quota_bytes, alias_for
     ) VALUES ($1, $2, $3, $4, $5, $6, 'pending', true, false, false, $7, $8, $9)`,
    [
      input.id,
      input.organizationId,
      input.deploymentId,
      input.localPart,
      `${input.localPart}@${input.domain}`,
      input.kind,
      input.kind === "system_alias" ? false : true,
      input.quotaBytes,
      input.aliasFor,
    ],
  );
}

async function queueCommand(db: Db, input: {
  serverId: string;
  organizationId: string;
  deploymentId: string;
  jobId: string;
  generation: number;
  authEpoch: number;
  commandType: string;
  parameters: Record<string, unknown>;
}): Promise<void> {
  const parsed = parseCommand(input.commandType, input.parameters);
  if (!parsed || parsed.scope !== "tenant") throw new HttpError(400, "UNKNOWN_COMMAND", "That command is not allowed.");
  const payloadHash = createHash("sha256").update(JSON.stringify(parsed.parameters)).digest("hex");
  await db.query(
    `INSERT INTO host_commands (
       id, server_id, job_id, organization_id, deployment_id, generation, auth_epoch, command_type, payload, payload_hash, state, expires_at
     ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10, 'queued', now() + interval '15 minutes')`,
    [
      randomUUID(),
      input.serverId,
      input.jobId,
      input.organizationId,
      input.deploymentId,
      input.generation,
      input.authEpoch,
      parsed.commandType,
      JSON.stringify(parsed.parameters),
      payloadHash,
    ],
  );
}

async function waitingJob(db: Db, organizationId: string, deploymentId: string, kind: string, code: string): Promise<string> {
  const existing = await db.query<{ id: string }>(
    `SELECT id FROM jobs
     WHERE organization_id = $1 AND deployment_id = $2 AND kind = $3 AND state = 'waiting_human'
     ORDER BY created_at DESC LIMIT 1`,
    [organizationId, deploymentId, kind],
  );
  if (existing.rows[0]) return existing.rows[0].id;
  const jobId = randomUUID();
  await db.query(
    `INSERT INTO jobs (id, organization_id, deployment_id, kind, state, checkpoint)
     VALUES ($1, $2, $3, $4, 'waiting_human', $5::jsonb)`,
    [jobId, organizationId, deploymentId, kind, JSON.stringify({ installerStarted: false, code })],
  );
  return jobId;
}

async function authorizeDeployment(db: Db, id: string, organizationId: string, expectedVersion: number): Promise<number> {
  const updated = await db.query<{ version: number }>(
    `UPDATE deployments
     SET mx_authorized_at = coalesce(mx_authorized_at, now()),
         desired_state = 'running',
         lifecycle_state = CASE WHEN lifecycle_state = 'draft' THEN 'onboarding' ELSE lifecycle_state END,
         onboarding_stage = CASE WHEN onboarding_stage = 'draft' THEN 'dns_credential_check' ELSE onboarding_stage END,
         version = version + 1,
         updated_at = now()
     WHERE id = $1 AND organization_id = $2 AND version = $3
     RETURNING version`,
    [id, organizationId, expectedVersion],
  );
  if (!updated.rows[0]) throw new HttpError(409, "VERSION_CONFLICT", "The deployment changed.");
  return updated.rows[0].version;
}

async function rememberDryRun(
  db: Db,
  deploymentId: string,
  organizationId: string,
  linked: { normalized_name: string },
  dryRun: ParsedInstallerResult | null,
): Promise<void> {
  if (!dryRun) return;
  const domain = await db.query<{ id: string }>(
    "SELECT id FROM domains WHERE normalized_name = $1 AND organization_id = $2",
    [linked.normalized_name, organizationId],
  );
  if (!domain.rows[0]) return;
  const fingerprint = createHash("sha256").update(JSON.stringify(dryRun.published)).digest("hex");
  await db.query(
    `INSERT INTO dns_plans (
       id, organization_id, domain_id, purpose, base_fingerprint, desired_records, operations, plan_hash, state
     ) VALUES ($1, $2, $3, 'installer_dry_run', $4, $5::jsonb, $6::jsonb, $4, 'planned')`,
    [
      randomUUID(),
      organizationId,
      domain.rows[0].id,
      fingerprint,
      JSON.stringify(dryRun.published),
      JSON.stringify({ previousMx: dryRun.previousMx, approvalGate: false }),
    ],
  );
}

async function actionError(db: Db, input: {
  organizationId: string;
  deploymentId: string;
  serverId: string | null;
  code: string;
  message: string;
  retryable?: boolean;
}): Promise<{ error: { code: string; message: string; retryable: boolean; requiredActionId: string | null } }> {
  const requiredActionId = await openAction(db, {
    organizationId: input.organizationId,
    deploymentId: input.deploymentId,
    serverId: input.serverId,
    code: input.code,
    audience: input.code.startsWith("domain.") ? "customer" : "operator",
    instructions: input.message,
  });
  return {
    error: {
      code: input.code,
      message: input.message,
      retryable: input.retryable ?? false,
      requiredActionId,
    },
  };
}

async function persist(
  db: Db,
  ctx: InstallationContext,
  actor: Actor,
  route: string,
  key: string,
  body: unknown,
  status: number,
  response: { error: { code: string; message: string; retryable: boolean; requiredActionId: string | null } },
): Promise<{ status: number; body: typeof response }> {
  await ctx.remember(db, actor.userId, route, key, body, status, response);
  return { status, body: response };
}

export async function recordBackupReport(
  db: Db,
  reporterId: string,
  deploymentId: string,
  body: {
    evidenceRef: string;
    expectedVersion: number;
    outcome?: "reported_complete" | "reported_failed" | "restore_verified";
    consistency?: "consistent" | "failed" | "unknown";
    releaseId?: string;
    schemaVersion?: string;
    startedAt?: string;
    completedAt?: string;
    expiresAt?: string;
    restoreAttestation?: string;
  },
): Promise<{ organizationId: string; response: Record<string, unknown> }> {
  if (!evidenceReferenceAccepted(body.evidenceRef) || (body.restoreAttestation ?? "").includes("://")) {
    throw new HttpError(422, "EVIDENCE_REF", "Backup evidence must be an internal reference, not a fetchable URL.");
  }
  const classified = classifyBackupReport(body);
  if (!classified.ok) throw new HttpError(422, classified.code, classified.message);
  const deployment = await db.query<{
    version: number;
    organization_id: string;
    server_id: string | null;
    generation: number;
    lifecycle_state: string;
    installer_status: string | null;
    dns_writes_accepted: boolean;
    brevo_authenticated: boolean;
    brevo_verified: boolean;
    mail_verified: boolean;
  }>(
    `SELECT version, organization_id, server_id, generation, lifecycle_state, installer_status,
            dns_writes_accepted, brevo_authenticated, brevo_verified, mail_verified
     FROM deployments WHERE id = $1`,
    [deploymentId],
  );
  const row = deployment.rows[0];
  if (!row) throw new HttpError(404, "NOT_FOUND", "The deployment was not found.");
  if (row.version !== body.expectedVersion) throw new HttpError(409, "VERSION_CONFLICT", "The deployment changed.");
  const countsAsReport = classified.state === "reported_complete";
  await db.query(
    `INSERT INTO backups (
       id, organization_id, deployment_id, server_id, generation, external_reference, evidence_source, state,
       reported_by, evidence_ref, release_id, schema_version, consistency_state,
       started_at, completed_at, restore_verified_at, expires_at, reported_at
     ) VALUES (
       $1, $2, $3, $4, $5, $6, 'operator', $7,
       $8, $6, $9, $10, $11,
       $12, $13, $14, $15, now()
     )`,
    [
      randomUUID(),
      row.organization_id,
      deploymentId,
      row.server_id,
      row.generation,
      body.evidenceRef,
      classified.state,
      reporterId,
      body.releaseId ?? null,
      body.schemaVersion ?? null,
      body.outcome ? body.consistency ?? (classified.state === "reported_failed" ? "failed" : classified.state === "reported_complete" ? "consistent" : "unknown") : null,
      body.startedAt ?? null,
      body.completedAt ?? null,
      classified.restoreVerified ? new Date() : null,
      body.expiresAt ?? null,
    ],
  );
  await db.query(
    `UPDATE deployments
     SET backup_reported_at = CASE WHEN $2::boolean THEN now() ELSE backup_reported_at END,
         version = version + 1, updated_at = now()
     WHERE id = $1`,
    [deploymentId, countsAsReport],
  );
  const allowed = countsAsReport && activationAllowed({
    installerStatus: row.installer_status,
    dnsWritesAccepted: row.dns_writes_accepted,
    brevoAuthenticated: row.brevo_authenticated,
    brevoVerified: row.brevo_verified,
    backupReported: true,
    mailVerified: row.mail_verified,
  });
  let reason: string | null = row.mail_verified ? null : "mail.verification_required";
  if (body.outcome === "reported_failed") reason = "backup.reported_failed";
  if (body.outcome === "restore_verified") reason = "backup.operator_attestation";
  if (!body.outcome || body.outcome === "reported_complete") {
    if (!allowed) {
      await openAction(db, {
        organizationId: row.organization_id,
        deploymentId,
        serverId: row.server_id,
        code: "mail.verification_required",
        audience: "operator",
        instructions: "Backup evidence is recorded. Live mail is still unverified, so the deployment stays onboarding.",
      });
    }
  } else if (body.outcome === "reported_failed") {
    await openAction(db, {
      organizationId: row.organization_id,
      deploymentId,
      serverId: row.server_id,
      code: "backup.reported_failed",
      audience: "operator",
      instructions: "The operator reported a failed backup. The last usable report was kept.",
    });
  } else {
    await openAction(db, {
      organizationId: row.organization_id,
      deploymentId,
      serverId: row.server_id,
      code: "backup.operator_attestation",
      audience: "operator",
      instructions: "Restore verification is an operator attestation. It is not a cloud API check.",
    });
  }
  if (!body.outcome) {
    return { organizationId: row.organization_id, response: { activated: allowed, reason, lifecycleState: "onboarding" } };
  }
  return {
    organizationId: row.organization_id,
    response: {
      activated: allowed,
      reason,
      lifecycleState: row.lifecycle_state,
      state: classified.state,
      cloudVerified: false,
      provenance: "operator-reported",
    },
  };
}

async function openAction(db: Db, input: {
  organizationId: string;
  deploymentId: string | null;
  serverId: string | null;
  code: string;
  audience: "operator" | "customer";
  instructions: string;
}): Promise<string> {
  const existing = await db.query<{ id: string }>(
    `SELECT id FROM required_actions
     WHERE state = 'open' AND code = $1 AND organization_id IS NOT DISTINCT FROM $2
     LIMIT 1`,
    [input.code, input.organizationId],
  );
  if (existing.rows[0]) return existing.rows[0].id;
  const id = randomUUID();
  await db.query(
    `INSERT INTO required_actions (id, scope, organization_id, server_id, deployment_id, audience, code, instructions, state)
     VALUES ($1, 'tenant', $2, $3, $4, $5, $6, $7, 'open')`,
    [id, input.organizationId, input.serverId, input.deploymentId, input.audience, input.code, input.instructions],
  );
  return id;
}

function mailboxHttp(error: MailboxNameError): HttpError {
  if (error.code === "RESERVED_LOCAL_PART") return new HttpError(422, "RESERVED_LOCAL_PART", error.message);
  return new HttpError(400, "VALIDATION", error.message);
}

function assertWriter(ctx: InstallationContext, actor: Actor): void {
  if (!actor.roles.includes("platform_administrator") && !actor.roles.includes("infrastructure_operator")) {
    throw new HttpError(403, "FORBIDDEN", "An infrastructure operator is required.");
  }
  ctx.requireVerified(actor);
  ctx.requireMfa(actor);
}

function validBrevoRecords(records: BrevoDnsRecord[]): boolean {
  const purposes = new Set(records.map((record) => record.purpose));
  return records.length === 3 && purposes.has("brevo_code") && purposes.has("dkim") && purposes.has("dmarc");
}

function savedBrevoReport(value: unknown, domain: string): { records: BrevoDnsRecord[]; authenticated: boolean; verified: boolean } | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const report = value as { domain?: unknown; authenticated?: unknown; verified?: unknown; records?: unknown };
  if (report.domain !== domain || !Array.isArray(report.records)) return null;
  const records = report.records.flatMap((item): BrevoDnsRecord[] => {
    if (!item || typeof item !== "object") return [];
    const row = item as { purpose?: unknown; type?: unknown; host?: unknown; value?: unknown };
    if (row.type !== "TXT" || typeof row.host !== "string" || typeof row.value !== "string") return [];
    if (row.purpose !== "brevo_code" && row.purpose !== "dkim" && row.purpose !== "dmarc") return [];
    return [{ purpose: row.purpose, type: "TXT", host: row.host, value: row.value }];
  });
  if (!validBrevoRecords(records)) return null;
  return { records, authenticated: report.authenticated === true, verified: report.verified === true };
}

function schedulerAuthorized(header: string | undefined, expected: string | undefined): boolean {
  if (!expected || !header) return false;
  const left = Buffer.from(header);
  const right = Buffer.from(expected);
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}

export async function createDeploymentForActor(ctx: InstallationContext, db: Db, actor: Actor, request: FastifyRequest, body: { domainId: string; firstMailboxLocalPart: string; testMailConsent: true }, idempotencyKey: string): Promise<{ status: number; body: Record<string, unknown> }> {
  ctx.requireVerified(actor);
  if (!actor.organizationId) throw new HttpError(422, "ORGANIZATION_REQUIRED", "Create an organization first.");
  await ctx.requireSubscription?.(db, actor.organizationId);
  const route = "POST /v1/deployments";
  const replayed = await ctx.replay(db, actor.userId, route, idempotencyKey, body);
  if (replayed) return replayed;
  let localPart: string;
  try {
    localPart = assertMailboxLocalPart(body.firstMailboxLocalPart);
  } catch (error) {
    if (error instanceof MailboxNameError) throw mailboxHttp(error);
    throw error;
  }
  const domain = await db.query<{ id: string; normalized_name: string }>(
    "SELECT id, normalized_name FROM domains WHERE id = $1 AND organization_id = $2",
    [body.domainId, actor.organizationId],
  );
  const row = domain.rows[0];
  if (!row) throw new HttpError(404, "NOT_FOUND", "The domain was not found.");
  const plan = await loadPlan(db, actor.organizationId);
  await requestInstallationAllocation(db,actor.organizationId,row.id);
  await ctx.setActor(db,"allocator");
  await allocateProfile(db,"e2-micro",100);
  await ctx.setActor(db,"customer");

  const deploymentId = randomUUID();
  const mailHostname = `mail.${row.normalized_name}`;
  const webmailHostname = `bearmail.${row.normalized_name}`;
  await db.query(
    `INSERT INTO deployments (
       id, organization_id, domain_id, desired_state, onboarding_stage, lifecycle_state, health_state,
       mail_hostname, webmail_hostname, first_mailbox_local_part, test_mail_consent, plan_snapshot
     ) VALUES ($1, $2, $3, 'draft', 'draft', 'onboarding', 'unknown', $4, $5, $6, true, $7::jsonb)`,
    [
      deploymentId,
      actor.organizationId,
      row.id,
      mailHostname,
      webmailHostname,
      localPart,
      JSON.stringify({
        id: plan.id,
        code: plan.code,
        revision: plan.revision,
        mailboxLimit: customerMailboxLimit(plan.code, plan.mailbox_limit),
        mailboxQuotaBytes: plan.quota,
      }),
    ],
  );
  const mailboxId = randomUUID();
  await insertMailbox(db, {
    id: mailboxId,
    organizationId: actor.organizationId,
    deploymentId,
    localPart,
    domain: row.normalized_name,
    kind: "customer",
    quotaBytes: plan.quota,
    aliasFor: null,
  });
  await insertMailbox(db, {
    id: randomUUID(),
    organizationId: actor.organizationId,
    deploymentId,
    localPart: "postmaster",
    domain: row.normalized_name,
    kind: "system_alias",
    quotaBytes: null,
    aliasFor: mailboxId,
  });
  await insertMailbox(db, {
    id: randomUUID(),
    organizationId: actor.organizationId,
    deploymentId,
    localPart: "abuse",
    domain: row.normalized_name,
    kind: "system_alias",
    quotaBytes: null,
    aliasFor: mailboxId,
  });
  await insertMailbox(db, {
    id: randomUUID(),
    organizationId: actor.organizationId,
    deploymentId,
    localPart: "bearportal-test",
    domain: row.normalized_name,
    kind: "system_test",
    quotaBytes: null,
    aliasFor: null,
  });
  await ctx.setActor(db, "platform_administrator");
  const assignedRelay = await db.query<{ relay_id: string; report: unknown }>(
    `SELECT r.id AS relay_id, r.validation_report AS report
     FROM relay_assignments a
     JOIN relay_connections r ON r.id = a.relay_connection_id
     WHERE a.organization_id = $1 AND a.released_at IS NULL
     LIMIT 1`,
    [actor.organizationId],
  );
  const savedBrevo = savedBrevoReport(assignedRelay.rows[0]?.report, row.normalized_name);
  if (assignedRelay.rows[0] && savedBrevo) {
    await db.query(
      `UPDATE deployments
       SET brevo_records = $2::jsonb,
           brevo_authenticated = $3,
           brevo_verified = $4,
           relay_connection_id = COALESCE(relay_connection_id, $5::uuid),
           updated_at = now()
       WHERE id = $1`,
      [
        deploymentId,
        JSON.stringify(savedBrevo.records),
        savedBrevo.authenticated,
        savedBrevo.verified,
        assignedRelay.rows[0].relay_id,
      ],
    );
  }
  await ctx.setActor(db, "customer");
  await ctx.audit(db, request, actor.userId, actor.organizationId, "deployment.create", deploymentId, {
    domain: row.normalized_name,
    mailbox: localPart,
  });
  const response = {
    id: deploymentId,
    domain: row.normalized_name,
    mailHostname,
    webmailHostname,
    onboardingStage: "draft",
    lifecycleState: "onboarding",
    mxAuthorized: false,
    version: 1,
    mailboxId,
  };
  await ctx.remember(db, actor.userId, route, idempotencyKey, body, 201, response);
  return { status: 201 as const, body: response };
}

export async function provisionDeploymentForActor(ctx: InstallationContext, db: Db, actor: Actor, request: FastifyRequest, id: string, body: { expectedVersion: number }, idempotencyKey: string): Promise<{ status: number; body: Record<string, unknown> }> {
  ctx.requireVerified(actor);
  if (!actor.organizationId) throw new HttpError(422, "ORGANIZATION_REQUIRED", "Create an organization first.");
  await ctx.requireSubscription?.(db, actor.organizationId);
  const route = "POST /v1/deployments/:id/provision";
  const replayed = await ctx.replay(db, actor.userId, route, idempotencyKey, { id, ...body });
  if (replayed) return replayed;
  const deployment = await loadDeployment(db, id, actor.organizationId);
  if (!deployment) throw new HttpError(404, "NOT_FOUND", "The deployment was not found.");
  if (deployment.version !== body.expectedVersion) throw new HttpError(409, "VERSION_CONFLICT", "The deployment changed.");
  const linked = await loadDomainLink(db, deployment.domain_id, actor.organizationId);
  if (!linked) throw new HttpError(422, "DOMAIN_REQUIRED", "The deployment has no domain.");
  const domainBlock = installDomainBlock({
    state: linked.state,
    hasCredential: Boolean(linked.secret_ref && linked.zone_id),
    sourceInstall: Boolean(ctx.installFromSource),
  });
  if (domainBlock !== "ok") {
    return persist(db, ctx, actor, route, idempotencyKey, { id, ...body }, 422, await actionError(db, {
      organizationId: actor.organizationId,
      deploymentId: id,
      serverId: null,
      code: domainBlock,
      message: domainBlock === "dns.credential_required"
        ? "A DNS credential is required before installation."
        : "Verify the domain before installation.",
    }));
  }
  await ctx.setActor(db, "platform_administrator");
  const host = await loadHost(db, actor.organizationId);
  await ctx.setActor(db, "customer");
  const plan = await loadPlan(db, actor.organizationId);
  if (host && host.profile_code !== plan.server_profile_code) {
    return persist(db, ctx, actor, route, idempotencyKey, { id, ...body }, 422, await actionError(db, {
      organizationId: actor.organizationId,
      deploymentId: id,
      serverId: host.id,
      code: "plan.profile_mismatch",
      message: "The reserved server does not match the plan profile.",
    }));
  }
  if (host && !sshIdentityAllowsInstall(host.identity_state, host.readiness_source)) {
    return persist(db, ctx, actor, route, idempotencyKey, { id, ...body }, 422, await actionError(db, {
      organizationId: actor.organizationId,
      deploymentId: id,
      serverId: host.id,
      code: "server.fingerprint_unconfirmed",
      message: "Confirm the enrolled device before installation.",
    }));
  }
  if (host && host.state !== "reserved" && host.state !== "assigned") {
    return persist(db, ctx, actor, route, idempotencyKey, { id, ...body }, 409, {
      error: { code: "INVALID_STATE", message: "The reserved server cannot accept installation.", retryable: false, requiredActionId: null },
    });
  }
  const quota = plan.quota;
  const plannedRecords = deployment.brevo_records ?? (ctx.installFromSource ? [] : null);
  const fingerprint = host && plannedRecords
    ? installerFingerprint({
      domain: linked.normalized_name,
      mailHostname: `mail.${linked.normalized_name}`,
      webmailHostname: deployment.webmail_hostname ?? `bearmail.${linked.normalized_name}`,
      publicIpv4: host.public_ipv4,
      provider: linked.provider,
      zone: linked.zone_id,
      brevoRecords: plannedRecords,
      relayHost: "smtp-relay.brevo.com",
    })
    : null;
  if (
    fingerprint
    && fingerprint === deployment.installer_input_hash
    && (deployment.installer_status === "succeeded" || deployment.installer_status === "tls_pending")
    && deployment.dns_writes_accepted
  ) {
    const response = {
      jobId: deployment.active_job_id,
      state: "queued",
      installerStatus: deployment.installer_status,
      dnsWritesAccepted: true,
      deploymentVersion: deployment.version,
      credentialApplied: false,
      mailVerified: false,
    };
    await ctx.remember(db, actor.userId, route, idempotencyKey, { id, ...body }, 202, response);
    return { status: 202 as const, body: response };
  }
  const version = await authorizeDeployment(db, id, actor.organizationId, body.expectedVersion);
  if (!host) {
    const jobId = await waitingJob(db, actor.organizationId, id, "install_release", "inventory.server_required");
    const actionId = await openAction(db, {
      organizationId: actor.organizationId,
      deploymentId: id,
      serverId: null,
      code: "inventory.server_required",
      audience: "operator",
      instructions: "An enrolled server is required. BearPortal does not create a machine.",
    });
    const response = { jobId, state: "waiting_human", requiredActionId: actionId, deploymentVersion: version };
    await ctx.remember(db, actor.userId, route, idempotencyKey, { id, ...body }, 202, response);
    return { status: 202 as const, body: response };
  }
  if (isExampleWebmail(deployment.webmail_hostname ?? `bearmail.${linked.normalized_name}`)) {
    return persist(db, ctx, actor, route, idempotencyKey, { id, ...body }, 422, await actionError(db, {
      organizationId: actor.organizationId,
      deploymentId: id,
      serverId: host.id,
      code: "INVALID_INPUT",
      message: "That webmail hostname is rejected.",
    }));
  }
  if (!ctx.release && !ctx.installFromSource) {
    return persist(db, ctx, actor, route, idempotencyKey, { id, ...body }, 422, await actionError(db, {
      organizationId: actor.organizationId,
      deploymentId: id,
      serverId: host.id,
      code: "release.unpinned",
      message: "No BearMail release is pinned. The installer contract has not been recorded as passed.",
    }));
  }
  if (ctx.release) {
    try {
      assertReleaseLayout(ctx.release.artifactDir, ctx.release.id);
    } catch (error) {
      if (error instanceof ReleaseLayoutError) {
        return persist(db, ctx, actor, route, idempotencyKey, { id, ...body }, 422, await actionError(db, {
          organizationId: actor.organizationId,
          deploymentId: id,
          serverId: host.id,
          code: error.code,
          message: error.message,
        }));
      }
      throw error;
    }
  }
  await ctx.setActor(db, "platform_administrator");
  const relay = await assignRelay(db, actor.organizationId);
  await ctx.setActor(db, "customer");
  if (!relay) {
    const jobId = await waitingJob(db, actor.organizationId, id, "install_release", "relay.unavailable");
    const actionId = await openAction(db, {
      organizationId: actor.organizationId,
      deploymentId: id,
      serverId: host.id,
      code: "relay.unavailable",
      audience: "operator",
      instructions: "Assign an available Brevo account. BearPortal does not create one.",
    });
    const response = { jobId, state: "waiting_human", requiredActionId: actionId, deploymentVersion: version };
    await ctx.remember(db, actor.userId, route, idempotencyKey, { id, ...body }, 202, response);
    return { status: 202 as const, body: response };
  }
  let records = deployment.brevo_records;
  if (!records && ctx.installFromSource) {
    records = [];
  } else if (!records) {
    requireOperation("brevo.create_domain");
    try {
      const createdDomain = await ctx.brevoClient.createDomain(linked.normalized_name);
      records = createdDomain.records;
    } catch {
      return persist(db, ctx, actor, route, idempotencyKey, { id, ...body }, 503, await actionError(db, {
        organizationId: actor.organizationId,
        deploymentId: id,
        serverId: host.id,
        code: "BREVO_UNAVAILABLE",
        message: "Live Brevo domain creation is not configured.",
        retryable: true,
      }));
    }
    if (!validBrevoRecords(records)) {
      return persist(db, ctx, actor, route, idempotencyKey, { id, ...body }, 422, await actionError(db, {
        organizationId: actor.organizationId,
        deploymentId: id,
        serverId: host.id,
        code: "BREVO_RECORDS_INVALID",
        message: "Brevo did not return the three DNS records.",
      }));
    }
    await db.query(
      `UPDATE deployments
       SET brevo_records = $2::jsonb, relay_connection_id = $3, onboarding_stage = 'brevo_domain_setup', updated_at = now()
       WHERE id = $1`,
      [id, JSON.stringify(records), relay.id],
    );
  }
  const admin = await ensureAdminSecret(db, ctx, actor.organizationId, id, deployment.admin_secret_ref, linked.normalized_name);
  const operationId = deployment.installer_operation_id && deployment.installer_input_hash === installerFingerprint({
    domain: linked.normalized_name,
    mailHostname: `mail.${linked.normalized_name}`,
    webmailHostname: deployment.webmail_hostname ?? `bearmail.${linked.normalized_name}`,
    publicIpv4: host.public_ipv4,
    provider: linked.provider,
    zone: linked.zone_id,
    brevoRecords: records,
    relayHost: "smtp-relay.brevo.com",
  })
    ? deployment.installer_operation_id
    : randomUUID();
  const inputHash = installerFingerprint({
    domain: linked.normalized_name,
    mailHostname: `mail.${linked.normalized_name}`,
    webmailHostname: deployment.webmail_hostname ?? `bearmail.${linked.normalized_name}`,
    publicIpv4: host.public_ipv4,
    provider: linked.provider,
    zone: linked.zone_id,
    brevoRecords: records,
    relayHost: "smtp-relay.brevo.com",
  });
  const releasePin = await sourceRelease(ctx, operationId);
  if (!releasePin) {
    return persist(db, ctx, actor, route, idempotencyKey, { id, ...body }, 503, await actionError(db, {
      organizationId: actor.organizationId,
      deploymentId: id,
      serverId: host.id,
      code: "INSTALLER_UNAVAILABLE",
      message: "The latest bearmail-install commit could not be read.",
      retryable: true,
    }));
  }
  if (!linked.secret_ref) {
    return persist(db, ctx, actor, route, idempotencyKey, { id, ...body }, 422, await actionError(db, {
      organizationId: actor.organizationId,
      deploymentId: id,
      serverId: host.id,
      code: "dns.credential_required",
      message: "A DNS credential is required before installation.",
    }));
  }
  const input = installerInput(releasePin, {
    operationId,
    deploymentId: id,
    generation: deployment.generation,
    domain: linked.normalized_name,
    webmailHostname: deployment.webmail_hostname ?? `bearmail.${linked.normalized_name}`,
    publicIpv4: host.public_ipv4,
    provider: linked.provider,
    zone: linked.zone_id,
    dnsSecretId: linked.secret_ref,
    brevoRecords: records,
    smtpLogin: relay.smtp_login,
    smtpSecretId: relay.smtp_secret_ref,
    adminSecretId: admin.secretId,
    quotaBytes: quota,
    adminPassword: admin.password,
  });
  await db.query(
    `UPDATE deployments
     SET installer_operation_id = $2, installer_input_hash = $3, server_id = $4, release_id = $5,
         onboarding_stage = 'installing', updated_at = now()
     WHERE id = $1`,
    [id, operationId, inputHash, host.id, releasePin.id],
  );
  const ran = await executeInstaller(ctx, db, {
    organizationId: actor.organizationId,
    deploymentId: id,
    operationId,
    generation: deployment.generation,
    modeStop: "dry_run",
    input,
  });
  if (ran.unavailable) {
    return persist(db, ctx, actor, route, idempotencyKey, { id, ...body }, 503, await actionError(db, {
      organizationId: actor.organizationId,
      deploymentId: id,
      serverId: host.id,
      code: "INSTALLER_UNAVAILABLE",
      message: "The BearMail installer is not configured.",
      retryable: true,
    }));
  }
  if (!ran.apply) {
    await rememberDryRun(db, id, actor.organizationId, linked, ran.dryRun);
    return persist(db, ctx, actor, route, idempotencyKey, { id, ...body }, 422, await actionError(db, {
      organizationId: actor.organizationId,
      deploymentId: id,
      serverId: host.id,
      code: ran.dryRun?.errorCode ?? "INSTALLER_FAILED",
      message: "The installer dry-run did not produce a plan. BearPortal did not publish DNS.",
    }));
  }
  await ctx.setActor(db, "platform_administrator");
  await db.query(
    `UPDATE servers
     SET state = 'assigned', tenant_tainted_at = coalesce(tenant_tainted_at, now()), version = version + 1, updated_at = now()
     WHERE id = $1 AND state IN ('reserved', 'assigned')`,
    [host.id],
  );
  await db.query(
    `UPDATE server_assignments
     SET deployment_id = $2
     WHERE id = $1 AND released_at IS NULL AND (deployment_id IS NULL OR deployment_id = $2)`,
    [host.assignment_id, id],
  );
  const jobId = randomUUID();
  await db.query(
    `INSERT INTO jobs (
       id, organization_id, deployment_id, generation, kind, state, checkpoint, lease_owner, lease_expires_at, fencing_token
     ) VALUES (
       $1, $2, $3, $4, 'install_release', 'queued', $5::jsonb, 'api', now() + interval '120 seconds', 1
     )`,
    [jobId, actor.organizationId, id, deployment.generation, JSON.stringify({
      operationId,
      installerStarted: true,
      status: ran.apply.status,
      dnsWritesAccepted: ran.apply.dnsWritesAccepted,
      ipProof: "not_performed",
    })],
  );
  await queueCommand(db, {
    serverId: host.id,
    organizationId: actor.organizationId,
    deploymentId: id,
    jobId,
    generation: host.assignment_generation,
    authEpoch: host.auth_epoch,
    commandType: "install_release",
    parameters: { releaseId: releasePin.id },
  });
  let authenticated = deployment.brevo_authenticated;
  let verified = deployment.brevo_verified;
  if (ran.apply.dnsWritesAccepted) {
    requireOperation("brevo.authenticate");
    try {
      const auth = await ctx.brevoClient.authenticate(linked.normalized_name);
      authenticated = auth.authenticated === true;
      verified = auth.verified === true;
    } catch {
      authenticated = false;
      verified = false;
    }
  }
  if (ran.apply.dnsWritesAccepted) {
    await queueCommand(db, {
      serverId: host.id,
      organizationId: actor.organizationId,
      deploymentId: id,
      jobId,
      generation: host.assignment_generation,
      authEpoch: host.auth_epoch,
      commandType: "sync_mailboxes",
      parameters: {},
    });
  }
  await ctx.setActor(db, "customer");
  const stage = !ran.apply.dnsWritesAccepted
    ? "installing"
    : authenticated && verified
      ? "verifying_mail"
      : "brevo_authenticate";
  await db.query(
    `UPDATE deployments
     SET installer_status = $2, previous_mx = $3::jsonb, published_records = $4::jsonb,
         dns_writes_accepted = $5, brevo_authenticated = $6, brevo_verified = $7,
         onboarding_stage = $8, active_job_id = $9, observed_ip = CASE WHEN $5 THEN $10::inet ELSE observed_ip END,
         ip_observed_at = CASE WHEN $5 THEN now() ELSE ip_observed_at END,
         mail_verified = false, lifecycle_state = 'onboarding', updated_at = now()
     WHERE id = $1`,
    [
      id,
      ran.apply.status,
      JSON.stringify(ran.apply.previousMx),
      JSON.stringify(ran.apply.published),
      ran.apply.dnsWritesAccepted,
      authenticated,
      verified,
      stage,
      jobId,
      host.public_ipv4,
    ],
  );
  if (stage === "verifying_mail") {
    await openAction(db, {
      organizationId: actor.organizationId,
      deploymentId: id,
      serverId: host.id,
      code: "mail.verification_required",
      audience: "operator",
      instructions: "Live mail has not been verified. Do not mark the deployment active.",
    });
  } else if (!ran.apply.dnsWritesAccepted) {
    await openAction(db, {
      organizationId: actor.organizationId,
      deploymentId: id,
      serverId: host.id,
      code: ran.apply.errorCode ?? "installer.dns_partial",
      audience: "operator",
      instructions: "The installer reported a partial or failed DNS publish. BearPortal does not write a compensating change.",
    });
  } else if (!authenticated || !verified) {
    await openAction(db, {
      organizationId: actor.organizationId,
      deploymentId: id,
      serverId: host.id,
      code: "brevo.authenticate_pending",
      audience: "operator",
      instructions: "Brevo has not reported the domain verified and authenticated.",
    });
  }
  await rememberDryRun(db, id, actor.organizationId, linked, ran.dryRun);
  await ctx.audit(db, request, actor.userId, actor.organizationId, "deployment.provision", id, {
    operationId,
    installerStatus: ran.apply.status,
    dnsWritesAccepted: ran.apply.dnsWritesAccepted,
  });
  const response = {
    jobId,
    state: "queued",
    installerStatus: ran.apply.status,
    dnsWritesAccepted: ran.apply.dnsWritesAccepted,
    brevoAuthenticated: authenticated,
    brevoVerified: verified,
    deploymentVersion: version,
    mailVerified: false,
    delivered: false,
  };
  await ctx.remember(db, actor.userId, route, idempotencyKey, { id, ...body }, 202, response);
  return { status: 202 as const, body: response };
}
