import {assertInstallDomainAvailable} from "./installation-request.ts";
import { setupFailureCode } from "./setup-errors.ts";
import { refreshInstalledTls, type InstalledTlsProbe } from "./installed-tls.ts";
import { refreshWaitingInventory } from "./refresh-inventory.ts";
import { randomUUID, timingSafeEqual } from "node:crypto";
import type { FastifyInstance, FastifyRequest } from "fastify";
import { dnsCredentialSchema } from "../../../packages/contracts/src/index.ts";
import { allocateProfile } from "../../../packages/servers/src/allocate.ts";
import { detectDnsProvider } from "../../../packages/providers/dns/src/detect.ts";
import { claimBrevoAccount, type InventoryContext } from "./inventory.ts";
import {
  createDeploymentForActor,
  provisionDeploymentForActor,
  ensureAdminSecret,
  type InstallationContext,
} from "./installation.ts";
import { enqueueOnboarding, requireSetupConsent } from "./onboarding-queue.ts";
import { HttpError } from "./errors.ts";

/** A small persistent onboarding queue. All execution reuses the API's tenant/installer services. */
export function registerOnboarding(
  app: FastifyInstance,
  inventory: InventoryContext,
  install: InstallationContext,
  intervalMs = 30_000,
  tlsProbe?: InstalledTlsProbe,
) {
  let active: Promise<boolean> | null = null;
  let currentOrganization: string | null = null;
  let stopping = false;
  let timer: ReturnType<typeof setInterval> | undefined;
  const run = (): Promise<boolean> => {
    if (stopping) return Promise.resolve(false);
    if (active) return active;
    active = processOne()
      .catch(async (error) => {
        const failure = setupFailureCode(error);
        const persistedCode = failure === "PROVIDER_RETRY" ? "SETUP_REVIEW_REQUIRED" : failure;
        if (currentOrganization) {
          await inventory
            .withSystem("inventory_worker", async (db) => {
              await inventory.setActor(db, "platform_administrator");
              await db.query(
                "UPDATE onboarding_requests SET state='attention',last_error_code=$2,updated_at=now() WHERE organization_id=$1",
                [currentOrganization, persistedCode],
              );
              await recordReview(
                db,
                currentOrganization!,
                persistedCode,
              );
            })
            .catch(() => undefined);
        }
        const code=(error as {code?:unknown})?.code;
        app.log.error(
          {failureCode:typeof code==='string'&&/^[0-9A-Z]{5}$/.test(code)?code:'INTERNAL'},
          "Automatic onboarding attempt failed; the persisted request will be checked again.",
        );
        return false;
      })
      .finally(() => {
        active = null;
        currentOrganization = null;
      });
    return active;
  };
  const wake = () => {
    if (intervalMs > 0) void run();
  };
  app.addHook("onReady", async () => {
    if (intervalMs > 0) {
      timer = setInterval(wake, intervalMs);
      timer.unref();
      wake();
    }
  });
  app.addHook("onClose", async () => {
    stopping = true;
    if (timer) clearInterval(timer);
    await active;
  });

  app.post("/portal/onboarding", async (request, reply) => {
    const form = request.body as Record<string, string> | undefined;
    await inventory.withActor(request, "customer", async (db, actor) => {
      inventory.requireVerified(actor);
      if (!actor.organizationId)
        throw new HttpError(422, "ORGANIZATION_REQUIRED", "Register first.");
      await inventory.requireSubscription?.(db, actor.organizationId);
      inventory.consumeLimit(actor.userId, "onboarding", 10, 60 * 60 * 1000);
      const domain = await db.query<{ id: string }>(
        `SELECT d.id FROM domains d JOIN dns_connections c ON c.domain_id=d.id AND c.organization_id=d.organization_id
        WHERE d.organization_id=$1 AND d.state <> 'retired' ORDER BY c.created_at DESC LIMIT 1`,
        [actor.organizationId],
      );
      if (!domain.rows[0])
        throw new HttpError(
          422,
          "DNS_CREDENTIAL_REQUIRED",
          "Connect your domain provider first.",
        );
      await requireSetupConsent(
        db,
        actor.organizationId,
        domain.rows[0].id,
        form?.deployConsent === "1",
      );
      await enqueueOnboarding(db, actor.organizationId, domain.rows[0].id);
    });
    wake();
    return reply.code(303).header("location", "/portal").send("");
  });
  app.post("/internal/onboarding/run", async (request, reply) => {
    const expected = inventory.schedulerToken;
    if (!expected)
      throw new HttpError(
        503,
        "SCHEDULER_UNAVAILABLE",
        "The scheduler is not configured.",
      );
    const header = request.headers["x-bearportal-scheduler"];
    if (
      typeof header !== "string" ||
      Buffer.byteLength(header) !== Buffer.byteLength(expected) ||
      !timingSafeEqual(Buffer.from(header), Buffer.from(expected))
    ) {
      throw new HttpError(
        401,
        "UNAUTHENTICATED",
        "Scheduler authentication is required.",
      );
    }
    return reply.send({ processed: await run(), requestId: request.id });
  });

  async function processOne(): Promise<boolean> {
    await refreshInstalledTls(inventory,tlsProbe);
    await refreshWaitingInventory(inventory);
    const request = { id: randomUUID() } as FastifyRequest;
    const prepared = await inventory.withSystem(
      "inventory_worker",
      async (db) => {
        await inventory.setActor(db, "platform_administrator");
        const mode = await db.query<{ mode: string }>(
          "SELECT mode FROM control_plane_state WHERE id=1",
        );
        if (mode.rows[0]?.mode === "recovery") return null;
        // An interrupted install is ambiguous: require review rather than blindly replaying host writes.
        const expired = await db.query<{
          organization_id: string;
        }>(`UPDATE onboarding_requests SET state='attention', last_error_code='OUTCOME_UNKNOWN', updated_at=now()
        WHERE state='installing' AND lease_expires_at < now() RETURNING organization_id`);
        for (const row of expired.rows)
          await recordReview(db, row.organization_id, "OUTCOME_UNKNOWN");
        const rows = await db.query<{
          organization_id: string;
          domain_id: string;
          attempts: number;
          normalized_name: string;
          identity_subject: string;
          user_id: string;
          verified_email: string;
          email_verified: boolean;
        }>(
          `SELECT r.organization_id,r.domain_id,r.attempts,d.normalized_name,u.identity_subject,u.id AS user_id,u.verified_email,u.email_verified
         FROM onboarding_requests r JOIN organizations o ON o.id=r.organization_id JOIN users u ON u.id=o.owner_user_id
         JOIN domains d ON d.id=r.domain_id AND d.organization_id=r.organization_id
         WHERE r.state IN ('queued','waiting_resources') AND r.next_attempt_at <= now()
           AND o.status='active' AND u.status='active' AND d.state <> 'retired'
           ${inventory.billingRequired ? `AND EXISTS(SELECT 1 FROM billing_subscriptions b WHERE b.organization_id=r.organization_id AND b.status IN ('trialing','active') AND b.access_until>now() AND b.cancel_requested_at IS NULL AND b.invoice_issue_code IS NULL)` : ''}
         ORDER BY r.created_at FOR UPDATE OF r SKIP LOCKED LIMIT 1`,
        );
        const item = rows.rows[0];
        if (!item) return null;
        currentOrganization = item.organization_id;
        const defer = async (
          state: string,
          code: string | null,
          missing: string | null = null,
        ) => {
          await db.query(
            `UPDATE onboarding_requests SET state=$2,last_error_code=$3,missing_resource=$4,
          next_attempt_at=now()+interval '30 seconds',updated_at=now() WHERE organization_id=$1`,
            [item.organization_id, state, code, missing],
          );
        };
        if (!item.email_verified) {
          await defer("attention", "EMAIL_UNVERIFIED");
          return null;
        }
        try{await assertInstallDomainAvailable(db,item.organization_id,item.domain_id)}catch(error){
          if(error instanceof HttpError&&error.code==="DOMAIN_ALREADY_IN_USE"){
            await defer("attention","DOMAIN_ALREADY_IN_USE");await recordReview(db,item.organization_id,"DOMAIN_ALREADY_IN_USE");return null;
          }
          throw error;
        }
        await inventory.setActor(db, "allocator");
        await allocateProfile(db, "e2-micro", 100);
        await inventory.setActor(db, "platform_administrator");
        const host = await db.query<{ id: string }>(
          `SELECT s.id FROM server_assignments a JOIN servers s ON s.id=a.server_id
        WHERE a.organization_id=$1 AND a.released_at IS NULL AND s.state IN ('reserved','assigned')`,
          [item.organization_id],
        );
        const assigned = await db.query<{ id: string; state: string }>(
          `SELECT a.id,r.state FROM relay_assignments a JOIN relay_connections r ON r.id=a.relay_connection_id WHERE a.organization_id=$1 AND a.released_at IS NULL`,
          [item.organization_id],
        );
        if (assigned.rows[0]?.state === "disabled") {
          await defer("attention", "RELAY_REVIEW_REQUIRED");
          return null;
        }
        const free =
          await db.query(`SELECT r.id FROM relay_connections r WHERE r.state IN ('inactive','available') AND r.api_secret_ref IS NOT NULL AND r.smtp_secret_ref IS NOT NULL
        AND NOT EXISTS(SELECT 1 FROM relay_assignments a WHERE a.relay_connection_id=r.id AND a.released_at IS NULL) LIMIT 1`);
        const hasRelay = Boolean(assigned.rows[0] || free.rows[0]);
        if (!host.rows[0] || !hasRelay) {
          const missing =
            !host.rows[0] && !hasRelay
              ? "server_and_relay"
              : !host.rows[0]
                ? "server"
                : "relay";
          await defer("waiting_resources", null, missing);
          return null;
        }
        const linked = await claimBrevoAccount(
          inventory,
          db,
          item.organization_id,
        );
        if (!linked) {
          await defer("waiting_resources", null, "relay");
          return null;
        }
        const dns = await db.query<{ provider: string; file_name: string }>(
          `SELECT c.provider,s.file_name FROM dns_connections c JOIN secret_refs s ON s.id=c.secret_ref AND s.state='active'
        WHERE c.organization_id=$1 AND c.domain_id=$2 ORDER BY c.created_at DESC LIMIT 1`,
          [item.organization_id, item.domain_id],
        );
        if (!dns.rows[0]) {
          await defer("attention", "DNS_CREDENTIAL_REQUIRED");
          return null;
        }
        if (item.attempts >= 20) {
          await defer("attention", "SETUP_REVIEW_REQUIRED");
          return null;
        }
        await db.query(
          "UPDATE onboarding_requests SET attempts=attempts+1 WHERE organization_id=$1",
          [item.organization_id],
        );
        try {
          const detected = detectDnsProvider(
            await inventory.lookupNameservers(item.normalized_name),
          );
          if (detected !== dns.rows[0].provider) {
            await defer("attention", "DNS_PROVIDER_CHANGED");
            return null;
          }
          const api = JSON.parse(inventory.secrets.read(linked.fileName)) as {
            apiKey?: string;
          };
          if (!api.apiKey) throw new Error("missing account credential");
          const parsedCredential = dnsCredentialSchema.parse({
            provider: detected,
            credentials: JSON.parse(
              inventory.secrets.read(dns.rows[0].file_name),
            ),
          });
          const credential = {
            provider: parsedCredential.provider,
            ...parsedCredential.credentials,
          } as import("../../../packages/providers/dns/src/publish-brevo.ts").DnsCredentialMaterial;
          const check = await inventory.operatorBrevo.requestDomain(
            api.apiKey,
            item.normalized_name,
          );
          if (check.domain !== item.normalized_name)
            throw new Error("domain mismatch");
          const records =
            check.publishRecords ??
            check.records.map(({ type, host, value }) => ({
              type,
              host,
              value,
            }));
          const secretValues = [
            api.apiKey,
            ...Object.values(parsedCredential.credentials),
          ];
          const redacted = (value: unknown) =>
            !secretValues.some(
              (secret) =>
                typeof secret === "string" &&
                secret.length >= 4 &&
                JSON.stringify(value).includes(secret),
            );
          if (!redacted(records))
            throw new Error("credential in provider response");
          if (records.length)
            await inventory.publishBrevoRecords({
              provider: credential.provider,
              zone: item.normalized_name,
              credential,
              records,
            });
          const authenticate = inventory.operatorBrevo.authenticateDomain;
          if (!authenticate) {
            await defer("attention", "BREVO_AUTH_UNAVAILABLE");
            return null;
          }
          const auth = await authenticate(api.apiKey, item.normalized_name);
          if (auth.domain !== item.normalized_name || !redacted(auth.records))
            throw new Error("invalid provider response");
          await db.query(
            `UPDATE relay_connections SET validation_report=$2::jsonb,version=version+1,updated_at=now() WHERE id=$1`,
            [
              linked.relayId,
              JSON.stringify({
                domain: item.normalized_name,
                authenticated: auth.authenticated === true,
                verified: auth.verified === true,
                records: auth.records,
                publishRecords: records,
              }),
            ],
          );
          if (auth.authenticated !== true || auth.verified !== true) {
            // Valid provider responses awaiting DNS are progress, not credential failures.
            await db.query(
              "UPDATE onboarding_requests SET attempts=0 WHERE organization_id=$1",
              [item.organization_id],
            );
            await defer("queued", "DNS_PROPAGATION");
            return null;
          }
          await setCustomer(db, item);
          const actor = actorFor(item);
          let deployment = (
            await db.query<{
              id: string;
              version: number;
              admin_secret_ref: string | null;
            }>(
              `SELECT id,version,admin_secret_ref FROM deployments WHERE organization_id=$1 AND lifecycle_state <> 'deleted' LIMIT 1`,
              [item.organization_id],
            )
          ).rows[0];
          if (!deployment) {
            const created = await createDeploymentForActor(
              install,
              db,
              actor,
              request,
              {
                domainId: item.domain_id,
                firstMailboxLocalPart: "hello",
                testMailConsent: true,
              },
              `onboarding-create-${item.domain_id}`,
            );
            if (created.status >= 400)
              throw new Error("deployment create failed");
            deployment = {
              id: created.body.id as string,
              version: created.body.version as number,
              admin_secret_ref: null,
            };
          }
          // Commit the administrator secret before the live runner resolves it on another connection.
          const admin = await ensureAdminSecret(
            db,
            install,
            item.organization_id,
            deployment.id,
            deployment.admin_secret_ref,
            item.normalized_name,
          );
          await db.query(
            `UPDATE deployments SET admin_secret_ref=$2,brevo_authenticated=true,brevo_verified=true,relay_connection_id=$3 WHERE id=$1`,
            [deployment.id, admin.secretId, linked.relayId],
          );
          await db.query(
            `UPDATE onboarding_requests SET state='installing',missing_resource=NULL,last_error_code=NULL,lease_expires_at=now()+interval '45 minutes',updated_at=now() WHERE organization_id=$1`,
            [item.organization_id],
          );
          return { item, deployment, auth };
        } catch (error) {
          const failure = setupFailureCode(error);
          if (failure.startsWith("DATABASE_") || failure === "MAILBOX_ADDRESS_CONFLICT") throw error;
          await inventory.setActor(db, "platform_administrator");
          await defer("queued", failure);
          return null;
        }
      },
    );
    if (!prepared) return false;
    try {
      await install.withSystem("inventory_worker", async (db) => {
        await inventory.setActor(db, "platform_administrator");
        const locked = await db.query(
          `SELECT state FROM onboarding_requests WHERE organization_id=$1 AND state='installing' FOR UPDATE`,
          [prepared.item.organization_id],
        );
        if (!locked.rows[0]) return;
        const mode = await db.query<{ mode: string }>(
          "SELECT mode FROM control_plane_state WHERE id=1",
        );
        if (mode.rows[0]?.mode === "recovery") {
          await db.query(
            `UPDATE onboarding_requests SET state='queued',next_attempt_at=now()+interval '30 seconds' WHERE organization_id=$1`,
            [prepared.item.organization_id],
          );
          return;
        }
        const owner = await db.query(
          `SELECT 1 FROM organizations o JOIN users u ON u.id=o.owner_user_id
          WHERE o.id=$1 AND o.owner_user_id=$2 AND o.status='active' AND u.status='active' AND u.email_verified=true`,
          [prepared.item.organization_id, prepared.item.user_id],
        );
        if (!owner.rows[0]) {
          await db.query(
            "UPDATE onboarding_requests SET state='attention',last_error_code='ACCOUNT_REVIEW_REQUIRED' WHERE organization_id=$1",
            [prepared.item.organization_id],
          );
          return;
        }
        await setCustomer(db, prepared.item);
        const result = await provisionDeploymentForActor(
          {
            ...install,
            brevoClient: {
              createDomain: async () => ({
                domain: prepared.item.normalized_name,
                authenticated: true,
                records: prepared.auth.records,
              }),
              authenticate: async () => ({
                authenticated: true,
                verified: true,
              }),
            },
          },
          db,
          actorFor(prepared.item),
          request,
          prepared.deployment.id,
          { expectedVersion: prepared.deployment.version },
          `onboarding-install-${prepared.deployment.id}-${prepared.deployment.version}`,
        );
        const accepted = result.body.dnsWritesAccepted === true;
        const failure = result.body.error as
          { code?: string; retryable?: boolean } | undefined;
        const retryable = !accepted && failure?.retryable === true;
        await inventory.setActor(db, "platform_administrator");
        await db.query(
          `UPDATE onboarding_requests SET state=$2,last_error_code=$3,lease_expires_at=NULL,next_attempt_at=now()+interval '60 seconds',updated_at=now() WHERE organization_id=$1`,
          [
            prepared.item.organization_id,
            accepted ? "installed" : retryable ? "queued" : "attention",
            accepted ? null : (failure?.code ?? "INSTALLATION_REVIEW_REQUIRED"),
          ],
        );
        if (accepted)
          await db.query(
            "UPDATE required_actions SET state='resolved',resolved_at=now() WHERE organization_id=$1 AND state='open' AND code LIKE 'onboarding.%'",
            [prepared.item.organization_id],
          );
      });
    } catch (error) {
      const localError = error as {
        code?: string;
        path?: string;
        syscall?: string;
      };
      const storageFailure =
        localError?.code === "EACCES" &&
        localError.path === "/var/lib/bearportal/work" &&
        ["mkdir", "chmod"].includes(localError.syscall ?? "");
      app.log.error(
        {
          failureCode: storageFailure
            ? "INSTALLER_STORAGE_UNAVAILABLE"
            : error instanceof HttpError
              ? error.code
              : "INSTALLATION_REVIEW_REQUIRED",
        },
        "Automatic installation could not complete.",
      );
      await inventory.withSystem("inventory_worker", async (db) => {
        await inventory.setActor(db, "platform_administrator");
        await db.query(
          `UPDATE onboarding_requests SET state=$2,last_error_code=$3,lease_expires_at=NULL,next_attempt_at=now()+interval '60 seconds',updated_at=now() WHERE organization_id=$1`,
          [
            prepared.item.organization_id,
            storageFailure ? "queued" : "attention",
            storageFailure
              ? "INSTALLER_STORAGE_UNAVAILABLE"
              : "INSTALLATION_REVIEW_REQUIRED",
          ],
        );
        if (!storageFailure)
          await recordReview(
            db,
            prepared.item.organization_id,
            "INSTALLATION_REVIEW_REQUIRED",
          );
      });
    }
    return true;
  }
  return wake;
}

type Owner = {
  organization_id: string;
  identity_subject: string;
  user_id: string;
  verified_email: string;
  email_verified: boolean;
};
function actorFor(item: Owner) {
  return {
    subject: item.identity_subject,
    email: item.verified_email,
    emailVerified: item.email_verified,
    userId: item.user_id,
    organizationId: item.organization_id,
    authTime: 0,
    amr: [],
    roles: [],
  };
}
async function setCustomer(
  db: Parameters<InventoryContext["setActor"]>[0],
  item: Owner,
) {
  for (const [key, value] of Object.entries({
    actor: "customer",
    subject: item.identity_subject,
    email: item.verified_email,
    user_id: item.user_id,
    organization_id: item.organization_id,
  })) {
    await db.query("SELECT set_config($1,$2,true)", [
      `bearportal.${key}`,
      value,
    ]);
  }
}

async function recordReview(
  db: Parameters<InventoryContext["setActor"]>[0],
  organizationId: string,
  code: string,
) {
  await db.query(
    `INSERT INTO required_actions(id,scope,organization_id,audience,code,instructions,state)
    SELECT $1,'tenant',$2,'operator',$3,'Review the saved onboarding request and live host/provider state before retrying.','open'
    WHERE NOT EXISTS(SELECT 1 FROM required_actions WHERE organization_id=$2 AND code=$3 AND state='open')`,
    [randomUUID(), organizationId, `onboarding.${code.toLowerCase()}`],
  );
}
