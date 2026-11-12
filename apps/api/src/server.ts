import {cookieValue} from "./auth-cookies.ts";
import { registerBilling, requireSubscription, type BillingConfig } from "./billing.ts";
import Stripe from "stripe";
import { registerBrowserAuth } from "./browser-auth.ts";
import { createIdentityPlatformClient, validatePlatformClaims, type IdentityPlatformClient } from "./identity-platform-client.ts";
import type { IdentityPlatformConfig } from "./identity-platform-config.ts";
import { resolveIdentitySubject } from "./identity-accounts.ts";
import type { InstalledTlsProbe } from "./installed-tls.ts";
import { registerAdminCredentials } from "./admin-credentials.ts";
import { registerDevelopmentLogin } from "./development-login.ts";
import { createHmac, randomUUID, createHash } from "node:crypto";
import { hostname } from "node:os";
import Fastify, { LogController, type FastifyInstance, type FastifyReply, type FastifyRequest } from "fastify";
import { decodeJwt, importSPKI, jwtVerify, type JWTPayload } from "jose";
import pg from "pg";
import { ZodError } from "zod";
import {
  dnsConnectionCreateSchema,
  dnsConnectionRotateSchema,
  domainCreateSchema,
  invitationCreateSchema,
  operatorRoleGrantSchema,
  organizationCreateSchema,
} from "../../../packages/contracts/src/index.ts";
import { DomainError, normalizeDomain, recoveryIsOutsideDomain } from "../../../packages/domain/src/domain.ts";
import { requireOperation } from "../../../packages/operations/src/registry.ts";
import {
  liveBrevoClient,
  authenticateBrevoDomain,
  requestBrevoDomain,
  unavailableRelayChecker,
  type BrevoClient,
  type OperatorBrevo,
  type RelayChecker,
} from "../../../packages/providers/brevo/src/index.ts";
import { lookupNameservers as defaultLookupNameservers, publishBrevoRecords as defaultPublishBrevoRecords, unavailableZoneReader, validateCredentialShape, type ZoneReader } from "../../../packages/providers/dns/src/index.ts";
import { SecretStore, loadSecretKey } from "../../../packages/secrets/src/store.ts";
import { allocateProfile, readCustomerServer, type Queryable } from "../../../packages/servers/src/allocate.ts";
import { unavailableDnsObserver, unavailableInstallerRunner, type DnsObserver, type InstallerRunner } from "../../../packages/servers/src/installer.ts";
import { liveMailInstall, resolveBearmailCommit, type MailInstallHooks } from "../../../packages/servers/src/mail-install.ts";
import type { SshProbeOutcome } from "../../../packages/servers/src/ssh-probe.ts";
import { HttpError } from "./errors.ts";
import { registerInstallationRoutes, repairAssignedAddress, type InstallationContext } from "./installation.ts";
import { registerOperatorInventory } from "./operator-inventory.ts";
import { registerOnboarding } from "./onboarding.ts";
import { registerInventoryRoutes, type InventoryContext } from "./inventory.ts";
import { registerLifecycleRoutes } from "./lifecycle.ts";
import { registerOversightRoutes } from "./oversight.ts";
import { backupFreshness } from "../../../packages/operations/src/lifecycle.ts";
import { signDevIdentity } from "./dev-identity.ts";
import { renderHome, renderOperatorAuth, type HomeState } from "./portal.ts";

const MFA_WINDOW_SECONDS = 15 * 60;
const OPERATOR_ROLES = ["support", "infrastructure_operator", "platform_administrator"] as const;
type OperatorRole = (typeof OPERATOR_ROLES)[number];

export type ApiDeps = {
  identityPlatform?:IdentityPlatformConfig;
  identityPlatformClient?:IdentityPlatformClient;
  lookupNameservers?: typeof defaultLookupNameservers;
  publishBrevoRecords?: typeof defaultPublishBrevoRecords;
  resolveInstallerCommit?: () => Promise<string>;
  onboardingIntervalMs?: number;
  installedTlsProbe?: InstalledTlsProbe;
  billing?: BillingConfig;
  stripe?: Stripe;
  /** Explicit opt-out for isolated legacy integration tests only. Normal startup always enforces billing. */
  billingRequired?: boolean;
  databaseUrl: string;
  secretsDir: string;
  secretKeyHex: string;
  jwtPublicKeyPem: string;
  issuer: string;
  audience: string;
  zoneReader?: ZoneReader;
  relayChecker?: RelayChecker;
  brevoClient?: BrevoClient;
  operatorBrevo?: OperatorBrevo;
  installerRunner?: InstallerRunner;
  mailInstall?: (hooks: MailInstallHooks) => InstallerRunner;
  dnsObserver?: DnsObserver;
  release?: { id: string; artifactDir: string };
  schedulerToken?: string;
  devJwtPrivateKeyPem?: string;
  sshProbe?: (publicIpv4: string) => Promise<SshProbeOutcome>;
};

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

type Db = pg.Client;

export async function buildServer(deps: ApiDeps, logDestination?: NodeJS.WritableStream): Promise<FastifyInstance> {
  const publicKey = await importSPKI(deps.jwtPublicKeyPem, "RS256");
  const pool = new pg.Pool({ connectionString: deps.databaseUrl, max: 25 });
  const lookupNameservers = deps.lookupNameservers ?? defaultLookupNameservers;
  const publishBrevoRecords = deps.publishBrevoRecords ?? defaultPublishBrevoRecords;
  const zoneReader = deps.zoneReader ?? unavailableZoneReader();
  const relayChecker = deps.relayChecker ?? unavailableRelayChecker();
  const brevoClient = deps.brevoClient ?? liveBrevoClient();
  const operatorBrevo = deps.operatorBrevo ?? {
    requestDomain: (apiKey: string, domain: string) => requestBrevoDomain(apiKey, domain),
    authenticateDomain: (apiKey: string, domain: string) => authenticateBrevoDomain(apiKey, domain),
  };
  const dnsObserver = deps.dnsObserver ?? unavailableDnsObserver();
  const secrets = new SecretStore(deps.secretsDir, loadSecretKey(deps.secretKeyHex));
  const installerRunner = deps.installerRunner ?? (
    deps.mailInstall
      ? deps.mailInstall({ readSecret: (secretId) => readInstallerSecret(pool, secrets, secretId) })
      : unavailableInstallerRunner()
  );
  const installFromSource = deps.mailInstall && !deps.installerRunner && !deps.release
    ? { resolveCommit: deps.resolveInstallerCommit ?? (() => resolveBearmailCommit()) }
    : undefined;
  const identityClient=deps.identityPlatform?(deps.identityPlatformClient??createIdentityPlatformClient(deps.identityPlatform)):undefined;
  const rateHits = new Map<string, number[]>();
  const app = Fastify({
    // Caddy runs locally; keep authentication limits scoped to the actual client.
    trustProxy: ["127.0.0.1", "::1"],
    logger: {
      level: "info",
      redact: {
        paths: ["req.headers.authorization", "req.headers.cookie", "req.body", "request.body"],
        censor: "[redacted]",
      },
      ...(logDestination ? { stream: logDestination } : {}),
    },
    logController: new LogController({ disableRequestLogging: true }),
    requestIdHeader: false,
    genReqId: () => randomUUID(),
  });
  app.addHook("onClose", async () => {
    await pool.end();
  });
  app.addHook("onRequest", async (request, reply) => {
    reply.header("x-request-id", request.id);
  });
  app.setErrorHandler((error, request, reply) => {
    if (error instanceof HttpError) {
      return sendError(reply, request, error.status, error.code, error.message, error.retryable, error.requiredActionId);
    }
    if (isZodError(error) || error instanceof DomainError) {
      return sendError(reply, request, 400, "VALIDATION", error instanceof DomainError ? error.message : "The request is not valid.");
    }
    const statusCode = (error as { statusCode?: number }).statusCode;
    if (statusCode === 400) {
      return sendError(reply, request, 400, "VALIDATION", "The request is not valid.");
    }
    if (error instanceof Stripe.errors.StripeError) {
      request.log.error({stripeType:error.type,stripeCode:error.code??"unknown",stripeStatus:error.statusCode??null},"Stripe billing request failed");
      const temporary=error.type === "StripeConnectionError" || error.type === "StripeAPIError" || error.type === "StripeRateLimitError";
      return sendError(reply,request,503,temporary?"BILLING_UNAVAILABLE":"BILLING_CONFIG_ERROR",temporary?"Stripe is temporarily unavailable. Please try again shortly.":"Billing setup needs attention. Please contact the operator.",temporary);
    }
    const code = pgCode(error);
    if (code === "23505" || code === "23503") {
      return sendError(reply, request, 409, "CONFLICT", "That record already exists.");
    }
    if (code === "42501") {
      return sendError(reply, request, 403, "FORBIDDEN", "The request is not allowed.");
    }
    request.log.error(
      { err: { name: error instanceof Error ? error.name : "Error", code: code ?? "none", message: error instanceof Error ? error.message : "" } },
      "request failed",
    );
    return sendError(reply, request, 500, "INTERNAL", "The request could not be completed.");
  });

  app.addContentTypeParser("application/x-www-form-urlencoded", { parseAs: "string" }, (_request, body, done) => {
    const text = typeof body === "string" ? body : body.toString("utf8");
    const fields: Record<string, string> = {};
    for (const [key, value] of new URLSearchParams(text)) fields[key] = value;
    done(null, fields);
  });

  app.get("/healthz", async (request) => ({ ok: true, requestId: request.id }));

  const homeState = (extra: HomeState = {}): HomeState => ({
    mode: deps.identityPlatform ? "identity" : deps.devJwtPrivateKeyPem ? "development" : "identity",
    managedAuth: Boolean(deps.identityPlatform),
    ...extra,
  });

  function sendHome(reply: FastifyReply, status: number, extra: HomeState = {}) {
    reply.code(status).type("text/html; charset=utf-8");
    return reply.send(renderHome(homeState(extra)));
  }

  app.get("/", async (_request, reply) => sendHome(reply, 200));

  registerDevelopmentLogin(app, Boolean(deps.devJwtPrivateKeyPem),undefined,deps.identityPlatform?()=>renderOperatorAuth():undefined);

  app.get("/register", async (_request, reply) => sendHome(reply, 200));
  app.get("/operator/security",async(_request,reply)=>reply.type("text/html; charset=utf-8").header("cache-control","no-store").header("referrer-policy","no-referrer").send(renderOperatorAuth(true)));
  app.get("/login", async (_request, reply) => sendHome(reply, 200, {authMode:"signin"}));

  app.post("/register", async (request, reply) => {
    const form = request.body as Record<string, string> | undefined;
    const email = (form?.email ?? "").trim().toLowerCase();
    const organization = (form?.organization ?? "").trim() || email.split("@")[0];
    const again = (status: number, error: string) => sendHome(reply, status, { error, email, organization });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 200) {
      return again(400, "Enter your email address.");
    }
    if (organization.length > 120) return again(400, "Enter an organization name.");
    if (!deps.devJwtPrivateKeyPem || deps.identityPlatform) {
      return again(403, "This server registers accounts through Identity Platform. Browser registration is available on the development server.");
    }
    try {
      consumeLimit(rateHits, `register:${email}`, "register", 10, 60 * 60 * 1000);
    } catch (error) {
      if (error instanceof HttpError && error.code === "RATE_LIMITED") {
        return again(429, "Too many registration attempts. Wait and try again.");
      }
      throw error;
    }
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const subject = `local:${email}`;
      await applySettings(client, { actor: "customer", subject, email, userId: "", organizationId: "", bootstrap: "" });
      const existing = await client.query<{ id: string }>("SELECT id FROM users WHERE identity_subject = $1", [subject]);
      const userId = existing.rows[0]?.id ?? randomUUID();
      await applySettings(client, { actor: "customer", subject, email, userId, organizationId: "", bootstrap: "" });
      if (existing.rows[0]) {
        const owned = await client.query<{ id: string }>(
          "SELECT id FROM organizations WHERE owner_user_id = $1 AND status = 'active'",
          [userId],
        );
        if (owned.rows[0]) {
          await client.query("COMMIT");
          const token = await signDevIdentity(deps.devJwtPrivateKeyPem, deps.issuer, deps.audience, email);
          reply.header("set-cookie", sessionCookie(token));
          reply.code(303).header("location", "/portal");
          return reply.send("");
        }
      }
      if (organization.length < 1) {
        await client.query("ROLLBACK");
        return again(400, "Enter an organization name.");
      }
      if (!existing.rows[0]) {
        await client.query(
          `INSERT INTO users (id, identity_subject, verified_email, email_verified, status) VALUES ($1, $2, $3, true, 'active')`,
          [userId, subject, email],
        );
      } else {
        await client.query(
          `UPDATE users SET verified_email = $2, email_verified = true, updated_at = now(), version = version + 1 WHERE id = $1`,
          [userId, email],
        );
      }
      const organizationId = randomUUID();
      await applySettings(client, { actor: "customer", subject, email, userId, organizationId, bootstrap: "" });
      await client.query(
        `INSERT INTO organizations (id, owner_user_id, name, status, billing_required) VALUES ($1, $2, $3, 'active', $4)`,
        [organizationId, userId, organization, deps.billingRequired !== false],
      );
      await client.query(
        `INSERT INTO allocation_requests (id, organization_id, profile_code, verified_registered_at, state)
         VALUES ($1, $2, 'e2-micro', now(), 'waiting_for_server')`,
        [randomUUID(), organizationId],
      );
      requireOperation("organization.allocate");
      await setActor(client, "allocator");
      const allocation = await allocateProfile(client, "e2-micro", 100);
      await setActor(client, "customer");
      for (const item of allocation.assigned) {
        await audit(client, request, userId, item.organizationId, "server.allocate", item.serverId, { assignmentId: item.assignmentId });
      }
      await audit(client, request, userId, organizationId, "organization.create", organizationId, { name: organization });
      await client.query("COMMIT");
      const token = await signDevIdentity(deps.devJwtPrivateKeyPem, deps.issuer, deps.audience, email);
      reply.header("set-cookie", sessionCookie(token));
      reply.code(303).header("location", "/portal");
      return reply.send("");
    } catch (error) {
      await client.query("ROLLBACK");
      if (error instanceof HttpError) {
        const text = error.code === "RECOVERY_MODE"
          ? "Registration is paused while the control plane recovers."
          : "Registration could not be completed.";
        return again(error.status, text);
      }
      throw error;
    } finally {
      await client.query("DISCARD ALL").catch(() => undefined);
      client.release();
    }
  });

  app.post("/v1/session", async (request, reply) => {
    const body = request.body as { idToken?: string } | undefined;
    if (!body || typeof body.idToken !== "string") {
      throw new HttpError(400, "VALIDATION", "An identity token is required.");
    }
    let incoming:JWTPayload;try{incoming=decodeJwt(body.idToken)}catch{throw new HttpError(401,"UNAUTHENTICATED","Sign in is required.");}
    if(deps.identityPlatform&&incoming.iss===`https://securetoken.google.com/${deps.identityPlatform.projectId}`)throw new HttpError(403,"USE_BROWSER_SIGN_IN","Use Google or email/password sign-in to start a browser session.");
    const actor = await verifiedPayload(body.idToken);
    reply.header("set-cookie", sessionCookie(body.idToken));
    return { ok: true, requestId: request.id, email: actor.email, emailVerified: actor.email_verified===true };
  });

  function demandIdempotency(request: FastifyRequest): string {
    const key = request.headers["idempotency-key"];
    if (typeof key !== "string" || key.length < 8 || key.length > 200) {
      throw new HttpError(400, "IDEMPOTENCY_KEY_REQUIRED", "Idempotency-Key is required.");
    }
    return key;
  }

  async function verifiedPayload(token:string):Promise<JWTPayload&{email:string}> {
    let raw:JWTPayload;try{raw=decodeJwt(token)}catch{throw new HttpError(401,"UNAUTHENTICATED","Sign in is required.");}
    if(deps.identityPlatform&&identityClient&&(raw.iss===`https://securetoken.google.com/${deps.identityPlatform.projectId}`||!deps.devJwtPrivateKeyPem)){
      const claims=validatePlatformClaims(await identityClient.verify(token),deps.identityPlatform);
      const subject=await resolveIdentitySubject(inventoryContext,claims);
      return {...claims,sub:subject,bearportalIdentitySubject:claims.sub};
    }
    try{const {payload}=await jwtVerify(token,publicKey,{issuer:deps.issuer,audience:deps.audience,algorithms:['RS256']});if(typeof payload.sub!=='string'||typeof payload.email!=='string')throw Error();return payload as JWTPayload&{email:string};}
    catch{throw new HttpError(401,"UNAUTHENTICATED","Sign in is required.");}
  }

  async function actorFrom(request: FastifyRequest): Promise<JWTPayload & { email: string }> {
    if (usesCookie(request) && request.method !== "GET" && !csrfAccepted(request)) {
      throw new HttpError(403, "CSRF", "A CSRF header is required for cookie sessions.");
    }
    const token = bearer(request) ?? cookieToken(request);
    if (!token) throw new HttpError(401, "UNAUTHENTICATED", "Sign in is required.");
    const payload = await verifiedPayload(token);
    if (typeof payload.sub !== "string" || typeof payload.email !== "string") {
      throw new HttpError(401, "UNAUTHENTICATED", "The identity token is missing a subject or email.");
    }
    return payload as JWTPayload & { email: string };
  }

  async function withActor<T>(request: FastifyRequest, mode: "customer" | "operator", fn: (db: Db, actor: Actor) => Promise<T>): Promise<T> {
    const payload = await actorFrom(request);
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await applySettings(client, {
        actor: "customer",
        subject: payload.sub!,
        email: payload.email,
        userId: "",
        organizationId: "",
        bootstrap: "",
      });
      const existing = await client.query<{ id: string; verified_email: string | null }>(
        "SELECT id, verified_email FROM users WHERE identity_subject = $1",
        [payload.sub],
      );
      const userId = existing.rows[0]?.id ?? randomUUID();
      await applySettings(client, {
        actor: "customer",
        subject: payload.sub!,
        email: payload.email,
        userId,
        organizationId: "",
        bootstrap: "",
      });
      const verified = payload.email_verified === true;
      if (!existing.rows[0]) {
        await client.query(
          `INSERT INTO users (id, identity_subject, verified_email, email_verified, status)
           VALUES ($1, $2, $3, $4, 'active')`,
          [userId, payload.sub, verified ? payload.email : null, verified],
        );
      } else if (verified && existing.rows[0].verified_email !== payload.email) {
        await client.query(
          `UPDATE users SET verified_email = $2, email_verified = true, updated_at = now(), version = version + 1 WHERE id = $1`,
          [userId, payload.email],
        );
      }
      const roles = await client.query<{ role: OperatorRole }>(
        `SELECT role FROM operator_roles WHERE user_id = $1 AND revoked_at IS NULL`,
        [userId],
      );
      const roleList = roles.rows.map((row) => row.role);
      const org = await client.query<{ id: string }>(
        `SELECT id FROM organizations WHERE owner_user_id = $1 AND status = 'active'`,
        [userId],
      );
      const organizationId = org.rows[0]?.id ?? "";
      let actorName: OperatorRole | "customer" = "customer";
      if (mode === "operator") {
        const role = highestRole(roleList);
        if (!role) throw new HttpError(403, "FORBIDDEN", "An operator role is required.");
        actorName = role;
      }
      await applySettings(client, {
        actor: actorName,
        subject: payload.sub!,
        email: payload.email,
        userId,
        organizationId,
        bootstrap: "",
      });
      const actor: Actor = {
        subject: payload.sub!,
        email: payload.email,
        emailVerified: verified,
        authTime: typeof payload.auth_time === "number" ? payload.auth_time : 0,
        amr: Array.isArray(payload.amr) ? payload.amr.filter((item): item is string => typeof item === "string") : [],
        userId,
        organizationId: organizationId || null,
        roles: roleList,
      };
      if(deps.identityPlatform&&payload.iss===`https://securetoken.google.com/${deps.identityPlatform.projectId}`){
        // Upstream/custom amr claims cannot substitute for this application's verified MFA session.
        actor.amr=[];
        const token=cookieValue(request,"bp_operator_mfa");
        if(token&&roleList.length){
          const mfa=(await client.query<{authenticated_at:Date}>(`SELECT authenticated_at FROM operator_mfa_sessions WHERE token_hash=$1 AND user_id=$2 AND identity_issuer=$3 AND identity_subject=$4 AND first_factor_auth_time=$5 AND expires_at>now()`,[hashToken(token),userId,payload.iss,payload.bearportalIdentitySubject,payload.auth_time])).rows[0];
          if(mfa){actor.amr=["totp"];actor.authTime=Math.floor(mfa.authenticated_at.getTime()/1000)}
        }
        if(mode==="operator"&&!actor.amr.includes("totp"))throw new HttpError(403,"MFA_REQUIRED","Confirm your authenticator at /operator/security before opening operator inventory.");
      }
      consumeLimit(rateHits, actor.userId, "api", 120, 60_000);
      const result = await fn(client, actor);
      await client.query("COMMIT");
      return result;
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      await client.query("DISCARD ALL").catch(() => undefined);
      client.release();
    }
  }

  function requireVerified(actor: Actor): void {
    if (!actor.emailVerified) throw new HttpError(403, "EMAIL_UNVERIFIED", "Verify your email before changing the account.");
  }

  function requireMfa(actor: Actor, windowSeconds = MFA_WINDOW_SECONDS): void {
    const fresh = actor.authTime > 0 && Math.floor(Date.now() / 1000) - actor.authTime <= windowSeconds;
    if (!actor.amr.includes("totp") || !fresh) {
      throw new HttpError(403, "MFA_REQUIRED", "A recent authenticator confirmation is required.");
    }
  }

  app.get("/v1/me", async (request) => {
    return withActor(request, "customer", async (db, actor) => ({
      requestId: request.id,
      identity: { email: actor.email, emailVerified: actor.emailVerified },
      organizationId: actor.organizationId,
      roles: actor.roles,
      allocationState: actor.organizationId ? await allocationState(db, actor.organizationId) : null,
    }));
  });

  app.post("/v1/organizations", async (request, reply) => {
    const idempotencyKey = demandIdempotency(request);
    const body = organizationCreateSchema.parse(request.body);
    const created = await withActor(request, "customer", async (db, actor) => {
      requireVerified(actor);
      const route = "POST /v1/organizations";
      const replayed = await replay(db, actor.userId, route, idempotencyKey, body, deps.secretKeyHex);
      if (replayed) return replayed;
      if (actor.organizationId) throw new HttpError(409, "ORGANIZATION_EXISTS", "This account already has an organization.");
      const tokenHash = hashToken(body.invitationToken);
      const invitation = await db.query<{ id: string; bound_email: string; expires_at: Date; consumed_at: Date | null }>(
        `SELECT id, bound_email, expires_at, consumed_at FROM invitations WHERE token_hash = $1`,
        [tokenHash],
      );
      const row = invitation.rows[0];
      if (!row || row.bound_email.toLowerCase() !== actor.email.toLowerCase()) {
        throw new HttpError(403, "INVITATION_INVALID", "The invitation does not match this email.");
      }
      if (row.consumed_at || row.expires_at.getTime() <= Date.now()) {
        throw new HttpError(409, "INVITATION_USED", "The invitation is no longer usable.");
      }
      const organizationId = randomUUID();
      await applySettings(db, {
        actor: "customer",
        subject: actor.subject,
        email: actor.email,
        userId: actor.userId,
        organizationId,
        bootstrap: "",
      });
      await db.query(
        `INSERT INTO organizations (id, owner_user_id, name, status, billing_required) VALUES ($1, $2, $3, 'active', $4)`,
        [organizationId, actor.userId, body.name, deps.billingRequired !== false],
      );
      await db.query(
        `UPDATE invitations SET consumed_at = now(), consumed_by = $2 WHERE id = $1`,
        [row.id, actor.userId],
      );
      const allocationId = randomUUID();
      await db.query(
        `INSERT INTO allocation_requests (id, organization_id, profile_code, verified_registered_at, state)
         VALUES ($1, $2, 'e2-micro', now(), 'waiting_for_server')`,
        [allocationId, organizationId],
      );
      requireOperation("organization.allocate");
      await setActor(db, "allocator");
      const allocation = await allocateProfile(db, "e2-micro", 100);
      await setActor(db, "customer");
      for (const item of allocation.assigned) {
        await audit(db, request, actor.userId, item.organizationId, "server.allocate", item.serverId, { assignmentId: item.assignmentId });
      }
      await audit(db, request, actor.userId, organizationId, "organization.create", organizationId, { name: body.name });
      const state = await allocationState(db, organizationId);
      const server = state === "allocated" ? await readCustomerServer(db, organizationId) : null;
      const response = { id: organizationId, allocationState: state, server };
      await remember(db, actor.userId, route, idempotencyKey, body, 201, response, deps.secretKeyHex);
      return { status: 201 as const, body: response };
    });
    return reply.code(created.status).send({ ...created.body, requestId: request.id });
  });

  app.post("/v1/domains", async (request, reply) => {
    const idempotencyKey = demandIdempotency(request);
    const body = domainCreateSchema.parse(request.body);
    const domainName = normalizeDomain(body.domain);
    const hashed = { domain: domainName, existingMail: body.existingMail };
    const created = await withActor(request, "customer", async (db, actor) => {
      requireVerified(actor);
      consumeLimit(rateHits, actor.userId, "domain", 10, 60 * 60 * 1000);
      if (!actor.organizationId) throw new HttpError(422, "ORGANIZATION_REQUIRED", "Create an organization first.");
      const route = "POST /v1/domains";
      const replayed = await replay(db, actor.userId, route, idempotencyKey, hashed, deps.secretKeyHex);
      if (replayed) return replayed;
      if (!recoveryIsOutsideDomain(actor.email, domainName)) {
        throw new HttpError(422, "RECOVERY_EMAIL_INSIDE_DOMAIN", "The recovery email must be outside the domain being hosted.");
      }
      const id = randomUUID();
      await db.query(
        `INSERT INTO domains (id, organization_id, normalized_name, existing_mail, state)
         VALUES ($1, $2, $3, $4, 'pending')`,
        [id, actor.organizationId, domainName, body.existingMail],
      );
      await audit(db, request, actor.userId, actor.organizationId, "domain.create", id, { domain: domainName });
      const response = { id, domain: domainName, state: "pending" };
      await remember(db, actor.userId, route, idempotencyKey, hashed, 201, response, deps.secretKeyHex);
      return { status: 201 as const, body: response };
    });
    return reply.code(created.status).send({ ...created.body, requestId: request.id });
  });

  app.get("/v1/domains/:id", async (request) => {
    const { id } = request.params as { id: string };
    return withActor(request, "customer", async (db, actor) => {
      const row = await db.query(
        `SELECT id, normalized_name, state FROM domains WHERE id = $1 AND organization_id = $2`,
        [id, actor.organizationId],
      );
      if (!row.rows[0]) throw new HttpError(404, "NOT_FOUND", "The domain was not found.");
      return { ...row.rows[0], requestId: request.id };
    });
  });

  app.post("/v1/dns-connections", async (request, reply) => {
    const idempotencyKey = demandIdempotency(request);
    const body = dnsConnectionCreateSchema.parse(request.body);
    validateCredentialShape({ provider: body.provider, credentials: body.credentials });
    const created = await withActor(request, "customer", async (db, actor) => {
      requireVerified(actor);
      if (!actor.organizationId) throw new HttpError(422, "ORGANIZATION_REQUIRED", "Create an organization first.");
      consumeLimit(rateHits, actor.userId, "credential", 10, 60 * 60 * 1000);
      const route = "POST /v1/dns-connections";
      const replayed = await replay(db, actor.userId, route, idempotencyKey, body, deps.secretKeyHex);
      if (replayed) return replayed;
      const domain = await db.query(
        `SELECT id FROM domains WHERE id = $1 AND organization_id = $2`,
        [body.domainId, actor.organizationId],
      );
      if (!domain.rows[0]) throw new HttpError(404, "NOT_FOUND", "The domain was not found.");
      if (!credentialAccepted(body.credentials)) {
        throw new HttpError(422, "DNS_CREDENTIAL_REJECTED", "The DNS credential was rejected.");
      }
      requireOperation("dns.store_credentials");
      const fileName = secrets.write(JSON.stringify(body.credentials));
      const secretId = randomUUID();
      await db.query(
        `INSERT INTO secret_refs (id, organization_id, purpose, file_name, key_id, state)
         VALUES ($1, $2, 'dns', $3, 'local-1', 'active')`,
        [secretId, actor.organizationId, fileName],
      );
      const id = randomUUID();
      await db.query(
        `INSERT INTO dns_connections
           (id, organization_id, domain_id, provider, zone_id, secret_ref, state)
         VALUES ($1, $2, $3, $4, $5, $6, 'stored')`,
        [id, actor.organizationId, body.domainId, body.provider, body.zoneId, secretId],
      );
      await audit(db, request, actor.userId, actor.organizationId, "dns.store", id, {
        provider: body.provider,
        zoneId: body.zoneId,
        secretRef: secretId,
      });
      const response = { id, provider: body.provider, state: "stored", version: 1 };
      await remember(db, actor.userId, route, idempotencyKey, body, 201, response, deps.secretKeyHex);
      return { status: 201 as const, body: response };
    });
    return reply.code(created.status).send({ ...created.body, requestId: request.id });
  });

  app.get("/v1/dns-connections/:id", async (request) => {
    const { id } = request.params as { id: string };
    return withActor(request, "customer", async (db, actor) => {
      const row = await db.query(
        `SELECT id, provider, zone_id, state, version FROM dns_connections WHERE id = $1 AND organization_id = $2`,
        [id, actor.organizationId],
      );
      if (!row.rows[0]) throw new HttpError(404, "NOT_FOUND", "The DNS connection was not found.");
      return { ...row.rows[0], requestId: request.id };
    });
  });

  app.post("/v1/dns-connections/:id/rotate", async (request, reply) => {
    const idempotencyKey = demandIdempotency(request);
    const { id } = request.params as { id: string };
    const body = dnsConnectionRotateSchema.parse(request.body);
    const created = await withActor(request, "customer", async (db, actor) => {
      requireVerified(actor);
      consumeLimit(rateHits, actor.userId, "credential", 10, 60 * 60 * 1000);
      const route = "POST /v1/dns-connections/:id/rotate";
      const replayed = await replay(db, actor.userId, route, idempotencyKey, { id, ...body }, deps.secretKeyHex);
      if (replayed) return replayed;
      const current = await db.query<{ secret_ref: string; provider: string; version: number; file_name: string }>(
        `SELECT c.secret_ref, c.provider, c.version, s.file_name
         FROM dns_connections c JOIN secret_refs s ON s.id = c.secret_ref
         WHERE c.id = $1 AND c.organization_id = $2`,
        [id, actor.organizationId],
      );
      const row = current.rows[0];
      if (!row) throw new HttpError(404, "NOT_FOUND", "The DNS connection was not found.");
      if (row.version !== body.expectedVersion) throw new HttpError(409, "VERSION_CONFLICT", "The DNS connection changed.");
      validateCredentialShape({ provider: row.provider, credentials: body.credentials });
      if (!credentialAccepted(body.credentials)) {
        await audit(db, request, actor.userId, actor.organizationId, "dns.rotate_rejected", id, { secretRef: row.secret_ref });
        const response = { id, state: "stored", version: row.version, rotated: false };
        await remember(db, actor.userId, route, idempotencyKey, { id, ...body }, 200, response, deps.secretKeyHex);
        return { status: 200 as const, body: response };
      }
      const fileName = secrets.write(JSON.stringify(body.credentials));
      const secretId = randomUUID();
      await db.query(
        `INSERT INTO secret_refs (id, organization_id, purpose, file_name, key_id, state)
         VALUES ($1, $2, 'dns', $3, 'local-1', 'active')`,
        [secretId, actor.organizationId, fileName],
      );
      await db.query(
        `UPDATE secret_refs SET state = 'retired', retired_at = now() WHERE id = $1`,
        [row.secret_ref],
      );
      await db.query(
        `UPDATE dns_connections SET secret_ref = $2, version = version + 1, updated_at = now() WHERE id = $1`,
        [id, secretId],
      );
      await audit(db, request, actor.userId, actor.organizationId, "dns.rotate", id, { secretRef: secretId });
      const response = { id, state: "stored", version: row.version + 1, rotated: true };
      await remember(db, actor.userId, route, idempotencyKey, { id, ...body }, 200, response, deps.secretKeyHex);
      return { status: 200 as const, body: response };
    });
    return reply.code(created.status).send({ ...created.body, requestId: request.id });
  });

  app.get("/v1/jobs/:id", async (request) => {
    const { id } = request.params as { id: string };
    return withActor(request, "customer", async (db, actor) => {
      const row = await db.query(`SELECT id, kind, state FROM jobs WHERE id = $1 AND organization_id = $2`, [id, actor.organizationId]);
      if (!row.rows[0]) throw new HttpError(404, "NOT_FOUND", "The job was not found.");
      return { ...row.rows[0], requestId: request.id };
    });
  });

  app.get("/v1/deployments/:id", async (request) => {
    const { id } = request.params as { id: string };
    return withActor(request, "customer", async (db, actor) => {
      const row = await db.query(
        `SELECT id, lifecycle_state, onboarding_stage, desired_state, health_state, generation, version,
                mail_hostname, webmail_hostname, release_id, host(observed_ip) AS observed_ip,
                installer_status, dns_writes_accepted, brevo_authenticated, brevo_verified, mail_verified,
                previous_mx, published_records, mx_authorized_at IS NOT NULL AS mx_authorized
         FROM deployments WHERE id = $1 AND organization_id = $2`,
        [id, actor.organizationId],
      );
      if (!row.rows[0]) throw new HttpError(404, "NOT_FOUND", "The deployment was not found.");
      const actions = await db.query(
        `SELECT id, code, audience FROM required_actions
         WHERE organization_id = $1 AND state = 'open' AND (deployment_id IS NULL OR deployment_id = $2)
         ORDER BY created_at DESC LIMIT 20`,
        [actor.organizationId, id],
      );
      return { ...row.rows[0], requiredActions: actions.rows, requestId: request.id };
    });
  });

  app.get("/v1/deployments/:id/events", async (request) => {
    const { id } = request.params as { id: string };
    return withActor(request, "customer", async (db, actor) => {
      const row = await db.query(`SELECT id FROM deployments WHERE id = $1 AND organization_id = $2`, [id, actor.organizationId]);
      if (!row.rows[0]) throw new HttpError(404, "NOT_FOUND", "The deployment was not found.");
      return { events: [], requestId: request.id };
    });
  });

  app.get("/v1/deployments/:id/events/stream", async (request, reply) => {
    const { id } = request.params as { id: string };
    await withActor(request, "customer", async (db, actor) => {
      const row = await db.query(`SELECT id FROM deployments WHERE id = $1 AND organization_id = $2`, [id, actor.organizationId]);
      if (!row.rows[0]) throw new HttpError(404, "NOT_FOUND", "The deployment was not found.");
      return true;
    });
    reply.hijack();
    reply.raw.writeHead(200, {
      "content-type": "text/event-stream",
      "cache-control": "no-cache",
      "x-request-id": request.id,
    });
    reply.raw.end(`event: ready\ndata: {}\n\n`);
  });

  app.get("/v1/deployments/:id/backups", async (request) => {
    const { id } = request.params as { id: string };
    return withActor(request, "customer", async (db, actor) => {
      const deployment = await db.query(`SELECT id FROM deployments WHERE id = $1 AND organization_id = $2`, [id, actor.organizationId]);
      if (!deployment.rows[0]) throw new HttpError(404, "NOT_FOUND", "The deployment was not found.");
      const backups = await db.query<{
        id: string;
        state: string;
        evidence_source: string;
        consistency_state: string | null;
        completed_at: Date | null;
        restore_verified_at: Date | null;
        reported_at: Date | null;
        cloud_verified: boolean;
      }>(
        `SELECT id, state, evidence_source, consistency_state, completed_at, restore_verified_at, reported_at, cloud_verified
         FROM backups WHERE deployment_id = $1 AND organization_id = $2
         ORDER BY created_at DESC`,
        [id, actor.organizationId],
      );
      return {
        backups: backups.rows.map((row) => ({
          id: row.id,
          state: row.state,
          evidence_source: row.evidence_source,
          consistencyState: row.consistency_state,
          completedAt: row.completed_at,
          restoreVerifiedAt: row.restore_verified_at,
          reportedAt: row.reported_at,
          provenance: row.evidence_source === "operator" ? "operator-reported" : row.evidence_source,
          cloudVerified: row.cloud_verified,
          freshness: backupFreshness(row.completed_at, Date.now()),
        })),
        requestId: request.id,
      };
    });
  });

  app.post("/v1/admin/invitations", async (request, reply) => {
    const idempotencyKey = demandIdempotency(request);
    const body = invitationCreateSchema.parse(request.body);
    const created = await withActor(request, "operator", async (db, actor) => {
      requireVerified(actor);
      if (!actor.roles.includes("platform_administrator")) throw new HttpError(403, "FORBIDDEN", "A platform administrator is required.");
      requireMfa(actor);
      const route = "POST /v1/admin/invitations";
      const replayed = await replay(db, actor.userId, route, idempotencyKey, body, deps.secretKeyHex);
      if (replayed) return replayed;
      const token = randomUUID() + randomUUID().replaceAll("-", "");
      const id = randomUUID();
      const expires = new Date(Date.now() + body.expiresInHours * 3600 * 1000);
      await db.query(
        `INSERT INTO invitations (id, bound_email, token_hash, expires_at, created_by)
         VALUES ($1, $2, $3, $4, $5)`,
        [id, body.boundEmail.toLowerCase(), hashToken(token), expires, actor.userId],
      );
      await audit(db, request, actor.userId, null, "invitation.create", id, { boundEmail: body.boundEmail.toLowerCase() });
      const response = {
        id,
        boundEmail: body.boundEmail.toLowerCase(),
        expiresAt: expires.toISOString(),
        tokenReplayable: false,
      };
      await remember(db, actor.userId, route, idempotencyKey, body, 201, response, deps.secretKeyHex);
      return { status: 201 as const, body: { ...response, invitationToken: token } };
    });
    return reply.code(created.status).send({ ...created.body, requestId: request.id });
  });

  app.post("/v1/admin/operator-roles", async (request, reply) => {
    const idempotencyKey = demandIdempotency(request);
    const body = operatorRoleGrantSchema.parse(request.body);
    const created = await withActor(request, "operator", async (db, actor) => {
      requireVerified(actor);
      if (!actor.roles.includes("platform_administrator")) throw new HttpError(403, "FORBIDDEN", "A platform administrator is required.");
      requireMfa(actor);
      const route = "POST /v1/admin/operator-roles";
      const replayed = await replay(db, actor.userId, route, idempotencyKey, body, deps.secretKeyHex);
      if (replayed) return replayed;
      const id = randomUUID();
      await db.query(
        `INSERT INTO operator_roles (id, user_id, role, granted_by, reason) VALUES ($1, $2, $3, $4, $5)`,
        [id, body.userId, body.role, actor.userId, body.reason],
      );
      await audit(db, request, actor.userId, null, "operator_role.grant", id, { role: body.role, userId: body.userId });
      const response = { id, role: body.role };
      await remember(db, actor.userId, route, idempotencyKey, body, 201, response, deps.secretKeyHex);
      return { status: 201 as const, body: response };
    });
    return reply.code(created.status).send({ ...created.body, requestId: request.id });
  });

  app.get("/v1/admin/audit-events", async (request) => {
    return withActor(request, "operator", async (db) => {
      const rows = await db.query(
        `SELECT id, actor_type, action, target, occurred_at FROM audit_events ORDER BY occurred_at DESC LIMIT 100`,
      );
      return { events: rows.rows, requestId: request.id };
    });
  });

  app.get("/v1/admin/secret-refs/:id", async (request) => {
    const { id } = request.params as { id: string };
    return withActor(request, "operator", async (db, actor) => {
      if (actor.roles.includes("support") && !actor.roles.includes("platform_administrator") && !actor.roles.includes("infrastructure_operator")) {
        throw new HttpError(403, "FORBIDDEN", "Support cannot read credentials.");
      }
      requireMfa(actor);
      const row = await db.query(`SELECT id, purpose, state, version FROM secret_refs WHERE id = $1`, [id]);
      if (!row.rows[0]) throw new HttpError(404, "NOT_FOUND", "The secret reference was not found.");
      return { ...row.rows[0], requestId: request.id };
    });
  });

  async function setActor(db: Queryable, actor: string): Promise<void> {
    await db.query("SELECT set_config('bearportal.actor', $1, true)", [actor]);
  }

  async function withSystem<T>(actor: "allocator" | "inventory_worker", fn: (db: Db) => Promise<T>): Promise<T> {
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await applySettings(client, { actor, subject: "", email: "", userId: "", organizationId: "", bootstrap: "" });
      const result = await fn(client);
      await client.query("COMMIT");
      return result;
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      await client.query("DISCARD ALL").catch(() => undefined);
      client.release();
    }
  }

  const enforceSubscription = deps.billingRequired === false ? async () => {} : requireSubscription;
  const inventoryContext: InventoryContext = {
    billingRequired: deps.billingRequired !== false,
    requireSubscription: enforceSubscription,
    withActor,
    withSystem,
    demandIdempotency,
    requireVerified,
    requireMfa: (actor) => requireMfa(actor, 2 * 60 * 60),
    consumeLimit: (actorId, bucket, limit, windowMs) => consumeLimit(rateHits, actorId, bucket, limit, windowMs),
    replay: (db, principalId, route, key, body) => replay(db, principalId, route, key, body, deps.secretKeyHex),
    remember: (db, principalId, route, key, body, status, response) => remember(db, principalId, route, key, body, status, response, deps.secretKeyHex),
    audit,
    setActor,
    secrets,
    zoneReader,
    relayChecker,
    operatorBrevo,
    lookupNameservers,
    publishBrevoRecords,
    sshProbe: deps.sshProbe,
    schedulerToken: deps.schedulerToken,
    addressRepair: (db, input) => repairAssignedAddress({
      withActor,
      withSystem,
      demandIdempotency,
      requireVerified,
      requireMfa,
      consumeLimit: (actorId, bucket, limit, windowMs) => consumeLimit(rateHits, actorId, bucket, limit, windowMs),
      replay: (db, principalId, route, key, body) => replay(db, principalId, route, key, body, deps.secretKeyHex),
      remember: (db, principalId, route, key, body, status, response) => remember(db, principalId, route, key, body, status, response, deps.secretKeyHex),
      audit,
      setActor,
      secrets,
      brevoClient,
      installerRunner,
      dnsObserver,
      release: deps.release,
      installFromSource,
      schedulerToken: deps.schedulerToken,
    }, db, input),
  };
  const refreshBilling = registerBilling(app, inventoryContext, deps.billing, deps.stripe);
  registerInventoryRoutes(app, inventoryContext);
  registerOperatorInventory(app, inventoryContext);
  registerAdminCredentials(app, inventoryContext);
  registerBrowserAuth(app,inventoryContext,deps.identityPlatform,identityClient,deps.secretKeyHex);

  const installationContext: InstallationContext = {
    billingRequired: deps.billingRequired !== false,
    requireSubscription: enforceSubscription,
    withActor,
    withSystem,
    demandIdempotency,
    requireVerified,
    requireMfa,
    consumeLimit: (actorId, bucket, limit, windowMs) => consumeLimit(rateHits, actorId, bucket, limit, windowMs),
    replay: (db, principalId, route, key, body) => replay(db, principalId, route, key, body, deps.secretKeyHex),
    remember: (db, principalId, route, key, body, status, response) => remember(db, principalId, route, key, body, status, response, deps.secretKeyHex),
    audit,
    setActor,
    secrets,
    brevoClient,
    installerRunner,
    dnsObserver,
    release: deps.release,
    installFromSource,
    schedulerToken: deps.schedulerToken,
  };
  registerInstallationRoutes(app, installationContext);
  inventoryContext.onboardingRequested = registerOnboarding(app, inventoryContext, installationContext, deps.onboardingIntervalMs ?? 30_000, deps.installedTlsProbe);

  registerOversightRoutes(app, {
    withActor,
    withSystem,
    demandIdempotency,
    requireVerified,
    requireMfa,
    replay: (db, principalId, route, key, body) => replay(db, principalId, route, key, body, deps.secretKeyHex),
    remember: (db, principalId, route, key, body, status, response) => remember(db, principalId, route, key, body, status, response, deps.secretKeyHex),
    audit,
    schedulerToken: deps.schedulerToken,
  });

  registerLifecycleRoutes(app, {
    refreshBilling,
    billingRequired: deps.billingRequired !== false,
    billingConfigured: Boolean(deps.billing),
    browserAuthEnabled:Boolean(deps.identityPlatform),
    withActor,
    withSystem,
    demandIdempotency,
    requireVerified,
    requireMfa,
    replay: (db, principalId, route, key, body) => replay(db, principalId, route, key, body, deps.secretKeyHex),
    remember: (db, principalId, route, key, body, status, response) => remember(db, principalId, route, key, body, status, response, deps.secretKeyHex),
    audit,
    lookupNameservers,
    schedulerToken: deps.schedulerToken,
  });

  return app;
}

function credentialAccepted(credentials: unknown): boolean {
  return !JSON.stringify(credentials).includes("reject:");
}

async function readInstallerSecret(pool: pg.Pool, secrets: SecretStore, secretId: string): Promise<string> {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(secretId)) {
    throw new Error("The installer secret id is not a UUID.");
  }
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("SELECT set_config('bearportal.actor', 'platform_administrator', true)");
    const found = await client.query<{ file_name: string }>(
      "SELECT file_name FROM secret_refs WHERE id = $1 AND state = 'active'",
      [secretId],
    );
    await client.query("COMMIT");
    const fileName = found.rows[0]?.file_name;
    if (!fileName) throw new Error("The installer secret is not stored.");
    return secrets.read(fileName);
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}

function highestRole(roles: OperatorRole[]): OperatorRole | null {
  if (roles.includes("platform_administrator")) return "platform_administrator";
  if (roles.includes("infrastructure_operator")) return "infrastructure_operator";
  return roles.includes("support") ? "support" : null;
}

async function applySettings(db: Db, settings: {
  actor: string;
  subject: string;
  email: string;
  userId: string;
  organizationId: string;
  bootstrap: string;
}): Promise<void> {
  const pairs: Array<[string, string]> = [
    ["bearportal.actor", settings.actor],
    ["bearportal.subject", settings.subject],
    ["bearportal.email", settings.email],
    ["bearportal.user_id", settings.userId],
    ["bearportal.organization_id", settings.organizationId],
    ["bearportal.bootstrap", settings.bootstrap],
  ];
  for (const [key, value] of pairs) {
    await db.query("SELECT set_config($1, $2, true)", [key, value]);
  }
}

async function allocationState(db: Db, organizationId: string): Promise<string> {
  const row = await db.query<{ state: string }>(
    `SELECT state FROM allocation_requests WHERE organization_id = $1 AND state <> 'cancelled' ORDER BY created_at DESC LIMIT 1`,
    [organizationId],
  );
  return row.rows[0]?.state ?? "waiting_for_server";
}

async function audit(
  db: Queryable,
  request: FastifyRequest,
  actorId: string,
  organizationId: string | null,
  action: string,
  target: string,
  redacted: Record<string, unknown>,
): Promise<void> {
  await db.query(
    `INSERT INTO audit_events (id, actor_type, actor_id, organization_id, action, target, request_id, redacted_diff)
     VALUES ($1, 'user', $2, $3, $4, $5, $6, $7::jsonb)`,
    [randomUUID(), actorId, organizationId, action, target, request.id, JSON.stringify(redacted)],
  );
}

function requestHash(body: unknown, keyHex: string): string {
  return createHmac("sha256", Buffer.from(keyHex, "hex")).update(stable(body)).digest("hex");
}

async function replay(db: Queryable, principalId: string, route: string, key: string, body: unknown, keyHex: string) {
  const hash = requestHash(body, keyHex);
  const existing = await db.query<{ request_hash: string; response: unknown; status_code: number }>(
    `SELECT request_hash, response, status_code FROM idempotency_keys WHERE principal_id = $1 AND route = $2 AND key = $3`,
    [principalId, route, key],
  );
  const row = existing.rows[0];
  if (!row) return null;
  if (row.request_hash !== hash) throw new HttpError(409, "IDEMPOTENCY_CONFLICT", "This idempotency key was used for a different request.");
  return { status: row.status_code, body: row.response as Record<string, unknown> };
}

async function remember(db: Queryable, principalId: string, route: string, key: string, body: unknown, status: number, response: unknown, keyHex: string) {
  await db.query(
    `INSERT INTO idempotency_keys (id, principal_id, route, key, request_hash, response, status_code, expires_at)
     VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, now() + interval '7 days')`,
    [randomUUID(), principalId, route, key, requestHash(body, keyHex), JSON.stringify(response), status],
  );
}

function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

function stable(value: unknown): string {
  return JSON.stringify(sortValue(value));
}

function sortValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortValue);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b)).map(([key, item]) => [key, sortValue(item)]));
  }
  return value;
}

function bearer(request: FastifyRequest): string | null {
  const header = request.headers.authorization;
  if (!header?.startsWith("Bearer ")) return null;
  return header.slice(7);
}

function usesCookie(request: FastifyRequest): boolean {
  return !bearer(request) && Boolean(cookieToken(request));
}

function csrfAccepted(request: FastifyRequest): boolean {
  if (request.headers["x-bearportal-csrf"] === "1") return true;
  const body = request.body;
  if (!body || typeof body !== "object" || Array.isArray(body)) return false;
  return (body as { csrf?: unknown }).csrf === "1";
}

function cookieToken(request: FastifyRequest): string | null {
  const raw = request.headers.cookie;
  if (!raw) return null;
  const match = raw.split(";").map((part) => part.trim()).find((part) => part.startsWith("bp_session="));
  return match ? decodeURIComponent(match.slice("bp_session=".length)) : null;
}

function sessionCookie(token: string): string {
  return `bp_session=${encodeURIComponent(token)}; HttpOnly; SameSite=Lax; Path=/`;
}

function consumeLimit(hits: Map<string, number[]>, actorId: string, bucket: string, limit: number, windowMs: number): void {
  const now = Date.now();
  const key = `${actorId}:${bucket}`;
  const recent = (hits.get(key) ?? []).filter((stamp) => now - stamp < windowMs);
  if (recent.length >= limit) {
    throw new HttpError(429, "RATE_LIMITED", "Too many requests.", true);
  }
  recent.push(now);
  hits.set(key, recent);
}

function isZodError(error: unknown): boolean {
  if (!error || typeof error !== "object") return false;
  if (error instanceof ZodError || (error as { name?: string }).name === "ZodError") return true;
  return isZodError((error as { cause?: unknown }).cause);
}

function pgCode(error: unknown): string | undefined {
  if (!error || typeof error !== "object") return undefined;
  const code = (error as { code?: unknown }).code;
  if (typeof code === "string") return code;
  return pgCode((error as { cause?: unknown }).cause);
}

function sendError(
  reply: FastifyReply,
  request: FastifyRequest,
  status: number,
  code: string,
  message: string,
  retryable = false,
  requiredActionId: string | null = null,
) {
  return reply.code(status).send({
    error: { code, message, retryable, requiredActionId },
    requestId: request.id,
  });
}

export async function bootstrapAdmin(databaseUrl: string, subject: string, email: string): Promise<{ userId: string }> {
  const client = new pg.Client({ connectionString: databaseUrl });
  await client.connect();
  try {
    await client.query("BEGIN");
    const userId = randomUUID();
    await applySettings(client, {
      actor: "platform_administrator",
      subject,
      email,
      userId,
      organizationId: "",
      bootstrap: "1",
    });
    const existing = await client.query(`SELECT 1 FROM operator_roles WHERE role = 'platform_administrator' AND revoked_at IS NULL`);
    if (existing.rowCount) throw new Error("A platform administrator already exists.");
    await client.query(
      `INSERT INTO users (id, identity_subject, verified_email, email_verified, status) VALUES ($1, $2, $3, true, 'active')`,
      [userId, subject, email],
    );
    await client.query(
      `INSERT INTO operator_roles (id, user_id, role, reason) VALUES ($1, $2, 'platform_administrator', 'initial bootstrap')`,
      [randomUUID(), userId],
    );
    await client.query(
      `INSERT INTO audit_events (id, actor_type, actor_id, action, target, request_id, redacted_diff)
       VALUES ($1, 'bootstrap', $2, 'operator_role.bootstrap', $3, $4, '{"role":"platform_administrator"}'::jsonb)`,
      [randomUUID(), userId, userId, randomUUID()],
    );
    await client.query("COMMIT");
    return { userId };
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    await client.end();
  }
}

export function controlPlaneHostname(): string {
  return hostname();
}
