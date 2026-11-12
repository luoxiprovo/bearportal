import { CUSTOMER_SESSION_SCRIPT } from "./customer-session-script.ts";
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z } from "zod";
import type { IdentityPlatformConfig } from "./identity-platform-config.ts";
import type {
  IdentityPlatformClient,
  IdentityTokens,
} from "./identity-platform-client.ts";
import { validatePlatformClaims } from "./identity-platform-client.ts";
import { completeIdentityAccount } from "./identity-accounts.ts";
import type { InventoryContext } from "./inventory.ts";
import { HttpError } from "./errors.ts";
import { BROWSER_AUTH_SCRIPT } from "./browser-auth-script.ts";

import {cookieValue,cookie} from "./auth-cookies.ts";
import {registerOperatorAuth} from "./operator-auth.ts";
import {hashToken} from "./operator-totp.ts";

function signState(value: string, key: string) {
  return createHmac("sha256", Buffer.from(key, "hex"))
    .update("bearportal.login." + value)
    .digest("base64url");
}
export function registerBrowserAuth(
  app: FastifyInstance,
  ctx: InventoryContext,
  config: IdentityPlatformConfig | undefined,
  client: IdentityPlatformClient | undefined,
  keyHex: string,
) {
  app.get("/assets/customer-session.js", async (_request, reply) => reply.type("application/javascript; charset=utf-8").header("cache-control", "no-store").send(CUSTOMER_SESSION_SCRIPT));
  const requireConfig = () => {
    if (!config || !client)
      throw new HttpError(
        503,
        "AUTH_NOT_CONFIGURED",
        "Account sign-in is not configured yet. Contact the operator.",
      );
    return { config, client };
  };
  function authorize(request: FastifyRequest) {
    const { config } = requireConfig();
    const origin = request.headers.origin;
    if (!origin || !config.origins.includes(origin))
      throw new HttpError(
        403,
        "CSRF",
        "Reload the sign-in page and try again.",
      );
    const header = request.headers["x-bearportal-auth-csrf"];
    const state = cookieValue(request, "bp_login");
    if (typeof header !== "string" || header !== state || state.length > 200)
      throw new HttpError(
        403,
        "CSRF",
        "Reload the sign-in page and try again.",
      );
    const [random, stamp, signature, ...extra] = state.split(".");
    const value = random + "." + stamp;
    const expected = signState(value, keyHex);
    const age = Date.now() - Number(stamp);
    if (
      extra.length ||
      !/^[A-Za-z0-9_-]{43}$/.test(random ?? "") ||
      !signature ||
      signature.length !== expected.length ||
      !Number.isFinite(age) ||
      age < 0 ||
      age > 15 * 60_000 ||
      !timingSafeEqual(Buffer.from(signature), Buffer.from(expected))
    )
      throw new HttpError(
        403,
        "CSRF",
        "Reload the sign-in page and try again.",
      );
    ctx.consumeLimit(request.ip, "browser-auth", 30, 15 * 60_000);
    return { origin, nonce: state };
  }
  app.get("/auth/options", async (request, reply) => {
    reply
      .header("cache-control", "no-store")
      .header("referrer-policy", "no-referrer");
    if (!config) return { configured: false };
    ctx.consumeLimit(request.ip, "browser-auth-options", 60, 15 * 60_000);
    const value = randomBytes(32).toString("base64url") + "." + Date.now();
    const state = value + "." + signState(value, keyHex);
    // A GET has no Origin header; the configured scheme controls Secure and POSTs enforce exact origins.
    reply.header(
      "set-cookie",
      cookie("bp_login", state, config.origins[0], "/auth", 15 * 60),
    );
    return {
      configured: true,
      googleClientId: config.googleClientId,
      csrf: state,
      nonce: state,
      hasRefreshSession: Boolean(cookieValue(request, "bp_refresh")),
    };
  });
  app.get("/assets/auth.js", async (_request, reply) =>
    reply
      .type("text/javascript; charset=utf-8")
      .header("cache-control", "no-cache")
      .send(BROWSER_AUTH_SCRIPT),
  );
  async function finish(
    request: FastifyRequest,
    reply: FastifyReply,
    tokens: IdentityTokens,
    origin: string,
    authoritativeGoogle = false,
  ) {
    const { config, client } = requireConfig();
    const claims = validatePlatformClaims(
      await client.verify(tokens.idToken),
      config,
    );
    const cookies = [
      cookie(
        "bp_refresh",
        tokens.refreshToken,
        origin,
        "/auth",
        30 * 24 * 60 * 60,
      ),
    ];
    reply
      .header("cache-control", "no-store")
      .header("referrer-policy", "no-referrer");
    if (claims.email_verified !== true) {
      cookies.push(cookie("bp_session", "", origin, "/", 0));
      reply.header("set-cookie", cookies);
      return { state: "verify_email", email: claims.email };
    }
    const account=await completeIdentityAccount(
      ctx,
      claims,
      request,
      claims.firebase.sign_in_provider === "password" || authoritativeGoogle,
    );
    await revokeOperatorSession(request);
    cookies.push(cookie("bp_session", tokens.idToken, origin),cookie("bp_operator_mfa","",origin,"/",0),cookie("bp_operator_enroll","",origin,"/auth",0));
    reply.header("set-cookie", cookies);
    return { state: "signed_in", redirect: account.operator?"/operator/security":"/portal" };
  }
  app.post("/auth/signup", async (request, reply) => {
    const { origin } = authorize(request);
    const { client } = requireConfig();
    const body = z
      .object({
        email: z.string().trim().email().max(200),
        password: z.string().min(12).max(256),
        confirmPassword: z.string().min(12).max(256),
      })
      .strict()
      .parse(request.body);
    if (body.password !== body.confirmPassword)
      throw new HttpError(400, "PASSWORD_MISMATCH", "Passwords do not match. Enter the same password in both fields.");
    const duplicate = await ctx.withSystem("inventory_worker", async db => {
      await ctx.setActor(db, "platform_administrator");
      return (await db.query("SELECT id FROM users WHERE lower(verified_email)=$1 LIMIT 1", [body.email.toLowerCase()])).rows.length > 0;
    });
    if (duplicate) throw new HttpError(409, "ACCOUNT_EXISTS", "An account with this email already exists. Sign in instead or use password reset.");
    let tokens: IdentityTokens;
    try {
      tokens = await client.password(body.email.toLowerCase(), body.password, true);
    } catch (error) {
      if (error instanceof HttpError)
        request.log.warn({ code: error.code, status: error.status }, "Email/password registration failed");
      throw error;
    }
    const result = await finish(request, reply, tokens, origin);
    if (result.state === "verify_email") {
      try {
        await client.sendVerification(tokens.idToken, origin);
      } catch {
        return { ...result, verificationDeliveryPending: true };
      }
    }
    return result;
  });
  app.post("/auth/signin", async (request, reply) => {
    const { origin } = authorize(request);
    const { client } = requireConfig();
    const body = z
      .object({
        email: z.string().trim().email().max(200),
        password: z.string().min(1).max(256),
      })
      .strict()
      .parse(request.body);
    return finish(
      request,
      reply,
      await client.password(body.email.toLowerCase(), body.password, false),
      origin,
    );
  });
  app.post("/auth/google", async (request, reply) => {
    const { origin, nonce } = authorize(request);
    const { client } = requireConfig();
    const body = z
      .object({ credential: z.string().min(1).max(16000) })
      .strict()
      .parse(request.body);
    const result = await client.google(body.credential, nonce, origin);
    return finish(request, reply, result, origin, result.authoritativeEmail);
  });
  app.post("/auth/verified", async (request, reply) => {
    const { origin } = authorize(request);
    const { client } = requireConfig();
    z.object({})
      .strict()
      .parse(request.body ?? {});
    const refresh = cookieValue(request, "bp_refresh");
    if (!refresh)
      throw new HttpError(401, "SIGN_IN_REQUIRED", "Please sign in again.");
    return finish(request, reply, await client.refresh(refresh), origin);
  });
  app.post("/auth/resend-verification", async (request, reply) => {
    const { origin } = authorize(request);
    const { client } = requireConfig();
    z.object({})
      .strict()
      .parse(request.body ?? {});
    const refresh = cookieValue(request, "bp_refresh");
    if (!refresh)
      throw new HttpError(401, "SIGN_IN_REQUIRED", "Please sign in again.");
    const tokens = await client.refresh(refresh);
    const claims = validatePlatformClaims(
      await client.verify(tokens.idToken),
      requireConfig().config,
    );
    if (claims.email_verified === true)
      return finish(request, reply, tokens, origin);
    reply.header("set-cookie", [
      cookie(
        "bp_refresh",
        tokens.refreshToken,
        origin,
        "/auth",
        30 * 24 * 60 * 60,
      ),
    ]);
    ctx.consumeLimit(claims.sub, "verification-email", 3, 15 * 60_000);
    await client.sendVerification(tokens.idToken, origin);
    return { sent: true };
  });
  app.post("/auth/password-reset", async (request, reply) => {
    const { origin } = authorize(request);
    const { client } = requireConfig();
    const body = z
      .object({ email: z.string().trim().email().max(200) })
      .strict()
      .parse(request.body);
    await client.resetPassword(body.email.toLowerCase(), origin);
    return {
      sent: true,
      message:
        "If an account exists for this address, a password reset email is on its way.",
    };
  });
  app.post("/auth/refresh", async (request, reply) => {
    const { origin } = authorize(request);
    const { client } = requireConfig();
    z.object({})
      .strict()
      .parse(request.body ?? {});
    const refresh = cookieValue(request, "bp_refresh");
    if (!refresh)
      throw new HttpError(401, "SIGN_IN_REQUIRED", "Please sign in again.");
    const tokens = await client.refresh(refresh);
    const claims = validatePlatformClaims(
      await client.verify(tokens.idToken),
      requireConfig().config,
    );
    // Refresh only existing application accounts; it cannot link a new identity by email.
    const { resolveIdentitySubject } = await import("./identity-accounts.ts");
    await resolveIdentitySubject(ctx, claims);
    reply.header("set-cookie", [
      cookie(
        "bp_refresh",
        tokens.refreshToken,
        origin,
        "/auth",
        30 * 24 * 60 * 60,
      ),
      cookie("bp_session", tokens.idToken, origin),
    ]);
    return { state: "signed_in", redirect: "/portal" };
  });
  async function revokeOperatorSession(request:FastifyRequest){
    const token=cookieValue(request,"bp_operator_mfa");
    if(token)await ctx.withSystem("inventory_worker",async db=>{await ctx.setActor(db,"platform_administrator");await db.query("DELETE FROM operator_mfa_sessions WHERE token_hash=$1",[hashToken(token)])});
  }
  registerOperatorAuth(app,ctx,config,client,keyHex,authorize);
  app.post("/auth/logout", async (request, reply) => {
    const { origin } = authorize(request);
    z.object({})
      .strict()
      .parse(request.body ?? {});
    await revokeOperatorSession(request);
    reply.header("set-cookie", [
      cookie("bp_operator_mfa","",origin,"/",0),
      cookie("bp_operator_enroll","",origin,"/auth",0),
      cookie("bp_session", "", origin, "/", 0),
      cookie("bp_refresh", "", origin, "/auth", 0),
    ]);
    return { redirect: "/login" };
  });
  app.addHook("onSend", async (request, reply, payload) => {
    if (request.url.startsWith("/auth/"))
      reply
        .header("cache-control", "no-store")
        .header("referrer-policy", "no-referrer");
    return payload;
  });
}
