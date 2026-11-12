import type { Queryable } from "../../../packages/servers/src/allocate.ts";
import { randomBytes } from "node:crypto";
import type { FastifyInstance, FastifyRequest } from "fastify";
import { z } from "zod";
import QRCode from "qrcode";
import {
  seal,
  open,
  loadSecretKey,
} from "../../../packages/secrets/src/store.ts";
import type { InventoryContext } from "./inventory.ts";
import type { IdentityPlatformConfig } from "./identity-platform-config.ts";
import {
  validatePlatformClaims,
  type IdentityPlatformClient,
} from "./identity-platform-client.ts";
import { HttpError } from "./errors.ts";
import { cookie, cookieValue } from "./auth-cookies.ts";
import {
  hashToken,
  newAuthenticator,
  verifyAuthenticator,
  recoveryCodes,
  recoveryHash,
  sameHash,
} from "./operator-totp.ts";
import { OPERATOR_AUTH_SCRIPT } from "./operator-auth-script.ts";

export function registerOperatorAuth(
  app: FastifyInstance,
  ctx: InventoryContext,
  config: IdentityPlatformConfig | undefined,
  client: IdentityPlatformClient | undefined,
  keyHex: string,
  authorize: (r: FastifyRequest) => { origin: string },
) {
  const key = loadSecretKey(keyHex);
  async function identity(request: FastifyRequest) {
    if (!config || !client)
      throw new HttpError(
        503,
        "AUTH_NOT_CONFIGURED",
        "Operator sign-in is not configured.",
      );
    const token = cookieValue(request, "bp_session");
    if (!token)
      throw new HttpError(
        401,
        "SIGN_IN_REQUIRED",
        "Sign in with your authorized operator account first.",
      );
    const claims = validatePlatformClaims(await client.verify(token), config);
    if (!claims.email_verified)
      throw new HttpError(
        403,
        "EMAIL_UNVERIFIED",
        "Verify your email before continuing.",
      );
    const account = await ctx.withSystem("inventory_worker", async (db) => {
      await ctx.setActor(db, "platform_administrator");
      const row = (
        await db.query<{ id: string; operator_mfa_reset_at: Date | null }>(
          `SELECT u.id,u.operator_mfa_reset_at FROM identity_accounts a JOIN users u ON u.id=a.user_id WHERE a.issuer=$1 AND a.subject=$2 AND u.status='active' AND EXISTS(SELECT 1 FROM operator_roles r WHERE r.user_id=u.id AND r.revoked_at IS NULL)`,
          [claims.iss, claims.sub],
        )
      ).rows[0];
      if (!row)
        throw new HttpError(
          403,
          "OPERATOR_REQUIRED",
          "This account is not authorized as an operator. Sign out and use your authorized account.",
        );
      if (
        row.operator_mfa_reset_at &&
        claims.auth_time < Math.ceil(row.operator_mfa_reset_at.getTime() / 1000)
      )
        throw new HttpError(
          401,
          "REAUTHENTICATE",
          "Sign in again after your authenticator reset before enrolling a new factor.",
        );
      return row;
    });
    return { ...account, claims, token };
  }
  async function lockAccount(
    db: Queryable,
    account: Awaited<ReturnType<typeof identity>>,
  ) {
    const row = (
      await db.query<{ operator_mfa_reset_at: Date | null; status: string }>(
        "SELECT operator_mfa_reset_at,status FROM users WHERE id=$1 FOR UPDATE",
        [account.id],
      )
    ).rows[0];
    if (
      !row ||
      row.status !== "active" ||
      (row.operator_mfa_reset_at &&
        account.claims.auth_time <
          Math.ceil(row.operator_mfa_reset_at.getTime() / 1000))
    )
      throw new HttpError(
        401,
        "REAUTHENTICATE",
        "Sign in again before continuing authenticator setup.",
      );
  }
  app.get("/assets/operator-auth.js", async (_request, reply) =>
    reply
      .type("application/javascript")
      .header("cache-control", "no-store")
      .send(OPERATOR_AUTH_SCRIPT),
  );
  app.get("/auth/operator/status", async (request) => {
    const account = await identity(request);
    return ctx.withSystem("inventory_worker", async (db) => {
      await ctx.setActor(db, "platform_administrator");
      const row = (
        await db.query<{ enrolled_at: Date | null }>(
          "SELECT enrolled_at FROM operator_totp WHERE user_id=$1",
          [account.id],
        )
      ).rows[0];
      return {
        email: account.claims.email,
        enrolled: Boolean(row?.enrolled_at),
      };
    });
  });
  app.post("/auth/operator/enroll", async (request, reply) => {
    const { origin } = authorize(request);
    z.object({})
      .strict()
      .parse(request.body ?? {});
    const account = await identity(request);
    if (Date.now() / 1000 - account.claims.auth_time > 600)
      throw new HttpError(
        401,
        "REAUTHENTICATE",
        "Sign in again before setting up your authenticator.",
      );
    ctx.consumeLimit(account.id, "operator-enrollment", 5, 15 * 60_000);
    const token =
      cookieValue(request, "bp_operator_enroll") ||
      randomBytes(32).toString("base64url");
    const seed = await ctx.withSystem("inventory_worker", async (db) => {
      await ctx.setActor(db, "platform_administrator");
      await lockAccount(db, account);
      const row = (
        await db.query<{
          secret: Buffer;
          enrolled_at: Date | null;
          enrollment_expires_at: Date | null;
          enrollment_token_hash: string;
        }>("SELECT * FROM operator_totp WHERE user_id=$1 FOR UPDATE", [
          account.id,
        ])
      ).rows[0];
      if (row?.enrolled_at)
        throw new HttpError(
          409,
          "ALREADY_ENROLLED",
          "Your authenticator is already set up. Enter a code to continue.",
        );
      if (
        row?.enrollment_expires_at &&
        row.enrollment_expires_at.getTime() > Date.now()
      ) {
        if (!sameHash(row.enrollment_token_hash, hashToken(token)))
          throw new HttpError(
            409,
            "ENROLLMENT_PENDING",
            "Setup has started in another browser. Finish there or try again after 10 minutes.",
          );
        return open(row.secret, key);
      }
      const secret = newAuthenticator(account.claims.email).secret.base32;
      await db.query(
        `INSERT INTO operator_totp(user_id,secret,enrollment_expires_at,enrollment_token_hash) VALUES($1,$2,now()+interval '10 minutes',$3) ON CONFLICT(user_id) DO UPDATE SET secret=$2,enrollment_expires_at=now()+interval '10 minutes',enrollment_token_hash=$3,last_counter=-1,failed_attempts=0,locked_until=NULL`,
        [account.id, seal(secret, key), hashToken(token)],
      );
      await ctx.audit(
        db,
        request,
        account.id,
        null,
        "operator.mfa.enrollment_started",
        account.id,
        {},
      );
      return secret;
    });
    reply.header(
      "set-cookie",
      cookie("bp_operator_enroll", token, origin, "/auth", 600),
    );
    const qr = await QRCode.toString(
      newAuthenticator(account.claims.email, seed).toString(),
      { type: "svg", errorCorrectionLevel: "M" },
    );
    return {
      secret: seed,
      qrDataUrl:
        "data:image/svg+xml;base64," + Buffer.from(qr).toString("base64"),
    };
  });
  app.post("/auth/operator/verify", async (request, reply) => {
    const { origin } = authorize(request);
    const { code } = z
      .object({ code: z.string().trim().min(1).max(80) })
      .strict()
      .parse(request.body);
    const account = await identity(request);
    ctx.consumeLimit(account.id, "operator-mfa", 20, 5 * 60_000);
    const session = randomBytes(32).toString("base64url");
    const result = await ctx.withSystem("inventory_worker", async (db) => {
      await ctx.setActor(db, "platform_administrator");
      // Serialize with authorization, reset and other MFA requests for this account.
      await lockAccount(db, account);
      const row = (
        await db.query<{
          secret: Buffer;
          enrolled_at: Date | null;
          enrollment_expires_at: Date | null;
          enrollment_token_hash: string;
          last_counter: string;
          recovery_hashes: string[];
          failed_attempts: number;
          locked_until: Date | null;
        }>("SELECT * FROM operator_totp WHERE user_id=$1 FOR UPDATE", [
          account.id,
        ])
      ).rows[0];
      if (!row)
        return { error: "Start authenticator setup first.", status: 409 };
      if (row.locked_until && row.locked_until.getTime() > Date.now())
        return {
          error:
            "Too many incorrect codes. Wait 5 minutes before trying again.",
          status: 429,
        };
      const enrolling = !row.enrolled_at;
      if (
        enrolling &&
        (!row.enrollment_expires_at ||
          row.enrollment_expires_at.getTime() <= Date.now() ||
          !sameHash(
            row.enrollment_token_hash,
            hashToken(cookieValue(request, "bp_operator_enroll")),
          ))
      )
        return {
          error:
            "Authenticator setup expired or belongs to another browser. Start setup again.",
          status: 409,
        };
      if (enrolling && Date.now() / 1000 - account.claims.auth_time > 600)
        return {
          error: "Sign in again before completing authenticator setup.",
          status: 401,
        };
      const counter = verifyAuthenticator(
        open(row.secret, key),
        code,
        Number(row.last_counter),
      );
      const hash = recoveryHash(code);
      const recoveryIndex = enrolling
        ? -1
        : row.recovery_hashes.findIndex((value) => sameHash(value, hash));
      if (counter === null && recoveryIndex < 0) {
        const failures = (row.locked_until ? 0 : row.failed_attempts) + 1;
        await db.query(
          `UPDATE operator_totp SET failed_attempts=$2,locked_until=CASE WHEN $2>=5 THEN now()+interval '5 minutes' ELSE NULL END WHERE user_id=$1`,
          [account.id, failures],
        );
        await ctx.audit(
          db,
          request,
          account.id,
          null,
          "operator.mfa.failed",
          account.id,
          {},
        );
        return {
          error:
            failures >= 5
              ? "Too many incorrect codes. Wait 5 minutes before trying again."
              : "That code is invalid or has already been used. Wait for the next authenticator code, or use an unused recovery code.",
          status: failures >= 5 ? 429 : 400,
        };
      }
      const codes = enrolling ? recoveryCodes() : undefined;
      const hashes = codes
        ? codes.map(recoveryHash)
        : row.recovery_hashes.filter((_, i) => i !== recoveryIndex);
      await db.query(
        `UPDATE operator_totp SET enrolled_at=coalesce(enrolled_at,now()),enrollment_expires_at=NULL,enrollment_token_hash=NULL,last_counter=$2,recovery_hashes=$3,failed_attempts=0,locked_until=NULL WHERE user_id=$1`,
        [account.id, counter ?? Number(row.last_counter), hashes],
      );
      const old = hashToken(cookieValue(request, "bp_operator_mfa"));
      await db.query(
        "DELETE FROM operator_mfa_sessions WHERE token_hash=$1 OR expires_at<now()",
        [old],
      );
      await db.query(
        `INSERT INTO operator_mfa_sessions(token_hash,user_id,identity_issuer,identity_subject,first_factor_auth_time,expires_at) VALUES($1,$2,$3,$4,$5,now()+interval '2 hours')`,
        [
          hashToken(session),
          account.id,
          account.claims.iss,
          account.claims.sub,
          account.claims.auth_time,
        ],
      );
      await ctx.audit(
        db,
        request,
        account.id,
        null,
        enrolling
          ? "operator.mfa.enrolled"
          : recoveryIndex >= 0
            ? "operator.mfa.recovery_used"
            : "operator.mfa.verified",
        account.id,
        {},
      );
      return { codes };
    });
    if ("error" in result)
      throw new HttpError(result.status!, "OPERATOR_MFA_FAILED", result.error!);
    reply.header("set-cookie", [
      cookie("bp_operator_mfa", session, origin, "/", 7200),
      cookie("bp_operator_enroll", "", origin, "/auth", 0),
    ]);
    return {
      redirect: "/operator",
      ...(result.codes ? { recoveryCodes: result.codes } : {}),
    };
  });
}
