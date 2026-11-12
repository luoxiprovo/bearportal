import { randomUUID } from "node:crypto";
import { allocateProfile } from "../../../packages/servers/src/allocate.ts";
import { mutationsPaused } from "./oversight.ts";
import type { InventoryContext } from "./inventory.ts";
import type { PlatformClaims } from "./identity-platform-client.ts";
import type { FastifyRequest } from "fastify";
import { HttpError } from "./errors.ts";

export async function resolveIdentitySubject(
  ctx: InventoryContext,
  claims: PlatformClaims,
): Promise<string> {
  if (claims.email_verified !== true)
    throw new HttpError(
      403,
      "EMAIL_UNVERIFIED",
      "Verify your email before continuing.",
    );
  return ctx.withSystem("inventory_worker", async (db) => {
    await ctx.setActor(db, "platform_administrator");
    const rows = await db.query<{ identity_subject: string; status: string }>(
      `SELECT u.identity_subject,u.status FROM identity_accounts a JOIN users u ON u.id=a.user_id WHERE a.issuer=$1 AND a.subject=$2`,
      [claims.iss, claims.sub],
    );
    if (!rows.rows[0] || rows.rows[0].status !== "active")
      throw new HttpError(
        401,
        "SIGN_IN_REQUIRED",
        "Sign in to BearPortal to continue.",
      );
    return rows.rows[0].identity_subject;
  });
}

export async function completeIdentityAccount(
  ctx: InventoryContext,
  claims: PlatformClaims,
  request: FastifyRequest,
  allowLegacyLink: boolean,
) {
  if (claims.email_verified !== true)
    throw new HttpError(
      403,
      "EMAIL_UNVERIFIED",
      "Verify your email before continuing.",
    );
  const email = claims.email.trim().toLowerCase();
  return ctx.withSystem("inventory_worker", async (db) => {
    await ctx.setActor(db, "platform_administrator");
    await db.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", [
      "bearportal.identity." + claims.iss + "." + claims.sub,
    ]);
    await db.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", ["bearportal.email." + email]);
    let user = (
      await db.query<{ id: string; status: string }>(
        `SELECT u.id,u.status FROM identity_accounts a JOIN users u ON u.id=a.user_id WHERE a.issuer=$1 AND a.subject=$2`,
        [claims.iss, claims.sub],
      )
    ).rows[0];
    if (user && user.status !== "active")
      throw new HttpError(
        403,
        "ACCOUNT_DISABLED",
        "This account is disabled. Contact the operator.",
      );
    if (!user) {
      const legacy = (
        await db.query<{ id: string; status: string }>(
          `SELECT u.id,u.status FROM users u WHERE u.identity_subject=$1 AND lower(u.verified_email)=$2 AND u.email_verified=true
        AND NOT EXISTS(SELECT 1 FROM operator_roles r WHERE r.user_id=u.id)`,
          ["local:" + email, email],
        )
      ).rows[0];
      if (legacy && !allowLegacyLink)
        throw new HttpError(
          409,
          "ACCOUNT_LINK_REQUIRED",
          "Use verified email/password sign-in to connect your existing account.",
        );
      if (legacy?.status === "disabled")
        throw new HttpError(
          403,
          "ACCOUNT_DISABLED",
          "This account is disabled. Contact the operator.",
        );
      user = legacy;
      if (!user) {
        const duplicate = await db.query("SELECT id FROM users WHERE lower(verified_email)=$1", [email]);
        if (duplicate.rows[0]) throw new HttpError(409, "ACCOUNT_EXISTS", "An account with this email already exists. Sign in with your existing method instead.");
        user = { id: randomUUID(), status: "active" };
        await db.query(
          "INSERT INTO users(id,identity_subject,verified_email,email_verified,status) VALUES($1,$2,$3,true,'active')",
          [
            user.id,
            "gip:" + claims.iss!.split("/").pop() + ":" + claims.sub,
            email,
          ],
        );
      }
      await db.query(
        "INSERT INTO identity_accounts(issuer,subject,user_id,provider) VALUES($1,$2,$3,$4)",
        [claims.iss, claims.sub, user.id, claims.firebase.sign_in_provider],
      );
      await ctx.audit(db, request, user.id, null, "identity.connect", user.id, {
        provider: claims.firebase.sign_in_provider,
        legacyAccountLinked: Boolean(legacy),
      });
    }
    await db.query(
      "UPDATE users SET verified_email=$2,email_verified=true,updated_at=now() WHERE id=$1",
      [user.id, email],
    );
    let org = (
      await db.query<{ id: string }>(
        "SELECT id FROM organizations WHERE owner_user_id=$1 AND status='active'",
        [user.id],
      )
    ).rows[0];
    if (!org) {
      if (await mutationsPaused(db))
        throw new HttpError(
          503,
          "RECOVERY_MODE",
          "Registration is temporarily paused. Try again later.",
        );
      org = { id: randomUUID() };
      await db.query(
        "INSERT INTO organizations(id,owner_user_id,name,status,billing_required) VALUES($1,$2,$3,'active',$4)",
        [org.id, user.id, email.split("@")[0].slice(0, 120), ctx.billingRequired === true],
      );
      await db.query(
        "INSERT INTO allocation_requests(id,organization_id,profile_code,verified_registered_at,state) VALUES($1,$2,'e2-micro',now(),'waiting_for_server')",
        [randomUUID(), org.id],
      );
      await ctx.setActor(db, "allocator");
      await allocateProfile(db, "e2-micro", 100);
      await ctx.setActor(db, "platform_administrator");
      await ctx.audit(
        db,
        request,
        user.id,
        org.id,
        "organization.create",
        org.id,
        { source: "identity-platform" },
      );
    }
    await ctx.audit(db, request, user.id, org.id, "identity.sign_in", user.id, {
      provider: claims.firebase.sign_in_provider,
    });
    return { organizationId: org.id };
  });
}
