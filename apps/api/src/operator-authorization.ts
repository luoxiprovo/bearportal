import type { InventoryContext } from "./inventory.ts";
import type { PlatformClaims } from "./identity-platform-client.ts";
import type { FastifyRequest } from "fastify";
import type { Queryable } from "../../../packages/servers/src/allocate.ts";
import { HttpError } from "./errors.ts";
import { randomUUID } from "node:crypto";

/** Email ownership alone never grants a role: an unexpired, explicit server approval is required. */
export async function consumeOperatorAuthorization(
  db: Queryable,
  ctx: InventoryContext,
  claims: PlatformClaims,
  request: FastifyRequest,
  authoritative: boolean,
): Promise<{ id: string; status: string } | null> {
  const pending = (
    await db.query<{
      id: string;
      target_user_id: string | null;
      role: string;
      created_at: Date;
    }>(
      `SELECT id,target_user_id,role,created_at FROM operator_authorizations WHERE issuer=$1 AND email=$2 AND consumed_at IS NULL AND expires_at>now() FOR UPDATE`,
      [claims.iss, claims.email.trim().toLowerCase()],
    )
  ).rows[0];
  if (!pending) return null;
  if (
    !authoritative ||
    claims.auth_time < Math.floor(pending.created_at.getTime() / 1000)
  )
    throw new HttpError(
      403,
      "OPERATOR_REAUTHENTICATE",
      "Sign in again with Google for your Gmail account, or verified email and password, to activate operator access.",
    );
  const bound = (
    await db.query<{ id: string; status: string }>(
      `SELECT u.id,u.status FROM identity_accounts a JOIN users u ON u.id=a.user_id WHERE a.issuer=$1 AND a.subject=$2`,
      [claims.iss, claims.sub],
    )
  ).rows[0];
  if (bound && pending.target_user_id && bound.id !== pending.target_user_id)
    throw new HttpError(
      409,
      "OPERATOR_IDENTITY_CONFLICT",
      "This identity already belongs to another account. Ask the server administrator to authorize that existing account.",
    );
  const target = pending.target_user_id ?? bound?.id ?? null;
  if (!target) return null; // The normal verified-account creation path will supply the new user below.
  const user = (
    await db.query<{ id: string; status: string }>(
      "SELECT id,status FROM users WHERE id=$1 FOR UPDATE",
      [target],
    )
  ).rows[0];
  if (!user || user.status !== "active")
    throw new HttpError(
      403,
      "ACCOUNT_DISABLED",
      "This operator account is disabled.",
    );
  const other = (
    await db.query(
      `SELECT 1 FROM identity_accounts WHERE user_id=$1 AND (issuer<>$2 OR subject<>$3)`,
      [target, claims.iss, claims.sub],
    )
  ).rows[0];
  if (other)
    throw new HttpError(
      409,
      "OPERATOR_IDENTITY_CONFLICT",
      "This operator account is already linked to a different identity. Use its original sign-in or ask the server administrator for recovery.",
    );
  const duplicate = (
    await db.query(
      "SELECT id FROM users WHERE lower(verified_email)=$1 AND id<>$2",
      [claims.email.trim().toLowerCase(), target],
    )
  ).rows[0];
  if (duplicate)
    throw new HttpError(
      409,
      "OPERATOR_IDENTITY_CONFLICT",
      "An account already uses this email. Authorize that account instead of merging accounts.",
    );
  return user;
}
export async function grantPendingOperatorRole(
  db: Queryable,
  ctx: InventoryContext,
  claims: PlatformClaims,
  request: FastifyRequest,
  userId: string,
) {
  const pending = (
    await db.query<{ id: string; role: string; target_user_id: string | null }>(
      `SELECT id,role,target_user_id FROM operator_authorizations WHERE issuer=$1 AND email=$2 AND consumed_at IS NULL AND expires_at>now() FOR UPDATE`,
      [claims.iss, claims.email.trim().toLowerCase()],
    )
  ).rows[0];
  if (!pending) return;
  if (pending.target_user_id && pending.target_user_id !== userId)
    throw new HttpError(
      409,
      "OPERATOR_IDENTITY_CONFLICT",
      "The approved operator account does not match this identity.",
    );
  await db.query(
    `INSERT INTO operator_roles(id,user_id,role,reason) VALUES($1,$2,$3,'Explicit server authorization') ON CONFLICT(user_id,role) WHERE revoked_at IS NULL DO NOTHING`,
    [randomUUID(), userId, pending.role],
  );
  await db.query(
    "UPDATE operator_authorizations SET consumed_at=now(),consumed_by=$2 WHERE id=$1",
    [pending.id, userId],
  );
  await ctx.audit(
    db,
    request,
    userId,
    null,
    "operator.identity.authorized",
    userId,
    { role: pending.role, authorizationId: pending.id },
  );
}
