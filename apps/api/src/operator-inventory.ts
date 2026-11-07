import { randomUUID } from "node:crypto";
import type { FastifyInstance, FastifyRequest, FastifyReply } from "fastify";
import {
  serverInventoryPatchSchema,
  relayInventoryPatchSchema,
  inventoryRemoveSchema,
} from "../../../packages/contracts/src/index.ts";
import { assertPublicUnicastIpv4 } from "../../../packages/servers/src/address.ts";
import type { InventoryContext } from "./inventory.ts";
import { HttpError } from "./errors.ts";
import { renderInventoryMessage } from "./portal.ts";

type Resource = "servers" | "brevo";
type Db = Parameters<InventoryContext["setActor"]>[0];
type Actor = Parameters<InventoryContext["requireMfa"]>[0];

export function registerOperatorInventory(
  app: FastifyInstance,
  ctx: InventoryContext,
) {
  const authorize = (actor: Actor, resource: Resource) => {
    ctx.requireVerified(actor);
    ctx.requireMfa(actor);
    if (
      !actor.roles.includes("platform_administrator") &&
      (resource === "brevo" || !actor.roles.includes("infrastructure_operator"))
    ) {
      throw new HttpError(
        403,
        "FORBIDDEN",
        resource === "brevo"
          ? "A platform administrator is required."
          : "An infrastructure operator is required.",
      );
    }
  };
  async function mutation(
    request: FastifyRequest,
    resource: Resource,
    route: string,
    body: unknown,
    work: (
      db: Db,
      actor: Actor,
      id: string,
    ) => Promise<Record<string, unknown>>,
  ) {
    const { id } = request.params as { id: string };
    if (
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
        id,
      )
    )
      throw new HttpError(400, "VALIDATION", "Invalid inventory identifier.");
    const key = ctx.demandIdempotency(request);
    return ctx.withActor(request, "operator", async (db, actor) => {
      authorize(actor, resource);
      const replay = await ctx.replay(db, actor.userId, route, key, {
        id,
        body,
      });
      if (replay) return replay;
      const response = await work(db, actor, id);
      await ctx.remember(
        db,
        actor.userId,
        route,
        key,
        { id, body },
        200,
        response,
      );
      return { status: 200, body: response };
    });
  }
  app.patch("/v1/admin/servers/:id", async (request, reply) => {
    const body = serverInventoryPatchSchema.parse(request.body);
    const result = await mutation(
      request,
      "servers",
      "PATCH /v1/admin/servers/:id",
      body,
      async (db, actor, id) => {
        const row = (
          await db.query<{
            version: number;
            state: string;
            public_ipv4: string;
            label: string;
            operator_contact: string;
            provider_reference: string | null;
            tainted: boolean;
          }>(
            `SELECT version,state,host(public_ipv4) AS public_ipv4,label,operator_contact,provider_reference,tenant_tainted_at IS NOT NULL AS tainted FROM servers WHERE id=$1 FOR UPDATE`,
            [id],
          )
        ).rows[0];
        if (!row) throw new HttpError(404, "NOT_FOUND", "Server not found.");
        if (row.version !== body.expectedVersion)
          throw new HttpError(
            409,
            "VERSION_CONFLICT",
            "This server changed. Refresh the inventory and try again.",
          );
        if (row.state === "retired")
          throw new HttpError(
            409,
            "RESOURCE_REMOVED",
            "Removed servers are read-only.",
          );
        const ipv4 =
          body.publicIpv4 === undefined
            ? row.public_ipv4
            : publicIp(body.publicIpv4);
        const addressChanged = ipv4 !== row.public_ipv4;
        if (addressChanged) {
          if (row.state === "assigned" || row.state === "reserved")
            throw new HttpError(
              409,
              "RESOURCE_IN_USE",
              "Use the reviewed IP-change workflow for an assigned server.",
            );
          await ensureUnusedServer(db, id, row.tainted);
        }
        const duplicate = await db.query(
          "SELECT id FROM servers WHERE id <> $1 AND public_ipv4=$2::inet AND state <> 'retired'",
          [id, ipv4],
        );
        if (duplicate.rows[0])
          throw new HttpError(
            409,
            "DUPLICATE_ADDRESS",
            "That address is already in inventory.",
          );
        const reference =
          body.providerReference === undefined
            ? row.provider_reference
            : body.providerReference;
        if (reference) {
          const found = await db.query(
            "SELECT id FROM servers WHERE id <> $1 AND provider_reference=$2 AND state <> 'retired'",
            [id, reference],
          );
          if (found.rows[0])
            throw new HttpError(
              409,
              "DUPLICATE_PROVIDER_REFERENCE",
              "That provider reference is already in inventory.",
            );
        }
        const saved = await db.query<{ version: number; state: string }>(
          `UPDATE servers SET label=$2,operator_contact=$3,provider_reference=$4,public_ipv4=$5::inet,
        state=CASE WHEN $6 THEN 'pending_validation' ELSE state END,
        validated_at=CASE WHEN $6 THEN NULL ELSE validated_at END,
        readiness_report=CASE WHEN $6 THEN NULL ELSE readiness_report END,
        available_since=CASE WHEN $6 THEN NULL ELSE available_since END,
        auth_epoch=auth_epoch+CASE WHEN $6 THEN 1 ELSE 0 END,
        version=version+1,updated_at=now() WHERE id=$1 RETURNING version,state`,
          [
            id,
            body.label ?? row.label,
            body.operatorContact ?? row.operator_contact,
            reference,
            ipv4,
            addressChanged,
          ],
        );
        await ctx.audit(db, request, actor.userId, null, "server.edit", id, {
          label: body.label ?? row.label,
          publicIpv4: ipv4,
          addressChanged,
        });
        return {
          serverId: id,
          ...saved.rows[0],
          requiresValidation: addressChanged,
        };
      },
    );
    return reply
      .code(result.status)
      .send({ ...result.body, requestId: request.id });
  });
  app.delete("/v1/admin/servers/:id", async (request, reply) => {
    const body = inventoryRemoveSchema.parse(request.body);
    const result = await mutation(
      request,
      "servers",
      "DELETE /v1/admin/servers/:id",
      body,
      async (db, actor, id) => {
        const row = (
          await db.query<{ version: number; state: string; tainted: boolean }>(
            "SELECT version,state,tenant_tainted_at IS NOT NULL AS tainted FROM servers WHERE id=$1 FOR UPDATE",
            [id],
          )
        ).rows[0];
        if (!row) throw new HttpError(404, "NOT_FOUND", "Server not found.");
        if (row.version !== body.expectedVersion)
          throw new HttpError(
            409,
            "VERSION_CONFLICT",
            "This server changed. Refresh before removing it.",
          );
        await ensureUnusedServer(db, id, row.tainted);
        if (row.state === "reserved" || row.state === "assigned")
          throw new HttpError(
            409,
            "RESOURCE_IN_USE",
            "An assigned server cannot be removed.",
          );
        const saved = await db.query<{ version: number }>(
          "UPDATE servers SET state='retired',validated_at=NULL,available_since=NULL,auth_epoch=auth_epoch+1,version=version+1,updated_at=now() WHERE id=$1 RETURNING version",
          [id],
        );
        await db.query(
          "UPDATE host_identities SET state='revoked',revoked_at=now(),version=version+1 WHERE server_id=$1 AND state <> 'revoked'",
          [id],
        );
        await ctx.audit(db, request, actor.userId, null, "server.remove", id, {
          previousState: row.state,
          inventoryOnly: true,
        });
        return {
          serverId: id,
          state: "retired",
          version: saved.rows[0].version,
          removed: true,
          cloudResourceDeleted: false,
        };
      },
    );
    return reply
      .code(result.status)
      .send({ ...result.body, requestId: request.id });
  });
  app.patch("/v1/admin/relay-connections/:id", async (request, reply) => {
    const body = relayInventoryPatchSchema.parse(request.body);
    const result = await mutation(
      request,
      "brevo",
      "PATCH /v1/admin/relay-connections/:id",
      body,
      async (db, actor, id) => {
        const row = (
          await db.query<{
            version: number;
            state: string;
            archived_at: Date | null;
            label: string;
            provider_account_id: string;
            smtp_login: string;
            daily_limit: number;
            api_secret_ref: string;
            smtp_secret_ref: string;
          }>(
            "SELECT version,state,archived_at,label,provider_account_id,smtp_login,daily_limit,api_secret_ref,smtp_secret_ref FROM relay_connections WHERE id=$1 FOR UPDATE",
            [id],
          )
        ).rows[0];
        if (!row)
          throw new HttpError(404, "NOT_FOUND", "Brevo account not found.");
        if (row.version !== body.expectedVersion)
          throw new HttpError(
            409,
            "VERSION_CONFLICT",
            "This account changed. Refresh the inventory and try again.",
          );
        if (row.archived_at && !body.restore)
          throw new HttpError(
            409,
            "RESOURCE_REMOVED",
            "Restore this account before editing it.",
          );
        if (body.restore && !row.archived_at)
          throw new HttpError(
            409,
            "INVALID_STATE",
            "This account is already in inventory.",
          );
        const assigned =
          row.state === "assigned" ||
          (
            await db.query(
              "SELECT id FROM relay_assignments WHERE relay_connection_id=$1 AND released_at IS NULL",
              [id],
            )
          ).rows.length > 0;
        const account =
          body.loginEmail?.toLowerCase() ?? row.provider_account_id;
        const affectsConnection =
          account !== row.provider_account_id ||
          (body.smtpLogin !== undefined && body.smtpLogin !== row.smtp_login) ||
          body.apiKey !== undefined ||
          body.smtpKey !== undefined ||
          body.paused !== undefined ||
          body.restore === true;
        if (assigned && affectsConnection)
          throw new HttpError(
            409,
            "RESOURCE_IN_USE",
            "This account is assigned. Only its label and recorded daily allowance can be edited here.",
          );
        const duplicate = await db.query(
          "SELECT id FROM relay_connections WHERE id <> $1 AND provider='brevo' AND provider_account_id=$2",
          [id, account],
        );
        if (duplicate.rows[0])
          throw new HttpError(
            409,
            "DUPLICATE_ACCOUNT",
            "That Brevo email is already in inventory, including removed accounts.",
          );
        const apiRef =
          body.apiKey === undefined
            ? row.api_secret_ref
            : await replaceCredential(db, row.api_secret_ref, "brevo-api", {
                apiKey: body.apiKey,
              });
        const smtpRef =
          body.smtpKey === undefined
            ? row.smtp_secret_ref
            : await replaceCredential(db, row.smtp_secret_ref, "brevo-smtp", {
                smtpKey: body.smtpKey,
              });
        const state = body.restore
          ? "inactive"
          : body.paused === true
            ? "disabled"
            : body.paused === false
              ? "inactive"
              : affectsConnection && row.state === "available"
                ? "inactive"
                : row.state;
        const saved = await db.query<{ version: number }>(
          `UPDATE relay_connections SET label=$2,provider_account_id=$3,smtp_login=$4,daily_limit=$5,
        api_secret_ref=$6,smtp_secret_ref=$7,state=$8,archived_at=CASE WHEN $9 THEN NULL ELSE archived_at END,
        validation_report=CASE WHEN $10 THEN NULL ELSE validation_report END,version=version+1,updated_at=now() WHERE id=$1 RETURNING version`,
          [
            id,
            body.label ?? row.label,
            account,
            body.smtpLogin ?? row.smtp_login,
            body.dailyLimit ?? row.daily_limit,
            apiRef,
            smtpRef,
            state,
            body.restore === true,
            affectsConnection,
          ],
        );
        await ctx.audit(
          db,
          request,
          actor.userId,
          null,
          body.restore ? "relay.restore" : "relay.edit",
          id,
          {
            label: body.label ?? row.label,
            loginEmail: account,
            credentialsReplaced:
              body.apiKey !== undefined || body.smtpKey !== undefined,
            state,
          },
        );
        return {
          id,
          version: saved.rows[0].version,
          state,
          restored: body.restore === true,
        };
      },
    );
    return reply
      .code(result.status)
      .send({ ...result.body, requestId: request.id });
  });
  app.delete("/v1/admin/relay-connections/:id", async (request, reply) => {
    const body = inventoryRemoveSchema.parse(request.body);
    const result = await mutation(
      request,
      "brevo",
      "DELETE /v1/admin/relay-connections/:id",
      body,
      async (db, actor, id) => {
        const row = (
          await db.query<{ version: number; state: string }>(
            "SELECT version,state FROM relay_connections WHERE id=$1 FOR UPDATE",
            [id],
          )
        ).rows[0];
        if (!row)
          throw new HttpError(404, "NOT_FOUND", "Brevo account not found.");
        if (row.version !== body.expectedVersion)
          throw new HttpError(
            409,
            "VERSION_CONFLICT",
            "This account changed. Refresh before removing it.",
          );
        const assigned = await db.query(
          "SELECT id FROM relay_assignments WHERE relay_connection_id=$1 AND released_at IS NULL",
          [id],
        );
        if (assigned.rows[0] || row.state === "assigned")
          throw new HttpError(
            409,
            "RESOURCE_IN_USE",
            "An assigned Brevo account cannot be removed.",
          );
        const saved = await db.query<{ version: number }>(
          "UPDATE relay_connections SET state='disabled',archived_at=now(),version=version+1,updated_at=now() WHERE id=$1 RETURNING version",
          [id],
        );
        await ctx.audit(db, request, actor.userId, null, "relay.remove", id, {
          inventoryOnly: true,
        });
        return {
          id,
          version: saved.rows[0].version,
          state: "disabled",
          removed: true,
          providerAccountDeleted: false,
        };
      },
    );
    return reply
      .code(result.status)
      .send({ ...result.body, requestId: request.id });
  });

  async function replaceCredential(
    db: Db,
    previousId: string | null,
    purpose: string,
    value: Record<string, string>,
  ): Promise<string> {
    const file = ctx.secrets.write(JSON.stringify(value));
    const id = randomUUID();
    await db.query(
      "INSERT INTO secret_refs(id,purpose,file_name,key_id,state) VALUES($1,$2,$3,'local-1','active')",
      [id, purpose, file],
    );
    if (previousId)
      await db.query(
        "UPDATE secret_refs SET state='retired',retired_at=now(),version=version+1 WHERE id=$1",
        [previousId],
      );
    return id;
  }

  // Browser forms reuse the existing authenticated API rather than maintaining a second mutation path.
  async function form(
    request: FastifyRequest,
    reply: FastifyReply,
    resource: Resource,
    method: "POST" | "PATCH" | "DELETE",
    path: string,
    payload: Record<string, unknown>,
    notice: string,
  ) {
    try {
      await ctx.withActor(request, "operator", async (_db, actor) =>
        authorize(actor, resource),
      );
      const input = request.body as Record<string, string>;
      const idempotency = input?.idempotencyKey;
      if (
        typeof idempotency !== "string" ||
        idempotency.length < 8 ||
        idempotency.length > 200
      )
        throw new HttpError(
          400,
          "IDEMPOTENCY_REQUIRED",
          "Refresh the inventory page before submitting this form.",
        );
      const result = await app.inject({
        method,
        url: path,
        headers: {
          ...(request.headers.authorization
            ? { authorization: request.headers.authorization }
            : {}),
          ...(request.headers.cookie ? { cookie: request.headers.cookie } : {}),
          "x-bearportal-csrf": "1",
          "idempotency-key": idempotency,
        },
        payload,
      });
      const body = result.json();
      if (result.statusCode >= 400) {
        const message =
          body?.error?.message ?? "The inventory change could not be saved.";
        if (request.headers.accept?.includes("application/json"))
          return reply
            .code(result.statusCode)
            .send({ error: { message, code: body?.error?.code } });
        return reply
          .code(result.statusCode)
          .type("text/html")
          .send(renderInventoryMessage(message, true));
      }
      ctx.onboardingRequested?.();
      const destination = `/operator?tab=${resource}&notice=${notice}#resources`;
      if (request.headers.accept?.includes("application/json"))
        return reply.send({ redirect: destination });
      return reply.code(303).header("location", destination).send("");
    } catch (error) {
      if (!(error instanceof HttpError)) throw error;
      if (request.headers.accept?.includes("application/json"))
        return reply
          .code(error.status)
          .send({ error: { message: error.message, code: error.code } });
      return reply
        .code(error.status)
        .type("text/html")
        .send(renderInventoryMessage(error.message, true));
    }
  }
  const fields = (request: FastifyRequest) => {
    if (
      !request.body ||
      typeof request.body !== "object" ||
      Array.isArray(request.body)
    )
      throw new HttpError(
        400,
        "VALIDATION",
        "Submit the inventory form with its required fields.",
      );
    return request.body as Record<string, string>;
  };
  const version = (request: FastifyRequest) =>
    Number(fields(request).expectedVersion);
  const id = (request: FastifyRequest) =>
    encodeURIComponent((request.params as { id: string }).id);
  app.post("/operator/inventory/servers", async (request, reply) => {
    const input = fields(request);
    return form(
      request,
      reply,
      "servers",
      "POST",
      "/v1/admin/servers",
      {
        label: input.label,
        publicIpv4: input.publicIpv4,
        profileCode: "e2-micro",
        operatorContact: input.operatorContact,
        ...(input.providerReference
          ? { providerReference: input.providerReference }
          : {}),
        preparationAttestations: Object.fromEntries(
          [
            "osPrepared",
            "storagePrepared",
            "firewallAttested",
            "cleanHost",
            "externalBackup",
          ].map((key) => [key, input[key] === "1"]),
        ),
      },
      "server-added",
    );
  });
  app.post("/operator/inventory/servers/:id/edit", async (request, reply) => {
    const input = fields(request);
    return form(
      request,
      reply,
      "servers",
      "PATCH",
      `/v1/admin/servers/${id(request)}`,
      {
        expectedVersion: version(request),
        label: input.label,
        operatorContact: input.operatorContact,
        providerReference: input.providerReference || null,
        publicIpv4: input.publicIpv4,
      },
      "server-saved",
    );
  });
  app.post("/operator/inventory/servers/:id/remove", async (request, reply) =>
    form(
      request,
      reply,
      "servers",
      "DELETE",
      `/v1/admin/servers/${id(request)}`,
      {
        expectedVersion: version(request),
        confirm: fields(request).confirm === "1",
      },
      "server-removed",
    ),
  );
  app.post("/operator/inventory/servers/:id/validate", async (request, reply) =>
    form(
      request,
      reply,
      "servers",
      "POST",
      `/v1/admin/servers/${id(request)}/validate`,
      { expectedVersion: version(request) },
      "server-checked",
    ),
  );
  app.post("/operator/inventory/brevo", async (request, reply) => {
    const input = fields(request);
    return form(
      request,
      reply,
      "brevo",
      "POST",
      "/v1/admin/relay-connections",
      {
        label: input.label || input.loginEmail,
        loginEmail: input.loginEmail,
        apiKey: input.apiKey,
        smtpLogin: input.smtpLogin,
        smtpKey: input.smtpKey,
        dailyLimit: Number(input.dailyLimit),
      },
      "brevo-added",
    );
  });
  app.post("/operator/inventory/brevo/:id/edit", async (request, reply) => {
    const input = fields(request);
    return form(
      request,
      reply,
      "brevo",
      "PATCH",
      `/v1/admin/relay-connections/${id(request)}`,
      {
        expectedVersion: version(request),
        label: input.label,
        loginEmail: input.loginEmail,
        smtpLogin: input.smtpLogin,
        dailyLimit: Number(input.dailyLimit),
        ...(input.apiKey ? { apiKey: input.apiKey } : {}),
        ...(input.smtpKey ? { smtpKey: input.smtpKey } : {}),
        ...(input.paused !== undefined ? { paused: input.paused === "1" } : {}),
      },
      "brevo-saved",
    );
  });
  app.post("/operator/inventory/brevo/:id/remove", async (request, reply) =>
    form(
      request,
      reply,
      "brevo",
      "DELETE",
      `/v1/admin/relay-connections/${id(request)}`,
      {
        expectedVersion: version(request),
        confirm: fields(request).confirm === "1",
      },
      "brevo-removed",
    ),
  );
  app.post("/operator/inventory/brevo/:id/restore", async (request, reply) =>
    form(
      request,
      reply,
      "brevo",
      "PATCH",
      `/v1/admin/relay-connections/${id(request)}`,
      { expectedVersion: version(request), restore: true },
      "brevo-restored",
    ),
  );
}

async function ensureUnusedServer(db: Db, id: string, tainted: boolean) {
  const owner = await db.query(
    "SELECT id FROM server_assignments WHERE server_id=$1 AND released_at IS NULL",
    [id],
  );
  const recovery = await db.query(
    "SELECT id FROM recovery_bindings WHERE replacement_server_id=$1 AND state='pending'",
    [id],
  );
  if (owner.rows[0] || recovery.rows[0] || tainted)
    throw new HttpError(
      409,
      "RESOURCE_IN_USE",
      "This server is assigned, reserved for recovery, or has tenant data. Use the reviewed lifecycle workflow before removing it or changing its address.",
    );
}

function publicIp(value: string): string {
  try {
    return assertPublicUnicastIpv4(value);
  } catch {
    throw new HttpError(
      400,
      "VALIDATION",
      "Enter a public unicast IPv4 address.",
    );
  }
}
