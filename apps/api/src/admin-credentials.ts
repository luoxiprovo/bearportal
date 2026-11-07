import type { FastifyInstance } from "fastify";
import { emptyObjectSchema } from "../../../packages/contracts/src/index.ts";
import type { InventoryContext } from "./inventory.ts";
import { HttpError } from "./errors.ts";

export function registerAdminCredentials(
  app: FastifyInstance,
  ctx: InventoryContext,
) {
  app.post(
    "/v1/deployments/:id/admin-credentials/reveal",
    async (request, reply) => {
      reply
        .header("cache-control", "no-store, private")
        .header("pragma", "no-cache");
      emptyObjectSchema.parse(request.body ?? {});
      const { id } = request.params as { id: string };
      if (
        !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
          id,
        )
      )
        throw new HttpError(
          400,
          "VALIDATION",
          "Invalid deployment identifier.",
        );
      return ctx.withActor(request, "customer", async (db, actor) => {
        ctx.requireVerified(actor);
        if (!actor.organizationId)
          throw new HttpError(
            404,
            "NOT_FOUND",
            "The installation was not found.",
          );
        ctx.consumeLimit(actor.userId, "reveal-mail-admin", 10, 5 * 60 * 1000);
        const found = await db.query<{
          installer_status: string | null;
          file_name: string | null;
          mail_hostname: string;
          webmail_hostname: string;
        }>(
          `SELECT d.installer_status,s.file_name,d.mail_hostname,d.webmail_hostname
        FROM deployments d JOIN organizations o ON o.id=d.organization_id
        LEFT JOIN secret_refs s ON s.id=d.admin_secret_ref AND s.organization_id=d.organization_id AND s.state='active' AND s.purpose IN ('installer-admin','bearmail-admin')
        WHERE d.id=$1 AND d.organization_id=$2 AND o.owner_user_id=$3 AND o.status='active' AND d.lifecycle_state<>'deleted'`,
          [id, actor.organizationId, actor.userId],
        );
        const row = found.rows[0];
        if (!row)
          throw new HttpError(
            404,
            "NOT_FOUND",
            "The installation was not found.",
          );
        if (!["succeeded", "tls_pending"].includes(row.installer_status ?? ""))
          throw new HttpError(
            409,
            "INSTALLATION_NOT_READY",
            "Administrator credentials are available after installation.",
          );
        if (!row.file_name)
          throw new HttpError(
            409,
            "CREDENTIAL_UNAVAILABLE",
            "The saved administrator credential needs operator review.",
          );
        let credential: { username: string; password: string };
        try {
          credential = JSON.parse(ctx.secrets.read(row.file_name));
          if (
            typeof credential?.username !== "string" ||
            !credential.username ||
            typeof credential.password !== "string" ||
            !credential.password
          )
            throw Error();
        } catch {
          throw new HttpError(
            503,
            "CREDENTIAL_UNAVAILABLE",
            "The saved administrator credential could not be read.",
          );
        }
        await ctx.audit(
          db,
          request,
          actor.userId,
          actor.organizationId,
          "deployment.admin_credentials_revealed",
          id,
          { credentialType: "mail-administrator" },
        );
        return {
          username: credential.username,
          password: credential.password,
          adminUrl: `https://${row.mail_hostname}/`,
          webmailUrl: `https://${row.webmail_hostname}/`,
        };
      });
    },
  );
}
