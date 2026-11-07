import { request } from "node:https";
import { checkServerIdentity } from "node:tls";
import { randomUUID } from "node:crypto";
import type { InventoryContext } from "./inventory.ts";
import { mutationsPaused } from "./oversight.ts";

export type InstalledTlsProbe = (input: {
  publicIpv4: string;
  mailHostname: string;
  webmailHostname: string;
}) => Promise<boolean>;
export const liveInstalledTls: InstalledTlsProbe = async (input) => {
  const check = (hostname: string) =>
    new Promise<boolean>((resolve) => {
      const req = request(
        {
          hostname: input.publicIpv4,
          servername: hostname,
          port: 443,
          path: "/",
          method: "HEAD",
          headers: { host: hostname },
          checkServerIdentity: (_host, cert) =>
            checkServerIdentity(hostname, cert),
        },
        (response) => {
          response.resume();
          resolve(
            (response.statusCode ?? 500) >= 200 &&
              (response.statusCode ?? 500) < 400,
          );
        },
      );
      req.setTimeout(8000, () => req.destroy());
      req.on("error", () => resolve(false));
      req.end();
    });
  return (
    await Promise.all([check(input.mailHostname), check(input.webmailHostname)])
  ).every(Boolean);
};

export async function refreshInstalledTls(
  ctx: InventoryContext,
  probe: InstalledTlsProbe = liveInstalledTls,
) {
  const candidate = await ctx.withSystem("inventory_worker", async (db) => {
    await ctx.setActor(db, "platform_administrator");
    if (await mutationsPaused(db)) return null;
    const rows = await db.query<{
      id: string;
      version: number;
      organization_id: string;
      server_id: string;
      public_ipv4: string;
      mail_hostname: string;
      webmail_hostname: string;
    }>(`SELECT d.id,d.version,d.organization_id,d.server_id,host(s.public_ipv4) AS public_ipv4,d.mail_hostname,d.webmail_hostname
      FROM deployments d JOIN onboarding_requests r ON r.organization_id=d.organization_id
      JOIN server_assignments a ON a.organization_id=d.organization_id AND a.server_id=d.server_id AND a.released_at IS NULL JOIN servers s ON s.id=a.server_id
      WHERE r.state='installed' AND d.installer_status='tls_pending' AND d.lifecycle_state<>'deleted' AND d.mail_hostname IS NOT NULL AND d.webmail_hostname IS NOT NULL
      ORDER BY d.updated_at LIMIT 1`);
    return rows.rows[0] ?? null;
  });
  if (!candidate) return;
  let ready = false;
  try {
    ready = await probe({
      publicIpv4: candidate.public_ipv4,
      mailHostname: candidate.mail_hostname,
      webmailHostname: candidate.webmail_hostname,
    });
  } catch {
    return;
  }
  if (!ready) return;
  await ctx.withSystem("inventory_worker", async (db) => {
    await ctx.setActor(db, "platform_administrator");
    if (await mutationsPaused(db)) return;
    const saved = await db.query(
      `UPDATE deployments d SET installer_status='succeeded',version=version+1,updated_at=now()
      WHERE d.id=$1 AND d.version=$2 AND d.installer_status='tls_pending' AND d.lifecycle_state<>'deleted'
      AND EXISTS(SELECT 1 FROM server_assignments a JOIN servers s ON s.id=a.server_id WHERE a.organization_id=d.organization_id AND a.server_id=d.server_id AND a.released_at IS NULL AND s.public_ipv4=$3::inet) RETURNING d.id`,
      [candidate.id, candidate.version, candidate.public_ipv4],
    );
    if (!saved.rows[0]) return;
    await db.query(
      "INSERT INTO audit_events(id,actor_type,organization_id,deployment_id,action,target,request_id,redacted_diff) VALUES($1,'system',$2,$3,'deployment.https_ready',$5,$4,'{\"mailHttpsVerified\":true,\"webmailHttpsVerified\":true}')",
      [randomUUID(), candidate.organization_id, candidate.id, randomUUID(), candidate.id],
    );
  });
}
