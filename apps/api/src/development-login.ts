import { createHash, randomBytes } from "node:crypto";
import { readFileSync, writeFileSync, unlinkSync } from "node:fs";
import type { FastifyInstance } from "fastify";

export const developmentLoginFile = new URL(
  "../../../.data/trial/operator-login.json",
  import.meta.url,
);
export function createDevelopmentLogin(
  token: string,
  file: URL = developmentLoginFile,
): string {
  const code = randomBytes(32).toString("base64url");
  writeFileSync(
    file,
    JSON.stringify({
      digest: digest(code),
      token,
      expires: Date.now() + 5 * 60_000,
    }),
    { mode: 0o600 },
  );
  return code;
}
function digest(code: string) {
  return createHash("sha256").update(code).digest("hex");
}

export function registerDevelopmentLogin(
  app: FastifyInstance,
  enabled: boolean,
  file: URL = developmentLoginFile,
) {
  app.get("/operator/login", async (_request, reply) => {
    if (!enabled) return reply.code(404).send({ error: "Not found" });
    return reply
      .header("cache-control", "no-store")
      .header("referrer-policy", "no-referrer")
      .type("text/html")
      .send(`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Operator sign-in · BearPortal</title><style>body{font:17px -apple-system,BlinkMacSystemFont,sans-serif;background:#f5f5f7;color:#1d1d1f;margin:0;padding:15vh 24px}main{background:white;border-radius:24px;padding:40px;max-width:460px;margin:auto}h1{letter-spacing:-.04em}p{line-height:1.6;color:#6e6e73}code{font-size:14px}</style><main><h1>BearPortal operator</h1><p id="status" role="status">Signing you in…</p></main><script>
(async()=>{const code=location.hash.slice(1);history.replaceState(null,'',location.pathname);const status=document.getElementById('status');if(!code){status.textContent='On the server, run pnpm trial:login, then open the link it prints.';return}try{const response=await fetch('/operator/login',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({code})});if(!response.ok)throw Error('This link has expired or has already been used. Run pnpm trial:login on the server for a new link.');location.replace('/operator')}catch(error){status.textContent=error.message}})();
</script></html>`);
  });
  app.post("/operator/login", async (request, reply) => {
    reply.header("cache-control", "no-store");
    if (!enabled) return reply.code(404).send({ error: "Not found" });
    const code = (request.body as { code?: unknown } | undefined)?.code;
    if (typeof code !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(code))
      return reply.code(401).send({ error: "Invalid link" });
    let saved: { digest: string; token: string; expires: number };
    try {
      saved = JSON.parse(readFileSync(file, "utf8"));
    } catch {
      return reply.code(401).send({ error: "Invalid link" });
    }
    if (saved.expires < Date.now() || saved.digest !== digest(code))
      return reply.code(401).send({ error: "Invalid link" });
    // Consume synchronously before awaiting any work so concurrent redemption cannot succeed twice.
    unlinkSync(file);
    const authorized = await app.inject({
      method: "GET",
      url: "/v1/admin/portal",
      headers: { authorization: "Bearer " + saved.token },
    });
    if (authorized.statusCode !== 200)
      return reply.code(403).send({ error: "Operator access required" });
    const session = await app.inject({
      method: "POST",
      url: "/v1/session",
      payload: { idToken: saved.token },
    });
    if (session.statusCode !== 200)
      return reply.code(401).send({ error: "Sign-in failed" });
    reply.header("set-cookie", session.headers["set-cookie"]!);
    return { ok: true };
  });
}
