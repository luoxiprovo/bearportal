import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import Fastify from "../apps/api/node_modules/fastify/fastify.js";
import {
  createDevelopmentLogin,
  registerDevelopmentLogin,
} from "../apps/api/src/development-login.ts";

test("development operator links expire, redeem once, check roles and stay disabled without development identity", async () => {
  const dir = mkdtempSync(join(tmpdir(), "bearportal-login-"));
  const file = pathToFileURL(join(dir, "login.json"));
  const app = Fastify();
  app.get("/v1/admin/portal", async (request, reply) =>
    request.headers.authorization === "Bearer admin-token"
      ? { ok: true }
      : reply.code(403).send({ error: "Forbidden" }),
  );
  app.post("/v1/session", async (_request, reply) =>
    reply
      .header(
        "set-cookie",
        "bp_session=admin-token; HttpOnly; SameSite=Lax; Path=/",
      )
      .send({ ok: true }),
  );
  registerDevelopmentLogin(app, true, file);
  try {
    let code = createDevelopmentLogin("admin-token", file);
    assert.equal(readFileSync(file, "utf8").includes(code), false);
    const redeem = (value: string) =>
      app.inject({
        method: "POST",
        url: "/operator/login",
        payload: { code: value },
      });
    assert.equal((await redeem("x".repeat(43))).statusCode, 401);
    const results = await Promise.all([redeem(code), redeem(code)]);
    assert.deepEqual(results.map((r) => r.statusCode).sort(), [200, 401]);
    assert.match(
      String(results.find((r) => r.statusCode === 200)!.headers["set-cookie"]),
      /HttpOnly/,
    );
    code = createDevelopmentLogin("admin-token", file);
    const expired = JSON.parse(readFileSync(file, "utf8"));
    expired.expires = Date.now() - 1;
    writeFileSync(file, JSON.stringify(expired));
    assert.equal((await redeem(code)).statusCode, 401);
    code = createDevelopmentLogin("customer-token", file);
    assert.equal((await redeem(code)).statusCode, 403);
    assert.equal((await redeem(code)).statusCode, 401);
    const page = await app.inject("/operator/login");
    assert.equal(page.headers["referrer-policy"], "no-referrer");
    assert.equal(page.headers["cache-control"], "no-store");
    assert.ok(page.body.includes("history.replaceState"));
  } finally {
    await app.close();
    rmSync(dir, { recursive: true, force: true });
  }
  const production = Fastify();
  registerDevelopmentLogin(production, false, file);
  assert.equal((await production.inject("/operator/login")).statusCode, 404);
  assert.equal(
    (
      await production.inject({
        method: "POST",
        url: "/operator/login",
        payload: { code: "x".repeat(43) },
      })
    ).statusCode,
    404,
  );
  await production.close();
});
