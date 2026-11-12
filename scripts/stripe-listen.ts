import { readFileSync, writeFileSync, renameSync, chmodSync } from "node:fs";
import { execFileSync, spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { join } from "node:path";

const root = fileURLToPath(new URL("../", import.meta.url));
const envFile = join(root, ".data/trial/env");
const redact = (text: string) =>
  text.replace(
    /whsec_[A-Za-z0-9_]+|[sr]k_(?:test|live)_[A-Za-z0-9_]+/g,
    "[private value hidden]",
  );
try {
  const original = readFileSync(envFile, "utf8");
  const env = Object.fromEntries(
    original
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line && !line.startsWith("#") && line.includes("="))
      .map((line) => {
        const i = line.indexOf("=");
        return [line.slice(0, i), line.slice(i + 1)];
      }),
  );
  if (!/^(sk|rk)_test_/.test(env.STRIPE_SECRET_KEY ?? ""))
    throw new Error(
      "Set a real Stripe test runtime key in .data/trial/env first. This helper does not forward live events.",
    );
  const port = Number(env.PORT || process.env.PORT || 8088);
  if (!Number.isInteger(port) || port < 1 || port > 65535)
    throw new Error("PORT is invalid.");
  const childEnv = { ...process.env, STRIPE_API_KEY: env.STRIPE_SECRET_KEY };
  const output = execFileSync(
    "stripe",
    ["listen", "--all-snapshot", "--print-secret"],
    {
      env: childEnv,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      timeout: 30000,
    },
  );
  const signingSecret = output.match(/\bwhsec_[A-Za-z0-9_]+\b/)?.[0];
  if (!signingSecret)
    throw new Error("Stripe did not return a signing secret.");
  // Re-read so this small update does not replace unrelated configuration edits.
  const current = readFileSync(envFile, "utf8");
  if (current !== original)
    throw new Error(
      "Configuration changed while connecting to Stripe. Run pnpm stripe:listen again.",
    );
  const pattern = /^\s*STRIPE_WEBHOOK_SECRET=.*$/gm;
  const updated = pattern.test(current)
    ? current.replace(pattern, "STRIPE_WEBHOOK_SECRET=" + signingSecret)
    : current.trimEnd() + "\nSTRIPE_WEBHOOK_SECRET=" + signingSecret + "\n";
  const temporary = envFile + ".stripe-listener-" + process.pid;
  writeFileSync(temporary, updated, { mode: 0o600 });
  chmodSync(temporary, 0o600);
  renameSync(temporary, envFile);
  console.log(
    "Saved the matching webhook signing secret to .data/trial/env. Start or restart BearPortal after this message.",
  );
  console.log(
    "Forwarding test events using the same private key as BearPortal. Keep this terminal open.",
  );
  const listener = spawn(
    "stripe",
    [
      "listen",
      "--all-snapshot",
      "--forward-to",
      `http://127.0.0.1:${port}/webhooks/stripe`,
    ],
    { env: childEnv, stdio: ["ignore", "pipe", "pipe"] },
  );
  for (const stream of [listener.stdout, listener.stderr])
    createInterface({ input: stream }).on("line", (line) =>
      console.log(redact(line)),
    );
  process.on("SIGINT", () => listener.kill("SIGINT"));
  process.on("SIGTERM", () => listener.kill("SIGTERM"));
  listener.on("error", () => {
    console.error(
      "Could not start Stripe CLI. Check that stripe is installed.",
    );
    process.exitCode = 1;
  });
  listener.on("exit", (code) => {
    process.exitCode = code ?? 0;
  });
} catch (error) {
  const failure = error as Error & { stderr?: Buffer | string };
  console.error(redact(failure.stderr?.toString() || failure.message));
  process.exitCode = 1;
}
