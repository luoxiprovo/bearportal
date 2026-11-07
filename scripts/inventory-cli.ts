import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import {
  serverCreateSchema,
  relayConnectionCreateSchema,
} from "../packages/contracts/src/index.ts";
import { assertPublicUnicastIpv4 } from "../packages/servers/src/address.ts";

export const inventoryHelp = `Usage:
  pnpm inventory servers list
  pnpm inventory servers add --file /path/to/server.json
  pnpm inventory brevo list
  pnpm inventory brevo add --file /path/to/brevo.json

Use --file - to read JSON from standard input.
Optional: --idempotency-key KEY when adding (reuse the same key and input after an uncertain response).
Runs against the API configured in .data/trial/env, using the existing development administrator.
See docs/runbooks/inventory.md for JSON examples and production API authentication.`;

export async function runInventory(
  args: string[],
  config: { origin: string; token: string; fetch?: typeof fetch },
): Promise<string> {
  const [resource, action, ...flags] = args;
  if (
    !["servers", "brevo"].includes(resource) ||
    !["add", "list"].includes(action)
  )
    throw new Error(inventoryHelp);
  const options = new Map<string, string>();
  for (let i = 0; i < flags.length; i += 2) {
    if (
      !["--file", "--idempotency-key"].includes(flags[i]) ||
      !flags[i + 1] ||
      options.has(flags[i])
    )
      throw new Error(inventoryHelp);
    options.set(flags[i], flags[i + 1]);
  }
  if (action === "list" && options.size) throw new Error(inventoryHelp);
  let body: Record<string, unknown> | undefined;
  if (action === "add") {
    const file = options.get("--file");
    if (!file)
      throw new Error(
        "Provide --file with the inventory JSON. " + inventoryHelp,
      );
    let input: unknown;
    try {
      const raw = readFileSync(file === "-" ? 0 : file, "utf8");
      if (raw.length > 65536) throw Error();
      input = JSON.parse(raw);
    } catch {
      throw new Error(
        "Cannot read inventory JSON. Check the file path and JSON syntax.",
      );
    }
    const parsed = (
      resource === "servers" ? serverCreateSchema : relayConnectionCreateSchema
    ).safeParse(input);
    if (!parsed.success)
      throw new Error(
        "Invalid inventory fields: " +
          parsed.error.issues
            .map((issue) => issue.path.join(".") + ": " + issue.message)
            .join("; "),
      );
    body = parsed.data;
    if (resource === "servers") {
      try {
        assertPublicUnicastIpv4(body.publicIpv4 as string);
      } catch {
        throw new Error("A public unicast IPv4 address is required.");
      }
    }
  }
  const key = options.get("--idempotency-key") ?? randomUUID();
  if (key.length < 8 || key.length > 200)
    throw new Error("Idempotency key must contain 8–200 characters.");
  const redact = (text: string) =>
    [config.token, body?.apiKey, body?.smtpKey].reduce<string>(
      (text, value) =>
        typeof value === "string" && value
          ? text.split(value).join("[redacted]")
          : text,
      text,
    );
  let response: Response;
  try {
    response = await (config.fetch ?? fetch)(
      new URL(
        resource === "servers"
          ? "/v1/admin/servers"
          : "/v1/admin/relay-connections",
        config.origin,
      ),
      {
        method: action === "add" ? "POST" : "GET",
        headers: {
          authorization: "Bearer " + config.token,
          ...(body
            ? { "content-type": "application/json", "idempotency-key": key }
            : {}),
        },
        ...(body ? { body: JSON.stringify(body) } : {}),
        redirect: "error",
      },
    );
  } catch {
    throw new Error(
      "Cannot reach BearPortal. Start it with pnpm trial:start and check the API origin.",
    );
  }
  const result = (await response.json()) as Record<string, unknown>;
  if (!response.ok) {
    const error = result.error as
      { message?: string; code?: string } | undefined;
    throw new Error(
      redact(
        `BearPortal HTTP ${response.status}: ${error?.message ?? "Request failed"}`,
      ),
    );
  }
  return redact(
    JSON.stringify(
      { ...result, ...(body ? { idempotencyKey: key } : {}) },
      null,
      2,
    ),
  );
}
