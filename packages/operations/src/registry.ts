import { createHash } from "node:crypto";

export type OperationState = "approved" | "withdrawn";

export type OperationRelease = {
  key: string;
  version: string;
  capability: string;
  state: OperationState;
  handler: string;
  digest: string;
};

/**
 * Capabilities that stay unreachable. An approval, a catalog row, or allow-all
 * cannot turn any of these into a worker.
 */
export const FORBIDDEN_CAPABILITIES = [
  "cloud.vm",
  "cloud.firewall",
  "cloud.disk",
  "cloud.region",
  "dns.write",
  "mail.read_body",
  "shell.exec",
  "iam.grant",
  "approval.self",
  "secret.read",
  "allocation.override",
  "plan.assign",
] as const;

export type ForbiddenCapability = (typeof FORBIDDEN_CAPABILITIES)[number];

const forbiddenCapabilities = new Set<string>(FORBIDDEN_CAPABILITIES);

export function isForbiddenCapability(capability: string): boolean {
  return forbiddenCapabilities.has(capability);
}

export function operationDigest(key: string, version: string, handler: string): string {
  return createHash("sha256").update(`${key}\n${version}\n${handler}`).digest("hex");
}

function pin(key: string, version: string, capability: string, state: OperationState): OperationRelease {
  const handler = `bearportal.handlers/${key}/${version}`;
  return { key, version, capability, state, handler, digest: operationDigest(key, version, handler) };
}

/** Approved releases plus withdrawn history. Callers cannot add a row at runtime. */
export const operationCatalog: readonly OperationRelease[] = [
  pin("organization.allocate", "1", "inventory.allocate", "approved"),
  pin("dns.store_credentials", "1", "dns.store", "approved"),
  pin("dns.dry_run", "1", "dns.read", "approved"),
  pin("dns.inspect", "1", "dns.read", "approved"),
  pin("brevo.create_domain", "1", "brevo.domain", "approved"),
  pin("brevo.authenticate", "1", "brevo.authenticate", "approved"),
  pin("installer.run", "1", "installer.run", "approved"),
  pin("mailbox.credential", "1", "mailbox.credential", "approved"),
  pin("inventory.validate", "1", "inventory.validate", "approved"),
  pin("relay.validate", "1", "relay.validate", "approved"),
  pin("deployment.read_state", "1", "deployment.read", "approved"),
  pin("deployment.read_state", "0", "deployment.read", "withdrawn"),
  pin("connections.validate", "1", "connections.read", "approved"),
  pin("health.probe", "1", "health.read", "approved"),
  pin("assignment.reconcile", "1", "inventory.reconcile", "approved"),
  pin("checkpoint.request", "1", "workflow.request", "approved"),
  pin("repair.propose", "1", "repair.plan", "approved"),
  pin("human_action.request", "1", "human.request", "approved"),
  pin("diagnosis.record", "1", "diagnosis.record", "approved"),
];

export const approvedOperations: readonly OperationRelease[] = operationCatalog.filter((item) => item.state === "approved");

export function requireOperation(key: string): OperationRelease {
  const found = approvedOperations.find((item) => item.key === key);
  if (!found) {
    throw new Error(`Operation ${key} is not an approved release.`);
  }
  return found;
}

export function resolveRelease(key: string, version?: string):
  | { ok: true; release: OperationRelease }
  | { ok: false; code: "UNREGISTERED" | "WITHDRAWN" | "VERSION_UNKNOWN" } {
  const matches = operationCatalog.filter((item) => item.key === key);
  if (matches.length === 0) return { ok: false, code: "UNREGISTERED" };
  const chosen = version ? matches.find((item) => item.version === version) : matches.find((item) => item.state === "approved");
  if (!chosen) return { ok: false, code: "VERSION_UNKNOWN" };
  if (chosen.state !== "approved") return { ok: false, code: "WITHDRAWN" };
  if (isForbiddenCapability(chosen.capability)) return { ok: false, code: "UNREGISTERED" };
  return { ok: true, release: chosen };
}
