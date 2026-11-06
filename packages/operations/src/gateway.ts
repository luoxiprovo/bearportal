import { createHash } from "node:crypto";
import { isForbiddenCapability, resolveRelease, type OperationRelease } from "./registry.ts";
import { AGENT_LIMITS, budgetExhausted } from "./policy.ts";

export const OVERSIGHT_TOOLS = [
  "read_deployment_state",
  "validate_connections",
  "inspect_dns",
  "run_health_probe",
  "reconcile_assignment",
  "request_checkpoint",
  "propose_repair",
  "request_human_action",
  "record_diagnosis",
] as const;

export type OversightTool = (typeof OVERSIGHT_TOOLS)[number];

const TOOL_KEYS: Record<OversightTool, string> = {
  read_deployment_state: "deployment.read_state",
  validate_connections: "connections.validate",
  inspect_dns: "dns.inspect",
  run_health_probe: "health.probe",
  reconcile_assignment: "assignment.reconcile",
  request_checkpoint: "checkpoint.request",
  propose_repair: "repair.propose",
  request_human_action: "human_action.request",
  record_diagnosis: "diagnosis.record",
};

const TENANT_TOOLS = new Set<OversightTool>([
  "read_deployment_state",
  "inspect_dns",
  "run_health_probe",
  "request_checkpoint",
  "propose_repair",
  "request_human_action",
  "record_diagnosis",
]);

const SCRATCH_TOOLS = new Set(["bash", "shell", "read_file", "write", "grep", "list_dir", "edit", "spawn_subagent"]);

const FORBIDDEN_TOOLS = new Set([
  "shell.exec",
  "iam.grant",
  "secret.read",
  "approval.decide",
  "vm.create",
  "firewall.update",
  "disk.resize",
  "dns.write",
  "plan.assign",
  "allocation.override",
  "read_mail_body",
]);

const CONTEXT_FIELDS = new Set([
  "jobId",
  "organizationId",
  "deploymentId",
  "serverId",
  "assignmentId",
  "generation",
  "authEpoch",
  "leaseFencingToken",
  "actor",
  "context",
]);

const SECRET_FIELDS = new Set([
  "password",
  "apiKey",
  "apiSecret",
  "smtpKey",
  "token",
  "secret",
  "credential",
  "credentials",
  "authorization",
]);

const COMMAND_FIELDS = new Set([
  "command",
  "shell",
  "code",
  "codeBody",
  "executable",
  "executablePath",
  "script",
  "scriptUrl",
  "scriptPath",
  "argv",
  "env",
]);

const PROBE_KINDS = new Set([
  "heartbeat",
  "reachability",
  "https",
  "jmap",
  "imaps",
  "smtp",
  "engine",
  "relay",
  "certificate",
  "delivery",
  "backup",
  "disk",
]);

const CHECKPOINT_KEYS = new Set(["installer.run", "brevo.authenticate", "mailbox.credential", "dns.dry_run", "brevo.create_domain"]);

const READ_COMPLETIONS = new Set([
  "deployment.read_state",
  "connections.validate",
  "dns.inspect",
  "assignment.reconcile",
  "repair.propose",
  "human_action.request",
  "diagnosis.record",
]);

export type SessionAuthority = {
  sessionId: string;
  scope: "tenant" | "inventory";
  organizationId: string | null;
  deploymentId: string | null;
  serverId: string | null;
  assignmentId: string | null;
  generation: number;
  authEpoch: number;
  leaseFencingToken: string;
  toolRequests: number;
  invocations: number;
  startedAtMs: number;
  state: "open" | "terminated";
};

export type TenantOperationContext = {
  scope: "tenant";
  organizationId: string;
  deploymentId: string;
  serverId: string | null;
  assignmentId: string | null;
  generation: number;
  authEpoch: number;
  leaseFencingToken: string;
  actor: "oversight";
};

export type InventoryOperationContext = {
  scope: "inventory";
  serverId: string;
  authEpoch: number;
  generation: number;
  leaseFencingToken: string;
  actor: "oversight";
};

export type GatewayDecision = {
  outcome: "pending" | "blocked" | "permanent_error";
  httpStatus: number;
  code: string;
  message: string;
  stepId: string | null;
  operationKey: string | null;
  version: string | null;
  handler: string | null;
  digest: string | null;
  requested: OperationRelease | null;
  productionInvoked: boolean;
  toolRequests: number;
  terminate: boolean;
  arguments: Record<string, unknown> | null;
};

function stable(value: unknown): string {
  return JSON.stringify(sortValue(value));
}

function sortValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortValue);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value as Record<string, unknown>).sort(([left], [right]) => left.localeCompare(right)).map(([key, item]) => [key, sortValue(item)]));
  }
  return value;
}

export function stepIdFor(sessionId: string, tool: string, version: string, args: Record<string, unknown>): string {
  return createHash("sha256").update(`${sessionId}\n${tool}\n${version}\n${stable(args)}`).digest("hex");
}

function blocked(session: SessionAuthority, code: string, message: string, status: number, terminate = false): GatewayDecision {
  return {
    outcome: status === 400 ? "permanent_error" : "blocked",
    httpStatus: status,
    code,
    message,
    stepId: null,
    operationKey: null,
    version: null,
    handler: null,
    digest: null,
    requested: null,
    productionInvoked: false,
    toolRequests: session.toolRequests + 1,
    terminate,
    arguments: null,
  };
}

function walkKeys(value: unknown, found: Set<string>): void {
  if (!value || typeof value !== "object") return;
  if (Array.isArray(value)) {
    for (const item of value) walkKeys(item, found);
    return;
  }
  for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
    found.add(key);
    walkKeys(item, found);
  }
}

function isUuid(value: unknown): value is string {
  return typeof value === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value);
}

function parseArguments(tool: OversightTool, args: Record<string, unknown>): { ok: true; value: Record<string, unknown> } | { ok: false; message: string } {
  const keys = Object.keys(args);
  if (tool === "read_deployment_state" || tool === "validate_connections" || tool === "reconcile_assignment") {
    if (keys.length > 0) return { ok: false, message: "The tool arguments are not valid." };
    return { ok: true, value: {} };
  }
  if (tool === "inspect_dns") {
    if (keys.some((key) => key !== "dnsText")) return { ok: false, message: "The tool arguments are not valid." };
    if (args.dnsText != null && (typeof args.dnsText !== "string" || args.dnsText.length > 2000)) {
      return { ok: false, message: "The tool arguments are not valid." };
    }
    return { ok: true, value: args.dnsText == null ? {} : { dnsText: args.dnsText } };
  }
  if (tool === "run_health_probe") {
    if (keys.length !== 1 || keys[0] !== "probeKind" || typeof args.probeKind !== "string" || !PROBE_KINDS.has(args.probeKind)) {
      return { ok: false, message: "The tool arguments are not valid." };
    }
    return { ok: true, value: { probeKind: args.probeKind } };
  }
  if (tool === "request_checkpoint") {
    if (keys.length !== 1 || keys[0] !== "checkpointKey" || typeof args.checkpointKey !== "string" || !CHECKPOINT_KEYS.has(args.checkpointKey)) {
      return { ok: false, message: "The tool arguments are not valid." };
    }
    return { ok: true, value: { checkpointKey: args.checkpointKey } };
  }
  if (tool === "propose_repair") {
    const allowed = keys.every((key) => key === "repairType" || key === "evidenceIds");
    const evidence = args.evidenceIds;
    if (!allowed || (args.repairType !== "dns_drift" && args.repairType !== "relay" && args.repairType !== "health")) {
      return { ok: false, message: "The tool arguments are not valid." };
    }
    if (!Array.isArray(evidence) || evidence.length > 20 || evidence.some((item) => !isUuid(item))) {
      return { ok: false, message: "The tool arguments are not valid." };
    }
    return { ok: true, value: { repairType: args.repairType, evidenceIds: evidence } };
  }
  if (tool === "request_human_action") {
    const allowed = keys.every((key) => key === "actionCode" || key === "evidenceIds");
    const evidence = args.evidenceIds;
    if (!allowed || typeof args.actionCode !== "string" || !/^[a-z][a-z0-9._-]{0,79}$/.test(args.actionCode)) {
      return { ok: false, message: "The tool arguments are not valid." };
    }
    if (args.actionCode.startsWith("cloud.") || args.actionCode.startsWith("iam.") || args.actionCode.startsWith("shell")) {
      return { ok: false, message: "That action is not a tool." };
    }
    if (!Array.isArray(evidence) || evidence.length > 20 || evidence.some((item) => !isUuid(item))) {
      return { ok: false, message: "The tool arguments are not valid." };
    }
    return { ok: true, value: { actionCode: args.actionCode, evidenceIds: evidence } };
  }
  const allowed = keys.every((key) => key === "summary" || key === "evidenceIds");
  const evidence = args.evidenceIds;
  if (!allowed || typeof args.summary !== "string" || args.summary.length < 1 || args.summary.length > 500) {
    return { ok: false, message: "The tool arguments are not valid." };
  }
  if (!Array.isArray(evidence) || evidence.length > 20 || evidence.some((item) => !isUuid(item))) {
    return { ok: false, message: "The tool arguments are not valid." };
  }
  return { ok: true, value: { summary: args.summary, evidenceIds: evidence } };
}

export function requestOperation(input: {
  tool: string;
  version?: string;
  claimedDigest?: string;
  arguments: Record<string, unknown>;
  session: SessionAuthority;
  context: TenantOperationContext | InventoryOperationContext;
  recovery: boolean;
  nowMs: number;
  approval?: { decision: string; capability: string } | null;
}): GatewayDecision {
  const session = input.session;
  if (session.state !== "open") {
    return blocked(session, "SESSION_CLOSED", "The oversight session is closed.", 409);
  }
  const budget = budgetExhausted({
    elapsedMs: input.nowMs - session.startedAtMs,
    toolRequests: session.toolRequests,
    invocations: session.invocations,
  });
  if (budget.exhausted) {
    return blocked(session, "BUDGET_EXHAUSTED", "The oversight run reached its budget.", 429, true);
  }
  if (input.recovery) {
    return blocked(session, "RECOVERY_MODE", "Control-plane recovery has paused agent requests.", 409);
  }
  const names = new Set<string>();
  walkKeys(input.arguments, names);
  if ([...names].some((key) => CONTEXT_FIELDS.has(key))) {
    return blocked(session, "CONTEXT_OVERRIDE", "The model cannot supply operation context.", 400);
  }
  if ([...names].some((key) => SECRET_FIELDS.has(key))) {
    return blocked(session, "CREDENTIAL_DENIED", "Credentials are not available to oversight.", 422);
  }
  if ([...names].some((key) => COMMAND_FIELDS.has(key))) {
    return blocked(session, "COMMAND_REJECTED", "Oversight cannot supply a command or script.", 422);
  }
  if (names.has("decision") || names.has("selfApprove")) {
    return blocked(session, "SELF_APPROVAL", "Oversight cannot approve its own plan.", 422);
  }
  if (input.approval && isForbiddenCapability(input.approval.capability)) {
    return blocked(session, "FORBIDDEN", "Approval cannot enable that capability.", 422);
  }
  if (SCRATCH_TOOLS.has(input.tool)) {
    return blocked(session, "SCRATCH_ONLY", "Scratch-workspace tools cannot call a production worker.", 422);
  }
  if (FORBIDDEN_TOOLS.has(input.tool) || isForbiddenCapability(input.tool)) {
    return blocked(session, "FORBIDDEN", "That capability is not a BearPortal tool.", 422);
  }
  if (!(OVERSIGHT_TOOLS as readonly string[]).includes(input.tool)) {
    return blocked(session, "UNREGISTERED", "That operation is not registered.", 422);
  }
  const tool = input.tool as OversightTool;
  if (input.context.scope !== session.scope || input.context.leaseFencingToken !== session.leaseFencingToken) {
    return blocked(session, "STALE_AUTHORITY", "The session authority does not match this operation.", 409, true);
  }
  if (input.context.generation !== session.generation || input.context.authEpoch !== session.authEpoch) {
    return blocked(session, "STALE_AUTHORITY", "The session authority does not match this operation.", 409, true);
  }
  if (session.scope === "tenant") {
    if (input.context.scope !== "tenant" || input.context.organizationId !== session.organizationId || input.context.deploymentId !== session.deploymentId) {
      return blocked(session, "TENANT_SCOPE", "The session cannot cross tenants.", 404);
    }
  } else if (TENANT_TOOLS.has(tool) || input.context.scope !== "inventory" || input.context.serverId !== session.serverId) {
    return blocked(session, "INVENTORY_SCOPE", "An inventory session cannot act as a tenant.", 422);
  }
  const parsed = parseArguments(tool, input.arguments);
  if (!parsed.ok) {
    const code = parsed.message === "That action is not a tool." ? "FORBIDDEN" : "INVALID_INPUT";
    return blocked(session, code, parsed.message, code === "FORBIDDEN" ? 422 : 400);
  }
  const operationKey = TOOL_KEYS[tool];
  const resolved = resolveRelease(operationKey, input.version);
  if (!resolved.ok) {
    const status = resolved.code === "UNREGISTERED" ? 422 : 422;
    return blocked(session, resolved.code, "That operation release cannot run.", status);
  }
  if (input.claimedDigest && input.claimedDigest !== resolved.release.digest) {
    return blocked(session, "DIGEST_MISMATCH", "The operation digest does not match the approved release.", 409);
  }
  let requested: OperationRelease | null = null;
  if (tool === "request_checkpoint") {
    const checkpoint = resolveRelease(String(parsed.value.checkpointKey));
    if (!checkpoint.ok) return blocked(session, checkpoint.code, "That checkpoint release cannot run.", 422);
    requested = checkpoint.release;
  }
  const version = resolved.release.version;
  return {
    outcome: "pending",
    httpStatus: 202,
    code: "ACCEPTED",
    message: "The verified worker has not completed this step.",
    stepId: stepIdFor(session.sessionId, tool, version, parsed.value),
    operationKey,
    version,
    handler: resolved.release.handler,
    digest: resolved.release.digest,
    requested,
    productionInvoked: true,
    toolRequests: session.toolRequests + 1,
    terminate: false,
    arguments: parsed.value,
  };
}

export function completeVerifiedStep(input: {
  operationKey: string;
  state: "pending" | "succeeded" | "blocked" | "retryable_error" | "permanent_error";
  digest: string;
  handler: string;
  claimedDigest?: string;
  sessionState: "open" | "terminated";
  sessionGeneration: number;
  currentGeneration: number;
  sessionEpoch: number;
  currentEpoch: number;
}): { outcome: "succeeded" | "pending" | "permanent_error"; httpStatus: number; code: string; message: string } {
  if (input.sessionState !== "open" || input.sessionGeneration !== input.currentGeneration || input.sessionEpoch !== input.currentEpoch) {
    return { outcome: "permanent_error", httpStatus: 409, code: "STALE_AUTHORITY", message: "The session authority is no longer current." };
  }
  if (input.claimedDigest && input.claimedDigest !== input.digest) {
    return { outcome: "pending", httpStatus: 409, code: "DIGEST_MISMATCH", message: "The worker digest does not match the pinned release." };
  }
  if (input.state !== "pending") {
    return { outcome: input.state === "succeeded" ? "succeeded" : "permanent_error", httpStatus: 200, code: "ALREADY_RECORDED", message: "The step already has a worker result." };
  }
  if (!READ_COMPLETIONS.has(input.operationKey)) {
    return { outcome: "pending", httpStatus: 202, code: "ACCEPTED", message: "The request is pinned and waiting for the verified worker." };
  }
  if (!input.handler.startsWith("bearportal.handlers/") || input.digest.length !== 64) {
    return { outcome: "permanent_error", httpStatus: 422, code: "UNREGISTERED", message: "The step is not pinned to an approved handler." };
  }
  return { outcome: "succeeded", httpStatus: 200, code: "VERIFIED", message: "The verified worker recorded the step." };
}

export function invocationAllowed(invocations: number): boolean {
  return invocations < AGENT_LIMITS.maxInvocationsPerCheckpoint;
}
