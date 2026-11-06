/** Oversight limits documented in SPEC.md section 9. */
export const AGENT_LIMITS = {
  maxElapsedMs: 5 * 60 * 1000,
  maxToolRequests: 20,
  maxInvocationsPerCheckpoint: 3,
  approvalWindowMs: 30 * 60 * 1000,
  watchdogMs: 120 * 1000,
  restartPerIncident: 1,
  restartPerDay: 2,
} as const;

export const FIVE_MINUTE_PROBES = ["heartbeat", "reachability", "https", "jmap", "imaps", "smtp", "engine"] as const;
export const DAILY_PROBES = ["certificate", "delivery", "backup"] as const;
export const NETWORK_PROBES = ["heartbeat", "reachability", "https", "jmap", "imaps", "smtp", "engine"] as const;
export const REQUIRED_PROBES = [...FIVE_MINUTE_PROBES, "relay", ...DAILY_PROBES, "disk"] as const;

export type ProbeName = (typeof REQUIRED_PROBES)[number];
export type ProbeState = "pass" | "fail" | "partial" | "absent";
export type HealthState = "unknown" | "healthy" | "degraded" | "unavailable";

const FIVE_MINUTE_FRESHNESS_MS = 30 * 60 * 1000;
const RELAY_FRESHNESS_MS = 2 * 60 * 60 * 1000;
const DAILY_FRESHNESS_MS = 26 * 60 * 60 * 1000;

export type HealthObservation = {
  probe: string;
  state: ProbeState;
  observedAt: number | null;
  diskPercent?: number | null;
};

export type DiskLevel = "unknown" | "ok" | "warn" | "degraded" | "action";

export function freshnessWindowMs(probe: string): number {
  if ((FIVE_MINUTE_PROBES as readonly string[]).includes(probe) || probe === "disk") return FIVE_MINUTE_FRESHNESS_MS;
  if (probe === "relay") return RELAY_FRESHNESS_MS;
  return DAILY_FRESHNESS_MS;
}

export function observationFresh(observation: HealthObservation, nowMs: number): boolean {
  if (observation.observedAt == null) return false;
  return nowMs - observation.observedAt <= freshnessWindowMs(observation.probe);
}

export function diskAssessment(percent: number | null | undefined): { level: DiskLevel; autoDelete: false } {
  if (percent == null || Number.isNaN(percent)) return { level: "unknown", autoDelete: false };
  if (percent >= 90) return { level: "action", autoDelete: false };
  if (percent >= 85) return { level: "degraded", autoDelete: false };
  if (percent >= 75) return { level: "warn", autoDelete: false };
  return { level: "ok", autoDelete: false };
}

export function deriveHealth(observations: readonly HealthObservation[], nowMs: number): {
  health: HealthState;
  reasons: string[];
  deliveryProven: boolean;
  acceptedMailIsDelivery: false;
  diskLevel: DiskLevel;
} {
  const latest = new Map<string, HealthObservation>();
  for (const observation of observations) latest.set(observation.probe, observation);
  const disk = latest.get("disk");
  const assessed = diskAssessment(disk?.diskPercent);
  const diskLevel = assessed.level;
  const delivery = latest.get("delivery");
  const deliveryProven = Boolean(delivery && delivery.state === "pass" && observationFresh(delivery, nowMs));
  if (latest.size === 0) {
    return { health: "unknown", reasons: ["health.no_evidence"], deliveryProven: false, acceptedMailIsDelivery: false, diskLevel };
  }
  const smtp = latest.get("smtp");
  const engine = latest.get("engine");
  if (smtp?.state === "fail" || engine?.state === "fail") {
    return {
      health: "unavailable",
      reasons: [smtp?.state === "fail" ? "smtp.outage" : "engine.outage"],
      deliveryProven,
      acceptedMailIsDelivery: false,
      diskLevel,
    };
  }
  const reasons: string[] = [];
  let missing = false;
  let degraded = false;
  for (const probe of REQUIRED_PROBES) {
    const observation = latest.get(probe);
    if (!observation || observation.state === "absent") {
      missing = true;
      reasons.push(`${probe}.missing`);
      continue;
    }
    if (!observationFresh(observation, nowMs)) {
      degraded = true;
      reasons.push(`${probe}.stale`);
    }
    if (observation.state === "fail" || observation.state === "partial") {
      degraded = true;
      reasons.push(`${probe}.${observation.state}`);
    }
  }
  if (assessed.level === "degraded" || assessed.level === "action") {
    degraded = true;
    reasons.push(`disk.${assessed.level}`);
  }
  if (missing && !degraded) {
    return { health: "unknown", reasons, deliveryProven, acceptedMailIsDelivery: false, diskLevel };
  }
  if (degraded || missing) {
    return { health: "degraded", reasons, deliveryProven, acceptedMailIsDelivery: false, diskLevel };
  }
  return { health: "healthy", reasons: [], deliveryProven, acceptedMailIsDelivery: false, diskLevel };
}

export function applyProbeResult(
  current: { consecutiveFailures: number; consecutiveSuccesses: number; open: boolean },
  result: "pass" | "fail",
): { consecutiveFailures: number; consecutiveSuccesses: number; open: boolean; notify: "incident" | "recovery" | null } {
  if (result === "fail") {
    const consecutiveFailures = current.consecutiveFailures + 1;
    const open = current.open || consecutiveFailures >= 2;
    return {
      consecutiveFailures,
      consecutiveSuccesses: 0,
      open,
      notify: !current.open && open ? "incident" : null,
    };
  }
  const consecutiveSuccesses = current.consecutiveSuccesses + 1;
  const close = current.open && consecutiveSuccesses >= 3;
  return {
    consecutiveFailures: 0,
    consecutiveSuccesses,
    open: current.open && !close,
    notify: close ? "recovery" : null,
  };
}

export type RetryDecision = {
  action: "retry" | "reconcile_only" | "stop";
  delayMs: number;
  reconcile: boolean;
  code: "RETRY" | "RECONCILE" | "AUTH_REJECTED" | "ATTEMPTS_EXHAUSTED";
};

export function nextRetry(input: {
  status: number | null;
  retryAfterMs: number | null;
  attempt: number;
  accepted: boolean;
  random?: number;
}): RetryDecision {
  const status = input.status;
  if (status === 401 || status === 403) {
    return { action: "stop", delayMs: 0, reconcile: false, code: "AUTH_REJECTED" };
  }
  const transient = status == null || status === 429 || (status >= 500 && status <= 599);
  if (!transient) {
    return { action: "stop", delayMs: 0, reconcile: input.accepted, code: input.accepted ? "RECONCILE" : "ATTEMPTS_EXHAUSTED" };
  }
  if (input.attempt >= 8) {
    return { action: "stop", delayMs: 0, reconcile: input.accepted, code: "ATTEMPTS_EXHAUSTED" };
  }
  const random = input.random ?? 0.5;
  const span = Math.min(300_000, 5_000 * 2 ** (input.attempt - 1));
  const jitter = 0.8 + Math.min(1, Math.max(0, random)) * 0.4;
  const computed = Math.round(span * jitter);
  const delayMs = input.retryAfterMs != null && input.retryAfterMs > 0 ? Math.min(300_000, input.retryAfterMs) : computed;
  return { action: "retry", delayMs, reconcile: input.accepted, code: input.accepted ? "RECONCILE" : "RETRY" };
}

export function humanWaitUsesModel(): false {
  return false;
}

export function restartAllowed(input: { incidentRestarts: number; restarts24h: number }): boolean {
  return input.incidentRestarts < AGENT_LIMITS.restartPerIncident && input.restarts24h < AGENT_LIMITS.restartPerDay;
}

export function restrictiveSecurity(databaseDesired: "running" | "suspended", hostObserved: "running" | "suspended"): "running" | "suspended" {
  if (databaseDesired === "suspended" || hostObserved === "suspended") return "suspended";
  return "running";
}

export function watchdogThaw(input: { frozenAtMs: number; nowMs: number; thawAck: boolean; journalWritable: boolean }): {
  thaw: boolean;
  waitedForJournal: false;
  reason: string;
} {
  if (input.thawAck) return { thaw: false, waitedForJournal: false, reason: "already_thawed" };
  if (input.nowMs - input.frozenAtMs >= AGENT_LIMITS.watchdogMs) {
    return { thaw: true, waitedForJournal: false, reason: "watchdog_deadline" };
  }
  return { thaw: false, waitedForJournal: false, reason: "within_deadline" };
}

export type RecoveryPosture = {
  mode: "recovery";
  mutationsPaused: true;
  dispatcherPaused: true;
  hostCommandsPaused: true;
  agentRequestsPaused: true;
  scheduledDeletionPaused: true;
  replayObsoleteMutations: false;
  allocateFromStaleAvailable: false;
  localMailPolicy: "unchanged";
};

export function recoveryPosture(): RecoveryPosture {
  return {
    mode: "recovery",
    mutationsPaused: true,
    dispatcherPaused: true,
    hostCommandsPaused: true,
    agentRequestsPaused: true,
    scheduledDeletionPaused: true,
    replayObsoleteMutations: false,
    allocateFromStaleAvailable: false,
    localMailPolicy: "unchanged",
  };
}

export function recordUsage(reported: number | null | undefined): { tokens: number | null; provenance: "reported" | "unknown" } {
  if (typeof reported === "number" && Number.isInteger(reported) && reported >= 0) {
    return { tokens: reported, provenance: "reported" };
  }
  return { tokens: null, provenance: "unknown" };
}

export function approvalUsable(input: {
  decision: "approve" | "reject" | "pending" | "invalidated" | "expired";
  planHash: string;
  generation: number;
  resourceId: string;
  dnsFingerprint: string;
  expiresAtMs: number;
  inFlight: boolean;
  nowMs: number;
  current: { planHash: string; generation: number; resourceId: string; dnsFingerprint: string };
}): { usable: boolean; reason: string } {
  if (input.current.planHash !== input.planHash || input.current.generation !== input.generation || input.current.resourceId !== input.resourceId || input.current.dnsFingerprint !== input.dnsFingerprint) {
    return { usable: false, reason: "invalidated" };
  }
  if (input.decision !== "approve") return { usable: false, reason: input.decision };
  if (input.nowMs > input.expiresAtMs && !input.inFlight) return { usable: false, reason: "expired" };
  return { usable: true, reason: "approved" };
}

export function budgetExhausted(input: { elapsedMs: number; toolRequests: number; invocations: number }): { exhausted: boolean; reason: string | null } {
  if (input.elapsedMs > AGENT_LIMITS.maxElapsedMs) return { exhausted: true, reason: "elapsed" };
  if (input.toolRequests >= AGENT_LIMITS.maxToolRequests) return { exhausted: true, reason: "tool_requests" };
  if (input.invocations > AGENT_LIMITS.maxInvocationsPerCheckpoint) return { exhausted: true, reason: "invocations" };
  return { exhausted: false, reason: null };
}
