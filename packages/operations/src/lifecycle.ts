/** Lifecycle decisions for operator-reported backups, restore, upgrades, and cancellation.
 * None of these functions call a cloud, DNS, mail, or model API.
 */

export const BACKUP_FRESH_MS = 26 * 60 * 60 * 1000;
export const RETENTION_MS = 7 * 24 * 60 * 60 * 1000;
export const CANCELLATION_GRACE_MS = 7 * 24 * 60 * 60 * 1000;
export const EXECUTION_WINDOW_MS = 24 * 60 * 60 * 1000;
export const APPROVAL_WINDOW_MS = 30 * 60 * 1000;

export type BackupOutcome = "reported_complete" | "reported_failed" | "restore_verified";
export type BackupConsistency = "consistent" | "failed" | "unknown";
export type FencingKind = "application_stop" | "external_isolation" | "missing_heartbeat";

export function evidenceReferenceAccepted(value: string): boolean {
  if (value.includes("://") || /[\s<>]/.test(value)) return false;
  return /^[A-Za-z0-9][A-Za-z0-9._:-]{2,199}$/.test(value);
}

export function classifyBackupReport(input: {
  outcome?: BackupOutcome;
  consistency?: BackupConsistency;
  restoreAttestation?: string;
}): { ok: true; state: "recorded" | BackupOutcome; restoreVerified: boolean } | { ok: false; code: string; message: string } {
  if (!input.outcome) return { ok: true, state: "recorded", restoreVerified: false };
  if (input.outcome === "restore_verified") {
    if (!input.restoreAttestation || input.restoreAttestation.trim().length < 8) {
      return {
        ok: false,
        code: "RESTORE_UNVERIFIED",
        message: "A backup reference is not restore verification. Operator attestation is required, and it is still not a cloud check.",
      };
    }
    return { ok: true, state: "restore_verified", restoreVerified: true };
  }
  if (input.outcome === "reported_complete" && input.consistency !== "consistent") {
    return { ok: false, code: "CONSISTENCY_REQUIRED", message: "A complete backup report needs operator consistency evidence." };
  }
  if (input.outcome === "reported_failed") return { ok: true, state: "reported_failed", restoreVerified: false };
  return { ok: true, state: "reported_complete", restoreVerified: false };
}

export function backupFreshness(completedAt: Date | string | null | undefined, nowMs: number): "fresh" | "stale" | "missing" {
  if (!completedAt) return "missing";
  const time = completedAt instanceof Date ? completedAt.getTime() : Date.parse(completedAt);
  if (!Number.isFinite(time)) return "missing";
  return nowMs - time > BACKUP_FRESH_MS ? "stale" : "fresh";
}

export function cancellationSchedule(nowMs: number): { executeAt: Date; windowEndsAt: Date; approvalExpiresAt: Date } {
  const executeAt = new Date(nowMs + CANCELLATION_GRACE_MS);
  return {
    executeAt,
    windowEndsAt: new Date(executeAt.getTime() + EXECUTION_WINDOW_MS),
    approvalExpiresAt: new Date(nowMs + APPROVAL_WINDOW_MS),
  };
}

export function cancellationTiming(input: {
  nowMs: number;
  executeAt: Date;
  windowEndsAt: Date;
  state: string;
}): "early" | "due" | "stale" | "closed" {
  if (input.state === "revoked" || input.state === "stopped" || input.state === "completed") return "closed";
  if (input.nowMs < input.executeAt.getTime()) return "early";
  if (input.nowMs > input.windowEndsAt.getTime()) return "stale";
  return "due";
}

export function fencingAllowsPromotion(kind: FencingKind): boolean {
  return kind === "application_stop" || kind === "external_isolation";
}

export function upgradePolicy(input: {
  compatible: boolean;
  irreversible: boolean;
  newMailAccepted: boolean;
  checksFailed: boolean;
  freshBackup: boolean;
}): {
  state: "blocked" | "preserve_required" | "rollback_required" | "pending";
  rollbackPolicy: "blocked" | "preserve_new_mail" | "binary_rollback";
  dataRollback: false;
  binariesExecuted: false;
  executed: false;
} {
  const fixed = { dataRollback: false as const, binariesExecuted: false as const, executed: false as const };
  if (!input.freshBackup) return { ...fixed, state: "blocked", rollbackPolicy: "blocked" };
  if (!input.compatible || input.irreversible || input.newMailAccepted) {
    return { ...fixed, state: "preserve_required", rollbackPolicy: "preserve_new_mail" };
  }
  if (input.checksFailed) return { ...fixed, state: "rollback_required", rollbackPolicy: "binary_rollback" };
  return { ...fixed, state: "pending", rollbackPolicy: "binary_rollback" };
}

export function cleanupDecision(input: {
  serviceStoppedAt: Date | null;
  dataRemovedAt: Date;
  nowMs: number;
  backupRetentionSatisfied: boolean;
  credentialsRevoked: boolean;
}): { ok: true } | { ok: false; code: "RETENTION_OPEN" | "SERVICE_NOT_STOPPED" } {
  if (!input.serviceStoppedAt) return { ok: false, code: "SERVICE_NOT_STOPPED" };
  if (!input.backupRetentionSatisfied || !input.credentialsRevoked) return { ok: false, code: "RETENTION_OPEN" };
  const earliest = input.serviceStoppedAt.getTime() + RETENTION_MS;
  if (input.nowMs < earliest || input.dataRemovedAt.getTime() < earliest) return { ok: false, code: "RETENTION_OPEN" };
  return { ok: true };
}
