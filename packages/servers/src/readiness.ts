export const BETA_PROFILE = "e2-micro";
export const MIN_MEMORY_MB = 1024;
export const MIN_DISK_GB = 20;
export const HEARTBEAT_MAX_AGE_MS = 3 * 60 * 1000;

export type HostReport = {
  os: string;
  init: string;
  architecture: string;
  memoryMb: number;
  diskGb: number;
  dataPathMounted: boolean;
  reachable: boolean;
  relayReachable: boolean;
  priorTenantData: boolean;
  supervisorVersion: string;
};

/**
 * Firewall attestation is not an input. Reachability comes only from the host report.
 * An applying bearmail-install creates /var/lib/stalwart. A missing mount is not a validation failure.
 */
export function readinessFailures(input: {
  profileCode: string;
  identityConfirmed: boolean;
  lastHeartbeatAt: Date | null;
  report: HostReport | null;
  now?: Date;
}): string[] {
  const now = input.now ?? new Date();
  const failures: string[] = [];
  if (!input.identityConfirmed) failures.push("server.fingerprint_unconfirmed");
  if (!input.report || !input.lastHeartbeatAt) {
    failures.push("server.readiness_missing");
  } else if (now.getTime() - input.lastHeartbeatAt.getTime() >= HEARTBEAT_MAX_AGE_MS) {
    failures.push("server.heartbeat_stale");
  }
  const profileMismatch = input.profileCode !== BETA_PROFILE;
  const capacityMismatch = Boolean(
    input.report &&
      (input.report.os !== "linux" ||
        input.report.init !== "systemd" ||
        (input.report.architecture !== "x64" && input.report.architecture !== "arm64") ||
        input.report.memoryMb < MIN_MEMORY_MB ||
        input.report.diskGb < MIN_DISK_GB),
  );
  if (profileMismatch || capacityMismatch) failures.push("server.incompatible_profile");
  if (input.report?.priorTenantData === true && !failures.includes("server.readiness_missing")) {
    failures.push("server.readiness_missing");
  }
  if (input.report && input.report.reachable !== true) failures.push("server.unreachable");
  if (input.report && input.report.relayReachable !== true) failures.push("server.relay_unreachable");
  return failures;
}
