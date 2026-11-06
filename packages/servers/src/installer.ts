import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { basename, join } from "node:path";

/** Beta customer mailboxes. System aliases and the test identity are outside this ceiling. */
export const BETA_CUSTOMER_MAILBOX_LIMIT = 4;
export const DEFAULT_MAILBOX_QUOTA_BYTES = 1073741824;

export const RELEASE_FILES = ["install.sh", "stalwart", "bearmail-webui.tar.gz", "mcp_install.sh"] as const;

/** A stored DNS credential is enough when BearPortal itself runs bearmail-install. */
export function installDomainBlock(input: {
  state: string;
  hasCredential: boolean;
  sourceInstall: boolean;
}): "ok" | "domain.unverified" | "dns.credential_required" {
  if (!input.hasCredential) {
    return input.state === "verified" ? "dns.credential_required" : "domain.unverified";
  }
  if (input.state !== "verified" && !input.sourceInstall) return "domain.unverified";
  return "ok";
}

/** An SSH readiness pass stands in for the older enrolled-device confirmation. */
export function sshIdentityAllowsInstall(identityState: string | null, readinessSource: string | null): boolean {
  return identityState === "confirmed" || readinessSource === "ssh";
}

const EXAMPLE_WEBMAIL = new Set([
  "webmail.example.com",
  "webmail.example.org",
  "webmail.example.net",
  "webmail.example.test",
  "bearmail.example.com",
  "bearmail.example.org",
  "bearmail.example.net",
  "bearmail.example.test",
]);

const LOCAL_PART = /^(?=.{1,64}$)[a-z0-9]+(?:[._-][a-z0-9]+)*$/;

export class MailboxNameError extends Error {
  readonly code: "VALIDATION" | "RESERVED_LOCAL_PART";

  constructor(code: "VALIDATION" | "RESERVED_LOCAL_PART", message: string) {
    super(message);
    this.name = "MailboxNameError";
    this.code = code;
  }
}

export type InstallerMode = "dry_run" | "apply";

export type InstallerRunRequest = {
  mode: InstallerMode;
  input: Record<string, unknown>;
};

export interface InstallerRunner {
  run(request: InstallerRunRequest): Promise<unknown>;
}

export class InstallerUnavailableError extends Error {
  constructor() {
    super("The BearMail installer is not configured.");
    this.name = "InstallerUnavailableError";
  }
}

/** Production default. It does not execute bearmail-install and it does not report success. */
export function unavailableInstallerRunner(): InstallerRunner {
  return {
    async run(): Promise<unknown> {
      throw new InstallerUnavailableError();
    },
  };
}

export type ObservedRecord = { name: string; type: string; value: string; priority?: number | null };

export interface DnsObserver {
  observe(domain: string): Promise<{ records: ObservedRecord[] }>;
}

export class DnsObserverUnavailableError extends Error {
  constructor() {
    super("Public DNS observation is not configured.");
    this.name = "DnsObserverUnavailableError";
  }
}

/** Production default. It does not query public DNS and it does not report a match. */
export function unavailableDnsObserver(): DnsObserver {
  return {
    async observe(): Promise<{ records: ObservedRecord[] }> {
      throw new DnsObserverUnavailableError();
    },
  };
}

export class ReleaseLayoutError extends Error {
  readonly code: "ARTIFACT_MISSING" | "ARTIFACT_CHECKSUM_MISMATCH";

  constructor(code: "ARTIFACT_MISSING" | "ARTIFACT_CHECKSUM_MISMATCH", message: string) {
    super(message);
    this.name = "ReleaseLayoutError";
    this.code = code;
  }
}

/** Customer mailbox names. Reserved system names are rejected here and inserted only by the installer flow. */
export function assertMailboxLocalPart(value: string): string {
  if (!LOCAL_PART.test(value)) {
    throw new MailboxNameError(
      "VALIDATION",
      "Use a lowercase mailbox name of letters, digits, and single internal dots, underscores, or hyphens.",
    );
  }
  if (value === "postmaster" || value === "abuse" || value.startsWith("bearportal-")) {
    throw new MailboxNameError("RESERVED_LOCAL_PART", "That mailbox name is reserved.");
  }
  return value;
}

export function customerMailboxLimit(planCode: string, planLimit: number): number {
  if (planCode === "beta") return Math.min(BETA_CUSTOMER_MAILBOX_LIMIT, planLimit);
  return planLimit;
}

export function isExampleWebmail(hostname: string): boolean {
  return EXAMPLE_WEBMAIL.has(hostname.toLowerCase());
}

/**
 * Identity of an installer desired configuration.
 * Generation is intentionally absent: a retry may increment it without becoming a new operation.
 */
export function installerFingerprint(input: {
  domain: string;
  mailHostname: string;
  webmailHostname: string;
  publicIpv4: string;
  provider: string;
  zone: string;
  brevoRecords: unknown;
  relayHost: string;
}): string {
  return createHash("sha256").update(stable({
    domain: input.domain,
    mailHostname: input.mailHostname,
    webmailHostname: input.webmailHostname,
    publicIpv4: input.publicIpv4,
    provider: input.provider,
    zone: input.zone,
    brevoRecords: input.brevoRecords,
    relayHost: input.relayHost,
  })).digest("hex");
}

/** Read the release directory. This does not execute any file in it. */
export function assertReleaseLayout(artifactDir: string, releaseId: string): void {
  if (basename(artifactDir) !== releaseId || !existsSync(artifactDir)) {
    throw new ReleaseLayoutError("ARTIFACT_MISSING", "The release directory does not match the release id.");
  }
  for (const name of RELEASE_FILES) {
    if (!existsSync(join(artifactDir, name))) {
      throw new ReleaseLayoutError("ARTIFACT_MISSING", "A required release file is absent.");
    }
  }
  const sumsPath = join(artifactDir, "SHA256SUMS");
  if (!existsSync(sumsPath)) {
    throw new ReleaseLayoutError("ARTIFACT_MISSING", "SHA256SUMS is absent.");
  }
  const sums = readFileSync(sumsPath, "utf8");
  for (const name of RELEASE_FILES) {
    const digest = createHash("sha256").update(readFileSync(join(artifactDir, name))).digest("hex");
    const matched = sums.split("\n").some((line) => {
      const match = /^([0-9a-f]{64})\s+\*?(\S+)\s*$/i.exec(line.trim());
      return Boolean(match && match[1]!.toLowerCase() === digest && match[2] === name);
    });
    if (!matched) {
      throw new ReleaseLayoutError("ARTIFACT_CHECKSUM_MISMATCH", "A release file does not match SHA256SUMS.");
    }
  }
}

export type InstallerStatus = "dry_run" | "succeeded" | "tls_pending" | "dns_partial" | "failed";

export type PublishedRecord = {
  type: string;
  host: string;
  value: string;
  state: string;
};

export type ParsedInstallerResult = {
  status: InstallerStatus;
  exitCode: number;
  retryable: boolean;
  errorCode: string | null;
  previousMx: Array<{ priority: number; target: string }>;
  published: PublishedRecord[];
  dnsWritesAccepted: boolean;
  minimumTtl: number | null;
  engineDkimHost: string | null;
  engineDkimValue: string | null;
};

/** Accept a runner result only when its status, exit, and retryable flag agree. */
export function parseInstallerResult(value: unknown): ParsedInstallerResult | null {
  if (!value || typeof value !== "object") return null;
  const row = value as Record<string, unknown>;
  const status = row.status;
  const exitCode = row.exitCode;
  const retryable = row.retryable;
  if (status !== "dry_run" && status !== "succeeded" && status !== "tls_pending" && status !== "dns_partial" && status !== "failed") {
    return null;
  }
  if (typeof exitCode !== "number" || typeof retryable !== "boolean") return null;
  if (retryable !== (exitCode === 10)) return null;
  if (status === "dry_run" && exitCode !== 0) return null;
  if (status === "succeeded" && exitCode !== 0) return null;
  if (status === "tls_pending" && exitCode !== 10) return null;
  if (status === "dns_partial" && exitCode !== 10 && exitCode !== 1) return null;
  if (status === "failed" && exitCode !== 1) return null;
  const errorCode = row.errorCode == null ? null : row.errorCode;
  if (errorCode != null && typeof errorCode !== "string") return null;
  const dns = row.dns;
  if (!dns || typeof dns !== "object") return null;
  const dnsRow = dns as Record<string, unknown>;
  const previousMx = parseMx(dnsRow.previousMx);
  const published = parsePublished(dnsRow.published);
  if (!previousMx || !published) return null;
  const minimumTtl = dnsRow.minimumTtl == null ? null : dnsRow.minimumTtl;
  if (minimumTtl != null && typeof minimumTtl !== "number") return null;
  const engineDkimHost = dnsRow.engineDkimHost == null ? null : dnsRow.engineDkimHost;
  const engineDkimValue = dnsRow.engineDkimValue == null ? null : dnsRow.engineDkimValue;
  if ((engineDkimHost != null && typeof engineDkimHost !== "string") || (engineDkimValue != null && typeof engineDkimValue !== "string")) {
    return null;
  }
  return {
    status,
    exitCode,
    retryable,
    errorCode,
    previousMx,
    published,
    dnsWritesAccepted: status === "succeeded" || status === "tls_pending",
    minimumTtl,
    engineDkimHost,
    engineDkimValue,
  };
}

/** Compare a public probe with the installer result. Apex and www are not required to move. */
export function compareDns(input: {
  domain: string;
  published: PublishedRecord[];
  observed: ObservedRecord[];
  baseline: ObservedRecord[];
}): { matches: boolean; mxMismatch: boolean; apexChanged: boolean } {
  const expectedMx = input.published.filter((record) => record.type === "MX" && record.state !== "failed");
  const mxMismatch = expectedMx.length === 0 || expectedMx.some((record) => !observedHasMx(input.observed, input.domain, record.value));
  const apexChanged = addressMoved(input.baseline, input.observed, input.domain, "A")
    || addressMoved(input.baseline, input.observed, `www.${input.domain}`, "A");
  return { matches: !mxMismatch && !apexChanged, mxMismatch, apexChanged };
}

/** Active requires installer, Brevo, backup, and live-mail evidence. Missing mail evidence stays onboarding. */
export function activationAllowed(input: {
  installerStatus: string | null;
  dnsWritesAccepted: boolean;
  brevoAuthenticated: boolean;
  brevoVerified: boolean;
  backupReported: boolean;
  mailVerified: boolean;
}): boolean {
  const installed = input.installerStatus === "succeeded" || input.installerStatus === "tls_pending";
  return installed
    && input.dnsWritesAccepted
    && input.brevoAuthenticated
    && input.brevoVerified
    && input.backupReported
    && input.mailVerified;
}

function observedHasMx(observed: ObservedRecord[], domain: string, publishedValue: string): boolean {
  const target = mxTarget(publishedValue);
  return observed.some((record) => {
    if (record.type !== "MX" || normalizeName(record.name) !== normalizeName(domain)) return false;
    const observedTarget = record.priority != null && !record.value.includes(" ")
      ? record.value
      : mxTarget(record.value);
    return normalizeName(observedTarget) === normalizeName(target);
  });
}

function addressMoved(baseline: ObservedRecord[], observed: ObservedRecord[], name: string, type: string): boolean {
  const before = baseline.find((record) => record.type === type && normalizeName(record.name) === normalizeName(name));
  const after = observed.find((record) => record.type === type && normalizeName(record.name) === normalizeName(name));
  if (!before || !after) return false;
  return before.value !== after.value;
}

function mxTarget(value: string): string {
  const match = /^\d+\s+(\S+)$/.exec(value.trim());
  return match ? match[1]! : value.trim();
}

function normalizeName(value: string): string {
  return value.trim().toLowerCase().replace(/\.$/, "");
}

function parseMx(value: unknown): Array<{ priority: number; target: string }> | null {
  if (!Array.isArray(value)) return null;
  const rows: Array<{ priority: number; target: string }> = [];
  for (const item of value) {
    if (!item || typeof item !== "object") return null;
    const row = item as Record<string, unknown>;
    if (typeof row.priority !== "number" || typeof row.target !== "string") return null;
    rows.push({ priority: row.priority, target: row.target });
  }
  return rows;
}

function parsePublished(value: unknown): PublishedRecord[] | null {
  if (!Array.isArray(value)) return null;
  const rows: PublishedRecord[] = [];
  for (const item of value) {
    if (!item || typeof item !== "object") return null;
    const row = item as Record<string, unknown>;
    if (typeof row.type !== "string" || typeof row.host !== "string" || typeof row.value !== "string" || typeof row.state !== "string") {
      return null;
    }
    rows.push({ type: row.type, host: row.host, value: row.value, state: row.state });
  }
  return rows;
}

function stable(value: unknown): string {
  return JSON.stringify(sortValue(value));
}

function sortValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortValue);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, item]) => [key, sortValue(item)]),
    );
  }
  return value;
}
