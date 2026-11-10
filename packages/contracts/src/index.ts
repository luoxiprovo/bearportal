import { z } from "zod";

/**
 * bearmail-install comes from the latest commit on this GitHub ref.
 * BearPortal does not pin an installer commit. During install it downloads
 * install.sh, stalwart, bearmail-webui.tar.gz, and mcp_install.sh for that
 * same commit and writes SHA256SUMS. It does not wait for /var/lib/bearportal/releases.
 */
export const BEARMAIL_PIN = {
  repository: "luoxiprovo/bearmail",
  ref: "refs/heads/main",
  installerPath: "bearmail-install",
  installerDoc: "docs/BEARPORTAL_INSTALL.md",
  dataPath: "/var/lib/stalwart",
} as const;

/**
 * Capabilities BearPortal still cannot claim. These are recorded gaps, not successful integrations.
 * The management HTTP API was not exercised against a running engine in this workspace.
 */
export const BLOCKING_GAPS = [
  {
    id: "engine-management-unverified",
    detail: "JMAP and admin routes for mailbox create, quota, and credential set are not verified against a running BearMail engine.",
  },
  {
    id: "live-provider-unverified",
    detail: "Name.com, Hostinger, GoDaddy, and Brevo have not been called with live credentials from this control plane.",
  },
  {
    id: "installer-suite-not-run-here",
    detail: "BearMail's installer tests were read on GitHub and were not executed in this workspace.",
  },
  {
    id: "grok-live-unverified",
    detail: "HarnessAgent is constructed locally with allow-all. Live xAI generation and a staging operation worker were not run.",
  },
] as const;

export const dnsProviderSchema = z.enum(["namecom", "hostinger", "godaddy"]);

export const namecomCredentialSchema = z.object({ username: z.string().min(1), token: z.string().min(1) }).strict();
export const hostingerCredentialSchema = z.object({ token: z.string().min(1) }).strict();
export const godaddyCredentialSchema = z.object({ token: z.string().min(1).max(4000) }).strict();

export const dnsCredentialSchema = z.discriminatedUnion("provider", [
  z.object({ provider: z.literal("namecom"), credentials: namecomCredentialSchema }).strict(),
  z.object({ provider: z.literal("hostinger"), credentials: hostingerCredentialSchema }).strict(),
  z.object({ provider: z.literal("godaddy"), credentials: godaddyCredentialSchema }).strict(),
]);

const recordSchema = z.object({
  purpose: z.enum(["brevo_code", "dkim", "dmarc"]),
  type: z.literal("TXT"),
  host: z.string().min(1),
  value: z.string().min(1),
}).strict();

/** Input bearmail-install accepts. Secrets stay in separate files. */
export const installerInputSchema = z.object({
  schemaVersion: z.literal(1),
  operationId: z.string().uuid(),
  deploymentId: z.string().uuid(),
  generation: z.number().int().positive(),
  mxCutoverAuthorized: z.literal(true),
  domain: z.string().min(1),
  mailHostname: z.string().min(1),
  webmailHostname: z.string().min(1),
  publicIpv4: z.string().min(1),
  publicIpv6: z.string().nullable(),
  dataPath: z.literal("/var/lib/stalwart"),
  dns: z.object({
    provider: dnsProviderSchema,
    zone: z.string().min(1),
    credentialFile: z.string().min(1),
  }).strict(),
  brevoDnsRecords: z.union([
    z.array(recordSchema).length(0),
    z.array(recordSchema).length(3),
  ]).optional(),
  relay: z.object({
    host: z.literal("smtp-relay.brevo.com"),
    port: z.literal(587),
    tls: z.literal("starttls-required"),
    login: z.string().min(1),
    credentialFile: z.string().min(1),
  }).strict(),
  adminCredentialFile: z.string().min(1),
  mailboxQuotaBytes: z.number().int().positive(),
  release: z.object({
    id: z.string().min(1),
    artifactDir: z.string().min(1),
    checksumFile: z.string().min(1),
  }).strict(),
}).strict();

export const errorBodySchema = z.object({
  error: z.object({
    code: z.string(),
    message: z.string(),
    retryable: z.boolean(),
    requiredActionId: z.string().nullable(),
  }).strict(),
  requestId: z.string(),
}).strict();

export const organizationCreateSchema = z.object({
  name: z.string().min(1).max(120),
  invitationToken: z.string().min(20),
}).strict();

export const domainCreateSchema = z.object({
  domain: z.string().min(1),
  existingMail: z.boolean(),
}).strict();

const dnsCredentialValueSchema = z.union([
  namecomCredentialSchema,
  hostingerCredentialSchema,
  godaddyCredentialSchema,
]);

export const dnsConnectionCreateSchema = z.object({
  domainId: z.string().uuid(),
  provider: dnsProviderSchema,
  zoneId: z.string().min(1),
  credentials: dnsCredentialValueSchema,
}).strict();

export const dnsConnectionRotateSchema = z.object({
  credentials: dnsCredentialValueSchema,
  expectedVersion: z.number().int(),
}).strict();

export const invitationCreateSchema = z.object({
  boundEmail: z.string().email(),
  expiresInHours: z.number().int().min(1).max(168).default(72),
}).strict();

export const operatorRoleGrantSchema = z.object({
  userId: z.string().uuid(),
  role: z.enum(["support", "infrastructure_operator", "platform_administrator"]),
  reason: z.string().min(3),
}).strict();

export const emptyObjectSchema = z.object({}).strict();

export const preparationAttestationsSchema = z.object({
  osPrepared: z.literal(true),
  storagePrepared: z.literal(true),
  firewallAttested: z.literal(true),
  cleanHost: z.literal(true),
  externalBackup: z.literal(true),
}).strict();

export const serverCreateSchema = z.object({
  label: z.string().min(1).max(120).optional(),
  publicIpv4: z.string().min(7).max(15),
  profileCode: z.string().min(1).max(64),
  operatorContact: z.string().trim().min(3).max(200).optional(),
  providerReference: z.string().min(1).max(200).optional(),
  preparationAttestations: preparationAttestationsSchema,
}).strict();

export const confirmIdentitySchema = z.object({
  fingerprint: z.string().regex(/^[0-9a-f]{64}$/),
  expectedVersion: z.number().int().positive(),
}).strict();

export const versionedSchema = z.object({
  expectedVersion: z.number().int().positive(),
}).strict();

export const quarantineSchema = z.object({
  reason: z.string().min(3).max(500),
  expectedVersion: z.number().int().positive(),
}).strict();

export const ipChangeSchema = z.object({
  publicIpv4: z.string().min(7).max(15),
  reason: z.string().min(3).max(500),
  expectedVersion: z.number().int().positive(),
}).strict();

export const releaseReservationSchema = z.object({
  expectedVersion: z.number().int().positive(),
  cancellationProof: z.literal(true),
}).strict();

export const recoveryBindingSchema = z.object({
  organizationId: z.string().uuid(),
  expectedVersion: z.number().int().positive(),
}).strict();

export const hostCommandSchema = z.object({
  commandType: z.string().min(1).max(64),
  expectedEpoch: z.number().int().positive(),
  parameters: z.unknown().optional(),
}).strict();

export const hostReportSchema = z.object({
  os: z.literal("linux"),
  init: z.literal("systemd"),
  architecture: z.enum(["x64", "arm64"]),
  memoryMb: z.number().int().positive(),
  diskGb: z.number().int().positive(),
  dataPathMounted: z.boolean(),
  reachable: z.boolean(),
  relayReachable: z.boolean(),
  priorTenantData: z.boolean(),
  supervisorVersion: z.string().min(1).max(80),
}).strict();

export const heartbeatSchema = z.object({
  serverId: z.string().uuid(),
  publicKey: z.string().min(40).max(88),
  authEpoch: z.number().int().positive(),
  observedAt: z.string().datetime(),
  signature: z.string().min(80).max(200),
  readiness: hostReportSchema,
}).strict();

export const hostEnrollSchema = z.object({
  serverId: z.string().uuid(),
  token: z.string().min(20),
  publicKey: z.string().min(40).max(88),
}).strict();

export const relayConnectionCreateSchema = z.object({
  label: z.string().min(1).max(120).optional(),
  loginEmail: z.string().email(),
  apiKey: z.string().min(1).max(400),
  smtpLogin: z.string().min(1).max(200),
  smtpKey: z.string().min(1).max(400),
  dailyLimit: z.number().int().positive().max(100000),
}).strict();

export const assignPlanSchema = z.object({
  planCode: z.string().min(1).max(64),
  planRevision: z.number().int().positive(),
  reason: z.string().min(3).max(500),
  expectedVersion: z.number().int().positive(),
}).strict();

export const assignRelaySchema = z.object({
  relayConnectionId: z.string().uuid(),
  expectedVersion: z.number().int().positive(),
}).strict();

export const cancelOnboardingSchema = z.object({
  reason: z.string().min(1).max(500).optional(),
  expectedVersion: z.number().int().positive(),
}).strict();

export const deploymentCreateSchema = z.object({
  domainId: z.string().uuid(),
  firstMailboxLocalPart: z.string().min(1).max(64),
  testMailConsent: z.literal(true),
}).strict();

export const mailboxCreateSchema = z.object({
  localPart: z.string().min(1).max(64),
  quotaBytes: z.number().int().positive().optional(),
}).strict();

export const mailboxPatchSchema = z.object({
  loginEnabled: z.boolean().optional(),
  sendEnabled: z.boolean().optional(),
  receiveEnabled: z.boolean().optional(),
  quotaBytes: z.number().int().positive().optional(),
  expectedVersion: z.number().int().positive(),
}).strict();

export const mailboxCredentialSchema = z.object({
  newPassword: z.string().min(12).max(200),
}).strict();

export const backupReportSchema = z.object({
  evidenceRef: z.string().min(3).max(200),
  expectedVersion: z.number().int().positive(),
  outcome: z.enum(["reported_complete", "reported_failed", "restore_verified"]).optional(),
  consistency: z.enum(["consistent", "failed", "unknown"]).optional(),
  releaseId: z.string().min(1).max(80).optional(),
  schemaVersion: z.string().min(1).max(40).optional(),
  startedAt: z.string().datetime({ offset: true }).optional(),
  completedAt: z.string().datetime({ offset: true }).optional(),
  expiresAt: z.string().datetime({ offset: true }).optional(),
  restoreAttestation: z.string().min(8).max(500).optional(),
}).strict();

export const serverBackupSchema = backupReportSchema.extend({
  deploymentId: z.string().uuid(),
}).strict();

export const restoreRequestSchema = z.object({
  backupId: z.string().uuid(),
  acknowledgePotentialDataLoss: z.literal(true),
  expectedVersion: z.number().int().positive(),
}).strict();

export const cancellationPlanSchema = z.object({
  reason: z.string().min(1).max(500).optional(),
  expectedVersion: z.number().int().positive(),
}).strict();

export const cancellationWaiverSchema = z.object({
  expectedVersion: z.number().int().positive(),
  acknowledgeNoFinalBackup: z.literal(true),
}).strict();

export const cancellationExecuteSchema = z.object({
  scheduleId: z.string().uuid(),
}).strict();

export const replacementPlanSchema = z.object({
  replacementServerId: z.string().uuid(),
  backupId: z.string().uuid().optional(),
  reason: z.string().min(1).max(500),
  expectedVersion: z.number().int().positive(),
}).strict();

export const restoreReadySchema = z.object({
  backupId: z.string().uuid(),
  fencing: z.enum(["application_stop", "external_isolation", "missing_heartbeat"]),
  evidenceRef: z.string().min(3).max(200),
  expectedVersion: z.number().int().positive(),
}).strict();

export const upgradePlanSchema = z.object({
  releaseId: z.string().min(1).max(80),
  compatible: z.boolean(),
  irreversible: z.boolean(),
  newMailAccepted: z.boolean(),
  checksFailed: z.boolean(),
  preUpgradeBackupId: z.string().uuid().optional(),
  expectedVersion: z.number().int().positive(),
}).strict();

export const isolationReportSchema = z.object({
  expectedVersion: z.number().int().positive(),
  evidenceRef: z.string().min(3).max(200),
  externallyIsolated: z.literal(true),
}).strict();

export const cleanupReportSchema = z.object({
  expectedVersion: z.number().int().positive(),
  outcome: z.enum(["deleted", "reimaged"]),
  dataRemovedAt: z.string().datetime({ offset: true }),
  backupRetentionSatisfied: z.boolean(),
  credentialsRevoked: z.boolean(),
  evidenceRef: z.string().min(3).max(200),
  operatorAttestation: z.string().min(8).max(500),
}).strict();

export const oversightToolSchema = z.object({
  arguments: z.object({}).passthrough(),
  version: z.string().min(1).max(40).optional(),
  claimedDigest: z.string().regex(/^[0-9a-f]{64}$/).optional(),
}).strict();

export const approvalDecisionSchema = z.object({
  decision: z.enum(["approve", "reject"]),
  planHash: z.string().regex(/^[0-9a-f]{64}$/),
  expectedVersion: z.number().int().positive(),
}).strict();

export const adminOperationSchema = z.object({
  kind: z.enum(["diagnose", "reconcile_ip", "upgrade", "restore", "suspend", "resume", "cancel_service"]),
  parameters: z.object({}).passthrough().optional(),
  expectedVersion: z.number().int().positive(),
}).strict();

export const hostingEstimateSchema = z.object({
  amountMinor: z.number().int().nonnegative(),
  currency: z.string().regex(/^[A-Z]{3}$/),
  expectedVersion: z.number().int().positive(),
}).strict();

export const healthObserveSchema = z.object({
  deploymentId: z.string().uuid(),
  probe: z.enum(["heartbeat", "reachability", "https", "jmap", "imaps", "smtp", "engine", "relay", "certificate", "delivery", "backup", "disk"]),
  state: z.enum(["pass", "fail", "partial", "absent"]),
  observedAt: z.string().datetime(),
  diskPercent: z.number().int().min(0).max(100).optional(),
}).strict();

export const providerFaultSchema = z.object({
  organizationId: z.string().uuid(),
  operationKey: z.string().min(1).max(80),
  status: z.number().int().min(0).max(599).nullable(),
  accepted: z.boolean(),
  retryAfterMs: z.number().int().nonnegative().max(300_000).nullable(),
  attempt: z.number().int().positive().max(20),
}).strict();

export const recoveryEnterSchema = z.object({
  reason: z.string().min(1).max(200),
}).strict();

export const watchdogSchema = z.object({
  frozenAt: z.string().datetime(),
  thawAck: z.boolean(),
  journalWritable: z.boolean(),
}).strict();

export const stepCompleteSchema = z.object({
  stepId: z.string().regex(/^[0-9a-f]{64}$/),
  claimedDigest: z.string().regex(/^[0-9a-f]{64}$/).optional(),
}).strict();

export const usageReportSchema = z.object({
  tokens: z.number().int().nonnegative().nullable(),
}).strict();

/** Operator inventory edits never accept owner, state, taint or credential-reference overrides. */
export const serverInventoryPatchSchema = z.object({
  expectedVersion: z.number().int().positive(),
  label: z.string().trim().min(1).max(120).optional(),
  operatorContact: z.string().trim().min(3).max(200).nullable().optional(),
  providerReference: z.string().trim().min(1).max(200).nullable().optional(),
  publicIpv4: z.string().min(7).max(15).optional(),
}).strict().refine(value => Object.keys(value).length > 1, "Include a field to update.");

export const relayInventoryPatchSchema = z.object({
  expectedVersion: z.number().int().positive(),
  label: z.string().trim().min(1).max(120).optional(),
  loginEmail: z.string().trim().email().optional(),
  smtpLogin: z.string().trim().min(1).max(200).optional(),
  dailyLimit: z.number().int().positive().max(100000).optional(),
  apiKey: z.string().min(1).max(400).optional(),
  smtpKey: z.string().min(1).max(400).optional(),
  paused: z.boolean().optional(),
  restore: z.literal(true).optional(),
}).strict().refine(value => Object.keys(value).length > 1, "Include a field to update.");

export const inventoryRemoveSchema = z.object({
  expectedVersion: z.number().int().positive(),
  confirm: z.literal(true),
}).strict();
