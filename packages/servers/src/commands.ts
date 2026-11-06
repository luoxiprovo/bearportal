const INVENTORY = new Set(["probe_readiness", "probe_services", "serve_ip_proof"]);

const TENANT = new Set([
  "install_release",
  "configure_relay",
  "sync_mailboxes",
  "set_mailbox_credential",
  "read_mail_state",
  "prepare_snapshot",
  "resume_after_snapshot",
  "upgrade_release",
  "stop_mail_services",
  "resume_services",
  "rotate_admin_credential",
]);

export type ParsedCommand = {
  scope: "inventory" | "tenant";
  commandType: string;
  parameters: Record<string, unknown>;
};

/** Allowlisted host commands. Unknown types and extra fields are rejected. There is no shell command. */
export function parseCommand(type: string, parameters: unknown): ParsedCommand | null {
  const params = parameters ?? {};
  if (!params || typeof params !== "object" || Array.isArray(params)) return null;
  const record = params as Record<string, unknown>;
  const keys = Object.keys(record);
  if (type === "install_release" || type === "upgrade_release") {
    if (keys.length !== 1 || typeof record.releaseId !== "string" || record.releaseId.length < 1 || record.releaseId.length > 200) {
      return null;
    }
    return { scope: "tenant", commandType: type, parameters: { releaseId: record.releaseId } };
  }
  if (INVENTORY.has(type) || TENANT.has(type)) {
    if (keys.length !== 0) return null;
    return {
      scope: INVENTORY.has(type) ? "inventory" : "tenant",
      commandType: type,
      parameters: {},
    };
  }
  return null;
}
