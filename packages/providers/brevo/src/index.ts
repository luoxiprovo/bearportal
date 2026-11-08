export type BrevoDnsRecord = {
  purpose: "brevo_code" | "dkim" | "dmarc";
  type: "TXT";
  host: string;
  value: string;
};

export type BrevoDomainResult = {
  domain: string;
  authenticated: boolean;
  records: BrevoDnsRecord[];
};

export interface BrevoClient {
  createDomain(domain: string): Promise<BrevoDomainResult>;
  authenticate(domain: string): Promise<{ authenticated: boolean; verified?: boolean }>;
}

/** Used until a live Brevo account is configured. It never reports a domain authenticated. */
export function fakeBrevoClient(): BrevoClient & { created: string[] } {
  const created: string[] = [];
  return {
    created,
    async createDomain(domain: string): Promise<BrevoDomainResult> {
      created.push(domain);
      return {
        domain,
        authenticated: false,
        records: [
          { purpose: "brevo_code", type: "TXT", host: "@", value: `brevo-code:fake-${domain}` },
          { purpose: "dkim", type: "TXT", host: "mail._domainkey", value: "k=rsa;p=fake" },
          { purpose: "dmarc", type: "TXT", host: "_dmarc", value: "v=DMARC1; p=none" },
        ],
      };
    },
    async authenticate(): Promise<{ authenticated: boolean; verified?: boolean }> {
      return { authenticated: false, verified: false };
    },
  };
}

export function liveBrevoClient(): BrevoClient {
  return {
    async createDomain(): Promise<BrevoDomainResult> {
      throw new Error("Live Brevo domain creation is not configured.");
    },
    async authenticate(): Promise<{ authenticated: boolean }> {
      throw new Error("Live Brevo authentication is not configured.");
    },
  };
}

export class BrevoRequestError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "BrevoRequestError";
  }
}

/** Flags are true only when Brevo's domain GET says so. The SMTP key is not sent. */
export type BrevoPublishRecord = {
  type: "TXT" | "CNAME";
  host: string;
  value: string;
};

export type BrevoDomainCheck = {
  domain: string;
  authenticated: boolean;
  verified: boolean;
  records: BrevoDnsRecord[];
  publishRecords?: BrevoPublishRecord[];
};

export type OperatorBrevo = {
  requestDomain(apiKey: string, domain: string): Promise<BrevoDomainCheck>;
  authenticateDomain?(apiKey: string, domain: string): Promise<BrevoDomainCheck>;
};

export type BrevoTransport = (input: {
  method: "POST" | "PUT" | "GET";
  path: string;
  apiKey: string;
  body?: string;
}) => Promise<{ status: number; body: string }>;

const BREVO_ORIGIN = "https://api.brevo.com";

export async function requestBrevoDomain(
  apiKey: string,
  domain: string,
  transport: BrevoTransport = liveBrevoTransport,
): Promise<BrevoDomainCheck> {
  const created = await brevoCall(transport, {
    method: "POST",
    path: "/v3/senders/domains",
    apiKey,
    body: JSON.stringify({ name: domain }),
  });
  rejectBrevoKey(created.status);
  if (created.status !== 200 && created.status !== 201 && !domainAlreadyPresent(created.status, created.body)) {
    throw new BrevoRequestError("Brevo did not accept the domain.");
  }
  return readBrevoDomain(apiKey, domain, transport, created.body);
}

/** Ask Brevo to authenticate a domain after its verification records are published. Flags come from the following GET. */
export async function authenticateBrevoDomain(
  apiKey: string,
  domain: string,
  transport: BrevoTransport = liveBrevoTransport,
): Promise<BrevoDomainCheck> {
  const authenticated = await brevoCall(transport, {
    method: "PUT",
    path: `/v3/senders/domains/${encodeURIComponent(domain)}/authenticate`,
    apiKey,
  });
  rejectBrevoKey(authenticated.status);
  return readBrevoDomain(apiKey, domain, transport, authenticated.body);
}

async function readBrevoDomain(
  apiKey: string,
  domain: string,
  transport: BrevoTransport,
  earlierBody: string,
): Promise<BrevoDomainCheck> {
  const read = await brevoCall(transport, {
    method: "GET",
    path: `/v3/senders/domains/${encodeURIComponent(domain)}`,
    apiKey,
  });
  rejectBrevoKey(read.status);
  if (read.status !== 200) throw new BrevoRequestError("Brevo could not verify the domain.");
  const payload = readJson(read.body);
  const flags = payload && typeof payload === "object" ? payload as Record<string, unknown> : {};
  let records = mapBrevoRecords(payload, apiKey);
  if (records.length === 0) records = mapBrevoRecords(readJson(earlierBody), apiKey);
  let publishRecords = mapBrevoPublishRecords(payload, apiKey);
  if (publishRecords.length === 0) publishRecords = mapBrevoPublishRecords(readJson(earlierBody), apiKey);
  return {
    domain,
    authenticated: flags.authenticated === true,
    verified: flags.verified === true,
    records,
    publishRecords,
  };
}

async function brevoCall(
  transport: BrevoTransport,
  input: { method: "POST" | "PUT" | "GET"; path: string; apiKey: string; body?: string },
): Promise<{ status: number; body: string }> {
  try {
    return await transport(input);
  } catch (error) {
    if (error instanceof BrevoRequestError) throw error;
    throw new BrevoRequestError("Brevo could not be reached.");
  }
}

function rejectBrevoKey(status: number): void {
  if (status === 401 || status === 403) throw new BrevoRequestError("Brevo rejected the API key.");
}

/** Brevo reports an existing domain as 400, 409, or 404 with code duplicate_parameter. */
function domainAlreadyPresent(status: number, body: string): boolean {
  if (status === 400 || status === 409) return true;
  if (status !== 404) return false;
  const parsed = readJson(body);
  return Boolean(parsed && typeof parsed === "object" && (parsed as { code?: unknown }).code === "duplicate_parameter");
}

async function liveBrevoTransport(input: {
  method: "POST" | "PUT" | "GET";
  path: string;
  apiKey: string;
  body?: string;
}): Promise<{ status: number; body: string }> {
  if (!input.path.startsWith("/v3/senders/domains")) throw new BrevoRequestError("Brevo could not be reached.");
  const url = new URL(input.path, BREVO_ORIGIN);
  if (url.origin !== BREVO_ORIGIN) throw new BrevoRequestError("Brevo could not be reached.");
  try {
    const response = await fetch(url, {
      method: input.method,
      redirect: "error",
      signal: AbortSignal.timeout(20_000),
      headers: {
        "api-key": input.apiKey,
        accept: "application/json",
        ...(input.body ? { "content-type": "application/json" } : {}),
      },
      body: input.body,
    });
    const text = await response.text();
    return { status: response.status, body: text.slice(0, 200_000) };
  } catch (error) {
    if (error instanceof BrevoRequestError) throw error;
    throw new BrevoRequestError("Brevo could not be reached.");
  }
}

export function mapBrevoPublishRecords(payload: unknown, apiKey: string): BrevoPublishRecord[] {
  if (!payload || typeof payload !== "object") return [];
  const dns = (payload as Record<string, unknown>).dns_records;
  if (!dns || typeof dns !== "object" || Array.isArray(dns)) return [];
  const records = dns as Record<string, unknown>;
  const mapped: BrevoPublishRecord[] = [];
  for (const key of ["brevo_code", "dmarc_record", "dmarc", "dkim_record", "dkim", "dkim1Record", "dkim2Record"]) {
    const raw = records[key];
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) continue;
    const record = raw as Record<string, unknown>;
    const type = String(record.type ?? "").toUpperCase();
    if (type !== "TXT" && type !== "CNAME") continue;
    const value = typeof record.value === "string" ? record.value.trim() : "";
    if (!value || value.length > 4000) continue;
    if (apiKey.length >= 8 && value.includes(apiKey)) continue;
    const hostName = typeof record.host_name === "string"
      ? record.host_name
      : typeof record.host === "string"
        ? record.host
        : "";
    const host = normalizedBrevoHost(hostName, key === "brevo_code" && type === "TXT");
    if (host.length > 253 || /\s/.test(host)) continue;
    if (mapped.some((item) => item.type === type && item.host === host && item.value === value)) continue;
    mapped.push({ type, host, value });
  }
  return mapped;
}

/** Brevo can return NA as the apex placeholder for its ownership-code TXT. */
function normalizedBrevoHost(hostName: string, ownershipCode: boolean): string {
  const host=hostName.trim().replace(/\.$/, "");
  if(!host || (ownershipCode && host.toUpperCase()==="NA")) return "@";
  return host;
}

function readJson(body: string): unknown {
  if (!body.trim()) return {};
  try {
    return JSON.parse(body) as unknown;
  } catch {
    return {};
  }
}

function mapBrevoRecords(payload: unknown, apiKey: string): BrevoDnsRecord[] {
  if (!payload || typeof payload !== "object") return [];
  const root = payload as Record<string, unknown>;
  const dns = root.dns_records;
  if (!dns || typeof dns !== "object" || Array.isArray(dns)) return [];
  const records = dns as Record<string, unknown>;
  const specs: Array<["brevo_code" | "dkim" | "dmarc", string[]]> = [
    ["brevo_code", ["brevo_code"]],
    ["dkim", ["dkim_record", "dkim"]],
    ["dmarc", ["dmarc_record", "dmarc"]],
  ];
  const mapped: BrevoDnsRecord[] = [];
  for (const [purpose, keys] of specs) {
    const raw = keys.map((key) => records[key]).find((value) => value && typeof value === "object" && !Array.isArray(value));
    if (!raw || typeof raw !== "object") continue;
    const record = raw as Record<string, unknown>;
    if (String(record.type ?? "").toUpperCase() !== "TXT") continue;
    const value = typeof record.value === "string" ? record.value.trim() : "";
    if (!value || value.length > 4000) continue;
    if (apiKey.length >= 8 && value.includes(apiKey)) continue;
    const hostName = typeof record.host_name === "string"
      ? record.host_name
      : typeof record.host === "string"
        ? record.host
        : "";
    const host = normalizedBrevoHost(hostName, purpose === "brevo_code");
    if (host.length > 253 || /\s/.test(host)) continue;
    mapped.push({ purpose, type: "TXT", host, value });
  }
  return mapped;
}

export type RelayCheckRequest = { relayId: string; smtpLogin: string };
export type RelayCheckResult = { ok: true } | { ok: false; code: "relay.activation_required" };

export interface RelayChecker {
  check(input: RelayCheckRequest): Promise<RelayCheckResult>;
}

/** Production default. Activation stays a required action until a real relay check exists. */
export function unavailableRelayChecker(): RelayChecker {
  return {
    async check(): Promise<RelayCheckResult> {
      return { ok: false, code: "relay.activation_required" };
    },
  };
}
