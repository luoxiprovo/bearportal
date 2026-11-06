import type { BrevoPublishRecord } from "../../brevo/src/index.ts";
import type { DetectedDnsProvider } from "./detect.ts";

export type DnsCredentialMaterial =
  | { provider: "namecom"; username: string; token: string }
  | { provider: "hostinger"; token: string }
  | { provider: "godaddy"; token: string };

export type DnsTransport = (input: {
  method: "GET" | "PUT" | "POST";
  url: string;
  headers: Record<string, string>;
  body?: string;
}) => Promise<{ status: number; body: string }>;

export type PublishBrevoResult = {
  written: number;
  unchanged: number;
};

type StoredRecord = { type: string; host: string; value: string };

/** Publish Brevo verification records with the credential bearmail-install will reuse. */
export async function publishBrevoRecords(input: {
  provider: DetectedDnsProvider;
  zone: string;
  credential: DnsCredentialMaterial;
  records: BrevoPublishRecord[];
  transport?: DnsTransport;
}): Promise<PublishBrevoResult> {
  if (input.credential.provider !== input.provider) {
    throw new Error("The DNS credential does not match the detected provider.");
  }
  if (input.records.length === 0) throw new Error("Brevo did not return records to publish.");
  const zone = input.zone.trim().toLowerCase().replace(/\.$/, "");
  const transport = input.transport ?? liveDnsTransport;
  const headers = providerHeaders(input.credential);
  const existing = await readZone(transport, input.provider, zone, headers);
  const desired = mergeRecords(existing, input.records, zone);
  const touched = changedGroups(existing, desired);
  if (touched.length === 0) return { written: 0, unchanged: input.records.length };
  await writeGroups(transport, input.provider, zone, headers, existing, desired, touched);
  return { written: touched.length, unchanged: input.records.length - touched.length };
}

function providerHeaders(credential: DnsCredentialMaterial): Record<string, string> {
  const headers = { accept: "application/json", "content-type": "application/json" };
  if (credential.provider === "namecom") {
    rejectHeaderValue(credential.username);
    rejectHeaderValue(credential.token);
    return { ...headers, authorization: `Basic ${Buffer.from(`${credential.username}:${credential.token}`).toString("base64")}` };
  }
  rejectHeaderValue(credential.token);
  return { ...headers, authorization: `Bearer ${credential.token}` };
}

function rejectHeaderValue(value: string): void {
  if (value.length === 0 || /[\r\n]/.test(value)) throw new Error("The DNS credential was rejected.");
}

async function readZone(
  transport: DnsTransport,
  provider: DetectedDnsProvider,
  zone: string,
  headers: Record<string, string>,
): Promise<StoredRecord[]> {
  const url = provider === "namecom"
    ? `https://api.name.com/v4/domains/${encodeURIComponent(zone)}/records?perPage=1000&page=1`
    : provider === "hostinger"
      ? `https://developers.hostinger.com/api/dns/v1/zones/${encodeURIComponent(zone)}`
      : `https://api.godaddy.com/v1/domains/${encodeURIComponent(zone)}/records`;
  const response = await call(transport, { method: "GET", url, headers });
  return normalizeZone(response.body, zone);
}

async function writeGroups(
  transport: DnsTransport,
  provider: DetectedDnsProvider,
  zone: string,
  headers: Record<string, string>,
  existing: StoredRecord[],
  desired: StoredRecord[],
  touched: string[],
): Promise<void> {
  const ttl = provider === "godaddy" ? 600 : 300;
  for (const key of touched) {
    const [type, host] = key.split("|") as [string, string];
    const rows = desired.filter((record) => record.type === type && record.host === host);
    if (provider === "namecom") {
      const base = `https://api.name.com/v4/domains/${encodeURIComponent(zone)}/records`;
      const fresh = rows.filter((row) => !existing.some((item) => item.type === row.type && item.host === row.host && item.value === row.value));
      for (const row of fresh) {
        await call(transport, {
          method: "POST",
          url: base,
          headers,
          body: JSON.stringify({ host: host === "@" ? "" : host, type, answer: row.value, ttl }),
        });
      }
      continue;
    }
    if (provider === "hostinger") {
      // overwrite replaces this name and type only. The body keeps every value in that set.
      await call(transport, {
        method: "PUT",
        url: `https://developers.hostinger.com/api/dns/v1/zones/${encodeURIComponent(zone)}`,
        headers,
        body: JSON.stringify({
          overwrite: true,
          zone: [{ name: host, type, ttl, records: rows.map((row) => ({ content: row.value })) }],
        }),
      });
      continue;
    }
    await call(transport, {
      method: "PUT",
      url: `https://api.godaddy.com/v1/domains/${encodeURIComponent(zone)}/records/${encodeURIComponent(type)}/${encodeURIComponent(host)}`,
      headers,
      body: JSON.stringify(rows.map((row) => ({ data: row.value, ttl }))),
    });
  }
}

function mergeRecords(existing: StoredRecord[], incoming: BrevoPublishRecord[], zone: string): StoredRecord[] {
  const desired = existing.map((record) => ({ ...record }));
  for (const record of incoming) {
    const host = relativeHost(record.host, zone);
    const value = cleanValue(record.type, record.value);
    if (!value) continue;
    if (desired.some((item) => item.type === record.type && item.host === host && item.value === value)) continue;
    if (record.type === "TXT" && isDmarc(value) && desired.some((item) => item.type === "TXT" && item.host === host && isDmarc(item.value))) {
      continue;
    }
    desired.push({ type: record.type, host, value });
  }
  return desired;
}

function isDmarc(value: string): boolean {
  return value.trim().toLowerCase().startsWith("v=dmarc1");
}

function changedGroups(before: StoredRecord[], after: StoredRecord[]): string[] {
  const keys = new Set([...before, ...after].map((record) => `${record.type}|${record.host}`));
  return [...keys].filter((key) => {
    const [type, host] = key.split("|");
    const left = before.filter((record) => record.type === type && record.host === host).map((record) => record.value).sort();
    const right = after.filter((record) => record.type === type && record.host === host).map((record) => record.value).sort();
    return left.join("\n") !== right.join("\n");
  });
}

function relativeHost(host: string, zone: string): string {
  const name = host.trim().toLowerCase().replace(/\.$/, "");
  if (name === "" || name === "@" || name === zone) return "@";
  if (name.endsWith(`.${zone}`)) return name.slice(0, -(zone.length + 1));
  return name;
}

function cleanValue(type: string, value: string): string {
  let text = value.trim();
  if ((type === "TXT" || type === "CNAME") && text.length >= 2 && text.startsWith('"') && text.endsWith('"')) {
    text = text.slice(1, -1).trim();
  }
  if (type === "CNAME") text = text.replace(/\.$/, "");
  return text;
}

function normalizeZone(body: string, zone: string): StoredRecord[] {
  let payload: unknown = {};
  try {
    payload = body.trim() ? JSON.parse(body) : {};
  } catch {
    throw new Error("The DNS provider rejected the record update.");
  }
  const rows = extractRows(payload);
  return rows.flatMap((row) => {
    const type = String(row.type ?? "").toUpperCase();
    if (type !== "TXT" && type !== "CNAME") return [];
    const host = relativeHost(String(row.host ?? row.name ?? "@"), zone);
    const value = cleanValue(type, String(row.value ?? row.answer ?? row.data ?? row.content ?? ""));
    if (!value) return [];
    return [{ type, host, value }];
  });
}

function extractRows(payload: unknown): Array<Record<string, unknown>> {
  if (Array.isArray(payload)) return payload.filter((row): row is Record<string, unknown> => !!row && typeof row === "object");
  if (!payload || typeof payload !== "object") return [];
  const root = payload as Record<string, unknown>;
  if (Array.isArray(root.records)) return root.records.filter((row): row is Record<string, unknown> => !!row && typeof row === "object");
  const groups = Array.isArray(root.zone) ? root.zone : Array.isArray(root.data) ? root.data : [];
  const rows: Array<Record<string, unknown>> = [];
  for (const group of groups) {
    if (!group || typeof group !== "object") continue;
    const item = group as Record<string, unknown>;
    if (typeof item.content === "string") {
      rows.push(item);
      continue;
    }
    const nested = Array.isArray(item.records) ? item.records : [];
    for (const record of nested) {
      if (!record || typeof record !== "object") continue;
      const content = (record as Record<string, unknown>).content;
      rows.push({ type: item.type, host: item.name, value: content });
    }
  }
  return rows;
}

async function call(transport: DnsTransport, input: { method: "GET" | "PUT" | "POST"; url: string; headers: Record<string, string>; body?: string }): Promise<{ status: number; body: string }> {
  let response: { status: number; body: string };
  try {
    response = await transport(input);
  } catch {
    throw new Error("The DNS provider could not be reached.");
  }
  if (response.status === 401 || response.status === 403) throw new Error("The DNS provider rejected the credential.");
  if (response.status === 404) throw new Error("The DNS zone was not found.");
  if (response.status < 200 || response.status >= 300) throw new Error("The DNS provider rejected the record update.");
  return response;
}

async function liveDnsTransport(input: {
  method: "GET" | "PUT" | "POST";
  url: string;
  headers: Record<string, string>;
  body?: string;
}): Promise<{ status: number; body: string }> {
  const allowed = input.url.startsWith("https://api.name.com/")
    || input.url.startsWith("https://developers.hostinger.com/")
    || input.url.startsWith("https://api.godaddy.com/");
  if (!allowed) throw new Error("The DNS provider could not be reached.");
  try {
    const response = await fetch(input.url, {
      method: input.method,
      redirect: "error",
      signal: AbortSignal.timeout(20_000),
      headers: input.headers,
      body: input.body,
    });
    return { status: response.status, body: (await response.text()).slice(0, 200_000) };
  } catch (error) {
    if (error instanceof Error && error.message === "The DNS provider could not be reached.") throw error;
    throw new Error("The DNS provider could not be reached.");
  }
}
