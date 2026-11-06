export type DnsRecord = {
  name: string;
  type: "A" | "AAAA" | "MX" | "TXT" | "NS" | "CNAME" | "CAA";
  value: string;
  priority?: number;
};

export type DnsPlanInput = {
  domain: string;
  mailHostname: string;
  webmailHostname: string;
  publicIpv4: string;
  publicIpv6?: string | null;
  brevoRecords: Array<{ purpose: "brevo_code" | "dkim" | "dmarc"; host: string; value: string }>;
  engineDkim: { host: string; value: string };
  zone: DnsRecord[];
};

export type DnsPlanSuccess = {
  ok: true;
  published: DnsRecord[];
  preserved: DnsRecord[];
  merged: DnsRecord[];
  previousMx: DnsRecord[];
  spf: string;
};

export type DnsPlanFailure = { ok: false; code: "DNS_RECORD_CONFLICT"; message: string };

const LOOKUPS = new Set(["include", "a", "mx", "ptr", "exists", "redirect"]);

function normName(name: string): string {
  return name.trim().toLowerCase().replace(/\.$/, "");
}

function fqdn(host: string, domain: string): string {
  const name = normName(host);
  if (name === "@" || name === domain) return domain;
  if (name.endsWith(`.${domain}`)) return name;
  return `${name}.${domain}`;
}

function copyZone(records: DnsRecord[]): DnsRecord[] {
  return records.map((record) => ({
    name: normName(record.name),
    type: record.type,
    value: record.value,
    ...(record.priority !== undefined ? { priority: record.priority } : {}),
  }));
}

function isLookup(token: string): boolean {
  const bare = token.replace(/^[+\-~?]/, "");
  const name = bare.split(/[:=/]/)[0]?.toLowerCase() ?? "";
  return LOOKUPS.has(name);
}

function lookupCount(spf: string): number {
  return spf
    .trim()
    .split(/\s+/)
    .filter((part) => part.toLowerCase() !== "v=spf1" && isLookup(part)).length;
}

function withBrevoInclude(spf: string): string {
  if (/include:spf\.brevo\.com/i.test(spf)) return spf;
  const parts = spf.trim().split(/\s+/);
  const allIndex = parts.findIndex((part) => /^(?:\+|-|~|\?)?all$/i.test(part));
  if (allIndex === -1) parts.push("include:spf.brevo.com");
  else parts.splice(allIndex, 0, "include:spf.brevo.com");
  return parts.join(" ");
}

function spfValues(zone: DnsRecord[], domain: string): string[] {
  return zone
    .filter((record) => record.type === "TXT" && record.name === domain && record.value.toLowerCase().startsWith("v=spf1"))
    .map((record) => record.value.trim());
}

export function mergeSpf(zone: DnsRecord[], domain: string): { ok: true; value: string } | DnsPlanFailure {
  const values = spfValues(zone, domain);
  const distinct = [...new Set(values)];
  if (distinct.length > 1) {
    return { ok: false, code: "DNS_RECORD_CONFLICT", message: "More than one SPF record cannot be merged." };
  }
  const merged = distinct.length === 0 ? "v=spf1 include:spf.brevo.com mx ~all" : withBrevoInclude(distinct[0]!);
  if (lookupCount(merged) > 10) {
    return { ok: false, code: "DNS_RECORD_CONFLICT", message: "The SPF record would exceed the 10-lookup limit." };
  }
  return { ok: true, value: merged };
}

function dmarcFailure(zone: DnsRecord[], domain: string): DnsPlanFailure | null {
  const name = `_dmarc.${domain}`;
  const records = zone.filter((record) => record.type === "TXT" && record.name === name);
  if (records.length > 1) {
    return { ok: false, code: "DNS_RECORD_CONFLICT", message: "More than one DMARC record is present." };
  }
  if (records.length === 1 && !records[0]!.value.toLowerCase().startsWith("v=dmarc1")) {
    return { ok: false, code: "DNS_RECORD_CONFLICT", message: "The existing DMARC record is not valid." };
  }
  return null;
}

function caaFailure(zone: DnsRecord[]): DnsPlanFailure | null {
  const records = zone.filter((record) => record.type === "CAA");
  if (records.length === 0) return null;
  const allows = records.some((record) => /issuewild|issue/i.test(record.value) && (/letsencrypt\.org/i.test(record.value) || record.value.includes('";"')));
  if (!allows) {
    return { ok: false, code: "DNS_RECORD_CONFLICT", message: "A CAA record would block certificate issuance." };
  }
  return null;
}

/** Read-only conflict check used when proving domain control. It adds no records. */
export function assessZoneRead(domain: string, records: DnsRecord[]): { ok: true } | DnsPlanFailure {
  const zone = copyZone(records);
  const name = normName(domain);
  const spf = mergeSpf(zone, name);
  if (!spf.ok) return spf;
  return dmarcFailure(zone, name) ?? caaFailure(zone) ?? { ok: true };
}

function sortRecords(records: DnsRecord[]): DnsRecord[] {
  return [...records].sort((a, b) => `${a.type}|${a.name}|${a.value}|${a.priority ?? ""}`.localeCompare(`${b.type}|${b.name}|${b.value}|${b.priority ?? ""}`));
}

function keyOf(record: DnsRecord): string {
  return `${record.type}|${record.name}|${record.value}|${record.priority ?? ""}`;
}

/**
 * Plan the mail record set bearmail-install would publish.
 * This function does not write, apply, or publish a zone.
 */
export function planDnsRecords(input: DnsPlanInput): DnsPlanSuccess | DnsPlanFailure {
  const domain = normName(input.domain);
  const mail = normName(input.mailHostname);
  const webmail = normName(input.webmailHostname);
  const zone = copyZone(input.zone);
  const managed = new Set([mail, webmail]);
  if (zone.some((record) => record.type === "CNAME" && managed.has(record.name))) {
    return { ok: false, code: "DNS_RECORD_CONFLICT", message: "Mail hostnames already have a CNAME." };
  }
  const spf = mergeSpf(zone, domain);
  if (!spf.ok) return spf;
  const dmarc = dmarcFailure(zone, domain);
  if (dmarc) return dmarc;
  const caa = caaFailure(zone);
  if (caa) return caa;

  const dmarcName = `_dmarc.${domain}`;
  const hasDmarc = zone.some((record) => record.type === "TXT" && record.name === dmarcName);
  const brevo = new Map(input.brevoRecords.map((record) => [record.purpose, record]));
  const brevoCode = brevo.get("brevo_code");
  const brevoDkim = brevo.get("dkim");
  const brevoDmarc = brevo.get("dmarc");
  if (!brevoCode || !brevoDkim || !brevoDmarc) {
    return { ok: false, code: "DNS_RECORD_CONFLICT", message: "Brevo TXT records are incomplete." };
  }

  const published: DnsRecord[] = [
    { name: mail, type: "A", value: input.publicIpv4 },
    { name: webmail, type: "A", value: input.publicIpv4 },
  ];
  if (input.publicIpv6) {
    published.push({ name: mail, type: "AAAA", value: input.publicIpv6 }, { name: webmail, type: "AAAA", value: input.publicIpv6 });
  }
  published.push(
    { name: domain, type: "MX", value: mail, priority: 10 },
    { name: fqdn(brevoCode.host, domain), type: "TXT", value: brevoCode.value },
    { name: fqdn(brevoDkim.host, domain), type: "TXT", value: brevoDkim.value },
    { name: fqdn(input.engineDkim.host, domain), type: "TXT", value: input.engineDkim.value },
    { name: domain, type: "TXT", value: spf.value },
  );
  if (!hasDmarc) {
    published.push({ name: fqdn(brevoDmarc.host, domain), type: "TXT", value: brevoDmarc.value });
  }

  const publishedKeys = new Set(published.map(keyOf));
  const previousMx = zone.filter((record) => record.type === "MX" && record.name === domain);
  const preserved = zone.filter((record) => {
    if (publishedKeys.has(keyOf(record))) return false;
    if (record.type === "MX" && record.name === domain) return false;
    if (record.type === "TXT" && record.name === domain && record.value.toLowerCase().startsWith("v=spf1")) return false;
    if ((record.type === "A" || record.type === "AAAA" || record.type === "CNAME") && managed.has(record.name)) return false;
    return true;
  });
  return {
    ok: true,
    published: sortRecords(published),
    preserved: sortRecords(preserved),
    merged: sortRecords([...preserved, ...published]),
    previousMx,
    spf: spf.value,
  };
}
