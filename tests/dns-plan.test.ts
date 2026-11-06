import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, it } from "node:test";
import * as dns from "../packages/providers/dns/src/index.ts";
import { assessZoneRead, planDnsRecords, type DnsRecord } from "../packages/providers/dns/src/plan.ts";

const domain = "alpha-bearportal.com";
const mail = "mail.alpha-bearportal.com";
const webmail = "webmail.alpha-bearportal.com";

const brevoRecords = [
  { purpose: "brevo_code" as const, host: "@", value: "brevo-code:alpha" },
  { purpose: "dkim" as const, host: "mail._domainkey", value: "k=rsa; p=brevo" },
  { purpose: "dmarc" as const, host: "_dmarc", value: "v=DMARC1; p=none" },
];

const engineDkim = { host: "default._domainkey", value: "k=rsa; p=engine" };

function zone(extra: DnsRecord[] = []): DnsRecord[] {
  return [
    { name: domain, type: "NS", value: "ns1.gamma-bearportal.com" },
    { name: domain, type: "NS", value: "ns2.gamma-bearportal.com" },
    { name: domain, type: "A", value: "192.0.2.20" },
    { name: `www.${domain}`, type: "A", value: "192.0.2.20" },
    { name: domain, type: "TXT", value: "google-site-verification=alpha" },
    { name: domain, type: "MX", value: "old-mail.alpha-bearportal.com", priority: 1 },
    ...extra,
  ];
}

function plan(records: DnsRecord[], ipv6?: string) {
  return planDnsRecords({
    domain,
    mailHostname: mail,
    webmailHostname: webmail,
    publicIpv4: "203.0.113.10",
    publicIpv6: ipv6 ?? null,
    brevoRecords,
    engineDkim,
    zone: records,
  });
}

describe("DNS plan A06", () => {
  it("publishes the mail set and preserves the website zone", () => {
    const records = zone();
    const before = structuredClone(records);
    const result = plan(records, "2001:db8::10");
    assert.equal(result.ok, true);
    if (!result.ok) return;
    assert.deepEqual(records, before);
    const published = result.published.map((record) => `${record.type} ${record.name} ${record.priority ?? ""} ${record.value}`);
    assert.ok(published.includes(`A ${mail}  203.0.113.10`));
    assert.ok(published.includes(`A ${webmail}  203.0.113.10`));
    assert.ok(published.includes(`AAAA ${mail}  2001:db8::10`));
    assert.ok(published.includes(`MX ${domain} 10 ${mail}`));
    assert.ok(published.includes(`TXT ${domain}  brevo-code:alpha`));
    assert.ok(published.includes(`TXT mail._domainkey.${domain}  k=rsa; p=brevo`));
    assert.ok(published.includes(`TXT default._domainkey.${domain}  k=rsa; p=engine`));
    assert.equal(result.spf, "v=spf1 include:spf.brevo.com mx ~all");
    assert.equal(result.published.filter((record) => record.type === "TXT" && record.value.toLowerCase().startsWith("v=spf1")).length, 1);
    assert.equal(result.merged.filter((record) => record.type === "MX").length, 1);
    assert.deepEqual(result.previousMx, [{ name: domain, type: "MX", value: "old-mail.alpha-bearportal.com", priority: 1 }]);
    for (const kept of ["NS", "A"]) {
      assert.ok(result.preserved.some((record) => record.type === kept && record.name === domain));
    }
    assert.ok(result.preserved.some((record) => record.type === "A" && record.name === `www.${domain}`));
    assert.ok(result.preserved.some((record) => record.type === "TXT" && record.value.includes("google-site-verification")));
    assert.equal(result.merged.some((record) => record.value === "old-mail.alpha-bearportal.com"), false);
  });

  it("keeps one existing SPF and a stricter DMARC record", () => {
    const records = zone([
      { name: domain, type: "TXT", value: "v=spf1 include:_spf.google.com ~all" },
      { name: `_dmarc.${domain}`, type: "TXT", value: "v=DMARC1; p=reject" },
    ]);
    const result = plan(records);
    assert.equal(result.ok, true);
    if (!result.ok) return;
    assert.equal(result.spf, "v=spf1 include:_spf.google.com include:spf.brevo.com ~all");
    assert.equal(result.published.some((record) => record.name === `_dmarc.${domain}`), false);
    assert.ok(result.preserved.some((record) => record.value === "v=DMARC1; p=reject"));
    assert.equal(result.merged.filter((record) => record.type === "TXT" && record.value.toLowerCase().startsWith("v=spf1")).length, 1);
  });

  it("rejects an ambiguous SPF merge before any change", () => {
    const records = zone([
      { name: domain, type: "TXT", value: "v=spf1 include:_spf.google.com ~all" },
      { name: domain, type: "TXT", value: "v=spf1 include:spf.protection.outlook.com ~all" },
    ]);
    const before = structuredClone(records);
    const result = plan(records);
    assert.deepEqual(result, { ok: false, code: "DNS_RECORD_CONFLICT", message: "More than one SPF record cannot be merged." });
    assert.deepEqual(records, before);
    assert.deepEqual(assessZoneRead(domain, records), result);
  });

  it("rejects an SPF record that would exceed ten lookups", () => {
    const includes = Array.from({ length: 10 }, (_, index) => `include:spf${index}.gamma-bearportal.com`).join(" ");
    const records = zone([{ name: domain, type: "TXT", value: `v=spf1 ${includes} ~all` }]);
    const before = structuredClone(records);
    const result = plan(records);
    assert.equal(result.ok, false);
    if (result.ok) return;
    assert.equal(result.code, "DNS_RECORD_CONFLICT");
    assert.match(result.message, /10-lookup/);
    assert.deepEqual(records, before);
  });

  it("rejects a mail CNAME and a blocking CAA record", () => {
    const cname = zone([{ name: mail, type: "CNAME", value: "other.gamma-bearportal.com" }]);
    assert.equal(plan(cname).ok, false);
    const caa = zone([{ name: domain, type: "CAA", value: '0 issue "ca.gamma-bearportal.com"' }]);
    const blocked = plan(caa);
    assert.equal(blocked.ok, false);
    if (blocked.ok) return;
    assert.match(blocked.message, /CAA/);
    const allowed = plan(zone([{ name: domain, type: "CAA", value: '0 issue "letsencrypt.org"' }]));
    assert.equal(allowed.ok, true);
  });

  it("plans records without writing and publishes only the Brevo verification set", () => {
    const names = Object.keys(dns);
    assert.deepEqual(names.filter((name) => /write|apply|publish/i.test(name)), ["publishBrevoRecords"]);
    for (const name of ["credentialProvider", "validateCredentialShape", "planDnsRecords", "assessZoneRead", "unavailableZoneReader"]) {
      assert.equal(typeof (dns as Record<string, unknown>)[name], "function");
    }
    const sourceDir = join(import.meta.dirname, "../packages/providers/dns/src");
    const files = readdirSync(sourceDir).filter((file) => file.endsWith(".ts"));
    for (const file of files) {
      const source = readFileSync(join(sourceDir, file), "utf8");
      assert.doesNotMatch(source, /writeZone|applyZone|publishZone/);
      if (file !== "publish-brevo.ts") assert.doesNotMatch(source, /\bfetch\s*\(|https?\.request\(/);
      if (file !== "nameservers.ts") assert.doesNotMatch(source, /dns\.promises/);
    }
  });
});
