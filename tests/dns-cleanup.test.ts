import { test } from "node:test";
import assert from "node:assert/strict";
import { applyCleanup, createDnsCleanupClient, keepReason, normalizeDomain, planRecords, relativeName, type ZoneRecord } from "../scripts/dns-cleanup.ts";

const domain = "example.com";
const r = (type: string, name: string, value = "192.0.2.1"): ZoneRecord => ({ type, name, value, raw: { type, name, value } });

test("DNS cleanup preserves only requested A hosts and zone authority, never all A or www CNAME", () => {
  for (const name of ["", "@", "example.com", "EXAMPLE.COM."]) assert.equal(relativeName(name, domain), "@");
  assert.equal(relativeName("WWW.Example.COM.", domain), "www");
  const rows = [r("A", "@"), r("A", "@", "192.0.2.2"), r("A", "www"), r("A", "mail"), r("AAAA", "@"), r("CNAME", "www"), r("TXT", "@"), r("MX", "@"), r("NS", "@"), r("SOA", "@"), r("NS", "delegated")];
  assert.deepEqual(planRecords(rows).preserved, [rows[0], rows[1], rows[2], rows[8], rows[9]]);
  assert.deepEqual(planRecords(rows).selected, [rows[3], rows[4], rows[5], rows[6], rows[7], rows[10]]);
});

test("DNS zone input rejects URLs, paths, IPs and malformed labels", () => {
  assert.equal(normalizeDomain(" Example.COM. "), domain);
  assert.equal(normalizeDomain("bücher.example"), "xn--bcher-kva.example");
  for (const bad of ["https://example.com", "example.com/path", "user@example.com", "*.example.com", "127.0.0.1", "-bad.com", "example..com", "com", "example.com:443"])
    assert.throws(() => normalizeDomain(bad), /DNS zone domain/);
});

test("Name.com reads all pages, retains backup fields and rechecks a record ID before delete", async () => {
  const records = [
    { id: 1, domainName: domain, type: "A", host: "", answer: "192.0.2.1", ttl: 300 },
    { id: 2, domainName: domain, type: "MX", host: "", answer: "mail.example.com", ttl: 600, priority: 10 },
  ];
  const methods: string[] = [];
  const client = createDnsCleanupClient(domain, { provider: "namecom", username: "user", token: "private-test-key" }, async (url, init) => {
    assert.equal((init.headers as Record<string, string>).authorization, "Basic " + Buffer.from("user:private-test-key").toString("base64"));
    methods.push(init.method!);
    if (init.method === "DELETE") { assert.ok(url.endsWith("/2")); return Response.json({}); }
    if (url.endsWith("/2")) return Response.json(records[1]);
    return Response.json(url.includes("page=1") ? { records: [records[0]], nextPage: 2 } : { records: [records[1]] });
  });
  const rows = await client.list();
  assert.equal(rows[1].raw.priority, 10);
  const deleted: string[] = [];
  await client.remove(planRecords(rows).selected, description => deleted.push(description));
  assert.deepEqual(methods, ["GET", "GET", "GET", "DELETE"]);
  assert.deepEqual(deleted, ["MX @ id=2"]);
});

test("Name.com refuses a target ID changed to a preserved A record", async () => {
  let deleted = false;
  const client = createDnsCleanupClient(domain, { provider: "namecom", username: "user", token: "private-test-key" }, async (_url, init) => {
    if (init.method === "DELETE") deleted = true;
    return Response.json({ id: 2, type: "A", host: "@", answer: "192.0.2.1" });
  });
  await assert.rejects(client.remove([{ ...r("TXT", "@", "old"), id: 2 }], () => {}), /changed/);
  assert.equal(deleted, false);
});

test("Hostinger deletes only explicit name/type groups and never sends an empty wildcard filter", async () => {
  const calls: { method?: string; body?: unknown }[] = [];
  const client = createDnsCleanupClient(domain, { provider: "hostinger", token: "private-test-key" }, async (_url, init) => {
    calls.push({ method: init.method, body: init.body ? JSON.parse(String(init.body)) : undefined });
    return Response.json(init.method === "GET" ? [
      { type: "A", name: "@", ttl: 300, records: [{ content: "192.0.2.1" }] },
      { type: "TXT", name: "@", ttl: 600, records: [{ content: "one" }, { content: "two" }] },
      { type: "CNAME", name: "www", ttl: 300, records: [{ content: domain }] },
    ] : { message: "Success" });
  });
  const rows = await client.list();
  await client.remove(planRecords(rows).selected, () => {});
  assert.deepEqual(calls.filter(c => c.method === "DELETE").map(c => c.body), [
    { filters: [{ name: "@", type: "TXT" }] }, { filters: [{ name: "www", type: "CNAME" }] },
  ]);
  await assert.rejects(client.remove([rows[0]], () => {}), /preserved/);
});

test("GoDaddy paginates until empty and deletes only a selected type/name set", async () => {
  const deleted: string[] = [];
  const client = createDnsCleanupClient(domain, { provider: "godaddy", token: "private-test-key" }, async (url, init) => {
    if (init.method === "DELETE") { deleted.push(url); return new Response(null, { status: 204 }); }
    const offset = new URL(url).searchParams.get("offset");
    return Response.json(offset === "0" ? [{ type: "A", name: "www", data: "192.0.2.1", ttl: 600 }]
      : offset === "1" ? [{ type: "A", name: "mail", data: "192.0.2.2", ttl: 600 }] : []);
  });
  const rows = await client.list();
  await client.remove(planRecords(rows).selected, () => {});
  assert.deepEqual(deleted, ["https://api.godaddy.com/v1/domains/example.com/records/A/mail"]);
  assert.throws(() => client.validateDeletion([r("NS", "delegated")]), /cannot delete NS/);
});

test("invalid or repeated provider pagination never becomes an incomplete deletion plan", async () => {
  const client = createDnsCleanupClient(domain, { provider: "namecom", username: "user", token: "private-test-key" }, async () => Response.json({ records: [], nextPage: 1 }));
  await assert.rejects(client.list(), /Repeated/);
  const godaddy = createDnsCleanupClient(domain, { provider: "godaddy", token: "private-test-key" }, async () => Response.json([{ type: "TXT", name: "@", data: "text" }]));
  await assert.rejects(godaddy.list(), /repeated a page/);
  const malformed = createDnsCleanupClient(domain, { provider: "hostinger", token: "private-test-key" }, async () => Response.json({ unexpected: [] }));
  await assert.rejects(malformed.list(), /Invalid Hostinger/);
});

test("provider errors never expose credentials or response bodies", async () => {
  for (const status of [401, 403, 429, 500]) {
    const client = createDnsCleanupClient(domain, { provider: "hostinger", token: "private-test-key" }, async () => new Response("private-test-key", { status }));
    await assert.rejects(client.list(), error => error instanceof Error && !error.message.includes("private-test-key") && error.message.includes(String(status)));
  }
});

test("failed backup, zone changes and provider changes prevent deletion", async () => {
  const rows = [r("A", "@"), r("MX", "@", "mail.example.com")];
  for (const failure of ["backup", "zone", "provider"]) {
    let deleted = false;
    await assert.rejects(applyCleanup({ before: rows,
      client: { validateDeletion: () => {}, list: async () => failure === "zone" ? [rows[0]] : rows, remove: async () => { deleted = true; } },
      checkProvider: async () => { if (failure === "provider") throw Error("changed provider"); },
      backup: () => { if (failure === "backup") throw Error("failed backup"); }, record: () => {},
    }));
    assert.equal(deleted, false);
  }
});

test("cleanup verifies preserved A values while allowing an automatically advanced SOA serial", async () => {
  const rows = [r("A", "@"), r("A", "www"), r("SOA", "@", "old serial"), r("MX", "@", "mail.example.com")];
  let deleted = false, backedUp = false;
  await applyCleanup({ before: rows,
    client: { validateDeletion: () => {}, list: async () => deleted ? [rows[0], rows[1], r("SOA", "@", "new serial")] : rows,
      remove: async (selected, done) => { assert.equal(backedUp, true); assert.deepEqual(selected, [rows[3]]); deleted = true; done("MX @"); } },
    checkProvider: async () => {}, backup: () => { backedUp = true; }, record: () => {},
  });
  assert.equal(deleted, true);
  let reads = 0;
  await assert.rejects(applyCleanup({ before: rows,
    client: { validateDeletion: () => {}, list: async () => ++reads === 1 ? rows : [r("A", "@", "192.0.2.99"), rows[1], rows[2]], remove: async () => {} },
    checkProvider: async () => {}, backup: () => {}, record: () => {},
  }), /verification/);
});


test("Name.com omitted apex host and empty TXT fields are normalized without losing records", async () => {
  const raw = [
    { id: 1, type: "A", answer: "192.0.2.1", fqdn: "example.com.", ttl: 300 },
    { id: 2, type: "A", answer: "192.0.2.2", ttl: 300 },
    { id: 3, type: "A", answer: "192.0.2.3", fqdn: "www.example.com.", ttl: 300 },
    { id: 4, type: "TXT", answer: "v=spf1 -all" },
    { id: 5, type: "TXT", fqdn: "example.com." },
    { id: 6, type: "MX", answer: "mail.example.com", priority: 10 },
  ];
  const deleted: string[] = [];
  const client = createDnsCleanupClient(domain, { provider: "namecom", username: "user", token: "private-test-key" }, async (url, init) => {
    if (init.method === "DELETE") { deleted.push(url); return Response.json({}); }
    if (url.includes("?")) return Response.json({ records: raw });
    return Response.json(raw.find(row => url.endsWith("/" + row.id)));
  });
  const rows = await client.list();
  assert.deepEqual(planRecords(rows).preserved.map(row => row.id), [1, 2, 3]);
  assert.deepEqual(planRecords(rows).selected.map(row => row.id), [4, 5, 6]);
  assert.equal(rows[4].value, "");
  assert.equal(Object.hasOwn(rows[0].raw, "host"), false, "Backup retains the original response fields");
  await client.remove(planRecords(rows).selected, () => {});
  assert.deepEqual(deleted.map(url => url.split("/").at(-1)), ["4", "5", "6"]);
});

test("Name.com rejects ambiguous, foreign or malformed fields without guessing protected A records", async () => {
  for (const row of [
    { id: 1, type: "A", host: null, answer: "192.0.2.1" },
    { id: 1, type: "A", host: "www" },
    { id: 1, type: "A", answer: "192.0.2.1", fqdn: "www.foreign.com." },
    { id: 1, type: "A", host: "mail", answer: "192.0.2.1", fqdn: "www.example.com." },
  ]) {
    const client = createDnsCleanupClient(domain, { provider: "namecom", username: "user", token: "private-test-key" }, async () => Response.json({ records: [row] }));
    await assert.rejects(client.list(), /Unrecognized|another zone|do not match/);
  }
});
