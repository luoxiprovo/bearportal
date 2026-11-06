import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { mapBrevoPublishRecords } from "../packages/providers/brevo/src/index.ts";
import { detectDnsProvider } from "../packages/providers/dns/src/detect.ts";
import { publishBrevoRecords, type DnsTransport } from "../packages/providers/dns/src/publish-brevo.ts";

describe("DNS provider detection and Brevo record publication", () => {
  it("detects one supported provider and rejects mixed or unknown nameservers", () => {
    assert.equal(detectDnsProvider(["ns07.domaincontrol.com", "ns08.domaincontrol.com"]), "godaddy");
    assert.equal(detectDnsProvider(["ns1.name.com."]), "namecom");
    assert.equal(detectDnsProvider(["ns1.dns-parking.com", "ns2.dns-parking.com"]), "hostinger");
    assert.equal(detectDnsProvider(["ns1.cloudflare.com"]), null);
    assert.equal(detectDnsProvider(["ns1.name.com", "ns1.domaincontrol.com"]), null);
    assert.equal(detectDnsProvider([]), null);
  });

  it("keeps Brevo CNAME DKIM records for publication", () => {
    const records = mapBrevoPublishRecords({
      dns_records: {
        brevo_code: { type: "TXT", value: "brevo-code:abc", host_name: "" },
        dmarc_record: { type: "TXT", value: "v=DMARC1; p=none", host_name: "_dmarc" },
        dkim1Record: { type: "CNAME", value: "b1.example", host_name: "brevo1._domainkey" },
        dkim2Record: { type: "CNAME", value: "b2.example", host_name: "brevo2._domainkey" },
        dkim_record: null,
      },
    }, "api-key");
    assert.deepEqual(records.map((record) => `${record.type} ${record.host}`), [
      "TXT @",
      "TXT _dmarc",
      "CNAME brevo1._domainkey",
      "CNAME brevo2._domainkey",
    ]);
  });

  it("adds a Brevo TXT without removing the existing TXT values at the same name", async () => {
    const calls: Array<{ method: string; url: string; body?: string; authorization: string }> = [];
    const transport: DnsTransport = async (input) => {
      calls.push({ method: input.method, url: input.url, body: input.body, authorization: input.headers.authorization ?? "" });
      if (input.method === "GET") {
        return {
          status: 200,
          body: JSON.stringify({
            zone: [{ name: "@", type: "TXT", ttl: 300, records: [{ content: "v=spf1 include:spf.example.com ~all" }] }],
          }),
        };
      }
      return { status: 200, body: "{}" };
    };
    const result = await publishBrevoRecords({
      provider: "hostinger",
      zone: "asdfs.site",
      credential: { provider: "hostinger", token: "hostinger-token" },
      records: [{ type: "TXT", host: "@", value: "brevo-code:abc" }],
      transport,
    });
    assert.equal(result.written, 1);
    assert.equal(calls[0]?.method, "GET");
    assert.equal(calls[1]?.method, "PUT");
    assert.equal(calls[1]?.authorization, "Bearer hostinger-token");
    const body = JSON.parse(calls[1]?.body ?? "{}") as { overwrite: boolean; zone: Array<{ records: Array<{ content: string }> }> };
    assert.equal(body.overwrite, true);
    assert.deepEqual(body.zone[0]?.records.map((record) => record.content).sort(), [
      "brevo-code:abc",
      "v=spf1 include:spf.example.com ~all",
    ]);
  });

  it("uses the GoDaddy personal access token and does not repeat an existing record", async () => {
    const calls: Array<{ method: string; url: string; authorization: string }> = [];
    const transport: DnsTransport = async (input) => {
      calls.push({ method: input.method, url: input.url, authorization: input.headers.authorization ?? "" });
      return {
        status: 200,
        body: JSON.stringify([{ type: "TXT", name: "@", data: "brevo-code:abc" }]),
      };
    };
    const result = await publishBrevoRecords({
      provider: "godaddy",
      zone: "asdfs.site",
      credential: { provider: "godaddy", token: "personal-access-token" },
      records: [{ type: "TXT", host: "@", value: "brevo-code:abc" }],
      transport,
    });
    assert.equal(result.written, 0);
    assert.equal(calls.length, 1);
    assert.equal(calls[0]?.authorization, "Bearer personal-access-token");
    assert.match(calls[0]?.url ?? "", /^https:\/\/api\.godaddy\.com\/v1\/domains\/asdfs\.site\/records/);
  });

  it("posts only a missing Name.com record and treats an empty apex host as @", async () => {
    const calls: Array<{ method: string; url: string; body?: string; authorization: string }> = [];
    const transport: DnsTransport = async (input) => {
      calls.push({ method: input.method, url: input.url, body: input.body, authorization: input.headers.authorization ?? "" });
      if (input.method === "GET") {
        return {
          status: 200,
          body: JSON.stringify({
            records: [
              { host: "", type: "TXT", answer: "v=spf1 include:spf.example.com ~all" },
              { host: "brevo1._domainkey", type: "CNAME", answer: "b1.example." },
            ],
          }),
        };
      }
      return { status: 201, body: "{}" };
    };
    const result = await publishBrevoRecords({
      provider: "namecom",
      zone: "asdfs.site",
      credential: { provider: "namecom", username: "alice", token: "name-token" },
      records: [
        { type: "TXT", host: "@", value: "brevo-code:abc" },
        { type: "CNAME", host: "brevo1._domainkey", value: "b1.example" },
      ],
      transport,
    });
    assert.equal(result.written, 1);
    const posts = calls.filter((call) => call.method === "POST");
    assert.equal(posts.length, 1);
    assert.equal(posts[0]?.authorization, `Basic ${Buffer.from("alice:name-token").toString("base64")}`);
    assert.deepEqual(JSON.parse(posts[0]?.body ?? "{}"), {
      host: "",
      type: "TXT",
      answer: "brevo-code:abc",
      ttl: 300,
    });
  });

  it("keeps an existing GoDaddy TXT when it adds the Brevo code", async () => {
    const calls: Array<{ method: string; url: string; body?: string }> = [];
    const transport: DnsTransport = async (input) => {
      calls.push({ method: input.method, url: input.url, body: input.body });
      if (input.method === "GET") {
        return { status: 200, body: JSON.stringify([{ type: "TXT", name: "@", data: '"v=spf1 include:spf.example.com ~all"' }]) };
      }
      return { status: 200, body: "{}" };
    };
    const result = await publishBrevoRecords({
      provider: "godaddy",
      zone: "asdfs.site",
      credential: { provider: "godaddy", token: "personal-access-token" },
      records: [{ type: "TXT", host: "@", value: "brevo-code:abc" }],
      transport,
    });
    assert.equal(result.written, 1);
    const put = calls.find((call) => call.method === "PUT");
    assert.match(put?.url ?? "", /\/records\/TXT\/(%40|@)$/);
    const body = JSON.parse(put?.body ?? "[]") as Array<{ data: string; ttl: number }>;
    assert.deepEqual(body.map((row) => row.data).sort(), ["brevo-code:abc", "v=spf1 include:spf.example.com ~all"]);
    assert.equal(body[0]?.ttl, 600);
  });

  it("does not add a second DMARC record when one is already published", async () => {
    const calls: Array<{ method: string; url: string; body?: string }> = [];
    const transport: DnsTransport = async (input) => {
      calls.push({ method: input.method, url: input.url, body: input.body });
      if (input.method === "GET") {
        return { status: 200, body: JSON.stringify([{ type: "TXT", name: "_dmarc", data: "v=DMARC1; p=reject" }]) };
      }
      return { status: 200, body: "{}" };
    };
    const result = await publishBrevoRecords({
      provider: "godaddy",
      zone: "asdfs.site",
      credential: { provider: "godaddy", token: "personal-access-token" },
      records: [{ type: "TXT", host: "_dmarc", value: "v=DMARC1; p=none" }],
      transport,
    });
    assert.equal(result.written, 0);
    assert.equal(calls.some((call) => call.method === "PUT"), false);
  });
});
