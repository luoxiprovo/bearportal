import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { describe, it } from "node:test";
import { randomUUID } from "node:crypto";
import {
  BEARMAIL_PIN,
  BLOCKING_GAPS,
  dnsCredentialSchema,
  errorBodySchema,
  installerInputSchema,
} from "../packages/contracts/src/index.ts";
import { openApiDocument } from "../packages/contracts/src/openapi.ts";
import { normalizeDomain, recoveryIsOutsideDomain } from "../packages/domain/src/domain.ts";
import { requireOperation } from "../packages/operations/src/registry.ts";
import { authenticateBrevoDomain, BrevoRequestError, fakeBrevoClient, liveBrevoClient, requestBrevoDomain, type BrevoTransport } from "../packages/providers/brevo/src/index.ts";
import * as dns from "../packages/providers/dns/src/index.ts";
import { open, seal } from "../packages/secrets/src/store.ts";
import { loadConfig } from "../apps/api/src/config.ts";

const installer = {
  schemaVersion: 1 as const,
  operationId: randomUUID(),
  deploymentId: randomUUID(),
  generation: 1,
  mxCutoverAuthorized: true as const,
  domain: "mail-a.alpha-bearportal.com",
  mailHostname: "mail.mail-a.alpha-bearportal.com",
  webmailHostname: "webmail.mail-a.alpha-bearportal.com",
  publicIpv4: "203.0.113.10",
  publicIpv6: null,
  dataPath: "/var/lib/stalwart" as const,
  dns: { provider: "namecom" as const, zone: "alpha-bearportal.com", credentialFile: "/run/dns.json" },
  brevoDnsRecords: [
    { purpose: "brevo_code" as const, type: "TXT" as const, host: "@", value: "brevo-code:abc" },
    { purpose: "dkim" as const, type: "TXT" as const, host: "mail._domainkey", value: "k=rsa;p=abc" },
    { purpose: "dmarc" as const, type: "TXT" as const, host: "_dmarc", value: "v=DMARC1; p=none" },
  ],
  relay: {
    host: "smtp-relay.brevo.com" as const,
    port: 587 as const,
    tls: "starttls-required" as const,
    login: "relay@smtp-brevo.com",
    credentialFile: "/run/smtp.json",
  },
  adminCredentialFile: "/run/admin.json",
  mailboxQuotaBytes: 1073741824,
  release: { id: "release-fixture", artifactDir: "/opt/bearmail/release-fixture", checksumFile: "/opt/bearmail/release-fixture/SHA256SUMS" },
};

describe("M1 contracts", () => {
  it("records the BearMail pin and the capabilities that are still unverified", () => {
    assert.equal(BEARMAIL_PIN.repository, "luoxiprovo/bearmail");
    assert.equal(BEARMAIL_PIN.ref, "refs/heads/main");
    assert.equal(BEARMAIL_PIN.installerPath, "bearmail-install");
    assert.equal(BEARMAIL_PIN.dataPath, "/var/lib/stalwart");
    assert.equal("commit" in BEARMAIL_PIN, false);
    assert.deepEqual(BLOCKING_GAPS.map((gap) => gap.id), [
      "engine-management-unverified",
      "live-provider-unverified",
      "installer-suite-not-run-here",
      "grok-live-unverified",
    ]);
  });

  it("accepts the installer input and rejects a cutover, path, or provider BearPortal does not allow", () => {
    assert.equal(installerInputSchema.parse(installer).mxCutoverAuthorized, true);
    assert.throws(() => installerInputSchema.parse({ ...installer, mxCutoverAuthorized: false }));
    assert.throws(() => installerInputSchema.parse({ ...installer, dataPath: "/var/lib/other" }));
    assert.throws(() => installerInputSchema.parse({ ...installer, dns: { ...installer.dns, provider: "cloudflare" } }));
    assert.throws(() => installerInputSchema.parse({ ...installer, brevoDnsRecords: installer.brevoDnsRecords.slice(0, 2) }));
    const { brevoDnsRecords: _omitted, ...withoutBrevoRecords } = installer;
    assert.equal(installerInputSchema.parse(withoutBrevoRecords).relay.login, installer.relay.login);
    assert.deepEqual(installerInputSchema.parse({ ...installer, brevoDnsRecords: [] }).brevoDnsRecords, []);
    assert.throws(() => installerInputSchema.parse({ ...installer, brevoDnsRecords: installer.brevoDnsRecords.slice(0, 1) }));
    assert.throws(() => installerInputSchema.parse({ ...installer, extra: true }));
  });

  it("accepts only the three DNS credential shapes and publishes only Brevo verification records", () => {
    const dnsKeys = Object.keys(dns).sort();
    assert.deepEqual(dnsKeys.filter((key) => /write|apply|publish/i.test(key)), ["publishBrevoRecords"]);
    for (const key of ["credentialProvider", "validateCredentialShape", "planDnsRecords", "assessZoneRead", "unavailableZoneReader"]) {
      assert.equal(typeof (dns as Record<string, unknown>)[key], "function");
    }
    const namecom = dns.validateCredentialShape({ provider: "namecom", credentials: { username: "acct", token: "secret" } });
    assert.equal(dns.credentialProvider(namecom), "namecom");
    dns.validateCredentialShape({ provider: "hostinger", credentials: { token: "secret" } });
    dns.validateCredentialShape({ provider: "godaddy", credentials: { token: "personal-access-token" } });
    assert.throws(() => dnsCredentialSchema.parse({ provider: "godaddy", credentials: { apiKey: "key", apiSecret: "secret" } }));
    assert.throws(() => dnsCredentialSchema.parse({ provider: "namecom", credentials: { token: "only" } }));
    assert.throws(() => dnsCredentialSchema.parse({ provider: "hostinger", credentials: { token: "secret", extra: "no" } }));
    assert.throws(() => dnsCredentialSchema.parse({ provider: "route53", credentials: {} }));
  });

  it("keeps the live Brevo client closed and the fake client unauthenticated", async () => {
    const fake = fakeBrevoClient();
    const created = await fake.createDomain("mail-a.alpha-bearportal.com");
    assert.equal(created.authenticated, false);
    assert.equal(created.records.length, 3);
    assert.equal((await fake.authenticate(created.domain)).authenticated, false);
    await assert.rejects(() => liveBrevoClient().createDomain("mail-a.alpha-bearportal.com"), /not configured/);
    await assert.rejects(() => liveBrevoClient().authenticate("mail-a.alpha-bearportal.com"), /not configured/);
  });

  it("reads Brevo domain flags only from the configuration response", async () => {
    const calls: string[] = [];
    const transport: BrevoTransport = async (input) => {
      calls.push(`${input.method} ${input.path}`);
      assert.equal(input.apiKey, "brevo-test-key");
      assert.equal(input.body?.includes("brevo-test-key") ?? false, false);
      if (input.method === "POST") {
        return {
          status: 400,
          body: JSON.stringify({ message: "already exists" }),
        };
      }
      if (input.method === "PUT") {
        return { status: 200, body: JSON.stringify({ verified: true, authenticated: true, message: "ok" }) };
      }
      return {
        status: 200,
        body: JSON.stringify({
          domain: "mail-a.alpha-bearportal.com",
          verified: false,
          authenticated: false,
          dns_records: {
            dkim_record: { type: "TXT", value: "k=rsa;p=from-get", host_name: "mail._domainkey.", status: false },
            brevo_code: { type: "TXT", value: "brevo-code:from-get", host_name: "", status: false },
            dmarc_record: { type: "TXT", value: "v=DMARC1; p=none", host_name: "_dmarc.", status: false },
          },
        }),
      };
    };
    const pending = await requestBrevoDomain("brevo-test-key", "mail-a.alpha-bearportal.com", transport);
    assert.equal(pending.authenticated, false);
    assert.equal(pending.verified, false);
    assert.equal(pending.records.find((record) => record.purpose === "dkim")?.host, "mail._domainkey");
    assert.equal(pending.records.find((record) => record.purpose === "dkim")?.value, "k=rsa;p=from-get");
    assert.equal(pending.records.find((record) => record.purpose === "brevo_code")?.host, "@");
    assert.equal(pending.records.find((record) => record.purpose === "dmarc")?.host, "_dmarc");
    assert.deepEqual(calls, [
      "POST /v3/senders/domains",
      "GET /v3/senders/domains/mail-a.alpha-bearportal.com",
    ]);

    const verified = await requestBrevoDomain("brevo-test-key", "mail-a.alpha-bearportal.com", async (input) => {
      if (input.method === "GET") {
        return {
          status: 200,
          body: JSON.stringify({
            verified: true,
            authenticated: true,
            dns_records: {
              dkim: { type: "TXT", value: "k=rsa;p=yes", host_name: "mail._domainkey" },
              brevo_code: { type: "TXT", value: "brevo-code:yes", host_name: "@" },
              dmarc: { type: "TXT", value: "v=DMARC1; p=none", host_name: "_dmarc" },
            },
          }),
        };
      }
      return { status: input.method === "PUT" ? 400 : 201, body: "{}" };
    });
    assert.equal(verified.authenticated, true);
    assert.equal(verified.verified, true);
    assert.equal(verified.records.length, 3);

    const cname = await requestBrevoDomain("brevo-test-key", "mail-a.alpha-bearportal.com", async (input) => {
      if (input.method !== "GET") return { status: input.method === "PUT" ? 400 : 201, body: "{}" };
      return {
        status: 200,
        body: JSON.stringify({
          verified: false,
          authenticated: false,
          dns_records: {
            dkim_record: { type: "CNAME", value: "cname.example", host_name: "mail._domainkey" },
            brevo_code: { type: "TXT", value: "brevo-code:x", host_name: "" },
            dmarc_record: { type: "TXT", value: "v=DMARC1; p=none", host_name: "_dmarc" },
          },
        }),
      };
    });
    assert.equal(cname.records.some((record) => record.purpose === "dkim"), false);
    assert.equal(cname.verified, false);

    const duplicate = await requestBrevoDomain("brevo-test-key", "mail-a.alpha-bearportal.com", async (input) => {
      if (input.method === "POST") {
        return { status: 404, body: JSON.stringify({ code: "duplicate_parameter", message: "Domain with same name already exists" }) };
      }
      if (input.method === "PUT") return { status: 400, body: "{}" };
      return {
        status: 200,
        body: JSON.stringify({
          verified: false,
          authenticated: false,
          dns_records: {
            dkim_record: null,
            dkim1Record: { type: "CNAME", value: "b1.example", host_name: "brevo1._domainkey" },
            dkim2Record: { type: "CNAME", value: "b2.example", host_name: "brevo2._domainkey" },
            brevo_code: { type: "TXT", value: "brevo-code:x", host_name: "@" },
            dmarc_record: { type: "TXT", value: "v=DMARC1; p=none", host_name: "_dmarc" },
          },
        }),
      };
    });
    assert.equal(duplicate.authenticated, false);
    assert.equal(duplicate.publishRecords?.filter((record) => record.type === "CNAME").length, 2);
    assert.equal(duplicate.publishRecords?.some((record) => record.type === "TXT" && record.host === "@"), true);

    await assert.rejects(
      () => requestBrevoDomain("brevo-test-key", "mail-a.alpha-bearportal.com", async () => ({
        status: 404,
        body: JSON.stringify({ code: "document_not_found", message: "Domain does not exist" }),
      })),
      (error: unknown) => error instanceof BrevoRequestError && error.message === "Brevo did not accept the domain.",
    );

    await assert.rejects(
      () => requestBrevoDomain("secret-api-key-should-not-leak", "mail-a.alpha-bearportal.com", async () => ({
        status: 401,
        body: "secret-api-key-should-not-leak",
      })),
      (error: unknown) => {
        assert.ok(error instanceof BrevoRequestError);
        assert.equal((error as Error).message, "Brevo rejected the API key.");
        return true;
      },
    );
    const callsAfterPublish: string[] = [];
    const authed = await authenticateBrevoDomain("brevo-test-key", "mail-a.alpha-bearportal.com", async (input) => {
      callsAfterPublish.push(`${input.method} ${input.path}`);
      if (input.method === "PUT") return { status: 200, body: "{}" };
      return {
        status: 200,
        body: JSON.stringify({
          verified: false,
          authenticated: true,
          dns_records: {
            brevo_code: { type: "TXT", value: "brevo-code:x", host_name: "@" },
            dmarc_record: { type: "TXT", value: "v=DMARC1; p=none", host_name: "_dmarc" },
            dkim1Record: { type: "CNAME", value: "b1.example", host_name: "brevo1._domainkey" },
            dkim2Record: { type: "CNAME", value: "b2.example", host_name: "brevo2._domainkey" },
          },
        }),
      };
    });
    assert.equal(authed.authenticated, true);
    assert.equal(authed.verified, false);
    assert.deepEqual(callsAfterPublish, [
      "PUT /v3/senders/domains/mail-a.alpha-bearportal.com/authenticate",
      "GET /v3/senders/domains/mail-a.alpha-bearportal.com",
    ]);
    const refused = await authenticateBrevoDomain("brevo-test-key", "mail-a.alpha-bearportal.com", async (input) => {
      if (input.method === "PUT") return { status: 400, body: JSON.stringify({ code: "invalid_parameter", message: "DNS not ready" }) };
      return {
        status: 200,
        body: JSON.stringify({ verified: false, authenticated: false, dns_records: {} }),
      };
    });
    assert.equal(refused.authenticated, false);
    assert.equal(refused.verified, false);

    await assert.rejects(
      () => requestBrevoDomain("brevo-test-key", "mail-a.alpha-bearportal.com", async () => {
        throw new Error("socket down brevo-test-key");
      }),
      (error: unknown) => {
        assert.equal((error as Error).message, "Brevo could not be reached.");
        return true;
      },
    );
  });

  it("rejects an operation that is not in the approved registry", () => {
    assert.equal(requireOperation("organization.allocate").state, "approved");
    assert.equal(requireOperation("dns.store_credentials").capability, "dns.store");
    assert.equal(requireOperation("brevo.create_domain").version, "1");
    assert.throws(() => requireOperation("shell.exec"));
  });

  it("normalizes a public domain and keeps recovery outside it", () => {
    assert.equal(normalizeDomain("Mail-A.Alpha-Bearportal.com."), "mail-a.alpha-bearportal.com");
    assert.throws(() => normalizeDomain("https://alpha-bearportal.com"));
    assert.throws(() => normalizeDomain("203.0.113.10"));
    assert.throws(() => normalizeDomain("example.com"));
    assert.equal(recoveryIsOutsideDomain("owner@recovery-bearportal.com", "mail-a.alpha-bearportal.com"), true);
    assert.equal(recoveryIsOutsideDomain("owner@recovery-bearportal.com", "recovery-bearportal.com"), false);
    assert.equal(recoveryIsOutsideDomain("owner@box.mail-a.alpha-bearportal.com", "mail-a.alpha-bearportal.com"), false);
  });

  it("seals a secret so the file bytes are not the plaintext", () => {
    const key = Buffer.alloc(32, 7);
    const sealed = seal("CANARY-seal-check", key);
    assert.equal(sealed.includes(Buffer.from("CANARY-seal-check")), false);
    assert.equal(open(sealed, key), "CANARY-seal-check");
    const tampered = Buffer.from(sealed);
    tampered[tampered.length - 1] ^= 1;
    assert.throws(() => open(tampered, key));
  });

  it("generates OpenAPI from the runtime schemas and lists the API routes", () => {
    const document = openApiDocument();
    const paths = document.paths as Record<string, Record<string, unknown>>;
    const sourceDir = new URL("../apps/api/src/", import.meta.url);
    const source = readdirSync(sourceDir)
      .filter((name) => name.endsWith(".ts"))
      .map((name) => readFileSync(new URL(name, sourceDir), "utf8"))
      .join("\n");
    const routes = [...source.matchAll(/app\.(get|post)\("([^"]+)"/g)].map((match) => {
      const path = match[2]!.replace(/:([A-Za-z0-9_]+)/g, "{$1}");
      return `${match[1]!.toUpperCase()} ${path}`;
    });
    for (const route of routes) {
      const [method, path] = route.split(" ");
      assert.ok(paths[path!]?.[method!.toLowerCase()], route);
    }
    const organization = (document.components as { schemas: Record<string, { additionalProperties?: boolean }> }).schemas.OrganizationCreate;
    assert.equal(organization.additionalProperties, false);
    errorBodySchema.parse({
      error: { code: "VALIDATION", message: "The request is not valid.", retryable: false, requiredActionId: null },
      requestId: randomUUID(),
    });
  });

  it("names missing configuration without echoing values", () => {
    const secret = "canary-secret-value-should-not-be-printed";
    assert.throws(
      () => loadConfig({ BEARPORTAL_SECRET_KEY: secret }),
      (error: unknown) => {
        assert.ok(error instanceof Error);
        assert.match(error.message, /DATABASE_URL/);
        assert.equal(error.message.includes(secret), false);
        return true;
      },
    );
    assert.throws(
      () => loadConfig({
        DATABASE_URL: "postgres://local/db",
        BEARPORTAL_SECRET_KEY: "abcd",
        BEARPORTAL_JWT_PUBLIC_KEY_FILE: "/tmp/key.pem",
        BEARPORTAL_JWT_ISSUER: "https://securetoken.google.com/example",
        BEARPORTAL_JWT_AUDIENCE: "example",
        BEARPORTAL_SECRETS_DIR: "/tmp/secrets",
      }),
      /BEARPORTAL_SECRET_KEY is invalid/,
    );
    assert.throws(
      () => loadConfig({
        BEARPORTAL_ENV: "production",
        BEARPORTAL_ALLOW_TEST_ISSUER: "1",
        DATABASE_URL: "postgres://local/db",
        BEARPORTAL_SECRET_KEY: "11".repeat(32),
        BEARPORTAL_JWT_PUBLIC_KEY_FILE: "/tmp/key.pem",
        BEARPORTAL_JWT_ISSUER: "https://test.bearportal.local",
        BEARPORTAL_JWT_AUDIENCE: "bearportal-test",
        BEARPORTAL_SECRETS_DIR: "/tmp/secrets",
      }),
      /Test identity issuer cannot be enabled in production/,
    );
    const base = {
      DATABASE_URL: "postgres://local/db",
      BEARPORTAL_SECRET_KEY: "11".repeat(32),
      BEARPORTAL_JWT_PUBLIC_KEY_FILE: "/tmp/key.pem",
      BEARPORTAL_JWT_ISSUER: "https://securetoken.google.com/example",
      BEARPORTAL_JWT_AUDIENCE: "example",
      BEARPORTAL_SECRETS_DIR: "/tmp/secrets",
    };
    assert.equal(loadConfig(base).schedulerToken, undefined);
    assert.equal(loadConfig({ ...base, BEARPORTAL_SCHEDULER_TOKEN: "" }).schedulerToken, undefined);
    assert.equal(loadConfig({ ...base, BEARPORTAL_SCHEDULER_TOKEN: "0123456789abcdef" }).schedulerToken, "0123456789abcdef");
    const leaked = "canary scheduler value must stay hidden";
    assert.throws(
      () => loadConfig({ ...base, BEARPORTAL_SCHEDULER_TOKEN: leaked }),
      (error: unknown) => {
        assert.ok(error instanceof Error);
        assert.match(error.message, /BEARPORTAL_SCHEDULER_TOKEN is invalid/);
        assert.equal(error.message.includes(leaked), false);
        return true;
      },
    );
  });
});
