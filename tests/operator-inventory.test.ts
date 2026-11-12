import { runInventory } from "../scripts/inventory-cli.ts";
import assert from "node:assert/strict";
import { test } from "node:test";
import { randomUUID } from "node:crypto";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";
import { generateKeyPair, exportSPKI, SignJWT } from "jose";
import { buildServer, bootstrapAdmin } from "../apps/api/src/server.ts";
import { migrate } from "../packages/db/src/migrate.ts";
import { SecretStore, loadSecretKey } from "../packages/secrets/src/store.ts";
import { integrationDatabases, queryTestDatabase } from "./helpers/database.ts";

const { databaseUrl, migrationUrl, superDatabaseUrl } = integrationDatabases();
const query = (text: string) => queryTestDatabase(text, superDatabaseUrl);
const q = (value: string) => "'" + value.replaceAll("'", "''") + "'";

test("operator inventory supports versioned browser CRUD, write-only credentials, assignment guards and role restrictions", async () => {
  await migrate(migrationUrl);
  await query(
    "TRUNCATE users,organizations,servers,relay_connections,domains,secret_refs,deployments,jobs,operator_roles,allocation_requests,invitations,idempotency_keys,audit_events,outbox_events CASCADE",
  );
  await query("UPDATE inventory_name_counters SET value=0");
  await query("UPDATE control_plane_state SET mode='normal' WHERE id=1");
  const pair = await generateKeyPair("RS256", { extractable: true });
  const issuer = "https://test.operator.local",
    audience = "operator-test",
    secretKeyHex = "ab".repeat(32);
  const secretsDir = mkdtempSync(join(tmpdir(), "bearportal-inventory-"));
  const admin = await bootstrapAdmin(
    databaseUrl,
    "inventory-admin",
    "admin@recovery.example.org",
  );
  const tokens: Record<string, string> = {};
  for (const role of [
    "admin",
    "infrastructure_operator",
    "support",
    "customer",
  ]) {
    const id = role === "admin" ? admin.userId : randomUUID();
    if (role !== "admin") {
      await query(
        `INSERT INTO users(id,identity_subject,verified_email,email_verified,status) VALUES(${q(id)},${q("inventory-" + role)},${q(role + "@recovery.example.org")},true,'active')`,
      );
      if (role !== "customer")
        await query(
          `INSERT INTO operator_roles(id,user_id,role,reason) VALUES(${q(randomUUID())},${q(id)},${q(role)},'Inventory test')`,
        );
    }
    tokens[role] = await new SignJWT({
      email:
        role === "admin"
          ? "admin@recovery.example.org"
          : role + "@recovery.example.org",
      email_verified: true,
      auth_time: Math.floor(Date.now() / 1000),
      amr: ["pwd", "totp"],
    })
      .setSubject(role === "admin" ? "inventory-admin" : "inventory-" + role)
      .setProtectedHeader({ alg: "RS256" })
      .setIssuer(issuer)
      .setAudience(audience)
      .setIssuedAt()
      .setExpirationTime("1h")
      .sign(pair.privateKey);
  }
  const logs: Buffer[] = [];
  let probes = 0;
  let failSsh = false;
  const app = await buildServer(
    {
      billingRequired: false,
      databaseUrl,
      secretsDir,
      secretKeyHex,
      jwtPublicKeyPem: await exportSPKI(pair.publicKey),
      issuer,
      audience,
      onboardingIntervalMs: 0,
      sshProbe: async () => {
        probes++;
        if(failSsh)return {ok:false,failures:["server.host_key_mismatch"],report:null};
        return {
          ok: true,
          failures: [],
          report: {
            source: "ssh",
            os: "Linux",
            init: "systemd",
            architecture: "x64",
            memoryMb: 1024,
            diskGb: 30,
            dataPathMounted: false,
            priorTenantData: false,
            reachable: true,
            hostKeyFingerprint: "SHA256:test-fingerprint",
          },
        };
      },
    },
    new Writable({
      write(chunk, _encoding, callback) {
        logs.push(Buffer.from(chunk));
        callback();
      },
    }),
  );
  const json = (
    method: "POST" | "PATCH" | "DELETE",
    url: string,
    payload: Record<string, unknown>,
    role = "admin",
    key = randomUUID(),
  ) =>
    app.inject({
      method,
      url,
      headers: {
        authorization: "Bearer " + tokens[role],
        "idempotency-key": key,
      },
      payload,
    });
  const form = (
    url: string,
    payload: Record<string, string>,
    role = "admin",
    key = randomUUID(),
  ) =>
    app.inject({
      method: "POST",
      url,
      headers: {
        authorization: "Bearer " + tokens[role],
        accept: "application/json",
        "content-type": "application/x-www-form-urlencoded",
      },
      payload: new URLSearchParams({
        csrf: "1",
        idempotencyKey: key,
        ...payload,
      }).toString(),
    });
  const serverFields = {
    publicIpv4: "8.8.4.4",
    providerReference: "instance-1",
    osPrepared: "1",
    storagePrepared: "1",
    firewallAttested: "1",
    cleanHost: "1",
    externalBackup: "1",
  };
  try {
    const supportPage = await app.inject({
      url: "/operator",
      headers: { authorization: "Bearer " + tokens.support },
    });
    assert.equal(supportPage.statusCode, 200);
    assert.equal(
      supportPage.body.includes('data-open-dialog="add-server"'),
      false,
    );
    assert.equal(
      supportPage.body.includes('data-open-dialog="add-brevo"'),
      false,
    );
    assert.equal(
      (await form("/operator/inventory/servers", serverFields, "support"))
        .statusCode,
      403,
    );
    assert.equal(
      (await form("/operator/inventory/servers", serverFields, "customer"))
        .statusCode,
      403,
    );
    const session = await app.inject({
      method: "POST",
      url: "/v1/session",
      payload: { idToken: tokens.admin },
    });
    const cookie = String(session.headers["set-cookie"]).split(";")[0];
    const csrf = await app.inject({
      method: "POST",
      url: "/operator/inventory/servers",
      headers: {
        cookie,
        accept: "application/json",
        "content-type": "application/x-www-form-urlencoded",
      },
      payload: new URLSearchParams({
        idempotencyKey: randomUUID(),
        ...serverFields,
      }).toString(),
    });
    assert.equal(
      csrf.statusCode,
      403,
      "form-to-API forwarding must not bypass cookie CSRF checks",
    );
    const badAttestations = await form("/operator/inventory/servers", {
      ...serverFields,
      cleanHost: "",
    });
    assert.equal(badAttestations.statusCode, 400);
    const added = await form(
      "/operator/inventory/servers",
      serverFields,
      "infrastructure_operator",
    );
    assert.equal(added.statusCode, 200, added.body);
    assert.ok(added.json().redirect.includes("server-added"));
    assert.equal(probes, 1);
    assert.deepEqual(await query("SELECT operator_contact IS NULL FROM servers"), [["t"]]);
    const id = (await query("SELECT id FROM servers"))[0][0];
    let version = Number(
      (await query(`SELECT version FROM servers WHERE id=${q(id)}`))[0][0],
    );
    const page = await app.inject({
      url: "/operator",
      headers: { authorization: "Bearer " + tokens.admin },
    });
    assert.ok(page.body.includes("s-1"));
    assert.match(page.body, /Operator contact \(optional\)/);
    assert.deepEqual(await query("SELECT label FROM servers"), [["s-1"]]);
    assert.equal(page.body.includes('placeholder="Mail server · US West"'), false);
    assert.equal(page.body.includes("<script>alert(1)</script>"), false);
    assert.ok(page.body.includes("data-resource-search"));
    assert.ok(page.body.includes("SHA256:test-fingerprint"));
    assert.equal(
      (
        await json("PATCH", `/v1/admin/servers/${id}`, {
          expectedVersion: version - 1,
          label: "stale",
        })
      ).statusCode,
      409,
    );
    assert.equal(
      (
        await json("PATCH", `/v1/admin/servers/${id}`, {
          expectedVersion: version,
          publicIpv4: "127.0.0.1",
        })
      ).statusCode,
      400,
    );
    assert.equal(
      (
        await json("PATCH", `/v1/admin/servers/${id}`, {
          expectedVersion: version,
          state: "available",
        })
      ).statusCode,
      400,
    );
    const edited = await form(`/operator/inventory/servers/${id}/edit`, {
      expectedVersion: String(version),
      label: "Mail West",
      operatorContact: "new-ops@example.org",
      providerReference: "instance-2",
      publicIpv4: "8.8.8.8",
    });
    assert.equal(edited.statusCode, 200, edited.body);
    assert.equal(
      (await query(`SELECT state FROM servers WHERE id=${q(id)}`))[0][0],
      "pending_validation",
    );
    version = Number(
      (await query(`SELECT version FROM servers WHERE id=${q(id)}`))[0][0],
    );
    assert.equal(
      (
        await form(`/operator/inventory/servers/${id}/validate`, {
          expectedVersion: String(version),
        })
      ).statusCode,
      200,
    );
    assert.equal(probes, 2);
    version = Number(
      (await query(`SELECT version FROM servers WHERE id=${q(id)}`))[0][0],
    );
    assert.equal(
      (
        await json("DELETE", `/v1/admin/servers/${id}`, {
          expectedVersion: version,
          confirm: false,
        })
      ).statusCode,
      400,
    );
    const removeKey = randomUUID();
    const removeBody = { expectedVersion: version, confirm: true };
    const removed = await json(
      "DELETE",
      `/v1/admin/servers/${id}`,
      removeBody,
      "admin",
      removeKey,
    );
    assert.equal(removed.statusCode, 200, removed.body);
    assert.equal(removed.json().cloudResourceDeleted, false);
    assert.equal(
      (await query(`SELECT state FROM servers WHERE id=${q(id)}`))[0][0],
      "retired",
    );
    const replay = await json(
      "DELETE",
      `/v1/admin/servers/${id}`,
      removeBody,
      "admin",
      removeKey,
    );
    assert.deepEqual(
      { ...replay.json<Record<string, unknown>>(), requestId: null },
      { ...removed.json<Record<string, unknown>>(), requestId: null },
    );
    assert.equal(
      (
        await query(
          `SELECT count(*) FROM audit_events WHERE action='server.remove' AND target=${q(id)}`,
        )
      )[0][0],
      "1",
    );

    const fresh = await form("/operator/inventory/servers", {
      ...serverFields,
      label: "Assigned server",
      providerReference: "assigned-instance",
    });
    assert.equal(fresh.statusCode, 200);
    const assignedServer = (
      await query("SELECT id FROM servers WHERE state='available'")
    )[0][0];
    assert.deepEqual(await query(`SELECT label FROM servers WHERE id=${q(assignedServer)}`), [["s-2"]]);
    const org = randomUUID();
    await query(
      `INSERT INTO organizations(id,owner_user_id,name,status) VALUES(${q(org)},${q(admin.userId)},'Northstar Studio','active'); INSERT INTO server_assignments(id,organization_id,server_id,reason) VALUES(${q(randomUUID())},${q(org)},${q(assignedServer)},'Inventory test'); UPDATE servers SET state='assigned',tenant_tainted_at=now() WHERE id=${q(assignedServer)}`,
    );
    const assignedVersion = Number(
      (
        await query(`SELECT version FROM servers WHERE id=${q(assignedServer)}`)
      )[0][0],
    );
    assert.equal(
      (
        await json("DELETE", `/v1/admin/servers/${assignedServer}`, {
          expectedVersion: assignedVersion,
          confirm: true,
        })
      ).statusCode,
      409,
    );
    assert.equal(
      (
        await json("PATCH", `/v1/admin/servers/${assignedServer}`, {
          expectedVersion: assignedVersion,
          publicIpv4: "1.1.1.1",
        })
      ).statusCode,
      409,
    );
    assert.equal(
      (
        await json("PATCH", `/v1/admin/servers/${assignedServer}`, {
          expectedVersion: assignedVersion,
          label: "Renamed assigned server",
        })
      ).statusCode,
      200,
    );

    const apiKey = "API-key-private-CANARY-operator",
      smtpKey = "SMTP-key-private-CANARY-operator";
    const account = {
      loginEmail: "brevo@example.org",
      smtpLogin: "login@smtp-brevo.com",
      dailyLimit: "300",
      apiKey,
      smtpKey,
    };
    assert.equal(
      (
        await form(
          "/operator/inventory/brevo",
          account,
          "infrastructure_operator",
        )
      ).statusCode,
      403,
    );
    assert.equal(
      (await form("/operator/inventory/brevo", account)).statusCode,
      200,
    );
    const relayId = (await query("SELECT id FROM relay_connections"))[0][0];
    let relayVersion = Number(
      (
        await query(
          `SELECT version FROM relay_connections WHERE id=${q(relayId)}`,
        )
      )[0][0],
    );
    const oldApiRef = (
      await query(
        `SELECT api_secret_ref FROM relay_connections WHERE id=${q(relayId)}`,
      )
    )[0][0];
    const accountPage = await app.inject({
      url: "/operator?tab=brevo",
      headers: { authorization: "Bearer " + tokens.admin },
    });
    assert.ok(accountPage.body.includes("b-1"));
    for (const secret of [apiKey, smtpKey])
      assert.equal(accountPage.body.includes(secret), false);
    assert.ok(
      accountPage.body.includes("Leave blank to keep the existing key"),
    );
    const saveBlank = await form(`/operator/inventory/brevo/${relayId}/edit`, {
      ...account,
      apiKey: "",
      smtpKey: "",
      expectedVersion: String(relayVersion),
      label: "Brevo Updated",
      paused: "1",
    });
    assert.equal(saveBlank.statusCode, 200, saveBlank.body);
    assert.equal(
      (
        await query(
          `SELECT api_secret_ref FROM relay_connections WHERE id=${q(relayId)}`,
        )
      )[0][0],
      oldApiRef,
    );
    assert.equal(
      (
        await query(
          `SELECT state FROM relay_connections WHERE id=${q(relayId)}`,
        )
      )[0][0],
      "disabled",
    );
    relayVersion = Number(
      (
        await query(
          `SELECT version FROM relay_connections WHERE id=${q(relayId)}`,
        )
      )[0][0],
    );
    const replacement = "API-key-rotated-CANARY-operator";
    const rotated = await json(
      "PATCH",
      `/v1/admin/relay-connections/${relayId}`,
      { expectedVersion: relayVersion, apiKey: replacement, paused: false },
    );
    assert.equal(rotated.statusCode, 200, rotated.body);
    assert.equal(rotated.body.includes(replacement), false);
    assert.equal(
      (
        await query(`SELECT state FROM secret_refs WHERE id=${q(oldApiRef)}`)
      )[0][0],
      "retired",
    );
    const file = (
      await query(
        `SELECT s.file_name FROM relay_connections r JOIN secret_refs s ON s.id=r.api_secret_ref WHERE r.id=${q(relayId)}`,
      )
    )[0][0];
    const store = new SecretStore(secretsDir, loadSecretKey(secretKeyHex));
    assert.equal(JSON.parse(store.read(file)).apiKey, replacement);
    assert.equal(
      readFileSync(join(secretsDir, file)).includes(Buffer.from(replacement)),
      false,
    );
    relayVersion = rotated.json().version;
    const archived = await form(`/operator/inventory/brevo/${relayId}/remove`, {
      expectedVersion: String(relayVersion),
      confirm: "1",
    });
    assert.equal(archived.statusCode, 200, archived.body);
    assert.equal(
      (
        await query(
          `SELECT archived_at IS NOT NULL FROM relay_connections WHERE id=${q(relayId)}`,
        )
      )[0][0],
      "t",
    );
    relayVersion = Number(
      (
        await query(
          `SELECT version FROM relay_connections WHERE id=${q(relayId)}`,
        )
      )[0][0],
    );
    const restored = await form(
      `/operator/inventory/brevo/${relayId}/restore`,
      { expectedVersion: String(relayVersion) },
    );
    assert.equal(restored.statusCode, 200, restored.body);
    assert.equal(
      (
        await query(
          `SELECT state FROM relay_connections WHERE id=${q(relayId)}`,
        )
      )[0][0],
      "inactive",
    );
    await query(
      `INSERT INTO relay_assignments(id,organization_id,relay_connection_id) VALUES(${q(randomUUID())},${q(org)},${q(relayId)}); UPDATE relay_connections SET state='assigned' WHERE id=${q(relayId)}`,
    );
    relayVersion = Number(
      (
        await query(
          `SELECT version FROM relay_connections WHERE id=${q(relayId)}`,
        )
      )[0][0],
    );
    assert.equal(
      (
        await json("DELETE", `/v1/admin/relay-connections/${relayId}`, {
          expectedVersion: relayVersion,
          confirm: true,
        })
      ).statusCode,
      409,
    );
    assert.equal(
      (
        await json("PATCH", `/v1/admin/relay-connections/${relayId}`, {
          expectedVersion: relayVersion,
          smtpKey: "must-not-apply",
        })
      ).statusCode,
      409,
    );
    assert.equal(
      (
        await json("PATCH", `/v1/admin/relay-connections/${relayId}`, {
          expectedVersion: relayVersion,
          label: "Assigned account label",
          dailyLimit: 250,
        })
      ).statusCode,
      200,
    );
    assert.equal(
      (
        await json("PATCH", `/v1/admin/relay-connections/${relayId}`, {
          expectedVersion: relayVersion,
          assigned: false,
        })
      ).statusCode,
      400,
    );
    const usersOverview = await app.inject({
      url: "/v1/admin/portal",
      headers: { authorization: "Bearer " + tokens.admin },
    });
    assert.equal(usersOverview.statusCode, 200, usersOverview.body);
    const registered = usersOverview.json().users as Array<
      Record<string, unknown>
    >;
    assert.equal(new Set(registered.map((user) => user.id)).size, 4);
    const allocated = registered.find((user) => user.organizationId === org)!;
    assert.ok(allocated);
    assert.equal(allocated.email, "admin@recovery.example.org");
    assert.equal(allocated.serverId, assignedServer);
    assert.equal(allocated.relayId, relayId);
    assert.equal(allocated.relayLabel, "Assigned account label");
    const usersPage = await app.inject({
      url: "/operator?tab=users",
      headers: { authorization: "Bearer " + tokens.admin },
    });
    assert.equal(usersPage.statusCode, 200);
    assert.ok(usersPage.body.includes("Users & allocations"));
    assert.ok(usersPage.body.includes("admin@recovery.example.org"));
    assert.ok(
      usersPage.body.includes(
        'data-open-dialog="server-' + assignedServer + '"',
      ),
    );
    assert.ok(
      usersPage.body.includes('data-open-dialog="brevo-' + relayId + '"'),
    );
    assert.ok(usersPage.body.includes("customer@recovery.example.org"));
    assert.equal(usersPage.body.includes(apiKey), false);
    assert.equal(usersPage.body.includes(smtpKey), false);
    const supportUsers = await app.inject({
      url: "/operator?tab=users",
      headers: { authorization: "Bearer " + tokens.support },
    });
    assert.equal(supportUsers.statusCode, 200);
    assert.ok(supportUsers.body.includes("Users & allocations"));
    assert.equal(supportUsers.body.includes("Allocated Brevo account"), false);
    assert.equal(supportUsers.body.includes("Assigned account label"), false);
    const deniedUsers = await app.inject({
      url: "/operator?tab=users",
      headers: { authorization: "Bearer " + tokens.customer },
    });
    assert.equal(deniedUsers.statusCode, 403);
    // Run the real CLI request builder against the same authenticated API as the forms.
    const cliFetch: typeof fetch = async (url, options) => {
      const path = new URL(String(url)).pathname;
      const response = await app.inject({
        method: options?.method as "POST" | "GET",
        url: path,
        headers: options?.headers as Record<string, string>,
        ...(options?.body ? { payload: String(options.body) } : {}),
      });
      return new Response(response.body, {
        status: response.statusCode,
        headers: { "content-type": "application/json" },
      });
    };
    const cliConfig = {
      origin: "http://inventory.test",
      token: tokens.admin,
      fetch: cliFetch,
    };
    const serverFile = join(secretsDir, "new-server.json");
    writeFileSync(
      serverFile,
      JSON.stringify({
        label: "CLI server",
        publicIpv4: "9.9.9.9",
        profileCode: "e2-micro",
        operatorContact: "ops@example.org",
        preparationAttestations: {
          osPrepared: true,
          storagePrepared: true,
          firewallAttested: true,
          cleanHost: true,
          externalBackup: true,
        },
      }),
    );
    const cliServer = JSON.parse(
      await runInventory(
        [
          "servers",
          "add",
          "--file",
          serverFile,
          "--idempotency-key",
          "cli-server-key",
        ],
        cliConfig,
      ),
    );
    assert.equal(cliServer.state, "available");
    const sameCliServer = JSON.parse(
      await runInventory(
        [
          "servers",
          "add",
          "--file",
          serverFile,
          "--idempotency-key",
          "cli-server-key",
        ],
        cliConfig,
      ),
    );
    assert.equal(sameCliServer.serverId, cliServer.serverId);
    assert.ok(
      (await runInventory(["servers", "list"], cliConfig)).includes(
        "CLI server",
      ),
    );
    const brevoFile = join(secretsDir, "new-brevo.json");
    writeFileSync(
      brevoFile,
      JSON.stringify({
        label: "CLI Brevo",
        loginEmail: "cli@example.org",
        smtpLogin: "cli-smtp",
        apiKey: "cli-api-canary",
        smtpKey: "cli-smtp-canary",
        dailyLimit: 300,
      }),
      { mode: 0o600 },
    );
    const cliBrevoOutput = await runInventory(
      ["brevo", "add", "--file", brevoFile],
      cliConfig,
    );
    assert.equal(cliBrevoOutput.includes("cli-api-canary"), false);
    assert.equal(cliBrevoOutput.includes("cli-smtp-canary"), false);
    assert.equal(JSON.parse(cliBrevoOutput).state, "inactive");
    assert.ok(
      (await runInventory(["brevo", "list"], cliConfig)).includes(
        "cli@example.org",
      ),
    );
    const portalAfterCli = await app.inject({
      url: "/operator?tab=brevo",
      headers: { authorization: "Bearer " + tokens.admin },
    });
    assert.ok(portalAfterCli.body.includes("CLI Brevo"));
    assert.ok(portalAfterCli.body.includes("CLI server"));
    const automaticBrevoKey = randomUUID();
    const secondAutomaticBrevo = await json("POST", "/v1/admin/relay-connections", {
      ...account, dailyLimit: 300, loginEmail: "second@example.org",
    }, "admin", automaticBrevoKey);
    assert.equal(secondAutomaticBrevo.statusCode, 201, secondAutomaticBrevo.body);
    assert.equal(secondAutomaticBrevo.json().label, "b-2");
    const repeatedBrevo = await json("POST", "/v1/admin/relay-connections", {
      ...account, dailyLimit: 300, loginEmail: "second@example.org",
    }, "admin", automaticBrevoKey);
    assert.equal(repeatedBrevo.json().id, secondAutomaticBrevo.json().id);
    assert.deepEqual(await query("SELECT value FROM inventory_name_counters WHERE prefix='b'"), [["2"]]);

    await assert.rejects(
      runInventory(["servers", "add", "--file", brevoFile], cliConfig),
      /Invalid inventory fields/,
    );
    await assert.rejects(
      runInventory(["brevo", "add", "--file", brevoFile], {
        ...cliConfig,
        token: tokens.customer,
      }),
      /HTTP 403/,
    );
    const agedToken = async (minutes: number, totp = true) =>
      new SignJWT({
        email: "admin@recovery.example.org",
        email_verified: true,
        auth_time: Math.floor(Date.now() / 1000) - minutes * 60,
        amr: totp ? ["pwd", "totp"] : ["pwd"],
      })
        .setSubject("inventory-admin")
        .setProtectedHeader({ alg: "RS256" })
        .setIssuer(issuer)
        .setAudience(audience)
        .setIssuedAt()
        .setExpirationTime("3h")
        .sign(pair.privateKey);
    const inventoryPatch = async (token: string) =>
      app.inject({
        method: "PATCH",
        url: `/v1/admin/servers/${cliServer.serverId}`,
        headers: {
          authorization: "Bearer " + token,
          "idempotency-key": randomUUID(),
        },
        payload: {
          expectedVersion: cliServer.version,
          label: "MFA window checked",
        },
      });
    const withinWindow = await agedToken(119);
    const acceptedInventory = await inventoryPatch(withinWindow);
    assert.equal(acceptedInventory.statusCode, 200, acceptedInventory.body);
    for (const token of [await agedToken(121), await agedToken(1, false)]) {
      const deniedInventory = await inventoryPatch(token);
      assert.equal(deniedInventory.statusCode, 403);
      assert.equal(deniedInventory.json().error.code, "MFA_REQUIRED");
    }
    const acceptedForm = await app.inject({
      method: "POST",
      url: `/operator/inventory/servers/${cliServer.serverId}/edit`,
      headers: {
        authorization: "Bearer " + withinWindow,
        accept: "application/json",
        "content-type": "application/x-www-form-urlencoded",
      },
      payload: new URLSearchParams({
        csrf: "1",
        idempotencyKey: randomUUID(),
        expectedVersion: String(acceptedInventory.json().version),
        label: "MFA form checked",
        publicIpv4: "9.9.9.9",
        operatorContact: "ops@example.org",
        providerReference: "",
      }).toString(),
    });
    assert.equal(acceptedForm.statusCode, 200, acceptedForm.body);
    const otherOperation = await app.inject({
      method: "POST",
      url: "/v1/admin/invitations",
      headers: {
        authorization: "Bearer " + withinWindow,
        "idempotency-key": randomUUID(),
      },
      payload: { boundEmail: "another@example.org", expiresInHours: 1 },
    });
    assert.equal(otherOperation.statusCode, 403);
    assert.equal(otherOperation.json().error.code, "MFA_REQUIRED");
    for (const secret of [apiKey, smtpKey, replacement]) {
      assert.equal(
        (
          await app.inject({
            url: "/operator?tab=brevo",
            headers: { authorization: "Bearer " + tokens.admin },
          })
        ).body.includes(secret),
        false,
      );
      assert.equal(Buffer.concat(logs).toString().includes(secret), false);
      assert.equal(
        (
          await query(
            "SELECT coalesce(string_agg(redacted_diff::text,''),'') FROM audit_events",
          )
        )[0][0].includes(secret),
        false,
      );
    }
    const infraPage = await app.inject({
      url: "/operator?tab=brevo",
      headers: { authorization: "Bearer " + tokens.infrastructure_operator },
    });
    assert.equal(
      infraPage.body.includes('data-open-dialog="add-brevo"'),
      false,
    );
    assert.ok(infraPage.body.includes("Read-only access"));
    failSsh=true;
    const beforeFailure=probes;
    const failedAdd=await form("/operator/inventory/servers",{...serverFields,label:"Failed SSH server",publicIpv4:"203.0.113.199",providerReference:"failed-ssh-test"});
    assert.equal(failedAdd.statusCode,200,failedAdd.body);
    assert.equal(probes,beforeFailure+1,"server addition runs the SSH probe without a separate validate request");
    const failedPage=await app.inject({url:"/operator",headers:{authorization:"Bearer "+tokens.admin}});
    assert.match(failedPage.body,/SSH check failed/);
    assert.match(failedPage.body,/host key differs from the saved key/);
    assert.match(failedPage.body,/server.host_key_mismatch/);
    assert.deepEqual(await query("SELECT state FROM servers WHERE provider_reference='failed-ssh-test'"),[["pending_validation"]]);

  } finally {
    await app.close();
  }
});
