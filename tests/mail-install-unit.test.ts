import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { installDomainBlock, sshIdentityAllowsInstall, InstallerUnavailableError } from "../packages/servers/src/installer.ts";
import { SSH_LOGIN_USER, sshInstallPlan } from "../packages/servers/src/ssh-install.ts";
import {
  BearmailArtifactError,
  liveMailInstall,
  prepareBearmailTree,
  rewriteInstallerInput,
} from "../packages/servers/src/mail-install.ts";

const COMMIT = "4020f666b5070df84480b79c0bdfdf78dbadd614";
const OPERATION = "8d0b6b6e-1c0a-4e0a-9c1a-6c0e5b7a1111";
const TOKEN = "gd-token-value";
const SMTP_KEY = "smtp-secret-value";
const ADMIN_PASSWORD = "admin-secret-value";

function scriptBytes(): Buffer {
  return Buffer.from(`#!/usr/bin/env python3\n# bearmail-install\n${"p".repeat(80)}\n`);
}

function releaseBytes(): Map<string, Buffer> {
  const install = Buffer.from(`#!/bin/sh\n# BEARMAIL_EASY\n${"a".repeat(10_000)}`);
  const stalwart = Buffer.alloc(1_000_000, 0);
  stalwart[0] = 0x7f;
  stalwart[1] = 0x45;
  stalwart[2] = 0x4c;
  stalwart[3] = 0x46;
  stalwart[18] = 0x3e;
  stalwart[19] = 0x00;
  const webui = Buffer.alloc(10_000, 0);
  webui[0] = 0x1f;
  webui[1] = 0x8b;
  const mcp = Buffer.from(`#!/bin/sh\nbearmail-mcp\nmcp_src="$RETVAL"\n${"m".repeat(1000)}\n`);
  return new Map([
    ["bearmail-install", scriptBytes()],
    ["install.sh", install],
    ["stalwart", stalwart],
    ["bearmail-webui.tar.gz", webui],
    ["mcp_install.sh", mcp],
  ]);
}

function transportFor(files: Map<string, Buffer>) {
  const urls: string[] = [];
  return {
    urls,
    async transport(url: string): Promise<{ status: number; body: Buffer }> {
      urls.push(url);
      const name = url.slice(url.lastIndexOf("/") + 1);
      const body = files.get(name);
      if (!url.startsWith(`https://raw.githubusercontent.com/luoxiprovo/bearmail/${COMMIT}/`) || !body) {
        throw new Error("unexpected url");
      }
      return { status: 200, body };
    },
  };
}

describe("mail install", () => {
  it("keeps the old gates unless the server was probed or the source install is configured", () => {
    assert.equal(installDomainBlock({ state: "pending", hasCredential: false, sourceInstall: true }), "domain.unverified");
    assert.equal(installDomainBlock({ state: "verified", hasCredential: false, sourceInstall: true }), "dns.credential_required");
    assert.equal(installDomainBlock({ state: "pending", hasCredential: true, sourceInstall: false }), "domain.unverified");
    assert.equal(installDomainBlock({ state: "pending", hasCredential: true, sourceInstall: true }), "ok");
    assert.equal(installDomainBlock({ state: "verified", hasCredential: true, sourceInstall: false }), "ok");
    assert.equal(sshIdentityAllowsInstall(null, null), false);
    assert.equal(sshIdentityAllowsInstall("pending", "heartbeat"), false);
    assert.equal(sshIdentityAllowsInstall(null, "ssh"), true);
    assert.equal(sshIdentityAllowsInstall("confirmed", null), true);
  });

  it("downloads the four release files for one commit and rejects an LFS pointer", async () => {
    const directory = mkdtempSync(join(tmpdir(), "bearportal-mail-tree-"));
    try {
      const good = transportFor(releaseBytes());
      const prepared = await prepareBearmailTree({ commit: COMMIT, directory, transport: good.transport });
      assert.equal(prepared.artifactDir, join(directory, COMMIT));
      assert.equal(good.urls.length, 5);
      const sums = readFileSync(join(prepared.artifactDir, "SHA256SUMS"), "utf8");
      assert.match(sums, /^[0-9a-f]{64}  install\.sh$/m);
      assert.match(sums, /^[0-9a-f]{64}  stalwart$/m);
      assert.equal(sums.includes(TOKEN), false);
      const pointer = releaseBytes();
      const stale = Buffer.alloc(1_000_000, 0);
      stale.write("version https://git-lfs.github.com/spec/v1\n");
      pointer.set("stalwart", stale);
      const bad = transportFor(pointer);
      await assert.rejects(
        prepareBearmailTree({ commit: COMMIT, directory: join(directory, "bad"), transport: bad.transport }),
        (error: unknown) => error instanceof BearmailArtifactError && error.code === "ARTIFACT_MISSING",
      );
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it("plans the release copy and runs bearmail-install with absolute credential paths", async () => {
    const releaseDir = `/var/lib/bearportal/work/${COMMIT}`;
    const plan = sshInstallPlan({
      endpoint: {
        host: "203.0.113.10",
        privateKeyFile: "/var/lib/bearportal/ssh/id_ed25519",
        knownHostsFile: "/var/lib/bearportal/ssh/known_hosts",
        acceptNewHostKey: false,
      },
      operationId: OPERATION,
      localInput: "/var/lib/bearportal/work/input.json",
      localDns: "/var/lib/bearportal/work/dns.json",
      localRelay: "/var/lib/bearportal/work/relay.json",
      localAdmin: "/var/lib/bearportal/work/admin.json",
      localInstaller: "/var/lib/bearportal/work/bearmail-install",
      localResult: "/var/lib/bearportal/work/result.json",
      localReleaseDir: releaseDir,
    });
    const remoteRelease = `/var/lib/bearportal/install/${OPERATION}/${COMMIT}`;
    assert.equal(plan.copyRelease.length, 5);
    assert.equal(plan.copyRelease.some((args) => args.at(-1) === `203.0.113.10:${remoteRelease}/stalwart`), true);
    assert.equal(plan.copyRelease.some((args) => args.at(-1) === `203.0.113.10:${remoteRelease}/SHA256SUMS`), true);
    assert.equal(plan.makeReleaseDir.includes(remoteRelease), true);
    assert.equal(plan.restrictRelease.some((args) => args.includes("0755") && args.includes(`${remoteRelease}/stalwart`)), true);
    assert.equal(plan.dryRun.includes("root"), false);
    assert.equal(plan.copyRelease.some((args) => args.includes("root")), false);
    assert.equal(plan.dryRun.includes(SSH_LOGIN_USER), true);

    const root = mkdtempSync(join(tmpdir(), "bearportal-mail-run-"));
    const keyFile = join(root, "id_ed25519");
    writeFileSync(keyFile, "not-a-real-key\n", { mode: 0o600 });
    const calls: string[][] = [];
    let copied = "";
    const runner = liveMailInstall({
      privateKeyFile: keyFile,
      knownHostsFile: join(root, "known_hosts"),
      workRoot: join(root, "work"),
      transport: transportFor(releaseBytes()).transport,
      async readSecret(secretId: string): Promise<string> {
        if (secretId.startsWith("11111111")) return JSON.stringify({ token: TOKEN });
        if (secretId.startsWith("22222222")) return JSON.stringify({ smtpKey: SMTP_KEY });
        return JSON.stringify({ username: "admin@asdfs.site", password: ADMIN_PASSWORD });
      },
      async spawn(args) {
        calls.push(args);
        const source = args.find((arg) => arg.startsWith(root) && arg.endsWith("/input.json"));
        if (source) copied = readFileSync(source, "utf8");
        const destination = args.at(-1) ?? "";
        if (args[0] === "scp" && destination.startsWith(root) && destination.endsWith("/result.json")) {
          writeFileSync(destination, JSON.stringify({
            status: "dry_run",
            errorCode: null,
            retryable: false,
            dns: { previousMx: [], published: [], minimumTtl: 600, engineDkimHost: null, engineDkimValue: null },
          }));
        }
        if (args.includes("a password is required")) return { code: 1, stdout: "", stderr: "a password is required" };
        return { code: 0, stdout: "", stderr: "" };
      },
    });
    try {
      const result = await runner.run({
        mode: "dry_run",
        input: installerSample(),
      });
      assert.equal((result as { status: string }).status, "dry_run");
      assert.equal((result as { exitCode: number }).exitCode, 0);
      assert.equal((result as { retryable: boolean }).retryable, false);
      const remote = JSON.parse(copied) as {
        dns: { credentialFile: string };
        relay: { credentialFile: string };
        adminCredentialFile: string;
        release: { id: string; artifactDir: string; checksumFile: string };
      };
      assert.equal(remote.dns.credentialFile, `/var/lib/bearportal/install/${OPERATION}/dns.json`);
      assert.equal(remote.relay.credentialFile, `/var/lib/bearportal/install/${OPERATION}/relay.json`);
      assert.equal(remote.adminCredentialFile, `/var/lib/bearportal/install/${OPERATION}/admin.json`);
      assert.equal(remote.release.id, COMMIT);
      assert.equal(remote.release.artifactDir, `/var/lib/bearportal/install/${OPERATION}/${COMMIT}`);
      assert.equal(remote.release.checksumFile, `/var/lib/bearportal/install/${OPERATION}/${COMMIT}/SHA256SUMS`);
      assert.equal(copied.includes(TOKEN), false);
      assert.equal(copied.includes(SMTP_KEY), false);
      assert.equal(copied.includes(ADMIN_PASSWORD), false);
      assert.equal(copied.includes("secret:"), false);
      const flat = calls.flat();
      assert.equal(flat.includes("--dry-run"), true);
      assert.equal(flat.includes("--input"), true);
      assert.equal(flat.includes("sudo"), true);
      assert.equal(flat.includes("-n"), true);
      assert.equal(flat.includes("root"), false);
      assert.equal(flat.some((arg) => arg.endsWith("/bearmail-install")), true);
      assert.equal(flat.includes("/usr/local/bin/bearmail-install"), false);
      assert.equal(flat.some((arg) => arg.includes(TOKEN) || arg.includes(SMTP_KEY) || arg.includes(ADMIN_PASSWORD)), false);
      assert.equal(existsSync(join(root, "work", OPERATION)), false);
      const rewritten = rewriteInstallerInput(installerSample(), `/var/lib/bearportal/install/${OPERATION}`);
      assert.equal((rewritten.release as { artifactDir: string }).artifactDir.endsWith(`/${COMMIT}`), true);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("fails closed when the control-plane key is missing and when sudo is refused", async () => {
    const root = mkdtempSync(join(tmpdir(), "bearportal-mail-fail-"));
    try {
      await assert.rejects(
        liveMailInstall({
          privateKeyFile: join(root, "missing-key"),
          workRoot: join(root, "work"),
          async readSecret() { return "{}"; },
          async spawn() { return { code: 0, stdout: "", stderr: "" }; },
        }).run({ mode: "dry_run", input: installerSample() }),
        InstallerUnavailableError,
      );
      const keyFile = join(root, "id_ed25519");
      writeFileSync(keyFile, "not-a-real-key\n", { mode: 0o600 });
      const calls: string[][] = [];
      const refused = await liveMailInstall({
        privateKeyFile: keyFile,
        knownHostsFile: join(root, "known_hosts"),
        workRoot: join(root, "work"),
        transport: transportFor(releaseBytes()).transport,
        async readSecret(secretId: string): Promise<string> {
          if (secretId.startsWith("11111111")) return JSON.stringify({ token: TOKEN });
          if (secretId.startsWith("22222222")) return JSON.stringify({ smtpKey: SMTP_KEY });
          return JSON.stringify({ username: "admin@asdfs.site", password: ADMIN_PASSWORD });
        },
        async spawn(args) {
          calls.push(args);
          return { code: 1, stdout: "", stderr: "a password is required" };
        },
      }).run({ mode: "dry_run", input: installerSample() });
      assert.equal((refused as { errorCode: string }).errorCode, "server.sudo_failed");
      assert.equal(calls.flat().includes("--dry-run"), false);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});

function installerSample(): Record<string, unknown> {
  return {
    schemaVersion: 1,
    operationId: OPERATION,
    deploymentId: "8d0b6b6e-1c0a-4e0a-9c1a-6c0e5b7a2222",
    generation: 1,
    mxCutoverAuthorized: true,
    domain: "asdfs.site",
    mailHostname: "mail.asdfs.site",
    webmailHostname: "webmail.asdfs.site",
    publicIpv4: "203.0.113.10",
    publicIpv6: null,
    dataPath: "/var/lib/stalwart",
    dns: { provider: "godaddy", zone: "asdfs.site", credentialFile: "secret:11111111-1111-4111-8111-111111111111" },
    brevoDnsRecords: [
      { purpose: "brevo_code", type: "TXT", host: "@", value: "brevo-code:example" },
      { purpose: "dkim", type: "TXT", host: "mail._domainkey", value: "k=rsa;p=example" },
      { purpose: "dmarc", type: "TXT", host: "_dmarc", value: "v=DMARC1; p=none" },
    ],
    relay: {
      host: "smtp-relay.brevo.com",
      port: 587,
      tls: "starttls-required",
      login: "login@smtp-brevo.com",
      credentialFile: "secret:22222222-2222-4222-8222-222222222222",
    },
    adminCredentialFile: "secret:33333333-3333-4333-8333-333333333333",
    mailboxQuotaBytes: 1073741824,
    release: {
      id: COMMIT,
      artifactDir: "/var/lib/bearportal/releases/ignored",
      checksumFile: "/var/lib/bearportal/releases/ignored/SHA256SUMS",
    },
  };
}
