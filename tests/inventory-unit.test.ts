import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { AddressError, assertPublicUnicastIpv4 } from "../packages/servers/src/address.ts";
import { parseCommand } from "../packages/servers/src/commands.ts";
import { readinessFailures, type HostReport } from "../packages/servers/src/readiness.ts";
import { SSH_LOGIN_USER, sshInstallPlan, sshReadinessCommands } from "../packages/servers/src/ssh-install.ts";
import { classifySshFailure, interpretSshProbe } from "../packages/servers/src/ssh-probe.ts";
import { heartbeatMessage } from "../packages/servers/src/signature.ts";

const report: HostReport = {
  os: "linux",
  init: "systemd",
  architecture: "x64",
  memoryMb: 1024,
  diskGb: 20,
  dataPathMounted: true,
  reachable: true,
  relayReachable: true,
  priorTenantData: false,
  supervisorVersion: "1",
};

function ready(overrides: Partial<Parameters<typeof readinessFailures>[0]> = {}): string[] {
  return readinessFailures({
    profileCode: "e2-micro",
    identityConfirmed: true,
    lastHeartbeatAt: new Date(),
    report,
    now: new Date(),
    ...overrides,
  });
}

describe("inventory units", () => {
  it("accepts only public unicast IPv4 addresses", () => {
    assert.equal(assertPublicUnicastIpv4(" 203.0.113.10 "), "203.0.113.10");
    assert.equal(assertPublicUnicastIpv4("192.0.2.1"), "192.0.2.1");
    for (const value of [
      "10.1.2.3",
      "127.0.0.1",
      "192.168.1.1",
      "172.16.0.1",
      "100.64.0.1",
      "169.254.169.254",
      "0.0.0.0",
      "224.0.0.1",
      "255.255.255.255",
      "203.0.113.010",
      "203.0.113",
      "not-an-ip",
    ]) {
      assert.throws(() => assertPublicUnicastIpv4(value), AddressError);
    }
    assert.throws(() => assertPublicUnicastIpv4("203.0.113.10", ["203.0.113.10"]), AddressError);
  });

  it("reports precise readiness failures and ignores firewall attestation", () => {
    const now = new Date("2026-11-02T12:00:00.000Z");
    assert.deepEqual(
      readinessFailures({ profileCode: "e2-micro", identityConfirmed: false, lastHeartbeatAt: null, report: null, now }),
      ["server.fingerprint_unconfirmed", "server.readiness_missing"],
    );
    assert.deepEqual(ready(), []);
    assert.deepEqual(
      ready({ lastHeartbeatAt: new Date(now.getTime() - 3 * 60 * 1000), now }),
      ["server.heartbeat_stale"],
    );
    assert.deepEqual(ready({ profileCode: "e2-small" }), ["server.incompatible_profile"]);
    assert.deepEqual(ready({ report: { ...report, memoryMb: 512 } }), ["server.incompatible_profile"]);
    assert.deepEqual(ready({ report: { ...report, reachable: false } }), ["server.unreachable"]);
    assert.deepEqual(ready({ report: { ...report, relayReachable: false } }), ["server.relay_unreachable"]);
    assert.deepEqual(ready({ report: { ...report, dataPathMounted: false } }), []);
    assert.deepEqual(ready({ report: { ...report, priorTenantData: true } }), ["server.readiness_missing"]);
    assert.deepEqual(
      ready({ report: { ...report, dataPathMounted: false, priorTenantData: true } }),
      ["server.readiness_missing"],
    );
    const missing = readinessFailures({
      profileCode: "e2-micro",
      identityConfirmed: false,
      lastHeartbeatAt: null,
      report: null,
      now,
    });
    assert.equal(missing.includes("server.heartbeat_stale"), false);
    assert.equal(missing.includes("server.unreachable"), false);
  });

  it("allowlists host commands and rejects a shell", () => {
    assert.deepEqual(parseCommand("probe_readiness", {}), { scope: "inventory", commandType: "probe_readiness", parameters: {} });
    assert.equal(parseCommand("probe_services", { extra: true }), null);
    assert.deepEqual(parseCommand("install_release", { releaseId: "rel-1" }), {
      scope: "tenant",
      commandType: "install_release",
      parameters: { releaseId: "rel-1" },
    });
    assert.equal(parseCommand("install_release", {}), null);
    assert.equal(parseCommand("upgrade_release", { releaseId: "rel-1", shell: "sh" }), null);
    assert.equal(parseCommand("bash", {}), null);
    assert.equal(parseCommand("shell.exec", {}), null);
    assert.equal(parseCommand("probe_readiness", []), null);
  });

  it("can explicitly bypass host identity for test probes, commands and file transfers", () => {
    const endpoint={host:"203.0.113.10",privateKeyFile:"/var/lib/bearportal/ssh/id_ed25519",knownHostsFile:"/var/lib/bearportal/ssh/known_hosts",acceptNewHostKey:false,skipHostKeyVerification:true};
    const plan=sshInstallPlan({endpoint,operationId:"8d0b6b6e-1c0a-4e0a-9c1a-6c0e5b7a1111",localInput:"/tmp/input.json",localDns:"/tmp/dns.json",localRelay:"/tmp/relay.json",localAdmin:"/tmp/admin.json",localInstaller:"/tmp/bearmail-install",localResult:"/tmp/result.json"});
    for(const args of [...sshReadinessCommands(endpoint),plan.dryRun,plan.apply,plan.copyInput,plan.fetchResult]){
      assert.ok(args.includes("StrictHostKeyChecking=no"));
      assert.ok(args.includes("UserKnownHostsFile=/dev/null"));
      assert.ok(args.includes("GlobalKnownHostsFile=/dev/null"));
      assert.ok(args.includes(endpoint.privateKeyFile));
      assert.equal(args.includes("StrictHostKeyChecking=accept-new"),false);
    }
    assert.ok(sshReadinessCommands({...endpoint,skipHostKeyVerification:false})[0].includes("StrictHostKeyChecking=yes"));
  });

  it("plans an SSH install as fixed arguments", () => {
    const plan = sshInstallPlan({
      endpoint: {
        host: "203.0.113.10",
        privateKeyFile: "/var/lib/bearportal/ssh/id_ed25519",
        knownHostsFile: "/var/lib/bearportal/ssh/known_hosts",
        acceptNewHostKey: false,
      },
      operationId: "8d0b6b6e-1c0a-4e0a-9c1a-6c0e5b7a1111",
      localInput: "/var/lib/bearportal/work/input.json",
      localDns: "/var/lib/bearportal/work/dns.json",
      localRelay: "/var/lib/bearportal/work/relay.json",
      localAdmin: "/var/lib/bearportal/work/admin.json",
      localInstaller: "/var/lib/bearportal/work/bearmail-install",
      localResult: "/var/lib/bearportal/work/result.json",
    });
    assert.equal(plan.remoteDir, "/var/lib/bearportal/install/8d0b6b6e-1c0a-4e0a-9c1a-6c0e5b7a1111");
    assert.deepEqual(plan.probes.map((args) => args.slice(-2)), [
      ["uname", "-s"],
      ["uname", "-m"],
      ["-f", "/proc/1/exe"],
      ["cat", "/proc/meminfo"],
      ["-B1", "/"],
      ["-A", "/var/lib/stalwart"],
    ]);
    assert.equal(plan.probes.some((args) => args.includes("mkdir") || args.includes("/bin/sh")), false);
    assert.equal(plan.restrictFiles.includes("chmod"), true);
    assert.equal(plan.restrictFiles.includes("0600"), true);
    assert.equal(plan.dryRun.includes("--dry-run"), true);
    assert.equal(plan.apply.includes("--dry-run"), false);
    const remoteInstaller = "/var/lib/bearportal/install/8d0b6b6e-1c0a-4e0a-9c1a-6c0e5b7a1111/bearmail-install";
    assert.equal(plan.apply.filter((arg) => arg === remoteInstaller).length, 1);
    assert.equal(plan.apply.includes("/usr/local/bin/bearmail-install"), false);
    assert.equal(plan.copyInstaller.at(-1), `203.0.113.10:${remoteInstaller}`);
    assert.equal(plan.restrictInstaller.includes("0700"), true);
    assert.equal(plan.restrictInstaller.at(-1), remoteInstaller);
    assert.equal(plan.dryRun.includes("sudo"), true);
    assert.equal(plan.dryRun.includes("-n"), true);
    assert.equal(plan.makeDir.includes("-o"), true);
    assert.equal(plan.makeDir.includes(SSH_LOGIN_USER), true);
    assert.equal(plan.releaseResult.at(-1), "/var/lib/bearportal/install/8d0b6b6e-1c0a-4e0a-9c1a-6c0e5b7a1111/result.json");
    assert.equal(plan.dryRun.includes("StrictHostKeyChecking=yes"), true);
    assert.equal(plan.dryRun.includes(SSH_LOGIN_USER), true);
    assert.equal(plan.copyInput.includes(`User=${SSH_LOGIN_USER}`), true);
    assert.equal(plan.dryRun.includes("root"), false);
    assert.equal(plan.copyInput.includes("root"), false);
    assert.equal(plan.fetchResult.at(-1), "/var/lib/bearportal/work/result.json");
    assert.equal(plan.copyInput.at(-1), "203.0.113.10:/var/lib/bearportal/install/8d0b6b6e-1c0a-4e0a-9c1a-6c0e5b7a1111/input.json");
    assert.equal(plan.copyRelease.length, 0);
    assert.equal(plan.makeReleaseDir.length, 0);
    assert.throws(() => sshInstallPlan({
      endpoint: {
        host: "10.1.2.3",
        privateKeyFile: "/var/lib/bearportal/ssh/id_ed25519",
        knownHostsFile: "/var/lib/bearportal/ssh/known_hosts",
        acceptNewHostKey: false,
      },
      operationId: "8d0b6b6e-1c0a-4e0a-9c1a-6c0e5b7a1111",
      localInput: "/var/lib/bearportal/work/input.json",
      localDns: "/var/lib/bearportal/work/dns.json",
      localRelay: "/var/lib/bearportal/work/relay.json",
      localAdmin: "/var/lib/bearportal/work/admin.json",
      localInstaller: "/var/lib/bearportal/work/bearmail-install",
      localResult: "/var/lib/bearportal/work/result.json",
    }));
    assert.throws(() => sshInstallPlan({
      endpoint: {
        host: "203.0.113.10",
        privateKeyFile: "/tmp/key;rm",
        knownHostsFile: "/var/lib/bearportal/ssh/known_hosts",
        acceptNewHostKey: false,
      },
      operationId: "8d0b6b6e-1c0a-4e0a-9c1a-6c0e5b7a1111",
      localInput: "/var/lib/bearportal/work/input.json",
      localDns: "/var/lib/bearportal/work/dns.json",
      localRelay: "/var/lib/bearportal/work/relay.json",
      localAdmin: "/var/lib/bearportal/work/admin.json",
      localInstaller: "/var/lib/bearportal/work/bearmail-install",
      localResult: "/var/lib/bearportal/work/result.json",
    }));
    assert.throws(() => sshInstallPlan({
      endpoint: {
        host: "203.0.113.10",
        privateKeyFile: "/var/lib/bearportal/ssh/id_ed25519",
        knownHostsFile: "/var/lib/bearportal/ssh/known_hosts",
        acceptNewHostKey: false,
      },
      operationId: "8d0b6b6e-1c0a-4e0a-9c1a-6c0e5b7a1111",
      localInput: "/var/lib/bearportal/work/input.json",
      localDns: "/var/lib/bearportal/work/dns.json",
      localRelay: "/var/lib/bearportal/work/relay.json",
      localAdmin: "/var/lib/bearportal/work/admin.json",
      localInstaller: "/var/lib/bearportal/work/install.sh",
      localResult: "/var/lib/bearportal/work/result.json",
    }));
  });

  it("reads a server with the fixed SSH readiness commands", () => {
    const commands = sshReadinessCommands({
      host: "203.0.113.10",
      privateKeyFile: "/var/lib/bearportal/ssh/id_ed25519",
      knownHostsFile: "/var/lib/bearportal/ssh/known_hosts",
      acceptNewHostKey: true,
    });
    assert.deepEqual(commands.map((args) => args.slice(-2)), [
      ["uname", "-s"],
      ["uname", "-m"],
      ["-f", "/proc/1/exe"],
      ["cat", "/proc/meminfo"],
      ["-B1", "/"],
      ["-A", "/var/lib/stalwart"],
    ]);
    assert.equal(commands.every((args) => args.includes("ConnectTimeout=10")), true);
    assert.equal(commands.every((args) => args.includes(SSH_LOGIN_USER)), true);
    assert.equal(commands.every((args) => args.includes("sudo") && args.includes("-n")), true);
    assert.equal(commands.some((args) => args.includes("root")), false);
    assert.equal(commands.some((args) => args.includes("sh") || args.includes("mkdir")), false);
    const ready = interpretSshProbe({
      unameS: { code: 0, stdout: "Linux\n", stderr: "" },
      unameM: { code: 0, stdout: "x86_64\n", stderr: "" },
      init: { code: 0, stdout: "/usr/lib/systemd/systemd\n", stderr: "" },
      meminfo: { code: 0, stdout: "MemTotal:        2048000 kB\n", stderr: "" },
      df: { code: 0, stdout: "Filesystem 1B-blocks Used Available Use% Mounted on\n/dev/root 21474836480 1 1 1% /\n", stderr: "" },
      dataPath: { code: 2, stdout: "", stderr: "ls: cannot access '/var/lib/stalwart': No such file or directory\n" },
      hostKeyFingerprint: "SHA256:hcAgpVkhTpd/Zt8zhxgzQi2LF1TxQbyzDUHec+hU8BI",
    });
    assert.equal(ready.ok, true);
    assert.equal(ready.report?.memoryMb, 2000);
    assert.equal(ready.report?.diskGb, 20);
    assert.equal(ready.report?.dataPathMounted, false);
    const occupied = interpretSshProbe({
      unameS: { code: 0, stdout: "Linux\n", stderr: "" },
      unameM: { code: 0, stdout: "x86_64\n", stderr: "" },
      init: { code: 0, stdout: "/usr/lib/systemd/systemd\n", stderr: "" },
      meminfo: { code: 0, stdout: "MemTotal:        2048000 kB\n", stderr: "" },
      df: { code: 0, stdout: "Filesystem 1B-blocks Used Available Use% Mounted on\n/dev/root 21474836480 1 1 1% /\n", stderr: "" },
      dataPath: { code: 0, stdout: "data\n", stderr: "" },
      hostKeyFingerprint: null,
    });
    assert.equal(occupied.ok, false);
    assert.deepEqual(occupied.failures, ["server.readiness_missing"]);
    const smallDisk = interpretSshProbe({
      unameS: { code: 0, stdout: "Linux\n", stderr: "" },
      unameM: { code: 0, stdout: "x86_64\n", stderr: "" },
      init: { code: 0, stdout: "/usr/lib/systemd/systemd\n", stderr: "" },
      meminfo: { code: 0, stdout: "MemTotal:         921600 kB\n", stderr: "" },
      df: { code: 0, stdout: "Filesystem 1B-blocks Used Available Use% Mounted on\n/dev/root 10737418240 1 1 1% /\n", stderr: "" },
      dataPath: { code: 2, stdout: "", stderr: "ls: cannot access '/var/lib/stalwart': No such file or directory\n" },
      hostKeyFingerprint: null,
    });
    assert.equal(smallDisk.ok, false);
    assert.equal(smallDisk.report?.memoryMb, 900);
    assert.equal(smallDisk.report?.diskGb, 10);
    assert.deepEqual(smallDisk.failures, ["server.incompatible_profile"]);
    assert.equal(classifySshFailure("Permission denied (publickey)."), "server.ssh_auth_failed");
    assert.equal(classifySshFailure("Host key verification failed."), "server.host_key_mismatch");
    assert.equal(classifySshFailure("sudo: a password is required"), "server.sudo_failed");
  });

  it("canonicalizes the heartbeat with sorted keys", () => {
    const message = heartbeatMessage({
      serverId: "server-1",
      authEpoch: 2,
      observedAt: "2026-11-02T12:00:00.000Z",
      readiness: { b: true, a: { d: 1, c: 2 } },
    });
    assert.equal(
      message,
      '{"authEpoch":2,"observedAt":"2026-11-02T12:00:00.000Z","readiness":{"a":{"c":2,"d":1},"b":true},"serverId":"server-1"}',
    );
  });
});
