import { basename, join } from "node:path";
import { assertPublicUnicastIpv4 } from "./address.ts";
import { RELEASE_FILES } from "./installer.ts";

const OPERATION_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

/** Login account on every mail server. The control-plane private key stays local. */
export const SSH_LOGIN_USER = "bearadmin";

export type SshEndpoint = {
  host: string;
  privateKeyFile: string;
  knownHostsFile: string;
  acceptNewHostKey: boolean;
};

export type SshInstallPlan = {
  remoteDir: string;
  probes: string[][];
  makeDir: string[];
  copyInput: string[];
  copyDns: string[];
  copyRelay: string[];
  copyAdmin: string[];
  copyInstaller: string[];
  copyRelease: string[][];
  makeReleaseDir: string[];
  restrictFiles: string[];
  restrictInstaller: string[];
  restrictRelease: string[][];
  dryRun: string[];
  apply: string[];
  fetchResult: string[];
  releaseResult: string[];
  removeRemoteDir: string[];
};

/** Fixed SSH argument lists for one install. This module does not open a connection. */
export function sshInstallPlan(input: {
  endpoint: SshEndpoint;
  operationId: string;
  localInput: string;
  localDns: string;
  localRelay: string;
  localAdmin: string;
  localInstaller: string;
  localResult: string;
  localReleaseDir?: string;
}): SshInstallPlan {
  const host = assertPublicUnicastIpv4(input.endpoint.host);
  const operationId = input.operationId.toLowerCase();
  if (!OPERATION_ID.test(operationId)) {
    throw new Error("The installer operation id is not a UUID.");
  }
  const remoteDir = `/var/lib/bearportal/install/${operationId}`;
  const remoteInput = `${remoteDir}/input.json`;
  const remoteDns = `${remoteDir}/dns.json`;
  const remoteRelay = `${remoteDir}/relay.json`;
  const remoteAdmin = `${remoteDir}/admin.json`;
  const remoteInstaller = `${remoteDir}/bearmail-install`;
  const remoteResult = `${remoteDir}/result.json`;
  const release = input.localReleaseDir ? releasePaths(input.localReleaseDir, remoteDir) : null;
  const endpoint = { ...input.endpoint, host };
  assertLocalPath(input.localInput);
  assertLocalPath(input.localDns);
  assertLocalPath(input.localRelay);
  assertLocalPath(input.localAdmin);
  assertLocalPath(input.localInstaller);
  assertLocalPath(input.localResult);
  if (basename(input.localInstaller) !== "bearmail-install") {
    throw new Error("The installer file must be named bearmail-install.");
  }
  assertLocalPath(input.endpoint.privateKeyFile);
  assertLocalPath(input.endpoint.knownHostsFile);
  const ssh = sshArgs(endpoint);
  const plan: SshInstallPlan = {
    remoteDir,
    probes: PROBES.map((remote) => withSudo(ssh, remote)),
    makeDir: withSudo(ssh, ["install", "-d", "-m", "0700", "-o", SSH_LOGIN_USER, remoteDir]),
    copyInput: scpToRemote(endpoint, input.localInput, remoteInput),
    copyDns: scpToRemote(endpoint, input.localDns, remoteDns),
    copyRelay: scpToRemote(endpoint, input.localRelay, remoteRelay),
    copyAdmin: scpToRemote(endpoint, input.localAdmin, remoteAdmin),
    copyInstaller: scpToRemote(endpoint, input.localInstaller, remoteInstaller),
    copyRelease: release ? release.files.map((file) => scpToRemote(endpoint, file.local, file.remote)) : [],
    makeReleaseDir: release ? withSudo(ssh, ["install", "-d", "-m", "0700", "-o", SSH_LOGIN_USER, release.remoteDir]) : [],
    restrictFiles: withSudo(ssh, ["chmod", "0600", remoteInput, remoteDns, remoteRelay, remoteAdmin]),
    restrictInstaller: withSudo(ssh, ["chmod", "0700", remoteInstaller]),
    restrictRelease: release
      ? [
          withSudo(ssh, ["chmod", "0755", ...release.executables]),
          withSudo(ssh, ["chmod", "0644", ...release.regular]),
        ]
      : [],
    // Stage on disk: /run may be mounted noexec and cannot run the engine artifact.
    dryRun: withSudo(ssh, [remoteInstaller, "--dry-run", "--input", remoteInput, "--result", remoteResult]),
    apply: withSudo(ssh, [remoteInstaller, "--input", remoteInput, "--result", remoteResult]),
    fetchResult: scpFromRemote(endpoint, remoteResult, input.localResult),
    releaseResult: withSudo(ssh, ["chown", SSH_LOGIN_USER, "--", remoteResult]),
    removeRemoteDir: withSudo(ssh, ["rm", "-r", "--", remoteDir]),
  };
  assertPlanArgs(plan);
  return plan;
}

const PROBES: string[][] = [
  ["uname", "-s"],
  ["uname", "-m"],
  ["readlink", "-f", "/proc/1/exe"],
  ["cat", "/proc/meminfo"],
  ["df", "-B1", "/"],
  ["ls", "-A", "/var/lib/stalwart"],
];

/** Readiness commands for one inventory address. This does not open a connection. */
export function sshReadinessCommands(endpoint: SshEndpoint): string[][] {
  const host = assertPublicUnicastIpv4(endpoint.host);
  const normalized = { ...endpoint, host };
  assertLocalPath(normalized.privateKeyFile);
  assertLocalPath(normalized.knownHostsFile);
  const args = sshArgs(normalized);
  const destination = args[args.length - 1];
  const prefix = [
    ...args.slice(0, -1),
    "-o", "ConnectTimeout=10",
    "-o", "HashKnownHosts=no",
    "-o", "UpdateHostKeys=no",
    destination,
  ];
  return PROBES.map((remote) => withSudo(prefix, remote));
}

/** Remote command prefix. `-n` fails instead of waiting for a password. */
function withSudo(prefix: string[], command: string[]): string[] {
  return [...prefix, "sudo", "-n", "--", ...command];
}

function sshArgs(endpoint: SshEndpoint): string[] {
  return [
    "ssh",
    "-o", "BatchMode=yes",
    "-o", "IdentitiesOnly=yes",
    "-o", endpoint.acceptNewHostKey ? "StrictHostKeyChecking=accept-new" : "StrictHostKeyChecking=yes",
    "-o", `UserKnownHostsFile=${endpoint.knownHostsFile}`,
    "-i", endpoint.privateKeyFile,
    "-p", "22",
    "-l", SSH_LOGIN_USER,
    endpoint.host,
  ];
}

function scpOptions(endpoint: SshEndpoint): string[] {
  return [
    "scp",
    "-o", "BatchMode=yes",
    "-o", "IdentitiesOnly=yes",
    "-o", endpoint.acceptNewHostKey ? "StrictHostKeyChecking=accept-new" : "StrictHostKeyChecking=yes",
    "-o", `UserKnownHostsFile=${endpoint.knownHostsFile}`,
    "-o", `User=${SSH_LOGIN_USER}`,
    "-i", endpoint.privateKeyFile,
    "-P", "22",
  ];
}

function scpToRemote(endpoint: SshEndpoint, local: string, remote: string): string[] {
  return [...scpOptions(endpoint), local, `${endpoint.host}:${remote}`];
}

function scpFromRemote(endpoint: SshEndpoint, remote: string, local: string): string[] {
  return [...scpOptions(endpoint), `${endpoint.host}:${remote}`, local];
}

function assertPlanArgs(value: unknown): void {
  if (typeof value === "string") {
    assertSafeArg(value);
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) assertPlanArgs(item);
    return;
  }
  if (value !== null && typeof value === "object") {
    for (const item of Object.values(value)) assertPlanArgs(item);
  }
}

function releasePaths(localReleaseDir: string, remoteDir: string): {
  remoteDir: string;
  files: Array<{ local: string; remote: string }>;
  executables: string[];
  regular: string[];
} {
  assertLocalPath(localReleaseDir);
  const releaseId = basename(localReleaseDir);
  if (!/^[0-9a-f]{40}$/.test(releaseId)) {
    throw new Error("The release directory name must be the bearmail commit.");
  }
  const remoteRelease = `${remoteDir}/${releaseId}`;
  const names = [...RELEASE_FILES, "SHA256SUMS"];
  const files = names.map((name) => ({ local: join(localReleaseDir, name), remote: `${remoteRelease}/${name}` }));
  return {
    remoteDir: remoteRelease,
    files,
    executables: ["install.sh", "stalwart", "mcp_install.sh"].map((name) => `${remoteRelease}/${name}`),
    regular: [`${remoteRelease}/bearmail-webui.tar.gz`, `${remoteRelease}/SHA256SUMS`],
  };
}

function assertLocalPath(value: string): void {
  if (!value.startsWith("/") || value.includes("..")) {
    throw new Error("A local installer path must be absolute.");
  }
  assertSafeArg(value);
}

function assertSafeArg(value: string): void {
  if (value.length === 0 || /[\s;|&$`<>\\"'()*?[\]]/.test(value)) {
    throw new Error("An SSH argument contains a shell character.");
  }
}
