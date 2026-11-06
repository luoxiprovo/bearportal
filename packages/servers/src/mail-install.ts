import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { BEARMAIL_PIN } from "../../contracts/src/index.ts";
import { InstallerUnavailableError, RELEASE_FILES, type InstallerRunner } from "./installer.ts";
import { SSH_KNOWN_HOSTS, SSH_PRIVATE_KEY, classifySshFailure, type SshCommandResult } from "./ssh-probe.ts";
import { sshInstallPlan, type SshInstallPlan } from "./ssh-install.ts";

const COMMIT_URL = `https://api.github.com/repos/${BEARMAIL_PIN.repository}/commits/main`;
const RAW_PREFIX = `https://raw.githubusercontent.com/${BEARMAIL_PIN.repository}/`;
const COMMIT = /^[0-9a-f]{40}$/;
const SECRET_ID = /^secret:([0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$/i;
const OPERATION_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

const ARTIFACT_NAMES = [...RELEASE_FILES, BEARMAIL_PIN.installerPath] as const;

export type MailTransport = (url: string) => Promise<{ status: number; body: Buffer }>;

export class BearmailArtifactError extends Error {
  readonly code: "ARTIFACT_MISSING" | "SOURCE_UNAVAILABLE";

  constructor(code: "ARTIFACT_MISSING" | "SOURCE_UNAVAILABLE", message: string) {
    super(message);
    this.name = "BearmailArtifactError";
    this.code = code;
  }
}

export type MailInstallHooks = {
  readSecret: (secretId: string) => Promise<string>;
  privateKeyFile?: string;
  knownHostsFile?: string;
  transport?: MailTransport;
  spawn?: (args: string[], timeoutMs: number) => Promise<SshCommandResult>;
  workRoot?: string;
};

/** Read the current main commit. This does not download the release files. */
export async function resolveBearmailCommit(transport: MailTransport = liveMailTransport): Promise<string> {
  const meta = await transport(COMMIT_URL);
  if (meta.status !== 200) {
    throw new BearmailArtifactError("SOURCE_UNAVAILABLE", "The latest bearmail-install commit could not be read.");
  }
  let sha = "";
  try {
    const parsed = JSON.parse(meta.body.toString("utf8")) as { sha?: unknown };
    if (typeof parsed.sha === "string") sha = parsed.sha;
  } catch {
    sha = "";
  }
  if (!COMMIT.test(sha)) {
    throw new BearmailArtifactError("SOURCE_UNAVAILABLE", "GitHub did not return a bearmail-install commit.");
  }
  return sha;
}

/** Download bearmail-install and the four release files for one commit, then write SHA256SUMS. */
export async function prepareBearmailTree(input: {
  commit: string;
  directory: string;
  transport?: MailTransport;
}): Promise<{ installerPath: string; artifactDir: string }> {
  if (!COMMIT.test(input.commit)) {
    throw new BearmailArtifactError("SOURCE_UNAVAILABLE", "The bearmail commit is not a GitHub sha.");
  }
  if (!input.directory.startsWith("/") || input.directory.includes("..")) {
    throw new BearmailArtifactError("ARTIFACT_MISSING", "The installer work directory must be absolute.");
  }
  const transport = input.transport ?? liveMailTransport;
  const artifactDir = join(input.directory, input.commit);
  mkdirSync(artifactDir, { recursive: true, mode: 0o700 });
  chmodSync(artifactDir, 0o700);
  const installerPath = join(input.directory, BEARMAIL_PIN.installerPath);
  const script = await readArtifact(transport, input.commit, BEARMAIL_PIN.installerPath);
  assertInstallerScript(script);
  writeFileSync(installerPath, script, { mode: 0o700 });
  chmodSync(installerPath, 0o700);
  const files = new Map<string, Buffer>();
  for (const name of RELEASE_FILES) {
    files.set(name, await readArtifact(transport, input.commit, name));
  }
  assertReleaseBytes(files);
  for (const name of RELEASE_FILES) {
    const mode = name === "bearmail-webui.tar.gz" ? 0o644 : 0o755;
    const path = join(artifactDir, name);
    writeFileSync(path, files.get(name)!, { mode });
    chmodSync(path, mode);
  }
  const sums = RELEASE_FILES.map((name) => {
    const digest = createHash("sha256").update(files.get(name)!).digest("hex");
    return `${digest}  ${name}`;
  }).join("\n") + "\n";
  const sumsPath = join(artifactDir, "SHA256SUMS");
  writeFileSync(sumsPath, sums, { mode: 0o644 });
  chmodSync(sumsPath, 0o644);
  return { installerPath, artifactDir };
}

/** Credential paths in the file bearmail-install reads are absolute paths on the mail server. */
export function rewriteInstallerInput(input: Record<string, unknown>, remoteDir: string): Record<string, unknown> {
  const release = input.release;
  const dns = input.dns;
  const relay = input.relay;
  if (!release || typeof release !== "object" || !dns || typeof dns !== "object" || !relay || typeof relay !== "object") {
    throw new BearmailArtifactError("ARTIFACT_MISSING", "The installer input is missing its release or credential paths.");
  }
  const releaseId = (release as { id?: unknown }).id;
  if (typeof releaseId !== "string" || !COMMIT.test(releaseId)) {
    throw new BearmailArtifactError("ARTIFACT_MISSING", "The installer release id is not a bearmail commit.");
  }
  return {
    ...input,
    dns: { ...dns, credentialFile: `${remoteDir}/dns.json` },
    relay: { ...relay, credentialFile: `${remoteDir}/relay.json` },
    adminCredentialFile: `${remoteDir}/admin.json`,
    release: {
      id: releaseId,
      artifactDir: `${remoteDir}/${releaseId}`,
      checksumFile: `${remoteDir}/${releaseId}/SHA256SUMS`,
    },
  };
}

/** Argument lists for one dry run or applying run. Removal is separate so it still runs after a failure. */
export function mailInstallArgv(plan: SshInstallPlan, mode: "dry_run" | "apply"): string[][] {
  return [
    plan.makeDir,
    ...(plan.makeReleaseDir.length > 0 ? [plan.makeReleaseDir] : []),
    plan.copyInput,
    plan.copyDns,
    plan.copyRelay,
    plan.copyAdmin,
    plan.copyInstaller,
    ...plan.copyRelease,
    plan.restrictFiles,
    plan.restrictInstaller,
    ...plan.restrictRelease,
    mode === "dry_run" ? plan.dryRun : plan.apply,
    plan.releaseResult,
    plan.fetchResult,
  ];
}

/** Production installer. It downloads the current main files and runs bearmail-install over SSH. */
export function liveMailInstall(hooks: MailInstallHooks): InstallerRunner {
  return {
    async run(request): Promise<unknown> {
      return runMailInstall(hooks, request.mode, request.input);
    },
  };
}

async function runMailInstall(hooks: MailInstallHooks, mode: "dry_run" | "apply", input: Record<string, unknown>): Promise<unknown> {
  const privateKeyFile = hooks.privateKeyFile ?? SSH_PRIVATE_KEY;
  if (!existsSync(privateKeyFile)) throw new InstallerUnavailableError();
  const operationId = typeof input.operationId === "string" ? input.operationId.toLowerCase() : "";
  const publicIpv4 = typeof input.publicIpv4 === "string" ? input.publicIpv4 : "";
  if (!OPERATION_ID.test(operationId) || publicIpv4.length === 0) {
    return failedResult("INVALID_INPUT");
  }
  const workRoot = hooks.workRoot ?? "/var/lib/bearportal/work";
  mkdirSync(workRoot, { recursive: true, mode: 0o700 });
  chmodSync(workRoot, 0o700);
  const workDir = join(workRoot, operationId);
  mkdirSync(workDir, { mode: 0o700 });
  chmodSync(workDir, 0o700);
  try {
    const release = input.release as { id?: unknown } | undefined;
    const commit = typeof release?.id === "string" ? release.id : "";
    let prepared: { installerPath: string; artifactDir: string };
    try {
      prepared = await prepareBearmailTree({ commit, directory: workDir, transport: hooks.transport });
    } catch (error) {
      if (error instanceof BearmailArtifactError && error.code === "SOURCE_UNAVAILABLE") throw new InstallerUnavailableError();
      return failedResult("ARTIFACT_MISSING");
    }
    const dns = input.dns as { provider?: unknown; credentialFile?: unknown } | undefined;
    const relay = input.relay as { credentialFile?: unknown } | undefined;
    const provider = typeof dns?.provider === "string" ? dns.provider : "";
    let dnsText = "";
    let relayText = "";
    let adminText = "";
    try {
      dnsText = await hooks.readSecret(secretId(dns?.credentialFile));
      relayText = await hooks.readSecret(secretId(relay?.credentialFile));
      adminText = await hooks.readSecret(secretId(input.adminCredentialFile));
      assertCredentialJson("dns", provider, dnsText);
      assertCredentialJson("relay", provider, relayText);
      assertCredentialJson("admin", provider, adminText);
    } catch {
      return failedResult("INVALID_INPUT");
    }
    const remoteDir = `/var/lib/bearportal/install/${operationId}`;
    const remoteInput = rewriteInstallerInput(input, remoteDir);
    const rendered = JSON.stringify(remoteInput);
    if (credentialLeaked(rendered, [dnsText, relayText, adminText])) return failedResult("INVALID_INPUT");
    const localInput = join(workDir, "input.json");
    const localDns = join(workDir, "dns.json");
    const localRelay = join(workDir, "relay.json");
    const localAdmin = join(workDir, "admin.json");
    const localResult = join(workDir, "result.json");
    writePrivate(localInput, `${rendered}\n`);
    writePrivate(localDns, dnsText.endsWith("\n") ? dnsText : `${dnsText}\n`);
    writePrivate(localRelay, relayText.endsWith("\n") ? relayText : `${relayText}\n`);
    writePrivate(localAdmin, adminText.endsWith("\n") ? adminText : `${adminText}\n`);
    const plan = sshInstallPlan({
      endpoint: {
        host: publicIpv4,
        privateKeyFile,
        knownHostsFile: hooks.knownHostsFile ?? SSH_KNOWN_HOSTS,
        acceptNewHostKey: false,
      },
      operationId,
      localInput,
      localDns,
      localRelay,
      localAdmin,
      localInstaller: prepared.installerPath,
      localResult,
      localReleaseDir: prepared.artifactDir,
    });
    const spawnCommand = hooks.spawn ?? defaultSpawn;
    const argv = mailInstallArgv(plan, mode);
    if (argv.some((args) => credentialLeaked(args.join("\n"), [dnsText, relayText, adminText]))) {
      return failedResult("INVALID_INPUT");
    }
    let sawInstaller = false;
    let installerCode = 1;
    let installerStderr = "";
    let failure = "";
    for (const args of argv) {
      const result = await spawnCommand(args, timeoutFor(args));
      if (args.includes("--input")) {
        sawInstaller = true;
        installerCode = result.code;
        installerStderr = result.stderr;
      }
      if (result.code !== 0 && !sawInstaller) {
        failure = classifySshFailure(result.stderr);
        break;
      }
    }
    try {
      await spawnCommand(plan.removeRemoteDir, 30_000);
    } catch {
      failure = failure || "server.unreachable";
    }
    if (!sawInstaller) return failedResult(failure || "server.unreachable");
    if (!existsSync(localResult)) return failedResult(failure || classifySshFailure(installerStderr));
    return resultFrom(installerCode, readFileSync(localResult, "utf8"));
  } finally {
    rmSync(workDir, { recursive: true, force: true });
  }
}

function resultFrom(exitCode: number, text: string): unknown {
  let parsed: Record<string, unknown> | null = null;
  try {
    const value = JSON.parse(text) as unknown;
    if (value && typeof value === "object" && !Array.isArray(value)) parsed = value as Record<string, unknown>;
  } catch {
    parsed = null;
  }
  const status = typeof parsed?.status === "string" ? parsed.status : "failed";
  const dns = parsed?.dns && typeof parsed.dns === "object" ? parsed.dns : { previousMx: [], published: [] };
  const errorCode = parsed?.errorCode == null ? null : parsed.errorCode;
  if (exitCode === 0 && (status === "dry_run" || status === "succeeded") && (errorCode == null || typeof errorCode === "string")) {
    return { status, exitCode: 0, retryable: false, errorCode, dns };
  }
  if (exitCode === 10 && (status === "tls_pending" || status === "dns_partial")) {
    return { status, exitCode: 10, retryable: true, errorCode: typeof errorCode === "string" ? errorCode : "TLS_PENDING", dns };
  }
  if (exitCode === 1 && (status === "failed" || status === "dns_partial")) {
    return { status, exitCode: 1, retryable: false, errorCode: typeof errorCode === "string" ? errorCode : "INSTALLER_FAILED", dns };
  }
  return failedResult(typeof errorCode === "string" ? errorCode : "INSTALLER_FAILED");
}

function failedResult(errorCode: string): Record<string, unknown> {
  return {
    status: "failed",
    exitCode: 1,
    retryable: false,
    errorCode,
    dns: { previousMx: [], published: [], minimumTtl: null, engineDkimHost: null, engineDkimValue: null },
  };
}

function secretId(value: unknown): string {
  if (typeof value !== "string") throw new BearmailArtifactError("ARTIFACT_MISSING", "A credential path is missing.");
  const match = SECRET_ID.exec(value);
  if (!match) throw new BearmailArtifactError("ARTIFACT_MISSING", "A credential path is not a stored secret.");
  return match[1]!.toLowerCase();
}

function assertCredentialJson(kind: "dns" | "relay" | "admin", provider: string, text: string): void {
  const parsed = JSON.parse(text) as unknown;
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new BearmailArtifactError("ARTIFACT_MISSING", "A credential file is not a JSON object.");
  }
  const keys = Object.keys(parsed).sort().join(",");
  if (kind === "dns" && provider === "namecom" && keys !== "token,username") {
    throw new BearmailArtifactError("ARTIFACT_MISSING", "The name.com credential file was rejected.");
  }
  if (kind === "dns" && provider !== "namecom" && keys !== "token") {
    throw new BearmailArtifactError("ARTIFACT_MISSING", "The DNS credential file was rejected.");
  }
  if (kind === "relay" && keys !== "smtpKey") {
    throw new BearmailArtifactError("ARTIFACT_MISSING", "The relay credential file was rejected.");
  }
  if (kind === "admin" && keys !== "password,username") {
    throw new BearmailArtifactError("ARTIFACT_MISSING", "The admin credential file was rejected.");
  }
}

function credentialLeaked(text: string, files: string[]): boolean {
  for (const file of files) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(file);
    } catch {
      return true;
    }
    if (!parsed || typeof parsed !== "object") return true;
    for (const value of Object.values(parsed)) {
      if (typeof value === "string" && value.length >= 4 && text.includes(value)) return true;
    }
  }
  return false;
}

function writePrivate(path: string, text: string): void {
  writeFileSync(path, text, { mode: 0o600 });
  chmodSync(path, 0o600);
}

function timeoutFor(args: string[]): number {
  if (args.includes("--input")) return 15 * 60 * 1000;
  if (args[0] === "scp") return 10 * 60 * 1000;
  return 30_000;
}

async function readArtifact(transport: MailTransport, commit: string, name: (typeof ARTIFACT_NAMES)[number]): Promise<Buffer> {
  const url = `${RAW_PREFIX}${commit}/${name}`;
  assertSourceUrl(url);
  let response: { status: number; body: Buffer };
  try {
    response = await transport(url);
  } catch {
    throw new BearmailArtifactError("SOURCE_UNAVAILABLE", "A bearmail release file could not be read.");
  }
  if (response.status !== 200) {
    throw new BearmailArtifactError("SOURCE_UNAVAILABLE", "A bearmail release file could not be read.");
  }
  const limit = name === "stalwart" ? 200_000_000 : 20_000_000;
  if (response.body.length === 0 || response.body.length > limit) {
    throw new BearmailArtifactError("ARTIFACT_MISSING", "A bearmail release file is the wrong size.");
  }
  return response.body;
}

function assertInstallerScript(body: Buffer): void {
  const script = body.toString("utf8");
  if (script.length < 40 || script.includes("\0") || !script.startsWith("#!/usr/bin/env python3\n") || !script.includes("bearmail-install")) {
    throw new BearmailArtifactError("ARTIFACT_MISSING", "The bearmail-install file is not usable.");
  }
}

function assertReleaseBytes(files: Map<string, Buffer>): void {
  const install = files.get("install.sh")!;
  const stalwart = files.get("stalwart")!;
  const webui = files.get("bearmail-webui.tar.gz")!;
  const mcp = files.get("mcp_install.sh")!;
  if (install.length < 10_000 || install.includes(0) || !install.toString("utf8").includes("BEARMAIL_EASY")) {
    throw new BearmailArtifactError("ARTIFACT_MISSING", "install.sh is not the published BearMail installer.");
  }
  if (stalwart.length < 1_000_000 || stalwart.subarray(0, 80).toString("utf8").includes("git-lfs.github.com")) {
    throw new BearmailArtifactError("ARTIFACT_MISSING", "stalwart is not the published engine binary.");
  }
  if (stalwart[0] !== 0x7f || stalwart[1] !== 0x45 || stalwart[2] !== 0x4c || stalwart[3] !== 0x46 || stalwart[18] !== 0x3e || stalwart[19] !== 0x00) {
    throw new BearmailArtifactError("ARTIFACT_MISSING", "stalwart is not an x86-64 ELF binary.");
  }
  if (webui.length < 10_000 || webui[0] !== 0x1f || webui[1] !== 0x8b) {
    throw new BearmailArtifactError("ARTIFACT_MISSING", "bearmail-webui.tar.gz is not a gzip archive.");
  }
  const mcpText = mcp.toString("utf8");
  if (
    mcp.length < 1_000
    || mcp.includes(0)
    || !mcpText.includes("bearmail-mcp")
    || !mcpText.includes('mcp_src="$RETVAL"')
    || mcpText.includes('mcp_src="$(fetch_mcp_sources)"')
  ) {
    throw new BearmailArtifactError("ARTIFACT_MISSING", "mcp_install.sh is not the published MCP installer.");
  }
}

function assertSourceUrl(url: string): void {
  if (url === COMMIT_URL) return;
  if (!url.startsWith(`https://raw.githubusercontent.com/${BEARMAIL_PIN.repository}/`)) {
    throw new BearmailArtifactError("SOURCE_UNAVAILABLE", "The bearmail source URL is not the GitHub file.");
  }
  const rest = url.slice(`https://raw.githubusercontent.com/${BEARMAIL_PIN.repository}/`.length);
  const slash = rest.indexOf("/");
  const commit = slash === -1 ? "" : rest.slice(0, slash);
  const name = slash === -1 ? "" : rest.slice(slash + 1);
  if (!COMMIT.test(commit) || !ARTIFACT_NAMES.includes(name as (typeof ARTIFACT_NAMES)[number])) {
    throw new BearmailArtifactError("SOURCE_UNAVAILABLE", "The bearmail source URL is not the GitHub file.");
  }
}

async function liveMailTransport(url: string): Promise<{ status: number; body: Buffer }> {
  assertSourceUrl(url);
  const headers: Record<string, string> = { "user-agent": "bearportal" };
  if (url === COMMIT_URL) headers.accept = "application/vnd.github+json";
  let response: Response;
  try {
    response = await fetch(url, { headers, redirect: "error" });
  } catch {
    throw new BearmailArtifactError("SOURCE_UNAVAILABLE", "The bearmail source could not be read.");
  }
  return { status: response.status, body: Buffer.from(await response.arrayBuffer()) };
}

function defaultSpawn(args: string[], timeoutMs: number): Promise<SshCommandResult> {
  const [file, ...rest] = args;
  return new Promise((resolve) => {
    if (!file) {
      resolve({ code: 127, stdout: "", stderr: "ssh unavailable" });
      return;
    }
    const child = spawn(file, rest, { shell: false, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    const take = (chunk: Buffer, current: string): string => (current + chunk.toString("utf8")).slice(-20_000);
    child.stdout?.on("data", (chunk: Buffer) => {
      stdout = take(chunk, stdout);
    });
    child.stderr?.on("data", (chunk: Buffer) => {
      stderr = take(chunk, stderr);
    });
    const timer = setTimeout(() => child.kill("SIGTERM"), timeoutMs);
    child.on("error", () => {
      clearTimeout(timer);
      resolve({ code: 127, stdout: "", stderr: "ssh unavailable" });
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ code: code ?? 1, stdout, stderr });
    });
  });
}
