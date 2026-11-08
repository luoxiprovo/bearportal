import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { chmodSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { sshReadinessCommands, type SshEndpoint } from "./ssh-install.ts";

export const SSH_PRIVATE_KEY = "/var/lib/bearportal/ssh/id_ed25519";
export const SSH_KNOWN_HOSTS = "/var/lib/bearportal/ssh/known_hosts";

export type SshCommandResult = { code: number; stdout: string; stderr: string };

export type SshProbeReport = {
  source: "ssh";
  os: string;
  init: string;
  architecture: string;
  memoryMb: number;
  diskGb: number;
  dataPathMounted: boolean;
  priorTenantData: boolean;
  reachable: boolean;
  hostKeyFingerprint: string | null;
};

export type SshProbeOutcome = {
  ok: boolean;
  failures: string[];
  report: SshProbeReport | null;
};

type ProbeCapture = {
  unameS: SshCommandResult;
  unameM: SshCommandResult;
  init: SshCommandResult;
  meminfo: SshCommandResult;
  df: SshCommandResult;
  dataPath: SshCommandResult;
  hostKeyFingerprint: string | null;
};

const GIB = 1024 * 1024 * 1024;

/** Classify a failed SSH attempt. The stderr text is not returned to callers. */
export function classifySshFailure(stderr: string): "server.ssh_auth_failed" | "server.host_key_mismatch" | "server.sudo_failed" | "server.unreachable" {
  const text = stderr.toLowerCase();
  if (text.includes("host key verification failed") || text.includes("remote host identification has changed")) {
    return "server.host_key_mismatch";
  }
  if (text.includes("a password is required") || text.includes("not in the sudoers") || text.includes("not allowed to execute")) {
    return "server.sudo_failed";
  }
  if (text.includes("permission denied") || text.includes("authentication failed")) return "server.ssh_auth_failed";
  return "server.unreachable";
}

/** Turn the six readiness command results into a pass or a failure list. */
export function interpretSshProbe(input: ProbeCapture): SshProbeOutcome {
  const first = input.unameS;
  if (first.code !== 0) {
    return { ok: false, failures: [classifySshFailure(first.stderr)], report: null };
  }
  const failures: string[] = [];
  const os = first.stdout.trim();
  const machine = input.unameM.code === 0 ? input.unameM.stdout.trim() : "";
  const architecture = machine === "x86_64" ? "x64" : machine === "aarch64" || machine === "arm64" ? "arm64" : "";
  const initPath = input.init.code === 0 ? input.init.stdout.trim() : "";
  const memoryMb = memoryMbFrom(input.meminfo.code === 0 ? input.meminfo.stdout : "");
  const diskGb = diskGbFrom(input.df.code === 0 ? input.df.stdout : "");
  const data = dataPathFrom(input.dataPath);
  // MemTotal is below the VM size. A 1 GB host still reports under 1024 MB.
  if (os !== "Linux" || !architecture || !initPath.includes("systemd") || memoryMb < 900 || diskGb < 20) {
    failures.push("server.incompatible_profile");
  }
  if (data.priorTenantData) failures.push("server.readiness_missing");
  if (data.unreadable) failures.push("server.readiness_missing");
  const report: SshProbeReport = {
    source: "ssh",
    os,
    init: initPath.includes("systemd") ? "systemd" : initPath,
    architecture,
    memoryMb,
    diskGb,
    dataPathMounted: data.mounted,
    priorTenantData: data.priorTenantData,
    reachable: true,
    hostKeyFingerprint: input.hostKeyFingerprint,
  };
  return { ok: failures.length === 0, failures, report };
}

export function hostKeyFingerprint(knownHosts: string, host: string): string | null {
  const line = knownHosts.split("\n").find((item) => {
    const marker = item.trim().split(/\s+/)[0] ?? "";
    return marker.split(",").includes(host);
  });
  if (!line) return null;
  const parts = line.trim().split(/\s+/);
  if (parts.length < 3) return null;
  const blob = Buffer.from(parts[2] ?? "", "base64");
  if (blob.length < 8) return null;
  const hash = createHash("sha256").update(blob).digest("base64").replace(/=+$/, "");
  return `SHA256:${hash}`;
}

/** Probe one inventory address. The host must already be a public unicast IPv4 address. */
export async function liveSshProbe(host: string, skipHostKeyVerification = false): Promise<SshProbeOutcome> {
  if (!existsSync(SSH_PRIVATE_KEY)) {
    return { ok: false, failures: ["server.ssh_unavailable"], report: null };
  }
  if (!skipHostKeyVerification && !existsSync(SSH_KNOWN_HOSTS)) {
    writeFileSync(SSH_KNOWN_HOSTS, "", { mode: 0o600 });
    chmodSync(SSH_KNOWN_HOSTS, 0o600);
  }
  const known = skipHostKeyVerification ? "" : readFileSync(SSH_KNOWN_HOSTS, "utf8");
  const endpoint: SshEndpoint = {
    host,
    privateKeyFile: SSH_PRIVATE_KEY,
    knownHostsFile: SSH_KNOWN_HOSTS,
    acceptNewHostKey: !skipHostKeyVerification && hostKeyFingerprint(known, host) == null,
    skipHostKeyVerification,
  };
  let commands: string[][];
  try {
    commands = sshReadinessCommands(endpoint);
  } catch {
    return { ok: false, failures: ["server.unreachable"], report: null };
  }
  const captures: SshCommandResult[] = [];
  for (const command of commands) {
    const result = await runCommand(command);
    captures.push(result);
    if (captures.length === 1 && result.code !== 0) break;
  }
  while (captures.length < 6) captures.push({ code: 255, stdout: "", stderr: "" });
  const fingerprint = skipHostKeyVerification ? null : hostKeyFingerprint(readFileSync(SSH_KNOWN_HOSTS, "utf8"), host);
  return interpretSshProbe({
    unameS: captures[0]!,
    unameM: captures[1]!,
    init: captures[2]!,
    meminfo: captures[3]!,
    df: captures[4]!,
    dataPath: captures[5]!,
    hostKeyFingerprint: fingerprint,
  });
}

function memoryMbFrom(text: string): number {
  const match = text.match(/^MemTotal:\s+(\d+)\s+kB/m);
  if (!match) return 0;
  return Math.floor(Number(match[1]) / 1024);
}

function diskGbFrom(text: string): number {
  const lines = text.trim().split("\n").map((line) => line.trim()).filter((line) => line && !line.startsWith("Filesystem"));
  const last = lines.at(-1);
  if (!last) return 0;
  const columns = last.split(/\s+/);
  const bytes = /^\d+$/.test(columns[0] ?? "") ? Number(columns[0]) : Number(columns[1]);
  if (!Number.isFinite(bytes) || bytes < 0) return 0;
  return Math.floor(bytes / GIB);
}

function dataPathFrom(result: SshCommandResult): { mounted: boolean; priorTenantData: boolean; unreadable: boolean } {
  if (result.code === 0) {
    const names = result.stdout.split("\n").map((line) => line.trim()).filter(Boolean);
    return { mounted: true, priorTenantData: names.length > 0, unreadable: false };
  }
  if (/no such file or directory/i.test(result.stderr)) {
    return { mounted: false, priorTenantData: false, unreadable: false };
  }
  return { mounted: false, priorTenantData: false, unreadable: true };
}

function runCommand(args: string[]): Promise<SshCommandResult> {
  const [file, ...rest] = args;
  return new Promise((resolve) => {
    if (!file) {
      resolve({ code: 127, stdout: "", stderr: "" });
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
    const timer = setTimeout(() => child.kill("SIGTERM"), 15_000);
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
