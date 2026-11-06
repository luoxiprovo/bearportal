import { chmodSync, existsSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { BEARMAIL_PIN } from "../../contracts/src/index.ts";

const COMMIT_URL = `https://api.github.com/repos/${BEARMAIL_PIN.repository}/commits/main`;
const RAW_PREFIX = `https://raw.githubusercontent.com/${BEARMAIL_PIN.repository}/`;
const COMMIT = /^[0-9a-f]{40}$/;

export class BearmailSourceError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "BearmailSourceError";
  }
}

export type BearmailSourceResponse = { status: number; body: string };

/** Reads one HTTPS URL. Callers pass only the two GitHub URLs this module builds. */
export type BearmailSourceTransport = (url: string, headers: Record<string, string>) => Promise<BearmailSourceResponse>;

export type ResolvedBearmailInstall = {
  repository: typeof BEARMAIL_PIN.repository;
  ref: typeof BEARMAIL_PIN.ref;
  commit: string;
  script: string;
};

/** Read bearmail-install from the current main commit. This does not execute it. */
export async function resolveLatestBearmailInstall(
  transport: BearmailSourceTransport = liveBearmailSource,
): Promise<ResolvedBearmailInstall> {
  const meta = await transport(COMMIT_URL, {
    accept: "application/vnd.github+json",
    "user-agent": "bearportal",
  });
  if (meta.status !== 200) {
    throw new BearmailSourceError("The latest bearmail-install commit could not be read.");
  }
  let sha = "";
  try {
    const parsed = JSON.parse(meta.body) as { sha?: unknown };
    if (typeof parsed.sha === "string") sha = parsed.sha;
  } catch {
    sha = "";
  }
  if (!COMMIT.test(sha)) {
    throw new BearmailSourceError("GitHub did not return a bearmail-install commit.");
  }
  const scriptUrl = `${RAW_PREFIX}${sha}/${BEARMAIL_PIN.installerPath}`;
  const file = await transport(scriptUrl, {
    accept: "text/plain",
    "user-agent": "bearportal",
  });
  if (file.status !== 200) {
    throw new BearmailSourceError("The latest bearmail-install file could not be read.");
  }
  assertInstallerScript(file.body);
  return {
    repository: BEARMAIL_PIN.repository,
    ref: BEARMAIL_PIN.ref,
    commit: sha,
    script: file.body,
  };
}

/** Write the resolved script for one install. The file is mode 0700 and is not executed here. */
export function writeBearmailInstall(directory: string, script: string): string {
  if (!directory.startsWith("/") || directory.includes("..") || !existsSync(directory)) {
    throw new BearmailSourceError("The installer directory must be an existing absolute path.");
  }
  assertInstallerScript(script);
  const path = join(directory, BEARMAIL_PIN.installerPath);
  writeFileSync(path, script, { mode: 0o700 });
  chmodSync(path, 0o700);
  return path;
}

function assertInstallerScript(script: string): void {
  if (script.length < 40 || script.length > 2_000_000 || script.includes("\0") || !script.startsWith("#!/usr/bin/env python3\n") || !script.includes("bearmail-install")) {
    throw new BearmailSourceError("The bearmail-install file is not usable.");
  }
}

async function liveBearmailSource(url: string, headers: Record<string, string>): Promise<BearmailSourceResponse> {
  if (url !== COMMIT_URL && !isRawInstallerUrl(url)) {
    throw new BearmailSourceError("The bearmail-install source URL is not the GitHub main file.");
  }
  let response: Response;
  try {
    response = await fetch(url, { headers, redirect: "error" });
  } catch {
    throw new BearmailSourceError("The latest bearmail-install could not be read.");
  }
  return { status: response.status, body: await response.text() };
}

function isRawInstallerUrl(url: string): boolean {
  if (!url.startsWith(RAW_PREFIX) || !url.endsWith(`/${BEARMAIL_PIN.installerPath}`)) return false;
  const commit = url.slice(RAW_PREFIX.length, url.length - BEARMAIL_PIN.installerPath.length - 1);
  return COMMIT.test(commit);
}
