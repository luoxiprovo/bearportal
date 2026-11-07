import { readFileSync, writeFileSync, renameSync } from "node:fs";
import { createInterface } from "node:readline/promises";
import {
  readIdentityPlatformConfig,
  type IdentityPlatformConfig,
} from "../apps/api/src/identity-platform-config.ts";

export function identityEnvironment(config: IdentityPlatformConfig) {
  return {
    BEARPORTAL_IDENTITY_PROJECT_ID: config.projectId,
    BEARPORTAL_IDENTITY_API_KEY: config.apiKey,
    BEARPORTAL_GOOGLE_CLIENT_ID: config.googleClientId,
    BEARPORTAL_AUTH_ORIGINS: config.origins.join(","),
  };
}
export function writeIdentitySettings(
  path: string,
  config: IdentityPlatformConfig,
) {
  const before = readFileSync(path, "utf8");
  const settings = identityEnvironment(config);
  const previous = Object.fromEntries(
    before
      .split("\n")
      .filter((line) => line && !line.startsWith("#") && line.includes("="))
      .map((line) => {
        const i = line.indexOf("=");
        return [line.slice(0, i), line.slice(i + 1)];
      }),
  );
  readIdentityPlatformConfig({ ...previous, ...settings });
  const saved =
    before
      .split("\n")
      .filter(
        (line) =>
          !Object.keys(settings).some((key) => line.startsWith(key + "=")),
      )
      .join("\n")
      .trimEnd() +
    "\n" +
    Object.entries(settings)
      .map(([key, value]) => key + "=" + value)
      .join("\n") +
    "\n";
  writeFileSync(path + ".before-identity-" + Date.now(), before, {
    mode: 0o600,
    flag: "wx",
  });
  const temporary = path + ".identity-" + process.pid;
  writeFileSync(temporary, saved, { mode: 0o600, flag: "wx" });
  renameSync(temporary, path);
}
export async function configureIdentity(path: string, args: string[]) {
  if (args.includes("--help")) {
    console.log(
      "pnpm auth:configure [--file /path/to/identity-platform.json]\nConfigures Google Cloud Identity Platform; preserves database/encryption/signing settings.",
    );
    return;
  }
  let config: IdentityPlatformConfig;
  if (args.length) {
    if (args.length !== 2 || args[0] !== "--file")
      throw new Error(
        "Use pnpm auth:configure or --file /path/to/identity-platform.json",
      );
    try {
      config = JSON.parse(readFileSync(args[1], "utf8"));
    } catch {
      throw new Error(
        "Could not read the Identity Platform JSON configuration.",
      );
    }
    if (!config || !Array.isArray(config.origins))
      throw new Error(
        "The configuration needs projectId, apiKey, googleClientId and origins.",
      );
  } else {
    if (!process.stdin.isTTY)
      throw new Error("Run pnpm auth:configure in a terminal, or use --file.");
    const terminal = createInterface({
      input: process.stdin,
      output: process.stdout,
    });
    try {
      config = {
        projectId: (
          await terminal.question("Google Cloud project ID: ")
        ).trim(),
        apiKey: (await terminal.question("Identity Platform API key: ")).trim(),
        googleClientId: (
          await terminal.question("Google OAuth web client ID: ")
        ).trim(),
        origins: (
          (
            await terminal.question(
              "BearPortal origins [http://localhost:8088,http://127.0.0.1:8088]: ",
            )
          ).trim() || "http://localhost:8088,http://127.0.0.1:8088"
        )
          .split(",")
          .map((s) => s.trim()),
      };
    } finally {
      terminal.close();
    }
  }
  writeIdentitySettings(path, config);
  console.log(
    "Identity Platform settings saved; existing database and encryption/signing keys preserved. Restart BearPortal to activate.",
  );
}
