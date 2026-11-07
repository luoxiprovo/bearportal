import { readIdentityPlatformConfig, type IdentityPlatformConfig } from "./identity-platform-config.ts";
const REQUIRED = [
  "DATABASE_URL",
  "BEARPORTAL_SECRET_KEY",
  "BEARPORTAL_JWT_PUBLIC_KEY_FILE",
  "BEARPORTAL_JWT_ISSUER",
  "BEARPORTAL_JWT_AUDIENCE",
  "BEARPORTAL_SECRETS_DIR",
] as const;

export type ApiConfig = {
  identityPlatform?: IdentityPlatformConfig;
  databaseUrl: string;
  secretKeyHex: string;
  jwtPublicKeyFile: string;
  issuer: string;
  audience: string;
  secretsDir: string;
  bindHost: string;
  port: number;
  /** Absent when BEARPORTAL_SCHEDULER_TOKEN is missing or empty. Internal routes then return 503. */
  schedulerToken?: string;
  /** Local test issuer only. Production is never allowed to sign browser identities. */
  allowDevIdentity: boolean;
  devJwtPrivateKeyFile?: string;
};

/** Read startup configuration. Error text names variables and never echoes their values. */
export function loadConfig(env: NodeJS.ProcessEnv): ApiConfig {
  const missing = REQUIRED.filter((name) => env[name] == null || env[name] === "");
  if (missing.length > 0) {
    throw new Error(`Missing configuration: ${missing.join(", ")}`);
  }
  if (!/^[0-9a-f]{64}$/i.test(env.BEARPORTAL_SECRET_KEY ?? "")) {
    throw new Error("BEARPORTAL_SECRET_KEY is invalid.");
  }
  if (env.BEARPORTAL_ENV === "production" && env.BEARPORTAL_ALLOW_TEST_ISSUER === "1") {
    throw new Error("Test identity issuer cannot be enabled in production.");
  }
  const allowTest = env.BEARPORTAL_ALLOW_TEST_ISSUER === "1";
  const issuer = env.BEARPORTAL_JWT_ISSUER ?? "";
  if (!allowTest && !issuer.startsWith("https://securetoken.google.com/")) {
    throw new Error("Identity Platform issuer is not configured.");
  }
  const port = env.PORT == null || env.PORT === "" ? 8088 : Number(env.PORT);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error("PORT is invalid.");
  }
  return {
    identityPlatform:readIdentityPlatformConfig(env),
    databaseUrl: env.DATABASE_URL ?? "",
    secretKeyHex: env.BEARPORTAL_SECRET_KEY ?? "",
    jwtPublicKeyFile: env.BEARPORTAL_JWT_PUBLIC_KEY_FILE ?? "",
    issuer,
    audience: env.BEARPORTAL_JWT_AUDIENCE ?? "",
    secretsDir: env.BEARPORTAL_SECRETS_DIR ?? "",
    bindHost: env.BEARPORTAL_BIND_HOST || "127.0.0.1",
    port,
    schedulerToken: readSchedulerToken(env.BEARPORTAL_SCHEDULER_TOKEN),
    allowDevIdentity: env.BEARPORTAL_ENV !== "production" && env.BEARPORTAL_ALLOW_TEST_ISSUER === "1",
    devJwtPrivateKeyFile: env.BEARPORTAL_JWT_PRIVATE_KEY_FILE || undefined,
  };
}

function readSchedulerToken(value: string | undefined): string | undefined {
  if (value == null || value === "") return undefined;
  if (value.length < 16 || value.length > 200 || /\s/.test(value)) {
    throw new Error("BEARPORTAL_SCHEDULER_TOKEN is invalid.");
  }
  return value;
}
