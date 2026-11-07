export type IdentityPlatformConfig = {
  projectId: string;
  apiKey: string;
  googleClientId: string;
  origins: string[];
};
export function readIdentityPlatformConfig(
  env: NodeJS.ProcessEnv,
): IdentityPlatformConfig | undefined {
  const names = [
    "BEARPORTAL_IDENTITY_PROJECT_ID",
    "BEARPORTAL_IDENTITY_API_KEY",
    "BEARPORTAL_GOOGLE_CLIENT_ID",
    "BEARPORTAL_AUTH_ORIGINS",
  ] as const;
  if (!names.some((name) => env[name])) return undefined;
  const missing = names.filter((name) => !env[name]);
  if (missing.length)
    throw new Error("Missing configuration: " + missing.join(", "));
  const projectId = env.BEARPORTAL_IDENTITY_PROJECT_ID!;
  if (!/^[a-z][a-z0-9-]{4,28}[a-z0-9]$/.test(projectId))
    throw new Error("BEARPORTAL_IDENTITY_PROJECT_ID is invalid.");
  const apiKey = env.BEARPORTAL_IDENTITY_API_KEY!;
  if (!/^[A-Za-z0-9_-]{20,200}$/.test(apiKey))
    throw new Error("BEARPORTAL_IDENTITY_API_KEY is invalid.");
  const googleClientId = env.BEARPORTAL_GOOGLE_CLIENT_ID!;
  if (!/^[A-Za-z0-9_-]+\.apps\.googleusercontent\.com$/.test(googleClientId))
    throw new Error("BEARPORTAL_GOOGLE_CLIENT_ID is invalid.");
  const origins = env
    .BEARPORTAL_AUTH_ORIGINS!.split(",")
    .map((value) => value.trim());
  for (const value of origins) {
    let url: URL;
    try {
      url = new URL(value);
    } catch {
      throw new Error("BEARPORTAL_AUTH_ORIGINS is invalid.");
    }
    const local = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
    if (
      url.origin !== value ||
      url.username ||
      url.password ||
      (url.protocol !== "https:" &&
        !(
          env.BEARPORTAL_ENV !== "production" &&
          local &&
          url.protocol === "http:"
        ))
    )
      throw new Error(
        "BEARPORTAL_AUTH_ORIGINS must contain HTTPS origins (loopback HTTP is allowed only in development).",
      );
  }
  return { projectId, apiKey, googleClientId, origins };
}
