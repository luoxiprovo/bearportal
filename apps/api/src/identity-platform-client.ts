import { createRemoteJWKSet, jwtVerify, type JWTPayload } from "jose";
import type { IdentityPlatformConfig } from "./identity-platform-config.ts";
import { HttpError } from "./errors.ts";
const identityKeys = createRemoteJWKSet(
  new URL(
    "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com",
  ),
);
const googleKeys = createRemoteJWKSet(
  new URL("https://www.googleapis.com/oauth2/v3/certs"),
);
// Keep only known diagnostic codes; never expose Google's raw error text or submitted credentials.
const providerDiagnostics = new Set([
  "EMAIL_EXISTS",
  "EMAIL_ALREADY_EXISTS",
  "WEAK_PASSWORD",
  "PASSWORD_DOES_NOT_MEET_REQUIREMENTS",
  "INVALID_EMAIL",
  "MISSING_EMAIL",
  "MISSING_PASSWORD",
  "ADMIN_ONLY_OPERATION",
  "ADMIN_RESTRICTED_OPERATION",
  "OPERATION_NOT_ALLOWED",
  "PASSWORD_LOGIN_DISABLED",
  "TOO_MANY_ATTEMPTS_TRY_LATER",
  "QUOTA_EXCEEDED",
  "CAPTCHA_CHECK_FAILED",
  "MISSING_RECAPTCHA_TOKEN",
  "INVALID_RECAPTCHA_TOKEN",
  "USER_DISABLED",
  "CONFIGURATION_NOT_FOUND",
  "INVALID_API_KEY",
  "API_KEY_INVALID",
  "EMAIL_NOT_FOUND",
  "INVALID_PASSWORD",
  "INVALID_LOGIN_CREDENTIALS",
]);
export class IdentityPlatformError extends HttpError {
  readonly providerCode: string;
  constructor(
    status: number,
    code: string,
    message: string,
    providerCode: string,
  ) {
    super(status, code, message);
    this.providerCode = providerDiagnostics.has(providerCode)
      ? providerCode
      : "UNRECOGNIZED_PROVIDER_ERROR";
  }
}
export type IdentityTokens = { idToken: string; refreshToken: string };
export type PlatformClaims = JWTPayload & {
  sub: string;
  email: string;
  email_verified: boolean;
  auth_time: number;
  firebase: { sign_in_provider: "password" | "google.com" };
};
export type IdentityPlatformClient = {
  password: (
    email: string,
    password: string,
    signup: boolean,
  ) => Promise<IdentityTokens>;
  google: (
    credential: string,
    nonce: string,
    origin: string,
  ) => Promise<IdentityTokens & { authoritativeEmail: boolean }>;
  refresh: (token: string) => Promise<IdentityTokens>;
  verify: (token: string) => Promise<PlatformClaims>;
  sendVerification: (token: string, origin: string) => Promise<void>;
  resetPassword: (email: string, origin: string) => Promise<void>;
};
export function validatePlatformClaims(
  payload: JWTPayload,
  config: IdentityPlatformConfig,
): PlatformClaims {
  const now = Math.floor(Date.now() / 1000);
  const provider = (
    payload.firebase as { sign_in_provider?: string } | undefined
  )?.sign_in_provider;
  if (
    payload.iss !== `https://securetoken.google.com/${config.projectId}` ||
    payload.aud !== config.projectId ||
    typeof payload.sub !== "string" ||
    !payload.sub ||
    payload.sub.length > 128 ||
    typeof payload.email_verified !== "boolean" ||
    typeof payload.email !== "string" ||
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(payload.email) ||
    payload.email.length > 200 ||
    typeof payload.auth_time !== "number" ||
    payload.auth_time <= 0 ||
    payload.auth_time > now + 30 ||
    typeof payload.exp !== "number" ||
    payload.exp <= now ||
    typeof payload.iat !== "number" ||
    payload.iat > now + 30 ||
    (payload.firebase as { tenant?: unknown } | undefined)?.tenant !==
      undefined ||
    !["password", "google.com"].includes(provider ?? "")
  )
    throw new HttpError(
      401,
      "UNAUTHENTICATED",
      "The identity could not be verified.",
    );
  return payload as PlatformClaims;
}
export function createIdentityVerifier(
  config: IdentityPlatformConfig,
  key: Parameters<typeof jwtVerify>[1] = identityKeys,
) {
  return async (token: string): Promise<PlatformClaims> => {
    try {
      const { payload } = await jwtVerify(token, key, {
        issuer: `https://securetoken.google.com/${config.projectId}`,
        audience: config.projectId,
        algorithms: ["RS256"],
      });
      return validatePlatformClaims(payload, config);
    } catch {
      throw new HttpError(
        401,
        "UNAUTHENTICATED",
        "The identity could not be verified.",
      );
    }
  };
}
export function createIdentityPlatformClient(
  config: IdentityPlatformConfig,
  transport: typeof fetch = fetch,
  keys: {
    identity?: Parameters<typeof jwtVerify>[1];
    google?: Parameters<typeof jwtVerify>[1];
  } = {},
): IdentityPlatformClient {
  const verify = createIdentityVerifier(config, keys.identity ?? identityKeys);
  async function call(
    method: string,
    body: Record<string, unknown>,
  ): Promise<Record<string, any>> {
    let response: Response;
    let result: Record<string, any>;
    try {
      response = await transport(
        `https://identitytoolkit.googleapis.com/v1/accounts:${method}?key=${encodeURIComponent(config.apiKey)}`,
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(body),
          signal: AbortSignal.timeout(15000),
          redirect: "error",
        },
      );
      result = (await response.json()) as Record<string, any>;
    } catch {
      throw new HttpError(
        503,
        "AUTH_UNAVAILABLE",
        "Sign-in is temporarily unavailable. Please try again.",
      );
    }
    if (!response.ok) {
      const providerMessage =
        typeof result.error?.message === "string" ? result.error.message : "";
      const code =
        /^[A-Z][A-Z0-9_]*(?=\s*:|\s*$)/.exec(providerMessage)?.[0] ??
        "UNRECOGNIZED_PROVIDER_ERROR";
      const failure = (
        status: number,
        publicCode: string,
        message: string,
      ): never => {
        throw new IdentityPlatformError(status, publicCode, message, code);
      };
      if (code === "TOO_MANY_ATTEMPTS_TRY_LATER" || response.status === 429)
        failure(
          429,
          "AUTH_RATE_LIMITED",
          "Too many attempts. Wait before trying again.",
        );
      if (method === "signUp") {
        if (["EMAIL_EXISTS", "EMAIL_ALREADY_EXISTS"].includes(code))
          failure(
            409,
            "ACCOUNT_EXISTS",
            "This email already has an account. Sign in with Google or reset your password.",
          );
        if (
          ["WEAK_PASSWORD", "PASSWORD_DOES_NOT_MEET_REQUIREMENTS"].includes(
            code,
          )
        )
          failure(
            400,
            "PASSWORD_REQUIREMENTS",
            "Use 12 or more characters with uppercase and lowercase letters, a number and a symbol.",
          );
        if (["INVALID_EMAIL", "MISSING_EMAIL"].includes(code))
          failure(400, "INVALID_EMAIL", "Enter a valid email address.");
        if (code === "MISSING_PASSWORD")
          failure(
            400,
            "PASSWORD_REQUIRED",
            "Enter and confirm your password.",
          );
        if (
          [
            "ADMIN_ONLY_OPERATION",
            "ADMIN_RESTRICTED_OPERATION",
            "OPERATION_NOT_ALLOWED",
            "PASSWORD_LOGIN_DISABLED",
          ].includes(code)
        )
          failure(
            503,
            "SIGN_UP_DISABLED",
            "Email signup is unavailable. Use Google or contact support.",
          );
        if (code === "QUOTA_EXCEEDED")
          failure(
            429,
            "SIGN_UP_LIMIT_REACHED",
            "Too many signup attempts. Try again later.",
          );
        if (
          [
            "CAPTCHA_CHECK_FAILED",
            "MISSING_RECAPTCHA_TOKEN",
            "INVALID_RECAPTCHA_TOKEN",
          ].includes(code)
        )
          failure(
            400,
            "SIGN_UP_VERIFICATION_FAILED",
            "Signup security check failed. Refresh and try again.",
          );
        if (code === "USER_DISABLED")
          failure(
            403,
            "ACCOUNT_DISABLED",
            "Account disabled. Contact support.",
          );
      }
      if (code === "PASSWORD_LOGIN_DISABLED")
        failure(
          503,
          "PASSWORD_LOGIN_DISABLED",
          "Password sign-in is unavailable. Use Google or contact support.",
        );
      if (
        [
          "OPERATION_NOT_ALLOWED",
          "CONFIGURATION_NOT_FOUND",
          "INVALID_API_KEY",
          "API_KEY_INVALID",
        ].includes(code) ||
        response.status === 403 ||
        response.status >= 500
      )
        failure(
          503,
          "AUTH_UNAVAILABLE",
          method === "signUp"
            ? "Signup is unavailable. Try again later or contact support."
            : "Sign-in is temporarily unavailable. Please try again.",
        );
      if (method === "signUp")
        failure(
          400,
          "SIGN_UP_FAILED",
          "Could not create your account. Try again or contact support with the reference below.",
        );
      failure(
        401,
        "SIGN_IN_FAILED",
        "Check your sign-in details or reset your password.",
      );
    }
    return result;
  }
  function tokens(value: Record<string, any>): IdentityTokens {
    if (value.mfaPendingCredential)
      throw new HttpError(
        403,
        "IDENTITY_MFA_REQUIRED",
        "This account requires two-step verification. Contact support.",
      );
    if (
      typeof value.idToken !== "string" ||
      typeof value.refreshToken !== "string" ||
      value.idToken.length > 16000 ||
      value.refreshToken.length > 4000
    )
      throw new HttpError(
        503,
        "AUTH_UNAVAILABLE",
        "Sign-in is temporarily unavailable.",
      );
    return { idToken: value.idToken, refreshToken: value.refreshToken };
  }
  return {
    verify,
    password: async (email, password, signup) =>
      tokens(
        await call(signup ? "signUp" : "signInWithPassword", {
          email,
          password,
          returnSecureToken: true,
        }),
      ),
    google: async (credential, nonce, origin) => {
      let payload: JWTPayload;
      try {
        ({ payload } = await jwtVerify(credential, keys.google ?? googleKeys, {
          issuer: ["accounts.google.com", "https://accounts.google.com"],
          audience: config.googleClientId,
          algorithms: ["RS256"],
        }));
        if (payload.nonce !== nonce) throw Error();
      } catch {
        throw new HttpError(
          401,
          "UNAUTHENTICATED",
          "Google sign-in could not be verified. Please try again.",
        );
      }
      const result = tokens(
        await call("signInWithIdp", {
          requestUri: origin,
          postBody: new URLSearchParams({
            id_token: credential,
            providerId: "google.com",
          }).toString(),
          returnSecureToken: true,
          returnIdpCredential: false,
        }),
      );
      const managed = await verify(result.idToken);
      if (
        managed.firebase.sign_in_provider !== "google.com" ||
        typeof payload.email !== "string" ||
        managed.email.toLowerCase() !== payload.email.toLowerCase()
      )
        throw new HttpError(
          401,
          "UNAUTHENTICATED",
          "Google sign-in could not be verified. Please try again.",
        );
      return {
        ...result,
        authoritativeEmail:
          payload.email_verified === true &&
          ((typeof payload.email === "string" &&
            payload.email.toLowerCase().endsWith("@gmail.com")) ||
            typeof payload.hd === "string"),
      };
    },
    refresh: async (token) => {
      let response: Response;
      let result: Record<string, any>;
      try {
        response = await transport(
          `https://securetoken.googleapis.com/v1/token?key=${encodeURIComponent(config.apiKey)}`,
          {
            method: "POST",
            headers: { "content-type": "application/x-www-form-urlencoded" },
            body: new URLSearchParams({
              grant_type: "refresh_token",
              refresh_token: token,
            }),
            signal: AbortSignal.timeout(15000),
            redirect: "error",
          },
        );
        result = (await response.json()) as Record<string, any>;
      } catch {
        throw new HttpError(
          503,
          "AUTH_UNAVAILABLE",
          "Sign-in is temporarily unavailable.",
        );
      }
      if (!response.ok)
        throw new HttpError(401, "SIGN_IN_REQUIRED", "Please sign in again.");
      return tokens({
        idToken: result.id_token,
        refreshToken: result.refresh_token,
      });
    },
    sendVerification: async (token, origin) => {
      await call("sendOobCode", {
        requestType: "VERIFY_EMAIL",
        idToken: token,
        continueUrl: origin + "/login",
      });
    },
    resetPassword: async (email, origin) => {
      try {
        await call("sendOobCode", {
          requestType: "PASSWORD_RESET",
          email,
          continueUrl: origin + "/login",
        });
      } catch (error) {
        if (error instanceof HttpError && error.status === 401) return;
        throw error;
      }
    },
  };
}
