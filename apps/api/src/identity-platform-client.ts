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
      const code = String(result.error?.message ?? "").split(" : ")[0];
      if(code==='PASSWORD_LOGIN_DISABLED')throw new HttpError(503,'PASSWORD_LOGIN_DISABLED','Email/password sign-in is not enabled yet. Use Google sign-in or contact the operator.');
      if (code === "TOO_MANY_ATTEMPTS_TRY_LATER" || response.status === 429)
        throw new HttpError(
          429,
          "AUTH_RATE_LIMITED",
          "Too many attempts. Wait before trying again.",
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
        throw new HttpError(
          503,
          "AUTH_UNAVAILABLE",
          "Sign-in is temporarily unavailable. Please try again.",
        );
      if (method === "signUp") {
        if (["WEAK_PASSWORD", "PASSWORD_DOES_NOT_MEET_REQUIREMENTS"].includes(code))
          throw new HttpError(
            400,
            "PASSWORD_REQUIREMENTS",
            "Choose a stronger password with at least 12 characters, including uppercase and lowercase letters, a number and a symbol.",
          );
        if (code === "INVALID_EMAIL")
          throw new HttpError(400, "INVALID_EMAIL", "Enter a valid email address.");
        if (["ADMIN_ONLY_OPERATION", "ADMIN_RESTRICTED_OPERATION"].includes(code))
          throw new HttpError(503, "SIGN_UP_DISABLED", "New account registration is not enabled. Contact the operator.");
        throw new HttpError(
          400,
          "SIGN_UP_FAILED",
          "Account creation could not be completed. If you registered before, including with Google, sign in instead or use password reset. Otherwise, check your email and password and try again.",
        );
      }
      throw new HttpError(
        401,
        "SIGN_IN_FAILED",
        "Sign-in could not be completed. Check your details or use password reset.",
      );
    }
    return result;
  }
  function tokens(value: Record<string, any>): IdentityTokens {
    if (value.mfaPendingCredential)
      throw new HttpError(
        403,
        "IDENTITY_MFA_REQUIRED",
        "This account requires its configured second factor. Contact the operator to complete sign-in.",
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
