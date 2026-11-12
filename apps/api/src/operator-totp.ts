import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { Secret, TOTP } from "otpauth";
export const hashToken = (value: string) =>
  createHash("sha256").update(value).digest("hex");
export function newAuthenticator(email: string, secret?: string) {
  return new TOTP({
    issuer: "BearPortal",
    label: email,
    algorithm: "SHA1",
    digits: 6,
    period: 30,
    secret: secret ? Secret.fromBase32(secret) : new Secret({ size: 20 }),
  });
}
export function verifyAuthenticator(
  secret: string,
  token: string,
  lastCounter: number,
  now = Date.now(),
): number | null {
  if (!/^\d{6}$/.test(token)) return null;
  const delta = newAuthenticator("", secret).validate({
    token,
    window: 1,
    timestamp: now,
  });
  if (delta === null) return null;
  const counter = Math.floor(now / 30000) + delta;
  return counter > lastCounter ? counter : null;
}
export function recoveryCodes() {
  return Array.from({ length: 10 }, () =>
    randomBytes(16).toString("hex").match(/.{8}/g)!.join("-"),
  );
}
export const recoveryHash = (value: string) =>
  hashToken(value.replace(/[-\s]/g, "").toLowerCase());
export function sameHash(a: string, b: string) {
  return (
    a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b))
  );
}
