import { importPKCS8, SignJWT } from "jose";

/** Sign a development identity. Production startup never calls this. */
export async function signDevIdentity(privateKeyPem: string, issuer: string, audience: string, email: string): Promise<string> {
  const key = await importPKCS8(privateKeyPem, "RS256");
  const authTime = Math.floor(Date.now() / 1000);
  return new SignJWT({
    email,
    email_verified: true,
    auth_time: authTime,
    amr: ["pwd"],
  })
    .setProtectedHeader({ alg: "RS256" })
    .setSubject(`local:${email}`)
    .setIssuer(issuer)
    .setAudience(audience)
    .setIssuedAt(authTime)
    .setExpirationTime("12h")
    .sign(key);
}
