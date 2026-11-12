import type { FastifyRequest } from "fastify";
export function cookieValue(request: FastifyRequest, name: string): string {
  const raw = request.headers.cookie
    ?.split(";")
    .map((part) => part.trim())
    .find((part) => part.startsWith(name + "="));
  try {
    return raw ? decodeURIComponent(raw.slice(name.length + 1)) : "";
  } catch {
    return "";
  }
}
export function cookie(
  name: string,
  value: string,
  origin: string,
  path = "/",
  maxAge?: number,
): string {
  return `${name}=${encodeURIComponent(value)}; HttpOnly; SameSite=Lax; Path=${path}${origin.startsWith("https:") ? "; Secure" : ""}${maxAge === undefined ? "" : "; Max-Age=" + maxAge}`;
}
