import { parse } from "tldts";

const RESERVED = new Set(["localhost", "local", "invalid", "test", "example", "example.com"]);

export class DomainError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DomainError";
  }
}

/** IDNA-normalize a customer domain and reject names BearPortal will not host. */
export function normalizeDomain(input: string): string {
  let value = input.trim().toLowerCase();
  if (value.endsWith(".")) value = value.slice(0, -1);
  if (value.length === 0 || value.includes("://") || value.includes("/") || value.includes(" ") || value.includes("@")) {
    throw new DomainError("Enter a domain name.");
  }
  if (netIsIp(value)) throw new DomainError("A domain name is required.");
  let ascii: string;
  try {
    ascii = value.split(".").map((label) => {
      if (label.length === 0 || label.length > 63) throw new DomainError("A domain label is empty or too long.");
      return puny(label);
    }).join(".");
  } catch (error) {
    if (error instanceof DomainError) throw error;
    throw new DomainError("The domain name is not valid.");
  }
  if (ascii.length > 253) throw new DomainError("The domain name is too long.");
  const parsed = parse(ascii, { allowPrivateDomains: false });
  if (!parsed.domain || parsed.isIcann !== true) throw new DomainError("The domain is not a public DNS name.");
  if (RESERVED.has(ascii) || ascii.endsWith(".local") || ascii.endsWith(".localhost")) {
    throw new DomainError("That domain cannot be hosted.");
  }
  return ascii;
}

export function emailDomain(email: string): string {
  const at = email.lastIndexOf("@");
  if (at < 1 || at === email.length - 1) throw new DomainError("The recovery email is not valid.");
  return normalizeDomain(email.slice(at + 1));
}

/** The recovery mailbox must not live on the domain being hosted. */
export function recoveryIsOutsideDomain(recoveryEmail: string, hostedDomain: string): boolean {
  const recovery = emailDomain(recoveryEmail);
  const hosted = normalizeDomain(hostedDomain);
  return recovery !== hosted && !recovery.endsWith(`.${hosted}`);
}

function puny(label: string): string {
  return new URL(`http://${label}`).hostname;
}

function netIsIp(value: string): boolean {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(value) || value.includes(":");
}
