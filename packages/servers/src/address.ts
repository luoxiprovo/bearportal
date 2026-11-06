const OCTET = /^(0|[1-9]\d{0,2})$/;

export class AddressError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AddressError";
  }
}

/** Accept a public unicast IPv4 address. Documentation ranges such as 203.0.113.0/24 stay allowed. */
export function assertPublicUnicastIpv4(value: string, blocked: readonly string[] = []): string {
  const trimmed = value.trim();
  const parts = trimmed.split(".");
  if (parts.length !== 4 || parts.some((part) => !OCTET.test(part))) {
    throw new AddressError("A public unicast IPv4 address is required.");
  }
  const numbers = parts.map((part) => Number(part));
  if (numbers.some((part) => part > 255)) {
    throw new AddressError("A public unicast IPv4 address is required.");
  }
  const [a, b] = numbers;
  const rejected =
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    a >= 224;
  if (rejected || blocked.includes(trimmed)) {
    throw new AddressError("A public unicast IPv4 address is required.");
  }
  return numbers.join(".");
}
