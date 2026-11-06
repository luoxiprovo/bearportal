export type DetectedDnsProvider = "namecom" | "hostinger" | "godaddy";

const PROVIDERS: Array<{ provider: DetectedDnsProvider; pattern: RegExp }> = [
  { provider: "namecom", pattern: /(^|\.)name\.com$/ },
  { provider: "hostinger", pattern: /(^|\.)(hostinger\.com|dns-parking\.com)$/ },
  { provider: "godaddy", pattern: /(^|\.)domaincontrol\.com$/ },
];

/** Classify authoritative nameservers. A mixed or unknown set has no provider. */
export function detectDnsProvider(nameservers: string[]): DetectedDnsProvider | null {
  const names = nameservers.map((name) => name.trim().toLowerCase().replace(/\.$/, "")).filter((name) => name.length > 0);
  if (names.length === 0) return null;
  const matched = new Set<DetectedDnsProvider>();
  for (const name of names) {
    const provider = PROVIDERS.find((item) => item.pattern.test(name))?.provider ?? null;
    if (!provider) return null;
    matched.add(provider);
  }
  if (matched.size !== 1) return null;
  return [...matched][0] ?? null;
}
