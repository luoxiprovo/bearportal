import { dnsCredentialSchema } from "../../../contracts/src/index.ts";

export type DnsCredential = ReturnType<typeof dnsCredentialSchema.parse>;

/**
 * Credential shape is the file bearmail-install reads.
 * publishBrevoRecords writes only the Brevo verification set. The installer still publishes mail records.
 */
export function validateCredentialShape(input: unknown): DnsCredential {
  return dnsCredentialSchema.parse(input);
}

export function credentialProvider(input: DnsCredential): DnsCredential["provider"] {
  return input.provider;
}

export { assessZoneRead, planDnsRecords } from "./plan.ts";
export type { DnsPlanInput, DnsRecord } from "./plan.ts";
export { detectDnsProvider } from "./detect.ts";
export type { DetectedDnsProvider } from "./detect.ts";
export { lookupNameservers } from "./nameservers.ts";
export { publishBrevoRecords } from "./publish-brevo.ts";
export type { DnsCredentialMaterial, DnsTransport, PublishBrevoResult } from "./publish-brevo.ts";
export { unavailableZoneReader } from "./reader.ts";
export type { ZoneReadRequest, ZoneReadResult, ZoneReader } from "./reader.ts";
