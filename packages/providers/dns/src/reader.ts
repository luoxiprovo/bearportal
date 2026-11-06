import type { DnsRecord } from "./plan.ts";

export type ZoneReadRequest = {
  provider: string;
  zone: string;
  domain: string;
};

export type ZoneReadResult =
  | { ok: true; snapshot: { zone: string; nameservers: string[]; records: DnsRecord[] } }
  | { ok: false; code: "PROOF_REJECTED" | "PROOF_EXPIRED" | "DNS_READER_UNAVAILABLE" };

export interface ZoneReader {
  readZone(input: ZoneReadRequest): Promise<ZoneReadResult>;
}

/** Production default. It does not call a DNS provider and it does not receive credentials. */
export function unavailableZoneReader(): ZoneReader {
  return {
    async readZone(): Promise<ZoneReadResult> {
      return { ok: false, code: "DNS_READER_UNAVAILABLE" };
    },
  };
}
