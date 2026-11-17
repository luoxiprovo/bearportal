/** Interactive DNS cleanup, independent of customer/database reset commands. */
import { resolveNs } from "node:dns/promises";
import { domainToASCII, fileURLToPath } from "node:url";
import { isIP } from "node:net";
import { createInterface } from "node:readline/promises";
import { Writable } from "node:stream";
import { mkdirSync, mkdtempSync, writeFileSync, renameSync, rmSync } from "node:fs";
import { join } from "node:path";
import { parseArgs } from "node:util";
import { detectDnsProvider } from "../packages/providers/dns/src/detect.ts";
import type { DnsCredentialMaterial } from "../packages/providers/dns/src/publish-brevo.ts";

export class DnsCleanupError extends Error {}
class DnsCleanupCanceled extends DnsCleanupError {}
let deletionMayHaveStarted = false;
export type ZoneRecord = { type: string; name: string; value: string; id?: number; raw: Record<string, unknown> };
type Transport = (url: string, init: RequestInit) => Promise<Response>;
export function normalizeDomain(input: string) {
  const clean = input.trim();
  if (/[\s/\\:@?#%]/.test(clean)) throw new DnsCleanupError("Enter a DNS zone domain such as example.com, without a URL, email, wildcard or path.");
  const domain = domainToASCII(clean.toLowerCase().replace(/\.$/, ""));
  if (!domain || domain.length > 253 || isIP(domain) || !domain.includes(".") ||
      domain.split(".").some(label => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label)))
    throw new DnsCleanupError("Enter a DNS zone domain such as example.com, without a URL, email, wildcard or path.");
  return domain;
}
export function relativeName(input: string, domain: string) {
  const name = input.trim().toLowerCase().replace(/\.$/, "");
  if (!name || name === "@" || name === domain) return "@";
  return name.endsWith("." + domain) ? name.slice(0, -(domain.length + 1)) : name;
}
export function keepReason(record: ZoneRecord): string | null {
  if (record.type === "A" && ["@", "www"].includes(record.name)) return "A record requested for preservation";
  if (record.name === "@" && ["NS", "SOA"].includes(record.type)) return "Zone authority record";
  return null;
}
export function planRecords(records: ZoneRecord[]) {
  return { preserved: records.filter(r => keepReason(r)), selected: records.filter(r => !keepReason(r)) };
}
function object(value: unknown): Record<string, any> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new DnsCleanupError("Invalid DNS provider response; nothing further was deleted.");
  return value as Record<string, any>;
}
function fingerprint(records: ZoneRecord[]) {
  function stable(value: any): any {
    if (Array.isArray(value)) return value.map(stable);
    if (value && typeof value === "object") return Object.fromEntries(Object.keys(value).sort().map(k => [k, stable(value[k])]));
    return value;
  }
  return JSON.stringify(records.map(r => JSON.stringify(stable(r))).sort());
}
export function createDnsCleanupClient(domain: string, credential: DnsCredentialMaterial, transport: Transport = fetch) {
  const provider = credential.provider;
  const token = credential.token;
  if (!token || /[\r\n]/.test(token) || (provider === "namecom" && (!credential.username || /[\r\n:]/.test(credential.username))))
    throw new DnsCleanupError("Invalid API credential.");
  const headers = {
    accept: "application/json", "content-type": "application/json",
    authorization: provider === "namecom" ? "Basic " + Buffer.from(credential.username + ":" + token).toString("base64") : "Bearer " + token,
  };
  const base = provider === "namecom" ? `https://api.name.com/v4/domains/${encodeURIComponent(domain)}/records`
    : provider === "hostinger" ? `https://developers.hostinger.com/api/dns/v1/zones/${encodeURIComponent(domain)}`
    : `https://api.godaddy.com/v1/domains/${encodeURIComponent(domain)}/records`;
  async function request(method: "GET" | "DELETE", url = base, body?: unknown): Promise<any> {
    let response: Response;
    try {
      response = await transport(url, { method, headers, body: body === undefined ? undefined : JSON.stringify(body),
        redirect: "error", signal: AbortSignal.timeout(20_000) });
    } catch { throw new DnsCleanupError("DNS request failed or timed out. Check the backup/receipt before retrying; the provider may already have applied a deletion."); }
    if (!response.ok) throw new DnsCleanupError(`DNS provider returned HTTP ${response.status}. Check domain access and API permissions. Earlier deletions remain applied.`);
    const text = await response.text();
    if (!text.trim()) return {};
    // A provider response must never echo the supplied credential into preview or backup.
    if ((token.length >= 4 && text.includes(token)) || text.includes(headers.authorization)) throw new DnsCleanupError("DNS response echoed credential material; stopped without displaying it.");
    try { return JSON.parse(text); } catch { throw new DnsCleanupError("Invalid JSON from DNS provider; inspect the receipt before retrying."); }
  }
  function record(raw: Record<string, any>, type: unknown, name: unknown, value: unknown, id?: unknown): ZoneRecord {
    if (typeof type !== "string" || !/^[A-Z][A-Z0-9]*$/i.test(type) || typeof name !== "string" || typeof value !== "string")
      throw new DnsCleanupError(`Unrecognized DNS record (type field: ${typeof type}; name field: ${typeof name}; value field: ${typeof value}). Stopped instead of omitting it.`);
    if (id !== undefined && (!Number.isSafeInteger(id) || (id as number) <= 0)) throw new DnsCleanupError("Invalid DNS record ID.");
    return { type: type.toUpperCase(), name: relativeName(name, domain), value, ...(id === undefined ? {} : { id: id as number }), raw };
  }
  function namecomRecord(raw: Record<string, any>): ZoneRecord {
    if (raw.domainName !== undefined && (typeof raw.domainName !== "string" || raw.domainName.toLowerCase().replace(/\.$/, "") !== domain))
      throw new DnsCleanupError("DNS response belongs to another zone.");
    if (raw.id === undefined) throw new DnsCleanupError("Missing DNS record ID.");
    // Name.com's JSON can omit empty string fields. An omitted host is the apex;
    // if fqdn is supplied, use it to distinguish the apex from a named record.
    let host = raw.host;
    if (raw.fqdn !== undefined) {
      if (typeof raw.fqdn !== "string") throw new DnsCleanupError("Invalid Name.com fqdn field.");
      const fqdn = raw.fqdn.toLowerCase().replace(/\.$/, "");
      if (fqdn !== domain && !fqdn.endsWith("." + domain))
        throw new DnsCleanupError("Name.com record fqdn belongs to another zone.");
      if (host === undefined) host = relativeName(fqdn, domain);
      else if (typeof host === "string" && relativeName(host, domain) !== relativeName(fqdn, domain))
        throw new DnsCleanupError("Name.com host and fqdn fields do not match.");
    }
    if (host === undefined) host = "";
    // An empty TXT answer can also be omitted; never invent an A record address.
    const answer = raw.answer === undefined && raw.type === "TXT" ? "" : raw.answer;
    return record(raw, raw.type, host, answer, raw.id);
  }
  async function list(): Promise<ZoneRecord[]> {
    const records: ZoneRecord[] = [];
    if (provider === "namecom") {
      let page = 1;
      const seen = new Set<number>();
      while (page) {
        if (seen.has(page)) throw new DnsCleanupError("Repeated DNS pagination page; stopped.");
        seen.add(page);
        const result = object(await request("GET", base + `?perPage=1000&page=${page}`));
        if (result.records !== undefined && !Array.isArray(result.records)) throw new DnsCleanupError("Invalid DNS record list.");
        for (const item of result.records ?? []) {
          const raw = object(item);
          records.push(namecomRecord(raw));
        }
        page = result.nextPage ?? 0;
        if (!Number.isSafeInteger(page) || page < 0) throw new DnsCleanupError("Invalid DNS pagination page.");
      }
      if (new Set(records.map(r => r.id)).size !== records.length) throw new DnsCleanupError("Duplicate DNS IDs; stopped.");
    } else if (provider === "hostinger") {
      const groups = await request("GET");
      if (!Array.isArray(groups)) throw new DnsCleanupError("Invalid Hostinger zone list.");
      for (const item of groups) {
        const raw = object(item);
        if (!Array.isArray(raw.records)) throw new DnsCleanupError("Invalid Hostinger record group.");
        for (const child of raw.records) {
          const value = object(child);
          records.push(record({ ...raw, records: [value] }, raw.type, raw.name, value.content));
        }
      }
    } else {
      let offset = 0;
      const pages = new Set<string>();
      while (true) {
        const rows = await request("GET", base + `?limit=100&offset=${offset}`);
        if (!Array.isArray(rows)) throw new DnsCleanupError("Invalid GoDaddy record list.");
        if (!rows.length) break;
        const signature = JSON.stringify(rows);
        if (pages.has(signature)) throw new DnsCleanupError("GoDaddy repeated a page; refusing an incomplete zone listing.");
        pages.add(signature);
        for (const item of rows) { const raw = object(item); records.push(record(raw, raw.type, raw.name, raw.data)); }
        offset += rows.length;
      }
    }
    return records;
  }
  function validateDeletion(records: ZoneRecord[]) {
    for (const r of records) {
      if (keepReason(r)) throw new DnsCleanupError("Refusing to delete a preserved record.");
      if (provider === "godaddy" && !["A", "AAAA", "CAA", "CNAME", "MX", "SRV", "TXT"].includes(r.type))
        throw new DnsCleanupError(`GoDaddy's supported delete endpoint cannot delete ${r.type}. Review this record manually; nothing was deleted.`);
      if (provider === "hostinger" && !["A", "AAAA", "CNAME", "ALIAS", "MX", "TXT", "NS", "SOA", "SRV", "CAA"].includes(r.type))
        throw new DnsCleanupError("Unsupported Hostinger record type; nothing was deleted.");
    }
  }
  async function remove(records: ZoneRecord[], done: (description: string) => void) {
    validateDeletion(records);
    if (provider === "namecom") {
      for (const r of records) {
        const raw = object(await request("GET", base + "/" + r.id));
        const current = namecomRecord(raw);
        if (keepReason(current) || fingerprint([current]) !== fingerprint([r]))
          throw new DnsCleanupError("DNS record changed before deletion; inspect the receipt and rerun preview.");
        await request("DELETE", base + "/" + r.id);
        done(`${r.type} ${r.name} id=${r.id}`);
      }
    } else {
      const groups = new Map<string, ZoneRecord>();
      for (const r of records) groups.set(r.type + "|" + r.name, r);
      for (const r of groups.values()) {
        if (provider === "hostinger") await request("DELETE", base, { filters: [{ name: r.raw.name, type: r.type }] });
        else await request("DELETE", base + "/" + encodeURIComponent(r.type) + "/" + encodeURIComponent(r.name));
        done(`${r.type} ${r.name}`);
      }
    }
  }
  return { list, remove, validateDeletion };
}

export async function applyCleanup(input: {
  before: ZoneRecord[];
  client: Pick<ReturnType<typeof createDnsCleanupClient>, "list" | "remove" | "validateDeletion">;
  checkProvider: () => Promise<void>;
  backup: () => void;
  record: (description: string) => void;
  progress?: (stage: "recheck" | "backup" | "delete" | "verify") => void;
}) {
  input.client.validateDeletion(planRecords(input.before).selected);
  input.progress?.("recheck");
  await input.checkProvider();
  if (fingerprint(await input.client.list()) !== fingerprint(input.before)) throw new DnsCleanupError("DNS zone changed after preview; rerun the command to review it again.");
  input.progress?.("backup");
  input.backup(); // A failed snapshot must prevent any deletion.
  input.progress?.("delete");
  await input.client.remove(planRecords(input.before).selected, input.record);
  input.progress?.("verify");
  const after = await input.client.list();
  // SOA serials advance normally when records are deleted; preserve authority without comparing serial text.
  const verification = (rows: ZoneRecord[]) => rows.map(r => r.type === "SOA" && r.name === "@"
    ? { ...r, value: "", raw: {} } : r);
  if (planRecords(after).selected.length || fingerprint(verification(after)) !== fingerprint(verification(planRecords(input.before).preserved)))
    throw new DnsCleanupError("DNS verification found remaining or changed records. Inspect the backup and receipt before retrying.");
}
async function main() {
  const { values } = parseArgs({ options: { domain: { type: "string" }, apply: { type: "boolean" }, help: { type: "boolean" } } });
  if (values.help) {
    console.log("pnpm dns:cleanup [--domain example.com] [--apply]\nPrompts for domain and provider API credentials. Detects Name.com, Hostinger or GoDaddy from authoritative nameservers.\nDefault: preview only. --apply additionally asks you to type the domain after preview.\nKeeps all A records at @ and www, and apex NS/SOA authority records; deletes other editable records.\nCreates a private zone backup/receipt before deletion. Secrets are never echoed or saved. Do not run while BearPortal or another tool is publishing DNS for the domain.");
    return;
  }
  if (!process.stdin.isTTY || !process.stdout.isTTY) throw new DnsCleanupError("Run in an interactive terminal so API credentials can be entered privately.");
  let muted = false;
  const output = new Writable({ write(chunk, _encoding, callback) { if (!muted) process.stdout.write(chunk); callback(); } });
  const terminal = createInterface({ input: process.stdin, output, terminal: true, historySize: 0 });
  const cancellation = new AbortController();
  terminal.on("SIGINT", () => cancellation.abort());
  terminal.on("close", () => cancellation.abort());
  async function ask(label: string, secret = false, allowEmpty = false) {
    while (true) {
      if (cancellation.signal.aborted) throw new DnsCleanupCanceled("Canceled. No DNS deletion was requested.");
      // Give readline the actual prompt so redraws cannot erase a separately printed label.
      if (secret) process.stdout.write(label);
      muted = secret;
      let answer: string;
      try { answer = (await terminal.question(label, { signal: cancellation.signal })).trim(); }
      catch (error) {
        if (cancellation.signal.aborted) throw new DnsCleanupCanceled("Canceled. No DNS deletion was requested.");
        throw error;
      } finally { muted = false; if (secret) process.stdout.write("\n"); }
      if (answer || allowEmpty) return answer;
      console.log("A value is required. Enter it, then press Enter. Press Ctrl+C to cancel.");
    }
  }
  const step = (number: number, title: string) => console.log(`\nStep ${number}/8 — ${title}`);
  let receiptPath: string | undefined;
  let lock: string | undefined;
  try {
    console.log("DNS cleanup — keep @ and www A records");
    console.log(values.apply ? "Apply mode: nothing will be deleted until you review the records and type the exact domain to confirm." : "Preview mode: records will only be listed. Nothing will be deleted.");
    console.log("Enter each answer and press Enter. API tokens are hidden while typing. Press Ctrl+C at any prompt to cancel.");
    step(1, "Choose the domain");
    const domain = normalizeDomain(values.domain ?? await ask("Enter the DNS zone domain only (example.com): "));
    console.log("Selected domain: " + domain);
    step(2, "Detect the DNS provider");
    console.log("Looking up authoritative nameservers. Please wait…");
    const nameservers = await resolveNs(domain);
    const provider = detectDnsProvider(nameservers);
    if (!provider) throw new DnsCleanupError("Unknown or mixed DNS provider. Supported providers are Name.com, Hostinger and GoDaddy; no credentials requested and no records changed.");
    console.log(`Domain: ${domain}\nDNS provider: ${provider}\nNameservers: ${nameservers.join(", ")}`);
    step(3, "Enter credentials for " + (provider === "namecom" ? "Name.com" : provider === "hostinger" ? "Hostinger" : "GoDaddy"));
    if (provider === "namecom") {
      console.log("Open your Name.com account → API settings. You need the API username and API token for an account that can manage this domain.");
      console.log("Enter the username first, then the token. Do not enter your email or account password in place of the API credentials.");
    } else if (provider === "hostinger") {
      console.log("Open Hostinger hPanel → profile → API. Create or copy an API token authorized to read and delete DNS records for this domain.");
    } else {
      console.log("Open https://developer.godaddy.com/en/personal-access-token and create or copy a personal access token with DNS read/update access for this domain.");
      console.log("Use the personal access token, not a legacy API key/secret pair.");
    }
    console.log("The token prompt will look blank while you type or paste. This is expected; press Enter when finished. Credentials are not saved.");
    const credential: DnsCredentialMaterial = provider === "namecom"
      ? { provider, username: await ask("Name.com API username (visible): "), token: await ask("Name.com API token (hidden; paste token, then press Enter): ", true) }
      : { provider, token: await ask(provider === "godaddy" ? "GoDaddy personal access token (hidden; paste token, then press Enter): " : "Hostinger API token (hidden; paste token, then press Enter): ", true) };
    const client = createDnsCleanupClient(domain, credential);
    console.log("Reading all DNS records from the provider. Please wait…");
    const records = await client.list();
    const plan = planRecords(records);
    step(4, "Review the records");
    console.log("KEEP records remain unchanged. DELETE records will be removed only after confirmation.");
    console.log("@ means the bare domain. Only A records at @ and www are kept, together with apex NS/SOA authority records.");
    console.log("ACTION\tTYPE\tNAME\tVALUE\tREASON (when preserved)");
    for (const [action, rows] of [["KEEP", plan.preserved], ["DELETE", plan.selected]] as const)
      for (const r of rows) console.log(`${action}\t${r.type}\t${r.name}\t${JSON.stringify(r.value)}${action === "KEEP" ? "\t" + keepReason(r) : ""}`);
    console.log(`Domain: ${domain} | Provider: ${provider} | Keep: ${plan.preserved.length} records | Delete: ${plan.selected.length} records`);
    if (!values.apply) { console.log(`Preview complete. Nothing changed. To review again and delete, run: pnpm dns:cleanup --domain ${domain} --apply`); return; }
    if (!plan.selected.length) { console.log("Cleanup is already complete: no records are selected for deletion. Nothing changed."); return; }
    client.validateDeletion(plan.selected);
    step(5, "Confirm deletion");
    console.log(`You are about to delete ${plan.selected.length} records from ${domain}, including any listed mail-routing, verification and subdomain records.`);
    console.log("Pause BearPortal setups and other DNS writers for this domain before continuing. A private backup will be saved before the first deletion.");
    console.log("Type the exact domain below and press Enter to proceed. Leave blank or enter anything else to cancel.");
    if (await ask(`Confirm domain [${domain}]: `, false, true) !== domain) { console.log("Canceled. Nothing deleted."); return; }
    const root = fileURLToPath(new URL("..", import.meta.url));
    const backupRoot = join(root, ".data/backups");
    mkdirSync(backupRoot, { recursive: true, mode: 0o700 });
    const data = join(root, ".data");
    const candidate = join(data, `dns-cleanup-${domain}.lock`);
    try { mkdirSync(candidate, { mode: 0o700 }); } catch { throw new DnsCleanupError("DNS cleanup lock exists or cannot be created. Ensure no other cleanup is running before retrying."); }
    lock = candidate;
    writeFileSync(join(lock, "owner.json"), JSON.stringify({ pid: process.pid, domain }), { mode: 0o600 });
    const receipt = { domain, provider, nameservers, records, deleted: [] as string[], complete: false };
    const save = () => {
      if (!receiptPath) throw new DnsCleanupError("Backup is not initialized.");
      writeFileSync(receiptPath + ".tmp", JSON.stringify(receipt, null, 2), { mode: 0o600 });
      renameSync(receiptPath + ".tmp", receiptPath);
    };
    await applyCleanup({ before: records, client,
      progress: stage => {
        if (stage === "recheck") { step(6, "Recheck the zone and save a backup"); console.log("Checking that nameservers and records have not changed since your preview…"); }
        if (stage === "backup") console.log("Saving the current zone and deletion receipt to a private backup. No deletion has started yet…");
        if (stage === "delete") { deletionMayHaveStarted = true; step(7, "Delete selected records and verify the result"); console.log(`Deleting the ${plan.selected.length} selected records. No more input is needed. Each completed delete request is printed below…`); }
        if (stage === "verify") console.log("Deletion requests finished. Reading the zone again to verify the selected records are gone and preserved records are unchanged…");
      },
      checkProvider: async () => {
        const current = await resolveNs(domain);
        if (detectDnsProvider(current) !== provider || JSON.stringify([...current].map(s => s.toLowerCase().replace(/\.$/, "")).sort()) !== JSON.stringify([...nameservers].map(s => s.toLowerCase().replace(/\.$/, "")).sort()))
          throw new DnsCleanupError("Authoritative nameservers changed since preview; stopped.");
      },
      backup: () => {
        const directory = mkdtempSync(join(backupRoot, `dns-cleanup-${domain}-`));
        receiptPath = join(directory, "zone-backup-and-receipt.json"); save();
        console.log("Private DNS backup: " + receiptPath);
      },
      record: description => { receipt.deleted.push(description); save(); console.log("Deleted: " + description); },
    });
    receipt.complete = true; save();
    step(8, "Cleanup complete");
    console.log("DNS cleanup verified through the provider API. Preserved A records were unchanged. Cached DNS answers may persist until their TTL expires.");
  } finally {
    terminal.close();
    if (receiptPath) console.log("Backup/receipt: " + receiptPath);
    if (lock) rmSync(lock, { recursive: true });
  }
}
if (process.argv[1] === fileURLToPath(import.meta.url)) main().catch(error => {
  if (error instanceof DnsCleanupCanceled) { console.log(error.message); return; }
  console.error(error instanceof DnsCleanupError ? error.message : "DNS cleanup stopped. Check domain nameservers, API access and backup storage. No credential values were logged.");
  console.error(deletionMayHaveStarted ? "Deletion may have begun; earlier changes remain applied. Inspect the private backup/receipt before retrying." : "Stopped before deletion. No DNS records were changed.");
  process.exitCode = 1;
});
