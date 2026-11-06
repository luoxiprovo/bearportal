export function escapeHtml(value: unknown): string {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

export function demoBadge(): string {
  if (process.env.BEARPORTAL_ENV === "production") return "";
  return `<p class="demo">Development preview</p>`;
}

const HONESTY = `<p>Backups shown here are operator-reported. A reference is not cloud proof. This portal has no cloud setup, restore, or success button.</p>`;

const PAGE_STYLE = `<style>
:root { color-scheme: light; }
* { box-sizing: border-box; }
html { scroll-behavior: smooth; }
body { margin: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; color: #1d1d1f; background: #fff; line-height: 1.47; }
a { color: #0066cc; text-decoration: none; }
.nav { position: sticky; top: 0; z-index: 2; display: flex; align-items: center; gap: 1.25rem; min-height: 3rem; padding: 0 1.25rem; background: rgba(255,255,255,.86); backdrop-filter: saturate(180%) blur(20px); border-bottom: 1px solid rgba(0,0,0,.08); }
.mark { color: #1d1d1f; font-weight: 600; letter-spacing: -0.02em; }
.nav nav { display: flex; gap: 1.1rem; font-size: .8rem; }
.nav nav a { color: #1d1d1f; }
.demo { margin-left: auto; font-size: .7rem; color: #6e6e73; border: 1px solid #d2d2d7; border-radius: 980px; padding: .2rem .55rem; }
.hero, .band, .steps, .dark, .register, .fineprint { padding: 4.5rem 1.5rem; }
.wrap { max-width: 61rem; margin: 0 auto; }
.hero { text-align: center; padding-top: 5.5rem; padding-bottom: 5rem; }
.eyebrow { margin: 0 0 .8rem; font-size: .8rem; letter-spacing: .08em; text-transform: uppercase; color: #6e6e73; }
h1 { margin: 0; font-size: clamp(2.6rem, 6vw, 4.6rem); line-height: 1.05; letter-spacing: -0.035em; font-weight: 600; }
.lede { max-width: 40rem; margin: 1.1rem auto 0; font-size: clamp(1.15rem, 2vw, 1.5rem); line-height: 1.35; color: #6e6e73; }
.actions { display: flex; justify-content: center; gap: .8rem; margin-top: 1.6rem; }
.pill, input.pill { display: inline-block; border: 0; border-radius: 980px; padding: .7rem 1.15rem; background: #0071e3; color: #fff; font: inherit; font-size: 1.05rem; cursor: pointer; }
.pill.quiet { background: transparent; color: #0066cc; }
.band { background: #f5f5f7; }
.grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 1rem; margin-top: 2rem; }
.grid article, .register form { background: #fff; border-radius: 1.1rem; padding: 1.5rem; }
.grid h2, .steps h2, .register h2 { margin: 0 0 .5rem; font-size: 1.5rem; letter-spacing: -0.03em; }
.grid p, .steps p, .register p { margin: 0; color: #6e6e73; }
.steps ol { list-style: none; padding: 0; margin: 2rem 0 0; display: grid; gap: 1.25rem; }
.steps li { display: grid; grid-template-columns: 2.2rem 1fr; gap: .8rem; font-size: 1.25rem; }
.steps b { font-size: 1.4rem; letter-spacing: -0.03em; }
.dark { background: #000; color: #f5f5f7; text-align: center; }
.dark p { max-width: 40rem; margin: 0 auto; font-size: clamp(1.8rem, 4vw, 3rem); line-height: 1.15; letter-spacing: -0.03em; font-weight: 600; }
.register { background: #f5f5f7; text-align: center; }
.register form { max-width: 28rem; margin: 1.4rem auto 0; display: grid; gap: .85rem; text-align: left; }
.register form + p { margin-top: 1rem; }
.register input.pill { width: 100%; text-align: center; }
label { display: grid; gap: .3rem; font-size: .85rem; color: #6e6e73; }
label.check { display: flex; align-items: center; gap: .5rem; }
input[type="email"], input[type="text"], input[type="password"] { width: 100%; border: 1px solid #d2d2d7; border-radius: .7rem; padding: .75rem .8rem; font: inherit; font-size: 1.05rem; color: #1d1d1f; background: #fff; }
.app form { display: grid; gap: .75rem; max-width: 32rem; margin-top: 1rem; }
.app form input.pill { width: 100%; }
input:focus, .pill:focus { outline: 2px solid #0071e3; outline-offset: 2px; }
.banner { margin: 0; padding: .8rem 1.5rem; text-align: center; background: #fff4f4; color: #8d1024; }
.fineprint, .fine { color: #6e6e73; font-size: .8rem; }
.fineprint { padding-top: 2rem; padding-bottom: 3rem; }
.fineprint p, .fine { margin: .4rem 0; }
.app { background: #f5f5f7; }
.app main.sheet { max-width: 61rem; margin: 0 auto; padding: 2.2rem 1.25rem 4rem; }
.app h1 { font-size: clamp(2rem, 4vw, 3rem); }
.app section { background: #fff; border-radius: 1.1rem; padding: 1.25rem 1.2rem 1.4rem; margin-top: 1rem; }
.app h2 { font-size: 1.35rem; letter-spacing: -0.03em; }
.app dl { display: grid; grid-template-columns: minmax(8rem, 14rem) 1fr; gap: .45rem 1rem; margin: 0; }
.app dt { color: #6e6e73; font-weight: 500; }
.app dd { margin: 0; }
.app footer { max-width: 61rem; margin: 0 auto; padding: 0 1.25rem 2.5rem; }
@media (max-width: 800px) {
  .grid, .app dl { grid-template-columns: 1fr; }
  .nav { flex-wrap: wrap; padding: .6rem 1rem; }
  .demo { margin-left: 0; }
  .hero, .band, .steps, .dark, .register { padding: 3rem 1.1rem; }
}

:root { --ink:#1d1d1f; --muted:#6e6e73; --blue:#0071e3; --canvas:#f5f5f7; }
button { font-family:inherit; }
button.pill { display:flex; align-items:center; justify-content:space-between; gap:2rem; min-height:50px; font-weight:500; }
.pill:hover { background:#0077ed; }
a:hover { text-decoration:underline; }
.nav { padding:0 max(24px,calc((100vw - 1080px)/2)); min-height:64px; }
.nav .mark { font-size:21px; letter-spacing:-1px; }
.nav nav { margin-left:auto; }
.brand-dot { color:var(--blue); }
.landing { max-width:1080px; margin:auto; padding:96px 24px 112px; display:grid; grid-template-columns:1.2fr 1fr; align-items:center; gap:80px; }
.landing h1 { font-size:clamp(58px,7vw,88px); letter-spacing:-.055em; line-height:1.01; }
.soft { color:#86868b; }
.landing .lede { font-size:21px; margin:24px 0; max-width:420px; line-height:1.5; }
.text-link { display:inline-block; font-size:15px; margin-top:20px; }
.signup-card { background:var(--canvas); border:1px solid rgba(0,0,0,.025); border-radius:32px; padding:40px; }
.mail-icon { width:64px; height:64px; border-radius:19px; background:#fff; color:var(--blue); padding:8px; margin-bottom:30px; box-shadow:0 6px 20px #00000006; }
.signup-card h2 { font-size:34px; letter-spacing:-.04em; line-height:1.1; margin:0 0 16px; }
.signup-card>p { color:var(--muted); font-size:16px; }
.signup-form { display:grid; gap:12px; margin-top:28px; }
.signup-form label { font-size:13px; }
.preview-note { font-size:11px!important; line-height:1.5; margin-top:24px; }
.field-error { font-size:13px; color:#b42318; margin:0; }
.journey { background:var(--canvas); padding:80px max(24px,calc((100vw - 1032px)/2)); }
.journey h2 { font-size:44px; letter-spacing:-.04em; line-height:1.1; margin:16px 0 50px; }
.journey-grid { display:grid; grid-template-columns:repeat(3,1fr); gap:48px; }
.step-number { color:#86868b; font-size:13px; font-weight:600; }
.journey-grid h3 { letter-spacing:-.025em; font-size:21px; margin:16px 0 10px; }
.journey-grid p { font-size:15px; color:var(--muted); line-height:1.65; }
.home-footer { display:flex; align-items:center; justify-content:space-between; max-width:1080px; margin:auto; padding:28px 24px; font-size:12px; color:var(--muted); }
.customer main.sheet { padding:56px 24px 64px; max-width:1080px; }
.customer main.sheet>h1 { display:none; }
.welcome-heading h1 { font-size:clamp(36px,5vw,52px); letter-spacing:-.045em; margin:8px 0 14px; }
.welcome-heading>p:last-child { color:var(--muted); font-size:18px; margin:0; }
.progress { display:flex; padding:0; list-style:none; margin:40px 0; gap:48px; font-size:13px; color:var(--muted); }
.progress li { display:flex; align-items:center; gap:10px; }
.progress span { border:1px solid #d2d2d7; border-radius:50%; width:26px; height:26px; display:grid; place-items:center; font-size:11px; }
.progress .complete span { border-color:var(--ink); background:var(--ink); color:#fff; }
.progress .current { color:var(--blue); }
.progress .current span { border-color:var(--blue); }
.onboarding-grid { display:grid; grid-template-columns:1.7fr 1fr; gap:24px; align-items:start; }
.customer section.setup-card { margin:0; border-radius:24px; padding:40px; min-width:0; }
.setup-card h2 { font-size:32px; letter-spacing:-.04em; line-height:1.13; margin:12px 0 20px; overflow-wrap:anywhere; }
.setup-card>p { color:var(--muted); line-height:1.65; }
.setup-card .eyebrow { font-size:11px; }
.customer .setup-card form { max-width:none; gap:16px; margin-top:28px; }
.customer .setup-card input[type=text],.customer .setup-card input[type=password],.signup-form input { min-height:52px; border-radius:12px; font-size:16px; }
label.check { align-items:flex-start; font-size:13px; color:var(--muted); line-height:1.5; }
label.check input { margin:3px 5px 0 0; flex:none; accent-color:var(--blue); width:16px; height:16px; }
.consent { padding-top:12px; border-top:1px solid #efeff1; }
.setup-summary { padding:28px 12px 28px 24px; }
.setup-summary h3 { font-size:22px; letter-spacing:-.025em; margin:12px 0 24px; overflow-wrap:anywhere; }
.setup-summary ul { list-style:none; padding:0; margin:0; }
.setup-summary li { padding:15px 0; border-bottom:1px solid #e5e5e7; font-size:12px; display:flex; justify-content:space-between; gap:12px; }
.setup-summary li>span { color:var(--muted); }
.setup-summary strong { font-weight:500; text-align:right; overflow-wrap:anywhere; min-width:0; }
.setup-summary .fine { margin-top:22px; font-size:12px; line-height:1.6; }
.capacity-note { padding:20px 24px; border:1px solid #e6e1d6; border-radius:16px; background:#faf8f2; display:flex; gap:14px; margin-bottom:24px; font-size:13px; }
.capacity-note strong { font-weight:600; }
.capacity-note p { margin:5px 0 0; color:#736d60; line-height:1.6; }
.status-dot { display:inline-block; width:7px; height:7px; margin-top:7px; border-radius:50%; background:#338463; flex:none; }
.status-dot.amber { background:#a17a2a; }
.status-label { color:#227356; background:#eef7f2; border-radius:100px; padding:6px 10px; font-size:11px; display:inline-block; margin-bottom:12px; }
.status-label.amber { background:#f7f1e5; color:#876b30; }
.address-preview { background:var(--canvas); border-radius:14px; padding:18px; display:flex; align-items:center; gap:14px; margin:24px 0; font-size:15px; overflow-wrap:anywhere; }
.address-preview svg { width:32px; height:32px; flex:none; color:#86868b; }
.provider-detected { display:flex; align-items:center; gap:14px; margin:0 0 24px; }
.provider-detected h3 { font-size:24px; margin:2px 0 0; letter-spacing:-.03em; }
.provider-check { width:42px; height:42px; border-radius:50%; display:grid; place-items:center; background:#eef7f2; color:#227356; }
.credential-help { font-size:13px; }
.credential-help p { color:var(--muted); }
summary { cursor:pointer; color:var(--ink); }
.service-details { margin-top:40px; border-top:1px solid #dedee2; padding-top:24px; font-size:13px; }
.service-details>summary { color:var(--muted); }
.details-grid { display:grid; grid-template-columns:1fr 1fr; gap:16px; margin-top:20px; }
.customer .details-grid section { margin:0; padding:24px; border-radius:18px; min-width:0; }
.details-grid h2 { font-size:18px; }
.details-grid dl { grid-template-columns:100px 1fr; font-size:12px; overflow-wrap:anywhere; }
.support-details { margin:20px 0; padding:16px; overflow-wrap:anywhere; }
.support-details dl { margin-top:20px; }
.standalone { max-width:620px; margin-top:32px!important; }
.notice { padding:18px; border-radius:14px; background:var(--canvas); font-size:14px; margin:24px 0; }
.notice.error { background:#fff0ed; color:#9f3327; }
.customer footer { max-width:1080px; color:var(--muted); }
@media(max-width:760px) { .landing { grid-template-columns:1fr; gap:44px; padding:56px 24px; }.landing h1 { font-size:64px; }.signup-card { padding:30px; }.journey { padding:56px 24px; }.journey-grid { grid-template-columns:1fr; gap:26px; }.journey h2 { font-size:36px; margin-bottom:32px; }.nav { padding:14px 24px; }.nav .demo { display:none; }.progress { gap:16px; font-size:11px; justify-content:space-between; }.progress li { gap:6px; }.onboarding-grid,.details-grid { grid-template-columns:1fr; }.customer section.setup-card { padding:28px; }.setup-summary { padding:20px 6px; }.customer main.sheet { padding:36px 20px; }.home-footer { gap:24px; }.welcome-heading>p:last-child { font-size:16px; } }
@media(prefers-reduced-motion:reduce) { html { scroll-behavior:auto; } }

</style>`;

export type SetupState = "pending" | "running" | "waiting_for_you" | "waiting_for_operator" | "succeeded" | "failed";

export type SetupStep = { name: string; state: SetupState; detail: string };

export type RecordLine = { name: string; type: string; value: string };

export type MailboxLine = {
  localPart: string;
  kind: string;
  state: string;
  loginEnabled: boolean;
  quotaBytes: number | null;
  usageBytes: number;
};

export type BackupLine = {
  state: string;
  freshness: "fresh" | "stale" | "missing";
  completedAt: string | null;
  provenance: string;
  evidenceRef: string | null;
};

export type ActivityLine = { kind: string; state: string; at: string | null };

export type DnsPlanLine = { purpose: string; state: string; records: RecordLine[] };

export type CustomerPortalView = {
  onboardingState?: "queued" | "waiting_resources" | "installing" | "installed" | "attention" | null;
  missingResource?: string | null;
  onboardingError?: string | null;
  organizationId: string;
  deploymentId: string | null;
  lifecycleState: string | null;
  onboardingStage: string | null;
  healthState: string | null;
  serverId: string | null;
  serverState: string | null;
  publicIpv4: string | null;
  webmailHostname: string | null;
  mailHostname: string | null;
  backupState: string | null;
  backupFreshness: "fresh" | "stale" | "missing";
  requiredActions: string[];
  mailVerified: boolean;
  cloudVerified: false;
  allocationState?: string | null;
  planCode?: string | null;
  planMailboxLimit?: number | null;
  planDailySend?: number | null;
  planSource?: "assigned" | "deployment_snapshot" | null;
  domainName?: string | null;
  domainState?: string | null;
  nameservers?: string[];
  dnsProvider?: string | null;
  dnsZone?: string | null;
  dnsState?: string | null;
  recheckRequired?: boolean;
  dnsPlans?: DnsPlanLine[];
  publishedRecords?: RecordLine[];
  previousMx?: RecordLine[];
  brevoAuthenticated?: boolean;
  brevoVerified?: boolean;
  brevoPurposes?: string[];
  dnsWritesAccepted?: boolean;
  installerStatus?: string | null;
  relayAssigned?: boolean;
  mailboxes?: MailboxLine[];
  backups?: BackupLine[];
  events?: ActivityLine[];
  jobs?: ActivityLine[];
  cancellationState?: string | null;
  cancellationExecuteAt?: string | null;
  serviceStopped?: boolean;
  recoveryEmail?: string | null;
  detectedProvider?: "namecom" | "hostinger" | "godaddy" | null;
  detectedNameservers?: string[];
  existingMail?: boolean;
  lastCheckedAt?: string | null;
  updatedAt?: string | null;
  acceptedMailIsDelivery?: false;
  manualDns?: false;
};

export type OperatorServerRow = {
  id: string;
  state: string;
  publicIpv4: string | null;
  label: string;
  ownerId: string | null;
  operatorContact?: string | null;
  providerReference?: string | null;
  profileCode?: string | null;
  lastHeartbeatAt?: string | null;
  validatedAt?: string | null;
  identityState?: string | null;
  fingerprint?: string | null;
  readiness?: string | null;
  tainted?: boolean;
  hostingEstimate?: string | null;
};

export type OperatorPortalView = {
  counts: Array<{ state: string; count: number }>;
  servers: OperatorServerRow[];
  requiredActions: string[];
  cloudVerified: false;
  waitlist?: Array<{ organizationId: string; profileCode: string; registeredAt: string | null }>;
  relays?: Array<{ id: string; label: string; account: string; smtpLogin: string; dailyLimit: number; state: string; assigned: boolean }>;
  deployments?: Array<{
    id: string;
    organizationId: string;
    lifecycleState: string;
    onboardingStage: string;
    healthState: string;
    serverId: string | null;
    publicIpv4: string | null;
    installerStatus: string | null;
    relayAssigned: boolean;
    brevoAuthenticated: boolean;
    brevoVerified: boolean;
    dnsWritesAccepted: boolean;
    mailVerified: boolean;
  }>;
  upgrades?: Array<{ deploymentId: string; state: string }>;
};

const INVENTORY_STATES = ["pending_validation", "available", "reserved", "assigned", "quarantined", "retired"];

export function recordLines(value: unknown, limit = 12): RecordLine[] {
  if (!Array.isArray(value)) return [];
  const lines: RecordLine[] = [];
  for (const item of value) {
    if (!item || typeof item !== "object") continue;
    const row = item as Record<string, unknown>;
    const name = typeof row.name === "string" ? row.name : typeof row.host === "string" ? row.host : "";
    const type = typeof row.type === "string" ? row.type : "";
    const raw = typeof row.value === "string" ? row.value : "";
    if (!name && !type && !raw) continue;
    lines.push({ name: name.slice(0, 120), type: type.slice(0, 16), value: raw.slice(0, 180) });
    if (lines.length >= limit) break;
  }
  return lines;
}

export function brevoPurposes(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  const purposes: string[] = [];
  for (const item of value) {
    if (!item || typeof item !== "object") continue;
    const purpose = (item as { purpose?: unknown }).purpose;
    if (typeof purpose === "string" && purpose.length > 0 && purpose.length <= 40) purposes.push(purpose);
  }
  return purposes;
}

export function deriveSetup(view: CustomerPortalView): SetupStep[] {
  const actions = new Set(view.requiredActions);
  const assigned = Boolean(view.serverId);
  const assignment: SetupState = assigned
    ? "succeeded"
    : view.allocationState === "waiting_for_server" || view.allocationState == null
      ? "waiting_for_operator"
      : "pending";
  let domain: SetupState = "pending";
  if (view.domainState === "verified" && view.dnsState === "validated") domain = view.recheckRequired ? "waiting_for_operator" : "succeeded";
  else if (view.dnsState === "rejected") domain = "failed";
  else if (view.domainState === "pending" || view.dnsState === "stored") domain = "waiting_for_you";
  else if (view.domainName) domain = "running";
  let resources: SetupState = "pending";
  if (actions.has("plan.profile_mismatch")) resources = "failed";
  else if (actions.has("inventory.server_required") || actions.has("relay.unavailable") || actions.has("release.unpinned")) {
    resources = "waiting_for_operator";
  } else if (assigned && view.planCode && view.relayAssigned) resources = "succeeded";
  else if (assigned || view.planCode || view.relayAssigned) resources = "running";
  const purposes = new Set(view.brevoPurposes ?? []);
  const brevoReady = purposes.has("brevo_code") && purposes.has("dkim") && purposes.has("dmarc");
  let brevo: SetupState = "pending";
  if (brevoReady) brevo = "succeeded";
  else if (view.onboardingStage === "brevo_domain_setup") brevo = "running";
  let install: SetupState = "pending";
  if (view.installerStatus === "failed" || view.installerStatus === "dns_partial") install = "failed";
  else if (view.installerStatus === "tls_pending") install = "waiting_for_operator";
  else if (view.installerStatus === "succeeded" && view.dnsWritesAccepted) install = "succeeded";
  else if (view.installerStatus || view.onboardingStage === "installing") install = "running";
  let auth: SetupState = "pending";
  if (view.brevoAuthenticated && view.brevoVerified) auth = "succeeded";
  else if (view.dnsWritesAccepted || actions.has("brevo.authenticate_pending")) auth = "waiting_for_operator";
  let mail: SetupState = "pending";
  if (view.mailVerified === true) mail = "succeeded";
  else if (view.dnsWritesAccepted || actions.has("mail.verification_required") || view.onboardingStage === "verifying_mail") {
    mail = "waiting_for_operator";
  }
  return [
    { name: "Account and server assignment", state: assignment, detail: assigned ? "A server is reserved or assigned. Refreshing does not request another." : "No server is assigned." },
    { name: "Domain and DNS credential", state: domain, detail: "There is no manual DNS mode. Unsupported providers are rejected." },
    { name: "Server, plan, and relay", state: resources, detail: "A missing plan, relay, or release stays a wait. It does not start an install." },
    { name: "Brevo domain records", state: brevo, detail: "Saved Brevo TXT purposes are evidence. They are not an authenticated domain by themselves." },
    { name: "BearMail installation", state: install, detail: "tls_pending and dns_partial are not live mail. Mail DNS is published by the remote installer." },
    { name: "Brevo authentication", state: auth, detail: "Brevo’s authenticated and verified flags are stored only when Brevo reports them. BearPortal asks Brevo to authenticate after the verification records are published. This step is not live mail." },
    { name: "Live mail verification", state: mail, detail: "Mail stays unverified until a live check exists. This screen cannot mark it verified." },
  ];
}

function shell(title: string, nav: string, body: string, bodyClass = "app"): string {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${escapeHtml(title)}</title>${PAGE_STYLE}</head>
<body class="${escapeHtml(bodyClass)}">
<header class="nav"><a class="mark" href="/">BearPortal</a><nav>${nav}</nav>${demoBadge()}</header>
<main class="sheet"><h1>${escapeHtml(title)}</h1>${body}</main>
<footer class="fine">${bodyClass.includes("customer") ? "<p>Your provider credentials stay private. Mailbox sign-in is separate from BearPortal.</p>" : HONESTY}</footer>
</body></html>`;
}

function definition(rows: Array<[string, unknown]>): string {
  const items = rows.map(([label, value]) => `<dt>${escapeHtml(label)}</dt><dd>${escapeHtml(value ?? "none")}</dd>`).join("");
  return `<dl>${items}</dl>`;
}

function recordList(records: RecordLine[] | undefined, empty: string): string {
  if (!records || records.length === 0) return `<p>${escapeHtml(empty)}</p>`;
  return `<ul>${records.map((row) => `<li>${escapeHtml(row.type)} ${escapeHtml(row.name)} ${escapeHtml(row.value)}</li>`).join("")}</ul>`;
}

export type HomeState = {
  mode?: "development" | "identity";
  error?: string;
  email?: string;
  organization?: string;
};

export function renderHome(state: HomeState = {}): string {
  const development = (state.mode ?? "development") === "development";
  const form = development ? `<form method="post" action="/register" class="signup-form">
<label for="signup-email">Your email address</label><input id="signup-email" name="email" type="email" placeholder="you@company.com" autocomplete="email" required maxlength="200" value="${escapeHtml(state.email ?? "")}" aria-describedby="signup-help">
${state.error ? `<p class="field-error" role="alert">${escapeHtml(state.error)}</p>` : ""}
<button class="pill" type="submit">Continue with email <span aria-hidden="true">↗</span></button>
<p id="signup-help" class="fine">Use an email you can access before your new domain is set up.</p>
</form>` : `<p>Continue with your verified email through your organization's sign-in provider.</p><a class="pill" href="/portal">Open your account</a>`;
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>BearPortal — Your domain. Your mail.</title>${PAGE_STYLE}</head>
<body class="home"><header class="nav"><a class="mark" href="/">BearPortal<span class="brand-dot" aria-hidden="true">.</span></a><nav><a href="#how">How it works</a><a href="/portal">Your account</a></nav>${demoBadge()}</header>
<main><section class="landing"><div class="landing-copy"><p class="eyebrow">Meet your new email</p><h1>Your domain.<br>Your mail.<br><span class="soft">Simply yours.</span></h1><p class="lede">Bring your domain. We’ll take care of setting up Bearmail, on a server dedicated to you.</p><a class="text-link" href="#how">A little setup. A lot less work. <span aria-hidden="true">↓</span></a></div>
<div class="signup-card" id="register"><div class="mail-icon" aria-hidden="true">${mailIcon()}</div><h2>Make room for<br>better email.</h2><p>Start with your email. Your domain comes next.</p>${form}${development ? `<p class="preview-note">Development preview: email verification is not enabled. Use a test account.</p>` : ""}</div></section>
<section class="journey" id="how"><p class="eyebrow">Three simple steps</p><h2>From your domain<br>to your inbox.</h2><div class="journey-grid"><article><span class="step-number">01</span><h3>Make yourself at home.</h3><p>Register with your email. Everything you need is in one place.</p></article><article><span class="step-number">02</span><h3>Connect your domain.</h3><p>Tell us your domain. We’ll find your DNS provider and guide you through connecting it.</p></article><article><span class="step-number">03</span><h3>We’ll handle the rest.</h3><p>We set up your mail service and install Bearmail. If capacity is tight, your place is saved.</p></article></div></section></main>
<footer class="home-footer"><a class="mark" href="/">BearPortal.</a><p>Made for your domain. Ready when you are.</p></footer></body></html>`;
}

function mailIcon(): string {
  return `<svg viewBox="0 0 48 48" fill="none" aria-hidden="true"><rect x="6" y="12" width="36" height="26" rx="7" stroke="currentColor" stroke-width="2"/><path d="m8 15 13 11a5 5 0 0 0 6 0l13-11" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>`;
}

export function renderCustomerPortal(view: CustomerPortalView): string {
  const domain = view.domainName ?? "";
  const hasServer = Boolean(view.serverId || view.allocationState === "allocated");
  const waiting = view.onboardingState === "waiting_resources";
  const requested = Boolean(view.onboardingState);
  const installed = view.onboardingState === "installed" || view.installerStatus === "succeeded" || view.installerStatus === "tls_pending";
  const busy = requested && !installed && view.onboardingState !== "attention";
  const step = installed ? 3 : requested || view.dnsState ? 2 : 1;
  const title = installed ? "Your mail is taking shape." : requested ? "We’re on it." : "Let’s make it yours.";
  const subtitle = installed ? `Bearmail is installed for ${domain}.` : requested ? "Your setup is saved. We’ll take it from here." : "A few simple steps. A place for all your mail.";
  const progress = `<ol class="progress" aria-label="Setup progress">${["Your account","Your domain","Your Bearmail"].map((label,i)=>`<li class="${i<step?"complete":""} ${i===step?"current":""}" ${i===step?'aria-current="step"':""}><span>${i<step?'✓':i+1}</span>${label}</li>`).join("")}</ol>`;
  const shortage = !hasServer || view.missingResource === "relay" || view.missingResource === "server_and_relay";
  const capacity = shortage && !installed ? `<aside class="capacity-note" role="status"><span class="status-dot amber"></span><div><strong>A little more room is on the way.</strong><p>Resources are tight right now. ${requested ? "Your setup is saved, and we’ll deploy it as soon as a server and mail-service account are available. You don’t need to submit it again." : "You can connect your domain now. We’ll save your place and deploy as soon as capacity is available."}</p></div></aside>` : "";
  let card: string;
  if (!domain) {
    card = `<section class="setup-card" id="domain"><p class="eyebrow">Step 2 · Your domain</p><h2>What’s your domain?</h2><p>Use the domain you’d like for your email, like <span class="example">hello@yourcompany.com</span>.</p>${customerDomainForm()}<p class="fine">We’ll detect who manages your DNS. Saving your domain won’t change your mail routing.</p></section>`;
  } else if (!requested && !view.dnsState) {
    card = `<section class="setup-card" id="domain"><p class="eyebrow">Step 2 · Connect your domain</p><h2>${escapeHtml(domain)}</h2>${providerNotice({nameservers:view.detectedNameservers,detectedProvider:view.detectedProvider})}${dnsCredentialForm({domain,detectedProvider:view.detectedProvider})}<a class="text-link" href="/portal">Check provider again ↗</a></section>`;
  } else if (!requested) {
    card = `<section class="setup-card" id="setup"><p class="eyebrow">Step 3 · Your Bearmail</p><h2>Everything in one place.</h2><p>Your domain provider is connected. We’ll verify the mail service and install Bearmail for <strong>${escapeHtml(domain)}</strong>.</p>${startSetupForm(domain)}</section>`;
  } else if (view.onboardingState === "attention") {
    card = `<section class="setup-card" id="setup"><span class="status-label amber">A little help needed</span><h2>Let’s finish connecting.</h2><p>${view.onboardingError === "OUTCOME_UNKNOWN" ? "Setup was interrupted. Our team needs to check your server before restarting. Your place is saved; there’s nothing you need to resubmit." : view.onboardingError === "DNS_PROVIDER_CHANGED" ? "Your DNS provider appears to have changed. Connect the current provider below." : "Setup needs another look. Check your provider credential, or try again. Your domain and place in line are saved."}</p>${view.onboardingError === "OUTCOME_UNKNOWN" ? "" : dnsCredentialForm({domain,detectedProvider:view.detectedProvider})}${view.dnsState && view.onboardingError !== "OUTCOME_UNKNOWN" ? startSetupForm(domain) : ""}</section>`;
  } else if (installed) {
    card = `<section class="setup-card" id="setup"><span class="status-label">${view.installerStatus === "tls_pending" ? "Finishing the connection" : "Bearmail installed"}</span><h2>A home for your email.</h2><p>${view.installerStatus === "tls_pending" ? "Bearmail is installed. Secure connections may still be finishing. We’ll keep your setup status here." : "Your Bearmail installation is in place."}</p><div class="address-preview">${mailIcon()}<span>${escapeHtml(view.webmailHostname ?? `bearmail.${domain}`)}</span></div>${view.installerStatus === "succeeded" && view.webmailHostname ? `<a class="pill" href="https://${escapeHtml(view.webmailHostname)}" target="_blank" rel="noopener noreferrer">Open Bearmail ↗</a>` : ""}<p class="fine">${view.mailVerified ? "Mail delivery has been verified." : "Mail delivery and mailbox access still need verification. Installation alone doesn’t confirm that messages can be received or sent."}</p></section>`;
  } else {
    const headline = waiting ? "Your place is saved." : view.onboardingState === "installing" ? "Making things ready." : "Connecting the pieces.";
    card = `<section class="setup-card" id="setup" role="status"><span class="status-label ${waiting?'amber':''}">${waiting?"Waiting for capacity":view.onboardingState==="installing"?"Installing Bearmail":"Setting up your domain"}</span><h2>${headline}</h2><p>${waiting ? "We’ll continue automatically when resources are available. You can close this page and come back anytime." : view.onboardingError === "DNS_PROPAGATION" ? "Your provider is connected. We’re waiting for the domain’s verification records to become visible." : "We’re authenticating your mail service and preparing your dedicated Bearmail installation. This can take a little while."}</p><div class="address-preview">${mailIcon()}<span>${escapeHtml(domain)}</span></div><p class="fine">Your progress is saved. No need to keep this page open.</p></section>`;
  }
  const summary = `<aside class="setup-summary"><p class="eyebrow">Your space</p><h3>${domain ? escapeHtml(domain) : "A domain of your own."}</h3><ul><li><span>Account</span><strong>${escapeHtml(view.recoveryEmail ?? "Registered")}</strong></li><li><span>Domain</span><strong>${domain ? "Saved" : "Up next"}</strong></li><li><span>Provider</span><strong>${providerLabel(view.detectedProvider ?? view.dnsProvider) || "We’ll find it for you"}</strong></li><li><span>Server</span><strong>${hasServer?"Reserved for you":"Waiting for capacity"}</strong></li><li><span>Mail service</span><strong>${view.relayAssigned?"Reserved for you":"Allocated during setup"}</strong></li></ul><p class="fine">Your mail runs on a server dedicated to your organization.</p></aside>`;
  const details = `<details class="service-details" id="account"><summary>Your account & service details</summary><div class="details-grid"><section><h2>Account</h2>${definition([["Email",view.recoveryEmail],["Domain",domain||"Not connected"],["Webmail",view.webmailHostname],["Mail server",view.mailHostname],["Plan",view.planCode??"Beta"]])}</section><section id="connections"><h2>Connection settings</h2>${definition([["IMAP",`${view.mailHostname??"Your mail hostname"} · 993 · TLS`],["SMTP submission",`${view.mailHostname??"Your mail hostname"} · 465 · TLS`],["JMAP",`${view.mailHostname??"Your mail hostname"} · 443`]])}<p class="fine">Use your mailbox address to sign in. Mailbox login is separate from BearPortal.</p></section><section id="mailboxes"><h2>Mailboxes</h2>${(view.mailboxes??[]).length?`<ul>${(view.mailboxes??[]).map(row=>`<li>${escapeHtml(row.localPart)}${domain?'@'+escapeHtml(domain):''} <span class="fine">${row.loginEnabled?"Login enabled":"Access pending"}</span></li>`).join("")}</ul>`:"<p>Your requested addresses will appear here.</p>"}<p class="fine">Requested addresses need to be applied to the mail server before use.</p></section><section id="backups"><h2>Backups and activity</h2><p>Backups are operator-reported. ${view.backupState?escapeHtml(view.backupState):"No backup is reported yet."}</p><ul>${[...(view.jobs??[]),...(view.events??[])].slice(0,5).map(row=>`<li>${escapeHtml(row.kind.replaceAll('_',' '))} <span class="fine">${escapeHtml(row.state)}</span></li>`).join("")}</ul></section></div><details class="support-details"><summary>Support information</summary>${definition([["Organization",view.organizationId],["Server address",view.publicIpv4],["Deployment",view.deploymentId],["Lifecycle",view.lifecycleState],["Health",view.healthState],["Installer status",view.installerStatus],["Live mail verified",view.mailVerified],["Cloud verified",false],["Required actions",view.requiredActions.join(", ")||"none"]])}${recordList(view.publishedRecords,"No published records are stored.")}</details></details>`;
  const refresh = busy ? `<script>setTimeout(function(){if(!document.querySelector('form:focus-within'))location.reload()},15000)</script>` : "";
  return shell("Your Bearmail",`<a href="#account">Your account</a>`,`<div class="welcome-heading"><p class="eyebrow">Welcome to your space</p><h1>${title}</h1><p>${escapeHtml(subtitle)}</p></div>${progress}${capacity}<div class="onboarding-grid">${card}${summary}</div>${details}${refresh}`,"app customer");
}

function startSetupForm(domain: string): string {
  return `<form method="post" action="/portal/onboarding"><input type="hidden" name="csrf" value="1"><label class="check consent"><input type="checkbox" name="deployConsent" value="1" required><span>I authorize BearPortal to route new mail for ${escapeHtml(domain)} to Bearmail and allow a setup test email. Existing messages won’t be migrated.</span></label><button class="pill" type="submit">Set up my Bearmail <span aria-hidden="true">↗</span></button></form>`;
}

function providerLabel(provider: string | null | undefined): string {
  return provider === "godaddy" ? "GoDaddy" : provider === "namecom" ? "Name.com" : provider === "hostinger" ? "Hostinger" : "";
}

export type BrevoAccountResultView = {
  error?: string;
  loginEmail?: string;
  stored?: boolean;
  state?: string;
};

export function renderBrevoAccountResult(view: BrevoAccountResultView): string {
  const banner = view.error ? `<p class="banner">${escapeHtml(view.error)}</p>` : "";
  const stored = view.stored
    ? `<p>The Brevo account is stored. Its state is ${escapeHtml(view.state ?? "inactive")}. It is not tied to a customer domain.</p>`
    : "";
  return shell(
    "Brevo account",
    `<a href="/operator">Operator inventory</a>`,
    `${banner}<section><h2>Brevo account</h2>
${stored}
<p>This page did not call Brevo. The registered customer enters the company domain in the portal. That is when BearPortal asks Brevo.</p>
<p>Saving an account does not publish DNS and does not verify a domain. The keys are not shown. The SMTP key is stored and is not sent.</p>
<p><a href="/operator">Back to inventory</a></p>
${brevoAccountForm(view.loginEmail ?? "")}
</section>`,
  );
}

export type BrevoDomainResultView = {
  error?: string;
  domain?: string;
  authenticated?: boolean;
  verified?: boolean;
  records?: Array<{ purpose: string; type: string; host: string; value: string }>;
  saved?: boolean;
  unavailable?: boolean;
  linked?: boolean;
  recordsSaved?: boolean;
  nameservers?: string[];
  detectedProvider?: "namecom" | "hostinger" | "godaddy" | null;
};

export type DnsCredentialResultView = {
  error?: string;
  domain?: string;
  provider?: string;
  stored?: boolean;
  written?: number;
  authenticated?: boolean;
  verified?: boolean;
};

export function renderBrevoDomainResult(view: BrevoDomainResultView): string {
  return shell("Connect your domain",`<a href="/portal">Your account</a>`,`<div class="welcome-heading"><p class="eyebrow">Step 2 · Your domain</p><h1>${view.saved?escapeHtml(view.domain):"Let’s find your domain."}</h1><p>${view.saved?"Your domain is saved. Let’s connect your provider.":"A place for your company’s email."}</p></div>${view.error?`<p class="notice error" role="alert">${escapeHtml(view.error)}</p>`:""}${view.unavailable?`<aside class="capacity-note" role="status"><span class="status-dot amber"></span><div><strong>Resources are tight right now.</strong><p>You can connect your domain below. We’ll save your setup and deploy as soon as server and mail-service capacity is available.</p></div></aside>`:""}<section class="setup-card standalone">${providerNotice(view)}${dnsCredentialForm(view)}${!view.saved || !view.detectedProvider ? customerDomainForm(view.domain??"") : ""}<a class="text-link" href="/portal">Back to your setup</a></section>`,"app customer");
}

export function renderDnsCredentialResult(view: DnsCredentialResultView): string {
  return shell("Connect your provider",`<a href="/portal">Your account</a>`,`<div class="welcome-heading"><p class="eyebrow">Your domain connection</p><h1>${view.error?"Let’s try that again.":"Your connection is saved."}</h1><p>${escapeHtml(view.domain??"")}</p></div><section class="setup-card standalone">${view.error?`<p class="notice error" role="alert">${escapeHtml(view.error)}</p>`:"<p>Your provider credential is stored securely. It won’t be shown again.</p>"}${view.stored?"<p>Your saved credential is available for setup.</p>":""}<a class="pill" href="/portal">Continue setup ↗</a></section>`,"app customer");
}

function providerNotice(view: { nameservers?: string[]; detectedProvider?: "namecom" | "hostinger" | "godaddy" | null }): string {
  if (!view.nameservers) return "<p>We’ll check your domain’s DNS provider before connecting.</p>";
  const provider = providerLabel(view.detectedProvider);
  if (!provider) return `<div class="notice"><h3>We couldn’t match your DNS provider.</h3><p>BearPortal currently supports Name.com, Hostinger and GoDaddy. If you recently changed nameservers, check again after they update.</p><details><summary>View nameservers</summary><p>${escapeHtml(view.nameservers.join(", ")||"No nameservers found")}</p></details></div>`;
  return `<div class="provider-detected"><span class="provider-check" aria-hidden="true">✓</span><div><span class="fine">DNS provider detected</span><h3>${provider}</h3></div></div><p>Connect ${provider} so we can add your mail records and verify your domain. You don’t need to configure Brevo yourself.</p>`;
}

function dnsCredentialForm(view: { domain?: string; detectedProvider?: "namecom" | "hostinger" | "godaddy" | null }): string {
  if (!view.domain || !view.detectedProvider) return "";
  const fields = view.detectedProvider === "namecom"
    ? `<label>Name.com username<input type="text" name="dnsUsername" autocomplete="off" required></label><label>API token<input type="password" name="dnsToken" autocomplete="off" required></label>`
    : `<label>${view.detectedProvider === "godaddy"?"Personal access token (PAT)":"API token"}<input type="password" name="dnsToken" autocomplete="off" required></label>`;
  const guide = view.detectedProvider === "godaddy" ? `<a href="https://developer.godaddy.com/en/personal-access-token" target="_blank" rel="noopener noreferrer">Create a GoDaddy personal access token ↗</a><p>Allow Domains and DNS access, including DNS updates.</p>` : view.detectedProvider === "hostinger" ? "<p>In Hostinger hPanel, open your profile, then API. Create a token with access to this domain’s DNS.</p>" : "<p>In your Name.com account, open API settings. Copy your account username and API token.</p>";
  return `<form method="post" action="/portal/dns-credential"><input type="hidden" name="csrf" value="1"><input type="hidden" name="domain" value="${escapeHtml(view.domain)}"><input type="hidden" name="onboarding" value="1">${fields}<details class="credential-help"><summary>Where do I find this?</summary>${guide}</details><label class="check consent"><input type="checkbox" name="deployConsent" value="1" required><span>I authorize BearPortal to route new mail for ${escapeHtml(view.domain)} to Bearmail and allow a setup test email. Existing messages won’t be migrated.</span></label><button class="pill" type="submit">Connect & set up Bearmail <span aria-hidden="true">↗</span></button><p class="fine">Your credential is encrypted. We’ll handle domain verification, the mail service and installation.</p></form>`;
}

function customerDomainForm(domain = "", existingMail = false): string {
  return `<form method="post" action="/portal/domain"><input type="hidden" name="csrf" value="1"><input type="hidden" name="onboarding" value="1"><label for="company-domain">Your domain<input id="company-domain" type="text" name="domain" value="${escapeHtml(domain)}" placeholder="yourcompany.com" autocomplete="off" autocapitalize="none" spellcheck="false" required></label><label class="check"><input type="checkbox" name="existingMail" value="1"${existingMail?" checked":""}> I already receive mail on this domain</label><button class="pill" type="submit">Find my provider <span aria-hidden="true">↗</span></button></form>`;
}

function brevoAccountForm(loginEmail = ""): string {
  return `<form method="post" action="/operator/brevo-account">
<input type="hidden" name="csrf" value="1">
<label>Brevo login email<input type="email" name="loginEmail" value="${escapeHtml(loginEmail)}" autocomplete="off" required></label>
<label>API key<input type="password" name="apiKey" autocomplete="off" required></label>
<label>SMTP login<input type="text" name="smtpLogin" autocomplete="off" required></label>
<label>SMTP key<input type="password" name="smtpKey" autocomplete="off" required></label>
<label>Daily send limit<input type="text" name="dailyLimit" inputmode="numeric" autocomplete="off"></label>
<input class="pill" type="submit" value="Save Brevo account">
</form>`;
}

function countLine(counts: Array<{ state: string; count: number }>): string {
  const byState = new Map(counts.map((row) => [row.state, row.count]));
  return INVENTORY_STATES.map((state) => `${state}:${byState.get(state) ?? 0}`).join(", ");
}

export function renderOperatorPortal(view: OperatorPortalView): string {
  const counts = view.counts.map((row) => `${row.state}:${row.count}`).join(", ") || "none";
  const servers = view.servers.map((server) =>
    `<li>${escapeHtml(server.id)} ${escapeHtml(server.state)} ${escapeHtml(server.publicIpv4)} owner ${escapeHtml(server.ownerId)} label ${escapeHtml(server.label)}
 contact ${escapeHtml(server.operatorContact)} profile ${escapeHtml(server.profileCode)}
 reference ${escapeHtml(server.providerReference)} heartbeat ${escapeHtml(server.lastHeartbeatAt)}
 identity ${escapeHtml(server.identityState)} fingerprint ${escapeHtml(server.fingerprint)}
 readiness ${escapeHtml(server.readiness)} tainted ${escapeHtml(server.tainted === true)}
 estimate ${escapeHtml(server.hostingEstimate)}</li>`,
  ).join("");
  const actions = view.requiredActions.length > 0 ? view.requiredActions.join(", ") : "none";
  const waitlist = (view.waitlist ?? []).map((row) =>
    `<li>${escapeHtml(row.organizationId)} ${escapeHtml(row.profileCode)} since ${escapeHtml(row.registeredAt)} reason waiting_for_server</li>`,
  ).join("");
  const relays = (view.relays ?? []).map((row) =>
    `<li>${escapeHtml(row.id)} ${escapeHtml(row.label)} ${escapeHtml(row.account)} smtp ${escapeHtml(row.smtpLogin)} limit ${escapeHtml(row.dailyLimit)} ${escapeHtml(row.state)} assigned ${escapeHtml(row.assigned)}</li>`,
  ).join("");
  const deployments = (view.deployments ?? []).map((row) =>
    `<li>${escapeHtml(row.id)} org ${escapeHtml(row.organizationId)} ${escapeHtml(row.lifecycleState)} ${escapeHtml(row.onboardingStage)} health ${escapeHtml(row.healthState)}
 server ${escapeHtml(row.serverId)} ${escapeHtml(row.publicIpv4)} installer ${escapeHtml(row.installerStatus)}
 relay ${escapeHtml(row.relayAssigned)} brevo ${escapeHtml(row.brevoAuthenticated)}/${escapeHtml(row.brevoVerified)}
 dns accepted ${escapeHtml(row.dnsWritesAccepted)} mail verified ${escapeHtml(row.mailVerified)}</li>`,
  ).join("");
  const upgrades = (view.upgrades ?? []).map((row) =>
    `<li>${escapeHtml(row.deploymentId)} ${escapeHtml(row.state)} binaries executed false data rollback false</li>`,
  ).join("");
  return shell(
    "Inventory",
    `<a href="#inventory">Server inventory</a><a href="#add">Add server</a><a href="#readiness">Readiness</a><a href="#waitlist">Waitlist</a><a href="#brevo">Brevo accounts</a><a href="#deployments">Deployment detail</a><a href="#actions">Required actions</a>`,
    `<section id="inventory"><h2>Server inventory</h2>
<p>Inventory counts ${escapeHtml(counts)}</p>
<p>States ${escapeHtml(countLine(view.counts))}</p>
<ul>${servers}</ul>
<p>Cloud verified ${escapeHtml(view.cloudVerified)}. A provider reference is a human lookup label. BearPortal does not call a cloud API with it.</p>
</section>
<section id="add"><h2>Add server</h2>
<p>Register with the server API: public address, label, profile, operator contact, and preparation attestations. Saving an address does not prove access. The operator installs BearPortal's SSH public key for the bearportal-control-plane account on that host, allows that account passwordless sudo, and allows port 22 only from the control plane. After the row is saved, BearPortal SSHs to that address and runs the readiness probe. A passing probe marks the server available. A failed probe leaves it pending_validation. That probe does not run bearmail-install.</p>
<p>Do not create or mount /var/lib/stalwart before registration. An applying bearmail-install creates that directory when BearMail is installed. A dry run does not. BearPortal does not create infrastructure, open a firewall, partition a disk, or resize a disk. There is no host agent to install.</p>
</section>
<section id="readiness"><h2>Readiness</h2>
<p>Readiness is an SSH probe from the control plane: Linux, systemd, architecture, memory, disk, and no unrelated mail data. A missing /var/lib/stalwart passes. A firewall attestation is not a connectivity test. A passing probe marks the server available. A failed probe on a new server leaves it pending_validation and records the failure codes. This page does not revalidate by itself.</p>
<ul>${servers}</ul>
</section>
<section id="waitlist"><h2>Waitlist</h2>
${waitlist ? `<ul>${waitlist}</ul>` : "<p>No verified customer is waiting.</p>"}
<p>New eligible servers are assigned by the allocator. This page does not pick an owner. Duplicate shortage notices stay deduplicated.</p>
</section>
<section id="brevo"><h2>Brevo accounts</h2>
${relays ? `<ul>${relays}</ul>` : "<p>No Brevo account is visible.</p>"}
<p>Add a Brevo account with its login email, API key, and SMTP key. You do not enter the customer's domain. The registered customer enters that domain in the portal. Saving an account does not call Brevo, does not publish DNS, and does not verify a domain. The SMTP key is stored and is not sent. The keys are write-only and are not shown. A new account stays inactive until a customer domain claims it. Claiming it does not prove the SMTP login and does not move the customer's server.</p>
${brevoAccountForm()}
</section>
<section id="deployments"><h2>Deployment detail</h2>
${deployments ? `<ul>${deployments}</ul>` : "<p>No deployment is visible.</p>"}
<h3>Upgrade plans</h3>
${upgrades ? `<ul>${upgrades}</ul>` : "<p>No upgrade plan is recorded. Recording a plan does not execute binaries. binaries executed false. Data rollback false.</p>"}
<p>Hosting estimates on the server rows are operator-entered, source operator, billing system not_google_billing. They are not a live billing total.</p>
</section>
<section id="actions"><h2>Required actions</h2>
<p>Required actions ${escapeHtml(actions)}</p>
<p>These rows are human work: preparation, repair, IP update, relay verification, DNS, backup report, restore, cleanup, and approval. This page does not mark them done.</p>
<p>Allowed application actions stay on their APIs: revalidate, quarantine, IP update, install retry, credential rotation, DNS recheck, upgrade plan, restore, and cancellation. None of those calls a cloud account, creates a machine, or reports success from this page.</p>
<p>Cleanup evidence does not return a server to available.</p>
</section>`,
  );
}
