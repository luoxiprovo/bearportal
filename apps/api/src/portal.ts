import type { BillingView } from "./billing.ts";
import { INVENTORY_FORM_SCRIPT } from "./inventory-form-script.ts";
import { setupErrorMessage } from "./setup-errors.ts";
import { randomUUID } from "node:crypto";
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
.customer .nav { padding-inline:24px; }
.customer .nav nav { order:2; margin-left:auto; align-items:center; flex-wrap:wrap; justify-content:flex-end; }
.customer .nav .demo { order:1; margin-left:0; }
.nav-auth-message { color:#a33125; font-size:12px; max-width:260px; }
.brand-dot { color:var(--blue); }
.landing { max-width:1080px; margin:auto; padding:96px 24px 112px; display:grid; grid-template-columns:1.2fr 1fr; align-items:center; gap:80px; }
.landing>* { min-width:0; }
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
.journey-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); gap:32px; }
.step-number { color:#86868b; font-size:13px; font-weight:600; }
.journey-grid h3 { letter-spacing:-.025em; font-size:21px; margin:16px 0 10px; }
.journey-grid p { font-size:15px; color:var(--muted); line-height:1.65; }
.home-footer { display:flex; align-items:center; justify-content:space-between; max-width:1080px; margin:auto; padding:28px 24px; font-size:12px; color:var(--muted); }
.customer main.sheet { padding:56px 24px 64px; max-width:1080px; }
.customer main.sheet>h1 { display:none; }
.setup-checklist { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); list-style:none; padding:0; gap:12px; margin:28px 0; }
.setup-checklist li { padding:14px; border:1px solid #e5e5ea; border-radius:14px; font-size:13px; color:var(--muted); overflow-wrap:anywhere; }
.setup-checklist strong,.setup-checklist small { display:block; }
.setup-checklist small { margin-top:6px; font-size:11px; }
.setup-checklist .current { background:#f0f6ff; border-color:#8dbcf0; color:#0055a8; }
.setup-checklist .complete { color:#227356; }
.next-step { margin:24px 0; padding:18px 22px; background:#f5f7fa; border-left:3px solid var(--blue); border-radius:8px; }
.next-step p { margin:6px 0 0; color:var(--muted); font-size:14px; }
.customer .subscription-details { margin-top:28px; border:1px solid #e5e5ea; border-radius:18px; padding:20px; }
.subscription-details>summary { font-size:14px; font-weight:600; }
.customer .subscription-details .setup-card { padding:20px 0 0; background:transparent; border:0; }
:where(a,button,input,summary):focus-visible { outline:3px solid #0570de; outline-offset:4px; }
[id] { scroll-margin-top:90px; }
.service-details:target { outline:2px solid #8dbcf0; outline-offset:8px; }
@media(max-width:760px) { .setup-checklist { grid-template-columns:repeat(2,minmax(0,1fr)); gap:8px; }.setup-checklist li { padding:12px; }.next-step { padding:16px; } }
.welcome-heading h1 { font-size:clamp(36px,5vw,52px); letter-spacing:-.045em; margin:8px 0 14px; }
.welcome-heading>p:last-child { color:var(--muted); font-size:18px; margin:0; }
.setup-progress { margin:32px 0; padding:28px; border:1px solid #e5e5ea; border-radius:24px; background:#fff; }
.milestone-heading { display:flex; justify-content:space-between; align-items:center; gap:16px; }.milestone-heading h2 { font-size:21px; margin:0; }.milestone-heading>span { font-size:12px; color:var(--blue); }.setup-progress>p { color:var(--muted); line-height:1.6; max-width:760px; }
.waiting-status { display:inline-block; animation:waiting-pulse 1.6s ease-in-out infinite; }@keyframes waiting-pulse { 50% { opacity:.35; } }.setup-progress .setup-timing { font-size:11px; margin:8px 0 0; }@media(prefers-reduced-motion:reduce) { .waiting-status { animation:none; } }
.backend-progress { height:6px; border-radius:6px; background:#e5e5ea; overflow:hidden; margin:22px 0; }.backend-progress>span { display:block; height:100%; background:var(--blue); transition:width .4s ease; }.working-spinner { border:2px solid #d7e6ff!important; border-top-color:var(--blue)!important; animation:setup-spin 1s linear infinite; }@keyframes setup-spin { to { transform:rotate(360deg); } }@media(prefers-reduced-motion:reduce) { .working-spinner { animation:none; } }
.milestones { display:grid; grid-template-columns:repeat(auto-fit,minmax(140px,1fr)); gap:20px; list-style:none; padding:0; margin:26px 0; }.milestones li { display:flex; gap:10px; color:var(--muted); }.milestone-number { flex-shrink:0; width:28px; height:28px; border:1px solid #d2d2d7; border-radius:50%; display:grid; place-items:center; font-size:12px; }.milestones strong { display:block; font-size:13px; font-weight:500; }.milestones small { display:block; font-size:11px; margin-top:5px; }.milestones .complete .milestone-number { background:var(--ink); color:white; border-color:var(--ink); }.milestones .current { color:var(--blue); }.milestones .current .milestone-number { border-color:var(--blue); background:#f0f6ff; }
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
@media(max-width:760px) { .landing { grid-template-columns:1fr; gap:44px; padding:56px 24px; }.landing h1 { font-size:clamp(44px,14vw,64px); }.signup-card { padding:30px; }.journey { padding:56px 24px; }.journey-grid { grid-template-columns:1fr; gap:26px; }.journey h2 { font-size:36px; margin-bottom:32px; }.nav { padding:14px 24px; }.nav .demo { display:none; }.progress { gap:16px; font-size:11px; justify-content:space-between; }.progress li { gap:6px; }.onboarding-grid,.details-grid { grid-template-columns:1fr; }.customer section.setup-card { padding:28px; }.setup-summary { padding:20px 6px; }.customer main.sheet { padding:36px 20px; }.home-footer { gap:24px; }.welcome-heading>p:last-child { font-size:16px; } }
@media(prefers-reduced-motion:reduce) { html { scroll-behavior:auto; } }


.operator main.sheet { max-width:1180px; padding:48px 24px 64px; }
.operator main.sheet>h1 { display:none; }
.operator-heading { display:flex; align-items:flex-start; justify-content:space-between; gap:24px; margin-bottom:32px; }
.operator-heading h1 { font-size:clamp(34px,4vw,48px); letter-spacing:-.045em; margin:8px 0 14px; }
.operator-heading p:last-child { color:#6e6e73; font-size:16px; margin:0; }
.operator-access,.read-only { font-size:11px; color:#6e6e73; border:1px solid #dcdce0; border-radius:100px; padding:7px 11px; white-space:nowrap; }
.operator-access { margin-top:6px; }
.inventory-stats { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:16px; margin:28px 0 34px; }
.inventory-stats article { background:#fff; border-radius:18px; padding:24px; display:grid; gap:10px; }
.inventory-stats article>span { color:#6e6e73; font-size:12px; }
.inventory-stats strong { font-size:34px; letter-spacing:-.035em; line-height:1; font-weight:500; }
.inventory-stats small { color:#86868b; font-size:11px; }
.inventory-tabs { display:flex; gap:8px; padding-bottom:20px; }
.inventory-tabs a { color:#6e6e73; font-size:14px; padding:9px 14px; border-radius:100px; }
.inventory-tabs a[aria-current] { background:#e4edf8; color:#0066cc; font-weight:500; }
.inventory-tabs a span { font-size:11px; padding-left:8px; opacity:.8; }
.operator section.inventory-panel { padding:0; border-radius:22px; margin:0; overflow:hidden; min-width:0; }
.panel-header { padding:28px 28px 0; display:flex; justify-content:space-between; align-items:center; gap:20px; }
.panel-header h2 { font-size:23px; margin:0 0 7px; letter-spacing:-.035em; }
.panel-header p { color:#6e6e73; font-size:13px; margin:0; }
.panel-header .pill { min-height:40px; font-size:13px; padding:10px 16px; white-space:nowrap; }
.inventory-tools { padding:24px 28px 18px; display:flex; justify-content:space-between; gap:16px; }
.search-control { position:relative; flex:1; max-width:400px; }
.search-control svg { position:absolute; top:11px; left:12px; width:18px; height:18px; color:#86868b; }
.search-control input { width:100%; padding:11px 12px 11px 38px; border:1px solid #e1e1e5; border-radius:10px; font:inherit; font-size:12px; background:#fafafa; color:#1d1d1f; }
.filter-control select,.inventory-form select { border:1px solid #dcdce0; border-radius:10px; background:#fff; padding:10px 30px 10px 12px; color:#424245; font:inherit; font-size:12px; min-height:40px; }
.resource-scroll { overflow-x:auto; position:relative; }
.resource-table { width:100%; border-collapse:collapse; font-size:12px; min-width:760px; }
.resource-table th { text-align:left; font-size:10px; text-transform:uppercase; letter-spacing:.05em; color:#86868b; font-weight:500; padding:12px 20px; background:#fafafa; border-bottom:1px solid #f0f0f2; }
.resource-table th:first-child,.resource-table td:first-child { padding-left:28px; }
.resource-table td { padding:20px; border-bottom:1px solid #f0f0f2; color:#515154; vertical-align:middle; }
.resource-table tbody tr:last-child td { border-bottom:0; }
.resource-table tbody tr:hover { background:#fcfcfd; }
.resource-table tr[hidden] { display:none; }
.resource-name { display:flex; gap:12px; align-items:center; }
.resource-name strong { color:#1d1d1f; font-weight:500; display:block; font-size:13px; }
.resource-name>div>span { display:block; color:#86868b; font-size:11px; margin-top:4px; }
.resource-icon { background:#f2f3f6; color:#737782; width:36px; height:36px; padding:6px; border-radius:11px; display:inline-block; flex:none; }
.resource-icon.mail { background:#eef4fc; color:#4782c3; }
.resource-icon svg { width:100%; height:100%; }
.resource-status { display:inline-flex; align-items:center; gap:6px; padding:5px 8px; border-radius:100px; font-size:10px; white-space:nowrap; }
.resource-status i { height:5px; width:5px; border-radius:50%; background:currentColor; }
.resource-status.green { background:#eff7f1; color:#33805b; }.resource-status.blue { background:#edf3fc; color:#3974b7; }.resource-status.amber { background:#faf4e9; color:#9a742b; }.resource-status.gray { background:#f0f0f3; color:#787881; }
.table-note { display:block; margin-top:5px; color:#86868b; font-size:10px; }
.row-actions { text-align:right; white-space:nowrap; }
.table-button { font:inherit; font-size:11px; border:0; background:transparent; color:#0066cc; padding:8px 0 8px 10px; cursor:pointer; }
.inventory-count { font-size:11px; color:#86868b; padding:15px 28px; margin:0; border-top:1px solid #f2f2f4; }
.inventory-empty { padding:44px 24px 36px; text-align:center; }.inventory-empty[hidden] { display:none; }.empty-symbol { display:block; width:40px; height:40px; color:#b2b2b9; margin:0 auto 16px; }.empty-symbol svg { width:100%; height:100%; }.inventory-empty h3 { font-size:18px; font-weight:500; margin:0 0 10px; }.inventory-empty p { color:#86868b; font-size:13px; margin:0; }
.inventory-notice { background:#eaf5ee; color:#2d6f4c; font-size:13px; border-radius:14px; padding:16px 20px; margin:0 0 24px; }
.inventory-activity { border-top:1px solid #dfdfe3; padding-top:22px; margin-top:34px; font-size:13px; }.inventory-activity>summary { color:#6e6e73; }.inventory-activity-grid { display:grid; grid-template-columns:1fr 1fr; gap:16px; margin-top:20px; }.operator .inventory-activity section { margin:0; border-radius:18px; padding:24px; min-width:0; }.inventory-activity h2 { font-size:18px; }.inventory-activity ul { list-style:none; padding:0; }.inventory-activity li { padding:12px 0; border-bottom:1px solid #f0f0f2; overflow-wrap:anywhere; }.inventory-activity li strong { font-weight:500; }.inventory-activity li span { display:block; color:#86868b; font-size:12px; margin-top:5px; }
.inventory-dialog { border:1px solid #e8e8eb; border-radius:24px; padding:0; width:min(620px,calc(100% - 32px)); max-height:90dvh; box-shadow:0 24px 100px #0002; color:#1d1d1f; }.inventory-dialog::backdrop { background:#0005; backdrop-filter:blur(4px); }.dialog-content { padding:34px; position:relative; }.dialog-content>h2 { font-size:30px; letter-spacing:-.04em; margin:10px 40px 12px 0; line-height:1.15; }.dialog-intro { color:#6e6e73; font-size:13px; margin-bottom:26px; line-height:1.6; }.dialog-close { border:0; background:#f0f0f3; width:28px; height:28px; border-radius:50%; position:absolute; top:24px; right:24px; font-size:20px; color:#73737a; cursor:pointer; }
.operator form.inventory-form { max-width:none; margin-top:18px; display:grid; gap:16px; }.inventory-form label { font-size:12px; gap:7px; }.inventory-form input[type=text],.inventory-form input[type=email],.inventory-form input[type=password],.inventory-form input[type=number] { font:inherit; font-size:14px; min-height:46px; padding:11px 12px; border:1px solid #d4d4da; border-radius:10px; background:#fff; width:100%; color:#1d1d1f; }.inventory-form input:read-only,.inventory-form input:disabled { color:#86868b; background:#f7f7f9; }.form-columns { display:grid; grid-template-columns:1fr 1fr; gap:16px; }.field-help { font-size:11px; color:#86868b; line-height:1.6; margin:0; }.dialog-buttons { display:flex; justify-content:flex-end; align-items:center; gap:10px; padding-top:12px; }.dialog-buttons .pill { font-size:13px; min-height:40px; padding:10px 18px; }.secondary-button { border:1px solid #dcdce1; color:#414147; background:#fff; border-radius:100px; font:inherit; font-size:12px; padding:10px 16px; cursor:pointer; }.inventory-form button:disabled { opacity:.6; cursor:wait; }
.preparation { border:1px solid #e5e5e9; padding:18px; border-radius:14px; display:grid; gap:13px; }.preparation legend { color:#6e6e73; padding:0 6px; font-size:11px; }.inventory-form label.check { display:flex; gap:7px; font-size:12px; }.inventory-help { background:#f7f7f9; border-radius:12px; padding:15px; font-size:12px; margin-top:8px; }.inventory-help p { line-height:1.6; color:#73737a; }.inventory-help dl { font-size:11px; margin-top:16px; grid-template-columns:120px minmax(0,1fr); overflow-wrap:anywhere; }.inventory-help code { font-size:11px; }.inline-action { padding:22px 0; border-top:1px solid #e8e8ec; margin-top:24px!important; }.inline-action strong { font-size:12px; font-weight:500; }.inline-action p { font-size:11px; color:#86868b; }.inline-action .secondary-button { justify-self:start; }.inventory-remove { border-top:1px solid #e9e9ed; padding-top:22px; margin-top:24px; font-size:12px; }.inventory-remove>summary { color:#a44137; }.inventory-remove>p { color:#86868b; font-size:12px; }.danger-button { justify-self:start; border:1px solid #eacac5; color:#a4372b; background:#fff4f2; border-radius:100px; padding:10px 16px; font:inherit; font-size:12px; cursor:pointer; }.resource-protected { background:#f7f7f9; margin-top:24px; padding:16px; border-radius:12px; font-size:12px; }.resource-protected p { color:#86868b; font-size:11px; line-height:1.6; }.form-error { background:#fff0ed; padding:12px; color:#9e3328; font-size:12px; line-height:1.6; border-radius:10px; margin:0; }.form-error[hidden] { display:none; }.sr-only { position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0; }
@media(max-width:760px) { .operator main.sheet { padding:30px 16px 50px; }.operator-heading { display:block; }.operator-access { display:inline-block; margin-top:18px; }.inventory-stats { grid-template-columns:1fr 1fr; gap:10px; }.inventory-stats article { padding:18px; }.inventory-stats strong { font-size:29px; }.panel-header { padding:22px 18px 0; flex-wrap:wrap; gap:16px; }.panel-header h2 { font-size:21px; }.inventory-tools { padding:20px 18px 16px; flex-direction:column; gap:10px; }.search-control { max-width:none; }.filter-control select { width:100%; }.inventory-count { padding-left:18px; }.inventory-activity-grid,.form-columns { grid-template-columns:1fr; }.dialog-content { padding:26px 22px; }.dialog-content>h2 { font-size:27px; }.inventory-dialog { max-height:94dvh; }.dialog-buttons { justify-content:stretch; }.dialog-buttons button { flex:1; justify-content:center; }.inventory-help dl { grid-template-columns:1fr; gap:5px; }.inventory-help dd { margin-bottom:8px; } }

.mail-access { margin-top:32px; }.mail-access-grid {display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:32px}.mail-access-grid>section {padding:0;background:transparent;border:0;min-width:0}.mail-access-grid h3 {font-size:20px;letter-spacing:-.025em}.mail-access-grid p {font-size:14px;color:#6e6e73;line-height:1.6}.mail-access-grid .pill {font-size:13px;overflow-wrap:anywhere}.admin-login {margin-top:24px}.admin-login label {display:grid;gap:6px;font-size:12px;margin-top:16px}.admin-login input {width:100%;min-width:0;padding:12px;border:1px solid #d2d2d7;border-radius:10px;font:14px ui-monospace,monospace;background:#fafafa;color:#1d1d1f}.admin-login [hidden] {display:none}@media(max-width:650px){.mail-access-grid{grid-template-columns:minmax(0,1fr);gap:24px}}
.managed-auth {margin-top:24px}.managed-auth form {padding:0;margin:18px 0;background:transparent}.managed-auth [hidden]{display:none!important}.managed-auth input {width:100%;min-width:0}.auth-google {min-height:44px;display:flex;justify-content:center;font-size:12px;color:#6e6e73}.auth-divider{display:flex;align-items:center;gap:12px;margin:18px 0;color:#86868b;font-size:11px}.auth-divider:before,.auth-divider:after{content:"";height:1px;background:#e5e5e8;flex:1}.auth-text-button,.nav-auth-button{font:inherit;font-size:12px;background:transparent;border:0;color:#0066cc;cursor:pointer;padding:8px}.managed-auth .auth-switch{font-size:13px;margin:20px 0}.managed-auth input:disabled,.managed-auth button:disabled{opacity:.55;cursor:wait}.auth-verification p{font-size:13px;margin:14px 0}.auth-verification .pill{font-size:13px}.managed-auth p.field-error{color:#a33125;font-size:13px}.auth-verification h3{font-size:20px;letter-spacing:-.02em}
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
  billing?: BillingView;
  browserAuthEnabled?:boolean;
  adminCredentialsAvailable?:boolean;
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
  version?: number;
  ownerName?: string | null;
  recoveryReserved?: boolean;
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
  readinessFailures?: string[];
  tainted?: boolean;
  hostingEstimate?: string | null;
};

export type OperatorUserRow = {
  id:string; email:string|null; emailVerified:boolean; status:string; createdAt:string|null;
  organizationId:string|null; organizationName:string|null; organizationStatus:string|null; domains:string|null;
  serverId:string|null; serverLabel:string|null; publicIpv4:string|null;
  relayId:string|null; relayLabel:string|null; relayAccount:string|null;
  lifecycleState:string|null; onboardingState:string|null;
};

export type OperatorPortalView = {
  billingCleanup?: Array<{organizationId:string;email:string;serverId:string|null;publicIpv4:string|null;relayId:string|null}>;
  canManageServers?: boolean;
  canManageBrevo?: boolean;
  canViewBrevo?: boolean;
  activeTab?: "servers" | "brevo" | "users";
  users?: OperatorUserRow[];
  notice?: string;
  counts: Array<{ state: string; count: number }>;
  servers: OperatorServerRow[];
  requiredActions: string[];
  cloudVerified: false;
  waitlist?: Array<{ organizationId: string; profileCode: string; registeredAt: string | null }>;
  relays?: Array<{ version?: number; archivedAt?: string | null; ownerName?: string | null; id: string; label: string; account: string; smtpLogin: string; dailyLimit: number; state: string; assigned: boolean }>;
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
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${escapeHtml(title)}</title>${PAGE_STYLE}${body.includes('id="checkout-form"') ? '<script src="https://js.stripe.com/dahlia/stripe.js" defer></script>' : ""}</head>
<body class="${escapeHtml(bodyClass)}">
<header class="nav"><a class="mark" href="/">BearPortal</a><nav>${nav}</nav>${demoBadge()}</header>
<main class="sheet"><h1>${escapeHtml(title)}</h1>${body}</main>
<footer class="fine">${bodyClass.includes("customer") ? "<p>Your provider credentials stay private. Mailbox sign-in is separate from BearPortal.</p>" : bodyClass.includes("operator") ? "<p>Inventory changes are audited. Cloud servers and provider accounts are managed separately.</p>" : HONESTY}</footer>
${bodyClass.includes("customer") ? '<script src="/assets/customer-session.js" defer></script>' : ""}</body></html>`;
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
  managedAuth?:boolean;
  authMode?:"signup"|"signin";
  mode?: "development" | "identity";
  error?: string;
  email?: string;
  organization?: string;
};

export function renderHome(state: HomeState = {}): string {
  const development = (state.mode ?? "development") === "development";
  const form = state.managedAuth || state.authMode === "signin" ? managedAuthForm(state.authMode??"signup") : development ? `<form method="post" action="/register" class="signup-form">
<label for="signup-email">Your email address</label><input id="signup-email" name="email" type="email" placeholder="you@company.com" autocomplete="email" required maxlength="200" value="${escapeHtml(state.email ?? "")}" aria-describedby="signup-help">
${state.error ? `<p class="field-error" role="alert">${escapeHtml(state.error)}</p>` : ""}
<button class="pill" type="submit">Continue with email <span aria-hidden="true">↗</span></button>
<p id="signup-help" class="fine">Use an email you can access before your new domain is set up.</p>
</form>` : `<p>Continue with your verified email through your organization's sign-in provider.</p><a class="pill" href="/portal">Open your account</a>`;
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>BearPortal — Your domain. Your mail.</title>${PAGE_STYLE}</head>
<body class="home"><header class="nav"><a class="mark" href="/">BearPortal<span class="brand-dot" aria-hidden="true">.</span></a><nav><a href="#how">How it works</a><a href="/login">Sign in</a><a href="/portal">Your account</a></nav>${demoBadge()}</header>
<main><section class="landing"><div class="landing-copy"><p class="eyebrow">Meet your new email</p><h1>Your domain.<br>Your mail.<br><span class="soft">Simply yours.</span></h1><p class="lede">Bring your domain. We’ll take care of setting up Bearmail, on a server dedicated to you.</p><a class="text-link" href="#how">A little setup. A lot less work. <span aria-hidden="true">↓</span></a></div>
<div class="signup-card" id="register"><div class="mail-icon" aria-hidden="true">${mailIcon()}</div><h2>${state.authMode==='signin'?'Welcome back.':'Make room for<br>better email.'}</h2><p>${state.authMode==='signin'?'Sign in to your BearPortal account.':state.managedAuth?'Create your account, subscribe, then connect your domain.':'Create your account, subscribe, then connect your domain.'}</p>${state.authMode!=="signin"?'<p class="fine">$20 USD/month plus applicable tax. First month free for eligible accounts; a payment method is required. Cancel before your first charge to avoid payment. You’ll need a domain and access to its DNS settings.</p>':""}${form}${development&&!state.managedAuth ? `<p class="preview-note">Development preview: email verification is not enabled. Use a test account.</p>` : ""}</div></section>
<section class="journey" id="how"><p class="eyebrow">Your path to Bearmail</p><h2>From your domain<br>to your inbox.</h2><div class="journey-grid"><article><span class="step-number">01</span><h3>Make yourself at home.</h3><p>Register with your email. Everything you need is in one place.</p></article><article><span class="step-number">02</span><h3>Start your subscription.</h3><p>Your first month is free if eligible, then $20 USD/month plus applicable tax. Add a payment method and cancel any time.</p></article><article><span class="step-number">03</span><h3>Connect your domain.</h3><p>Tell us your domain. We’ll find your DNS provider and guide you through connecting it.</p></article><article><span class="step-number">04</span><h3>Set up your mailboxes.</h3><p>We install Bearmail. Then open the administrator console to create your mailboxes and test sending and receiving email.</p></article></div></section></main>
<footer class="home-footer"><a class="mark" href="/">BearPortal.</a><p>Made for your domain. Ready when you are.</p></footer></body></html>`;
}

function managedAuthForm(mode:"signup"|"signin"):string {
  const signup=mode==='signup';
  return `<div class="managed-auth" data-managed-auth data-auth-mode="${mode}"><div class="auth-google" data-auth-google aria-label="Google sign-in">Loading Google sign-in…</div><div class="auth-divider"><span>or use your email</span></div><p data-auth-message class="fine" role="status" hidden></p><form method="post" action="${signup?'/auth/signup':'/auth/signin'}" class="signup-form" data-auth-form><label for="signup-email">Email address</label><input id="signup-email" name="email" type="email" placeholder="you@company.com" autocomplete="email" maxlength="200" required disabled><label for="signup-password">Password</label><input id="signup-password" name="password" type="password" autocomplete="${signup?'new-password':'current-password'}" ${signup?'minlength="12"':''} maxlength="256" required disabled>${signup?'<label for="signup-confirm-password">Confirm password</label><input id="signup-confirm-password" name="confirmPassword" type="password" autocomplete="new-password" minlength="12" maxlength="256" required disabled><p class="fine">Use at least 12 characters. We’ll send a verification email before setup begins.</p>':''}<button class="pill" type="submit" disabled>${signup?'Create account':'Sign in'}</button><button class="auth-text-button" type="button" data-auth-reset disabled>Forgot password?</button></form><div class="auth-verification" data-auth-verification hidden><h3>Verify your email</h3><p>Open the verification link in your inbox. Your setup can begin once your address is confirmed.</p><button class="pill" type="button" data-auth-verified>I’ve verified my email</button><button class="auth-text-button" type="button" data-auth-resend>Resend verification email</button></div><button class="auth-text-button" type="button" data-auth-resume hidden>Continue with saved sign-in</button><p class="auth-switch">${signup?'Already have an account? <a href="/login">Sign in</a>':'New to BearPortal? <a href="/register">Create an account</a>'}</p><p class="fine">This is your BearPortal account. Mailbox accounts are created separately after installation.</p><noscript><p>Enable JavaScript to sign in with Google or email and password.</p></noscript></div><script src="/assets/auth.js" defer></script>`;
}

function billingCard(billing: BillingView, continueSetupLabel?: string): string {
  const hidden = '<input type="hidden" name="csrf" value="1">';
  const date = billing.trialEndsAt ? new Date(billing.trialEndsAt).toLocaleDateString("en-US", {timeZone:"UTC",year:"numeric",month:"long",day:"numeric"}) : null;
  if (billing.entitled) return `<section class="setup-card" id="subscription"><p class="eyebrow">Your subscription</p><h2>${billing.status === "trialing" ? "Your first month is free." : "$20 USD per month + applicable tax"}</h2><p>${billing.status === "trialing" ? `Your first charge is on ${escapeHtml(date)}. Then $20 USD plus applicable tax each month. Cancel before this date to avoid the first charge.` : "Your subscription is active. You can install Bearmail and manage your billing here."}</p>${continueSetupLabel?`<a class="pill" href="#setup-next-step">${escapeHtml(continueSetupLabel)}</a>`:""}<form method="post" action="/portal/billing/manage">${hidden}<button class="secondary-button" type="submit">Manage billing & invoices</button></form><details><summary>Cancel subscription</summary><p>Cancellation stops future billing immediately. Our operator will manually stop your service and release its resources.</p><form method="post" action="/portal/billing/cancel">${hidden}<label class="check"><input type="checkbox" name="confirm" value="1" required>Cancel my subscription and request manual resource release.</label><button class="secondary-button" type="submit">Confirm cancellation</button></form></details></section>`;
  if (billing.cleanupRequired || billing.status === "canceled") return `<section class="setup-card" id="subscription" role="status"><h2>Your subscription is canceled.</h2><p>No further subscription charges will be made. The operator has been notified to manually stop your service and release the server and Brevo resources.</p></section>`;
  if (billing.invoiceIssue) return `<section class="setup-card" id="subscription"><h2>Your invoice needs attention.</h2><p>${billing.invoiceIssue === "TAX_LOCATION_REQUIRED" ? "Update your billing address so Stripe can calculate tax and finalize your invoice." : billing.invoiceIssue === "PAYMENT_AUTHENTICATION_REQUIRED" ? "Confirm your payment with your bank to complete this invoice." : "Stripe could not finalize your invoice. Please check your billing details or contact the operator."}</p><form method="post" action="/portal/billing/manage">${hidden}<button class="pill" type="submit">Manage billing & invoices</button></form><form method="post" action="/portal/billing/cancel">${hidden}<label><input type="checkbox" name="confirm" value="1" required>Cancel my subscription</label><button class="secondary-button" type="submit">Confirm cancellation</button></form></section>`;
  if (["past_due","unpaid","incomplete","paused","active","trialing","invalid_plan","incomplete_expired"].includes(billing.status)) return `<section class="setup-card" id="subscription"><h2>Check your subscription.</h2><p>Your subscription needs attention before Bearmail can be installed.</p><form method="post" action="/portal/billing/manage">${hidden}<button class="pill" type="submit">Manage subscription</button></form><form method="post" action="/portal/billing/cancel">${hidden}<label><input type="checkbox" name="confirm" value="1" required>Cancel my subscription</label><button class="secondary-button" type="submit">Confirm cancellation</button></form></section>`;
  return `<section class="setup-card" id="subscription"><p class="eyebrow">Before you install Bearmail</p><h2>${billing.trialAvailable ? "First month free. Then $20/month + tax." : "$20 USD per month + applicable tax"}</h2><p>Subscribe for $20 USD per month plus applicable tax to unlock Bearmail installation. ${billing.trialAvailable ? "Your first calendar month is free. Add a payment method at checkout; billing starts in the second month. Cancel any time during your free month to avoid being charged." : "This account has already used its free month. Billing starts when you subscribe. You can cancel any time."}</p>${billing.configured ? `<form method="post" action="/portal/billing/checkout" data-stripe-checkout data-stripe-publishable-key="${escapeHtml(process.env.STRIPE_PUBLISHABLE_KEY??'')}">${hidden}<button class="pill" type="submit">${billing.trialAvailable ? "Subscribe · first month free" : "Subscribe · $20/month"}</button></form><div id="checkout-form"></div>` : '<p role="status">Subscriptions are being configured. Please contact the operator.</p>'}<p class="fine">If you cancel, the operator will manually stop your service and release its resources.</p></section>`;
}

function mailIcon(): string {
  return `<svg viewBox="0 0 48 48" fill="none" aria-hidden="true"><rect x="6" y="12" width="36" height="26" rx="7" stroke="currentColor" stroke-width="2"/><path d="m8 15 13 11a5 5 0 0 0 6 0l13-11" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>`;
}

export function setupProgress(view: CustomerPortalView): { current: number; complete: boolean; note: string; running: boolean } {
  const installed = view.onboardingState === "installed" || ["succeeded", "tls_pending"].includes(view.installerStatus ?? "");
  const complete = view.installerStatus === "succeeded";
  const current = installed || view.onboardingError === "MAILBOX_ADDRESS_CONFLICT" || view.onboardingState === "installing" || (view.brevoAuthenticated && view.brevoVerified) ? 1 : 0;
  const running = !complete && (view.onboardingState === "installing" || (view.onboardingState === "queued" && !view.onboardingError));
  const note = view.onboardingError ? setupErrorMessage(view.onboardingError)
    : complete ? "Bearmail and secure connections are ready. Reveal your administrator credentials below, create mailboxes, then test sending and receiving mail."
    : view.onboardingState === "attention" ? "Setup is paused for operator review. Your progress is saved."
    : view.onboardingState === "waiting_resources" ? "Waiting for a server or mail-service account. No completion estimate is available until capacity is ready. We’ll continue automatically."
    : installed ? "Bearmail is installed. Checking HTTPS certificates for the administrator and webmail sites."
    : current === 1 ? "Installing Bearmail on your allocated server. This usually takes several minutes; server preparation and downloads may take longer."
    : "Adding the domain’s DNS verification records and checking authentication with Brevo. DNS verification can take minutes to hours; we’ll continue automatically.";
  return { current, complete, note, running };
}

function renderSetupProgress(view: CustomerPortalView): string {
  if (!view.onboardingState && !view.installerStatus) return "";
  const { current, complete, note, running } = setupProgress(view);
  const labels = ["Verifying Brevo domain", "Installing Bearmail"];
  const animating = !complete && view.onboardingState !== "attention" && (running || current === 0);
  const status = complete ? "Complete" : view.onboardingState === "attention" ? "Paused · needs attention" : running ? "Working" : "Waiting";
  const statusMarkup = status === "Waiting" ? '<span class="waiting-status">Waiting<span aria-hidden="true">…</span></span>' : status;
  const timing = !complete && view.onboardingState !== "attention" ? '<p class="setup-timing">The whole process, including domain records taking effect, may take about 7 minutes.</p>' : "";
  const value = complete ? 2 : current;
  const code = view.onboardingError;
  return `<section class="setup-progress" aria-labelledby="setup-progress-title"><div class="milestone-heading"><h2 id="setup-progress-title">${complete ? "Your setup is complete" : `Step ${current + 1} of 2 · ${labels[current]}`}</h2><span>${statusMarkup}</span></div>${timing}<div class="backend-progress" role="progressbar" aria-label="Backend setup progress" aria-valuemin="0" aria-valuemax="2" aria-valuenow="${value}" aria-valuetext="${escapeHtml(complete ? "Both backend stages complete" : `${labels[current]}: ${status}`)}"><span style="width:${value * 50}%"></span></div><p role="${view.onboardingState === "attention" ? "alert" : "status"}">${escapeHtml(note)}${code ? `<br><small>Error code: <code>${escapeHtml(code)}</code></small>` : ""}</p><ol class="milestones" aria-label="Setup progress">${labels.map((label, i) => {
    const done = complete || i < current;
    const active = !complete && i === current;
    return `<li class="${done ? "complete" : active ? "current" : "upcoming"}"${active ? ' aria-current="step"' : ''}><span class="milestone-number ${active && animating ? "working-spinner" : ""}" aria-hidden="true">${done ? "✓" : active && animating ? "" : i + 1}</span><div><strong>${label}</strong><small>${done ? "Complete" : active ? statusMarkup : "Up next"}</small></div></li>`;
  }).join("")}</ol><p class="fine">${complete ? "Mailbox access and mail delivery still need to be tested." : "Progress refreshes automatically. Your setup is saved; no need to authorize it again."}</p></section>`;
}

function customerJourney(view: CustomerPortalView): string {
  const blocked = Boolean(view.billing && !view.billing.entitled);
  const canceled = blocked && (view.billing?.status === "canceled" || view.billing?.cleanupRequired);
  const reconnect = view.onboardingState === "attention" && ["DNS_CREDENTIAL_REQUIRED", "DNS_PROVIDER_CHANGED"].includes(view.onboardingError ?? "");
  const complete = view.installerStatus === "succeeded" && !blocked;
  const stage = blocked ? 0 : !view.domainName ? 1 : reconnect || (!view.dnsState && !view.onboardingState) ? 2 : 3;
  const steps = ["Subscription", "Your domain", "Connect DNS", "Install Bearmail"];
  const instruction = canceled ? "Your subscription is canceled" : blocked
    ? view.billing?.status === "none" ? "Start your subscription" : "Review your subscription"
    : !view.domainName ? "Add your domain"
    : reconnect ? "Reconnect your DNS provider"
    : stage === 2 ? (view.detectedProvider ? "Connect your DNS provider" : "Check your DNS provider")
    : complete ? "Create your first mailbox"
    : view.onboardingState === "attention" ? "Wait for operator review"
    : view.onboardingState ? "Setup is in progress — no action needed"
    : "Authorize Bearmail installation";
  const help = canceled ? "No setup action is needed. Future subscription billing has stopped, and the operator has been notified to release your resources." : blocked ? "Complete the subscription step below to unlock domain setup."
    : !view.domainName ? "Enter a domain you own, such as yourcompany.com. We’ll find its DNS provider next."
    : stage === 2 && !view.detectedProvider ? "We couldn’t identify a supported provider. Check the domain below and try again. BearPortal supports Name.com, Hostinger and GoDaddy."
    : reconnect || stage === 2 ? "Have your provider’s API credential ready. The form below explains where to find it and asks for permission before changing mail routing."
    : complete ? "Open the administrator console below, reveal your administrator login, and create a mailbox. Then sign in to webmail and test sending and receiving."
    : view.onboardingState === "attention" ? "Your progress is saved. The operator needs to resolve the issue shown below; you don’t need to submit setup again."
    : view.onboardingState ? "This page updates automatically. You can close it and return later; we’ll continue from your saved progress."
    : "Review the mail-routing permission below, then choose Set up my Bearmail. Existing messages won’t be migrated.";
  return `<ol class="setup-checklist" aria-label="Your Bearmail setup checklist">${steps.map((label,i)=>{
    const done = i < stage || (complete && i === 3);
    return `<li class="${done?"complete":i===stage?"current":"upcoming"}"${i===stage&&!complete?' aria-current="step"':''}><strong><span aria-hidden="true">${done?"✓":i+1} · </span>${label}</strong><small>${done?"Complete":i===stage?(canceled?"Canceled":"Current step"):"Coming next"}</small></li>`;
  }).join("")}</ol><aside class="next-step" aria-labelledby="next-step-title"><strong id="next-step-title">${instruction}</strong><p>${help}</p></aside>`;
}

export function renderCustomerPortal(view: CustomerPortalView): string {
  const domain = view.domainName ?? "";
  const hasServer = Boolean(view.serverId || view.allocationState === "allocated");
  const waiting = view.onboardingState === "waiting_resources";
  const requested = Boolean(view.onboardingState);
  const installed = view.onboardingState === "installed" || view.installerStatus === "succeeded" || view.installerStatus === "tls_pending";
  const busy = requested && (view.installerStatus !== "succeeded");
  const title = view.billing && !view.billing.entitled ? (view.billing.status === "none" ? "Start with your subscription." : "Review your subscription.") : installed ? (view.installerStatus === "succeeded" ? "Create your first mailbox." : "Finishing secure connections.") : requested ? "Setting up your Bearmail." : view.billing?.entitled ? (!domain ? "Add your domain." : !view.dnsState ? "Connect your DNS provider." : "Ready to install Bearmail.") : "Let’s make it yours.";
  const subtitle = view.billing && !view.billing.entitled ? "Subscribe first, then connect your domain and install Bearmail." : installed ? `Bearmail is installed for ${domain}.` : requested ? "Your setup is saved. We’ll take it from here." : view.billing?.entitled ? (!domain ? "Your subscription is confirmed. Add your domain and continue setting up Bearmail." : "Your subscription is confirmed. Continue from your saved setup below.") : "A few simple steps. A place for all your mail.";
  const progress = view.billing && !view.billing.entitled ? "" : renderSetupProgress(view);
  const shortage = !hasServer || view.missingResource === "relay" || view.missingResource === "server_and_relay";
  const capacity = shortage && !installed && (!view.billing || (view.billing.entitled && requested)) ? `<aside class="capacity-note" role="status"><span class="status-dot amber"></span><div><strong>A little more room is on the way.</strong><p>Resources are tight right now. ${requested ? `Your setup is saved. ${view.missingResource === "server" ? "Your mail-service account is reserved. We’re checking server availability and will continue automatically." : view.missingResource === "relay" ? "Your server is reserved. We’ll continue as soon as a mail-service account is available." : "We’ll deploy it as soon as a server and mail-service account are available."} You don’t need to submit it again.` : "You can connect your domain now. We’ll save your place and deploy as soon as capacity is available."}</p></div></aside>` : "";
  let card: string;
  if (view.billing && !view.billing.entitled) {
    card = billingCard(view.billing);
  } else if (!domain) {
    card = `<section class="setup-card" id="domain"><p class="eyebrow">Your domain</p><h2>What’s your domain?</h2><p>Enter only your domain, like <span class="example">yourcompany.com</span>, without an email address or https://.</p>${customerDomainForm()}<p class="fine">We’ll detect who manages your DNS. Saving your domain won’t change your mail routing.</p></section>`;
  } else if (!requested && !view.dnsState) {
    card = `<section class="setup-card" id="domain"><p class="eyebrow">Connect your domain</p><h2>${escapeHtml(domain)}</h2>${providerNotice({nameservers:view.detectedNameservers,detectedProvider:view.detectedProvider})}${dnsCredentialForm({domain,detectedProvider:view.detectedProvider})}${!view.detectedProvider?customerDomainForm(domain):""}</section>`;
  } else if (!requested) {
    card = `<section class="setup-card" id="setup"><p class="eyebrow">Your Bearmail</p><h2>Everything in one place.</h2><p>Your domain provider is connected. We’ll verify the mail service and install Bearmail for <strong>${escapeHtml(domain)}</strong>.</p>${startSetupForm(domain)}</section>`;
  } else if (view.onboardingState === "attention") {
    const credentialNeeded=view.onboardingError === "DNS_CREDENTIAL_REQUIRED" || view.onboardingError === "DNS_PROVIDER_CHANGED";
    card = `<section class="setup-card" id="setup"><span class="status-label amber">${credentialNeeded?'Provider connection needed':'Our team is on it'}</span><h2>${credentialNeeded?'Reconnect your provider.':'We’re finishing your setup.'}</h2><p>${credentialNeeded?'The saved provider connection is missing or the provider has changed. Update your credential below; your existing setup authorization is saved.':'Your credential and setup authorization are saved. Our team is checking an installation issue. You don’t need to authorize the steps again or resubmit your credential.'}</p>${credentialNeeded?dnsCredentialForm({domain,detectedProvider:view.detectedProvider,setupAuthorized:true}):''}</section>`;
  } else if (installed) {
    card = `<section class="setup-card" id="setup"><span class="status-label">${view.installerStatus === "tls_pending" ? "Finishing the connection" : "Bearmail installed"}</span><h2>A home for your email.</h2><p>${view.installerStatus === "tls_pending" ? "Bearmail is installed. Secure connections may still be finishing. We’ll keep your setup status here." : "Your Bearmail installation is in place."}</p><div class="address-preview">${mailIcon()}<span>${escapeHtml(view.webmailHostname ?? `bearmail.${domain}`)}</span></div>${view.installerStatus === "succeeded" && view.webmailHostname ? `<a class="pill" href="https://${escapeHtml(view.webmailHostname)}" target="_blank" rel="noopener noreferrer">Open Bearmail ↗</a>` : ""}<p class="fine">${view.mailVerified ? "Mail delivery has been verified." : "Mail delivery and mailbox access still need verification. Installation alone doesn’t confirm that messages can be received or sent."}</p></section>`;
  } else {
    const headline = waiting ? "Your place is saved." : view.onboardingState === "installing" ? "Making things ready." : "Connecting the pieces.";
    card = `<section class="setup-card" id="setup" role="status"><span class="status-label ${waiting?'amber':''}">${waiting?"Waiting for capacity":view.onboardingState==="installing"?"Installing Bearmail":"Setting up your domain"}</span><h2>${headline}</h2><p>${waiting ? "We’ll continue automatically when resources are available. You can close this page and come back anytime." : view.onboardingError === "INSTALLER_STORAGE_UNAVAILABLE" || view.onboardingError === "INSTALLER_UNAVAILABLE" ? "Your domain connection is saved. We’re preparing the installation service and will retry automatically." : view.onboardingError === "DNS_PROPAGATION" ? "Your provider is connected. We’re waiting for the domain’s verification records to become visible." : "We’re authenticating your mail service and preparing your dedicated Bearmail installation. This can take a little while."}</p><div class="address-preview">${mailIcon()}<span>${escapeHtml(domain)}</span></div><p class="fine">Your progress is saved. No need to keep this page open.</p></section>`;
  }
  const summary = `<aside class="setup-summary"><p class="eyebrow">Your space</p><h3>${domain ? escapeHtml(domain) : "A domain of your own."}</h3><ul>${view.billing?`<li><span>Subscription</span><strong>${view.billing.entitled?(view.billing.status==="trialing"?"Free month active":"Active"):view.billing.status==="none"?"Not started":"Needs attention"}</strong></li>`:""}<li><span>Account</span><strong>${escapeHtml(view.recoveryEmail ?? "Registered")}</strong></li><li><span>Domain</span><strong>${domain ? "Saved" : "Up next"}</strong></li><li><span>Provider</span><strong>${providerLabel(view.detectedProvider ?? view.dnsProvider) || "We’ll find it for you"}</strong></li><li><span>Server</span><strong>${hasServer?"Reserved for you":requested?"Waiting for capacity":"Allocated during setup"}</strong></li><li><span>Mail service</span><strong>${view.relayAssigned?"Reserved for you":"Allocated during setup"}</strong></li></ul><p class="fine">Your mail runs on a server dedicated to your organization.</p></aside>`;
  const details = `<details class="service-details" id="account"><summary>Your account & service details</summary><div class="details-grid"><section><h2>Account</h2>${definition([["Email",view.recoveryEmail],["Domain",domain||"Not connected"],["Webmail",view.webmailHostname],["Mail server",view.mailHostname],["Plan",view.planCode??"Beta"]])}</section><section id="connections"><h2>Connection settings</h2>${definition([["IMAP",`${view.mailHostname??"Your mail hostname"} · 993 · TLS`],["SMTP submission",`${view.mailHostname??"Your mail hostname"} · 465 · TLS`],["JMAP",`${view.mailHostname??"Your mail hostname"} · 443`]])}<p class="fine">Use your mailbox address to sign in. Mailbox login is separate from BearPortal.</p></section><section id="mailboxes"><h2>Mailboxes</h2>${(view.mailboxes??[]).length?`<ul>${(view.mailboxes??[]).map(row=>`<li>${escapeHtml(row.localPart)}${domain?'@'+escapeHtml(domain):''} <span class="fine">${row.loginEnabled?"Login enabled":"Access pending"}</span></li>`).join("")}</ul>`:"<p>Your requested addresses will appear here.</p>"}<p class="fine">Requested addresses need to be applied to the mail server before use.</p></section><section id="backups"><h2>Backups and activity</h2><p>Backups are operator-reported. ${view.backupState?escapeHtml(view.backupState):"No backup is reported yet."}</p><ul>${[...(view.jobs??[]),...(view.events??[])].slice(0,5).map(row=>`<li>${escapeHtml(row.kind.replaceAll('_',' '))} <span class="fine">${escapeHtml(row.state)}</span></li>`).join("")}</ul></section></div><details class="support-details"><summary>Support information</summary>${definition([["Organization",view.organizationId],["Server address",view.publicIpv4],["Deployment",view.deploymentId],["Lifecycle",view.lifecycleState],["Health",view.healthState],["Installer status",view.installerStatus],["Live mail verified",view.mailVerified],["Cloud verified",false],["Required actions",view.requiredActions.join(", ")||"none"]])}${recordList(view.publishedRecords,"No published records are stored.")}</details></details>`;
  const refresh = busy ? `<script>setTimeout(function(){if(!document.querySelector('form:focus-within'))location.reload()},15000)</script>` : "";
  return shell("Your Bearmail",`<a href="#account">Your account</a>${view.browserAuthEnabled?'<button type="button" class="nav-auth-button" data-auth-logout hidden>Sign out</button>':''}`,`<div class="welcome-heading"><p class="eyebrow">Welcome to your space</p><h1>${title}</h1><p>${escapeHtml(subtitle)}</p></div>${customerJourney(view)}${progress}${capacity}<div class="onboarding-grid" id="setup-next-step">${card}${summary}</div>${view.billing?.entitled?`<details class="subscription-details" id="billing-details"><summary>Subscription & billing · ${view.billing.status==="trialing"?"Free month active":"Active"}</summary>${billingCard(view.billing,!requested?(domain?"Continue Bearmail setup":"Add your domain"):undefined)}</details>`:""}${installed&&(!view.billing||view.billing.entitled)?mailAccessCard(view):''}${details}${refresh}${view.browserAuthEnabled?'<script src="/assets/auth.js" defer></script>':''}`,"app customer");
}

function mailAccessCard(view:CustomerPortalView):string {
  const domain=view.domainName??'';
  const adminHost=view.mailHostname??`mail.${domain}`;
  const webmailHost=view.webmailHostname??`bearmail.${domain}`;
  const pending=view.installerStatus==='tls_pending';
  return `<section class="setup-card mail-access"><p class="eyebrow">Next · Create your mailboxes</p><h2>Start with the administrator console.</h2><ol><li>Reveal your administrator login and open the administrator console.</li><li>Create a mailbox and set its password.</li><li>Open webmail with that mailbox’s full email address and password, then test sending and receiving.</li></ol>${pending?'<p class="notice">HTTPS certificates are still being issued. If either site is unavailable, wait for certificates to finish.</p>':''}<div class="mail-access-grid"><section><h3>Administrator console</h3><p>Create mailboxes, set their passwords and manage your domain.</p><a class="pill" href="https://${escapeHtml(adminHost)}/" target="_blank" rel="noopener noreferrer">Open ${escapeHtml(adminHost)} ↗</a>${view.adminCredentialsAvailable&&view.deploymentId?`<div class="admin-login" data-admin-login data-reveal-url="/v1/deployments/${escapeHtml(view.deploymentId)}/admin-credentials/reveal"><p class="fine">Use the administrator login generated during installation. Only your BearPortal account can reveal it.</p><button type="button" class="secondary-button" data-reveal-admin aria-expanded="false">Show administrator login</button><div data-admin-login-values hidden><label>Administrator username<input type="text" readonly autocomplete="off" data-admin-username></label><label>Generated password<input type="text" readonly autocomplete="off" spellcheck="false" data-admin-password></label><p class="fine">Keep this login private. Use it to create regular mailbox accounts in the administrator console.</p></div><p class="form-error" role="alert" data-admin-login-error hidden></p></div>`:'<p class="fine">The generated administrator login is not available here yet.</p>'}</section><section><h3>Bearmail webmail</h3><p>Mailbox users sign in here to send and receive email.</p><a class="pill" href="https://${escapeHtml(webmailHost)}/" target="_blank" rel="noopener noreferrer">Open ${escapeHtml(webmailHost)} ↗</a><p class="fine">Sign in with the full mailbox address, such as hello@${escapeHtml(domain)}, and the password set for that mailbox. Create and enable the mailbox in the administrator console first. Your BearPortal login is separate.</p></section></div></section>${ADMIN_LOGIN_SCRIPT}`;
}
const ADMIN_LOGIN_SCRIPT=`<script>
(function(){document.querySelectorAll('[data-admin-login]').forEach(function(panel){var button=panel.querySelector('[data-reveal-admin]'),values=panel.querySelector('[data-admin-login-values]'),username=panel.querySelector('[data-admin-username]'),password=panel.querySelector('[data-admin-password]'),error=panel.querySelector('[data-admin-login-error]');function hide(){values.hidden=true;username.value='';password.value='';button.textContent='Show administrator login';button.setAttribute('aria-expanded','false')}button.addEventListener('click',async function(){if(!values.hidden){hide();return}button.disabled=true;error.hidden=true;try{var response=await fetch(panel.dataset.revealUrl,{method:'POST',headers:{'content-type':'application/json','x-bearportal-csrf':'1'},body:'{}',cache:'no-store'});var result=await response.json();if(!response.ok)throw Error(result.error&&result.error.message||'Could not load the administrator login.');username.value=result.username;password.value=result.password;values.hidden=false;button.textContent='Hide administrator login';button.setAttribute('aria-expanded','true')}catch(failure){error.textContent=failure.message;error.hidden=false}finally{button.disabled=false}});window.addEventListener('pagehide',hide)})})();
</script>`;

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
  setupAuthorized?: boolean;
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
  return shell("Connect your domain",`<a href="/portal">Your account</a>`,`<div class="welcome-heading"><p class="eyebrow">Your domain</p><h1>${view.saved?escapeHtml(view.domain):"Let’s find your domain."}</h1><p>${view.saved?"Your domain is saved. Let’s connect your provider.":"A place for your company’s email."}</p></div>${view.error?`<p class="notice error" role="alert">${escapeHtml(view.error)}</p>`:""}${view.unavailable?`<aside class="capacity-note" role="status"><span class="status-dot amber"></span><div><strong>Resources are tight right now.</strong><p>You can connect your domain below. We’ll save your setup and deploy as soon as server and mail-service capacity is available.</p></div></aside>`:""}<section class="setup-card standalone">${providerNotice(view)}${dnsCredentialForm(view)}${!view.saved || !view.detectedProvider ? customerDomainForm(view.domain??"") : ""}<a class="text-link" href="/portal">Back to your setup</a></section>`,"app customer");
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

function dnsCredentialForm(view: { setupAuthorized?: boolean; domain?: string; detectedProvider?: "namecom" | "hostinger" | "godaddy" | null }): string {
  if (!view.domain || !view.detectedProvider) return "";
  const fields = view.detectedProvider === "namecom"
    ? `<label>Name.com username<input type="text" name="dnsUsername" autocomplete="off" required></label><label>API token<input type="password" name="dnsToken" autocomplete="off" required></label>`
    : `<label>${view.detectedProvider === "godaddy"?"Personal access token (PAT)":"API token"}<input type="password" name="dnsToken" autocomplete="off" required></label>`;
  const guide = view.detectedProvider === "godaddy" ? `<a href="https://developer.godaddy.com/en/personal-access-token" target="_blank" rel="noopener noreferrer">Create a GoDaddy personal access token ↗</a><p>Allow Domains and DNS access, including DNS updates.</p>` : view.detectedProvider === "hostinger" ? "<p>In Hostinger hPanel, open your profile, then API. Create a token with access to this domain’s DNS.</p>" : "<p>In your Name.com account, open API settings. Copy your account username and API token.</p>";
  return `<form method="post" action="/portal/dns-credential"><input type="hidden" name="csrf" value="1"><input type="hidden" name="domain" value="${escapeHtml(view.domain)}"><input type="hidden" name="onboarding" value="1">${fields}<details class="credential-help"><summary>Where do I find this?</summary>${guide}</details>${view.setupAuthorized?'<p class="fine">Your existing setup authorization is saved.</p>':`<label class="check consent"><input type="checkbox" name="deployConsent" value="1" required><span>I authorize BearPortal to verify ${escapeHtml(view.domain)}, authenticate it with Brevo, update its mail-routing DNS, install Bearmail on my allocated server and send a setup test email. Existing messages won’t be migrated.</span></label>`}<button class="pill" type="submit">Connect & set up Bearmail <span aria-hidden="true">↗</span></button><p class="fine">Your credential is encrypted. We’ll handle domain verification, the mail service and installation.</p></form>`;
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
  const canEditServer = view.canManageServers === true;
  const canEditBrevo = view.canManageBrevo === true;
  const canViewBrevo = view.canViewBrevo !== false;
  const tab = view.activeTab === "users" ? "users" : view.activeTab === "brevo" && canViewBrevo ? "brevo" : "servers";
  const currentServers = view.servers.filter(row=>row.state!=="retired");
  const currentRelays = (view.relays??[]).filter(row=>!row.archivedAt);
  const readyServers = currentServers.filter(row=>row.state==="available"&&!row.tainted&&!row.ownerId&&row.validatedAt&&Date.now()-new Date(row.validatedAt).getTime()<300000).length;
  const readyRelays = currentRelays.filter(row=>!row.assigned&&(row.state==="inactive"||row.state==="available")).length;
  const notices:Record<string,string>={"server-added":"Server successfully added. Review its SSH check below.","server-saved":"Server details saved. An address change requires a new SSH check.","server-removed":"Server removed from inventory. The cloud machine was not deleted.","server-checked":"SSH check completed. Review the server’s current status.","brevo-added":"Brevo account successfully added. It can be claimed by a waiting setup.","brevo-saved":"Brevo account details saved. Stored changes do not update a running mail server.","brevo-removed":"Brevo account removed from inventory. The provider account was not deleted.","brevo-restored":"Brevo account restored to inventory."};
  const notice=view.notice&&notices[view.notice]?`<div class="inventory-notice" role="status">${escapeHtml(notices[view.notice])}</div>`:"";
  const billingAlerts=(view.billingCleanup??[]).length?`<section class="inventory-notice" role="status"><h2>Subscription cancellations · manual cleanup required</h2>${view.billingCleanup!.map(item=>`<article><strong>${escapeHtml(item.email)}</strong><p>Organization: ${escapeHtml(item.organizationId)} · Server: ${escapeHtml(item.publicIpv4??item.serverId??"None allocated")} · Brevo: ${escapeHtml(item.relayId??"None shown")}</p><p>Manually stop this customer's service and release the server and Brevo account through the reviewed cleanup workflow. Preserve tenant data until retention and cleanup are complete.</p>${canEditServer?`<form method="post" action="/operator/billing/${escapeHtml(item.organizationId)}/cleanup"><input type="hidden" name="csrf" value="1"><label><input type="checkbox" name="confirm" value="1" required>Manual cleanup and release are complete</label><button class="secondary-button" type="submit">Mark cleanup complete</button></form>`:""}</article>`).join('')}</section>`:"";
  const stats=`<div class="inventory-stats"><article><span>Servers ready</span><strong>${readyServers}</strong><small>${currentServers.length} current servers</small></article>${canViewBrevo?`<article><span>Mail accounts ready</span><strong>${readyRelays}</strong><small>${currentRelays.length} current Brevo accounts</small></article>`:""}<article><span>Customers waiting</span><strong>${view.waitlist?.length??0}</strong><small>Capacity is assigned in order</small></article><article><span>Needs attention</span><strong>${view.requiredActions.length}</strong><small>Open operator actions</small></article></div>`;
  const serverRows=view.servers.map(row=>{
    const removed=row.state==="retired";
    return `<tr data-resource-row data-search="${escapeHtml([row.label,row.publicIpv4,row.providerReference,row.ownerName,row.ownerId,row.state].join(' ').toLowerCase())}" data-state="${escapeHtml(row.state)}" data-removed="${removed}"><td><div class="resource-name"><span class="resource-icon" aria-hidden="true">${serverIcon()}</span><div><strong>${escapeHtml(row.label)}</strong><span>${escapeHtml(row.publicIpv4)}</span></div></div></td><td>${resourceStatus(row.state==="available"&&(!row.validatedAt||Date.now()-new Date(row.validatedAt).getTime()>=300000)?"stale":row.state==="pending_validation"&&row.readinessFailures?.length?"ssh_failed":row.state)}${row.readinessFailures?.length?`<small class="table-note">${escapeHtml(sshFailureMessage(row.readinessFailures[0]))}</small>`:""}${row.tainted?'<small class="table-note">Tenant data recorded</small>':""}</td><td>${escapeHtml(row.ownerName??row.ownerId??(row.recoveryReserved?"Reserved for recovery":"Unassigned"))}</td><td><time>${escapeHtml(inventoryDate(row.validatedAt))}</time></td><td class="row-actions"><button type="button" class="table-button" data-open-dialog="server-${escapeHtml(row.id)}">${canEditServer&&!removed?"Review / edit":"View details"}</button></td></tr>`;
  }).join('');
  const relayRows=(view.relays??[]).map(row=>`<tr data-resource-row data-search="${escapeHtml([row.label,row.account,row.smtpLogin,row.ownerName,row.state].join(' ').toLowerCase())}" data-state="${escapeHtml(row.state)}" data-removed="${Boolean(row.archivedAt)}"><td><div class="resource-name"><span class="resource-icon mail" aria-hidden="true">${mailIcon()}</span><div><strong>${escapeHtml(row.label)}</strong><span>${escapeHtml(row.account)}</span></div></div></td><td>${resourceStatus(row.archivedAt?'removed':row.state)}</td><td>${escapeHtml(row.ownerName??(row.assigned?"Assigned":"Unassigned"))}</td><td>${escapeHtml(row.dailyLimit)} <span class="fine">/ day</span></td><td class="row-actions"><button type="button" class="table-button" data-open-dialog="brevo-${escapeHtml(row.id)}">${canEditBrevo&&!row.archivedAt?"Review / edit":"View details"}</button></td></tr>`).join('');
  const toolbar=(type:"servers"|"brevo")=>`<div class="inventory-tools"><label class="search-control"><span class="sr-only">Search ${type==='servers'?'servers':'Brevo accounts'}</span><svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><circle cx="10.5" cy="10.5" r="6" stroke="currentColor" stroke-width="1.7"/><path d="m15 15 5 5" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/></svg><input type="search" data-resource-search placeholder="Search ${type==='servers'?'name, IP or customer':'account, email or customer'}" autocomplete="off"></label><label class="filter-control"><span class="sr-only">Filter status</span><select data-resource-filter><option value="">Current resources</option>${type==='servers'?'<option value="available">Available</option><option value="pending_validation">Needs SSH check</option><option value="reserved">Reserved</option><option value="assigned">In use</option><option value="quarantined">Quarantined</option>':'<option value="inactive">Ready to assign</option><option value="assigned">In use</option><option value="disabled">Paused</option>'}<option value="removed">Removed resources</option></select></label></div>`;
  const serverPanel=`<section class="inventory-panel" id="resources" data-resource-panel><header class="panel-header"><div><h2>Server inventory</h2><p>Review access, capacity and customer assignments.</p></div>${canEditServer?'<button class="pill" type="button" data-open-dialog="add-server">+ Add server</button>':'<span class="read-only">Read-only access</span>'}</header>${toolbar('servers')}<div class="resource-scroll"><table class="resource-table"><thead><tr><th scope="col">Server</th><th scope="col">Status</th><th scope="col">Assigned to</th><th scope="col">Last successful SSH check</th><th scope="col"><span class="sr-only">Actions</span></th></tr></thead><tbody>${serverRows}</tbody></table></div><div class="inventory-empty" data-empty-state ${view.servers.length?'hidden':''}><span class="empty-symbol" aria-hidden="true">${serverIcon()}</span><h3>No servers here yet.</h3><p>Add a prepared server to make room for the next customer.</p></div><p class="inventory-count" aria-live="polite" data-resource-count></p></section>`;
  const brevoPanel=`<section class="inventory-panel" id="resources" data-resource-panel><header class="panel-header"><div><h2>Brevo accounts</h2><p>Your mail-service inventory, with credentials kept private.</p></div>${canEditBrevo?'<button class="pill" type="button" data-open-dialog="add-brevo">+ Add Brevo account</button>':'<span class="read-only">Read-only access</span>'}</header>${toolbar('brevo')}<div class="resource-scroll"><table class="resource-table"><thead><tr><th scope="col">Account</th><th scope="col">Status</th><th scope="col">Assigned to</th><th scope="col">Recorded allowance</th><th scope="col"><span class="sr-only">Actions</span></th></tr></thead><tbody>${relayRows}</tbody></table></div><div class="inventory-empty" data-empty-state ${(view.relays??[]).length?'hidden':''}><span class="empty-symbol" aria-hidden="true">${mailIcon()}</span><h3>No accounts here yet.</h3><p>Add a Brevo account to support the next Bearmail setup.</p></div><p class="inventory-count" aria-live="polite" data-resource-count></p></section>`;
  const usersPanel = operatorUsersPanel(view.users??[],canViewBrevo);
  const dialogs=`${canEditServer?addServerDialog():""}${canEditBrevo?addBrevoDialog():""}${view.servers.map(row=>serverInventoryDialog(row,canEditServer)).join('')}${canViewBrevo?(view.relays??[]).map(row=>brevoInventoryDialog(row,canEditBrevo)).join(''):""}`;
  const activity=`<details class="inventory-activity"><summary>Waiting customers, deployments & operator actions</summary><div class="inventory-activity-grid"><section id="waitlist"><h2>Waitlist</h2>${(view.waitlist??[]).length?`<ul>${view.waitlist!.map(row=>`<li><strong>${escapeHtml(row.organizationId)}</strong><span>${escapeHtml(row.profileCode)} · ${escapeHtml(inventoryDate(row.registeredAt))}</span></li>`).join('')}</ul>`:'<p>No customer is waiting for a server.</p>'}<p class="fine">The allocator assigns the oldest compatible customer. Inventory forms do not override ownership.</p></section><section id="actions"><h2>Required actions</h2>${view.requiredActions.length?`<ul>${view.requiredActions.map(code=>`<li>${escapeHtml(code.replace(/[._]/g,' '))}</li>`).join('')}</ul>`:'<p>Nothing needs your attention right now.</p>'}</section><section id="deployments"><h2>Deployment detail</h2>${(view.deployments??[]).length?`<ul>${view.deployments!.map(row=>`<li><strong>${escapeHtml(row.organizationId)}</strong><span>${escapeHtml(row.lifecycleState)} · ${escapeHtml(row.onboardingStage)} · installer ${escapeHtml(row.installerStatus??'not started')}</span><span>Server ${escapeHtml(row.publicIpv4??'waiting')} · mail verified ${row.mailVerified}</span></li>`).join('')}</ul>`:'<p>No deployments are recorded.</p>'}<p class="fine">Backup evidence is operator-reported. Upgrade plans do not execute binaries; binaries executed false, data rollback false.</p></section></div></details>`;
  return shell('Resources',`<a href="#resources">Resources</a><a href="#actions">Operator actions</a>`,`<div class="operator-heading"><div><p class="eyebrow">Operator workspace</p><h1>Room for what’s next.</h1><p>Manage your servers and mail accounts. Keep every resource in view.</p></div><span class="operator-access">${canEditBrevo?'Platform administrator':canEditServer?'Infrastructure operator':'Support · read only'}</span></div>${notice}${billingAlerts}${stats}<nav class="inventory-tabs" aria-label="Inventory type"><a href="/operator?tab=servers#resources" ${tab==='servers'?'aria-current="page"':''}>Servers <span>${currentServers.length}</span></a>${canViewBrevo?`<a href="/operator?tab=brevo#resources" ${tab==='brevo'?'aria-current="page"':''}>Brevo accounts <span>${currentRelays.length}</span></a>`:""}<a href="/operator?tab=users#resources" ${tab==='users'?'aria-current="page"':''}>Users <span>${new Set((view.users??[]).map(user=>user.id)).size}</span></a></nav>${tab==='users'?usersPanel:tab==='brevo'?brevoPanel:serverPanel}${activity}${dialogs}${(view.users??[]).map((user,index)=>operatorUserDialog(user,index,canViewBrevo)).join('')}${INVENTORY_SCRIPT}`,"app operator");
}

function resourceStatus(state:string):string {
  const labels:Record<string,string>={available:'Available',pending_validation:'Needs SSH check',ssh_failed:'SSH check failed',stale:'Needs SSH refresh',reserved:'Reserved',assigned:'In use',quarantined:'Quarantined',retired:'Removed',removed:'Removed',inactive:'Ready to assign',disabled:'Paused'};
  const tone=state==='available'||state==='inactive'?'green':state==='assigned'||state==='reserved'?'blue':state==='pending_validation'||state==='ssh_failed'||state==='stale'||state==='quarantined'?'amber':'gray';
  return `<span class="resource-status ${tone}"><i aria-hidden="true"></i>${escapeHtml(labels[state]??state)}</span>`;
}
function inventoryDate(value:string|null|undefined):string {if(!value)return 'Not checked';const date=new Date(value);return Number.isNaN(date.getTime())?value:date.toLocaleString('en-US',{month:'short',day:'numeric',year:'numeric',timeZone:'UTC'});}
function serverIcon():string {return '<svg viewBox="0 0 32 32" fill="none" aria-hidden="true"><rect x="6" y="5" width="20" height="9" rx="3" stroke="currentColor" stroke-width="1.6"/><rect x="6" y="18" width="20" height="9" rx="3" stroke="currentColor" stroke-width="1.6"/><path d="M10 9.5h.1M10 22.5h.1M15 9.5h7M15 22.5h7" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/></svg>';}
function inventoryHidden(version?:number):string {return `<input type="hidden" name="csrf" value="1"><input type="hidden" name="idempotencyKey" value="${randomUUID()}">${version===undefined?'':`<input type="hidden" name="expectedVersion" value="${version}">`}`;}
function operatorUsersPanel(users:OperatorUserRow[],canViewBrevo:boolean):string {
  const rows=users.map((user,index)=>`<tr data-resource-row data-state="${escapeHtml(user.status)}" data-removed="false" data-search="${escapeHtml([user.email,user.id,user.organizationName,user.domains,user.publicIpv4,user.serverLabel,canViewBrevo?user.relayAccount:'',user.status].join(' ').toLowerCase())}"><td><strong>${escapeHtml(user.email??'Email not recorded')}</strong><span class="table-note">${user.emailVerified?'Verified email':'Email unverified'} · ${escapeHtml(user.status)}</span></td><td>${escapeHtml(user.organizationName??'No customer organization')}<span class="table-note">${escapeHtml(user.domains??'No domain')}</span></td><td>${user.serverId?`<button class="table-button" type="button" data-open-dialog="server-${escapeHtml(user.serverId)}">${escapeHtml(user.serverLabel??'Review server')}</button><span class="table-note">${escapeHtml(user.publicIpv4)}</span>`:'<span class="fine">Not allocated</span>'}</td>${canViewBrevo?`<td>${user.relayId?`<button class="table-button" type="button" data-open-dialog="brevo-${escapeHtml(user.relayId)}">${escapeHtml(user.relayLabel??'Review account')}</button><span class="table-note">${escapeHtml(user.relayAccount)}</span>`:'<span class="fine">Not allocated</span>'}</td>`:''}<td>${escapeHtml(user.lifecycleState??user.onboardingState??(user.organizationId?'Setup not started':'No customer setup'))}</td><td><button class="table-button" type="button" data-open-dialog="user-${index}">View user</button></td></tr>`).join('');
  return `<section class="inventory-panel" id="resources" data-resource-panel data-user-panel><header class="panel-header"><div><h2>Users & allocations</h2><p>Review registered users, their domains and the resources allocated to their organizations.</p></div></header><div class="inventory-tools"><label class="search-control"><span class="sr-only">Search users and allocations</span><input type="search" data-resource-search placeholder="Search email, domain, server or account" autocomplete="off"></label><label class="filter-control"><span class="sr-only">Filter users</span><select data-resource-filter><option value="">All users</option><option value="active">Active users</option><option value="disabled">Disabled users</option></select></label></div><div class="resource-scroll"><table class="resource-table"><thead><tr><th scope="col">User</th><th scope="col">Organization / domain</th><th scope="col">Allocated server</th>${canViewBrevo?'<th scope="col">Allocated Brevo account</th>':''}<th scope="col">Setup status</th><th scope="col">Details</th></tr></thead><tbody>${rows}</tbody></table></div><div class="inventory-empty" data-empty-state ${users.length?'hidden':''}><h3>No users yet.</h3><p>Registered users will appear here.</p></div><p class="inventory-count" aria-live="polite" data-resource-count></p></section>`;
}
function operatorUserDialog(user:OperatorUserRow,index:number,canViewBrevo:boolean):string {
  return inventoryDialog(`user-${index}`,user.email??'User details','Current organization and live resource assignments.',definition([['User ID',user.id],['Email',user.email],['Email verified',user.emailVerified],['Account status',user.status],['Registered',inventoryDate(user.createdAt)],['Organization',user.organizationName],['Organization ID',user.organizationId],['Organization status',user.organizationStatus],['Domains',user.domains],['Server',user.serverLabel],['Server address',user.publicIpv4],...(canViewBrevo?([['Brevo account',user.relayAccount],['Brevo inventory ID',user.relayId]] as Array<[string,unknown]>):[]),['Deployment status',user.lifecycleState],['Setup request',user.onboardingState]]));
}

function inventoryField(label:string,name:string,value='',type='text',options:{required?:boolean;readonly?:boolean;disabled?:boolean;placeholder?:string}={}):string {
  return `<label>${escapeHtml(label)}<input name="${escapeHtml(name)}" type="${type}" ${type==='password'?'autocomplete="new-password"':'autocomplete="off"'} ${type==='number'?'min="1" max="100000"':''} ${options.required?'required':''} ${options.readonly?'readonly':''} ${options.disabled?'disabled':''} placeholder="${escapeHtml(options.placeholder??'')}" ${type==='password'?'':`value="${escapeHtml(value)}"`}></label>`;
}
function inventoryDialog(id:string,title:string,subtitle:string,content:string):string {return `<dialog class="inventory-dialog" id="${escapeHtml(id)}" aria-labelledby="${escapeHtml(id)}-title"><div class="dialog-content"><button type="button" class="dialog-close" data-close-dialog aria-label="Close dialog">×</button><p class="eyebrow">Inventory</p><h2 id="${escapeHtml(id)}-title">${escapeHtml(title)}</h2><p class="dialog-intro">${escapeHtml(subtitle)}</p>${content}</div></dialog>`;}
function formError():string {return '<p class="form-error" role="alert" tabindex="-1" hidden></p>';}
function inventorySubmit(label:string):string {return `${formError()}<div class="dialog-buttons"><button type="button" class="secondary-button" data-close-dialog>Cancel</button><button type="submit" class="pill">${label}</button></div>`;}
function addServerDialog():string {
  const attestations=[['osPrepared','Linux, systemd and SSH are ready'],['storagePrepared','The server has enough storage and memory'],['firewallAttested','The required SSH and mail ports are configured'],['cleanHost','There is no unrelated mail data on this server'],['externalBackup','An external backup process is arranged']];
  return inventoryDialog('add-server','Add a server','Register a prepared server. BearPortal will check access over SSH.',`<form method="post" action="/operator/inventory/servers" class="inventory-form">${inventoryHidden()}<div class="form-columns">${inventoryField('Public IPv4 address','publicIpv4','','text',{required:true,placeholder:'203.0.113.10'})}${inventoryField('Operator contact (optional)','operatorContact','','email',{placeholder:'ops@yourcompany.com'})}${inventoryField('Provider reference (optional)','providerReference','','text',{placeholder:'A name or ID for your records'})}</div><details class="inventory-help"><summary>Prepare the SSH connection</summary><p>Install the control-plane public key for <code>bearadmin</code> and allow noninteractive sudo. Keep SSH restricted to the control-plane address. Leave <code>/var/lib/stalwart</code> empty or absent. No host agent is required.</p><p>Use x86-64 Linux with systemd, at least 1 GiB memory and 20 GiB storage. The current allocation profile is <code>e2-micro</code>. Saving does not create infrastructure or open a firewall.</p></details><fieldset class="preparation"><legend>Before you add this server</legend>${attestations.map(([name,label])=>`<label class="check"><input type="checkbox" name="${name}" value="1" required><span>${label}</span></label>`).join('')}</fieldset>${inventorySubmit('Add and check SSH')}</form>`);
}
function addBrevoDialog():string {return inventoryDialog('add-brevo','Add a Brevo account','Store the account once. Customers connect their own domains during setup.',`<form method="post" action="/operator/inventory/brevo" class="inventory-form">${inventoryHidden()}${inventoryField('Brevo login email','loginEmail','','email',{required:true})}<div class="form-columns">${inventoryField('SMTP login','smtpLogin','','text',{required:true})}${inventoryField('Daily allowance','dailyLimit','300','number',{required:true})}</div>${inventoryField('REST API key','apiKey','','password',{required:true})}${inventoryField('SMTP key','smtpKey','','password',{required:true})}<p class="field-help">The API key and SMTP key are different. Both are encrypted and never shown again. The daily allowance is a recorded limit, not a live quota reading.</p><details class="inventory-help"><summary>Where do I find these?</summary><p>In Brevo, open Settings → SMTP & API. Create an API key, copy the SMTP login and generate an SMTP key. You do not enter a customer domain here.</p></details>${inventorySubmit('Add Brevo account')}</form>`);}
function sshFailureMessage(code:string):string {
  const messages:Record<string,string>={
    "server.host_key_mismatch":"The SSH host key differs from the saved key. Verify the server fingerprint before updating known_hosts.",
    "server.ssh_auth_failed":"SSH login failed. Check the BearPortal public key in bearadmin’s authorized_keys.",
    "server.sudo_failed":"SSH connected, but noninteractive sudo failed for bearadmin.",
    "server.unreachable":"The SSH connection failed. Check the server address, SSH service and firewall.",
  };
  return messages[code]??`Readiness check failed: ${code}`;
}

function serverInventoryDialog(row:OperatorServerRow,editable:boolean):string {
  const removed=row.state==='retired';const protectedServer=Boolean(row.ownerId||row.tainted||row.recoveryReserved||row.state==='assigned'||row.state==='reserved');
  const failure=row.readinessFailures?.length?`<p class="notice error" role="alert">SSH check failed. ${row.readinessFailures.map(code=>`${escapeHtml(sshFailureMessage(code))} <code>${escapeHtml(code)}</code>`).join("<br>")}</p>`:"";
  const metadata=`${failure}<details class="inventory-help"><summary>Connection, readiness & history</summary>${definition([['Inventory ID',row.id],['Status',row.state],['Profile',row.profileCode],['Assigned to',row.ownerName??row.ownerId??'Unassigned'],['Last successful SSH check',inventoryDate(row.validatedAt)],['Readiness',row.readiness],['Host fingerprint',row.fingerprint],['Tenant data recorded',row.tainted===true],['Hosting estimate',row.hostingEstimate??'Not recorded']])}<p>Changes here do not resize or delete a cloud machine. Backup information is operator-reported.</p></details>`;
  if(!editable||removed)return inventoryDialog(`server-${row.id}`,row.label,removed?'This server was removed from active inventory. Its history is retained.':'Server resource details.',definition([['Public IPv4',row.publicIpv4],['Contact',row.operatorContact],['Provider reference',row.providerReference]])+metadata);
  const fields=`<form method="post" action="/operator/inventory/servers/${escapeHtml(row.id)}/edit" class="inventory-form">${inventoryHidden(row.version)}${inventoryField('Server name','label',row.label,'text',{required:true})}${inventoryField('Public IPv4 address','publicIpv4',row.publicIpv4??'','text',{required:true,readonly:protectedServer})}${protectedServer?'<p class="field-help">This server is assigned, reserved or contains tenant data. Its address is read-only here; moving an active deployment requires the reviewed IP-change workflow.</p>':'<p class="field-help">Changing the address resets readiness. Run a new SSH check before assignment.</p>'}<div class="form-columns">${inventoryField('Operator contact (optional)','operatorContact',row.operatorContact??'','email')}${inventoryField('Provider reference','providerReference',row.providerReference??'')}</div>${inventorySubmit('Save changes')}</form>`;
  const validate=!protectedServer&&(row.state==='available'||row.state==='pending_validation')?`<form method="post" action="/operator/inventory/servers/${escapeHtml(row.id)}/validate" class="inventory-form inline-action">${inventoryHidden(row.version)}<div><strong>Check the connection</strong><p>Run the fixed SSH readiness probe again. A passing check may assign the server to a waiting customer.</p></div>${formError()}<button class="secondary-button" type="submit">Check SSH access</button></form>`:'';
  const remove=protectedServer?'<div class="resource-protected"><strong>This server is in use.</strong><p>Deletion is blocked while a customer assignment, recovery reservation or tenant data remains.</p></div>':`<details class="inventory-remove"><summary>Remove this server from inventory</summary><p>The cloud machine stays in place. BearPortal retains this record and its history.</p><form method="post" action="/operator/inventory/servers/${escapeHtml(row.id)}/remove" class="inventory-form">${inventoryHidden(row.version)}<label class="check"><input type="checkbox" name="confirm" value="1" required><span>Remove ${escapeHtml(row.label)} from inventory.</span></label>${formError()}<button type="submit" class="danger-button">Delete from inventory</button></form></details>`;
  return inventoryDialog(`server-${row.id}`,row.label,`${row.publicIpv4??'No address'} · ${row.ownerName??(row.ownerId?'Assigned':'Unassigned')}`,fields+validate+metadata+remove);
}
function brevoInventoryDialog(row:NonNullable<OperatorPortalView['relays']>[number],editable:boolean):string {
  const removed=Boolean(row.archivedAt);const protectedAccount=row.assigned||row.state==='assigned';
  const metadata=`<details class="inventory-help"><summary>Resource details</summary>${definition([['Inventory ID',row.id],['Account email',row.account],['SMTP login',row.smtpLogin],['Assigned to',row.ownerName??(row.assigned?'Assigned':'Unassigned')],['State',row.state],['Removed at',row.archivedAt??'Not removed']])}<p>API and SMTP keys are write-only. Stored settings do not automatically update a running mail server.</p></details>`;
  if(!editable)return inventoryDialog(`brevo-${row.id}`,row.label,'Brevo resource details. Credentials are never displayed.',metadata);
  if(removed)return inventoryDialog(`brevo-${row.id}`,row.label,'Removed from active inventory. The provider account and encrypted credentials are retained.',metadata+`<form method="post" action="/operator/inventory/brevo/${escapeHtml(row.id)}/restore" class="inventory-form">${inventoryHidden(row.version)}${formError()}<button class="pill" type="submit">Restore to inventory</button></form>`);
  const fields=`<form method="post" action="/operator/inventory/brevo/${escapeHtml(row.id)}/edit" class="inventory-form">${inventoryHidden(row.version)}${inventoryField('Account label','label',row.label,'text',{required:true})}${inventoryField('Brevo login email','loginEmail',row.account,'email',{required:true,disabled:protectedAccount})}<div class="form-columns">${inventoryField('SMTP login','smtpLogin',row.smtpLogin,'text',{required:true,disabled:protectedAccount})}${inventoryField('Recorded daily allowance','dailyLimit',String(row.dailyLimit),'number',{required:true})}</div>${protectedAccount?'<p class="field-help">Assigned accounts keep their connection settings. You can edit the label and recorded allowance here; credential changes require a maintenance workflow.</p>':`${inventoryField('Replace API key (optional)','apiKey','','password',{placeholder:'Leave blank to keep the existing key'})}${inventoryField('Replace SMTP key (optional)','smtpKey','','password',{placeholder:'Leave blank to keep the existing key'})}<label>Availability<select name="paused"><option value="0" ${row.state!=='disabled'?'selected':''}>Accept new setups</option><option value="1" ${row.state==='disabled'?'selected':''}>Paused — do not assign</option></select></label><p class="field-help">Blank key fields keep the saved credentials. Domain and SMTP verification happen during setup.</p>`}${inventorySubmit('Save changes')}</form>`;
  const remove=protectedAccount?'<div class="resource-protected"><strong>This account is assigned.</strong><p>Deletion is blocked while it belongs to a customer.</p></div>':`<details class="inventory-remove"><summary>Remove this account from inventory</summary><p>The Brevo account is not deleted. Its record and encrypted credentials are retained for history and restoration.</p><form method="post" action="/operator/inventory/brevo/${escapeHtml(row.id)}/remove" class="inventory-form">${inventoryHidden(row.version)}<label class="check"><input type="checkbox" name="confirm" value="1" required><span>Remove ${escapeHtml(row.label)} from inventory.</span></label>${formError()}<button type="submit" class="danger-button">Delete from inventory</button></form></details>`;
  return inventoryDialog(`brevo-${row.id}`,row.label,row.account,fields+metadata+remove);
}
export function renderInventoryMessage(message:string,error=false):string {return shell(error?'Check your changes':'Inventory updated','<a href="/operator">Back to inventory</a>',`<section class="setup-card standalone"><p role="${error?'alert':'status'}">${escapeHtml(message)}</p><a class="pill" href="/operator">Back to inventory</a></section>`,"app operator");}

const INVENTORY_SCRIPT = `<script>
(function(){
  document.querySelectorAll('[data-open-dialog]').forEach(function(button){button.addEventListener('click',function(){var dialog=document.getElementById(button.dataset.openDialog);if(dialog)dialog.showModal()})});
  document.querySelectorAll('[data-close-dialog]').forEach(function(button){button.addEventListener('click',function(){button.closest('dialog').close()})});
  document.querySelectorAll('[data-resource-panel]').forEach(function(panel){
    var search=panel.querySelector('[data-resource-search]'),filter=panel.querySelector('[data-resource-filter]');
    function update(){var term=search.value.toLowerCase().trim(),state=filter.value,count=0;panel.querySelectorAll('[data-resource-row]').forEach(function(row){var removed=row.dataset.removed==='true';row.hidden=!(state==='removed'?removed:!removed&&(!state||row.dataset.state===state))||!row.dataset.search.includes(term);if(!row.hidden)count++});var empty=panel.querySelector('[data-empty-state]');empty.hidden=count>0;empty.querySelector('h3').textContent=term||state?'No matches.':panel.hasAttribute('data-user-panel')?'No users yet.':'No resources here yet.';empty.querySelector('p').textContent=term||state?'Try another search or status filter.':panel.hasAttribute('data-user-panel')?'Registered users will appear here.':'Add a prepared resource to support the next customer.';panel.querySelector('[data-resource-count]').textContent=count+' resource'+(count===1?'':'s')+' shown'}
    search.addEventListener('input',update);filter.addEventListener('change',update);update();
  });
  ${INVENTORY_FORM_SCRIPT}
})();
</script>`;
