import { existsSync, readFileSync } from "node:fs";
export function migrationPaused(file?: string): boolean {
  return Boolean(file && existsSync(file));
}
export function assertMigrationStartup(file: string): void {
  if (!existsSync(file)) return;
  let target = false;
  try {
    target = JSON.parse(readFileSync(file, "utf8")).role === "target";
  } catch {}
  if (!target)
    throw new Error(
      "This BearPortal server is fenced after migration export. Use the documented migration rollback procedure before restarting it.",
    );
}
export const MIGRATION_PAGE =
  '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="refresh" content="30"><title>BearPortal is moving</title><style>body{font:17px system-ui;margin:15vh auto;padding:24px;max-width:560px;color:#1d1d1f}p{line-height:1.6;color:#555}a{color:#0066cc}</style></head><body><h1>BearPortal is moving.</h1><p>Your progress is saved. Please try again shortly. This page will refresh automatically.</p><p>Your installed mail service continues running on its own server.</p></body></html>';
