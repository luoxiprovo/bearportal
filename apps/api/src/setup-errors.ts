/** Only known, credential-free failures may reach customer status. Never persist raw provider responses. */
export function setupFailureCode(error: unknown): string {
  if ((error as { constraint?: unknown } | null)?.constraint === 'mailboxes_address_key') return 'MAILBOX_ADDRESS_CONFLICT';
  const code = (error as { code?: unknown } | null)?.code;
  if (code === 'ENOTFOUND' || code === 'ENODATA') return 'DOMAIN_DNS_NOT_FOUND';
  if (typeof code === 'string' && /^[0-9A-Z]{5}$/.test(code)) return `DATABASE_${code}`;
  const message = error instanceof Error ? error.message : '';
  const known: Record<string, string> = {
    'The DNS provider rejected the credential.': 'DNS_CREDENTIAL_REJECTED',
    'The DNS zone was not found.': 'DNS_ZONE_NOT_FOUND',
    'The DNS provider could not be reached.': 'DNS_PROVIDER_UNREACHABLE',
    'The DNS provider rejected the record update.': 'DNS_RECORD_REJECTED',
    'The DNS credential does not match the detected provider.': 'DNS_PROVIDER_CHANGED',
  };
  return known[message] ?? 'PROVIDER_RETRY';
}

export function setupErrorMessage(code: string): string {
  const messages: Record<string, string> = {
    DOMAIN_ALREADY_IN_USE: 'This domain already has a setup or installation under another account. An operator must review its ownership before setup can continue.',
    DOMAIN_DNS_NOT_FOUND: 'No DNS nameservers were found for the submitted domain. Check the domain spelling and registration; we’ll retry automatically.',
    MAILBOX_ADDRESS_CONFLICT: 'This domain’s mailbox address is already in use by an existing setup. Installation is paused. Use a different domain or ask an operator to review the existing domain assignment.',
    DNS_PROPAGATION: 'Brevo has not confirmed the domain verification records yet. Waiting for DNS; we’ll check again automatically.',
    DNS_CREDENTIAL_REJECTED: 'The domain provider rejected the saved credential. Check its validity and DNS permissions.',
    DNS_ZONE_NOT_FOUND: 'The domain provider could not find this domain in the connected account. Check the domain spelling and account access.',
    DNS_PROVIDER_UNREACHABLE: 'The domain provider could not be reached. We’ll retry automatically.',
    DNS_RECORD_REJECTED: 'The domain provider rejected a DNS record update. We’ll retry; persistent failures need operator review.',
    DNS_CREDENTIAL_REQUIRED: 'No usable domain-provider credential was found. Reconnect your provider.',
    DNS_PROVIDER_CHANGED: 'The domain’s nameservers do not match the saved provider connection. Check the domain spelling and provider.',
    PROVIDER_RETRY: 'A provider or setup preparation request failed. We’ll retry automatically. No more specific cause was recorded.',
    SETUP_REVIEW_REQUIRED: 'The setup worker failed or exhausted its retry limit. Setup is paused for operator review; no more specific cause was recorded.',
    OUTCOME_UNKNOWN: 'Installation was interrupted and its outcome is unknown. An operator must check the server before it can continue.',
    EMAIL_UNVERIFIED: 'The BearPortal account email is not verified.',
    ACCOUNT_REVIEW_REQUIRED: 'The account is not eligible to continue setup. Operator review is required.',
    RELAY_REVIEW_REQUIRED: 'The allocated mail-service account is disabled. Operator review is required.',
    BREVO_AUTH_UNAVAILABLE: 'Brevo domain authentication is unavailable in the installation service.',
    INSTALLER_UNAVAILABLE: 'The installation service is unavailable. We’ll retry automatically.',
    INSTALLER_STORAGE_UNAVAILABLE: 'The installation service cannot access its working storage. We’ll retry automatically.',
    TLS_PENDING: 'Bearmail is installed; HTTPS certificate checks are still pending.',
  };
  if (/^DATABASE_[0-9A-Z]{5}$/.test(code)) return `A database operation failed (SQLSTATE ${code.slice(9)}). Setup is paused for operator review.`;
  return messages[code] ?? 'The backend reported a setup failure. Operator review is required; see the error code below.';
}
