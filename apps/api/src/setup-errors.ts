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
    DOMAIN_ALREADY_IN_USE: 'This domain is in use by another account. Ask an operator to review ownership.',
    DOMAIN_DNS_NOT_FOUND: 'No nameservers found. Check the domain spelling and registration.',
    MAILBOX_ADDRESS_CONFLICT: 'This domain’s mailbox address is already in use. Ask an operator to review the assignment.',
    DNS_PROPAGATION: 'Waiting for DNS verification. We’ll check again automatically.',
    DNS_CREDENTIAL_REJECTED: 'DNS credential rejected. Check the token and its DNS permissions.',
    DNS_ZONE_NOT_FOUND: 'Domain not found in this DNS account. Check the spelling and account access.',
    DNS_PROVIDER_UNREACHABLE: 'DNS provider unavailable. We’ll retry automatically.',
    DNS_RECORD_REJECTED: 'DNS update rejected. We’ll retry automatically.',
    DNS_CREDENTIAL_REQUIRED: 'Reconnect your DNS provider.',
    DNS_PROVIDER_CHANGED: 'DNS provider changed. Reconnect your domain.',
    PROVIDER_RETRY: 'Setup could not continue. We’ll retry automatically.',
    SETUP_REVIEW_REQUIRED: 'Setup is paused for operator review.',
    OUTCOME_UNKNOWN: 'Installation was interrupted. An operator must check the server before retrying.',
    EMAIL_UNVERIFIED: 'The BearPortal account email is not verified.',
    ACCOUNT_REVIEW_REQUIRED: 'An operator must review this account before setup can continue.',
    RELAY_REVIEW_REQUIRED: 'Your mail-service account is disabled. Operator review is needed.',
    BREVO_AUTH_UNAVAILABLE: 'Domain authentication is unavailable. Contact support.',
    INSTALLER_UNAVAILABLE: 'The installation service is unavailable. We’ll retry automatically.',
    INSTALLER_STORAGE_UNAVAILABLE: 'Installation storage is unavailable. We’ll retry automatically.',
    TLS_PENDING: 'Bearmail is installed. Checking HTTPS certificates.',
  };
  if (/^DATABASE_[0-9A-Z]{5}$/.test(code)) return `A database operation failed (SQLSTATE ${code.slice(9)}). Setup is paused for operator review.`;
  return messages[code] ?? 'Setup needs operator review. See the error code below.';
}
