import assert from 'node:assert/strict';
import { test } from 'node:test';
import { setupErrorMessage, setupFailureCode } from '../apps/api/src/setup-errors.ts';

test('setup failures retain safe provider and database causes without exposing raw responses', () => {
  assert.equal(setupFailureCode(new Error('The DNS zone was not found.')), 'DNS_ZONE_NOT_FOUND');
  assert.equal(setupFailureCode(new Error('The DNS provider rejected the credential.')), 'DNS_CREDENTIAL_REJECTED');
  assert.equal(setupFailureCode({code:'ENOTFOUND'}), 'DOMAIN_DNS_NOT_FOUND');
  assert.equal(setupFailureCode({code:'23505',constraint:'mailboxes_address_key'}), 'MAILBOX_ADDRESS_CONFLICT');
  assert.equal(setupFailureCode({code:'23505'}), 'DATABASE_23505');
  assert.match(setupErrorMessage('DATABASE_25P02'), /SQLSTATE 25P02/);
  const secret='private-provider-response-canary';
  const safe=setupFailureCode(new Error(secret));
  assert.equal(safe,'PROVIDER_RETRY');
  assert.equal(setupErrorMessage(safe).includes(secret),false);
  assert.match(setupErrorMessage('SETUP_REVIEW_REQUIRED'), /no more specific cause was recorded/);
});
