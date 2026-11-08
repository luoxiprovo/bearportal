import assert from "node:assert/strict";
import { test } from "node:test";
import { runInNewContext } from "node:vm";
import { CUSTOMER_SESSION_SCRIPT } from "../apps/api/src/customer-session-script.ts";

async function submitCase(configured: boolean, hasRefreshSession: boolean, status = 200) {
  let listener: (event: any) => Promise<void>;
  let submits = 0;
  const calls: {url: string; options: any}[] = [];
  const errors: any[] = [];
  const button = {};
  const form = {
    addEventListener: (_: string, fn: typeof listener) => { listener = fn; },
    querySelector: () => null,
    setAttribute() {}, removeAttribute() {},
    appendChild: (element: any) => errors.push(element),
    requestSubmit: (submitter: unknown) => { assert.equal(submitter, button); submits++; void listener({ submitter: button, preventDefault: () => assert.fail("renewed form was blocked") }); },
  };
  const document = {
    querySelectorAll: () => [form],
    createElement: () => ({ dataset: {}, setAttribute() {}, appendChild() {} }),
  };
  runInNewContext(CUSTOMER_SESSION_SCRIPT, { document, fetch: async (url: string, options: any) => {
    calls.push({url, options});
    return url === '/auth/options'
      ? {ok: true, json: async () => ({configured, hasRefreshSession, csrf: 'fresh-csrf'})}
      : {ok: status === 200, status};
  }});
  await listener!({ submitter: button, preventDefault() {} });
  return {submits, calls, errors};
}

test("customer forms refresh before sending once and retain the form on expired or unavailable sessions", async () => {
  const ok = await submitCase(true, true);
  assert.equal(ok.submits, 1);
  assert.deepEqual(ok.calls.map(call => call.url), ['/auth/options', '/auth/refresh']);
  assert.equal(ok.calls[1].options.headers['x-bearportal-auth-csrf'], 'fresh-csrf');
  assert.equal(ok.calls[1].options.body, '{}'); // No form fields or provider credentials enter authentication requests.
  for (const status of [401, 503]) {
    const failed = await submitCase(true, true, status);
    assert.equal(failed.submits, 0);
    assert.equal(failed.errors.length, 1);
  }
  const missing = await submitCase(true, false);
  assert.equal(missing.submits, 0);
  assert.equal(missing.calls.length, 1);
  assert.match(missing.errors[0].textContent, /sign-in has expired/);
  const trial = await submitCase(false, false);
  assert.equal(trial.submits, 1);
  assert.equal(trial.calls.length, 1);
});
