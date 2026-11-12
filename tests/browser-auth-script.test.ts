import assert from "node:assert/strict";
import { test } from "node:test";
import { runInNewContext } from "node:vm";
import { BROWSER_AUTH_SCRIPT } from "../apps/api/src/browser-auth-script.ts";

test("sign out obtains a fresh CSRF token on every attempt and redirects after logout", async () => {
  let click!: () => Promise<void>;
  let token = "page-open-token";
  let fail = true;
  let redirect = "";
  const calls: string[] = [];
  const message = {
    hidden: true,
    textContent: "",
    className: "",
    classList: { toggle() {} },
    setAttribute() {},
  };
  const logout = {
    hidden: true,
    disabled: false,
    textContent: "Sign out",
    parentElement: { appendChild() {} },
    addEventListener: (_event: string, handler: typeof click) => { click = handler; },
  };
  await runInNewContext(BROWSER_AUTH_SCRIPT, {
    document: {
      querySelector: (selector: string) => selector === "[data-auth-logout]" ? logout : null,
      createElement: () => message,
    },
    location: { assign: (url: string) => { redirect = url; } },
    fetch: async (url: string, options: any) => {
      calls.push(url);
      if (url === "/auth/options") {
        token = "fresh-" + calls.length;
        return { ok: true, json: async () => ({ configured: true, csrf: token }) };
      }
      assert.equal(url, "/auth/logout");
      assert.equal(options.headers["x-bearportal-auth-csrf"], token);
      assert.equal(logout.disabled, true);
      assert.equal(logout.textContent, "Signing out…");
      return { ok: !fail, json: async () => fail ? { error: { message: "Please try again." } } : { redirect: "/login" } };
    },
  });
  assert.equal(logout.hidden, false);
  // Another tab or a setup form may rotate the cookie before the click.
  token = "another-tab-token";
  await click();
  assert.equal(message.hidden, false);
  assert.equal(message.textContent, "Please try again.");
  assert.equal(logout.disabled, false);
  assert.equal(logout.textContent, "Sign out");
  assert.equal(redirect, "");
  fail = false;
  token = "expired-token";
  await click();
  assert.equal(redirect, "/login");
  assert.deepEqual(calls, ["/auth/options", "/auth/logout", "/auth/options", "/auth/logout"]);
});
