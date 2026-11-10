import assert from "node:assert/strict";
import { test } from "node:test";
import { runInNewContext } from "node:vm";
import { INVENTORY_FORM_SCRIPT } from "../apps/api/src/inventory-form-script.ts";

function browserForm(resource: "servers" | "brevo", alreadyAdded: boolean, status = 200) {
  const destination = `/operator?tab=${resource}&notice=${resource === "servers" ? "server" : "brevo"}-added#resources`;
  const location = new URL(alreadyAdded ? destination : `/operator?tab=${resource}`, "https://portal.example");
  let listener!: (event: any) => Promise<void>;
  let complete!: () => void;
  const ready = new Promise<void>(resolve => { complete = resolve; });
  const calls: string[] = [];
  const button = { disabled: false, textContent: "Add" };
  const error = { hidden: true, textContent: "", focus() { calls.push("focus error"); } };
  const form = {
    action: `https://portal.example/operator/inventory/${resource}`,
    addEventListener(_name: string, fn: typeof listener) { listener = fn; },
    querySelector(selector: string) { return selector === ".form-error" ? error : button; },
    setAttribute() {}, removeAttribute() {},
    closest() { return { close() { calls.push("close"); } }; },
  };
  runInNewContext(INVENTORY_FORM_SCRIPT, {
    URL, URLSearchParams, FormData: class {},
    document: { querySelector: () => null, querySelectorAll: () => [form] },
    location: {
      href: location.href, origin: location.origin, pathname: location.pathname, search: location.search,
      reload() { calls.push("reload"); }, assign(url: string) { calls.push(url); },
    },
    fetch: async () => { calls.push("request"); await ready; return { ok: status === 200, json: async () => status === 200 ? { redirect: destination } : { error: { message: "Duplicate address" } } }; },
  });
  return { submit: () => listener({ submitter: button, preventDefault() {} }), complete, calls, button, error, destination };
}

for (const resource of ["servers", "brevo"] as const) {
  test(`${resource}: consecutive adds close the dialog and refresh the current inventory URL`, async () => {
    const browser = browserForm(resource, true);
    const first = browser.submit();
    assert.equal(browser.button.disabled, true);
    assert.match(browser.button.textContent, /Checking SSH|Saving/);
    await browser.submit();
    assert.deepEqual(browser.calls, ["request"]);
    browser.complete(); await first;
    assert.deepEqual(browser.calls, ["request", "close", "reload"]);
    assert.equal(browser.button.disabled, true);
  });
  test(`${resource}: first add closes the dialog and navigates to its success notice`, async () => {
    const browser = browserForm(resource, false);
    browser.complete(); await browser.submit();
    assert.deepEqual(browser.calls, ["request", "close", `https://portal.example${browser.destination}`]);
  });
}
test("failed additions keep the dialog open, explain the failure and allow a retry", async () => {
  const browser = browserForm("servers", true, 409);
  browser.complete(); await browser.submit();
  assert.deepEqual(browser.calls, ["request", "focus error"]);
  assert.equal(browser.error.hidden, false);
  assert.equal(browser.error.textContent, "Duplicate address");
  assert.equal(browser.button.disabled, false);
  assert.equal(browser.button.textContent, "Add");
  await browser.submit();
  assert.equal(browser.calls.filter(call => call === "request").length, 2);
});
