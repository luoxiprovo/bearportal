import assert from "node:assert/strict";
import { test } from "node:test";
import { runInNewContext } from "node:vm";
import { CUSTOMER_SESSION_SCRIPT } from "../apps/api/src/customer-session-script.ts";

async function submitCase(
  configured: boolean,
  hasRefreshSession: boolean,
  status = 200,
) {
  let listener: (event: any) => Promise<void>;
  let submits = 0;
  const calls: { url: string; options: any }[] = [];
  const errors: any[] = [];
  const button = {};
  const form = {
    addEventListener: (_: string, fn: typeof listener) => {
      listener = fn;
    },
    querySelector: () => null,
    setAttribute() {},
    removeAttribute() {},
    appendChild: (element: any) => errors.push(element),
    requestSubmit: (submitter: unknown) => {
      assert.equal(submitter, button);
      submits++;
      void listener({
        submitter: button,
        preventDefault: () => assert.fail("renewed form was blocked"),
      });
    },
  };
  const document = {
    querySelectorAll: () => [form],
    createElement: () => ({ dataset: {}, setAttribute() {}, appendChild() {} }),
  };
  runInNewContext(CUSTOMER_SESSION_SCRIPT, {
    document,
    fetch: async (url: string, options: any) => {
      calls.push({ url, options });
      return url === "/auth/options"
        ? {
            ok: true,
            json: async () => ({
              configured,
              hasRefreshSession,
              csrf: "fresh-csrf",
            }),
          }
        : { ok: status === 200, status };
    },
  });
  await listener!({ submitter: button, preventDefault() {} });
  return { submits, calls, errors };
}

test("customer forms refresh before sending once and retain the form on expired or unavailable sessions", async () => {
  const ok = await submitCase(true, true);
  assert.equal(ok.submits, 1);
  assert.deepEqual(
    ok.calls.map((call) => call.url),
    ["/auth/options", "/auth/refresh"],
  );
  assert.equal(
    ok.calls[1].options.headers["x-bearportal-auth-csrf"],
    "fresh-csrf",
  );
  assert.equal(ok.calls[1].options.body, "{}"); // No form fields or provider credentials enter authentication requests.
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

test("embedded checkout refreshes auth, mounts the form once, reports confirmation errors and returns through billing verification", async () => {
  let listener!: (event: any) => Promise<void>;
  let confirmListener!: (event: any) => Promise<void>;
  const calls: string[] = [],
    errors: any[] = [];
  const button = { disabled: false, hidden: false };
  const form = {
    action: "https://portal.example/portal/billing/checkout",
    dataset: {
      stripeCheckout: "",
      stripePublishableKey: "pk_test_fixture",
    } as Record<string, string>,
    addEventListener: (_: string, fn: typeof listener) => {
      listener = fn;
    },
    querySelector: () => null,
    setAttribute() {},
    removeAttribute() {},
    appendChild: (el: any) => errors.push(el),
    requestSubmit: () =>
      assert.fail(
        "embedded checkout must fetch JSON, not navigate to its endpoint",
      ),
  };
  let appearance: any,
    decline = true;
  const event = { kind: "Stripe form confirm event" };
  runInNewContext(CUSTOMER_SESSION_SCRIPT, {
    document: {
      querySelectorAll: () => [form],
      createElement: () => ({
        dataset: {},
        setAttribute() {},
        appendChild() {},
      }),
    },
    location: {
      origin: "https://portal.example",
      assign: (url: string) => calls.push(url),
    },
    encodeURIComponent,
    URLSearchParams,
    FormData: class {},
    fetch: async (url: string, options: any) => {
      calls.push(url);
      if (url === "/auth/options")
        return {
          ok: true,
          json: async () => ({
            configured: true,
            hasRefreshSession: true,
            csrf: "auth-csrf",
          }),
        };
      if (url === "/auth/refresh") return { ok: true };
      assert.equal(options.method, "POST");
      assert.equal(options.headers.accept, "application/json");
      return {
        ok: true,
        json: async () => ({ client_secret: "client-secret-fixture" }),
      };
    },
    Stripe: (key: string) => {
      assert.equal(key, "pk_test_fixture");
      return {
        initCheckoutFormSdk: ({ clientSecret, appearance: options }: any) => {
          appearance = options;
          return {
            createForm: ({ layout }: any) => {
              assert.equal(layout, "expanded");
              return {
                mount: (selector: string) => {
                  assert.equal(selector, "#checkout-form");
                  calls.push("mount");
                },
                unmount: () =>
                  assert.fail("valid checkout must remain mounted"),
                on: (name: string, fn: typeof confirmListener) => {
                  assert.equal(name, "confirm");
                  confirmListener = fn;
                },
              };
            },
            loadActions: async () => {
              assert.equal(await clientSecret, "client-secret-fixture");
              return {
                type: "success",
                actions: {
                  getSession: () => ({ id: "cs_test_fixture" }),
                  confirm: async (options: any) => {
                    assert.equal(options.formConfirmEvent, event);
                    assert.equal(options.redirect, "if_required");
                    assert.equal(
                      options.returnUrl,
                      "https://portal.example/portal/billing/return?session_id=cs_test_fixture",
                    );
                    return decline
                      ? {
                          type: "error",
                          error: { message: "Your card was declined." },
                        }
                      : { type: "success", session: { id: "cs_test_fixture" } };
                  },
                },
              };
            },
          };
        },
      };
    },
  });
  await listener({ submitter: button, preventDefault() {} });
  assert.deepEqual(calls.slice(0, 3), [
    "/auth/options",
    "/auth/refresh",
    form.action,
  ]);
  assert.equal(button.hidden, true);
  assert.equal(appearance.theme, "stripe");
  assert.equal(appearance.variables.colorPrimary, "#0570de");
  assert.equal(appearance.variables.fontSizeBase, "16px");
  assert.equal(appearance.inputs, "spaced");
  await confirmListener(event);
  assert.equal(errors[0].textContent, "Your card was declined.");
  decline = false;
  await confirmListener(event);
  assert.equal(
    calls.at(-1),
    "https://portal.example/portal/billing/return?session_id=cs_test_fixture",
  );
  await listener({ submitter: button, preventDefault() {} });
  assert.equal(calls.filter((call) => call === form.action).length, 1);
  assert.equal(calls.filter((call) => call === "mount").length, 1);
});

test("checkout errors do not suggest signing in again unless the server returns 401", async () => {
  for (const status of [503, 401]) {
    let submit!: (event: any) => Promise<void>;
    const errors: any[] = [];
    const form = {
      action: "https://portal.example/portal/billing/checkout",
      dataset: { stripeCheckout: "", stripePublishableKey: "pk_test_fixture" },
      addEventListener: (_name: string, fn: typeof submit) => {
        submit = fn;
      },
      querySelector: () => null,
      setAttribute() {},
      removeAttribute() {},
      appendChild: (el: any) => errors.push(el),
    };
    runInNewContext(CUSTOMER_SESSION_SCRIPT, {
      document: {
        querySelectorAll: () => [form],
        createElement: (tag: string) => ({
          tag,
          dataset: {},
          children: [] as any[],
          setAttribute() {},
          appendChild(child: any) {
            this.children.push(child);
          },
        }),
      },
      URLSearchParams,
      FormData: class {},
      Stripe: () => ({
        initCheckoutFormSdk: ({ clientSecret }: any) => ({
          createForm: () => ({ mount() {}, unmount() {} }),
          loadActions: async () => {
            await clientSecret;
            return { type: "error" };
          },
        }),
      }),
      fetch: async (url: string) =>
        url === "/auth/options"
          ? { ok: true, json: async () => ({ configured: false }) }
          : {
              ok: false,
              status,
              json: async () => ({
                error: {
                  message:
                    status === 401
                      ? "Please sign in again."
                      : "Billing setup needs attention. Please contact the operator.",
                },
              }),
            },
    });
    await submit({ submitter: { disabled: false }, preventDefault() {} });
    assert.equal(errors.length, 1);
    assert.equal(errors[0].children.length, status === 401 ? 1 : 0);
    if (status === 503)
      assert.match(errors[0].textContent, /Billing setup needs attention/);
  }
});
