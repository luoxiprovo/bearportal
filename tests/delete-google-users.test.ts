import { test } from "node:test";
import assert from "node:assert/strict";
import { createAdminIdentity, type IdentityUser } from "../scripts/reset-google-test-data.ts";
import { deleteNonOperators, isProtected } from "../scripts/delete-google-users.ts";
const user = (uid: string, email = uid + "@example.org"): IdentityUser => ({ uid, email, providers: [] });
const protection = () => ({ project: "test-project", protectedEmails: new Set(["operator@example.org"]), protectedUids: new Set(["operator-uid"]) });

test("Google enumeration follows pagination, uses quota project, and discards credential fields", async () => {
  let calls = 0;
  const api = createAdminIdentity(async (input, init) => {
    const url = new URL(String(input));
    assert.equal(init?.method, "GET");
    assert.equal((init?.headers as Record<string, string>)["x-goog-user-project"], "test-project");
    assert.equal(url.searchParams.get("maxResults"), "1000");
    calls++;
    if (calls === 1) return Response.json({ users: [{ localId: "a", passwordHash: "secret" }], nextPageToken: "next" });
    assert.equal(url.searchParams.get("nextPageToken"), "next");
    return Response.json({ users: [{ localId: "b", email: "B@example.org", refreshToken: "secret" }] });
  }, () => "token");
  const users = await api.list("test-project");
  assert.deepEqual(users, [user("a", ""), user("b", "b@example.org")]);
  assert.equal(JSON.stringify(users).includes("secret"), false);
});

test("deletion preserves operator UID, authorized email, and newly protected identities", async () => {
  const selected = [user("operator-uid", "alias@example.org"), user("other", "operator@example.org"), user("promoted"), user("customer"), user("no-email", ""), user("missing")];
  assert.equal(isProtected(selected[0], protection()), true);
  const removed: string[] = [];
  const results: string[] = [];
  await deleteNonOperators(selected, async () => {
    const current = protection(); current.protectedUids.add("promoted"); return current;
  }, {
    lookupUid: async (_project, uid) => selected.find(u => u.uid === uid && uid !== "missing") ?? null,
    remove: async (_project, uid) => { removed.push(uid); },
  }, (uid, status) => results.push(uid + ":" + status));
  assert.deepEqual(removed, ["customer", "no-email"]);
  assert.ok(results.includes("promoted:protected"));
  assert.ok(results.includes("missing:missing"));
});

test("changed identity and unavailable protection stop deletion", async () => {
  let removed = false;
  await assert.rejects(deleteNonOperators([user("customer")], async () => protection(), {
    lookupUid: async () => user("customer", "changed@example.org"),
    remove: async () => { removed = true; },
  }, () => {}), /changed/);
  await assert.rejects(deleteNonOperators([user("customer")], async () => { throw Error("database unavailable"); }, {
    lookupUid: async () => user("customer"), remove: async () => { removed = true; },
  }, () => {}), /database unavailable/);
  assert.equal(removed, false);
});

test("partial deletion failure preserves recorded progress and stops subsequent users", async () => {
  const removed: string[] = [], recorded: string[] = [];
  await assert.rejects(deleteNonOperators([user("first"), user("second"), user("third")], async () => protection(), {
    lookupUid: async (_project, uid) => user(uid),
    remove: async (_project, uid) => { if (uid === "second") throw Error("denied"); removed.push(uid); },
  }, uid => recorded.push(uid)), /denied/);
  assert.deepEqual(removed, ["first"]);
  assert.deepEqual(recorded, ["first"]);
});
