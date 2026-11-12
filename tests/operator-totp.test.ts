import assert from "node:assert/strict";
import { test } from "node:test";
import {
  newAuthenticator,
  verifyAuthenticator,
  recoveryCodes,
  recoveryHash,
} from "../apps/api/src/operator-totp.ts";
test("authenticator matches RFC 6238 SHA1 vectors and rejects replay and malformed input", () => {
  const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
  for (const [seconds, expected] of [
    [59, "287082"],
    [1111111109, "081804"],
    [1111111111, "050471"],
    [1234567890, "005924"],
    [2000000000, "279037"],
    [20000000000, "353130"],
  ] as const) {
    const now = seconds * 1000;
    assert.equal(
      newAuthenticator("", secret).generate({ timestamp: now }),
      expected,
    );
    const counter = verifyAuthenticator(secret, expected, -1, now);
    assert.equal(counter, Math.floor(seconds / 30));
    assert.equal(verifyAuthenticator(secret, expected, counter!, now), null);
  }
  assert.equal(verifyAuthenticator(secret, "abcdef", -1), null);
  const codes = recoveryCodes();
  assert.equal(new Set(codes).size, 10);
  assert.equal(
    recoveryHash(codes[0]!),
    recoveryHash(codes[0]!.replaceAll("-", "").toUpperCase()),
  );
});
