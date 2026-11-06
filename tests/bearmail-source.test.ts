import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import {
  BearmailSourceError,
  resolveLatestBearmailInstall,
  writeBearmailInstall,
  type BearmailSourceTransport,
} from "../packages/servers/src/bearmail-source.ts";

const COMMIT = "262c68fef70b32c7d7ea16cae738fc19d3b32df3";
const SCRIPT = "#!/usr/bin/env python3\n# bearmail-install fixture\n";

function transport(status = 200, script = SCRIPT, sha: unknown = COMMIT): BearmailSourceTransport {
  return async (url) => {
    if (url === "https://api.github.com/repos/luoxiprovo/bearmail/commits/main") {
      return { status, body: JSON.stringify({ sha }) };
    }
    assert.equal(url, `https://raw.githubusercontent.com/luoxiprovo/bearmail/${COMMIT}/bearmail-install`);
    return { status, body: script };
  };
}

describe("latest bearmail-install", () => {
  it("reads the installer from the current GitHub main commit and does not execute it", async () => {
    const resolved = await resolveLatestBearmailInstall(transport());
    assert.equal(resolved.repository, "luoxiprovo/bearmail");
    assert.equal(resolved.ref, "refs/heads/main");
    assert.equal(resolved.commit, COMMIT);
    assert.equal(resolved.script, SCRIPT);
    const directory = mkdtempSync(join(tmpdir(), "bearportal-installer-"));
    try {
      const path = writeBearmailInstall(directory, resolved.script);
      assert.equal(path, join(directory, "bearmail-install"));
      assert.equal(readFileSync(path, "utf8"), SCRIPT);
      assert.equal(statSync(path).mode & 0o777, 0o700);
      chmodSync(path, 0o644);
      writeBearmailInstall(directory, resolved.script);
      assert.equal(statSync(path).mode & 0o777, 0o700);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it("rejects a missing commit, a bad file, and a directory that is not absolute", async () => {
    await assert.rejects(resolveLatestBearmailInstall(transport(404)), BearmailSourceError);
    await assert.rejects(resolveLatestBearmailInstall(transport(200, SCRIPT, "main")), BearmailSourceError);
    await assert.rejects(resolveLatestBearmailInstall(transport(200, "<html>bearmail-install</html>")), BearmailSourceError);
    assert.throws(() => writeBearmailInstall("/tmp", "not an installer"), BearmailSourceError);
    assert.throws(() => writeBearmailInstall("relative", SCRIPT), BearmailSourceError);
  });
});
