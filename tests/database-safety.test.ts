import assert from "node:assert/strict";
import { test } from "node:test";
import { integrationDatabases } from "./helpers/database.ts";

function urls(database = "bearportal_test_safety"): NodeJS.ProcessEnv {
  return {
    DATABASE_URL: `postgres://app:password@127.0.0.1:5432/${database}`,
    MIGRATION_DATABASE_URL: `postgres://owner:password@127.0.0.1:5432/${database}`,
    BEARPORTAL_SUPER_DATABASE_URL: `postgres://admin:password@127.0.0.1:5432/${database}`,
  };
}
test("destructive integration tests reject missing, working, and mismatched database targets", () => {
  assert.throws(() => integrationDatabases({}), /require DATABASE_URL/);
  assert.throws(() => integrationDatabases({ DATABASE_URL: urls().DATABASE_URL }), /require MIGRATION_DATABASE_URL/);
  assert.throws(() => integrationDatabases(urls("bearportal")), /bearportal_test_/);
  for (const key of ["DATABASE_URL", "MIGRATION_DATABASE_URL", "BEARPORTAL_SUPER_DATABASE_URL"]) {
    assert.throws(() => integrationDatabases({ ...urls(), [key]: urls("bearportal")[key] }), /bearportal_test_/);
    assert.throws(() => integrationDatabases({ ...urls(), [key]: urls("bearportal_test_other")[key] }), /same host, port, and database/);
    assert.throws(() => integrationDatabases({ ...urls(), [key]: urls()[key]!.replace("127.0.0.1", "other-host") }), /same host, port, and database/);
  }
  assert.throws(() => integrationDatabases({ ...urls(), BEARPORTAL_SUPER_DATABASE_URL: urls().BEARPORTAL_SUPER_DATABASE_URL + "?host=another-host" }), /unsupported connection parameter/);
  assert.doesNotThrow(() => integrationDatabases(urls()));
});
