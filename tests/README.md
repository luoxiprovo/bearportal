# Running tests safely

Run `pnpm test`. With no database URL variables set, the launcher creates a uniquely named `bearportal_test_*` database in the local PostgreSQL cluster and removes it afterward. This requires the existing `bearportal` / `bearportal_app` roles and noninteractive `sudo -u postgres` access.

For an externally managed test database, explicitly set all three variables:

- `DATABASE_URL`: application connection
- `MIGRATION_DATABASE_URL`: schema owner connection
- `BEARPORTAL_SUPER_DATABASE_URL`: administrative connection with the privileges needed by fixtures

All three must target the same host, port, and database. The database name must start with `bearportal_test_`. Integration suites truncate their fixture tables. Supply only a disposable test database; never use the working `bearportal` database or source `.data/trial/env` for tests.

The shared database helper validates every administrative connection before executing SQL. Integration suites also validate all three connections before migrations or fixture setup. There is no administrative fallback to the working database.

Unit tests can be run directly, for example:

```sh
pnpm exec tsx --test tests/database-safety.test.ts tests/inventory-unit.test.ts
```

Identity Platform coverage in `browser-auth.test.ts` and `identity-platform.test.ts` uses cryptographically signed test tokens and injected provider adapters in the disposable database. It covers verified registration, Google proof, password/verification/reset/refresh, legacy resource preservation, operator exclusions, CSRF/origin controls and secret redaction. It does not send real verification emails or claim live Google OAuth validation without a configured project.
