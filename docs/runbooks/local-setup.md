# Local setup

Follow [../try-it.md](../try-it.md) for development startup. Configuration names are in [../../.env.example](../../.env.example); runtime validation is in [../../apps/api/src/config.ts](../../apps/api/src/config.ts).

`main.ts` loads the application database URL, encryption key, JWT public key/issuer/audience, secret directory, bind address and port. The migration command separately uses `MIGRATION_DATABASE_URL`. Development registration also needs the generated private signing key and test-issuer flag. Production rejects the test issuer.

Normal startup provides live SSH probing and the live installer runner, plus the Brevo account-form and DNS publishing functions. Development startup is therefore capable of real external changes. Fake DNS, relay, Brevo and installer adapters are injected by automated tests rather than selected automatically by development mode.

Generic zone proof, relay checking and DNS observation remain unavailable by default. Provisioning's `BrevoClient` is still a throwing placeholder, distinct from the working Brevo form functions. [../../SPEC.md](../../SPEC.md) lists these boundaries.

`BEARPORTAL_SCHEDULER_TOKEN` enables the internal routes that check it. Missing/empty configuration leaves those routes at 503; setting the token does not install a general scheduler service. The onboarding queue runs independently inside the API every 30 seconds; its explicit internal run endpoint requires the token.

Use `pnpm typecheck` and `pnpm test`. The test launcher uses isolated databases. Do not source the ordinary trial database URLs for tests, and do not reset application data after tests. `trial:reset` explicitly deletes operational rows and should only be used for an intentional development reset.

The control-plane host and the mail server have different roles. Install customer Bearmail on the assigned mail server, not on the API host.
