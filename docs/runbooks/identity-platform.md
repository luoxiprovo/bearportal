# Google Cloud Identity Platform sign-up and sign-in

BearPortal uses **Google Cloud Identity Platform directly** for email/password accounts, verification email, password reset and Google sign-in. It does not use Firebase Authentication or the Firebase SDK. The browser loads Google's Identity Services button; BearPortal calls Identity Platform's REST APIs and verifies signed ID tokens with Google's rotating public keys. Passwords are sent to Identity Platform and are not stored in the BearPortal database or secret directory.

The server can save the project/API key/client configuration without administrative Cloud access. Its Compute Engine service account received `ACCESS_TOKEN_SCOPE_INSUFFICIENT` when reading administrative Identity Platform settings, so the project owner must configure provider enablement and OAuth origins in Google Cloud Console. A missing configuration does not create a simulated Google/password login. Existing local development sessions and operator login links continue to work.

## Set up the Google Cloud project

1. Sign in to [Google Cloud Console](https://console.cloud.google.com/) with an account that can administer your chosen project. Create or select the project, then open **Identity Platform** and enable the service. Review any service/billing terms in the console yourself.
2. In Identity Platform, enable the **Email/Password** sign-in provider. Require email verification for BearPortal setup; the application also enforces this before creating its user/organization or assigning resources. Configure a provider password policy of at least 12 characters and enable email enumeration protection.
3. Configure an OAuth consent screen in **Google Auth Platform**. Create an OAuth client of type **Web application**. Add the BearPortal browser origins as authorized JavaScript origins. For the current SSH-tunnel workflow add `http://localhost`, `http://localhost:8088` and `http://127.0.0.1:8088`. Google’s setup guide specifically requires both the base localhost entry and its port-specific entry. The base entry belongs in the Google OAuth client; the BearPortal application itself continues to run on port 8088. Add your HTTPS portal origin when deploying publicly. Use the exact browser origin, including a non-default port; do not include a path.
4. Enable the **Google** provider in Identity Platform and configure that OAuth web client's ID and secret there. BearPortal needs the client ID, not the OAuth client secret. While the consent app is in testing mode, add the intended Google accounts as test users; publish the consent app when you are ready for public sign-up.
5. Add the BearPortal hostnames to Identity Platform's authorized domains, including `localhost` and `127.0.0.1` for this development setup. Configure the verification and password-reset email templates/sender in Identity Platform. The managed email action handler completes verification/reset; its continue URL returns to `/login`.
6. Obtain the project's Identity Platform API key. Restrict it to the Identity Toolkit and Secure Token APIs. The key is used by the BearPortal backend, so a browser HTTP-referrer restriction will block these server requests. Any IP restriction must allow the control-plane server's outbound address.
7. Keep the project in its default tenant. Separate Identity Platform tenants and additional sign-in providers are not supported by this integration.

## Configure BearPortal without an editor

On the BearPortal server:

```sh
cd /home/luoxi23vr/bearportal
pnpm trial:migrate
pnpm auth:configure
```

Enter the project ID, API key, OAuth web client ID and permitted browser origins when prompted. This command validates the fields, saves a private backup of `.data/trial/env`, and updates only the four authentication settings. It preserves database URLs, encryption keys and existing signing keys.

Alternatively, supply a JSON file shaped like [identity-platform.example.json](../../examples/auth/identity-platform.example.json):

```sh
pnpm auth:configure --file /path/to/identity-platform.json
```

The environment settings are:

```text
BEARPORTAL_IDENTITY_PROJECT_ID=your-google-cloud-project
BEARPORTAL_IDENTITY_API_KEY=your-identity-platform-api-key
BEARPORTAL_GOOGLE_CLIENT_ID=your-web-client.apps.googleusercontent.com
BEARPORTAL_AUTH_ORIGINS=http://localhost:8088,http://127.0.0.1:8088
```

Restart the running API after configuration. Start with `pnpm trial:start` if it is stopped. Do not run `trial:reset`. The browser routes require migration `008_identity_accounts.sql`; migration is additive and retains existing users, domains, deployments and resource assignments.

Public production origins must use HTTPS. Production must also retain the existing production environment/issuer checks (`BEARPORTAL_ENV=production`, no test issuer or local identity signing). Use the configured project's secure-token issuer/audience in the normal JWT settings. Development operator links are not a production authentication mechanism.

## Customer flow

- Open `/register` and choose Google, or enter an email and a password of at least 12 characters.
- Google sign-in verifies the Google token, audience and browser nonce, exchanges it through Identity Platform, and verifies the resulting project token.
- Email/password sign-up sends a verification email. An unverified address cannot claim an application account or resources. After following the link, choose **I've verified my email** or sign in again at `/login`.
- Existing users use `/login`. **Forgot password?** sends a managed reset email; the response does not reveal whether an account exists. **Continue with saved sign-in** refreshes an existing browser sign-in.
- Identity and refresh tokens use HttpOnly cookies. Passwords and tokens are not returned in sign-in JSON or placed in browser local/session storage. Sign out clears this browser's cookies. Token refresh remains subject to upstream account status and revocation.
- An expired managed page session returns to `/login?resume=1`, where the saved refresh session can resume. Identity Platform ID tokens normally expire after one hour; the existing development operator token lifetime and two-hour inventory MFA window are separate.
- Signup/login does not change the once-only domain setup consent or rerun an installed deployment.

Identity Platform accounts requiring an additional MFA challenge are rejected with an explicit message rather than bypassed; the browser does not currently implement that upstream challenge. Existing operator roles are not granted or linked merely because a Google account has the same email. Production operators use explicit server authorization and BearPortal authenticator verification; see [operator-login.md](operator-login.md).

## Existing customer accounts

`identity_accounts` binds a verified Identity Platform issuer/UID to a stable application user. Verified email/password identities can connect an existing ordinary `local:<email>` account. Authoritative Gmail/Google Workspace proof can do the same through Google sign-in. The organization, domains, server, Brevo account and deployments retain their original IDs. Unverified email, unsupported tenants/providers and wrong-project tokens are rejected. Accounts that have operator-role records are excluded from automatic email matching.

For an older email-only development account, choose Google with the same authoritative Gmail/Workspace address, or create an Identity Platform email/password account with the same email and verify it. There is no old BearPortal password to import.

Once bound, identity lookup uses issuer and UID, not a client-supplied user/organization ID or an unverified email. Concurrent sign-ins are serialized per UID to avoid duplicate registrations. Disabled application accounts cannot sign in or refresh.

## Troubleshooting

- **Sign-in is not configured:** set all four variables and restart the API. Partial configurations are rejected at startup.
- **Google origin/client error:** check the OAuth web client ID and exact authorized JavaScript origin.
- **Verification email delayed:** check Identity Platform email configuration/quotas, then use the resend button. The newly created upstream account and pending sign-in are retained.
- **Sign-in temporarily unavailable:** check provider enablement, project/API key and API restrictions. Backend provider error bodies are not echoed to customers or logs.
- **Existing account needs linking:** use verified email/password sign-in. A third-party Google email assertion without Gmail/Workspace authority does not automatically claim an older local account.

Primary references: [Identity Platform REST operations](https://cloud.google.com/identity-platform/docs/use-rest-api), [password sign-in](https://cloud.google.com/identity-platform/docs/reference/rest/v1/accounts/signInWithPassword), [Google ID-token verification](https://developers.google.com/identity/gsi/web/guides/verify-google-id-token), [Google button nonce](https://developers.google.com/identity/gsi/web/reference/js-reference), [Google localhost origin setup](https://developers.google.com/identity/gsi/web/guides/get-google-api-clientid).

Activation diagnostics distinguish two separate allowlists: Identity Platform authorized domains contain hostnames, while the OAuth web client authorized JavaScript origins contain full origins including ports. A valid project/API key and an authorized Identity Platform domain do not alone authorize the Google button. `PASSWORD_LOGIN_DISABLED` is presented as a provider configuration issue rather than an incorrect customer password.

For the current local deployment, use `http://localhost:8088/register` and `http://localhost:8088/login` in the Mac browser. This origin passed the live Google button/origin check. The 127.0.0.1 variant remains suitable for local API access but its Google browser-origin check has not passed.
