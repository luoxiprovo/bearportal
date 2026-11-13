import { fileURLToPath } from "node:url";
import { assertMigrationStartup } from "./migration-fence.ts";
import { readFileSync, mkdirSync, accessSync, constants } from "node:fs";
import { liveMailInstall } from "../../../packages/servers/src/mail-install.ts";
import { liveSshProbe } from "../../../packages/servers/src/ssh-probe.ts";
import { loadConfig } from "./config.ts";
import { buildServer } from "./server.ts";

const migrationFenceFile = fileURLToPath(new URL("../../../.data/server-migration-source.lock", import.meta.url));
assertMigrationStartup(migrationFenceFile);
const config = loadConfig(process.env);
// Fail at startup if installation storage is unavailable, before accepting customer setups.
mkdirSync("/var/lib/bearportal/work", { recursive: true, mode: 0o700 });
accessSync("/var/lib/bearportal/work", constants.R_OK | constants.W_OK | constants.X_OK);
const jwtPublicKeyPem = readFileSync(config.jwtPublicKeyFile, "utf8");
const devJwtPrivateKeyPem = config.allowDevIdentity && config.devJwtPrivateKeyFile
  ? readFileSync(config.devJwtPrivateKeyFile, "utf8")
  : undefined;
const app = await buildServer({
  migrationFenceFile,
  billing: config.billing,
  identityPlatform:config.identityPlatform,
  databaseUrl: config.databaseUrl,
  secretsDir: config.secretsDir,
  secretKeyHex: config.secretKeyHex,
  jwtPublicKeyPem,
  issuer: config.issuer,
  audience: config.audience,
  schedulerToken: config.schedulerToken,
  devJwtPrivateKeyPem,
  sshProbe: (host) => liveSshProbe(host, config.skipSshHostKeyVerification),
  mailInstall: (hooks) => liveMailInstall({...hooks, skipHostKeyVerification:config.skipSshHostKeyVerification}),
});

await app.listen({ host: config.bindHost, port: config.port });
app.log.info({ host: config.bindHost, port: config.port }, "api listening");
