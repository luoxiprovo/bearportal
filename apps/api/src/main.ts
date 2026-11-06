import { readFileSync } from "node:fs";
import { liveMailInstall } from "../../../packages/servers/src/mail-install.ts";
import { liveSshProbe } from "../../../packages/servers/src/ssh-probe.ts";
import { loadConfig } from "./config.ts";
import { buildServer } from "./server.ts";

const config = loadConfig(process.env);
const jwtPublicKeyPem = readFileSync(config.jwtPublicKeyFile, "utf8");
const devJwtPrivateKeyPem = config.allowDevIdentity && config.devJwtPrivateKeyFile
  ? readFileSync(config.devJwtPrivateKeyFile, "utf8")
  : undefined;
const app = await buildServer({
  databaseUrl: config.databaseUrl,
  secretsDir: config.secretsDir,
  secretKeyHex: config.secretKeyHex,
  jwtPublicKeyPem,
  issuer: config.issuer,
  audience: config.audience,
  schedulerToken: config.schedulerToken,
  devJwtPrivateKeyPem,
  sshProbe: liveSshProbe,
  mailInstall: liveMailInstall,
});

await app.listen({ host: config.bindHost, port: config.port });
app.log.info({ host: config.bindHost, port: config.port }, "api listening");
