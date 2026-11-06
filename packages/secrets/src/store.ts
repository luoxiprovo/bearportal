import { createCipheriv, createDecipheriv, randomBytes, randomUUID } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";

export type SecretKey = Buffer;

export function loadSecretKey(hex = process.env.BEARPORTAL_SECRET_KEY): SecretKey {
  if (!hex || !/^[0-9a-f]{64}$/i.test(hex)) {
    throw new Error("BEARPORTAL_SECRET_KEY must be 64 hex characters.");
  }
  return Buffer.from(hex, "hex");
}

export function seal(plaintext: string, key: SecretKey): Buffer {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const body = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([Buffer.from([1]), iv, tag, body]);
}

export function open(payload: Buffer, key: SecretKey): string {
  if (payload[0] !== 1 || payload.length < 1 + 12 + 16) {
    throw new Error("Secret file is not a BearPortal seal.");
  }
  const iv = payload.subarray(1, 13);
  const tag = payload.subarray(13, 29);
  const body = payload.subarray(29);
  const decipher = createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(body), decipher.final()]).toString("utf8");
}

export class SecretStore {
  constructor(
    private readonly directory: string,
    private readonly key: SecretKey,
  ) {
    mkdirSync(directory, { recursive: true, mode: 0o700 });
    chmodSync(directory, 0o700);
  }

  write(plaintext: string): string {
    const fileName = `${randomUUID()}.bin`;
    const path = join(this.directory, fileName);
    writeFileSync(path, seal(plaintext, this.key), { mode: 0o600 });
    chmodSync(path, 0o600);
    return fileName;
  }

  read(fileName: string): string {
    if (!/^[0-9a-f-]{36}\.bin$/i.test(fileName)) {
      throw new Error("Secret file name is not valid.");
    }
    return open(readFileSync(join(this.directory, fileName)), this.key);
  }

  destroy(fileName: string): void {
    if (!/^[0-9a-f-]{36}\.bin$/i.test(fileName)) {
      throw new Error("Secret file name is not valid.");
    }
    const path = join(this.directory, fileName);
    if (existsSync(path)) unlinkSync(path);
  }
}
