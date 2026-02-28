import { createHash, createPrivateKey, createPublicKey } from "node:crypto";
import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";

export function loadIdentity(nodeName, keysDir = ".archipel/keys") {
  const absKeysDir = resolve(keysDir);
  const privatePath = join(absKeysDir, `${nodeName}_ed25519.pem`);
  const publicPath = join(absKeysDir, `${nodeName}_ed25519.pub.pem`);

  const privatePem = readFileSync(privatePath, "utf8");
  const publicPem = readFileSync(publicPath, "utf8");

  const privateKey = createPrivateKey(privatePem);
  const publicKey = createPublicKey(publicPem);
  const nodeId = createHash("sha256").update(publicPem, "utf8").digest("hex");

  return {
    nodeName,
    nodeId,
    privatePem,
    publicPem,
    privateKey,
    publicKey,
    privatePath,
    publicPath,
  };
}
