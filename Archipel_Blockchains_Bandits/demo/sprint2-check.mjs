import { once } from "node:events";
import { setTimeout as wait } from "node:timers/promises";
import { execFileSync } from "node:child_process";
import { resolve } from "node:path";
import { SecureNode } from "../src/messaging/secure-node.mjs";

const keysScript = resolve("src/crypto/generate-keys.mjs");
execFileSync(process.execPath, [keysScript, "--node-name", "alice", "--force"], { stdio: "inherit" });
execFileSync(process.execPath, [keysScript, "--node-name", "bob", "--force"], { stdio: "inherit" });

const dataDir = ".archipel/sprint2";
const alice = new SecureNode({ nodeName: "alice", host: "127.0.0.1", port: 8801, dataDir });
const bob = new SecureNode({ nodeName: "bob", host: "127.0.0.1", port: 8802, dataDir });

await bob.start();
await alice.start();

const secret = "HELLO_BOB_SECRET_MESSAGE";
const messagePromise = once(bob, "message");
const sent = await alice.sendEncryptedMessage({ host: "127.0.0.1", port: 8802, plaintext: secret });
const [received] = await Promise.race([
  messagePromise,
  wait(6000).then(() => {
    throw new Error("timeout waiting Bob message");
  }),
]);

await alice.stop();
await bob.stop();

if (received.plaintext !== secret) {
  throw new Error("decrypted plaintext mismatch");
}

const plainHex = Buffer.from(secret, "utf8").toString("hex");
if (sent.wireHex.includes(plainHex) || received.wireHex.includes(plainHex)) {
  throw new Error("plaintext detected on wire payload");
}

console.log(`from=${received.from}`);
console.log(`message=${received.plaintext}`);
console.log(`wire_sample=${sent.wireHex.slice(0, 80)}...`);
console.log("Sprint 2 check passed");
