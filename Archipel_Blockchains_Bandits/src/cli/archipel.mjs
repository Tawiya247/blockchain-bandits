#!/usr/bin/env node
import { ArchipelNode } from "../network/archipel-node.mjs";
import { SecureNode } from "../messaging/secure-node.mjs";

function arg(name, fallback) {
  const idx = process.argv.indexOf(name);
  if (idx >= 0 && idx + 1 < process.argv.length) return process.argv[idx + 1];
  return fallback;
}

const cmd = process.argv[2];
if (cmd === "start") {
  const node = new ArchipelNode({
    nodeName: arg("--node-name", process.env.ARCHIPEL_NODE_NAME ?? "node-1"),
    tcpPort: Number(arg("--port", process.env.ARCHIPEL_TCP_PORT ?? "7777")),
    mcastIp: process.env.ARCHIPEL_UDP_MULTICAST_IP ?? "239.255.42.99",
    mcastPort: Number(process.env.ARCHIPEL_UDP_MULTICAST_PORT ?? "6000"),
    discoveryIntervalSec: Number(process.env.ARCHIPEL_DISCOVERY_INTERVAL_SEC ?? "30"),
    peerTimeoutSec: Number(process.env.ARCHIPEL_PEER_TIMEOUT_SEC ?? "90"),
    keepAliveSec: Number(process.env.ARCHIPEL_KEEPALIVE_INTERVAL_SEC ?? "15"),
    dataDir: process.env.ARCHIPEL_DATA_DIR ?? ".archipel",
    keysDir: process.env.ARCHIPEL_KEYS_DIR ?? ".archipel/keys",
  });

  node.start();
  process.on("SIGINT", () => {
    node.stop();
    process.exit(0);
  });
} else if (cmd === "secure-listen") {
  const secureNode = new SecureNode({
    nodeName: arg("--node-name", process.env.ARCHIPEL_NODE_NAME ?? "node-1"),
    host: arg("--host", "0.0.0.0"),
    port: Number(arg("--port", "8801")),
    dataDir: process.env.ARCHIPEL_DATA_DIR ?? ".archipel",
    keysDir: process.env.ARCHIPEL_KEYS_DIR ?? ".archipel/keys",
  });

  secureNode.on("message", ({ from, plaintext }) => {
    console.log(`[secure-message] from=${from.slice(0, 12)} text=${plaintext}`);
  });

  await secureNode.start();
  process.on("SIGINT", async () => {
    await secureNode.stop();
    process.exit(0);
  });
} else if (cmd === "secure-send") {
  const secureNode = new SecureNode({
    nodeName: arg("--node-name", process.env.ARCHIPEL_NODE_NAME ?? "node-1"),
    host: arg("--host", "127.0.0.1"),
    port: Number(arg("--port", "8801")),
    dataDir: process.env.ARCHIPEL_DATA_DIR ?? ".archipel",
    keysDir: process.env.ARCHIPEL_KEYS_DIR ?? ".archipel/keys",
  });
  await secureNode.start();
  const toHost = arg("--to-host", "127.0.0.1");
  const toPort = Number(arg("--to-port", "8802"));
  const message = arg("--message", "hello");
  const sent = await secureNode.sendEncryptedMessage({
    host: toHost,
    port: toPort,
    plaintext: message,
  });
  console.log(`secure-send ok to=${sent.peerNodeId.slice(0, 12)}`);
  await secureNode.stop();
} else {
  console.log("Usage:");
  console.log("  node src/cli/archipel.mjs start --node-name node-1 --port 7777");
  console.log("  node src/cli/archipel.mjs secure-listen --node-name bob --port 8802");
  console.log(
    "  node src/cli/archipel.mjs secure-send --node-name alice --to-host 127.0.0.1 --to-port 8802 --message hello"
  );
  process.exit(1);
}
