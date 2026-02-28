import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

function fingerprint(publicKeyPem) {
  return createHash("sha256").update(publicKeyPem, "utf8").digest("hex");
}

export class TrustStore {
  constructor(filePath) {
    this.filePath = filePath;
    this.map = new Map();
    this.load();
  }

  load() {
    try {
      const raw = readFileSync(this.filePath, "utf8");
      const entries = JSON.parse(raw);
      this.map = new Map(entries.map((x) => [x.node_id, x]));
    } catch {
      this.map = new Map();
    }
  }

  save() {
    mkdirSync(dirname(this.filePath), { recursive: true });
    writeFileSync(this.filePath, JSON.stringify([...this.map.values()], null, 2), "utf8");
  }

  verifyOrTrust(nodeId, publicKeyPem) {
    const fp = fingerprint(publicKeyPem);
    const known = this.map.get(nodeId);
    if (!known) {
      this.map.set(nodeId, {
        node_id: nodeId,
        public_key_pem: publicKeyPem,
        fingerprint: fp,
        trust_mode: "TOFU",
        first_seen: Date.now(),
        last_seen: Date.now(),
      });
      this.save();
      return { trusted: true, tofu: true };
    }
    if (known.fingerprint !== fp || known.public_key_pem !== publicKeyPem) {
      return { trusted: false, reason: "public key changed (possible MITM)" };
    }
    known.last_seen = Date.now();
    this.map.set(nodeId, known);
    this.save();
    return { trusted: true, tofu: false };
  }

  getPublicKeyPem(nodeId) {
    return this.map.get(nodeId)?.public_key_pem ?? null;
  }
}
