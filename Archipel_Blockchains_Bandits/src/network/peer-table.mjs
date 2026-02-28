import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

export class PeerTable {
  constructor(filePath) {
    this.filePath = filePath;
    this.map = new Map();
    this.dirty = false;
    this.load();
  }

  load() {
    try {
      const raw = readFileSync(this.filePath, "utf8");
      const arr = JSON.parse(raw);
      this.map = new Map(arr.map((p) => [p.node_id, p]));
      this.dirty = false;
    } catch {
      this.map = new Map();
      this.dirty = false;
    }
  }

  save({ force = false } = {}) {
    if (!force && !this.dirty) return;
    mkdirSync(dirname(this.filePath), { recursive: true });
    writeFileSync(this.filePath, JSON.stringify([...this.map.values()], null, 2), "utf8");
    this.dirty = false;
  }

  upsert(peer) {
    const existing = this.map.get(peer.node_id);
    this.map.set(peer.node_id, {
      node_id: peer.node_id,
      ip: peer.ip,
      tcp_port: peer.tcp_port,
      last_seen: peer.last_seen ?? Date.now(),
      shared_files: existing?.shared_files ?? [],
      reputation: existing?.reputation ?? 1,
    });
    this.dirty = true;
  }

  merge(peers) {
    for (const peer of peers) this.upsert(peer);
  }

  prune(timeoutMs) {
    const now = Date.now();
    for (const [nodeId, peer] of this.map) {
      if (now - peer.last_seen > timeoutMs) {
        this.map.delete(nodeId);
        this.dirty = true;
      }
    }
  }

  list() {
    return [...this.map.values()].sort((a, b) => a.node_id.localeCompare(b.node_id));
  }
}
