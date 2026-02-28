import dgram from "node:dgram";
import net from "node:net";
import { mkdirSync } from "node:fs";
import { join, resolve } from "node:path";
import { PACKET_TYPE, TCP_FRAME_TYPE } from "./constants.mjs";
import { buildPacket, parsePacket } from "./packet.mjs";
import { encodeFrame, decodeFrames } from "./tcp-frame.mjs";
import { PeerTable } from "./peer-table.mjs";
import { resolveNodeIdHex } from "./identity.mjs";

export class ArchipelNode {
  constructor(options) {
    this.nodeName = options.nodeName;
    this.tcpPort = Number(options.tcpPort);
    this.mcastIp = options.mcastIp;
    this.mcastPort = Number(options.mcastPort);
    this.discoveryIntervalMs = Number(options.discoveryIntervalSec) * 1000;
    this.peerTimeoutMs = Number(options.peerTimeoutSec) * 1000;
    this.keepAliveMs = Number(options.keepAliveSec) * 1000;
    this.dataDir = resolve(options.dataDir);
    this.keysDir = resolve(options.keysDir);
    this.nodeIdHex = resolveNodeIdHex(this.nodeName, this.tcpPort, this.keysDir);
    this.peerTable = new PeerTable(join(this.dataDir, `peers-${this.nodeName}.json`));
    this.tcpSockets = new Set();
    this.udpSocket = null;
    this.tcpServer = null;
    this.helloTimer = null;
    this.pruneTimer = null;
    this.flushTimer = null;
    this.pingTimer = null;
    this.printTimer = null;
  }

  log(msg) {
    console.log(`[${this.nodeName}:${this.tcpPort}] ${msg}`);
  }

  start() {
    mkdirSync(this.dataDir, { recursive: true });
    this.startTcpServer();
    this.startUdpDiscovery();
    this.pruneTimer = setInterval(() => this.peerTable.prune(this.peerTimeoutMs), 5000);
    this.flushTimer = setInterval(() => this.peerTable.save(), 5000);
    this.pingTimer = setInterval(() => this.broadcastPing(), this.keepAliveMs);
    this.printTimer = setInterval(() => this.printPeerTable(), 10000);
    if ((process.env.ARCHIPEL_DISCOVERY_HMAC_KEY ?? "").length === 0) {
      this.log("WARN empty ARCHIPEL_DISCOVERY_HMAC_KEY");
    }
  }

  stop() {
    clearInterval(this.helloTimer);
    clearInterval(this.pruneTimer);
    clearInterval(this.flushTimer);
    clearInterval(this.pingTimer);
    clearInterval(this.printTimer);
    for (const s of this.tcpSockets) s.destroy();
    this.peerTable.save({ force: true });
    if (this.tcpServer) this.tcpServer.close();
    if (this.udpSocket) this.udpSocket.close();
  }

  startUdpDiscovery() {
    this.udpSocket = dgram.createSocket({ type: "udp4", reuseAddr: true });
    this.udpSocket.on("error", (err) => this.log(`udp error: ${err.message}`));
    this.udpSocket.on("message", (msg, rinfo) => {
      try {
        const pkt = parsePacket(msg);
        if (pkt.type !== PACKET_TYPE.HELLO) return;
        if (pkt.nodeId === this.nodeIdHex) return;
        this.log(`HELLO from ${pkt.nodeId.slice(0, 12)} @ ${rinfo.address}:${pkt.payload.tcp_port}`);
        this.peerTable.upsert({
          node_id: pkt.nodeId,
          ip: rinfo.address,
          tcp_port: pkt.payload.tcp_port,
          last_seen: Date.now(),
        });
        this.sendPeerListToPeer(rinfo.address, pkt.payload.tcp_port);
      } catch (err) {
        this.log(`udp parse fail: ${err.message}`);
      }
    });
    this.udpSocket.bind(this.mcastPort, () => {
      this.udpSocket.addMembership(this.mcastIp);
      this.log(`discovery listening on ${this.mcastIp}:${this.mcastPort}`);
      this.sendHello();
      this.helloTimer = setInterval(() => this.sendHello(), this.discoveryIntervalMs);
    });
  }

  sendHello() {
    const hello = buildPacket(PACKET_TYPE.HELLO, this.nodeIdHex, {
      tcp_port: this.tcpPort,
      timestamp: Date.now(),
    });
    this.udpSocket.send(hello, this.mcastPort, this.mcastIp);
    this.log("HELLO broadcast");
  }

  startTcpServer() {
    this.tcpServer = net.createServer((socket) => this.attachSocket(socket));
    this.tcpServer.on("error", (err) => this.log(`tcp error: ${err.message}`));
    this.tcpServer.listen(this.tcpPort, "0.0.0.0", () => {
      this.log(`tcp server listening on ${this.tcpPort}`);
    });
  }

  attachSocket(socket) {
    socket.setNoDelay(true);
    const state = { buffer: Buffer.alloc(0) };
    this.tcpSockets.add(socket);
    socket.on("data", (chunk) => {
      for (const frame of decodeFrames(state, chunk)) this.handleFrame(socket, frame);
    });
    socket.on("close", () => this.tcpSockets.delete(socket));
    socket.on("error", () => this.tcpSockets.delete(socket));
  }

  handleFrame(socket, frame) {
    if (frame.type === TCP_FRAME_TYPE.PING) {
      socket.write(encodeFrame(TCP_FRAME_TYPE.PONG, { ts: Date.now() }));
      return;
    }
    if (frame.type === TCP_FRAME_TYPE.PEER_LIST) {
      const peers = frame.payload?.peers ?? [];
      const filtered = peers.filter((p) => p.node_id !== this.nodeIdHex);
      this.peerTable.merge(filtered);
      this.log(`peer list merged (${filtered.length} entries)`);
    }
  }

  sendPeerListToPeer(ip, port) {
    const socket = net.createConnection({ host: ip, port: Number(port) }, () => {
      const peers = this.peerTable.list();
      socket.write(encodeFrame(TCP_FRAME_TYPE.PEER_LIST, { peers }));
      socket.end();
    });
    socket.on("error", (err) => this.log(`peer_list send fail ${ip}:${port} ${err.message}`));
  }

  broadcastPing() {
    for (const socket of this.tcpSockets) {
      socket.write(encodeFrame(TCP_FRAME_TYPE.PING, { ts: Date.now() }));
    }
  }

  printPeerTable() {
    const peers = this.peerTable.list();
    const summary = peers
      .map((p) => `${p.node_id.slice(0, 12)} ${p.ip}:${p.tcp_port}`)
      .join(" | ");
    this.log(`peer_table=${peers.length}${summary ? ` -> ${summary}` : ""}`);
  }

  peerCount() {
    return this.peerTable.list().filter((p) => p.node_id !== this.nodeIdHex).length;
  }
}
