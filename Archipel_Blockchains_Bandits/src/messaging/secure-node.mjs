import net from "node:net";
import { EventEmitter } from "node:events";
import {
  createHash,
  createPublicKey,
  createCipheriv,
  createDecipheriv,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
  randomBytes,
  sign,
  verify,
} from "node:crypto";
import { resolve, join } from "node:path";
import { decodeFrames, encodeFrame } from "../network/tcp-frame.mjs";
import { loadIdentity } from "../crypto/keyring.mjs";
import { TrustStore } from "./trust-store.mjs";

const FT = {
  HELLO: 0x10,
  HELLO_REPLY: 0x11,
  AUTH: 0x12,
  AUTH_OK: 0x13,
  SECURE_MSG: 0x14,
};

function waitForFrame(socketState, type, timeoutMs = 5000) {
  return new Promise((resolvePromise, rejectPromise) => {
    const timer = setTimeout(() => rejectPromise(new Error(`timeout waiting frame ${type}`)), timeoutMs);
    const queued = socketState.frames.findIndex((f) => f.type === type);
    if (queued >= 0) {
      clearTimeout(timer);
      const frame = socketState.frames.splice(queued, 1)[0];
      resolvePromise(frame);
      return;
    }
    socketState.waiters.push({
      type,
      done: (err, frame) => {
        clearTimeout(timer);
        if (err) rejectPromise(err);
        else resolvePromise(frame);
      },
    });
  });
}

function feedFrames(socketState, chunk) {
  socketState.lastRawHex = chunk.toString("hex");
  const frames = decodeFrames(socketState, chunk);
  for (const frame of frames) {
    const waiterIdx = socketState.waiters.findIndex((w) => w.type === frame.type);
    if (waiterIdx >= 0) {
      const w = socketState.waiters.splice(waiterIdx, 1)[0];
      w.done(null, frame);
    } else {
      socketState.frames.push(frame);
    }
  }
}

function transcriptHash(helloPayload, helloReplyPayload) {
  const raw = JSON.stringify({
    a: helloPayload.node_id,
    b: helloReplyPayload.node_id,
    e_a: helloPayload.eph_pub_pem,
    e_b: helloReplyPayload.eph_pub_pem,
  });
  return createHash("sha256").update(raw, "utf8").digest();
}

function deriveSessionKey(sharedSecret) {
  return hkdfSync("sha256", sharedSecret, Buffer.alloc(0), Buffer.from("archipel-v1"), 32);
}

function secureMessageHash(nonce, ciphertext, authTag) {
  return createHash("sha256").update(nonce).update(ciphertext).update(authTag).digest();
}

export class SecureNode extends EventEmitter {
  constructor(options) {
    super();
    this.nodeName = options.nodeName;
    this.host = options.host ?? "127.0.0.1";
    this.port = Number(options.port);
    this.dataDir = resolve(options.dataDir ?? ".archipel");
    this.keysDir = resolve(options.keysDir ?? ".archipel/keys");
    this.identity = loadIdentity(this.nodeName, this.keysDir);
    this.trustStore = new TrustStore(join(this.dataDir, `trust-${this.nodeName}.json`));
    this.server = null;
  }

  log(msg) {
    console.log(`[secure:${this.nodeName}:${this.port}] ${msg}`);
  }

  async start() {
    this.server = net.createServer((socket) => this.onIncomingSocket(socket));
    await new Promise((resolvePromise, rejectPromise) => {
      this.server.once("error", rejectPromise);
      this.server.listen(this.port, this.host, () => resolvePromise());
    });
    this.log("listening");
  }

  async stop() {
    if (!this.server) return;
    await new Promise((resolvePromise) => this.server.close(() => resolvePromise()));
    this.log("stopped");
  }

  async onIncomingSocket(socket) {
    const socketState = {
      buffer: Buffer.alloc(0),
      frames: [],
      waiters: [],
      lastRawHex: "",
      ended: false,
    };
    socket.on("data", (chunk) => feedFrames(socketState, chunk));
    socket.on("end", () => {
      socketState.ended = true;
    });
    socket.on("error", () => {});

    try {
      const session = await this.responderHandshake(socket, socketState);
      while (!socket.destroyed && !socketState.ended) {
        const frame = await waitForFrame(socketState, FT.SECURE_MSG, 15000).catch((err) => {
          if (socketState.ended || socket.destroyed) return null;
          throw err;
        });
        if (!frame) break;
        const msg = this.decryptMessage(session, frame.payload);
        this.emit("message", { from: session.peerNodeId, plaintext: msg, wireHex: socketState.lastRawHex });
      }
    } catch (err) {
      this.log(`incoming session end: ${err.message}`);
      socket.destroy();
    }
  }

  async responderHandshake(socket, socketState) {
    const hello = await waitForFrame(socketState, FT.HELLO);
    const helloP = hello.payload;

    const trust = this.trustStore.verifyOrTrust(helloP.node_id, helloP.identity_pub_pem);
    if (!trust.trusted) throw new Error(trust.reason);

    const ephB = generateKeyPairSync("x25519");
    const ephBPubPem = ephB.publicKey.export({ type: "spki", format: "pem" });
    const th = transcriptHash(helloP, { node_id: this.identity.nodeId, eph_pub_pem: ephBPubPem });
    const sigB = sign(null, th, this.identity.privateKey).toString("base64");

    socket.write(
      encodeFrame(FT.HELLO_REPLY, {
        node_id: this.identity.nodeId,
        identity_pub_pem: this.identity.publicPem,
        eph_pub_pem: ephBPubPem,
        sig_b: sigB,
      })
    );

    const shared = diffieHellman({
      privateKey: ephB.privateKey,
      publicKey: createPublicKey(helloP.eph_pub_pem),
    });
    const sessionKey = deriveSessionKey(shared);

    const auth = await waitForFrame(socketState, FT.AUTH);
    const authOk = verify(
      null,
      createHash("sha256").update(shared).digest(),
      createPublicKey(helloP.identity_pub_pem),
      Buffer.from(auth.payload.sig_a, "base64")
    );
    if (!authOk) throw new Error("AUTH signature invalid");
    socket.write(encodeFrame(FT.AUTH_OK, { ok: true }));

    this.log(`secure handshake ok with ${helloP.node_id.slice(0, 12)}`);
    return {
      key: sessionKey,
      peerNodeId: helloP.node_id,
    };
  }

  async sendEncryptedMessage({ host, port, plaintext }) {
    const socket = net.createConnection({ host, port: Number(port) });
    const socketState = { buffer: Buffer.alloc(0), frames: [], waiters: [], lastRawHex: "" };
    socket.on("data", (chunk) => feedFrames(socketState, chunk));
    socket.on("error", () => {});

    await new Promise((resolvePromise, rejectPromise) => {
      socket.once("connect", resolvePromise);
      socket.once("error", rejectPromise);
    });

    const session = await this.initiatorHandshake(socket, socketState);
    const frameBuffer = this.encryptMessageFrame(session, plaintext);
    socket.write(frameBuffer);
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 200));
    socket.end();
    return {
      peerNodeId: session.peerNodeId,
      wireHex: frameBuffer.toString("hex"),
    };
  }

  async initiatorHandshake(socket, socketState) {
    const ephA = generateKeyPairSync("x25519");
    const ephAPubPem = ephA.publicKey.export({ type: "spki", format: "pem" });

    socket.write(
      encodeFrame(FT.HELLO, {
        node_id: this.identity.nodeId,
        identity_pub_pem: this.identity.publicPem,
        eph_pub_pem: ephAPubPem,
        timestamp: Date.now(),
      })
    );

    const helloReply = await waitForFrame(socketState, FT.HELLO_REPLY);
    const p = helloReply.payload;

    const trust = this.trustStore.verifyOrTrust(p.node_id, p.identity_pub_pem);
    if (!trust.trusted) throw new Error(trust.reason);

    const th = transcriptHash(
      {
        node_id: this.identity.nodeId,
        eph_pub_pem: ephAPubPem,
      },
      p
    );
    const okSigB = verify(null, th, createPublicKey(p.identity_pub_pem), Buffer.from(p.sig_b, "base64"));
    if (!okSigB) throw new Error("HELLO_REPLY signature invalid");

    const shared = diffieHellman({
      privateKey: ephA.privateKey,
      publicKey: createPublicKey(p.eph_pub_pem),
    });
    const sessionKey = deriveSessionKey(shared);

    const sigA = sign(null, createHash("sha256").update(shared).digest(), this.identity.privateKey);
    socket.write(encodeFrame(FT.AUTH, { sig_a: sigA.toString("base64") }));
    await waitForFrame(socketState, FT.AUTH_OK);

    this.log(`secure handshake ok with ${p.node_id.slice(0, 12)}`);
    return {
      key: sessionKey,
      peerNodeId: p.node_id,
    };
  }

  encryptMessageFrame(session, plaintext) {
    const nonce = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", session.key, nonce);
    const ciphertext = Buffer.concat([cipher.update(Buffer.from(plaintext, "utf8")), cipher.final()]);
    const authTag = cipher.getAuthTag();
    const signature = sign(
      null,
      secureMessageHash(nonce, ciphertext, authTag),
      this.identity.privateKey
    ).toString("base64");

    return encodeFrame(FT.SECURE_MSG, {
      sender_id: this.identity.nodeId,
      nonce: nonce.toString("base64"),
      ciphertext: ciphertext.toString("base64"),
      auth_tag: authTag.toString("base64"),
      signature,
    });
  }

  decryptMessage(session, payload) {
    const senderPem = this.trustStore.getPublicKeyPem(payload.sender_id);
    if (!senderPem) throw new Error("unknown sender key");

    const nonce = Buffer.from(payload.nonce, "base64");
    const ciphertext = Buffer.from(payload.ciphertext, "base64");
    const authTag = Buffer.from(payload.auth_tag, "base64");
    const sig = Buffer.from(payload.signature, "base64");

    const sigOk = verify(
      null,
      secureMessageHash(nonce, ciphertext, authTag),
      createPublicKey(senderPem),
      sig
    );
    if (!sigOk) throw new Error("message signature invalid");

    const decipher = createDecipheriv("aes-256-gcm", session.key, nonce);
    decipher.setAuthTag(authTag);
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
    return plaintext;
  }
}
