export const PACKET_TYPE = {
  HELLO: 0x01,
  PEER_LIST: 0x02,
};

export const TCP_FRAME_TYPE = {
  PEER_LIST: 0x02,
  PING: 0x08,
  PONG: 0x09,
};

export const MAGIC = Buffer.from("ARCP", "ascii");
export const HMAC_KEY =
  process.env.ARCHIPEL_DISCOVERY_HMAC_KEY ?? "archipel-dev-key-change-in-production";
