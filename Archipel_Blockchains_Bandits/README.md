# Archipel - Blockchains Bandits

Protocole P2P local, decentralise, chiffre, sans serveur central.

## Sprint courant

- Sprint 2 termine

## Stack choisie (Sprint 0)

- Runtime: Node.js (>= 20)
- Discovery reseau: UDP multicast
- Transfert reseau: TCP sockets
- Crypto cible:
- Ed25519 (identite/signature)
- X25519 + HKDF-SHA256 (cle de session)
- AES-256-GCM (chiffrement)
- HMAC-SHA256 (integrite)

## Schema architecture

Voir [docs/architecture.md](docs/architecture.md).

## Spec format paquet

Voir [docs/protocol-spec.md](docs/protocol-spec.md).

## Configuration

1. Copier l'environnement:

```powershell
Copy-Item .env.example .env
```

2. Generer les cles locales Ed25519:

```powershell
node src/crypto/generate-keys.mjs --node-name node-1
```

3. (Optionnel) Regenerer en ecrasant:

```powershell
node src/crypto/generate-keys.mjs --node-name node-1 --force
```

## Livrables Sprint 0

- README complete avec stack, architecture et spec paquet
- Architecture documentee (`docs/architecture.md`)
- Specification paquet minimale (`docs/protocol-spec.md`)
- PKI locale: script de generation de cles (`src/crypto/generate-keys.mjs`)

## Livrables Sprint 1

- Couche discovery UDP multicast (`239.255.42.99:6000`) implementee
- Peer table en memoire + persistance JSON (`.archipel/peers-*.json`)
- Timeout pair mort (90s parametre)
- Serveur TCP de reception + echange `PEER_LIST` en TLV (Type-Length-Value)
- Keep-alive applicatif `PING/PONG` toutes les 15s
- Affichage peer table en console (log periodique)
- Verification 3 noeuds:

```powershell
npm run sprint1:check
```

Le script lance 3 noeuds locaux (`7777`, `7778`, `7779`) et valide que chaque noeud decouvre les 2 autres.

## Commandes secure (Sprint 2)

```powershell
node src/cli/archipel.mjs secure-listen --node-name bob --port 8802
node src/cli/archipel.mjs secure-send --node-name alice --to-host 127.0.0.1 --to-port 8802 --message Bonjour
```

## Livrables Sprint 2

- Handshake authentifie sans CA (mode Noise-like): `HELLO -> HELLO_REPLY -> AUTH -> AUTH_OK`
- Identite de noeud: Ed25519 (signature/verification)
- Echange de cle de session: X25519 + HKDF-SHA256
- Chiffrement de message: AES-256-GCM
- Integrite/signature message: signature Ed25519 sur hash du message chiffre
- Web of Trust (TOFU): stockage et verification de la cle publique par `node_id`
- Demo Alice -> Bob:

```powershell
npm run sprint2:check
```

Le test valide:
- Bob dechiffre correctement le message d'Alice
- Le plaintext n'apparait pas dans les octets transportes
