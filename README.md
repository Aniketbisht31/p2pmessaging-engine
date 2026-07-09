# p2p

A secure peer-to-peer messaging engine in Go with a minimal local CLI client.

## Overview

This repository implements a P2P messaging engine with:

- custom framed transport
- authenticated handshake using Ed25519/X25519
- AES-256-GCM session encryption
- reliable message delivery with ACKs and retransmit
- discovery and reconnect support
- encrypted storage backed by SQLite
- a decoupled CLI client in `cmd/p2p-client`

## Project Structure

- `protocol.go` - frame format, handshake payloads, session cipher, and protocol helpers.
- `net.go` - connection manager, per-peer connection loops, reliable send, ACK handling, discovery, and reconnect logic.
- `storage.go` - encrypted SQLite persistence for message history, contacts, and known peers.
- `client.go` - high-level client wrapper around `ConnManager` and storage.
- `cmd/p2p-client/main.go` - local CLI entrypoint for running a peer and interacting with the engine.
- `integration_test.go` - in-process peer integration tests for handshake, encrypted delivery, and unreliable network behavior.
- `protocol_test.go` - protocol-level unit tests.

## Requirements

- Go 1.25+
- `go` toolchain installed

## Build

From the repository root:

```powershell
cd C:\Users\Aniket\p2p
 go build -o p2pchat.exe ./cmd/p2p-client
```

## Run

Start peers in separate terminals.

Peer A:

```powershell
cd C:\Users\Aniket\p2p
.\p2pchat.exe --port 9001 --name alice
```

Peer B:

```powershell
cd C:\Users\Aniket\p2p
.\p2pchat.exe --port 9002 --peer localhost:9001 --name bob
```

The CLI starts with an interactive prompt where you can use commands like:

- `send <peer-address> <message>`
- `peers`
- `history`
- `addcontact <public-key> <alias>`
- `contacts`
- `connect <peer-address>`
- `exit`

## Usage Notes

- `--port` sets the local listen port.
- `--peer` connects this peer to a remote peer at startup.
- `--name` is a local label printed on launch.

## Testing

Run unit and integration tests with:

```powershell
go test ./...
```

## Development

- The core networking logic is isolated in package `p2p`.
- `ConnManager` manages connections, inbound delivery, and graceful shutdown.
- `PeerConn` handles per-peer read/write loops and reliable message state.
- `SessionCipher` provides ordered AES-GCM encryption and replay protection.

## Notes

This repository is intended as a foundational P2P messaging engine with a runnable local CLI. It can be extended with stronger session authentication, peer discovery over UDP, message routing, and richer client-side UX.
