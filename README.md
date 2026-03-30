<div align="center">

# revanity-go

**Vanity address generator for [Reticulum](https://reticulum.network) and LXMF networks.**

[![Go 1.20+](https://img.shields.io/badge/go-1.20+-00ADD8.svg)](https://go.dev)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Status: Stable](https://img.shields.io/badge/status-stable-brightgreen.svg)](https://github.com/ratspeak/revanity-go)

</div>

---

Brute-forces cryptographic key pairs in parallel until it finds one whose destination hash matches your pattern. Uses libsodium's hand-optimized ARM64 assembly for X25519 scalar multiplication on Apple Silicon.

## Install

Requires [libsodium](https://doc.libsodium.org/installation) and Go 1.20+.

```bash
# macOS
brew install libsodium

# Linux (Debian/Ubuntu)
sudo apt install libsodium-dev
```

```bash
git clone https://github.com/ratspeak/revanity-go.git
cd revanity-go
CGO_ENABLED=1 go build -o revanity-go
```

## Usage

```bash
# Find address starting with "dead"
./revanity-go -prefix dead

# Other match modes
./revanity-go -suffix cafe
./revanity-go -contains beef
./revanity-go -regex "^(dead|beef)"

# Options
./revanity-go -prefix dead -workers 8                # set worker count
./revanity-go -prefix dead -dest nomadnetwork.node   # different dest type
./revanity-go -prefix deadbeef -dry-run              # estimate difficulty only
./revanity-go -prefix dead -quiet                    # output address only
```

## Multi-Pattern Search

Search for multiple patterns at once with comma-separated values. Stops automatically when every pattern has at least one match. Duplicates found along the way are saved too.

```bash
./revanity-go -prefix aa,bb,cc
./revanity-go -prefix dead,beef,cafe,babe   # find all four
```

Combine with `-loop` to keep going after all patterns are satisfied.

## Loop Mode

Search continuously, collecting every match instead of stopping at the first one.

```bash
./revanity-go -prefix dead -loop
./revanity-go -prefix dead -loop -output my_results   # custom output directory
```

Both multi-pattern and loop mode save results to `results/` (or the directory specified by `-output`):

- `<mode>_<patterns>.jsonl` — one JSON object per line with dest hash, identity hash, matched pattern, private key (hex/base32/base64), all destination hashes, and metadata. Append-safe across runs.
- `<dest_hash>.identity` — individual 64-byte binary keys for direct import into Sideband, Nomadnet, or any RNS application.

## Output

In single mode (without `-loop`), two files are saved on match:

- `<address>.identity` — 64-byte binary key (import directly into Sideband/Nomadnet/any RNS app)
- `<address>.txt` — human-readable info with private key formats and import instructions

## How It Works

Reticulum addresses are truncated SHA-256 hashes of Ed25519/X25519 public keys. revanity-go generates random keypairs in parallel, hashes them, and checks against your target pattern. Longer patterns take exponentially longer — each additional hex character multiplies the average time by 16x.

| Pattern Length | Avg Attempts | Rough Time (8 cores) |
|---------------|-------------|---------------------|
| 4 chars | ~65K | seconds |
| 6 chars | ~17M | minutes |
| 8 chars | ~4.3B | hours |

## License

MIT
