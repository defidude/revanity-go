# revanity-go

Vanity address generator for [Reticulum](https://reticulum.network) & LXMF networks. Pure Go, zero dependencies.

Generate custom Reticulum destination hashes that start with, end with, or contain a specific hex pattern — useful for memorable node addresses.

## Install

```bash
git clone https://github.com/ratspeak/revanity-go
cd revanity-go
go build -o revanity-go
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
./revanity-go -prefix dead -workers 8       # set worker count
./revanity-go -prefix dead -dest nomadnetwork.node  # different dest type
./revanity-go -prefix deadbeef -dry-run     # estimate difficulty only
./revanity-go -prefix dead -quiet           # output address only
./revanity-go -prefix dead -output mykey    # custom output filename
```

## Output

On match, two files are saved:
- `<address>.identity` — 64-byte binary key (import directly into Sideband, NomadNet, or any RNS app)
- `<address>.txt` — human-readable info with private key formats and import instructions

## How It Works

Reticulum addresses are truncated SHA-256 hashes of Ed25519/X25519 public keys. revanity-go generates random keypairs in parallel, hashes them, and checks against your target pattern. Longer patterns take exponentially longer — each additional hex character multiplies the average time by 16x.

| Pattern Length | Avg Attempts | Rough Time (8 cores) |
|---------------|-------------|---------------------|
| 4 chars | ~65K | seconds |
| 6 chars | ~17M | minutes |
| 8 chars | ~4.3B | hours |

## Requirements

Go 1.20+

## License

AGPL-3.0 — see [LICENSE](LICENSE).
