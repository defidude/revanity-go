# revanity-go

Vanity address generator for [Reticulum](https://reticulum.network) & LXMF networks. Pure Go, zero dependencies.

## Install

```
git clone https://github.com/defidude/dude.eth.git
cd dude.eth
go build -o revanity-go
```

## Usage

```
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
- `<address>.identity` — 64-byte binary key (import directly into Sideband/Nomadnet/any RNS app)
- `<address>.txt` — human-readable info with private key formats and import instructions

## Requirements

Go 1.20+
