package main

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// exportedIdentity holds all information about an exported identity.
type exportedIdentity struct {
	PrivateKeyRaw    [64]byte
	IdentityHashHex  string
	DestHashes       map[string]string // dest_type -> 32-char hex
	PrivateKeyHex    string
	PrivateKeyBase32 string
	PrivateKeyBase64 string
}

// prepareExport generates all export formats for an identity.
func prepareExport(privateKey [64]byte, identityHash [16]byte, destType, destHashHex string) *exportedIdentity {
	dests := make(map[string]string)

	// Compute destination hashes for all known destination types
	for dt, nameHash := range destNameHashes {
		dh := destHashFromIdentityHash(nameHash, identityHash[:])
		dests[dt] = hex.EncodeToString(dh)
	}

	// Include custom destination type if not already present
	if _, exists := dests[destType]; !exists && destHashHex != "" {
		dests[destType] = destHashHex
	}

	return &exportedIdentity{
		PrivateKeyRaw:    privateKey,
		IdentityHashHex:  hex.EncodeToString(identityHash[:]),
		DestHashes:       dests,
		PrivateKeyHex:    hex.EncodeToString(privateKey[:]),
		PrivateKeyBase32: base32.StdEncoding.EncodeToString(privateKey[:]),
		PrivateKeyBase64: base64.StdEncoding.EncodeToString(privateKey[:]),
	}
}

// saveIdentityFile saves the identity as a raw 64-byte binary file (RNS-compatible).
func saveIdentityFile(privateKey [64]byte, path string) (string, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}

	dir := filepath.Dir(absPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}

	if err := os.WriteFile(absPath, privateKey[:], 0o600); err != nil {
		return "", err
	}

	return absPath, nil
}

// saveIdentityText saves identity info as a human-readable text file with import instructions.
func saveIdentityText(export *exportedIdentity, path string) (string, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}

	dir := filepath.Dir(absPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}

	var b strings.Builder
	b.WriteString("# revanity Generated Identity\n")
	b.WriteString(fmt.Sprintf("# Identity Hash: %s\n", export.IdentityHashHex))
	b.WriteString("#\n")
	b.WriteString("# Destination Hashes:\n")
	for dt, dh := range export.DestHashes {
		b.WriteString(fmt.Sprintf("#   %s: %s\n", dt, dh))
	}
	b.WriteString("#\n")
	b.WriteString("# Private Key (KEEP SECRET):\n")
	b.WriteString(fmt.Sprintf("#   Hex:    %s\n", export.PrivateKeyHex))
	b.WriteString(fmt.Sprintf("#   Base32: %s\n", export.PrivateKeyBase32))
	b.WriteString(fmt.Sprintf("#   Base64: %s\n", export.PrivateKeyBase64))
	b.WriteString("#\n")
	b.WriteString("# Import Instructions:\n")
	b.WriteString("#\n")
	b.WriteString("#   Nomadnet:\n")
	b.WriteString("#     cp <file>.identity ~/.nomadnetwork/storage/identity\n")
	b.WriteString("#     (restart Nomadnet after copying)\n")
	b.WriteString("#\n")
	b.WriteString("#   Sideband (Linux):\n")
	b.WriteString("#     cp <file>.identity ~/.config/sideband/storage/identity\n")
	b.WriteString("#\n")
	b.WriteString("#   Sideband (macOS):\n")
	b.WriteString("#     cp <file>.identity ~/Library/Application\\ Support/Sideband/storage/identity\n")
	b.WriteString("#\n")
	b.WriteString("#   Sideband (Android):\n")
	b.WriteString("#     Import the Base32 string above via Settings > Identity\n")
	b.WriteString("#\n")
	b.WriteString("#   rnid utility:\n")
	b.WriteString(fmt.Sprintf("#     rnid -m %s\n", export.PrivateKeyHex))
	b.WriteString(fmt.Sprintf("#     rnid -m %s -B\n", export.PrivateKeyBase32))
	b.WriteString("#\n")
	b.WriteString("#   Any RNS application (Python):\n")
	b.WriteString("#     import RNS\n")
	b.WriteString("#     identity = RNS.Identity.from_file('path/to/<file>.identity')\n")
	b.WriteString("#\n")

	if err := os.WriteFile(absPath, []byte(b.String()), 0o600); err != nil {
		return "", err
	}

	return absPath, nil
}
