package main

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
)

// RNS constants (verified against RNS v1.1.3)
const (
	NameHashLen  = 10 // bytes (80 bits)
	TruncatedLen = 16 // bytes (128 bits)
)

// Precomputed name hashes for known destination types.
var destNameHashes map[string][]byte

func init() {
	lxmf, _ := hex.DecodeString("6ec60bc318e2c0f0d908")
	nomadnet, _ := hex.DecodeString("213e6311bcec54ab4fde")
	destNameHashes = map[string][]byte{
		"lxmf.delivery":    lxmf,
		"nomadnetwork.node": nomadnet,
	}
}

// computeNameHash computes the 10-byte name hash for a destination type.
func computeNameHash(destName string) []byte {
	h := sha256.Sum256([]byte(destName))
	out := make([]byte, NameHashLen)
	copy(out, h[:NameHashLen])
	return out
}

// keyResult holds the output of a single key generation attempt.
type keyResult struct {
	PrivateKey   [64]byte
	IdentityHash [16]byte
	DestHex      string
}

// generateAndHash generates one identity and computes its destination hash.
// This is the hot-path function called in the inner loop of each worker.
func generateAndHash(nameHash []byte) keyResult {
	// Generate X25519 key pair
	xPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		panic("x25519 keygen failed: " + err.Error())
	}
	xPub := xPriv.PublicKey().Bytes()

	// Generate Ed25519 key pair
	ePub, ePriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic("ed25519 keygen failed: " + err.Error())
	}

	// Identity hash: SHA256(x25519_pub || ed25519_pub)[:16]
	var pubConcat [64]byte
	copy(pubConcat[:32], xPub)
	copy(pubConcat[32:], ePub)
	idFull := sha256.Sum256(pubConcat[:])

	var identityHash [16]byte
	copy(identityHash[:], idFull[:TruncatedLen])

	// Destination hash: SHA256(name_hash || identity_hash)[:16]
	var destInput [NameHashLen + TruncatedLen]byte
	copy(destInput[:NameHashLen], nameHash)
	copy(destInput[NameHashLen:], identityHash[:])
	destFull := sha256.Sum256(destInput[:])

	var destHexBuf [32]byte
	hex.Encode(destHexBuf[:], destFull[:TruncatedLen])

	// Private key: x25519_prv(32) + ed25519_seed(32) = 64 bytes
	var privKey [64]byte
	copy(privKey[:32], xPriv.Bytes())
	copy(privKey[32:], ePriv.Seed())

	return keyResult{
		PrivateKey:   privKey,
		IdentityHash: identityHash,
		DestHex:      string(destHexBuf[:]),
	}
}

// destHashFromIdentityHash computes the 16-byte destination hash.
func destHashFromIdentityHash(nameHash, identityHash []byte) []byte {
	combined := make([]byte, len(nameHash)+len(identityHash))
	copy(combined, nameHash)
	copy(combined[len(nameHash):], identityHash)
	h := sha256.Sum256(combined)
	out := make([]byte, TruncatedLen)
	copy(out, h[:TruncatedLen])
	return out
}
