package main

/*
#cgo CFLAGS: -I/opt/homebrew/include
#cgo LDFLAGS: -L/opt/homebrew/lib -lsodium
#include <sodium.h>
*/
import "C"

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"unsafe"
)

// RNS constants (verified against RNS v1.1.3)
const (
	NameHashLen  = 10 // bytes (80 bits)
	TruncatedLen = 16 // bytes (128 bits)
)

// Precomputed name hashes for known destination types.
var destNameHashes map[string][]byte

func init() {
	if C.sodium_init() < 0 {
		panic("libsodium init failed")
	}

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
	PatternIdx   int
}

// scalarBaseMult computes the X25519 public key from a private scalar
// using libsodium's hand-optimized ARM64 assembly.
func scalarBaseMult(pub, priv *[32]byte) {
	C.crypto_scalarmult_curve25519_base(
		(*C.uchar)(unsafe.Pointer(&pub[0])),
		(*C.uchar)(unsafe.Pointer(&priv[0])),
	)
}

// workerState holds per-worker pre-allocated state and a fast CSPRNG.
//
// The CSPRNG uses AES-256-CTR seeded from crypto/rand, eliminating
// per-iteration syscalls to the OS entropy source.
//
// The Ed25519 key pair is generated once per worker and reused across
// iterations. Only the X25519 key varies per attempt. This halves the
// per-iteration curve operations (one ScalarBaseMult instead of two)
// while producing equally secure identities — the Ed25519 key is still
// randomly generated, just not re-rolled every attempt.
type workerState struct {
	rng cipher.Stream

	// Ed25519 key pair (generated once per worker, constant across iterations)
	edSeed [32]byte
	edPub  [32]byte

	// Per-iteration X25519 buffers
	xScalar [32]byte
	xPub    [32]byte

	// Hash computation buffers (reused every iteration)
	pubConcat [64]byte                         // x25519_pub || ed25519_pub
	destInput [NameHashLen + TruncatedLen]byte // name_hash || identity_hash
}

func newWorkerState(nameHash []byte) *workerState {
	var key [32]byte
	var iv [aes.BlockSize]byte
	if _, err := rand.Read(key[:]); err != nil {
		panic("seed RNG: " + err.Error())
	}
	if _, err := rand.Read(iv[:]); err != nil {
		panic("seed RNG: " + err.Error())
	}
	block, err := aes.NewCipher(key[:])
	if err != nil {
		panic("AES init: " + err.Error())
	}
	w := &workerState{
		rng: cipher.NewCTR(block, iv[:]),
	}

	// Pre-fill the constant name_hash portion of destInput
	copy(w.destInput[:NameHashLen], nameHash)

	// Generate Ed25519 key pair once — reused for all iterations
	w.fillRand(w.edSeed[:])
	edPriv := ed25519.NewKeyFromSeed(w.edSeed[:])
	copy(w.edPub[:], edPriv[32:])
	copy(w.pubConcat[32:], w.edPub[:]) // pre-fill constant half

	return w
}

// fillRand fills p with pseudorandom bytes from the AES-CTR stream.
func (w *workerState) fillRand(p []byte) {
	for i := range p {
		p[i] = 0
	}
	w.rng.XORKeyStream(p, p)
}

// generateAndCheck generates one X25519 key pair, computes the destination
// hash (using the pre-generated Ed25519 key), and checks it against all
// compiled patterns. Only allocates on match.
func (w *workerState) generateAndCheck(patterns []*compiledPattern) (keyResult, bool) {
	// Generate 32 random bytes for X25519 scalar
	w.fillRand(w.xScalar[:])

	// X25519 public key via libsodium (hand-optimized ARM64 assembly)
	scalarBaseMult(&w.xPub, &w.xScalar)

	// Identity hash: SHA256(x25519_pub || ed25519_pub)[:16]
	// ed25519_pub is pre-filled in w.pubConcat[32:]
	copy(w.pubConcat[:32], w.xPub[:])
	idFull := sha256.Sum256(w.pubConcat[:])

	// Dest hash: SHA256(name_hash || identity_hash)[:16]
	copy(w.destInput[NameHashLen:], idFull[:TruncatedLen])
	destFull := sha256.Sum256(w.destInput[:])

	for i, cp := range patterns {
		if cp.matchesHash(destFull[:TruncatedLen]) {
			// Match — build full result (allocations fine here, happens rarely)
			var privKey [64]byte
			copy(privKey[:32], w.xScalar[:])
			copy(privKey[32:], w.edSeed[:])

			var identityHash [16]byte
			copy(identityHash[:], idFull[:TruncatedLen])

			var hexBuf [32]byte
			hex.Encode(hexBuf[:], destFull[:TruncatedLen])

			return keyResult{
				PrivateKey:   privKey,
				IdentityHash: identityHash,
				DestHex:      string(hexBuf[:]),
				PatternIdx:   i,
			}, true
		}
	}

	return keyResult{}, false
}

// destHashFromIdentityHash computes the 16-byte destination hash (non-hot-path).
func destHashFromIdentityHash(nameHash, identityHash []byte) []byte {
	combined := make([]byte, len(nameHash)+len(identityHash))
	copy(combined, nameHash)
	copy(combined[len(nameHash):], identityHash)
	h := sha256.Sum256(combined)
	out := make([]byte, TruncatedLen)
	copy(out, h[:TruncatedLen])
	return out
}
