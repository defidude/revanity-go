package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math"
	"regexp"
	"strings"
)

// matchMode represents the type of pattern matching to perform.
type matchMode int

const (
	modePrefix matchMode = iota
	modeSuffix
	modeContains
	modeRegex
)

func (m matchMode) String() string {
	switch m {
	case modePrefix:
		return "prefix"
	case modeSuffix:
		return "suffix"
	case modeContains:
		return "contains"
	case modeRegex:
		return "regex"
	}
	return "unknown"
}

// compiledPattern is a ready-to-use pattern matcher.
type compiledPattern struct {
	mode    matchMode
	pattern string
	regex   *regexp.Regexp

	// Byte-level matching for prefix/suffix (avoids hex encoding in hot path)
	bytePattern []byte // full bytes to compare
	byteOffset  int    // offset in hash where comparison starts
	nibbleCheck bool   // whether there's an extra nibble to verify
	nibbleIdx   int    // byte index in hash for the nibble
	nibbleMask  byte   // 0xf0 (high nibble) or 0x0f (low nibble)
	nibbleValue byte   // expected value after masking

	// For contains mode: pattern as raw ASCII hex bytes
	patternHex []byte
}

// newCompiledPattern creates a compiled pattern from a mode and pattern string.
// For hex-based modes (prefix/suffix/contains), the pattern is validated and lowercased.
// For regex mode, the pattern is compiled as a case-insensitive regex.
func newCompiledPattern(mode matchMode, pattern string) (*compiledPattern, error) {
	cp := &compiledPattern{mode: mode}

	if mode == modeRegex {
		re, err := regexp.Compile("(?i)" + pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid regex: %w", err)
		}
		cp.pattern = pattern
		cp.regex = re
		return cp, nil
	}

	cleaned, err := validateHexPattern(pattern)
	if err != nil {
		return nil, err
	}
	cp.pattern = cleaned

	switch mode {
	case modePrefix:
		cp.setupPrefixBytes(cleaned)
	case modeSuffix:
		cp.setupSuffixBytes(cleaned)
	case modeContains:
		cp.patternHex = []byte(cleaned)
	}

	return cp, nil
}

// setupPrefixBytes prepares byte-level prefix matching.
// Even-length: compare full bytes at start of hash.
// Odd-length: compare full bytes + check high nibble of the next byte.
func (cp *compiledPattern) setupPrefixBytes(hexStr string) {
	n := len(hexStr)
	nFull := n / 2
	if nFull > 0 {
		cp.bytePattern, _ = hex.DecodeString(hexStr[:nFull*2])
		cp.byteOffset = 0
	}
	if n%2 == 1 {
		cp.nibbleCheck = true
		cp.nibbleIdx = nFull
		cp.nibbleMask = 0xf0
		cp.nibbleValue = hexNibble(hexStr[n-1]) << 4
	}
}

// setupSuffixBytes prepares byte-level suffix matching.
// Even-length: compare full bytes at end of hash.
// Odd-length: check low nibble of the byte before full bytes, then compare full bytes.
func (cp *compiledPattern) setupSuffixBytes(hexStr string) {
	n := len(hexStr)
	nFull := n / 2

	if n%2 == 1 {
		cp.nibbleCheck = true
		cp.nibbleIdx = TruncatedLen - nFull - 1
		cp.nibbleMask = 0x0f
		cp.nibbleValue = hexNibble(hexStr[0])
		if nFull > 0 {
			cp.bytePattern, _ = hex.DecodeString(hexStr[1:])
			cp.byteOffset = TruncatedLen - nFull
		}
	} else if nFull > 0 {
		cp.bytePattern, _ = hex.DecodeString(hexStr)
		cp.byteOffset = TruncatedLen - nFull
	}
}

// hexNibble converts a lowercase hex char to its 4-bit value.
func hexNibble(c byte) byte {
	if c >= '0' && c <= '9' {
		return c - '0'
	}
	return c - 'a' + 10
}

// matchesHash checks a 16-byte raw hash against the pattern.
// For prefix/suffix: compares bytes directly (no hex encoding on the hot path).
// For contains/regex: hex-encodes into a stack-allocated buffer.
func (cp *compiledPattern) matchesHash(hash []byte) bool {
	switch cp.mode {
	case modePrefix, modeSuffix:
		if len(cp.bytePattern) > 0 {
			if !bytes.Equal(hash[cp.byteOffset:cp.byteOffset+len(cp.bytePattern)], cp.bytePattern) {
				return false
			}
		}
		if cp.nibbleCheck {
			if hash[cp.nibbleIdx]&cp.nibbleMask != cp.nibbleValue {
				return false
			}
		}
		return true

	case modeContains:
		var buf [32]byte
		hex.Encode(buf[:], hash)
		return bytes.Contains(buf[:], cp.patternHex)

	case modeRegex:
		var buf [32]byte
		hex.Encode(buf[:], hash)
		return cp.regex.Match(buf[:])
	}
	return false
}

// matches tests if a 32-char lowercase hex address matches the pattern (non-hot-path).
func (cp *compiledPattern) matches(hexAddr string) bool {
	switch cp.mode {
	case modePrefix:
		return strings.HasPrefix(hexAddr, cp.pattern)
	case modeSuffix:
		return strings.HasSuffix(hexAddr, cp.pattern)
	case modeContains:
		return strings.Contains(hexAddr, cp.pattern)
	case modeRegex:
		return cp.regex.MatchString(hexAddr)
	}
	return false
}

// validateHexPattern validates and lowercases a hex pattern string.
func validateHexPattern(pattern string) (string, error) {
	cleaned := strings.ToLower(strings.TrimSpace(pattern))
	if cleaned == "" {
		return "", fmt.Errorf("pattern cannot be empty")
	}
	for _, c := range cleaned {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return "", fmt.Errorf("pattern '%s' contains non-hex characters; only 0-9 and a-f are valid", pattern)
		}
	}
	if len(cleaned) > 32 {
		return "", fmt.Errorf("pattern length %d exceeds maximum address length of 32 hex chars", len(cleaned))
	}
	return cleaned, nil
}

// difficulty holds the result of a difficulty estimation.
type difficulty struct {
	ExpectedAttempts int64
	SecondsPerCore   float64
	DifficultyDesc   string
	CanEstimate      bool
}

// estimateDifficulty estimates expected attempts and time to find a match.
func estimateDifficulty(mode matchMode, pattern string) difficulty {
	if mode == modeRegex {
		return difficulty{
			DifficultyDesc: "Cannot estimate for regex",
			CanEstimate:    false,
		}
	}

	n := len(pattern)
	var expected float64

	switch mode {
	case modePrefix, modeSuffix:
		expected = math.Pow(16, float64(n))
	case modeContains:
		positions := math.Max(1, float64(32-n+1))
		expected = math.Pow(16, float64(n)) / positions
	}

	keysPerSec := 5000.0 // conservative single-core estimate
	secs := expected / keysPerSec

	var desc string
	switch {
	case expected < 100:
		desc = "Instant"
	case expected < 100_000:
		desc = "Seconds"
	case expected < 10_000_000:
		desc = "Minutes"
	case expected < 1_000_000_000:
		desc = "Hours"
	case expected < 100_000_000_000:
		desc = "Days"
	default:
		desc = "Weeks+ (consider a shorter pattern)"
	}

	return difficulty{
		ExpectedAttempts: int64(expected),
		SecondsPerCore:   secs,
		DifficultyDesc:   desc,
		CanEstimate:      true,
	}
}
