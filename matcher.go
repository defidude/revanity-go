package main

import (
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
	return cp, nil
}

// matches tests if a 32-char lowercase hex address matches the pattern.
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
	ExpectedAttempts     int64
	SecondsPerCore       float64
	DifficultyDesc       string
	CanEstimate          bool
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
