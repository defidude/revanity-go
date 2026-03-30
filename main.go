package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"
)

const version = "1.0.0"

func formatTime(d time.Duration) string {
	secs := d.Seconds()
	switch {
	case secs < 1:
		return fmt.Sprintf("%.0fms", secs*1000)
	case secs < 60:
		return fmt.Sprintf("%.1fs", secs)
	case secs < 3600:
		return fmt.Sprintf("%.1fm", secs/60)
	case secs < 86400:
		return fmt.Sprintf("%.1fh", secs/3600)
	default:
		return fmt.Sprintf("%.1fd", secs/86400)
	}
}

func formatRate(rate float64) string {
	switch {
	case rate < 1000:
		return fmt.Sprintf("%.0f", rate)
	case rate < 1_000_000:
		return fmt.Sprintf("%.1fK", rate/1000)
	default:
		return fmt.Sprintf("%.2fM", rate/1_000_000)
	}
}

func main() {
	// Flags
	prefix := flag.String("prefix", "", "Find address starting with this hex string")
	suffix := flag.String("suffix", "", "Find address ending with this hex string")
	contains := flag.String("contains", "", "Find address containing this hex string anywhere")
	regex := flag.String("regex", "", "Find address matching this regex pattern")
	dest := flag.String("dest", "lxmf.delivery", "Destination type")
	workers := flag.Int("workers", 0, "Number of worker goroutines (default: auto)")
	output := flag.String("output", "", "Output file path prefix (default: ./<dest_hash>)")
	loop := flag.Bool("loop", false, "Search continuously, saving each match")
	dryRun := flag.Bool("dry-run", false, "Show difficulty estimate without searching")
	quiet := flag.Bool("quiet", false, "Minimal output (just the result address)")
	showVersion := flag.Bool("version", false, "Show version")

	// Short aliases
	flag.StringVar(prefix, "p", "", "")
	flag.StringVar(suffix, "s", "", "")
	flag.StringVar(contains, "c", "", "")
	flag.StringVar(regex, "r", "", "")
	flag.StringVar(dest, "d", "lxmf.delivery", "")
	flag.IntVar(workers, "w", 0, "")
	flag.StringVar(output, "o", "", "")
	flag.BoolVar(loop, "l", false, "")
	flag.BoolVar(quiet, "q", false, "")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "revanity-go - Reticulum/LXMF Vanity Address Generator\n\n")
		fmt.Fprintf(os.Stderr, "Usage: revanity-go [options]\n\n")
		fmt.Fprintf(os.Stderr, "Pattern (exactly one required, comma-separated for multi-pattern):\n")
		fmt.Fprintf(os.Stderr, "  -prefix, -p HEX      Find address starting with hex string\n")
		fmt.Fprintf(os.Stderr, "  -suffix, -s HEX      Find address ending with hex string\n")
		fmt.Fprintf(os.Stderr, "  -contains, -c HEX    Find address containing hex string\n")
		fmt.Fprintf(os.Stderr, "  -regex, -r PATTERN   Find address matching regex pattern\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		fmt.Fprintf(os.Stderr, "  -dest, -d TYPE       Destination type (default: lxmf.delivery)\n")
		fmt.Fprintf(os.Stderr, "  -workers, -w NUM     Number of worker goroutines (default: auto)\n")
		fmt.Fprintf(os.Stderr, "  -output, -o PATH     Output directory for loop mode (default: results/)\n")
		fmt.Fprintf(os.Stderr, "  -loop, -l            Search continuously, saving each match\n")
		fmt.Fprintf(os.Stderr, "  -dry-run             Show difficulty estimate without searching\n")
		fmt.Fprintf(os.Stderr, "  -quiet, -q           Minimal output (just the result address)\n")
		fmt.Fprintf(os.Stderr, "  -version             Show version\n\n")
		fmt.Fprintf(os.Stderr, "Examples:\n")
		fmt.Fprintf(os.Stderr, "  revanity-go -prefix dead\n")
		fmt.Fprintf(os.Stderr, "  revanity-go -suffix cafe -workers 8\n")
		fmt.Fprintf(os.Stderr, "  revanity-go -contains beef\n")
		fmt.Fprintf(os.Stderr, "  revanity-go -regex \"^(dead|beef)\"\n")
		fmt.Fprintf(os.Stderr, "  revanity-go -prefix dead -loop    # find all matches continuously\n")
		fmt.Fprintf(os.Stderr, "  revanity-go -prefix aa,bb,cc      # find all three patterns\n")
	}

	flag.Parse()

	if *showVersion {
		fmt.Printf("revanity-go %s\n", version)
		os.Exit(0)
	}

	// Determine mode and pattern (exactly one must be set)
	var mode matchMode
	var patternRaw string
	set := 0

	if *prefix != "" {
		mode = modePrefix
		patternRaw = *prefix
		set++
	}
	if *suffix != "" {
		mode = modeSuffix
		patternRaw = *suffix
		set++
	}
	if *contains != "" {
		mode = modeContains
		patternRaw = *contains
		set++
	}
	if *regex != "" {
		mode = modeRegex
		patternRaw = *regex
		set++
	}

	if set == 0 {
		fmt.Fprintln(os.Stderr, "Error: exactly one pattern flag is required (-prefix, -suffix, -contains, or -regex)")
		flag.Usage()
		os.Exit(1)
	}
	if set > 1 {
		fmt.Fprintln(os.Stderr, "Error: only one pattern flag can be used at a time")
		os.Exit(1)
	}

	// Split comma-separated patterns
	patterns := strings.Split(patternRaw, ",")
	for i := range patterns {
		patterns[i] = strings.TrimSpace(patterns[i])
	}

	// Create generator
	gen, err := newVanityGenerator(patterns, mode, *dest, *workers)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	multiMode := len(gen.PatternStrs) > 1

	if !*quiet {
		fmt.Printf("revanity-go v%s\n", version)
		if multiMode {
			fmt.Printf("  Patterns:    %s=[%s] (%d patterns)\n", mode, strings.Join(gen.PatternStrs, ", "), len(gen.PatternStrs))
		} else {
			fmt.Printf("  Pattern:     %s='%s'\n", mode, gen.PatternStrs[0])
		}
		fmt.Printf("  Destination: %s\n", *dest)
		fmt.Printf("  Workers:     %d\n", gen.NumWorkers)
		if *loop {
			fmt.Printf("  Mode:        continuous (loop)\n")
		} else if multiMode {
			fmt.Printf("  Mode:        multi-pattern (stops when all found)\n")
		}
		if !multiMode {
			diff := estimateDifficulty(mode, gen.PatternStrs[0])
			if diff.CanEstimate {
				fmt.Printf("  Expected:    ~%s attempts per match\n", formatNumber(diff.ExpectedAttempts))
			}
			fmt.Printf("  Difficulty:  %s\n", diff.DifficultyDesc)
		}
		fmt.Println()
	}

	if *dryRun {
		os.Exit(0)
	}

	// Handle Ctrl+C gracefully
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	if *loop || multiMode {
		runLoopMode(gen, ctx, mode, *output, *quiet, *loop, multiMode)
		return
	}

	if !*quiet {
		fmt.Println("Searching...")
	}

	// Progress callback
	onProgress := func(stats generatorStats) {
		if *quiet {
			return
		}
		fmt.Fprintf(os.Stderr,
			"\r  Checked: %s  |  Rate: %s/sec  |  Elapsed: %s  ",
			formatNumber(int64(stats.TotalChecked)),
			formatRate(stats.Rate),
			formatTime(stats.Elapsed),
		)
	}

	result := gen.runBlocking(ctx, 500*time.Millisecond, onProgress)

	if !*quiet {
		fmt.Fprintln(os.Stderr)
	}

	if result == nil {
		fmt.Fprintln(os.Stderr, "No results found (search was interrupted).")
		os.Exit(1)
	}

	export := prepareExport(result.PrivateKey, result.IdentityHash, result.DestType, result.DestHashHex)

	if !*quiet {
		sep := strings.Repeat("=", 60)
		fmt.Printf("\n%s\n", sep)
		fmt.Println("  MATCH FOUND")
		if lxmf, ok := export.DestHashes["lxmf.delivery"]; ok {
			fmt.Printf("  LXMF Address:   %s\n", lxmf)
		}
		if nomad, ok := export.DestHashes["nomadnetwork.node"]; ok {
			fmt.Printf("  NomadNet Node:  %s\n", nomad)
		}
		fmt.Printf("  Identity Hash:  %s\n", export.IdentityHashHex)
		fmt.Printf("  Time:           %s\n", formatTime(result.Elapsed))
		fmt.Printf("  Keys Checked:   %s\n", formatNumber(int64(result.TotalChecked)))
		fmt.Printf("  Rate:           %s/sec\n", formatRate(result.Rate))
		fmt.Printf("%s\n", sep)
	}

	outPrefix := *output
	if outPrefix == "" {
		outPrefix = result.DestHashHex
	}

	identityPath, err := saveIdentityFile(result.PrivateKey, outPrefix+".identity")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error saving identity file: %v\n", err)
		os.Exit(1)
	}

	textPath, err := saveIdentityText(export, outPrefix+".txt")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error saving text file: %v\n", err)
		os.Exit(1)
	}

	if !*quiet {
		fmt.Printf("\n  Saved identity: %s\n", identityPath)
		fmt.Printf("  Saved info:     %s\n", textPath)
	}

	if *quiet {
		fmt.Println(result.DestHashHex)
	}
}

func runLoopMode(gen *vanityGenerator, ctx context.Context, mode matchMode, output string, quiet bool, loop bool, multiMode bool) {
	outDir := output
	if outDir == "" {
		outDir = "results"
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating output directory: %v\n", err)
		os.Exit(1)
	}

	jsonlPath := filepath.Join(outDir, fmt.Sprintf("%s_%s.jsonl", mode, strings.Join(gen.PatternStrs, ",")))
	foundCount := 0

	// Track which patterns have been satisfied (for multi-pattern auto-stop)
	foundPerPattern := make(map[int]int) // patternIdx -> count
	totalPatterns := len(gen.PatternStrs)

	// Wrap context so we can cancel when all patterns are found
	searchCtx, searchCancel := context.WithCancel(ctx)
	defer searchCancel()

	if !quiet {
		if multiMode && !loop {
			fmt.Printf("Searching for %d patterns (Ctrl+C to stop)...\n", totalPatterns)
		} else {
			fmt.Println("Searching continuously (Ctrl+C to stop)...")
		}
	}

	onProgress := func(stats generatorStats) {
		if quiet {
			return
		}
		if multiMode {
			satisfied := len(foundPerPattern)
			fmt.Fprintf(os.Stderr,
				"\r  Checked: %s  |  Rate: %s/sec  |  Elapsed: %s  |  Found: %d (%d/%d patterns)  ",
				formatNumber(int64(stats.TotalChecked)),
				formatRate(stats.Rate),
				formatTime(stats.Elapsed),
				foundCount,
				satisfied,
				totalPatterns,
			)
		} else {
			fmt.Fprintf(os.Stderr,
				"\r  Checked: %s  |  Rate: %s/sec  |  Elapsed: %s  |  Found: %d  ",
				formatNumber(int64(stats.TotalChecked)),
				formatRate(stats.Rate),
				formatTime(stats.Elapsed),
				foundCount,
			)
		}
	}

	onResult := func(result *generatorResult) {
		foundCount++
		foundPerPattern[result.PatternIdx]++
		isDuplicate := foundPerPattern[result.PatternIdx] > 1

		export := prepareExport(result.PrivateKey, result.IdentityHash, result.DestType, result.DestHashHex)

		if err := appendResultJSONL(jsonlPath, export, result); err != nil {
			fmt.Fprintf(os.Stderr, "\nError saving result: %v\n", err)
		}

		identityPath := filepath.Join(outDir, result.DestHashHex+".identity")
		if _, err := saveIdentityFile(result.PrivateKey, identityPath); err != nil {
			fmt.Fprintf(os.Stderr, "\nError saving identity file: %v\n", err)
		}

		if quiet {
			fmt.Println(result.DestHashHex)
		} else {
			fmt.Fprintf(os.Stderr, "\n")
			dupTag := ""
			if isDuplicate {
				dupTag = " (duplicate)"
			}
			if multiMode {
				fmt.Printf("  [Match #%d] %s  pattern='%s'%s  (%s, %s checked)\n",
					foundCount,
					result.DestHashHex,
					result.PatternStr,
					dupTag,
					formatTime(result.Elapsed),
					formatNumber(int64(result.TotalChecked)),
				)
			} else {
				fmt.Printf("  [Match #%d] %s  (%s, %s checked)\n",
					foundCount,
					result.DestHashHex,
					formatTime(result.Elapsed),
					formatNumber(int64(result.TotalChecked)),
				)
			}
		}

		// Auto-stop when all patterns satisfied (multi-pattern without loop)
		if multiMode && !loop && len(foundPerPattern) >= totalPatterns {
			searchCancel()
		}
	}

	gen.runLoop(searchCtx, 500*time.Millisecond, onProgress, onResult)

	if !quiet {
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Printf("\nSearch stopped. Found %d matching identities", foundCount)
		if multiMode {
			fmt.Printf(" across %d/%d patterns", len(foundPerPattern), totalPatterns)
		}
		fmt.Println(".")
		fmt.Printf("Results: %s\n", jsonlPath)
	}
}

// formatNumber adds comma separators to an integer.
func formatNumber(n int64) string {
	if n < 0 {
		return "-" + formatNumber(-n)
	}
	s := fmt.Sprintf("%d", n)
	if len(s) <= 3 {
		return s
	}

	var result strings.Builder
	remainder := len(s) % 3
	if remainder > 0 {
		result.WriteString(s[:remainder])
	}
	for i := remainder; i < len(s); i += 3 {
		if result.Len() > 0 {
			result.WriteByte(',')
		}
		result.WriteString(s[i : i+3])
	}
	return result.String()
}

