package main

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// generatorResult holds a single vanity address match with stats.
type generatorResult struct {
	PrivateKey   [64]byte
	IdentityHash [16]byte
	DestHashHex  string
	DestType     string
	Elapsed      time.Duration
	TotalChecked uint64
	Rate         float64
}

// generatorStats holds live stats during generation.
type generatorStats struct {
	TotalChecked uint64
	Elapsed      time.Duration
	Rate         float64
	IsRunning    bool
}

// vanityGenerator orchestrates parallel vanity address generation using goroutines.
type vanityGenerator struct {
	PatternStr string
	Pattern    *compiledPattern
	NameHash   []byte
	DestType   string
	NumWorkers int

	counter   atomic.Uint64
	startTime time.Time
	cancel    context.CancelFunc
	ctx       context.Context
	resultCh  chan keyResult
	wg        sync.WaitGroup
}

// newVanityGenerator creates a new generator, validating inputs.
func newVanityGenerator(pattern string, mode matchMode, destType string, numWorkers int) (*vanityGenerator, error) {
	cp, err := newCompiledPattern(mode, pattern)
	if err != nil {
		return nil, err
	}

	nameHash, ok := destNameHashes[destType]
	if !ok {
		if !strings.Contains(destType, ".") {
			return nil, fmt.Errorf("invalid destination type: %s (use format 'app.aspect')", destType)
		}
		nameHash = computeNameHash(destType)
	}

	if numWorkers <= 0 {
		numWorkers = runtime.NumCPU() - 1
		if numWorkers < 1 {
			numWorkers = 1
		}
	}

	return &vanityGenerator{
		PatternStr: cp.pattern,
		Pattern:    cp,
		NameHash:   nameHash,
		DestType:   destType,
		NumWorkers: numWorkers,
	}, nil
}

// start launches worker goroutines.
func (g *vanityGenerator) start(parentCtx context.Context) {
	g.ctx, g.cancel = context.WithCancel(parentCtx)
	g.resultCh = make(chan keyResult, 1)
	g.startTime = time.Now()
	g.counter.Store(0)

	for i := 0; i < g.NumWorkers; i++ {
		g.wg.Add(1)
		go g.worker()
	}
}

// worker runs a tight key generation loop until a match is found or context is cancelled.
func (g *vanityGenerator) worker() {
	defer g.wg.Done()

	nameHash := g.NameHash
	pattern := g.Pattern
	const batchSize = 500

	for {
		select {
		case <-g.ctx.Done():
			return
		default:
		}

		for i := 0; i < batchSize; i++ {
			result := generateAndHash(nameHash)
			if pattern.matches(result.DestHex) {
				g.counter.Add(uint64(i + 1))
				select {
				case g.resultCh <- result:
				default:
				}
				g.cancel()
				return
			}
		}
		g.counter.Add(batchSize)
	}
}

// stats returns current generation statistics.
func (g *vanityGenerator) stats() generatorStats {
	elapsed := time.Since(g.startTime)
	total := g.counter.Load()
	rate := 0.0
	if elapsed > 0 {
		rate = float64(total) / elapsed.Seconds()
	}
	return generatorStats{
		TotalChecked: total,
		Elapsed:      elapsed,
		Rate:         rate,
		IsRunning:    g.ctx.Err() == nil,
	}
}

// stop cancels all workers and waits for them to finish.
func (g *vanityGenerator) stop() {
	g.cancel()
	g.wg.Wait()
}

// runBlocking runs the generator synchronously with periodic progress callbacks.
// Returns the result if found, or nil if interrupted.
func (g *vanityGenerator) runBlocking(parentCtx context.Context, progressInterval time.Duration, onProgress func(generatorStats)) *generatorResult {
	g.start(parentCtx)

	ticker := time.NewTicker(progressInterval)
	defer ticker.Stop()

	for {
		select {
		case result := <-g.resultCh:
			// Match found
			elapsed := time.Since(g.startTime)
			total := g.counter.Load()
			rate := 0.0
			if elapsed > 0 {
				rate = float64(total) / elapsed.Seconds()
			}
			g.stop()
			return &generatorResult{
				PrivateKey:   result.PrivateKey,
				IdentityHash: result.IdentityHash,
				DestHashHex:  result.DestHex,
				DestType:     g.DestType,
				Elapsed:      elapsed,
				TotalChecked: total,
				Rate:         rate,
			}

		case <-ticker.C:
			if onProgress != nil {
				onProgress(g.stats())
			}

		case <-parentCtx.Done():
			// External cancellation (e.g., Ctrl+C)
			g.stop()
			return nil
		}
	}
}
