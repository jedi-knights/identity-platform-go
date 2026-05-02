// Package weighted provides a CDF-based weighted random URL picker and a
// transport decorator that routes requests across a pool of upstream endpoints
// according to per-entry weights.
//
// Design: Strategy pattern — Picker implements a weighted variant of URL
// selection that degrades gracefully to uniform random choice when all weights
// are equal or no weights are specified, making it a compatible replacement
// for roundrobin.Picker in mixed-weight deployments.
package weighted

import (
	"math/rand"
	"sort"
	"sync"
)

// cdfEntry caches the cumulative distribution function for a route's URL pool.
// Built once per route name on first Pick call; reused for all subsequent calls.
// Routes are static (no hot-reload of route weights), so the cache never expires.
type cdfEntry struct {
	urls  []string
	cdf   []int // cdf[i] = sum of weights[0..i]; used for binary-search selection
	total int   // sum of all positive weights; 0 means all weights were ≤ 0
}

// Picker selects a URL from a weighted pool using CDF-based random selection.
//
// When all weights are equal or no weights are provided the selection degrades
// to uniform random choice (equal probability for each URL).
//
// Thread-safe: CDF entries are cached in a sync.Map with LoadOrStore semantics
// so concurrent first-requests for the same route are safe without locking.
type Picker struct {
	cache sync.Map // routeName → *cdfEntry
}

// NewPicker creates a Picker with no pre-allocated state.
func NewPicker() *Picker {
	return &Picker{}
}

// Pick returns a URL selected from urls for routeName using weighted random choice.
//
// urls and weights must be parallel slices (same length). When weights is nil,
// empty, or all values are equal the selection is uniform random. Entries with
// weight ≤ 0 are excluded from selection.
func (p *Picker) Pick(routeName string, urls []string, weights []int) string {
	if len(urls) == 0 {
		return ""
	}
	if len(urls) == 1 {
		return urls[0]
	}
	if len(weights) == 0 || allEqual(weights) {
		return urls[rand.Intn(len(urls))]
	}
	return p.weightedPick(routeName, urls, weights)
}

// weightedPick performs the CDF binary-search selection for non-uniform weights.
func (p *Picker) weightedPick(routeName string, urls []string, weights []int) string {
	entry := p.getCDF(routeName, urls, weights)
	if entry.total <= 0 {
		return urls[rand.Intn(len(urls))]
	}
	n := rand.Intn(entry.total)
	idx := sort.SearchInts(entry.cdf, n+1)
	if idx >= len(entry.urls) {
		return entry.urls[len(entry.urls)-1]
	}
	return entry.urls[idx]
}

// getCDF returns the cached CDF entry for routeName, computing it on first call.
func (p *Picker) getCDF(routeName string, urls []string, weights []int) *cdfEntry {
	if v, ok := p.cache.Load(routeName); ok {
		return v.(*cdfEntry)
	}
	entry := buildCDF(urls, weights)
	actual, _ := p.cache.LoadOrStore(routeName, entry)
	return actual.(*cdfEntry)
}

// buildCDF computes the cumulative distribution function from urls and weights.
// Entries with weight ≤ 0 contribute 0 to the CDF (they can never be selected).
func buildCDF(urls []string, weights []int) *cdfEntry {
	cdf := make([]int, len(urls))
	total := 0
	for i, w := range weights {
		if w > 0 {
			total += w
		}
		cdf[i] = total
	}
	return &cdfEntry{urls: urls, cdf: cdf, total: total}
}

// allEqual reports whether all values in s are identical.
// Returns true for nil and empty slices.
func allEqual(s []int) bool {
	if len(s) == 0 {
		return true
	}
	first := s[0]
	for _, v := range s[1:] {
		if v != first {
			return false
		}
	}
	return true
}
