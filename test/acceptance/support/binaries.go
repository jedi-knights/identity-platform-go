// Package support provides the acceptance-test harness: building and
// spawning real service binaries as child processes (Go's internal/
// package-visibility rule makes true in-process reuse of each service's
// container.go impossible from a sibling module — verified empirically,
// not assumed), a shared Redis container, and per-scenario fixture and
// SQLite-file isolation helpers.
package support

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
)

var (
	repoRootOnce sync.Once
	repoRootPath string

	buildMu    sync.Mutex
	builtPaths = map[string]string{}
	buildErrs  = map[string]error{}
)

// RepoRoot returns the absolute path to the repository root, computed from
// this file's own location so it is independent of whatever working
// directory `go test` happens to run from.
func RepoRoot() string {
	repoRootOnce.Do(func() {
		_, file, _, _ := runtime.Caller(0)
		// This file lives at test/acceptance/support/binaries.go.
		repoRootPath = filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
	})
	return repoRootPath
}

// BuildBinary compiles the given service's cmd package once per test-suite
// run and returns the path to the resulting binary. Safe for concurrent
// use under godog's parallel runner — the whole check-build-cache sequence
// is serialized by a single mutex, which only matters at suite startup
// (a handful of small Go binaries build in well under a second each) and
// never during scenario execution.
func BuildBinary(service string) (string, error) {
	buildMu.Lock()
	defer buildMu.Unlock()

	if path, ok := builtPaths[service]; ok {
		return path, nil
	}
	if err, ok := buildErrs[service]; ok {
		return "", err
	}

	outDir, err := os.MkdirTemp("", "acceptance-bin-")
	if err != nil {
		buildErrs[service] = err
		return "", err
	}
	outPath := filepath.Join(outDir, service)

	cmd := exec.Command("go", "build", "-o", outPath, "./cmd")
	cmd.Dir = filepath.Join(RepoRoot(), "services", service)
	if out, err := cmd.CombinedOutput(); err != nil {
		buildErr := fmt.Errorf("building %s: %w\n%s", service, err, out)
		buildErrs[service] = buildErr
		return "", buildErr
	}

	builtPaths[service] = outPath
	return outPath, nil
}
