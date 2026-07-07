package support

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"time"
)

// RunningService is a spawned service process bound to a local port.
type RunningService struct {
	Name    string
	BaseURL string

	cmd    *exec.Cmd
	exited <-chan error
	output *bytes.Buffer
}

// FreePort asks the OS for an unused TCP port on 127.0.0.1. There is a
// small, unavoidable race between closing the probe listener and the
// child process binding the same port — standard practice for this kind
// of port allocation in test harnesses, and acceptable here.
func FreePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, fmt.Errorf("allocating free port: %w", err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// StartService spawns binaryPath with the current process's environment
// plus env, and waits for it to accept TCP connections on port before
// returning. If the process exits before becoming ready, its captured
// stdout/stderr is included in the returned error instead of waiting out
// the full timeout.
func StartService(ctx context.Context, name, binaryPath string, port int, env []string) (*RunningService, error) {
	cmd := exec.CommandContext(ctx, binaryPath)
	cmd.Env = append(os.Environ(), env...)
	output := &bytes.Buffer{}
	cmd.Stdout = output
	cmd.Stderr = output

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting %s: %w", name, err)
	}

	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	if err := waitForReady(addr, 10*time.Second, exited); err != nil {
		_ = cmd.Process.Kill()
		return nil, fmt.Errorf("waiting for %s to become ready: %w\noutput:\n%s", name, err, output.String())
	}

	return &RunningService{
		Name:    name,
		BaseURL: "http://" + addr,
		cmd:     cmd,
		exited:  exited,
		output:  output,
	}, nil
}

// waitForReady polls addr until a TCP connection succeeds, the process
// exits early, or timeout elapses.
func waitForReady(addr string, timeout time.Duration, exited <-chan error) error {
	deadline := time.After(timeout)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case err := <-exited:
			return fmt.Errorf("process exited early: %v", err)
		case <-deadline:
			return fmt.Errorf("timed out after %s", timeout)
		case <-ticker.C:
			if conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond); err == nil {
				_ = conn.Close()
				return nil
			}
		}
	}
}

// Stop terminates the service process and waits for it to exit. The
// process's Wait() was already consumed by the background goroutine
// StartService launched, so Stop only kills and drains that channel —
// calling cmd.Wait() again here would panic ("Wait was already called").
func (s *RunningService) Stop() {
	if s.cmd.Process != nil {
		_ = s.cmd.Process.Kill()
	}
	<-s.exited
}

// Output returns everything the process wrote to stdout/stderr, for
// diagnostics when a step fails against this service.
func (s *RunningService) Output() string {
	return s.output.String()
}
