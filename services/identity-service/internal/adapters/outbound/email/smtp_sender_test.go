package email

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ocrosby/identity-platform-go/services/identity-service/internal/domain"
)

// received is one message as the fake server saw it.
type received struct {
	from, to string
	auth     string // decoded AUTH PLAIN payload, "" when none
	data     string // raw DATA section
}

// fakeSMTP is a minimal in-process SMTP server: enough of RFC 5321 for one
// message per connection, advertising AUTH PLAIN, with no STARTTLS.
type fakeSMTP struct {
	got      chan received
	rejectAt string // command prefix to answer with a 550, e.g. "RCPT"
	hang     bool   // accept the connection then say nothing
}

func startFakeSMTP(t *testing.T, f *fakeSMTP) (host string, port int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	f.got = make(chan received, 4)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(conn)
		}
	}()
	h, p, _ := net.SplitHostPort(ln.Addr().String())
	port, _ = strconv.Atoi(p)
	return h, port
}

func (f *fakeSMTP) serve(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	if f.hang {
		time.Sleep(5 * time.Second)
		return
	}
	r := bufio.NewReader(conn)
	say := func(s string) { _, _ = fmt.Fprint(conn, s+"\r\n") }
	say("220 fake ESMTP")
	var msg received
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		if f.rejectAt != "" && strings.HasPrefix(strings.ToUpper(line), f.rejectAt) {
			say("550 rejected")
			continue
		}
		if quit := f.command(line, r, say, &msg); quit {
			return
		}
	}
}

// command handles one client line; it reports true when the session is over.
func (f *fakeSMTP) command(line string, r *bufio.Reader, say func(string), msg *received) bool {
	up := strings.ToUpper(line)
	switch {
	case strings.HasPrefix(up, "EHLO"):
		say("250-fake\r\n250 AUTH PLAIN")
	case strings.HasPrefix(up, "AUTH PLAIN"):
		b, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(line[len("AUTH PLAIN"):]))
		msg.auth = strings.ReplaceAll(string(b), "\x00", "|")
		say("235 ok")
	case strings.HasPrefix(up, "MAIL FROM:"):
		msg.from = line[len("MAIL FROM:"):]
		say("250 ok")
	case strings.HasPrefix(up, "RCPT TO:"):
		msg.to = line[len("RCPT TO:"):]
		say("250 ok")
	case up == "DATA":
		say("354 go")
		msg.data = readData(r)
		say("250 queued")
		f.got <- *msg
	case up == "QUIT":
		say("221 bye")
		return true
	default:
		say("250 ok")
	}
	return false
}

func readData(r *bufio.Reader) string {
	var sb strings.Builder
	for {
		l, err := r.ReadString('\n')
		if err != nil || l == ".\r\n" {
			return sb.String()
		}
		sb.WriteString(l)
	}
}

func newTestSender(t *testing.T, host string, port int, mutate func(*SMTPConfig)) *SMTPSender {
	t.Helper()
	cfg := SMTPConfig{Host: host, Port: port, From: "Identity <noreply@example.com>", Timeout: 2 * time.Second}
	if mutate != nil {
		mutate(&cfg)
	}
	s, err := NewSMTPSender(cfg)
	if err != nil {
		t.Fatalf("NewSMTPSender: %v", err)
	}
	return s
}

func parse(t *testing.T, raw string) (*mail.Message, string) {
	t.Helper()
	m, err := mail.ReadMessage(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("delivered message does not parse: %v\n%s", err, raw)
	}
	b, err := io.ReadAll(quotedprintable.NewReader(m.Body))
	if err != nil {
		t.Fatalf("decoding body: %v", err)
	}
	return m, string(b)
}

func TestSMTPSender_DeliversPasswordResetEmail(t *testing.T) {
	f := &fakeSMTP{}
	host, port := startFakeSMTP(t, f)
	s := newTestSender(t, host, port, nil)
	url := "https://login.example.com/reset-password?token=abc_DEF-123"

	err := s.SendPasswordResetEmail(context.Background(), domain.PasswordResetEmail{To: "user@example.com", Name: "Ada Lovelace", ResetURL: url})

	if err != nil {
		t.Fatalf("send: %v", err)
	}
	got := <-f.got
	if !strings.Contains(got.from, "noreply@example.com") || !strings.Contains(got.to, "user@example.com") {
		t.Errorf("envelope from=%q to=%q, want noreply@example.com -> user@example.com", got.from, got.to)
	}
	m, body := parse(t, got.data)
	assertResetHeaders(t, m)
	if !strings.Contains(body, url) {
		t.Errorf("body does not contain the reset URL intact:\n%s", body)
	}
}

func assertResetHeaders(t *testing.T, m *mail.Message) {
	t.Helper()
	if !strings.Contains(strings.ToLower(m.Header.Get("Subject")), "reset") {
		t.Errorf("Subject = %q, want a password-reset subject", m.Header.Get("Subject"))
	}
	if to, _ := mail.ParseAddress(m.Header.Get("To")); to == nil || to.Address != "user@example.com" || to.Name != "Ada Lovelace" {
		t.Errorf("To header = %q, want Ada Lovelace <user@example.com>", m.Header.Get("To"))
	}
	if mt, _, _ := mime.ParseMediaType(m.Header.Get("Content-Type")); mt != "text/plain" {
		t.Errorf("Content-Type = %q, want text/plain", m.Header.Get("Content-Type"))
	}
}

func TestSMTPSender_DeliversVerificationEmail(t *testing.T) {
	f := &fakeSMTP{}
	host, port := startFakeSMTP(t, f)
	s := newTestSender(t, host, port, nil)
	url := "https://login.example.com/verify?token=xyz"

	if err := s.SendVerificationEmail(context.Background(), domain.VerificationEmail{To: "user@example.com", VerificationURL: url}); err != nil {
		t.Fatalf("send: %v", err)
	}
	m, body := parse(t, (<-f.got).data)
	if !strings.Contains(strings.ToLower(m.Header.Get("Subject")), "verify") || !strings.Contains(body, url) {
		t.Errorf("subject %q / body missing verification content:\n%s", m.Header.Get("Subject"), body)
	}
}

func TestSMTPSender_LongURLSurvivesLineLimits(t *testing.T) {
	f := &fakeSMTP{}
	host, port := startFakeSMTP(t, f)
	s := newTestSender(t, host, port, nil)
	url := "https://login.example.com/reset-password?token=" + strings.Repeat("a", 2000)

	if err := s.SendPasswordResetEmail(context.Background(), domain.PasswordResetEmail{To: "u@example.com", ResetURL: url}); err != nil {
		t.Fatalf("send: %v", err)
	}
	raw := (<-f.got).data
	for _, line := range strings.Split(raw, "\r\n") {
		if len(line) > 998 {
			t.Fatalf("line of %d bytes violates RFC 5322 limit", len(line))
		}
	}
	if _, body := parse(t, raw); !strings.Contains(body, url) {
		t.Error("long URL was corrupted in transit")
	}
}

func TestSMTPSender_AuthenticatesWhenCredentialsConfigured(t *testing.T) {
	f := &fakeSMTP{}
	host, port := startFakeSMTP(t, f)
	s := newTestSender(t, host, port, func(c *SMTPConfig) { c.Username, c.Password = "mailer", "s3cret" })

	if err := s.SendPasswordResetEmail(context.Background(), domain.PasswordResetEmail{To: "u@example.com", ResetURL: "https://x/y"}); err != nil {
		t.Fatalf("send: %v", err)
	}
	if got := (<-f.got).auth; got != "|mailer|s3cret" {
		t.Errorf("AUTH PLAIN payload = %q, want |mailer|s3cret", got)
	}
}

func TestSMTPSender_RejectsHeaderInjection(t *testing.T) {
	f := &fakeSMTP{}
	host, port := startFakeSMTP(t, f)
	s := newTestSender(t, host, port, nil)

	err := s.SendPasswordResetEmail(context.Background(), domain.PasswordResetEmail{To: "a@example.com\r\nBcc: evil@example.org", ResetURL: "https://x/y"})
	if err == nil {
		t.Fatal("recipient containing CRLF must be rejected")
	}

	// A hostile display name must be encoded, not become a new header.
	if err := s.SendPasswordResetEmail(context.Background(), domain.PasswordResetEmail{To: "a@example.com", Name: "Eve\r\nBcc: evil@example.org", ResetURL: "https://x/y"}); err != nil {
		t.Fatalf("hostile name should be neutralized, not fail: %v", err)
	}
	m, _ := parse(t, (<-f.got).data)
	if m.Header.Get("Bcc") != "" {
		t.Error("display name injected a Bcc header")
	}
	select {
	case extra := <-f.got:
		t.Errorf("unexpected second message delivered: %q", extra.to)
	default:
	}
}

func TestSMTPSender_ServerRejectionIsAnErrorWithoutLeakingSecrets(t *testing.T) {
	f := &fakeSMTP{rejectAt: "RCPT"}
	host, port := startFakeSMTP(t, f)
	s := newTestSender(t, host, port, func(c *SMTPConfig) { c.Username, c.Password = "mailer", "s3cret" })

	err := s.SendPasswordResetEmail(context.Background(), domain.PasswordResetEmail{To: "u@example.com", ResetURL: "https://x/y?token=SECRETTOKEN"})

	if err == nil {
		t.Fatal("expected an error when the server rejects the recipient")
	}
	for _, secret := range []string{"s3cret", "SECRETTOKEN"} {
		if strings.Contains(err.Error(), secret) {
			t.Errorf("error leaks %q: %v", secret, err)
		}
	}
}

func TestSMTPSender_HonorsTimeoutAndContext(t *testing.T) {
	f := &fakeSMTP{hang: true}
	host, port := startFakeSMTP(t, f)
	s := newTestSender(t, host, port, func(c *SMTPConfig) { c.Timeout = 300 * time.Millisecond })

	start := time.Now()
	err := s.SendPasswordResetEmail(context.Background(), domain.PasswordResetEmail{To: "u@example.com", ResetURL: "https://x/y"})

	if err == nil {
		t.Fatal("expected a timeout error from a server that never answers")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("send blocked %v, want it bounded by the configured timeout", elapsed)
	}
}

func TestNewSMTPSender_ValidatesConfig(t *testing.T) {
	tests := []struct {
		name string
		cfg  SMTPConfig
	}{
		{"missing host", SMTPConfig{Port: 587, From: "a@example.com"}},
		{"missing from", SMTPConfig{Host: "smtp.example.com", Port: 587}},
		{"from is not an address", SMTPConfig{Host: "smtp.example.com", Port: 587, From: "not an address"}},
		{"bad port", SMTPConfig{Host: "smtp.example.com", Port: 0, From: "a@example.com"}},
		{"username without password", SMTPConfig{Host: "smtp.example.com", Port: 587, From: "a@example.com", Username: "u"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewSMTPSender(tt.cfg); err == nil {
				t.Error("expected a configuration error")
			}
		})
	}
}
