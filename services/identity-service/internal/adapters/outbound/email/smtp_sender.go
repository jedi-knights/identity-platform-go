package email

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"github.com/ocrosby/identity-platform-go/services/identity-service/internal/domain"
)

// Compile-time interface check.
var _ domain.EmailSender = (*SMTPSender)(nil)

// defaultSMTPTimeout bounds one whole delivery (dial through QUIT) when
// SMTPConfig.Timeout is zero. net/smtp has no timeouts of its own, and the
// callers are HTTP requests that must not hang on a slow mail relay.
const defaultSMTPTimeout = 15 * time.Second

// SMTPConfig configures SMTPSender.
type SMTPConfig struct {
	Host string
	Port int // submission (587, STARTTLS) is the supported mode; implicit TLS (465) is not

	// Username/Password enable AUTH PLAIN. Both or neither. PLAIN is only
	// ever sent over TLS (or to localhost): net/smtp refuses otherwise, so a
	// relay that does not offer STARTTLS cannot be handed credentials.
	Username string
	Password string

	// From is the envelope and header sender, e.g. "Identity <noreply@example.com>".
	From string

	// Timeout bounds one delivery. Zero selects defaultSMTPTimeout.
	Timeout time.Duration
}

// SMTPSender delivers plain-text mail through an SMTP relay, upgrading to TLS
// via STARTTLS whenever the relay offers it. It dials per message: reset and
// verification mail is low volume and a held-open connection would need
// reconnect and idle-timeout handling for no benefit.
type SMTPSender struct {
	cfg  SMTPConfig
	from *mail.Address
}

// NewSMTPSender validates cfg and returns a sender. Misconfiguration is an
// error here, at startup, rather than a failed email the first time a user
// asks for a reset.
func NewSMTPSender(cfg SMTPConfig) (*SMTPSender, error) {
	if strings.TrimSpace(cfg.Host) == "" {
		return nil, errors.New("smtp host is required")
	}
	if cfg.Port < 1 || cfg.Port > 65535 {
		return nil, fmt.Errorf("smtp port %d out of range", cfg.Port)
	}
	if (cfg.Username == "") != (cfg.Password == "") {
		return nil, errors.New("smtp username and password must be set together")
	}
	from, err := mail.ParseAddress(cfg.From)
	if err != nil {
		return nil, fmt.Errorf("smtp from address: %w", err)
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultSMTPTimeout
	}
	return &SMTPSender{cfg: cfg, from: from}, nil
}

// SendVerificationEmail sends the account-verification link.
func (s *SMTPSender) SendVerificationEmail(ctx context.Context, msg domain.VerificationEmail) error {
	body := greeting(msg.Name) +
		"Confirm your email address by opening this link:\n\n" + msg.VerificationURL + "\n\n" +
		"If you didn't create an account, you can ignore this email.\n"
	return s.send(ctx, msg.To, msg.Name, "Verify your email address", body)
}

// SendPasswordResetEmail sends the password-reset link.
func (s *SMTPSender) SendPasswordResetEmail(ctx context.Context, msg domain.PasswordResetEmail) error {
	body := greeting(msg.Name) +
		"Choose a new password by opening this link. It works once and expires soon:\n\n" + msg.ResetURL + "\n\n" +
		"If you didn't ask to reset your password, you can ignore this email; your password has not changed.\n"
	return s.send(ctx, msg.To, msg.Name, "Reset your password", body)
}

func greeting(name string) string {
	if n := sanitizeHeaderText(name); n != "" {
		return "Hi " + n + ",\n\n"
	}
	return "Hello,\n\n"
}

// sanitizeHeaderText drops control characters so caller-supplied text can
// never terminate a header line and start a new one.
func sanitizeHeaderText(s string) string {
	return strings.TrimSpace(strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s))
}

// send builds and delivers one message. Errors name the failing SMTP stage
// only: they must not echo the body (a token) or the credentials.
func (s *SMTPSender) send(ctx context.Context, to, name, subject, body string) error {
	rcpt, err := mail.ParseAddress(to)
	if err != nil {
		return errors.New("invalid recipient address")
	}
	rcpt.Name = sanitizeHeaderText(name)

	raw, err := s.compose(rcpt, subject, body)
	if err != nil {
		return err
	}
	return s.deliver(ctx, rcpt.Address, raw)
}

// compose renders the RFC 5322 message. The body is quoted-printable so long
// URLs are wrapped under the 998-byte line limit and decode back intact.
func (s *SMTPSender) compose(rcpt *mail.Address, subject, body string) ([]byte, error) {
	id, err := messageID(s.from.Address)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	hdr := func(k, v string) { buf.WriteString(k + ": " + v + "\r\n") }
	hdr("From", s.from.String())
	hdr("To", rcpt.String())
	hdr("Subject", subject)
	hdr("Date", time.Now().UTC().Format(time.RFC1123Z))
	hdr("Message-ID", id)
	hdr("MIME-Version", "1.0")
	hdr("Content-Type", `text/plain; charset="utf-8"`)
	hdr("Content-Transfer-Encoding", "quoted-printable")
	buf.WriteString("\r\n")

	qp := quotedprintable.NewWriter(&buf)
	if _, err := qp.Write([]byte(body)); err != nil {
		return nil, fmt.Errorf("encoding email body: %w", err)
	}
	if err := qp.Close(); err != nil {
		return nil, fmt.Errorf("encoding email body: %w", err)
	}
	return buf.Bytes(), nil
}

func messageID(fromAddr string) (string, error) {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generating message id: %w", err)
	}
	domainPart := fromAddr[strings.LastIndex(fromAddr, "@")+1:]
	return "<" + hex.EncodeToString(b[:]) + "@" + domainPart + ">", nil
}

// deliver runs one SMTP transaction. A single deadline covers every stage,
// and cancelling ctx closes the connection so a blocked read returns.
func (s *SMTPSender) deliver(ctx context.Context, rcpt string, raw []byte) error {
	deadline := time.Now().Add(s.cfg.Timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	dialCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	var dialer net.Dialer
	conn, err := dialer.DialContext(dialCtx, "tcp", net.JoinHostPort(s.cfg.Host, strconv.Itoa(s.cfg.Port)))
	if err != nil {
		return errors.New("smtp: connecting to relay failed")
	}
	defer context.AfterFunc(dialCtx, func() { _ = conn.Close() })()
	if err := conn.SetDeadline(deadline); err != nil {
		_ = conn.Close()
		return errors.New("smtp: setting deadline failed")
	}
	c, err := smtp.NewClient(conn, s.cfg.Host)
	if err != nil {
		_ = conn.Close()
		return errors.New("smtp: relay greeting failed")
	}
	// Close after QUIT only releases the socket; its error cannot change whether
	// the message was accepted, which is already decided by transact.
	defer func() { _ = c.Close() }()
	return s.transact(c, rcpt, raw)
}

// Server reply text (code + message) is included in rejection errors: it never
// contains our credentials or the message body.
//
// transact performs STARTTLS, AUTH and the mail transaction on c.
func (s *SMTPSender) transact(c *smtp.Client, rcpt string, raw []byte) error {
	if err := s.secure(c); err != nil {
		return err
	}
	steps := []struct {
		stage string
		do    func() error
	}{
		{"MAIL FROM", func() error { return c.Mail(s.from.Address) }},
		{"RCPT TO", func() error { return c.Rcpt(rcpt) }},
	}
	for _, st := range steps {
		if err := st.do(); err != nil {
			return fmt.Errorf("smtp: %s rejected: %w", st.stage, err)
		}
	}
	if err := writeData(c, raw); err != nil {
		return err
	}
	// The relay accepted the message at DATA; a failed QUIT does not undo that.
	_ = c.Quit()
	return nil
}

func writeData(c *smtp.Client, raw []byte) error {
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("smtp: DATA rejected: %w", err)
	}
	if _, err := w.Write(raw); err != nil {
		return errors.New("smtp: writing message failed")
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("smtp: message not accepted: %w", err)
	}
	return nil
}

// secure upgrades the connection with STARTTLS when offered, then
// authenticates if credentials are configured.
func (s *SMTPSender) secure(c *smtp.Client) error {
	if ok, _ := c.Extension("STARTTLS"); ok {
		if err := c.StartTLS(&tls.Config{ServerName: s.cfg.Host, MinVersion: tls.VersionTLS12}); err != nil {
			return errors.New("smtp: STARTTLS failed")
		}
	}
	if s.cfg.Username == "" {
		return nil
	}
	if err := c.Auth(smtp.PlainAuth("", s.cfg.Username, s.cfg.Password, s.cfg.Host)); err != nil {
		return errors.New("smtp: authentication failed")
	}
	return nil
}
