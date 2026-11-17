package container

import (
	"testing"

	"github.com/jedi-knights/go-platform/testutil"

	"github.com/ocrosby/identity-platform-go/services/identity-service/internal/adapters/outbound/email"
	"github.com/ocrosby/identity-platform-go/services/identity-service/internal/config"
)

func TestNewEmailSender(t *testing.T) {
	smtpOK := config.EmailConfig{Sender: "smtp", SMTPHost: "smtp.example.com", SMTPPort: 587, From: "Id <noreply@example.com>"}
	tests := []struct {
		name     string
		cfg      config.EmailConfig
		wantSMTP bool
		wantErr  bool
	}{
		{"default is stdout", config.EmailConfig{}, false, false},
		{"noop", config.EmailConfig{Sender: "noop"}, false, false},
		{"smtp complete", smtpOK, true, false},
		{"smtp without from fails startup", config.EmailConfig{Sender: "smtp", SMTPHost: "h", SMTPPort: 587}, false, true},
		{"smtp without host fails startup", config.EmailConfig{Sender: "smtp", SMTPPort: 587, From: "a@example.com"}, false, true},
		{"unknown sender", config.EmailConfig{Sender: "pigeon"}, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := newEmailSender(tt.cfg, testutil.NewTestLogger())
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			_, isSMTP := got.(*email.SMTPSender)
			if isSMTP != tt.wantSMTP {
				t.Errorf("is SMTP sender = %v, want %v", isSMTP, tt.wantSMTP)
			}
		})
	}
}
