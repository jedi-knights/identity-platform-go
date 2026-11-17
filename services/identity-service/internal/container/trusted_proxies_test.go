package container

import "testing"

func TestParseTrustedProxies(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    int
		wantErr bool
	}{
		{"empty trusts no one", "", 0, false},
		{"blank entries ignored", " , ,", 0, false},
		{"v6 and v4 with spaces", "fdaa::/16, 10.0.0.0/8", 2, false},
		{"bare IP is not a CIDR", "10.0.0.1", 0, true},
		{"garbage fails startup", "fdaa::/16,nope", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseTrustedProxies(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if len(got) != tt.want {
				t.Errorf("got %d prefixes, want %d", len(got), tt.want)
			}
		})
	}
}
