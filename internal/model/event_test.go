package model

import (
	"strings"
	"testing"
)

func TestRedact(t *testing.T) {
	got := strings.Join(Redact([]string{"curl", "--token=abc", "--password", "def", "API_KEY=xyz", "https://example.test"}), " ")
	if got != "curl --token=[REDACTED] --password [REDACTED] API_KEY=[REDACTED] https://example.test" {
		t.Fatal(got)
	}
}

func TestAuthorizationHeaderRedaction(t *testing.T) {
	got := Redact([]string{"curl", "-H", "Authorization: Bearer sensitive-token", "url"})
	if got[2] != "Authorization: [REDACTED]" || got[3] != "url" {
		t.Fatal(got)
	}
}
