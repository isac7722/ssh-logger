package model

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
)

type Event struct {
	ID            string   `json:"id"`
	Time          int64    `json:"time"`
	Kind          string   `json:"kind"`
	SessionID     string   `json:"session_id"`
	User          string   `json:"user"`
	LoginUID      string   `json:"login_uid"`
	EffectiveUser string   `json:"effective_user"`
	IP            string   `json:"ip"`
	Program       string   `json:"program"`
	Args          []string `json:"args"`
	Outcome       string   `json:"outcome"`
	PID           *int     `json:"pid,omitempty"`
	PPID          *int     `json:"ppid,omitempty"`
}
type Termination struct {
	ID        string `json:"id"`
	SessionID string `json:"session_id"`
	Expires   int64  `json:"expires"`
}
type TerminationResult struct {
	ID    string `json:"id"`
	Error string `json:"error"`
}
type IngestResponse struct {
	Firewall     *FirewallPolicy `json:"firewall,omitempty"`
	Accepted     int             `json:"accepted"`
	Terminations []Termination   `json:"terminations,omitempty"`
}
type Batch struct {
	CanFirewall        bool                `json:"can_firewall,omitempty"`
	CanAllowlist       bool                `json:"can_allowlist,omitempty"`
	FirewallResult     *FirewallResult     `json:"firewall_result,omitempty"`
	CanTerminate       bool                `json:"can_terminate,omitempty"`
	TerminationResults []TerminationResult `json:"termination_results,omitempty"`
	Events             []Event             `json:"events"`
	Health             string              `json:"health"`
	Backlog            int                 `json:"backlog"`
	Dropped            int64               `json:"dropped"`
	ActiveSessions     []string            `json:"active_sessions"`
}

func ID() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// Redact before an argument is persisted locally or centrally. This is a
// best-effort filter; arbitrary secrets in positional arguments are unknowable.
func Redact(args []string) []string {
	out := make([]string, len(args))
	hide := false
	for i, a := range args {
		if hide {
			out[i] = "[REDACTED]"
			hide = false
			continue
		}
		lower := strings.ToLower(a)
		sensitive := false
		for _, key := range []string{"password", "passwd", "token", "secret", "api-key", "api_key", "authorization"} {
			if strings.Contains(lower, key) {
				sensitive = true
				break
			}
		}
		if sensitive {
			if p := strings.IndexByte(a, '='); p >= 0 {
				out[i] = a[:p+1] + "[REDACTED]"
			} else if p := strings.IndexByte(a, ':'); p >= 0 {
				out[i] = a[:p+1] + " [REDACTED]"
			} else if strings.ContainsAny(a, " \t\n") {
				out[i] = "[REDACTED]"
			} else {
				out[i] = a
				hide = true
			}
		} else {
			out[i] = a
		}
	}
	return out
}
