package model

import "testing"

func TestAllowlistPolicyValidation(t *testing.T) {
	valid := FirewallPolicy{Revision: "allowlist", Ports: []int{22}, Mode: "allowlist", Allowed: []string{"192.0.2.1", "2001:db8::1"}}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name   string
		modify func(*FirewallPolicy)
	}{
		{"empty active list", func(p *FirewallPolicy) { p.Allowed = nil }},
		{"duplicate", func(p *FirewallPolicy) { p.Allowed = []string{"192.0.2.1", "192.0.2.1"} }},
		{"noncanonical", func(p *FirewallPolicy) { p.Allowed = []string{"::ffff:192.0.2.1"} }},
		{"injection", func(p *FirewallPolicy) { p.Allowed = []string{"192.0.2.1; flush ruleset"} }},
		{"subnet", func(p *FirewallPolicy) { p.Allowed = []string{"192.0.2.0/24"} }},
		{"mixed policies", func(p *FirewallPolicy) { p.Bans = []IPBan{{IP: "192.0.2.2"}} }},
		{"unknown mode", func(p *FirewallPolicy) { p.Mode = "unknown" }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := valid
			tt.modify(&p)
			if p.Validate() == nil {
				t.Fatal("invalid policy accepted")
			}
		})
	}
	valid.Mode = "off"
	valid.Allowed = nil
	if err := valid.Validate(); err != nil {
		t.Fatal("empty disabled policy rejected", err)
	}
}
