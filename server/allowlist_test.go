package main

import (
	"encoding/json"
	"sshlogger/internal/model"
	"strings"
	"testing"
)

func TestAllowlistLifecycleAndAgentCompatibility(t *testing.T) {
	a, h := fixture(t)
	cookie, csrf := admin(t, h)
	s := newServer(t, h, cookie, csrf, "allowlist-host")
	base := "/api/servers/" + s["id"]
	change := func(method, path string, body any, want int) {
		t.Helper()
		w := request(h, method, base+path, body, cookie, csrf, "")
		if w.Code != want {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
		}
	}
	ingest := func(supported bool, result *model.FirewallResult) *model.FirewallPolicy {
		t.Helper()
		w := request(h, "POST", "/api/ingest", model.Batch{CanFirewall: true, CanAllowlist: supported, FirewallResult: result, Health: "ok"}, "", "", s["token"])
		if w.Code != 200 {
			t.Fatal(w.Body.String())
		}
		var response model.IngestResponse
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		return response.Firewall
	}
	settings := map[string]any{"ports": []int{22, 2222}, "mode": "allowlist"}
	change("PUT", "/firewall/settings", map[string]any{"ports": []int{22}, "protected": []string{"192.0.2.2"}}, 202)
	change("PUT", "/firewall/settings", map[string]any{"ports": []int{2222}}, 202)
	if protected := ingest(false, nil).Protected; len(protected) != 1 || protected[0] != "192.0.2.2" {
		t.Fatal("port update erased legacy protection", protected)
	}
	// Upgrades retain existing bans; allowlist registration does not activate it.
	change("POST", "/bans", model.IPBan{IP: "203.0.113.99"}, 202)
	legacy := ingest(false, nil)
	if legacy.Mode != "" || len(legacy.Bans) != 1 {
		t.Fatal(legacy)
	}
	change("PUT", "/firewall/settings", settings, 400) // Empty.
	for _, ip := range []string{"127.0.0.1", "0.0.0.0", "192.0.2.0/24", "192.0.2.1; flush ruleset"} {
		change("POST", "/allowlist", map[string]string{"ip": ip}, 400)
	}
	change("POST", "/allowlist", map[string]string{"ip": "::ffff:192.0.2.1"}, 202)
	change("POST", "/allowlist", map[string]string{"ip": "192.0.2.1"}, 202)
	change("PUT", "/firewall/settings", settings, 400) // Old agent.
	p := ingest(true, nil)
	if p.Mode != "" || len(p.Bans) != 1 || len(p.Allowed) != 1 || p.Allowed[0] != "192.0.2.1" {
		t.Fatal(p)
	}
	change("PUT", "/firewall/settings", settings, 202)
	p = ingest(true, nil)
	if p.Mode != "allowlist" || len(p.Bans) != 0 || len(p.Ports) != 2 {
		t.Fatal(p)
	}
	// Never send new policy semantics to an old agent or trust its acknowledgement.
	if got := ingest(false, &model.FirewallResult{Revision: p.Revision}); got != nil {
		t.Fatal("allowlist sent to old agent", got)
	}
	var applied string
	a.store.db.QueryRow("SELECT applied_revision FROM firewall_policies WHERE server_id=?", s["id"]).Scan(&applied)
	if applied == p.Revision {
		t.Fatal("old agent marked allowlist applied")
	}
	ingest(true, &model.FirewallResult{Revision: p.Revision})
	change("DELETE", "/allowlist/192.0.2.1", nil, 400) // Last allowed IP cannot be removed while enabled.
	change("POST", "/bans", model.IPBan{IP: "192.0.2.5"}, 400)
	change("POST", "/allowlist", map[string]string{"ip": "2001:db8::1"}, 202)
	change("DELETE", "/allowlist/192.0.2.1", nil, 202)
	p = ingest(true, nil)
	if len(p.Allowed) != 1 || p.Allowed[0] != "2001:db8::1" {
		t.Fatal(p)
	}
	ingest(true, &model.FirewallResult{Revision: p.Revision})
	change("POST", "/revoke", nil, 409) // Enabled restrictions must not be orphaned.
	change("PUT", "/firewall/settings", map[string]any{"ports": []int{22}, "mode": "off"}, 202)
	change("DELETE", "/allowlist/2001:db8::1", nil, 202)
	change("POST", "/revoke", nil, 409) // Wait for removal acknowledgement.
	p = ingest(true, nil)
	if p.Mode != "off" || len(p.Allowed) != 0 || len(p.Bans) != 0 {
		t.Fatal(p)
	}
	ingest(true, &model.FirewallResult{Revision: p.Revision})
	change("POST", "/revoke", nil, 200)
}

func TestAllowlistAuthorization(t *testing.T) {
	_, h := fixture(t)
	cookie, csrf := admin(t, h)
	s := newServer(t, h, cookie, csrf, "assigned")
	hidden := newServer(t, h, cookie, csrf, "hidden")
	base := "/api/servers/" + s["id"]
	for _, auth := range []struct {
		cookie, csrf string
		status       int
	}{{"", "", 401}, {cookie, "", 403}} {
		for _, method := range []string{"POST", "PUT", "DELETE"} {
			path := base + "/allowlist"
			if method != "POST" {
				path += "/192.0.2.1"
			}
			w := request(h, method, path, map[string]string{"ip": "192.0.2.1"}, auth.cookie, auth.csrf, "")
			if w.Code != auth.status {
				t.Fatal(method, w.Code)
			}
		}
	}
	credentials := map[string]string{"username": "allow-operator", "password": "operator-password-123"}
	request(h, "POST", "/api/admins", credentials, cookie, csrf, "")
	request(h, "PUT", "/api/admins/allow-operator/access", map[string]any{"role": "admin", "server_ids": []string{s["id"]}}, cookie, csrf, "")
	w := request(h, "POST", "/api/login", credentials, "", "", "")
	var session map[string]string
	json.Unmarshal(w.Body.Bytes(), &session)
	oc, ot := w.Result().Cookies()[0].String(), session["csrf"]
	for _, tt := range []struct {
		method, path string
		body         any
		status       int
	}{
		{"POST", base + "/allowlist", map[string]string{"ip": "192.0.2.1"}, 202},
		{"PUT", base + "/allowlist/192.0.2.1", map[string]string{"name": "사무실"}, 202},
		{"DELETE", base + "/allowlist/192.0.2.1", nil, 202},
		{"PUT", base + "/firewall/settings", map[string]any{"ports": []int{22}, "mode": "allowlist"}, 403},
		{"POST", "/api/servers/" + hidden["id"] + "/allowlist", map[string]string{"ip": "192.0.2.1"}, 404},
		{"PUT", "/api/servers/" + hidden["id"] + "/allowlist/192.0.2.1", map[string]string{"name": "사무실"}, 404},
		{"DELETE", "/api/servers/" + hidden["id"] + "/allowlist/192.0.2.1", nil, 404},
	} {
		w = request(h, tt.method, tt.path, tt.body, oc, ot, "")
		if w.Code != tt.status {
			t.Fatal(tt.path, w.Code, w.Body.String())
		}
	}
}

func TestAllowedIPNames(t *testing.T) {
	_, h := fixture(t)
	cookie, csrf := admin(t, h)
	s := newServer(t, h, cookie, csrf, "named-ips")
	base := "/api/servers/" + s["id"]
	change := func(method, path string, body any, want int) {
		t.Helper()
		w := request(h, method, base+path, body, cookie, csrf, "")
		if w.Code != want {
			t.Fatalf("%s %s: %d %s", method, path, w.Code, w.Body.String())
		}
	}
	read := func() model.FirewallPolicy {
		t.Helper()
		w := request(h, "GET", base+"/firewall", nil, cookie, csrf, "")
		var response struct {
			Policy model.FirewallPolicy `json:"policy"`
		}
		if w.Code != 200 {
			t.Fatal(w.Body.String())
		}
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		return response.Policy
	}
	change("POST", "/allowlist", map[string]string{"ip": "::ffff:192.0.2.1", "name": " 사무실 "}, 202)
	change("POST", "/allowlist", map[string]string{"ip": "192.0.2.1"}, 202)
	p := read()
	if len(p.Allowed) != 1 || p.AllowedNames["192.0.2.1"] != "사무실" {
		t.Fatal(p)
	}
	change("PUT", "/allowlist/192.0.2.1", map[string]string{"name": "자택"}, 202)
	p = read()
	if len(p.Allowed) != 1 || p.Allowed[0] != "192.0.2.1" || p.AllowedNames["192.0.2.1"] != "자택" {
		t.Fatal(p)
	}
	revision := p.Revision
	change("PUT", "/allowlist/192.0.2.1", map[string]string{"ip": "192.0.2.2", "name": "변경"}, 400)
	change("PUT", "/allowlist/192.0.2.1", map[string]string{}, 400)
	change("PUT", "/allowlist/192.0.2.2", map[string]string{"name": "없는 IP"}, 400)
	change("PUT", "/allowlist/192.0.2.1", map[string]string{"name": strings.Repeat("가", 101)}, 400)
	if read().Revision != revision {
		t.Fatal("invalid update changed policy")
	}
	change("PUT", "/allowlist/192.0.2.1", map[string]string{"name": strings.Repeat("가", 100)}, 202)
	change("PUT", "/allowlist/192.0.2.1", map[string]string{"name": " "}, 202)
	if len(read().AllowedNames) != 0 {
		t.Fatal("name was not cleared")
	}
	change("POST", "/allowlist", map[string]string{"ip": "2001:db8::1", "name": "IPv6"}, 202)
	change("PUT", "/allowlist/2001:db8::1", map[string]string{"name": "새 이름"}, 202)
	change("DELETE", "/allowlist/2001:db8::1", nil, 202)
	if len(read().AllowedNames) != 0 {
		t.Fatal("deleted IP retained its name")
	}
	change("POST", "/allowlist", map[string]string{"ip": "192.0.2.3", "name": strings.Repeat("a", 101)}, 400)
	if len(read().Allowed) != 1 {
		t.Fatal("invalid registration changed allowed IPs")
	}
}
