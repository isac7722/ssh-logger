package main

import (
	"encoding/json"
	"sshlogger/internal/model"
	"strings"
	"testing"
)

func TestFirewallLifecycleAndIsolation(t *testing.T) {
	a, h := fixture(t)
	cookie, csrf := admin(t, h)
	s := newServer(t, h, cookie, csrf, "host")
	other := newServer(t, h, cookie, csrf, "other")
	base := "/api/servers/" + s["id"]
	ingest := func(token string, result *model.FirewallResult) *model.FirewallPolicy {
		t.Helper()
		w := request(h, "POST", "/api/ingest", model.Batch{CanFirewall: true, FirewallResult: result, Health: "ok"}, "", "", token)
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		var r model.IngestResponse
		json.Unmarshal(w.Body.Bytes(), &r)
		if r.Firewall == nil {
			t.Fatal("missing policy")
		}
		return r.Firewall
	}
	change := func(method, path string, body any, want int) {
		t.Helper()
		w := request(h, method, base+path, body, cookie, csrf, "")
		if w.Code != want {
			t.Fatal(path, w.Code, w.Body.String())
		}
	}
	for _, credentials := range []struct {
		cookie, csrf string
		want         int
	}{{"", "", 401}, {cookie, "", 403}} {
		w := request(h, "POST", base+"/bans", model.IPBan{IP: "203.0.113.1"}, credentials.cookie, credentials.csrf, "")
		if w.Code != credentials.want {
			t.Fatal(w.Code)
		}
	}
	change("PUT", "/firewall/settings", map[string]any{"ports": []int{22, 2222}, "protected": []string{"203.0.113.1", "2001:db8::1"}}, 202)
	for _, ip := range []string{"203.0.113.1", "::ffff:203.0.113.1", "2001:db8::1", "127.0.0.1", "0.0.0.0", "::1", "2001:db8::1%eth0", "1.2.3.4; flush ruleset", "192.0.2.0/24"} {
		change("POST", "/bans", model.IPBan{IP: ip}, 400)
	}
	change("POST", "/bans", model.IPBan{IP: "::ffff:203.0.113.8"}, 202)
	change("POST", "/bans", model.IPBan{IP: "2001:db8::8", Disconnect: true}, 202)
	if w := request(h, "POST", base+"/revoke", nil, cookie, csrf, ""); w.Code != 409 {
		t.Fatal("banned server revoked", w.Code)
	}
	p := ingest(s["token"], nil)
	if len(p.Bans) != 2 || p.Bans[0].IP != "203.0.113.8" || !p.Bans[1].Disconnect {
		t.Fatal(p)
	}
	ingest(other["token"], &model.FirewallResult{Revision: p.Revision})
	var applied, errText string
	a.store.db.QueryRow("SELECT applied_revision FROM firewall_policies WHERE server_id=?", s["id"]).Scan(&applied)
	if applied != "" {
		t.Fatal("foreign ack accepted")
	}
	ingest(s["token"], &model.FirewallResult{Revision: p.Revision, Error: "permission denied"})
	a.store.db.QueryRow("SELECT error FROM firewall_policies WHERE server_id=?", s["id"]).Scan(&errText)
	if errText != "permission denied" {
		t.Fatal(errText)
	}
	ingest(s["token"], &model.FirewallResult{Revision: p.Revision})
	a.store.db.QueryRow("SELECT applied_revision FROM firewall_policies WHERE server_id=?", s["id"]).Scan(&applied)
	if applied != p.Revision {
		t.Fatal(applied)
	}
	change("DELETE", "/bans/203.0.113.8", nil, 202)
	next := ingest(s["token"], &model.FirewallResult{Revision: p.Revision})
	if len(next.Bans) != 1 || next.Revision == p.Revision {
		t.Fatal(next)
	}
	a.store.db.QueryRow("SELECT applied_revision FROM firewall_policies WHERE server_id=?", s["id"]).Scan(&applied)
	if applied == next.Revision {
		t.Fatal("stale ack accepted")
	}
	change("DELETE", "/bans/2001:db8::8", nil, 202)
	if w := request(h, "POST", base+"/revoke", nil, cookie, csrf, ""); w.Code != 409 {
		t.Fatal("unacknowledged unban allowed revocation", w.Code)
	}
	final := ingest(s["token"], nil)
	if len(final.Bans) != 0 || len(final.Ports) != 2 || len(final.Protected) != 2 {
		t.Fatal(final)
	}
	ingest(s["token"], &model.FirewallResult{Revision: final.Revision})
	// Offline policies stay pending, with the requester and history preserved.
	w := request(h, "GET", base+"/firewall", nil, cookie, csrf, "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"requested_by":"admin"`) || !strings.Contains(w.Body.String(), `"action":"unban"`) {
		t.Fatal(w.Body.String())
	}
	if w := request(h, "POST", base+"/revoke", nil, cookie, csrf, ""); w.Code != 200 {
		t.Fatal("settled unban prevented revocation", w.Code)
	}
	// Use the other server to check old protocol compatibility.
	s = other
	// Old agents remain able to deliver logs but do not receive firewall commands.
	w = request(h, "POST", "/api/ingest", model.Batch{}, "", "", s["token"])
	if w.Code != 200 || strings.Contains(w.Body.String(), `"firewall":`) {
		t.Fatal(w.Body.String())
	}
}
