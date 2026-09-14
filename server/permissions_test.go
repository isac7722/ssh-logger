package main

import (
	"encoding/json"
	"net/http"
	"sshlogger/internal/model"
	"strings"
	"testing"
	"time"
)

func newServer(t *testing.T, h http.Handler, cookie, csrf, name string) map[string]string {
	t.Helper()
	w := request(h, "POST", "/api/servers", map[string]string{"name": name}, cookie, csrf, "")
	if w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	var s map[string]string
	json.Unmarshal(w.Body.Bytes(), &s)
	return s
}
func TestServerAssignmentsEnforcedEverywhere(t *testing.T) {
	a, h := fixture(t)
	cookie, csrf := admin(t, h)
	s1 := newServer(t, h, cookie, csrf, "visible")
	s2 := newServer(t, h, cookie, csrf, "hidden")
	for _, s := range []map[string]string{s1, s2} {
		b := model.Batch{CanTerminate: true, CanFirewall: true, Health: "ok", ActiveSessions: []string{"boot:7"}, Events: []model.Event{{ID: "e", Time: time.Now().UnixMilli(), Kind: "session_start", SessionID: "boot:7", User: s["name"], IP: "203.0.113.5"}}}
		if w := request(h, "POST", "/api/ingest", b, "", "", s["token"]); w.Code != 200 {
			t.Fatal(w.Body.String())
		}
	}
	credentials := map[string]string{"username": "operator", "password": "operator-password-123"}
	if w := request(h, "POST", "/api/admins", credentials, cookie, csrf, ""); w.Code != 201 {
		t.Fatal(w.Body.String())
	}
	w := request(h, "POST", "/api/login", credentials, "", "", "")
	var session map[string]string
	json.Unmarshal(w.Body.Bytes(), &session)
	oc := w.Result().Cookies()[0].String()
	ot := session["csrf"]
	for _, path := range []string{"/api/servers", "/api/events", "/api/sessions"} {
		if w = request(h, "GET", path, nil, oc, ot, ""); w.Code != 200 || strings.TrimSpace(w.Body.String()) != "[]" {
			t.Fatal(path, w.Body.String())
		}
	}
	assign := func(role string, ids []string, want int) {
		t.Helper()
		w := request(h, "PUT", "/api/admins/operator/access", map[string]any{"role": role, "server_ids": ids}, cookie, csrf, "")
		if w.Code != want {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	assign("admin", []string{s1["id"]}, 200)
	for _, path := range []string{"/api/servers", "/api/events", "/api/sessions", "/api/events?summary=1"} {
		w = request(h, "GET", path, nil, oc, ot, "")
		if w.Code != 200 || strings.Contains(w.Body.String(), "hidden") || !strings.Contains(w.Body.String(), "visible") {
			t.Fatal(path, w.Body.String())
		}
	}
	w = request(h, "GET", "/api/overview", nil, oc, ot, "")
	var totals []map[string]int
	json.Unmarshal(w.Body.Bytes(), &totals)
	if len(totals) != 1 || totals[0]["total"] != 1 || totals[0]["logins"] != 1 || totals[0]["active"] != 1 {
		t.Fatal(w.Body.String())
	}
	for _, path := range []string{"/api/events?server_id=" + s2["id"], "/api/sessions?server_id=" + s2["id"]} {
		w = request(h, "GET", path, nil, oc, ot, "")
		if strings.TrimSpace(w.Body.String()) != "[]" {
			t.Fatal(path, w.Body.String())
		}
	}
	for _, tt := range []struct {
		method, path string
		body         any
		want         int
	}{
		{"GET", "/api/admins", nil, 403}, {"GET", "/api/settings", nil, 403},
		{"POST", "/api/servers/" + s2["id"] + "/rotate", nil, 404}, {"POST", "/api/servers/" + s2["id"] + "/revoke", nil, 404},
		{"PUT", "/api/admins/operator/access", map[string]any{"role": "super_admin"}, 403},
		{"GET", "/api/servers/" + s2["id"] + "/firewall", nil, 404},
		{"POST", "/api/servers/" + s2["id"] + "/bans", model.IPBan{IP: "203.0.113.5"}, 404},
		{"DELETE", "/api/servers/" + s2["id"] + "/bans/203.0.113.5", nil, 404},
		{"POST", "/api/servers/" + s2["id"] + "/sessions/boot:7/terminate", nil, 404},
		{"POST", "/api/servers/" + s1["id"] + "/sessions/boot:7/terminate", nil, 202},
		{"POST", "/api/servers/" + s1["id"] + "/bans", model.IPBan{IP: "203.0.113.5"}, 202},
		{"PUT", "/api/servers/" + s1["id"] + "/firewall/settings", map[string]any{"ports": []int{22}}, 403},
	} {
		w = request(h, tt.method, tt.path, tt.body, oc, ot, "")
		if w.Code != tt.want {
			t.Fatal(tt.path, w.Code, w.Body.String())
		}
	}
	// Invalid replacement rolls back the existing assignment.
	assign("admin", []string{"missing"}, 400)
	var n int
	a.store.db.QueryRow("SELECT COUNT(*) FROM admin_servers WHERE username='operator'").Scan(&n)
	if n != 1 {
		t.Fatal(n)
	}
	assign("admin", nil, 200)
	if w = request(h, "GET", "/api/servers", nil, oc, ot, ""); strings.TrimSpace(w.Body.String()) != "[]" {
		t.Fatal("live session retained access", w.Body.String())
	}
	if w = request(h, "PUT", "/api/admins/admin/access", map[string]any{"role": "admin", "server_ids": []string{}}, cookie, csrf, ""); w.Code != 400 {
		t.Fatal("last super admin demoted", w.Code)
	}
	assign("super_admin", nil, 200)
	if w = request(h, "GET", "/api/servers", nil, oc, ot, ""); !strings.Contains(w.Body.String(), "hidden") {
		t.Fatal("promotion not effective", w.Body.String())
	}
}
