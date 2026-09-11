package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sshlogger/internal/model"
	"testing"
	"time"
)

func TestRevokedServerIsSoftDeletedFromAllViews(t *testing.T) {
	a, h := fixture(t)
	cookie, csrf := admin(t, h)
	now := time.Now().UnixMilli()
	create := func(name string, extra int) map[string]string {
		t.Helper()
		w := request(h, "POST", "/api/servers", map[string]string{"name": name}, cookie, csrf, "")
		if w.Code != 201 {
			t.Fatal(w.Code, w.Body.String())
		}
		var server map[string]string
		if err := json.Unmarshal(w.Body.Bytes(), &server); err != nil {
			t.Fatal(err)
		}
		events := []model.Event{
			{ID: "start", Time: now, Kind: "session_start", SessionID: "boot:1", User: "alice"},
			{ID: "failure", Time: now, Kind: "login_failure"},
			{ID: "exec", Time: now, Kind: "exec", SessionID: "boot:1", Program: "/usr/bin/id", Args: []string{"id"}},
		}
		for i := 0; i < extra; i++ {
			events = append(events, model.Event{ID: fmt.Sprintf("extra-%d", i), Time: now + 1, Kind: "exec", Program: "/usr/bin/id", Args: []string{"id"}})
		}
		w = request(h, "POST", "/api/ingest", model.Batch{Events: events, Health: "ok", ActiveSessions: []string{"boot:1"}}, "", "", server["token"])
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		return server
	}
	kept := create("kept", 0)
	removed := create("removed", 60)
	// An offline session must also disappear from the unknown-session count.
	if _, err := a.store.db.Exec("UPDATE servers SET last_seen=0 WHERE id=?", removed["id"]); err != nil {
		t.Fatal(err)
	}
	w := request(h, "POST", "/api/servers/"+removed["id"]+"/revoke", nil, cookie, csrf, "")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	for _, test := range []struct {
		path  string
		count int
	}{
		{"/api/servers", 1}, {"/api/events", 3}, {"/api/sessions", 1}, {"/api/sessions?active=1", 1},
		{"/api/events?server_id=" + removed["id"], 0}, {"/api/sessions?server_id=" + removed["id"], 0},
	} {
		w = request(h, "GET", test.path, nil, cookie, "", "")
		var rows []map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil || w.Code != 200 || len(rows) != test.count {
			t.Fatalf("%s: %d %s (%v)", test.path, w.Code, w.Body.String(), err)
		}
		for _, row := range rows {
			if row["server_id"] == removed["id"] || row["id"] == removed["id"] {
				t.Fatalf("deleted server visible: %s", test.path)
			}
		}
	}
	w = request(h, "GET", "/api/events?summary=1&activity=all", nil, cookie, "", "")
	var summary struct {
		Total   int              `json:"total_count"`
		Visible int              `json:"visible_count"`
		Items   []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &summary); err != nil || w.Code != 200 || summary.Total != 3 || summary.Visible != 3 || len(summary.Items) != 3 {
		t.Fatal(w.Code, w.Body.String(), err)
	}
	w = request(h, "GET", "/api/overview", nil, cookie, "", "")
	var overview []map[string]int
	if err := json.Unmarshal(w.Body.Bytes(), &overview); err != nil || w.Code != 200 || len(overview) != 1 {
		t.Fatal(w.Code, w.Body.String(), err)
	}
	for key, want := range map[string]int{"total": 1, "healthy": 1, "active": 1, "unknown": 0, "logins": 1, "failures": 1} {
		if overview[0][key] != want {
			t.Fatalf("overview %s: got %d want %d", key, overview[0][key], want)
		}
	}
	for _, action := range []string{"rotate", "revoke"} {
		if w = request(h, "POST", "/api/servers/"+removed["id"]+"/"+action, nil, cookie, csrf, ""); w.Code != 404 {
			t.Fatalf("deleted server %s: %d", action, w.Code)
		}
	}
	if w = request(h, "POST", "/api/ingest", model.Batch{Health: "ok"}, "", "", removed["token"]); w.Code != http.StatusUnauthorized {
		t.Fatal("deleted server can ingest", w.Code)
	}
	if w = request(h, "POST", "/api/servers/"+kept["id"]+"/rotate", nil, cookie, csrf, ""); w.Code != 200 {
		t.Fatal("active server cannot rotate", w.Code)
	}
	var revoked, events, sessions int
	err := a.store.db.QueryRow("SELECT revoked,(SELECT COUNT(*) FROM events WHERE server_id=s.id),(SELECT COUNT(*) FROM sessions WHERE server_id=s.id) FROM servers s WHERE id=?", removed["id"]).Scan(&revoked, &events, &sessions)
	if err != nil || revoked != 1 || events != 63 || sessions != 1 {
		t.Fatalf("records were not retained: revoked=%d events=%d sessions=%d err=%v", revoked, events, sessions, err)
	}
}
