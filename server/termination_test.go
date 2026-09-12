package main

import (
	"encoding/json"
	"sshlogger/internal/model"
	"testing"
	"time"
)

func TestSessionTerminationLifecycle(t *testing.T) {
	a, h := fixture(t)
	cookie, csrf := admin(t, h)
	w := request(h, "POST", "/api/servers", map[string]string{"name": "host"}, cookie, csrf, "")
	var server map[string]string
	json.Unmarshal(w.Body.Bytes(), &server)
	sid := "boot:42"
	now := time.Now().UnixMilli()
	b := model.Batch{Health: "ok", ActiveSessions: []string{sid}, Events: []model.Event{{ID: "start", Time: now, Kind: "session_start", SessionID: sid}}}
	ingest := func(b model.Batch) model.IngestResponse {
		t.Helper()
		w := request(h, "POST", "/api/ingest", b, "", "", server["token"])
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		var response model.IngestResponse
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		return response
	}
	ingest(b)
	path := "/api/servers/" + server["id"] + "/sessions/" + sid + "/terminate"
	for _, tt := range []struct {
		cookie, csrf string
		want         int
	}{{"", "", 401}, {cookie, "", 403}, {cookie, csrf, 409}} {
		if w := request(h, "POST", path, nil, tt.cookie, tt.csrf, ""); w.Code != tt.want {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	b.CanTerminate = true
	ingest(b)
	for i := 0; i < 2; i++ {
		if w := request(h, "POST", path, nil, cookie, csrf, ""); w.Code != 202 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	response := ingest(b)
	if len(response.Terminations) != 1 {
		t.Fatal(response)
	}
	command := response.Terminations[0]
	var requester string
	if err := a.store.db.QueryRow("SELECT requested_by FROM session_terminations WHERE id=?", command.ID).Scan(&requester); err != nil || requester != "admin" {
		t.Fatal(requester, err)
	}
	// A different server cannot consume or acknowledge this command.
	w = request(h, "POST", "/api/servers", map[string]string{"name": "other"}, cookie, csrf, "")
	var other map[string]string
	json.Unmarshal(w.Body.Bytes(), &other)
	w = request(h, "POST", "/api/ingest", model.Batch{CanTerminate: true, TerminationResults: []model.TerminationResult{{ID: command.ID}}}, "", "", other["token"])
	var foreign model.IngestResponse
	json.Unmarshal(w.Body.Bytes(), &foreign)
	if w.Code != 200 || len(foreign.Terminations) != 0 {
		t.Fatal(w.Body.String())
	}
	if len(ingest(b).Terminations) != 1 {
		t.Fatal("foreign acknowledgement changed request")
	}
	b.TerminationResults = []model.TerminationResult{{ID: command.ID, Error: "permission denied"}}
	if len(ingest(b).Terminations) != 0 {
		t.Fatal("completed request redelivered")
	}
	w = request(h, "GET", "/api/sessions", nil, cookie, csrf, "")
	var rows []map[string]any
	json.Unmarshal(w.Body.Bytes(), &rows)
	if len(rows) != 1 || rows[0]["termination_status"] != "failed" || rows[0]["status"] != "active" {
		t.Fatal(w.Body.String())
	}
	b.TerminationResults = nil
	if w = request(h, "POST", path, nil, cookie, csrf, ""); w.Code != 202 {
		t.Fatal(w.Body.String())
	}
	response = ingest(b)
	command = response.Terminations[0]
	b.TerminationResults = []model.TerminationResult{{ID: command.ID}}
	ingest(b)
	ingest(b) // Retry is idempotent, and stale active snapshots cannot reopen the session.
	w = request(h, "GET", "/api/sessions", nil, cookie, csrf, "")
	json.Unmarshal(w.Body.Bytes(), &rows)
	if rows[0]["status"] != "ended" || rows[0]["termination_status"] != "succeeded" {
		t.Fatal(w.Body.String())
	}
	if w = request(h, "POST", path, nil, cookie, csrf, ""); w.Code != 409 {
		t.Fatal(w.Code)
	}
}

func TestTerminationExpiryAndOfflineServer(t *testing.T) {
	a, h := fixture(t)
	cookie, csrf := admin(t, h)
	now := time.Now().UnixMilli()
	_, err := a.store.db.Exec(`INSERT INTO servers(id,name,token_hash,created,last_seen,health) VALUES('s','s',?,1,?,'ok'); INSERT INTO server_control VALUES('s',1); INSERT INTO sessions VALUES('s','boot:1','u','ip',1,NULL,1)`, hash("token"), now)
	if err != nil {
		t.Fatal(err)
	}
	path := "/api/servers/s/sessions/boot:1/terminate"
	if w := request(h, "POST", path, nil, cookie, csrf, ""); w.Code != 202 {
		t.Fatal(w.Body.String())
	}
	a.store.db.Exec("UPDATE session_terminations SET expires=1")
	w := request(h, "POST", "/api/ingest", model.Batch{CanTerminate: true, Health: "ok", ActiveSessions: []string{"boot:1"}}, "", "", "token")
	var response model.IngestResponse
	json.Unmarshal(w.Body.Bytes(), &response)
	if w.Code != 200 || len(response.Terminations) != 0 {
		t.Fatal(w.Body.String())
	}
	a.store.db.Exec("UPDATE servers SET last_seen=1")
	if w := request(h, "POST", path, nil, cookie, csrf, ""); w.Code != 409 {
		t.Fatal(w.Code)
	}
	a.store.db.Exec("UPDATE servers SET last_seen=?,revoked=1", now)
	if w := request(h, "POST", path, nil, cookie, csrf, ""); w.Code != 404 {
		t.Fatal(w.Code)
	}
}
