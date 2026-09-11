package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sshlogger/internal/model"
	"sync"
	"testing"
	"time"
)

func fixture(t *testing.T) (*App, http.Handler) {
	t.Helper()
	s, e := openStore(filepath.Join(t.TempDir(), "db.sqlite"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.db.Close() })
	h, _ := bcrypt.GenerateFromPassword([]byte("long-test-password"), bcrypt.MinCost)
	if _, e = s.db.Exec("INSERT INTO admins VALUES('admin',?)", string(h)); e != nil {
		t.Fatal(e)
	}
	a := &App{store: s, origin: "http://localhost:8080"}
	return a, a.routes()
}
func request(h http.Handler, method, path string, body any, cookie, csrf, token string) *httptest.ResponseRecorder {
	b, _ := json.Marshal(body)
	r := httptest.NewRequest(method, path, bytes.NewReader(b))
	r.Header.Set("Origin", "http://localhost:8080")
	r.Header.Set("X-CSRF-Token", csrf)
	if cookie != "" {
		r.Header.Set("Cookie", cookie)
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func admin(t *testing.T, h http.Handler) (string, string) {
	t.Helper()
	w := request(h, "POST", "/api/login", map[string]string{"username": "admin", "password": "long-test-password"}, "", "", "")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var b map[string]string
	json.Unmarshal(w.Body.Bytes(), &b)
	return w.Result().Cookies()[0].String(), b["csrf"]
}
func TestAuthCSRFExpiryAndRevocation(t *testing.T) {
	a, h := fixture(t)
	if w := request(h, "GET", "/api/events", nil, "", "", ""); w.Code != 401 {
		t.Fatal(w.Code)
	}
	c, csrf := admin(t, h)
	if w := request(h, "POST", "/api/servers", map[string]string{"name": "prod"}, c, "", ""); w.Code != 403 {
		t.Fatal(w.Code)
	}
	w := request(h, "POST", "/api/servers", map[string]string{"name": "prod"}, c, csrf, "")
	if w.Code != 201 {
		t.Fatal(w.Body.String())
	}
	var server map[string]string
	json.Unmarshal(w.Body.Bytes(), &server)
	w = request(h, "POST", "/api/servers/"+server["id"]+"/revoke", nil, c, csrf, "")
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	w = request(h, "POST", "/api/ingest", model.Batch{Health: "ok"}, "", "", server["token"])
	if w.Code != 401 {
		t.Fatal(w.Code)
	}
	a.store.db.Exec("UPDATE auth_sessions SET expires=0")
	if w = request(h, "GET", "/api/me", nil, c, "", ""); w.Code != 401 {
		t.Fatal(w.Code)
	}
}
func TestIngestIdempotencyLinkingAndRollback(t *testing.T) {
	a, h := fixture(t)
	c, csrf := admin(t, h)
	w := request(h, "POST", "/api/servers", map[string]string{"name": "prod"}, c, csrf, "")
	var server map[string]string
	json.Unmarshal(w.Body.Bytes(), &server)
	now := time.Now().UnixMilli()
	events := []model.Event{{ID: "start", Time: now, Kind: "session_start", SessionID: "boot:1", User: "alice", IP: "203.0.113.1"}, {ID: "exec", Time: now, Kind: "exec", SessionID: "boot:1", User: "alice", EffectiveUser: "root", Program: "curl", Args: []string{"curl", "--password=secret"}}}
	batch := model.Batch{Events: events, Health: "ok", ActiveSessions: []string{"boot:1"}}
	for i := 0; i < 2; i++ {
		w = request(h, "POST", "/api/ingest", batch, "", "", server["token"])
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	var n int
	a.store.db.QueryRow("SELECT COUNT(*) FROM events").Scan(&n)
	if n != 2 {
		t.Fatalf("duplicate records: %d", n)
	}
	var cmd string
	a.store.db.QueryRow("SELECT command FROM events WHERE id='exec'").Scan(&cmd)
	if cmd != "curl --password=[REDACTED]" {
		t.Fatal(cmd)
	}
	w = request(h, "GET", "/api/sessions", nil, c, "", "")
	var rows []map[string]any
	json.Unmarshal(w.Body.Bytes(), &rows)
	if len(rows) != 1 || rows[0]["status"] != "active" {
		t.Fatal(w.Body.String())
	}
	a.store.db.Exec("UPDATE servers SET last_seen=0")
	w = request(h, "GET", "/api/sessions", nil, c, "", "")
	json.Unmarshal(w.Body.Bytes(), &rows)
	if rows[0]["status"] != "unknown" {
		t.Fatal(w.Body.String())
	}
	batch.Events = []model.Event{{ID: "new", Time: now, Kind: "exec"}, {ID: "bad", Time: now, Kind: "invalid"}}
	if w = request(h, "POST", "/api/ingest", batch, "", "", server["token"]); w.Code != 400 {
		t.Fatal(w.Code)
	}
	a.store.db.QueryRow("SELECT COUNT(*) FROM events").Scan(&n)
	if n != 2 {
		t.Fatal("partial batch written")
	}
}
func TestBackupRestoreRetention(t *testing.T) {
	a, _ := fixture(t)
	a.store.db.Exec("INSERT INTO servers(id,name,token_hash,created) VALUES('s','s','h',0)")
	a.store.db.Exec(`INSERT INTO events(server_id,id,time,received,kind,session_id,user,login_uid,effective_user,ip,program,args,command,outcome) VALUES('s','old',1,1,'exec','','','','','','','[]','','')`)
	snapshot := filepath.Join(t.TempDir(), "backup.db")
	if _, e := a.store.db.Exec("VACUUM INTO ?", snapshot); e != nil {
		t.Fatal(e)
	}
	if e := a.store.cleanup(context.Background()); e != nil {
		t.Fatal(e)
	}
	var n int
	a.store.db.QueryRow("SELECT COUNT(*) FROM events").Scan(&n)
	if n != 0 {
		t.Fatal(n)
	}
	dest := filepath.Join(t.TempDir(), "restored.db")
	if e := restoreSnapshot(dest, snapshot); e != nil {
		t.Fatal(e)
	}
	db, e := sql.Open("sqlite", dest)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	if e = db.QueryRow("SELECT COUNT(*) FROM events").Scan(&n); e != nil || n != 1 {
		t.Fatal(n, e)
	}
}
func TestWriterWaitHonorsContext(t *testing.T) {
	a, _ := fixture(t)
	a.store.writer <- struct{}{}
	defer func() { <-a.store.writer }()
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	if e := a.store.transaction(ctx, func(*sql.Tx) error { return nil }); e == nil {
		t.Fatal("expected timeout")
	}
}

func TestConcurrentIngestSearchAndCleanup(t *testing.T) {
	a, h := fixture(t)
	c, csrf := admin(t, h)
	w := request(h, "POST", "/api/servers", map[string]string{"name": "load"}, c, csrf, "")
	var server map[string]string
	json.Unmarshal(w.Body.Bytes(), &server)
	var wg sync.WaitGroup
	errs := make(chan string, 128)
	started := time.Now()
	for worker := 0; worker < 8; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for batch := 0; batch < 5; batch++ {
				events := []model.Event{}
				for n := 0; n < 25; n++ {
					events = append(events, model.Event{ID: fmt.Sprintf("%d-%d-%d", worker, batch, n), Time: time.Now().UnixMilli(), Kind: "exec", User: "alice", Program: "/usr/bin/id", Args: []string{"id"}})
				}
				res := request(h, "POST", "/api/ingest", model.Batch{Events: events, Health: "ok"}, "", "", server["token"])
				if res.Code != 200 {
					errs <- res.Body.String()
				}
				res = request(h, "GET", "/api/events?q=id&user=alice", nil, c, "", "")
				if res.Code != 200 {
					errs <- res.Body.String()
				}
			}
		}(worker)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for n := 0; n < 5; n++ {
			if e := a.store.cleanup(context.Background()); e != nil {
				errs <- e.Error()
			}
		}
	}()
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
	var n int
	if e := a.store.db.QueryRow("SELECT COUNT(*) FROM events").Scan(&n); e != nil || n != 1000 {
		t.Fatalf("count=%d error=%v", n, e)
	}
	t.Logf("1000 events, 40 concurrent-batch requests, searches and cleanup in %s", time.Since(started))
}

func TestLoginFailureLimit(t *testing.T) {
	a, h := fixture(t)
	login := func(password string, want int) {
		t.Helper()
		w := request(h, "POST", "/api/login", map[string]string{"username": "admin", "password": password}, "", "", "")
		if w.Code != want {
			t.Fatalf("login: got %d, want %d: %s", w.Code, want, w.Body.String())
		}
	}
	for i := 0; i < 12; i++ {
		login("long-test-password", http.StatusOK)
	}
	for i := 0; i < 9; i++ {
		login("wrong-password", http.StatusUnauthorized)
	}
	login("long-test-password", http.StatusOK)
	for i := 0; i < 10; i++ {
		login("wrong-password", http.StatusUnauthorized)
	}
	var count int
	var reset int64
	if err := a.store.db.QueryRow("SELECT count, reset FROM login_attempts").Scan(&count, &reset); err != nil || count != 10 {
		t.Fatalf("failure count = %d, err = %v", count, err)
	}
	login("wrong-password", http.StatusTooManyRequests)
	login("long-test-password", http.StatusTooManyRequests)
	var afterReset int64
	if err := a.store.db.QueryRow("SELECT count, reset FROM login_attempts").Scan(&count, &afterReset); err != nil || count != 10 || afterReset != reset {
		t.Fatalf("blocked requests changed limit: count=%d reset=%d err=%v", count, afterReset, err)
	}
	if _, err := a.store.db.Exec("UPDATE login_attempts SET reset=?", time.Now().Add(-time.Second).UnixMilli()); err != nil {
		t.Fatal(err)
	}
	login("wrong-password", http.StatusUnauthorized)
	if err := a.store.db.QueryRow("SELECT count FROM login_attempts").Scan(&count); err != nil || count != 1 {
		t.Fatalf("expired failure count = %d, err = %v", count, err)
	}
	login("long-test-password", http.StatusOK)
}

func TestLoginSessionStorageFailureDoesNotCountAsAuthenticationFailure(t *testing.T) {
	a, h := fixture(t)
	if _, err := a.store.db.Exec(`CREATE TRIGGER reject_session BEFORE INSERT ON auth_sessions BEGIN SELECT RAISE(ABORT, 'session storage unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	w := request(h, "POST", "/api/login", map[string]string{"username": "admin", "password": "long-test-password"}, "", "", "")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("got %d, want 503", w.Code)
	}
	var count int
	if err := a.store.db.QueryRow("SELECT COUNT(*) FROM login_attempts").Scan(&count); err != nil || count != 0 {
		t.Fatalf("successful authentication counted as failure: rows=%d err=%v", count, err)
	}
}
