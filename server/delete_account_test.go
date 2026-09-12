package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"sshlogger/internal/model"
)

func accountLogin(t *testing.T, h http.Handler, username string) (string, string) {
	t.Helper()
	w := request(h, "POST", "/api/login", map[string]string{"username": username, "password": "long-test-password"}, "", "", "")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var session map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &session); err != nil {
		t.Fatal(err)
	}
	return w.Result().Cookies()[0].String(), session["csrf"]
}

func TestDeleteAdminPermissionsSessionsAndHistory(t *testing.T) {
	a, h := fixture(t)
	cookie, csrf := admin(t, h)
	for _, name := range []string{"operator", "unassigned", "other-super"} {
		if _, err := a.store.db.Exec("INSERT INTO admins SELECT ?,password_hash FROM admins WHERE username='admin'", name); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := a.store.db.Exec("INSERT INTO admin_roles VALUES('operator','admin'),('other-super','super_admin')"); err != nil {
		t.Fatal(err)
	}
	op, ot := accountLogin(t, h, "operator")
	op2, _ := accountLogin(t, h, "operator")
	other, _ := accountLogin(t, h, "other-super")
	s := newServer(t, h, cookie, csrf, "preserved")
	if _, err := a.store.db.Exec("INSERT INTO admin_servers VALUES('operator',?)", s["id"]); err != nil {
		t.Fatal(err)
	}
	if w := request(h, "POST", "/api/servers/"+s["id"]+"/bans", model.IPBan{IP: "203.0.113.10"}, op, ot, ""); w.Code != 202 {
		t.Fatal(w.Body.String())
	}
	if _, err := a.store.db.Exec("INSERT INTO session_terminations(id,server_id,session_id,requested_by,created,expires,status) VALUES('old',?,'ssh-session','operator',1,2,'succeeded')", s["id"]); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, cookie, csrf string
		want               int
	}{
		{"operator", "", "", 401}, {"operator", cookie, "", 403},
		{"operator", op, ot, 403}, {"unassigned", op, ot, 403},
		{"admin", cookie, csrf, 403}, {"other-super", cookie, csrf, 403},
		{"missing", cookie, csrf, 404},
	} {
		w := request(h, "DELETE", "/api/admins/"+tc.name, nil, tc.cookie, tc.csrf, "")
		if w.Code != tc.want {
			t.Fatalf("delete %s: got %d want %d: %s", tc.name, w.Code, tc.want, w.Body.String())
		}
	}
	r := httptest.NewRequest("DELETE", "/api/admins/operator", nil)
	r.Header.Set("Cookie", cookie)
	r.Header.Set("X-CSRF-Token", csrf)
	r.Header.Set("Origin", "https://other.example")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("cross-origin delete accepted", w.Code)
	}
	for _, name := range []string{"operator", "unassigned"} {
		if w := request(h, "DELETE", "/api/admins/"+name, nil, cookie, csrf, ""); w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		for _, table := range []string{"admins", "auth_sessions", "admin_roles", "admin_servers"} {
			var n int
			if err := a.store.db.QueryRow("SELECT COUNT(*) FROM "+table+" WHERE username=?", name).Scan(&n); err != nil || n != 0 {
				t.Fatal(table, n, err)
			}
		}
	}
	for _, c := range []string{op, op2} {
		if w := request(h, "GET", "/api/me", nil, c, "", ""); w.Code != 401 {
			t.Fatal("deleted account session survived", w.Code)
		}
	}
	if w := request(h, "POST", "/api/login", map[string]string{"username": "operator", "password": "long-test-password"}, "", "", ""); w.Code != 401 {
		t.Fatal("deleted account logged in", w.Code)
	}
	for _, c := range []string{cookie, other} {
		if w := request(h, "GET", "/api/me", nil, c, "", ""); w.Code != 200 {
			t.Fatal("unrelated session removed", w.Code)
		}
	}
	for _, table := range []string{"firewall_history", "session_terminations"} {
		var n int
		if err := a.store.db.QueryRow("SELECT COUNT(*) FROM " + table + " WHERE requested_by='operator'").Scan(&n); err != nil || n != 1 {
			t.Fatal("history lost", table, n, err)
		}
	}
	if w := request(h, "DELETE", "/api/admins/operator", nil, cookie, csrf, ""); w.Code != 404 {
		t.Fatal(w.Code)
	}
}

func TestDeleteAdminRechecksAuthorization(t *testing.T) {
	for _, tc := range []struct {
		name, mutation string
		want           int
	}{
		{"caller demoted", "UPDATE admin_roles SET role='admin' WHERE username='admin'", 403},
		{"caller logged out", "DELETE FROM auth_sessions WHERE username='admin'", 401},
		{"target promoted", "INSERT INTO admin_roles VALUES('operator','super_admin')", 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, h := fixture(t)
			cookie, csrf := admin(t, h)
			if _, err := a.store.db.Exec("INSERT INTO admins SELECT 'operator',password_hash FROM admins WHERE username='admin'"); err != nil {
				t.Fatal(err)
			}
			wrapped := a.auth(a.super(func(w http.ResponseWriter, r *http.Request) {
				if _, err := a.store.db.Exec(tc.mutation); err != nil {
					t.Fatal(err)
				}
				r.SetPathValue("username", "operator")
				a.deleteAdmin(w, r)
			}))
			if w := request(wrapped, "DELETE", "/api/admins/operator", nil, cookie, csrf, ""); w.Code != tc.want {
				t.Fatal(w.Code, w.Body.String())
			}
			var n int
			if err := a.store.db.QueryRow("SELECT COUNT(*) FROM admins WHERE username='operator'").Scan(&n); err != nil || n != 1 {
				t.Fatal("target removed", n, err)
			}
		})
	}
}

func TestDeleteAdminRollsBackCleanupOnFailure(t *testing.T) {
	a, h := fixture(t)
	cookie, csrf := admin(t, h)
	if _, err := a.store.db.Exec("INSERT INTO admins SELECT 'operator',password_hash FROM admins WHERE username='admin'; INSERT INTO admin_roles VALUES('operator','admin')"); err != nil {
		t.Fatal(err)
	}
	op, _ := accountLogin(t, h, "operator")
	s := newServer(t, h, cookie, csrf, "retained")
	if _, err := a.store.db.Exec("INSERT INTO admin_servers VALUES('operator',?)", s["id"]); err != nil {
		t.Fatal(err)
	}
	if _, err := a.store.db.Exec("CREATE TRIGGER prevent_delete BEFORE DELETE ON admins BEGIN SELECT RAISE(ABORT,'test failure'); END"); err != nil {
		t.Fatal(err)
	}
	if w := request(h, "DELETE", "/api/admins/operator", nil, cookie, csrf, ""); w.Code != 503 {
		t.Fatal(w.Code)
	}
	for _, table := range []string{"admins", "auth_sessions", "admin_roles", "admin_servers"} {
		var n int
		if err := a.store.db.QueryRow("SELECT COUNT(*) FROM " + table + " WHERE username='operator'").Scan(&n); err != nil || n != 1 {
			t.Fatal(table, n, err)
		}
	}
	if w := request(h, "GET", "/api/me", nil, op, "", ""); w.Code != 200 {
		t.Fatal("rollback lost session", w.Code)
	}
}
