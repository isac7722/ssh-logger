package main

import (
	"encoding/json"
	"net/http/httptest"
	"sshlogger/internal/model"
	"strings"
	"testing"
)

func TestAdminServerManagement(t *testing.T) {
	a, h := fixture(t)
	rootCookie, rootCSRF := admin(t, h)
	type auth struct{ cookie, csrf string }
	root := auth{rootCookie, rootCSRF}
	call := func(who auth, method, path string, body any, want int) *httptest.ResponseRecorder {
		t.Helper()
		w := request(h, method, "/api"+path, body, who.cookie, who.csrf, "")
		if w.Code != want {
			t.Fatalf("%s %s: %d %s", method, path, w.Code, w.Body.String())
		}
		return w
	}
	account := func(name string) auth {
		t.Helper()
		credentials := map[string]string{"username": name, "password": "operator-password-123"}
		call(root, "POST", "/admins", credentials, 201)
		w := call(auth{}, "POST", "/login", credentials, 200)
		var data map[string]string
		json.Unmarshal(w.Body.Bytes(), &data)
		return auth{w.Result().Cookies()[0].String(), data["csrf"]}
	}
	first, second := account("first"), account("second")
	hidden := newServer(t, h, rootCookie, rootCSRF, "root-only")
	create := call(first, "POST", "/servers", map[string]string{"name": "shared"}, 201)
	var shared map[string]string
	json.Unmarshal(create.Body.Bytes(), &shared)
	base := "/servers/" + shared["id"]
	for _, who := range []auth{first, second} {
		w := call(who, "GET", "/servers", nil, 200)
		if !strings.Contains(w.Body.String(), "shared") || strings.Contains(w.Body.String(), "root-only") {
			t.Fatal(w.Body.String())
		}
	}
	var assigned int
	if err := a.store.db.QueryRow("SELECT COUNT(*) FROM admin_servers WHERE server_id=?", shared["id"]).Scan(&assigned); err != nil || assigned != 2 {
		t.Fatal(assigned, err)
	}
	later := account("later")
	if w := call(later, "GET", "/servers", nil, 200); strings.TrimSpace(w.Body.String()) != "[]" {
		t.Fatal("retroactive assignment", w.Body.String())
	}
	for _, tt := range []struct {
		method, suffix string
		body           any
	}{
		{"PUT", "", map[string]string{"name": "renamed"}}, {"POST", "/rotate", nil}, {"POST", "/revoke", nil}, {"DELETE", "", nil},
	} {
		call(first, tt.method, "/servers/"+hidden["id"]+tt.suffix, tt.body, 404)
		call(later, tt.method, base+tt.suffix, tt.body, 404)
		call(auth{}, tt.method, base+tt.suffix, tt.body, 401)
		call(auth{first.cookie, ""}, tt.method, base+tt.suffix, tt.body, 403)
	}
	call(auth{}, "POST", "/servers", map[string]string{"name": "unauthorized"}, 401)
	call(auth{first.cookie, ""}, "POST", "/servers", map[string]string{"name": "unauthorized"}, 403)
	call(second, "PUT", base, map[string]string{"name": " renamed "}, 200)
	call(first, "PUT", base, map[string]string{"name": ""}, 400)
	call(first, "PUT", base, map[string]string{"name": "root-only"}, 409)
	if w := call(first, "GET", "/servers", nil, 200); !strings.Contains(w.Body.String(), "renamed") {
		t.Fatal(w.Body.String())
	}
	rotated := call(second, "POST", base+"/rotate", nil, 200)
	var token map[string]string
	json.Unmarshal(rotated.Body.Bytes(), &token)
	if token["token"] == "" || token["token"] == shared["token"] {
		t.Fatal("token not rotated")
	}
	ingest := func(value string, want int) {
		t.Helper()
		w := request(h, "POST", "/api/ingest", model.Batch{Health: "ok"}, "", "", value)
		if w.Code != want {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	ingest(shared["token"], 401)
	ingest(token["token"], 200)
	call(root, "PUT", "/admins/first/access", map[string]any{"role": "admin", "server_ids": []string{}}, 200)
	call(first, "PUT", base, map[string]string{"name": "forbidden"}, 404)
	call(first, "POST", base+"/rotate", nil, 404)
	call(first, "DELETE", base, nil, 404)
	call(second, "DELETE", base, nil, 200)
	ingest(token["token"], 401)
	call(second, "PUT", base, map[string]string{"name": "revived"}, 404)
	call(second, "POST", base+"/rotate", nil, 404)
	if w := call(second, "GET", "/servers", nil, 200); strings.TrimSpace(w.Body.String()) != "[]" {
		t.Fatal(w.Body.String())
	}
	// Registration and automatic assignments roll back together if an assignment fails.
	if _, err := a.store.db.Exec("CREATE TRIGGER fail_assignment BEFORE INSERT ON admin_servers BEGIN SELECT RAISE(ABORT,'test failure'); END"); err != nil {
		t.Fatal(err)
	}
	call(first, "POST", "/servers", map[string]string{"name": "rollback"}, 409)
	var count int
	if err := a.store.db.QueryRow("SELECT COUNT(*) FROM servers WHERE name='rollback'").Scan(&count); err != nil || count != 0 {
		t.Fatal(count, err)
	}
}
