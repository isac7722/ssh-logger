package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestAdminAccountsAndPasswordChange(t *testing.T) {
	a, h := fixture(t)
	cookie, csrf := admin(t, h)
	secondCookie, _ := admin(t, h)
	create := map[string]string{"username": "operator", "password": "operator-password-123"}
	for _, route := range []struct {
		method, path string
		body         any
	}{
		{"GET", "/api/admins", nil}, {"POST", "/api/admins", create},
		{"PUT", "/api/me/password", map[string]string{"current_password": "long-test-password", "new_password": "changed-password-123"}},
	} {
		if w := request(h, route.method, route.path, route.body, "", "", ""); w.Code != 401 {
			t.Fatalf("unauthenticated %s: %d", route.path, w.Code)
		}
		if route.method != "GET" {
			if w := request(h, route.method, route.path, route.body, cookie, "", ""); w.Code != 403 {
				t.Fatalf("missing CSRF %s: %d", route.path, w.Code)
			}
		}
	}
	for _, body := range []map[string]string{
		{"username": "bad name", "password": "operator-password-123"},
		{"username": "operator", "password": "short"},
		{"username": "operator", "password": strings.Repeat("한", 25)},
	} {
		if w := request(h, "POST", "/api/admins", body, cookie, csrf, ""); w.Code != 400 {
			t.Fatalf("invalid account: %d", w.Code)
		}
	}
	if w := request(h, "POST", "/api/admins", create, cookie, csrf, ""); w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := request(h, "POST", "/api/admins", create, cookie, csrf, ""); w.Code != 409 {
		t.Fatalf("duplicate: %d", w.Code)
	}
	var stored string
	if err := a.store.db.QueryRow("SELECT password_hash FROM admins WHERE username='operator'").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored == create["password"] || bcrypt.CompareHashAndPassword([]byte(stored), []byte(create["password"])) != nil {
		t.Fatal("password not hashed correctly")
	}
	w := request(h, "POST", "/api/login", create, "", "", "")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	operatorCookie := w.Result().Cookies()[0].String()
	var session map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &session); err != nil || session["username"] != "operator" {
		t.Fatal(session, err)
	}
	w = request(h, "GET", "/api/admins", nil, operatorCookie, "", "")
	if w.Code != 200 || strings.Contains(w.Body.String(), "password") || !strings.Contains(w.Body.String(), "operator") {
		t.Fatal(w.Code, w.Body.String())
	}
	if w = request(h, "POST", "/api/admins", map[string]string{"username": "third", "password": "third-password-123"}, operatorCookie, session["csrf"], ""); w.Code != 201 {
		t.Fatalf("additional admin permissions: %d", w.Code)
	}
	change := map[string]string{"current_password": "wrong", "new_password": "changed-password-123"}
	if w = request(h, "PUT", "/api/me/password", change, cookie, csrf, ""); w.Code != 400 {
		t.Fatal(w.Code)
	}
	change["current_password"] = "long-test-password"
	change["new_password"] = "short"
	if w = request(h, "PUT", "/api/me/password", change, cookie, csrf, ""); w.Code != 400 {
		t.Fatal(w.Code)
	}
	change["new_password"] = "changed-password-123"
	if w = request(h, "PUT", "/api/me/password", change, cookie, csrf, ""); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	for _, oldCookie := range []string{cookie, secondCookie} {
		if w = request(h, "GET", "/api/me", nil, oldCookie, "", ""); w.Code != http.StatusUnauthorized {
			t.Fatal("old session survived password change", w.Code)
		}
	}
	if w = request(h, "GET", "/api/me", nil, operatorCookie, "", ""); w.Code != 200 {
		t.Fatal("other admin logged out", w.Code)
	}
	if w = request(h, "POST", "/api/login", map[string]string{"username": "admin", "password": "long-test-password"}, "", "", ""); w.Code != 401 {
		t.Fatal("old password accepted", w.Code)
	}
	if w = request(h, "POST", "/api/login", map[string]string{"username": "admin", "password": "changed-password-123"}, "", "", ""); w.Code != 200 {
		t.Fatal("new password rejected", w.Code)
	}
}
