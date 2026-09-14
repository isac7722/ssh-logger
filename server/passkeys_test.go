package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// Real ES256 signatures exercise the library verification and server state machine together.
type testPasskey struct {
	key        *ecdsa.PrivateKey
	id         []byte
	count      uint32
	noPresence bool
}

func newTestPasskey(t *testing.T) *testPasskey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 32)
	rand.Read(id)
	return &testPasskey{key: key, id: id}
}
func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
func (k *testPasskey) response(t *testing.T, options map[string]any, register bool, origin, rp string, uv bool) map[string]any {
	t.Helper()
	typ := "webauthn.get"
	if register {
		typ = "webauthn.create"
	}
	client, _ := json.Marshal(map[string]any{"type": typ, "challenge": options["challenge"], "origin": origin, "crossOrigin": false})
	rpHash := sha256.Sum256([]byte(rp))
	auth := append([]byte{}, rpHash[:]...)
	flags := byte(1 | 8 | 16)
	if k.noPresence {
		flags &^= 1
	}
	if uv {
		flags |= 4
	}
	if register {
		flags |= 64
	}
	auth = append(auth, flags)
	k.count++
	auth = binary.BigEndian.AppendUint32(auth, k.count)
	result := map[string]any{"id": b64(k.id), "rawId": b64(k.id), "type": "public-key", "clientExtensionResults": map[string]any{}}
	if register {
		auth = append(auth, make([]byte, 16)...)
		auth = binary.BigEndian.AppendUint16(auth, uint16(len(k.id)))
		auth = append(auth, k.id...)
		cose, err := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: k.key.X.FillBytes(make([]byte, 32)), -3: k.key.Y.FillBytes(make([]byte, 32))})
		if err != nil {
			t.Fatal(err)
		}
		auth = append(auth, cose...)
		att, _ := cbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": auth})
		result["response"] = map[string]any{"clientDataJSON": b64(client), "attestationObject": b64(att), "transports": []string{"internal", "hybrid"}}
	} else {
		clientHash := sha256.Sum256(client)
		signed := append(append([]byte{}, auth...), clientHash[:]...)
		digest := sha256.Sum256(signed)
		sig, err := ecdsa.SignASN1(rand.Reader, k.key, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		result["response"] = map[string]any{"clientDataJSON": b64(client), "authenticatorData": b64(auth), "signature": b64(sig)}
	}
	return result
}
func parseBody(t *testing.T, w *httptest.ResponseRecorder, want int) map[string]any {
	t.Helper()
	if w.Code != want {
		t.Fatalf("status %d want %d: %s", w.Code, want, w.Body.String())
	}
	var b map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &b); err != nil {
		t.Fatal(err)
	}
	return b
}
func beginKey(t *testing.T, h http.Handler, c, csrf, action, target string) map[string]any {
	t.Helper()
	return parseBody(t, request(h, "POST", "/api/me/passkeys/begin", map[string]string{"password": "long-test-password", "action": action, "target": target, "name": "1Password"}, c, csrf, ""), 200)
}
func keyFinish(t *testing.T, h http.Handler, k *testPasskey, b map[string]any, path, c, csrf string) *httptest.ResponseRecorder {
	t.Helper()
	return request(h, "POST", path, map[string]any{"request_id": b["request_id"], "credential": k.response(t, b["options"].(map[string]any), b["step"] == "register", "http://localhost:8080", "localhost", true)}, c, csrf, "")
}
func enroll(t *testing.T, h http.Handler, c, csrf string) *testPasskey {
	t.Helper()
	k := newTestPasskey(t)
	b := beginKey(t, h, c, csrf, "add", "")
	if b["step"] != "register" {
		t.Fatal(b)
	}
	result := parseBody(t, keyFinish(t, h, k, b, "/api/me/passkeys/register/finish", c, csrf), 200)
	if result["logout"] != true {
		t.Fatal(result)
	}
	return k
}
func loginKey(t *testing.T, h http.Handler, k *testPasskey) (string, string) {
	t.Helper()
	b := parseBody(t, request(h, "POST", "/api/login", map[string]string{"username": "admin", "password": "long-test-password"}, "", "", ""), 200)
	if b["mfa_required"] != true {
		t.Fatal(b)
	}
	w := keyFinish(t, h, k, b, "/api/login/passkey/finish", "", "")
	result := parseBody(t, w, 200)
	return w.Result().Cookies()[0].String(), result["csrf"].(string)
}

func TestPasskeyLifecycle(t *testing.T) {
	a, h := fixture(t)
	c, csrf := admin(t, h)
	other, _ := admin(t, h)
	k := enroll(t, h, c, csrf)
	for _, cookie := range []string{c, other} {
		if w := request(h, "GET", "/api/me", nil, cookie, "", ""); w.Code != 401 {
			t.Fatal("old session survived")
		}
	}
	c, csrf = loginKey(t, h, k)
	other, _ = loginKey(t, h, k)
	b := beginKey(t, h, c, csrf, "add", "")
	if b["step"] != "authenticate" {
		t.Fatal(b)
	}
	b = parseBody(t, keyFinish(t, h, k, b, "/api/me/passkeys/finish", c, csrf), 200)
	second := newTestPasskey(t)
	parseBody(t, keyFinish(t, h, second, b, "/api/me/passkeys/register/finish", c, csrf), 200)
	if w := request(h, "GET", "/api/me", nil, other, "", ""); w.Code != 401 {
		t.Fatal("other session survived")
	}
	if w := request(h, "GET", "/api/me", nil, c, "", ""); w.Code != 200 {
		t.Fatal("current session lost")
	}
	loginKey(t, h, second)
	b = beginKey(t, h, c, csrf, "delete", b64(k.id))
	parseBody(t, keyFinish(t, h, second, b, "/api/me/passkeys/finish", c, csrf), 200)
	b = beginKey(t, h, c, csrf, "delete", b64(second.id))
	out := parseBody(t, keyFinish(t, h, second, b, "/api/me/passkeys/finish", c, csrf), 200)
	if out["logout"] != true {
		t.Fatal(out)
	}
	var count int
	a.store.db.QueryRow("SELECT COUNT(*) FROM passkeys").Scan(&count)
	if count != 0 {
		t.Fatal(count)
	}
	admin(t, h)
}
func TestPasskeyRejectsInvalidProofAndReplay(t *testing.T) {
	for _, kind := range []string{"origin", "rp", "presence", "signature", "challenge", "owner"} {
		t.Run(kind, func(t *testing.T) {
			_, h := fixture(t)
			c, csrf := admin(t, h)
			k := enroll(t, h, c, csrf)
			w := request(h, "POST", "/api/login", map[string]string{"username": "admin", "password": "long-test-password"}, "", "", "")
			b := parseBody(t, w, 200)
			if len(w.Result().Cookies()) != 0 {
				t.Fatal("password alone issued session")
			}
			options := b["options"].(map[string]any)
			origin, rp, uv := "http://localhost:8080", "localhost", true
			if kind == "origin" {
				origin = "https://evil.example"
			}
			if kind == "rp" {
				rp = "evil.example"
			}
			if kind == "presence" {
				k.noPresence = true
			}
			if kind == "challenge" {
				options["challenge"] = "wrong"
			}
			if kind == "owner" {
				k = newTestPasskey(t)
			}
			proof := k.response(t, options, false, origin, rp, uv)
			if kind == "signature" {
				proof["response"].(map[string]any)["signature"] = b64([]byte("invalid"))
			}
			body := map[string]any{"request_id": b["request_id"], "credential": proof}
			parseBody(t, request(h, "POST", "/api/login/passkey/finish", body, "", "", ""), 400)
			parseBody(t, request(h, "POST", "/api/login/passkey/finish", body, "", "", ""), 400)
		})
	}
}
func TestRegistrationRejectsOriginRPAndMissingPresence(t *testing.T) {
	for _, kind := range []string{"origin", "rp", "presence"} {
		t.Run(kind, func(t *testing.T) {
			a, h := fixture(t)
			c, csrf := admin(t, h)
			b := beginKey(t, h, c, csrf, "add", "")
			k := newTestPasskey(t)
			origin, rp, uv := "http://localhost:8080", "localhost", true
			if kind == "origin" {
				origin = "https://evil.example"
			}
			if kind == "rp" {
				rp = "evil.example"
			}
			if kind == "presence" {
				k.noPresence = true
			}
			body := map[string]any{"request_id": b["request_id"], "credential": k.response(t, b["options"].(map[string]any), true, origin, rp, uv)}
			parseBody(t, request(h, "POST", "/api/me/passkeys/register/finish", body, c, csrf, ""), 400)
			var n int
			a.store.db.QueryRow("SELECT COUNT(*) FROM passkeys").Scan(&n)
			if n != 0 {
				t.Fatal(n)
			}
		})
	}
}
func TestPasskeyExpirySessionBindingAndPasswordChange(t *testing.T) {
	for _, kind := range []string{"expired", "logout", "password", "version", "wrong-session", "csrf", "purpose"} {
		t.Run(kind, func(t *testing.T) {
			a, h := fixture(t)
			c, csrf := admin(t, h)
			b := beginKey(t, h, c, csrf, "add", "")
			k := newTestPasskey(t)
			path := "/api/me/passkeys/register/finish"
			want := 400
			switch kind {
			case "expired":
				a.store.db.Exec("UPDATE auth_pending SET expires=0")
			case "logout":
				request(h, "POST", "/api/logout", map[string]any{}, c, csrf, "")
				want = 401
			case "password":
				parseBody(t, request(h, "PUT", "/api/me/password", map[string]string{"current_password": "long-test-password", "new_password": "changed-password-123"}, c, csrf, ""), 200)
				want = 401
			case "version":
				a.store.db.Exec("UPDATE account_auth SET version=version+1")
			case "wrong-session":
				c, csrf = admin(t, h)
			case "csrf":
				csrf = "wrong"
				want = 403
			case "purpose":
				path = "/api/me/passkeys/finish"
			}
			parseBody(t, keyFinish(t, h, k, b, path, c, csrf), want)
		})
	}
}
func TestPasskeyConcurrentCompletion(t *testing.T) {
	_, h := fixture(t)
	c, csrf := admin(t, h)
	k := enroll(t, h, c, csrf)
	b := parseBody(t, request(h, "POST", "/api/login", map[string]string{"username": "admin", "password": "long-test-password"}, "", "", ""), 200)
	body := map[string]any{"request_id": b["request_id"], "credential": k.response(t, b["options"].(map[string]any), false, "http://localhost:8080", "localhost", true)}
	var wg sync.WaitGroup
	codes := make(chan int, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes <- request(h, "POST", "/api/login/passkey/finish", body, "", "", "").Code
		}()
	}
	wg.Wait()
	close(codes)
	counts := map[int]int{}
	for code := range codes {
		counts[code]++
	}
	if counts[200] != 1 || counts[400] != 1 {
		t.Fatal(counts)
	}
}
func TestPasskeyResetAndRateLimits(t *testing.T) {
	a, h := fixture(t)
	c, csrf := admin(t, h)
	for i := 0; i < 10; i++ {
		parseBody(t, request(h, "POST", "/api/me/passkeys/begin", map[string]string{"password": "wrong", "action": "add", "name": "test"}, c, csrf, ""), 400)
	}
	parseBody(t, request(h, "POST", "/api/me/passkeys/begin", map[string]string{"password": "long-test-password", "action": "add", "name": "test"}, c, csrf, ""), 429)
	a.store.db.Exec("DELETE FROM auth_limits")
	k := enroll(t, h, c, csrf)
	c, csrf = loginKey(t, h, k)
	beginKey(t, h, c, csrf, "add", "")
	if err := a.store.resetTwoFactor(context.Background(), "admin"); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"passkeys", "auth_pending", "auth_sessions"} {
		var n int
		a.store.db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n)
		if n != 0 {
			t.Fatal(table, n)
		}
	}
	admin(t, h)
	if err := a.store.resetTwoFactor(context.Background(), "missing"); err == nil {
		t.Fatal("missing account accepted")
	}
}
func TestPasskeyForeignAccountCannotManage(t *testing.T) {
	a, h := fixture(t)
	c, csrf := admin(t, h)
	k := enroll(t, h, c, csrf)
	a.store.db.Exec("INSERT INTO admins SELECT 'operator',password_hash FROM admins WHERE username='admin'")
	w := request(h, "POST", "/api/login", map[string]string{"username": "operator", "password": "long-test-password"}, "", "", "")
	b := parseBody(t, w, 200)
	oc := w.Result().Cookies()[0].String()
	ot := b["csrf"].(string)
	c, csrf = loginKey(t, h, k)
	begin := beginKey(t, h, c, csrf, "disable", "")
	parseBody(t, keyFinish(t, h, k, begin, "/api/me/passkeys/finish", oc, ot), 400)
	parseBody(t, request(h, "POST", "/api/me/passkeys/begin", map[string]string{"password": "long-test-password", "action": "delete", "target": b64(k.id)}, oc, ot, ""), 400)
	parseBody(t, keyFinish(t, h, k, begin, "/api/me/passkeys/finish", c, csrf), 200)
}
func TestPasskeyFinishStorageFailureRollsBack(t *testing.T) {
	a, h := fixture(t)
	c, csrf := admin(t, h)
	b := beginKey(t, h, c, csrf, "add", "")
	k := newTestPasskey(t)
	if _, err := a.store.db.Exec(`CREATE TRIGGER reject_revocation BEFORE DELETE ON auth_sessions BEGIN SELECT RAISE(ABORT,'test failure'); END`); err != nil {
		t.Fatal(err)
	}
	parseBody(t, keyFinish(t, h, k, b, "/api/me/passkeys/register/finish", c, csrf), 503)
	var n int
	a.store.db.QueryRow("SELECT COUNT(*) FROM passkeys").Scan(&n)
	if n != 0 {
		t.Fatal("partial enrollment", n)
	}
	if w := request(h, "GET", "/api/me", nil, c, "", ""); w.Code != 200 {
		t.Fatal("session lost")
	}
}
func TestPasskeyConfiguration(t *testing.T) {
	for _, origin := range []string{"https://ssh.pangjoong.com", "http://localhost:8080", "http://remote.example", "https://127.0.0.1", "https://example.com/path"} {
		t.Run(fmt.Sprint(origin), func(t *testing.T) {
			a := &App{origin: origin}
			_, err := a.webAuthn()
			valid := origin == "https://ssh.pangjoong.com" || origin == "http://localhost:8080"
			if (err == nil) != valid {
				t.Fatal(err)
			}
		})
	}
}

func TestPasskeyLoginLimitAndInvalidation(t *testing.T) {
	a, h := fixture(t)
	c, csrf := admin(t, h)
	k := enroll(t, h, c, csrf)
	for i := 0; i < 10; i++ {
		b := parseBody(t, request(h, "POST", "/api/login", map[string]string{"username": "admin", "password": "long-test-password"}, "", "", ""), 200)
		parseBody(t, request(h, "POST", "/api/login/passkey/finish", map[string]any{"request_id": b["request_id"], "credential": map[string]any{}}, "", "", ""), 400)
	}
	parseBody(t, request(h, "POST", "/api/login", map[string]string{"username": "admin", "password": "long-test-password"}, "", "", ""), 429)
	a.store.db.Exec("UPDATE auth_limits SET reset=0")
	c, csrf = loginKey(t, h, k)
	pending := parseBody(t, request(h, "POST", "/api/login", map[string]string{"username": "admin", "password": "long-test-password"}, "", "", ""), 200)
	parseBody(t, request(h, "PUT", "/api/me/password", map[string]string{"current_password": "long-test-password", "new_password": "changed-password-123"}, c, csrf, ""), 200)
	parseBody(t, keyFinish(t, h, k, pending, "/api/login/passkey/finish", "", ""), 400)
	var n int
	a.store.db.QueryRow("SELECT COUNT(*) FROM passkeys").Scan(&n)
	if n != 1 {
		t.Fatal("password change removed passkey")
	}
}
func TestDeleteAccountCascadesPasskeysAndPending(t *testing.T) {
	a, h := fixture(t)
	root, rootCSRF := admin(t, h)
	a.store.db.Exec("INSERT INTO admins SELECT 'operator',password_hash FROM admins WHERE username='admin'")
	w := request(h, "POST", "/api/login", map[string]string{"username": "operator", "password": "long-test-password"}, "", "", "")
	body := parseBody(t, w, 200)
	c, csrf := w.Result().Cookies()[0].String(), body["csrf"].(string)
	enroll(t, h, c, csrf)
	parseBody(t, request(h, "POST", "/api/login", map[string]string{"username": "operator", "password": "long-test-password"}, "", "", ""), 200)
	parseBody(t, request(h, "DELETE", "/api/admins/operator", nil, root, rootCSRF, ""), 200)
	for _, table := range []string{"passkeys", "account_auth", "auth_pending"} {
		var n int
		a.store.db.QueryRow("SELECT COUNT(*) FROM " + table + " WHERE username='operator'").Scan(&n)
		if n != 0 {
			t.Fatal(table, n)
		}
	}
}

func TestPasskeysWithoutAdditionalUserVerification(t *testing.T) {
	for _, registeredWithUV := range []bool{false, true} {
		t.Run(fmt.Sprint(registeredWithUV), func(t *testing.T) {
			_, h := fixture(t)
			c, csrf := admin(t, h)
			k := newTestPasskey(t)
			finish := func(b map[string]any, path string, uv bool) *httptest.ResponseRecorder {
				options := b["options"].(map[string]any)
				policy := options["userVerification"]
				registration := b["step"] == "register"
				if registration {
					policy = options["authenticatorSelection"].(map[string]any)["userVerification"]
				}
				if policy != "discouraged" {
					t.Fatalf("unexpected verification policy: %v", policy)
				}
				return request(h, "POST", path, map[string]any{"request_id": b["request_id"], "credential": k.response(t, options, registration, "http://localhost:8080", "localhost", uv)}, c, csrf, "")
			}
			b := beginKey(t, h, c, csrf, "add", "")
			parseBody(t, finish(b, "/api/me/passkeys/register/finish", registeredWithUV), 200)
			c, csrf = "", ""
			b = parseBody(t, request(h, "POST", "/api/login", map[string]string{"username": "admin", "password": "long-test-password"}, "", "", ""), 200)
			if b["mfa_required"] != true {
				t.Fatal("Passkey second factor was bypassed")
			}
			w := finish(b, "/api/login/passkey/finish", false)
			result := parseBody(t, w, 200)
			c, csrf = w.Result().Cookies()[0].String(), result["csrf"].(string)
			b = beginKey(t, h, c, csrf, "disable", "")
			result = parseBody(t, finish(b, "/api/me/passkeys/finish", false), 200)
			if result["logout"] != true {
				t.Fatal("disable did not revoke sessions")
			}
		})
	}
}
