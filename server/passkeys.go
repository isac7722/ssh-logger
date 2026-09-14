package main

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"golang.org/x/crypto/bcrypt"
	"sshlogger/internal/model"
)

const ceremonyTTL = 5 * time.Minute

type passkeyUser struct {
	Name, ID, PasswordHash string
	Version                int
	Credentials            []webauthn.Credential
	Total                  int
}

func (u *passkeyUser) WebAuthnID() []byte                         { return []byte(u.ID) }
func (u *passkeyUser) WebAuthnName() string                       { return u.Name }
func (u *passkeyUser) WebAuthnDisplayName() string                { return u.Name }
func (u *passkeyUser) WebAuthnCredentials() []webauthn.Credential { return u.Credentials }

type pendingAuth struct {
	Username, PasswordHash, SessionHash, Purpose, Target, Name, RPID, Origin, IP string
	Version                                                                      int
	Session                                                                      webauthn.SessionData
}
type ceremonyResponse struct {
	MFARequired bool   `json:"mfa_required,omitempty"`
	RequestID   string `json:"request_id,omitempty"`
	Step        string `json:"step,omitempty"`
	Options     any    `json:"options,omitempty"`
	Logout      bool   `json:"logout,omitempty"`
}
type authProblem struct {
	code    int
	message string
}

func (e *authProblem) Error() string { return e.message }
func invalidAuth() error {
	return &authProblem{400, "인증이 유효하지 않거나 만료되었습니다. 처음부터 다시 시도하세요."}
}

func (a *App) webAuthn() (*webauthn.WebAuthn, error) {
	u, err := url.Parse(a.origin)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" || (u.Scheme != "https" && !(u.Scheme == "http" && u.Hostname() == "localhost")) || net.ParseIP(u.Hostname()) != nil {
		return nil, &authProblem{503, "Passkey는 HTTPS 도메인 또는 http://localhost 접속 설정이 필요합니다."}
	}
	return webauthn.New(&webauthn.Config{RPID: u.Hostname(), RPDisplayName: "SSH Logger", RPOrigins: []string{a.origin},
		AttestationPreference:  protocol.PreferNoAttestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{ResidentKey: protocol.ResidentKeyRequirementRequired, UserVerification: protocol.VerificationDiscouraged},
		Timeouts:               webauthn.TimeoutsConfig{Login: webauthn.TimeoutConfig{Enforce: true, Timeout: ceremonyTTL, TimeoutUVD: ceremonyTTL}, Registration: webauthn.TimeoutConfig{Enforce: true, Timeout: ceremonyTTL, TimeoutUVD: ceremonyTTL}},
	})
}
func (a *App) loadPasskeyUser(tx *sql.Tx, name, rp string) (*passkeyUser, error) {
	if _, err := tx.Exec("INSERT OR IGNORE INTO account_auth(username,user_id) SELECT username,? FROM admins WHERE username=?", model.ID(), name); err != nil {
		return nil, err
	}
	u := &passkeyUser{Name: name}
	if err := tx.QueryRow("SELECT a.password_hash,s.user_id,s.version FROM admins a JOIN account_auth s ON s.username=a.username WHERE a.username=?", name).Scan(&u.PasswordHash, &u.ID, &u.Version); err != nil {
		return nil, err
	}
	rows, err := tx.Query("SELECT rp_id,credential FROM passkeys WHERE username=?", name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var storedRP, raw string
		if err = rows.Scan(&storedRP, &raw); err != nil {
			return nil, err
		}
		u.Total++
		if storedRP == rp {
			var c webauthn.Credential
			if err = json.Unmarshal([]byte(raw), &c); err != nil {
				return nil, err
			}
			u.Credentials = append(u.Credentials, c)
		}
	}
	return u, rows.Err()
}
func sessionHash(r *http.Request) string {
	if c, e := r.Cookie("session"); e == nil {
		return hash(c.Value)
	}
	return ""
}
func checkLimit(tx *sql.Tx, key string) error {
	var count int
	err := tx.QueryRow("SELECT count FROM auth_limits WHERE key=? AND reset>?", key, time.Now().UnixMilli()).Scan(&count)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if count >= 10 {
		return &authProblem{429, "인증 시도가 많습니다. 15분 후 다시 시도하세요."}
	}
	return nil
}
func recordFailure(tx *sql.Tx, key string) error {
	now := time.Now().UnixMilli()
	_, err := tx.Exec("INSERT INTO auth_limits VALUES(?,1,?) ON CONFLICT(key) DO UPDATE SET count=CASE WHEN reset<=? THEN 1 ELSE count+1 END,reset=CASE WHEN reset<=? THEN excluded.reset ELSE reset END", key, now+15*60*1000, now, now)
	return err
}
func checkActiveSession(tx *sql.Tx, session, username string) error {
	var n int
	if err := tx.QueryRow("SELECT COUNT(*) FROM auth_sessions WHERE token_hash=? AND username=? AND expires>?", session, username, time.Now().UnixMilli()).Scan(&n); err != nil {
		return err
	}
	if n != 1 {
		return &authProblem{401, "다시 로그인하세요."}
	}
	return nil
}
func savePending(tx *sql.Tx, p pendingAuth) (string, error) {
	id := model.ID()
	raw, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	// Bound abandoned requests per account, including requests from cancelled browser prompts.
	if _, err = tx.Exec("DELETE FROM auth_pending WHERE username=? AND (expires<=? OR id_hash IN (SELECT id_hash FROM auth_pending WHERE username=? ORDER BY expires DESC LIMIT -1 OFFSET 9))", p.Username, time.Now().UnixMilli(), p.Username); err != nil {
		return "", err
	}
	_, err = tx.Exec("INSERT INTO auth_pending VALUES(?,?,?,?)", hash(id), p.Username, time.Now().Add(ceremonyTTL).UnixMilli(), string(raw))
	return id, err
}
func (a *App) beginCeremony(tx *sql.Tx, wa *webauthn.WebAuthn, u *passkeyUser, p pendingAuth, registration bool) (ceremonyResponse, error) {
	var options any
	var data *webauthn.SessionData
	var err error
	step := "authenticate"
	if registration {
		step = "register"
		exclude := []protocol.CredentialDescriptor{}
		for _, c := range u.Credentials {
			exclude = append(exclude, c.Descriptor())
		}
		var creation *protocol.CredentialCreation
		creation, data, err = wa.BeginRegistration(u, webauthn.WithExclusions(exclude), webauthn.WithRegistrationOrigin(a.origin))
		if err == nil {
			options = creation.Response
		}
	} else {
		if len(u.Credentials) == 0 {
			return ceremonyResponse{}, &authProblem{400, "현재 도메인에서 사용할 Passkey가 없습니다. 서버 운영자에게 복구를 요청하세요."}
		}
		var assertion *protocol.CredentialAssertion
		assertion, data, err = wa.BeginLogin(u, webauthn.WithUserVerification(protocol.VerificationDiscouraged), webauthn.WithLoginOrigin(a.origin))
		if err == nil {
			options = assertion.Response
		}
	}
	if err != nil {
		return ceremonyResponse{}, err
	}
	p.Username = u.Name
	p.PasswordHash = u.PasswordHash
	p.Version = u.Version
	p.RPID = wa.Config.RPID
	p.Origin = a.origin
	p.Session = *data
	id, err := savePending(tx, p)
	return ceremonyResponse{RequestID: id, Step: step, Options: options, MFARequired: p.Purpose == "login"}, err
}

// Client failures are committed so consumed requests and failure counters cannot be replayed.
// Storage errors roll back the entire operation, including credential/session changes.
func (a *App) authTransaction(w http.ResponseWriter, r *http.Request, fn func(*sql.Tx) (any, error)) {
	var result any
	var problem *authProblem
	err := a.store.transaction(r.Context(), func(tx *sql.Tx) error {
		var err error
		result, err = fn(tx)
		if errors.As(err, &problem) {
			return nil
		}
		return err
	})
	if err != nil {
		fail(w, 503, "인증 정보를 저장하지 못했습니다. 다시 시도하세요.")
		return
	}
	if problem != nil {
		fail(w, problem.code, problem.message)
		return
	}
	if outcome, ok := result.(ceremonyResponse); ok && outcome.Logout {
		a.clearSessionCookie(w)
	}
	if login, ok := result.(completedLogin); ok {
		a.setSessionCookie(w, login.Token, login.Expires)
		reply(w, 200, map[string]string{"csrf": login.CSRF, "username": login.Username})
		return
	}
	reply(w, 200, result)
}
func (a *App) passkeyList(w http.ResponseWriter, r *http.Request) {
	rows, err := a.store.rows(r.Context(), "SELECT id,name,created,last_used FROM passkeys WHERE username=? ORDER BY created,id", identity(r).Username)
	if err != nil {
		fail(w, 503, "Passkey 목록을 불러오지 못했습니다.")
		return
	}
	_, configErr := a.webAuthn()
	reply(w, 200, map[string]any{"enabled": len(rows) > 0, "passkeys": rows, "available": configErr == nil})
}
func (a *App) passkeyBegin(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Password string `json:"password"`
		Action   string `json:"action"`
		Target   string `json:"target"`
		Name     string `json:"name"`
	}
	if !decode(w, r, &b) {
		return
	}
	b.Name = strings.TrimSpace(b.Name)
	if (b.Action != "add" && b.Action != "delete" && b.Action != "disable") || (b.Action == "add" && (b.Name == "" || utf8.RuneCountInString(b.Name) > 80)) || (b.Action == "delete" && b.Target == "") {
		fail(w, 400, "작업과 Passkey 이름(1–80자)을 확인하세요.")
		return
	}
	a.authTransaction(w, r, func(tx *sql.Tx) (any, error) {
		wa, err := a.webAuthn()
		if err != nil {
			return nil, err
		}
		name := identity(r).Username
		key := "manage:" + name
		if err = checkActiveSession(tx, sessionHash(r), name); err != nil {
			return nil, err
		}
		if err = checkLimit(tx, key); err != nil {
			return nil, err
		}
		u, err := a.loadPasskeyUser(tx, name, wa.Config.RPID)
		if err != nil {
			return nil, err
		}
		if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(b.Password)) != nil {
			if err = recordFailure(tx, key); err != nil {
				return nil, err
			}
			return nil, &authProblem{400, "현재 비밀번호가 올바르지 않습니다."}
		}
		if b.Action != "add" && u.Total == 0 {
			return nil, invalidAuth()
		}
		if b.Action == "delete" {
			var n int
			if err = tx.QueryRow("SELECT COUNT(*) FROM passkeys WHERE id=? AND username=?", b.Target, name).Scan(&n); err != nil {
				return nil, err
			}
			if n != 1 {
				return nil, invalidAuth()
			}
		}
		p := pendingAuth{Purpose: b.Action, Target: b.Target, Name: b.Name, SessionHash: sessionHash(r)}
		if u.Total == 0 {
			p.Purpose = "register"
		}
		return a.beginCeremony(tx, wa, u, p, u.Total == 0)
	})
}
func invalidatePending(tx *sql.Tx, username string) error {
	if _, err := tx.Exec("UPDATE account_auth SET version=version+1 WHERE username=?", username); err != nil {
		return err
	}
	_, err := tx.Exec("DELETE FROM auth_pending WHERE username=?", username)
	return err
}
func revokeAfterPasskeyChange(tx *sql.Tx, name, current string, all bool) error {
	if err := invalidatePending(tx, name); err != nil {
		return err
	}
	if all {
		current = ""
	}
	_, err := tx.Exec("DELETE FROM auth_sessions WHERE username=? AND token_hash<>?", name, current)
	return err
}
func (s *Store) resetTwoFactor(ctx context.Context, username string) error {
	return s.transaction(ctx, func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRow("SELECT COUNT(*) FROM admins WHERE username=?", username).Scan(&n); err != nil {
			return err
		}
		if n != 1 {
			return fmt.Errorf("account not found: %s", username)
		}
		if _, err := tx.Exec("DELETE FROM passkeys WHERE username=?", username); err != nil {
			return err
		}
		if _, err := tx.Exec("DELETE FROM auth_limits WHERE key IN (?,?)", "manage:"+username, "login:"+username); err != nil {
			return err
		}
		return revokeAfterPasskeyChange(tx, username, "", true)
	})
}
func (a *App) passkeyFinish(w http.ResponseWriter, r *http.Request) {
	a.finishCeremony(w, r, false, false)
}
func (a *App) registrationFinish(w http.ResponseWriter, r *http.Request) {
	a.finishCeremony(w, r, true, false)
}
func (a *App) passkeyLoginFinish(w http.ResponseWriter, r *http.Request) {
	a.finishCeremony(w, r, false, true)
}
func (a *App) finishCeremony(w http.ResponseWriter, r *http.Request, registration, login bool) {
	if !a.sameOrigin(r) {
		fail(w, 403, "요청 출처가 올바르지 않습니다.")
		return
	}
	var b struct {
		RequestID  string          `json:"request_id"`
		Credential json.RawMessage `json:"credential"`
	}
	if !decode(w, r, &b) {
		return
	}
	a.authTransaction(w, r, func(tx *sql.Tx) (any, error) {
		var raw string
		var expires int64
		if err := tx.QueryRow("SELECT data,expires FROM auth_pending WHERE id_hash=?", hash(b.RequestID)).Scan(&raw, &expires); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, invalidAuth()
			}
			return nil, err
		}
		var p pendingAuth
		if err := json.Unmarshal([]byte(raw), &p); err != nil {
			return nil, err
		}
		// Wrong sessions/endpoints must not consume another user's pending request.
		if (p.Purpose == "login") != login || (p.Purpose == "register") != registration || (!login && (p.SessionHash != sessionHash(r) || p.Username != identity(r).Username)) {
			return nil, invalidAuth()
		}
		if _, err := tx.Exec("DELETE FROM auth_pending WHERE id_hash=?", hash(b.RequestID)); err != nil {
			return nil, err
		}
		if expires <= time.Now().UnixMilli() {
			return nil, invalidAuth()
		}
		if !login {
			if err := checkActiveSession(tx, p.SessionHash, p.Username); err != nil {
				return nil, err
			}
		}
		wa, err := a.webAuthn()
		if err != nil {
			return nil, err
		}
		u, err := a.loadPasskeyUser(tx, p.Username, wa.Config.RPID)
		if err != nil {
			return nil, err
		}
		if p.Version != u.Version || p.PasswordHash != u.PasswordHash || p.RPID != wa.Config.RPID || p.Origin != a.origin {
			return nil, invalidAuth()
		}
		key := "manage:" + p.Username
		if login {
			key = "login:" + p.Username
		}
		if err = checkLimit(tx, key); err != nil {
			return nil, err
		}
		var credential *webauthn.Credential
		if registration {
			var parsed *protocol.ParsedCredentialCreationData
			parsed, err = protocol.ParseCredentialCreationResponseBytes(b.Credential)
			if err == nil {
				credential, err = wa.CreateCredential(u, p.Session, parsed)
			}
		} else {
			var parsed *protocol.ParsedCredentialAssertionData
			parsed, err = protocol.ParseCredentialRequestResponseBytes(b.Credential)
			if err == nil {
				credential, err = wa.ValidateLogin(u, p.Session, parsed)
			}
		}
		if err != nil {
			if err = recordFailure(tx, key); err != nil {
				return nil, err
			}
			return nil, invalidAuth()
		}
		id := base64.RawURLEncoding.EncodeToString(credential.ID)
		encoded, err := json.Marshal(credential)
		if err != nil {
			return nil, err
		}
		now := time.Now().UnixMilli()
		if registration {
			var n int
			if err = tx.QueryRow("SELECT COUNT(*) FROM passkeys WHERE id=?", id).Scan(&n); err != nil {
				return nil, err
			}
			if n != 0 {
				return nil, &authProblem{409, "이미 등록된 Passkey입니다."}
			}
			if _, err = tx.Exec("INSERT INTO passkeys(id,username,rp_id,credential,name,created) VALUES(?,?,?,?,?,?)", id, u.Name, p.RPID, string(encoded), p.Name, now); err != nil {
				return nil, err
			}
			if err = revokeAfterPasskeyChange(tx, u.Name, p.SessionHash, u.Total == 0); err != nil {
				return nil, err
			}
		} else {
			if _, err = tx.Exec("UPDATE passkeys SET credential=?,last_used=? WHERE id=? AND username=?", string(encoded), now, id, u.Name); err != nil {
				return nil, err
			}
			if p.Purpose == "add" {
				p.Purpose = "register"
				return a.beginCeremony(tx, wa, u, p, true)
			}
			if !login {
				if p.Purpose == "disable" {
					_, err = tx.Exec("DELETE FROM passkeys WHERE username=?", u.Name)
				} else {
					_, err = tx.Exec("DELETE FROM passkeys WHERE username=? AND id=?", u.Name, p.Target)
				}
				if err != nil {
					return nil, err
				}
				if err = revokeAfterPasskeyChange(tx, u.Name, p.SessionHash, p.Purpose == "disable" || u.Total == 1); err != nil {
					return nil, err
				}
			}
		}
		if _, err = tx.Exec("DELETE FROM auth_limits WHERE key=?", key); err != nil {
			return nil, err
		}
		if login {
			result, err := createLoginSession(tx, u.Name)
			if err != nil {
				return nil, err
			}
			_, err = tx.Exec("DELETE FROM login_attempts WHERE ip=?", p.IP)
			return result, err
		}
		return ceremonyResponse{Logout: (registration && u.Total == 0) || (!registration && (p.Purpose == "disable" || u.Total == 1))}, nil
	})
}

type completedLogin struct {
	Token, CSRF, Username string
	Expires               time.Time
}

func createLoginSession(tx *sql.Tx, name string) (completedLogin, error) {
	c := completedLogin{Token: model.ID(), CSRF: model.ID(), Username: name, Expires: time.Now().Add(12 * time.Hour)}
	_, err := tx.Exec("INSERT INTO auth_sessions(token_hash,csrf,expires,username) VALUES(?,?,?,?)", hash(c.Token), c.CSRF, c.Expires.UnixMilli(), name)
	return c, err
}
func (a *App) setSessionCookie(w http.ResponseWriter, token string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{Name: "session", Value: token, Path: "/", HttpOnly: true, Secure: a.secure, SameSite: http.SameSiteStrictMode, Expires: expires, MaxAge: 43200})
}
func (a *App) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: "session", Value: "", Path: "/", HttpOnly: true, Secure: a.secure, SameSite: http.SameSiteStrictMode, MaxAge: -1})
}
