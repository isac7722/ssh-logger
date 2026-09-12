package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sshlogger/internal/model"
	"strconv"
	"strings"
	"time"
)

type App struct {
	store  *Store
	origin string
	secure bool
	webDir string
}

func reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, status int, msg string) {
	reply(w, status, map[string]string{"error": msg})
}
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		fail(w, 400, "잘못된 요청 형식입니다.")
		return false
	}
	if e := d.Decode(&struct{}{}); e != io.EOF {
		fail(w, 400, "하나의 JSON 객체만 허용합니다.")
		return false
	}
	return true
}
func (a *App) routes() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /api/health", func(w http.ResponseWriter, r *http.Request) {
		if e := a.store.db.PingContext(r.Context()); e != nil {
			fail(w, 503, "database unavailable")
			return
		}
		reply(w, 200, map[string]string{"status": "ok"})
	})
	m.HandleFunc("POST /api/login", a.login)
	m.HandleFunc("POST /api/ingest", a.ingest)
	m.HandleFunc("GET /api/me", a.auth(func(w http.ResponseWriter, r *http.Request) {
		var csrf, username string
		c, _ := r.Cookie("session")
		if e := a.store.db.QueryRowContext(r.Context(), "SELECT csrf, username FROM auth_sessions WHERE token_hash=?", hash(c.Value)).Scan(&csrf, &username); e != nil {
			fail(w, 401, "로그인이 필요합니다.")
			return
		}
		reply(w, 200, map[string]string{"csrf": csrf, "username": username, "role": identity(r).Role})
	}))
	m.HandleFunc("POST /api/logout", a.auth(a.logout))
	m.HandleFunc("PUT /api/me/password", a.auth(a.changePassword))
	m.HandleFunc("GET /api/admins", a.auth(a.super(a.admins)))
	m.HandleFunc("POST /api/admins", a.auth(a.super(a.createAdmin)))
	m.HandleFunc("DELETE /api/admins/{username}", a.auth(a.super(a.deleteAdmin)))
	m.HandleFunc("GET /api/servers", a.auth(a.servers))
	m.HandleFunc("POST /api/servers", a.auth(a.super(a.createServer)))
	m.HandleFunc("POST /api/servers/{id}/rotate", a.auth(a.super(a.rotate)))
	m.HandleFunc("POST /api/servers/{id}/revoke", a.auth(a.super(a.revoke)))
	m.HandleFunc("GET /api/events", a.auth(a.events))
	m.HandleFunc("GET /api/sessions", a.auth(a.sessions))
	m.HandleFunc("POST /api/servers/{id}/sessions/{session}/terminate", a.auth(a.assigned(a.terminateSession)))
	m.HandleFunc("PUT /api/admins/{username}/access", a.auth(a.super(a.updateAdminAccess)))
	m.HandleFunc("GET /api/servers/{id}/firewall", a.auth(a.assigned(a.firewall)))
	m.HandleFunc("PUT /api/servers/{id}/firewall/settings", a.auth(a.super(a.assigned(a.firewallSettings))))
	m.HandleFunc("POST /api/servers/{id}/bans", a.auth(a.assigned(a.banIP)))
	m.HandleFunc("DELETE /api/servers/{id}/bans/{ip}", a.auth(a.assigned(a.unbanIP)))
	m.HandleFunc("POST /api/servers/{id}/allowlist", a.auth(a.assigned(a.allowIP)))
	m.HandleFunc("DELETE /api/servers/{id}/allowlist/{ip}", a.auth(a.assigned(a.removeAllowedIP)))
	m.HandleFunc("GET /api/overview", a.auth(a.overview))
	m.HandleFunc("GET /api/settings", a.auth(a.super(a.settings)))
	m.HandleFunc("PUT /api/settings", a.auth(a.super(a.saveSettings)))
	m.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) { fail(w, 404, "API 경로를 찾을 수 없습니다.") })
	m.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" && r.Method != "HEAD" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		clean := filepath.Clean("/" + r.URL.Path)
		p := filepath.Join(a.webDir, clean)
		if stat, e := os.Stat(p); e == nil && !stat.IsDir() {
			http.ServeFile(w, r, p)
			return
		}
		if strings.Contains(filepath.Base(clean), ".") {
			http.NotFound(w, r)
			return
		}
		http.ServeFile(w, r, filepath.Join(a.webDir, "index.html"))
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Cache-Control", "no-store")
		}
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		m.ServeHTTP(w, r.WithContext(ctx))
	})
}
func (a *App) sameOrigin(r *http.Request) bool { return r.Header.Get("Origin") == a.origin }
func (a *App) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, e := r.Cookie("session")
		if e != nil {
			fail(w, 401, "로그인이 필요합니다.")
			return
		}
		var csrf string
		var p principal
		e = a.store.db.QueryRowContext(r.Context(), "SELECT s.csrf,s.username,COALESCE(a.role,'admin') FROM auth_sessions s LEFT JOIN admin_roles a ON a.username=s.username WHERE s.token_hash=? AND s.expires>?", hash(c.Value), time.Now().UnixMilli()).Scan(&csrf, &p.Username, &p.Role)
		if e != nil {
			fail(w, 401, "로그인이 만료되었습니다.")
			return
		}
		if r.Method != "GET" && (!a.sameOrigin(r) || r.Header.Get("X-CSRF-Token") != csrf) {
			fail(w, 403, "요청 출처 또는 CSRF 토큰이 올바르지 않습니다.")
			return
		}
		next(w, withIdentity(r, p))
	}
}
func (a *App) login(w http.ResponseWriter, r *http.Request) {
	if !a.sameOrigin(r) {
		fail(w, 403, "PUBLIC_ORIGIN과 접속 주소가 일치해야 합니다.")
		return
	}
	var b struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decode(w, r, &b) {
		return
	}
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	now := time.Now().UnixMilli()
	var failures int
	e := a.store.db.QueryRowContext(r.Context(), "SELECT count FROM login_attempts WHERE ip=? AND reset>?", ip, now).Scan(&failures)
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		fail(w, 503, "잠시 후 다시 시도하세요.")
		return
	}
	if failures >= 10 {
		fail(w, 429, "로그인 시도가 많습니다. 15분 후 다시 시도하세요.")
		return
	}
	var h string
	e = a.store.db.QueryRowContext(r.Context(), "SELECT password_hash FROM admins WHERE username=?", b.Username).Scan(&h)
	if e != nil {
		h = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
	}
	valid := bcrypt.CompareHashAndPassword([]byte(h), []byte(b.Password)) == nil
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		fail(w, 503, "잠시 후 다시 시도하세요.")
		return
	}
	if e != nil || !valid {
		now = time.Now().UnixMilli()
		e = a.store.transaction(r.Context(), func(tx *sql.Tx) error {
			_, err := tx.ExecContext(r.Context(), "INSERT INTO login_attempts VALUES(?,1,?) ON CONFLICT(ip) DO UPDATE SET count=CASE WHEN reset<=? THEN 1 ELSE count+1 END,reset=CASE WHEN reset<=? THEN excluded.reset ELSE reset END", ip, now+15*60*1000, now, now)
			return err
		})
		if e != nil {
			fail(w, 503, "잠시 후 다시 시도하세요.")
			return
		}
		fail(w, 401, "계정 또는 비밀번호가 올바르지 않습니다.")
		return
	}
	token, csrf := model.ID(), model.ID()
	expires := time.Now().Add(12 * time.Hour)
	e = a.store.transaction(r.Context(), func(tx *sql.Tx) error {
		// Do not issue a session for a password changed during bcrypt verification.
		res, e := tx.ExecContext(r.Context(), "INSERT INTO auth_sessions(token_hash,csrf,expires,username) SELECT ?,?,?,username FROM admins WHERE username=? AND password_hash=?", hash(token), csrf, expires.UnixMilli(), b.Username, h)
		if e != nil {
			return e
		}
		n, e := res.RowsAffected()
		if e != nil {
			return e
		}
		if n != 1 {
			return errCredentialsChanged
		}
		_, e = tx.ExecContext(r.Context(), "DELETE FROM login_attempts WHERE ip=?", ip)
		return e
	})
	if errors.Is(e, errCredentialsChanged) {
		fail(w, 401, "비밀번호가 변경되었습니다. 다시 로그인하세요.")
		return
	}
	if e != nil {
		fail(w, 503, "로그인 저장에 실패했습니다.")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "session", Value: token, Path: "/", HttpOnly: true, Secure: a.secure, SameSite: http.SameSiteStrictMode, Expires: expires, MaxAge: 43200})
	reply(w, 200, map[string]string{"csrf": csrf, "username": b.Username})
}
func (a *App) logout(w http.ResponseWriter, r *http.Request) {
	c, _ := r.Cookie("session")
	e := a.store.transaction(r.Context(), func(tx *sql.Tx) error {
		_, e := tx.ExecContext(r.Context(), "DELETE FROM auth_sessions WHERE token_hash=?", hash(c.Value))
		return e
	})
	if e != nil {
		fail(w, 503, "로그아웃에 실패했습니다.")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "session", Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: a.secure, SameSite: http.SameSiteStrictMode})
	reply(w, 200, map[string]bool{"ok": true})
}
func (a *App) query(w http.ResponseWriter, r *http.Request, q string, args ...any) {
	v, e := a.store.rows(r.Context(), q, args...)
	if e != nil {
		fail(w, 503, "데이터 조회에 실패했습니다.")
		return
	}
	reply(w, 200, v)
}
func (a *App) servers(w http.ResponseWriter, r *http.Request) {
	a.query(w, r, "SELECT id,name,created,last_seen,health,backlog,dropped,revoked FROM servers WHERE revoked=0 AND "+scope(r, "id")+" ORDER BY name")
}
func (a *App) createServer(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Name string `json:"name"`
	}
	if !decode(w, r, &b) {
		return
	}
	b.Name = strings.TrimSpace(b.Name)
	if len(b.Name) < 1 || len(b.Name) > 100 {
		fail(w, 400, "서버 이름은 1–100바이트로 입력하세요.")
		return
	}
	id, token := model.ID(), model.ID()
	e := a.store.transaction(r.Context(), func(tx *sql.Tx) error {
		_, e := tx.ExecContext(r.Context(), "INSERT INTO servers(id,name,token_hash,created) VALUES(?,?,?,?)", id, b.Name, hash(token), time.Now().UnixMilli())
		return e
	})
	if e != nil {
		fail(w, 409, "서버를 등록할 수 없습니다. 중복 이름인지 확인하세요.")
		return
	}
	reply(w, 201, map[string]string{"id": id, "token": token})
}
func (a *App) rotate(w http.ResponseWriter, r *http.Request) { a.changeToken(w, r, false) }
func (a *App) revoke(w http.ResponseWriter, r *http.Request) { a.changeToken(w, r, true) }
func (a *App) changeToken(w http.ResponseWriter, r *http.Request, revoke bool) {
	token := model.ID()
	var count int64
	pendingFirewall := errors.New("pending firewall")
	e := a.store.transaction(r.Context(), func(tx *sql.Tx) error {
		if revoke {
			var pending int
			if err := tx.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM firewall_policies WHERE server_id=? AND (json_array_length(policy,'$.bans')>0 OR json_extract(policy,'$.mode')='allowlist' OR (revision!=applied_revision AND EXISTS(SELECT 1 FROM firewall_history WHERE server_id=?)))`, r.PathValue("id"), r.PathValue("id")).Scan(&pending); err != nil {
				return err
			}
			if pending > 0 {
				return pendingFirewall
			}
		}
		v, e := tx.ExecContext(r.Context(), "UPDATE servers SET token_hash=?,revoked=? WHERE id=? AND revoked=0", hash(token), revoke, r.PathValue("id"))
		if e != nil {
			return e
		}
		count, e = v.RowsAffected()
		return e
	})
	if errors.Is(e, pendingFirewall) {
		fail(w, 409, "SSH 접근 제어를 끄고 에이전트 적용 완료를 확인한 뒤 서버를 폐기하세요.")
		return
	}
	if e != nil {
		fail(w, 503, "인증 정보 변경에 실패했습니다.")
		return
	}
	if count == 0 {
		fail(w, 404, "서버가 없습니다.")
		return
	}
	if revoke {
		reply(w, 200, map[string]bool{"ok": true})
	} else {
		reply(w, 200, map[string]string{"token": token, "id": r.PathValue("id")})
	}
}
func (a *App) ingest(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if token == "" {
		fail(w, 401, "invalid token")
		return
	}
	var b model.Batch
	if !decode(w, r, &b) {
		return
	}
	if b.FirewallResult != nil && (len(b.FirewallResult.Revision) > 100 || len(b.FirewallResult.Error) > 500) {
		fail(w, 400, "invalid firewall result")
		return
	}
	if len(b.TerminationResults) > 100 || len(b.Events) > 500 || len(b.ActiveSessions) > 10000 || len(b.Health) > 200 || b.Backlog < 0 || b.Dropped < 0 {
		fail(w, 400, "invalid batch")
		return
	}
	for _, result := range b.TerminationResults {
		if len(result.ID) > 200 || len(result.Error) > 500 {
			fail(w, 400, "invalid termination result")
			return
		}
	}
	now := time.Now().UnixMilli()
	for i := range b.Events {
		e := &b.Events[i]
		if e.ID == "" || len(e.ID) > 200 || e.Time <= 0 || e.Time > now+300000 || len(e.SessionID) > 200 || len(e.User) > 256 || len(e.LoginUID) > 64 || len(e.EffectiveUser) > 256 || len(e.IP) > 100 || len(e.Program) > 4096 || len(e.Args) > 4096 || (e.PID != nil && (*e.PID < 1 || int64(*e.PID) > 2147483647)) || (e.PPID != nil && (*e.PPID < 0 || int64(*e.PPID) > 2147483647)) {
			fail(w, 400, "invalid event")
			return
		}
		switch e.Kind {
		case "login_success", "login_failure", "session_start", "session_end", "exec":
		default:
			fail(w, 400, "invalid event kind")
			return
		}
		e.Args = model.Redact(e.Args)
	}
	for _, id := range b.ActiveSessions {
		if len(id) > 200 {
			fail(w, 400, "invalid session")
			return
		}
	}
	var commands []model.Termination
	var policy *model.FirewallPolicy
	unauthorized := errors.New("unauthorized")
	err := a.store.transaction(r.Context(), func(tx *sql.Tx) error {
		var server string
		if e := tx.QueryRowContext(r.Context(), "SELECT id FROM servers WHERE token_hash=? AND revoked=0", hash(token)).Scan(&server); e != nil {
			if e == sql.ErrNoRows {
				return unauthorized
			}
			return e
		}
		var controlErr error
		commands, controlErr = ingestTerminations(r, tx, server, b, now)
		if controlErr != nil {
			return controlErr
		}
		policy, controlErr = ingestFirewall(r, tx, server, b, now)
		if controlErr != nil {
			return controlErr
		}
		for _, e := range b.Events {
			args, _ := json.Marshal(e.Args)
			res, err := tx.ExecContext(r.Context(), `INSERT OR IGNORE INTO events(server_id,id,time,received,kind,session_id,user,login_uid,effective_user,ip,program,args,command,outcome,pid,ppid) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, server, e.ID, e.Time, now, e.Kind, e.SessionID, e.User, e.LoginUID, e.EffectiveUser, e.IP, e.Program, string(args), strings.Join(e.Args, " "), e.Outcome, e.PID, e.PPID)
			if err != nil {
				return err
			}
			n, err := res.RowsAffected()
			if err != nil {
				return err
			}
			if n == 0 {
				continue
			}
			if e.SessionID != "" && e.Kind == "session_start" {
				_, err = tx.ExecContext(r.Context(), `INSERT INTO sessions(server_id,id,user,ip,started) VALUES(?,?,?,?,?) ON CONFLICT(server_id,id) DO UPDATE SET user=excluded.user,ip=excluded.ip,started=MIN(started,excluded.started)`, server, e.SessionID, e.User, e.IP, e.Time)
			} else if e.SessionID != "" && e.Kind == "session_end" {
				_, err = tx.ExecContext(r.Context(), `INSERT INTO sessions(server_id,id,user,ip,started,ended) VALUES(?,?,?,?,?,?) ON CONFLICT(server_id,id) DO UPDATE SET ended=excluded.ended,live=0`, server, e.SessionID, e.User, e.IP, e.Time, e.Time)
			}
			if err != nil {
				return err
			}
		}
		if _, e := tx.ExecContext(r.Context(), "UPDATE sessions SET live=0 WHERE server_id=?", server); e != nil {
			return e
		}
		for _, id := range b.ActiveSessions {
			if _, e := tx.ExecContext(r.Context(), "UPDATE sessions SET live=1 WHERE server_id=? AND id=? AND ended IS NULL", server, id); e != nil {
				return e
			}
		}
		_, e := tx.ExecContext(r.Context(), "UPDATE servers SET last_seen=?,health=?,backlog=?,dropped=? WHERE id=?", now, b.Health, b.Backlog, b.Dropped, server)
		return e
	})
	if err == unauthorized {
		fail(w, 401, "invalid or revoked token")
		return
	}
	if err != nil {
		w.Header().Set("Retry-After", "5")
		fail(w, 503, "storage unavailable; retry batch")
		return
	}
	reply(w, 200, model.IngestResponse{Accepted: len(b.Events), Terminations: commands, Firewall: policy})
}
func page(r *http.Request) int {
	p, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if p < 0 {
		p = 0
	}
	if p > 100000 {
		p = 100000
	}
	return p
}
func filters(r *http.Request, alias string) (string, []any, error) {
	q := r.URL.Query()
	where := " WHERE 1=1"
	args := []any{}
	from := time.Now().Add(-24 * time.Hour).UnixMilli()
	to := time.Now().Add(time.Minute).UnixMilli()
	var e error
	if v := q.Get("from"); v != "" {
		from, e = strconv.ParseInt(v, 10, 64)
		if e != nil {
			return "", nil, e
		}
	}
	if v := q.Get("to"); v != "" {
		to, e = strconv.ParseInt(v, 10, 64)
		if e != nil {
			return "", nil, e
		}
	}
	if from < 0 || to < from || to-from > 366*24*60*60*1000 {
		return "", nil, fmt.Errorf("invalid range")
	}
	where += " AND " + alias + "time BETWEEN ? AND ?"
	args = append(args, from, to)
	for _, key := range []string{"server_id", "user", "ip", "session_id", "kind"} {
		if v := q.Get(key); v != "" {
			column := alias + key
			if key == "ip" {
				column = "COALESCE(NULLIF(e.ip,''),se.ip,'')"
			}
			where += " AND " + column + "=?"
			args = append(args, v)
		}
	}
	if v := q.Get("q"); v != "" {
		where += " AND (instr(" + alias + "command,?)>0 OR instr(" + alias + "program,?)>0)"
		args = append(args, v, v)
	}
	return where, args, nil
}
func (a *App) events(w http.ResponseWriter, r *http.Request) {
	where, args, err := filters(r, "e.")
	if err != nil {
		fail(w, 400, "조회 기간은 최대 366일이며 시작·종료 시각을 확인해야 합니다.")
		return
	}
	activity := r.URL.Query().Get("activity")
	if activity == "" {
		activity = "all"
	}
	if activity != "all" && activity != "important" && activity != "routine" {
		fail(w, 400, "activity는 important, all, routine 중 하나여야 합니다.")
		return
	}
	summary := r.URL.Query().Get("summary") == "1"
	where += " AND s.revoked=0 AND " + scope(r, "s.id")
	from := ` FROM events e JOIN servers s ON s.id=e.server_id LEFT JOIN sessions se ON se.server_id=e.server_id AND se.id=e.session_id`
	visibleWhere := where
	if activity == "important" {
		visibleWhere += " AND (" + routineReasonSQL + ")=''"
	}
	if activity == "routine" {
		visibleWhere += " AND (" + routineReasonSQL + ")!=''"
	}
	selectSQL := `SELECT e.*,COALESCE(NULLIF(e.ip,''),se.ip,'') AS ip,s.name AS server_name,CASE WHEN se.id IS NOT NULL THEN 1 ELSE 0 END AS linked,` + routineReasonSQL + ` AS routine_reason` + from + visibleWhere + ` ORDER BY e.time DESC,e.seq DESC LIMIT 51 OFFSET ?`
	pageArgs := append(append([]any{}, args...), page(r)*50)
	if !summary {
		a.query(w, r, selectSQL, pageArgs...)
		return
	}
	// Counts and page share a read snapshot. Filtering happens before pagination,
	// including when the latest 50+ records are all routine commands.
	tx, err := a.store.db.BeginTx(r.Context(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		fail(w, 503, "데이터 조회에 실패했습니다.")
		return
	}
	defer tx.Rollback()
	var total, routine int64
	err = tx.QueryRowContext(r.Context(), `SELECT COUNT(*),COALESCE(SUM(CASE WHEN (`+routineReasonSQL+`)!='' THEN 1 ELSE 0 END),0)`+from+where, args...).Scan(&total, &routine)
	if err != nil {
		fail(w, 503, "활동 집계에 실패했습니다.")
		return
	}
	items, err := queryRows(r.Context(), tx, selectSQL, pageArgs...)
	if err != nil {
		fail(w, 503, "데이터 조회에 실패했습니다.")
		return
	}
	if err = tx.Commit(); err != nil {
		fail(w, 503, "데이터 조회에 실패했습니다.")
		return
	}
	visible := total
	if activity == "important" {
		visible = total - routine
	}
	if activity == "routine" {
		visible = routine
	}
	reply(w, 200, map[string]any{"items": items, "total_count": total, "routine_count": routine, "visible_count": visible, "activity": activity})
}
func (a *App) sessions(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	where := " WHERE s.revoked=0 AND " + scope(r, "s.id")
	args := []any{time.Now().Add(-60 * time.Second).UnixMilli()}
	for _, key := range []string{"server_id", "user", "ip"} {
		if v := q.Get(key); v != "" {
			where += " AND se." + key + "=?"
			args = append(args, v)
		}
	}
	if q.Get("active") == "1" {
		where += " AND se.ended IS NULL"
	}
	args = append(args, page(r)*50)
	a.query(w, r, `SELECT se.*,s.name AS server_name,COALESCE((SELECT enabled FROM server_control WHERE server_id=s.id),0) AS can_terminate,
 (SELECT CASE WHEN status='pending' AND expires<CAST(strftime('%s','now') AS INTEGER)*1000 THEN 'expired' ELSE status END FROM session_terminations WHERE server_id=se.server_id AND session_id=se.id ORDER BY created DESC,rowid DESC LIMIT 1) AS termination_status,
 (SELECT error FROM session_terminations WHERE server_id=se.server_id AND session_id=se.id ORDER BY created DESC,rowid DESC LIMIT 1) AS termination_error,CASE WHEN se.ended IS NOT NULL THEN 'ended' WHEN se.live=1 AND s.last_seen>? AND s.revoked=0 AND s.health='ok' THEN 'active' ELSE 'unknown' END AS status FROM sessions se JOIN servers s ON s.id=se.server_id`+where+` ORDER BY se.started DESC LIMIT 51 OFFSET ?`, args...)
}
func (a *App) overview(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	start := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC).UnixMilli()
	if v := r.URL.Query().Get("day_start"); v != "" {
		n, e := strconv.ParseInt(v, 10, 64)
		if e != nil || n > now.UnixMilli() || n < now.Add(-26*time.Hour).UnixMilli() {
			fail(w, 400, "invalid day start")
			return
		}
		start = n
	}
	a.query(w, r, `WITH visible_servers AS (SELECT * FROM servers WHERE `+scope(r, "id")+`) SELECT (SELECT COUNT(*) FROM sessions se JOIN visible_servers s ON s.id=se.server_id WHERE ended IS NULL AND live=1 AND last_seen>? AND s.health='ok' AND revoked=0) AS active,(SELECT COUNT(*) FROM events e JOIN visible_servers s ON s.id=e.server_id WHERE s.revoked=0 AND e.kind='session_start' AND e.time>=?) AS logins,(SELECT COUNT(*) FROM events e JOIN visible_servers s ON s.id=e.server_id WHERE s.revoked=0 AND e.kind='login_failure' AND e.time>=?) AS failures,(SELECT COUNT(*) FROM visible_servers WHERE last_seen>? AND health='ok' AND revoked=0) AS healthy,(SELECT COUNT(*) FROM visible_servers WHERE revoked=0) AS total,(SELECT COUNT(*) FROM sessions se JOIN visible_servers s ON s.id=se.server_id WHERE s.revoked=0 AND ended IS NULL AND (live=0 OR last_seen<=? OR health!='ok')) AS unknown`, now.Add(-60*time.Second).UnixMilli(), start, start, now.Add(-60*time.Second).UnixMilli(), now.Add(-60*time.Second).UnixMilli())
}
func (a *App) settings(w http.ResponseWriter, r *http.Request) {
	a.query(w, r, "SELECT retention_days FROM settings")
}
func (a *App) saveSettings(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Days int `json:"retention_days"`
	}
	if !decode(w, r, &b) {
		return
	}
	if b.Days < 1 || b.Days > 365 {
		fail(w, 400, "보관 기간은 1–365일입니다.")
		return
	}
	e := a.store.transaction(r.Context(), func(tx *sql.Tx) error {
		_, e := tx.ExecContext(r.Context(), "UPDATE settings SET retention_days=? WHERE id=1", b.Days)
		return e
	})
	if e != nil {
		fail(w, 503, "설정 저장에 실패했습니다.")
		return
	}
	reply(w, 200, map[string]bool{"ok": true})
}
