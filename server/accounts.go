package main

import (
	"database/sql"
	"errors"
	"net/http"
	"regexp"
	"time"

	"golang.org/x/crypto/bcrypt"
)

var errCredentialsChanged = errors.New("credentials changed")
var adminUsername = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

func validPassword(password string) bool { return len(password) >= 12 && len(password) <= 72 }

func (a *App) admins(w http.ResponseWriter, r *http.Request) {
	a.query(w, r, "SELECT a.username,COALESCE(r.role,'admin') AS role,COALESCE((SELECT json_group_array(server_id) FROM admin_servers WHERE username=a.username),'[]') AS server_ids FROM admins a LEFT JOIN admin_roles r ON r.username=a.username ORDER BY a.username")
}

func (a *App) createAdmin(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decode(w, r, &b) {
		return
	}
	if !adminUsername.MatchString(b.Username) {
		fail(w, 400, "계정명은 영문·숫자로 시작하는 1–64자의 영문·숫자·점·밑줄·하이픈만 사용할 수 있습니다.")
		return
	}
	if !validPassword(b.Password) {
		fail(w, 400, "비밀번호는 UTF-8 기준 12–72바이트여야 합니다.")
		return
	}
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(b.Password), bcrypt.DefaultCost)
	if err != nil {
		fail(w, 503, "비밀번호 저장을 준비하지 못했습니다.")
		return
	}
	var created bool
	err = a.store.transaction(r.Context(), func(tx *sql.Tx) error {
		c, _ := r.Cookie("session")
		var active int
		if err := tx.QueryRowContext(r.Context(), "SELECT COUNT(*) FROM auth_sessions WHERE token_hash=? AND expires>?", hash(c.Value), time.Now().UnixMilli()).Scan(&active); err != nil {
			return err
		}
		if active != 1 {
			return errCredentialsChanged
		}
		res, err := tx.ExecContext(r.Context(), "INSERT INTO admins(username,password_hash) VALUES(?,?) ON CONFLICT(username) DO NOTHING", b.Username, string(passwordHash))
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		created = n == 1
		return err
	})
	if errors.Is(err, errCredentialsChanged) {
		fail(w, 401, "다시 로그인하세요.")
		return
	}
	if err != nil {
		fail(w, 503, "관리자 계정 저장에 실패했습니다.")
		return
	}
	if !created {
		fail(w, 409, "이미 사용 중인 관리자 계정명입니다.")
		return
	}
	reply(w, 201, map[string]string{"username": b.Username})
}

func (a *App) changePassword(w http.ResponseWriter, r *http.Request) {
	var b struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if !decode(w, r, &b) {
		return
	}
	if !validPassword(b.NewPassword) {
		fail(w, 400, "새 비밀번호는 UTF-8 기준 12–72바이트여야 합니다.")
		return
	}
	c, _ := r.Cookie("session")
	var username, oldHash string
	err := a.store.db.QueryRowContext(r.Context(), "SELECT a.username,a.password_hash FROM admins a JOIN auth_sessions s ON s.username=a.username WHERE s.token_hash=? AND s.expires>?", hash(c.Value), time.Now().UnixMilli()).Scan(&username, &oldHash)
	if errors.Is(err, sql.ErrNoRows) {
		fail(w, 401, "다시 로그인하세요.")
		return
	}
	if err != nil {
		fail(w, 503, "계정 정보를 확인하지 못했습니다.")
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(oldHash), []byte(b.CurrentPassword)) != nil {
		fail(w, 400, "현재 비밀번호가 올바르지 않습니다.")
		return
	}
	if b.CurrentPassword == b.NewPassword {
		fail(w, 400, "현재 비밀번호와 다른 새 비밀번호를 입력하세요.")
		return
	}
	newHash, err := bcrypt.GenerateFromPassword([]byte(b.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		fail(w, 503, "비밀번호 저장을 준비하지 못했습니다.")
		return
	}
	err = a.store.transaction(r.Context(), func(tx *sql.Tx) error {
		res, err := tx.ExecContext(r.Context(), "UPDATE admins SET password_hash=? WHERE username=? AND password_hash=? AND EXISTS(SELECT 1 FROM auth_sessions WHERE token_hash=? AND expires>?)", string(newHash), username, oldHash, hash(c.Value), time.Now().UnixMilli())
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n != 1 {
			return errCredentialsChanged
		}
		_, err = tx.ExecContext(r.Context(), "DELETE FROM auth_sessions WHERE username=?", username)
		return err
	})
	if errors.Is(err, errCredentialsChanged) {
		fail(w, 401, "계정 정보가 변경되었습니다. 다시 로그인하세요.")
		return
	}
	if err != nil {
		fail(w, 503, "비밀번호 변경에 실패했습니다.")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "session", Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: a.secure, SameSite: http.SameSiteStrictMode})
	reply(w, 200, map[string]string{"status": "ok"})
}
