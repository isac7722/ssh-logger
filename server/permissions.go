package main

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
)

type principal struct{ Username, Role string }
type principalKey struct{}

func identity(r *http.Request) principal {
	p, _ := r.Context().Value(principalKey{}).(principal)
	return p
}
func scope(r *http.Request, column string) string {
	p := identity(r)
	if p.Role == "super_admin" {
		return "1=1"
	}
	return column + " IN (SELECT server_id FROM admin_servers WHERE username=" + sqlLiteral(p.Username) + ")"
}
func (a *App) super(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if identity(r).Role != "super_admin" {
			fail(w, 403, "Super admin 권한이 필요합니다.")
			return
		}
		next(w, r)
	}
}
func (a *App) assigned(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var n int
		if err := a.store.db.QueryRowContext(r.Context(), "SELECT 1 FROM servers WHERE id=? AND revoked=0 AND "+scope(r, "id"), r.PathValue("id")).Scan(&n); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				fail(w, 404, "접근 가능한 서버가 없습니다.")
			} else {
				fail(w, 503, "권한 조회 실패")
			}
			return
		}
		next(w, r)
	}
}
func (a *App) updateAdminAccess(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Role    string   `json:"role"`
		Servers []string `json:"server_ids"`
	}
	if !decode(w, r, &b) {
		return
	}
	if (b.Role != "super_admin" && b.Role != "admin") || len(b.Servers) > 1000 {
		fail(w, 400, "잘못된 권한 설정입니다.")
		return
	}
	target := r.PathValue("username")
	invalid := errors.New("invalid")
	err := a.store.transaction(r.Context(), func(tx *sql.Tx) error {
		var n int
		if e := tx.QueryRowContext(r.Context(), "SELECT COUNT(*) FROM admins WHERE username=?", target).Scan(&n); e != nil {
			return e
		}
		if n != 1 {
			return invalid
		}
		if b.Role != "super_admin" {
			if e := tx.QueryRowContext(r.Context(), "SELECT COUNT(*) FROM admin_roles WHERE role='super_admin' AND username!=?", target).Scan(&n); e != nil {
				return e
			}
			if n == 0 {
				return invalid
			}
		}
		if _, e := tx.ExecContext(r.Context(), "DELETE FROM admin_servers WHERE username=?", target); e != nil {
			return e
		}
		for _, id := range b.Servers {
			if e := tx.QueryRowContext(r.Context(), "SELECT COUNT(*) FROM servers WHERE id=? AND revoked=0", id).Scan(&n); e != nil {
				return e
			}
			if n != 1 {
				return invalid
			}
			if _, e := tx.ExecContext(r.Context(), "INSERT OR IGNORE INTO admin_servers VALUES(?,?)", target, id); e != nil {
				return e
			}
		}
		_, e := tx.ExecContext(r.Context(), "INSERT INTO admin_roles VALUES(?,?) ON CONFLICT(username) DO UPDATE SET role=excluded.role", target, b.Role)
		return e
	})
	if errors.Is(err, invalid) {
		fail(w, 400, "계정·서버를 확인하세요. 마지막 super admin은 해제할 수 없습니다.")
		return
	}
	if err != nil {
		fail(w, 503, "권한 저장 실패")
		return
	}
	reply(w, 200, map[string]bool{"ok": true})
}
func withIdentity(r *http.Request, p principal) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), principalKey{}, p))
}
