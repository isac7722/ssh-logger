package main

import (
	"database/sql"
	"errors"
	"net/http"
	"sshlogger/internal/model"
	"time"
)

func (a *App) terminateSession(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UnixMilli()
	unavailable := errors.New("unavailable")
	var id string
	err := a.store.transaction(r.Context(), func(tx *sql.Tx) error {
		var valid int
		err := tx.QueryRowContext(r.Context(), `SELECT 1 FROM sessions se JOIN servers s ON s.id=se.server_id JOIN server_control c ON c.server_id=s.id WHERE se.server_id=? AND se.id=? AND se.ended IS NULL AND se.live=1 AND s.revoked=0 AND s.health='ok' AND s.last_seen>? AND c.enabled=1`, r.PathValue("id"), r.PathValue("session"), now-60000).Scan(&valid)
		if errors.Is(err, sql.ErrNoRows) {
			return unavailable
		}
		if err != nil {
			return err
		}
		err = tx.QueryRowContext(r.Context(), `SELECT id FROM session_terminations WHERE server_id=? AND session_id=? AND status='pending' AND expires>? LIMIT 1`, r.PathValue("id"), r.PathValue("session"), now).Scan(&id)
		if err == nil {
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		cookie, _ := r.Cookie("session")
		id = model.ID()
		_, err = tx.ExecContext(r.Context(), `INSERT INTO session_terminations(id,server_id,session_id,requested_by,created,expires,status) SELECT ?,?,?,username,?,?,'pending' FROM auth_sessions WHERE token_hash=?`, id, r.PathValue("id"), r.PathValue("session"), now, now+30000, hash(cookie.Value))
		return err
	})
	if errors.Is(err, unavailable) {
		fail(w, 409, "종료 가능한 활성 세션이 아닙니다. 에이전트 업데이트와 연결 상태를 확인하세요.")
		return
	}
	if err != nil {
		fail(w, 503, "종료 요청 저장에 실패했습니다.")
		return
	}
	reply(w, 202, map[string]string{"id": id, "status": "pending"})
}

func ingestTerminations(r *http.Request, tx *sql.Tx, server string, b model.Batch, now int64) ([]model.Termination, error) {
	ctx := r.Context()
	if _, err := tx.ExecContext(ctx, `INSERT INTO server_control VALUES(?,?) ON CONFLICT(server_id) DO UPDATE SET enabled=excluded.enabled`, server, b.CanTerminate); err != nil {
		return nil, err
	}
	for _, result := range b.TerminationResults {
		status := "succeeded"
		if result.Error != "" {
			status = "failed"
		}
		if status == "succeeded" {
			if _, err := tx.ExecContext(ctx, `UPDATE sessions SET ended=COALESCE(ended,?),live=0 WHERE server_id=? AND id=(SELECT session_id FROM session_terminations WHERE id=? AND server_id=? AND status='pending')`, now, server, result.ID, server); err != nil {
				return nil, err
			}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE session_terminations SET status=?,error=? WHERE id=? AND server_id=? AND status='pending'`, status, result.Error, result.ID, server); err != nil {
			return nil, err
		}
	}
	if !b.CanTerminate {
		return nil, nil
	}
	rows, err := tx.QueryContext(ctx, `SELECT id,session_id,expires FROM session_terminations WHERE server_id=? AND status='pending' AND expires>? ORDER BY created LIMIT 100`, server, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	commands := []model.Termination{}
	for rows.Next() {
		var c model.Termination
		if err = rows.Scan(&c.ID, &c.SessionID, &c.Expires); err != nil {
			return nil, err
		}
		commands = append(commands, c)
	}
	return commands, rows.Err()
}
