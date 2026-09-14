package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	_ "modernc.org/sqlite"
	"os"
	"path/filepath"

	"time"
)

type Store struct {
	db     *sql.DB
	writer chan struct{}
}

func openStore(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db, writer: make(chan struct{}, 1)}
	_, err = db.Exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000; PRAGMA foreign_keys=ON;
 CREATE TABLE IF NOT EXISTS schema_version(version INTEGER NOT NULL);
 INSERT INTO schema_version SELECT 1 WHERE NOT EXISTS(SELECT 1 FROM schema_version);
 CREATE TABLE IF NOT EXISTS admins(username TEXT PRIMARY KEY,password_hash TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS auth_sessions(token_hash TEXT PRIMARY KEY,csrf TEXT NOT NULL,expires INTEGER NOT NULL);
 CREATE TABLE IF NOT EXISTS settings(id INTEGER PRIMARY KEY CHECK(id=1),retention_days INTEGER NOT NULL);
 INSERT OR IGNORE INTO settings VALUES(1,30);
 CREATE TABLE IF NOT EXISTS servers(id TEXT PRIMARY KEY,name TEXT NOT NULL UNIQUE,token_hash TEXT NOT NULL UNIQUE,created INTEGER NOT NULL,last_seen INTEGER NOT NULL DEFAULT 0,health TEXT NOT NULL DEFAULT 'waiting',backlog INTEGER NOT NULL DEFAULT 0,dropped INTEGER NOT NULL DEFAULT 0,revoked INTEGER NOT NULL DEFAULT 0);
 CREATE TABLE IF NOT EXISTS sessions(server_id TEXT NOT NULL REFERENCES servers(id),id TEXT NOT NULL,user TEXT NOT NULL,ip TEXT NOT NULL,started INTEGER NOT NULL,ended INTEGER,live INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(server_id,id));
 CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY AUTOINCREMENT,server_id TEXT NOT NULL REFERENCES servers(id),id TEXT NOT NULL,time INTEGER NOT NULL,received INTEGER NOT NULL,kind TEXT NOT NULL,session_id TEXT NOT NULL,user TEXT NOT NULL,login_uid TEXT NOT NULL,effective_user TEXT NOT NULL,ip TEXT NOT NULL,program TEXT NOT NULL,args TEXT NOT NULL,command TEXT NOT NULL,outcome TEXT NOT NULL,UNIQUE(server_id,id));
 CREATE INDEX IF NOT EXISTS events_time ON events(time DESC,seq DESC);
 CREATE INDEX IF NOT EXISTS events_server_time ON events(server_id,time DESC);
 CREATE INDEX IF NOT EXISTS events_user_time ON events(user,time DESC);
 CREATE INDEX IF NOT EXISTS events_session ON events(server_id,session_id,time);
 CREATE INDEX IF NOT EXISTS sessions_time ON sessions(started DESC);
 CREATE TABLE IF NOT EXISTS login_attempts(ip TEXT PRIMARY KEY,count INTEGER NOT NULL,reset INTEGER NOT NULL);
 `)
	if err != nil {
		db.Close()
		return nil, err
	}
	if err = s.migrate(); err != nil {
		db.Close()
		return nil, err
	}

	return s, nil
}
func hash(s string) string { v := sha256.Sum256([]byte(s)); return hex.EncodeToString(v[:]) }
func (s *Store) transaction(ctx context.Context, f func(*sql.Tx) error) error {
	// Serialize all writers; context bounds waiting for a DB connection/statement.
	select {
	case s.writer <- struct{}{}:
		defer func() { <-s.writer }()
	case <-ctx.Done():
		return ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = f(tx); e != nil {
		return e
	}
	return tx.Commit()
}

type rowQuerier interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func (s *Store) rows(ctx context.Context, q string, args ...any) ([]map[string]any, error) {
	return queryRows(ctx, s.db, q, args...)
}
func queryRows(ctx context.Context, db rowQuerier, q string, args ...any) ([]map[string]any, error) {
	rows, e := db.QueryContext(ctx, q, args...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	cols, e := rows.Columns()
	if e != nil {
		return nil, e
	}
	out := []map[string]any{}
	for rows.Next() {
		vals := make([]any, len(cols))
		ptr := make([]any, len(cols))
		for i := range vals {
			ptr[i] = &vals[i]
		}
		if e = rows.Scan(ptr...); e != nil {
			return nil, e
		}
		m := map[string]any{}
		for i, k := range cols {
			v := vals[i]
			if b, ok := v.([]byte); ok {
				v = string(b)
			}
			if k == "args" {
				var a []string
				_ = json.Unmarshal([]byte(fmt.Sprint(v)), &a)
				v = a
			}
			m[k] = v
		}
		out = append(out, m)
	}
	return out, rows.Err()
}
func (s *Store) cleanup(ctx context.Context) error {
	return s.transaction(ctx, func(tx *sql.Tx) error {
		var days int
		if e := tx.QueryRowContext(ctx, "SELECT retention_days FROM settings WHERE id=1").Scan(&days); e != nil {
			return e
		}
		cutoff := time.Now().Add(-time.Duration(days) * 24 * time.Hour).UnixMilli()
		for _, q := range []string{
			"DELETE FROM session_terminations WHERE created < ?",
			"DELETE FROM events WHERE seq IN (SELECT seq FROM events WHERE time < ? LIMIT 1000)",
			"DELETE FROM sessions WHERE rowid IN (SELECT rowid FROM sessions WHERE COALESCE(ended,started) < ? AND (live=0 OR server_id IN (SELECT id FROM servers WHERE last_seen < CAST(strftime('%s','now') AS INTEGER)*1000-60000 OR revoked=1)) LIMIT 1000)",
			"DELETE FROM auth_sessions WHERE expires < ?",
			"DELETE FROM login_attempts WHERE reset < ?",
			"DELETE FROM auth_pending WHERE expires < ?",
			"DELETE FROM auth_limits WHERE reset < ?",
		} {
			v := cutoff
			if q == "DELETE FROM auth_sessions WHERE expires < ?" || q == "DELETE FROM login_attempts WHERE reset < ?" || q == "DELETE FROM auth_pending WHERE expires < ?" || q == "DELETE FROM auth_limits WHERE reset < ?" {
				v = time.Now().UnixMilli()
			}
			if _, e := tx.ExecContext(ctx, q, v); e != nil {
				return e
			}
		}
		return nil
	})
}
