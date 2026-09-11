package main

import (
	"database/sql"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
)

// Caller must stop the service first. Restore replaces the complete database,
// including administrator credentials and server tokens from the snapshot.
func restoreSnapshot(dest, source string) error {
	abs, e := filepath.Abs(source)
	if e != nil {
		return e
	}
	u := url.URL{Scheme: "file", Path: abs, RawQuery: "mode=ro"}
	db, e := sql.Open("sqlite", u.String())
	if e != nil {
		return e
	}
	var integrity string
	e = db.QueryRow("PRAGMA integrity_check").Scan(&integrity)
	if e != nil || integrity != "ok" {
		db.Close()
		return fmt.Errorf("invalid backup: %s: %v", integrity, e)
	}
	var version int
	e = db.QueryRow("SELECT version FROM schema_version").Scan(&version)
	db.Close()
	if e != nil || version < 1 || version > currentSchemaVersion {
		return fmt.Errorf("unsupported schema: %d: %v", version, e)
	}
	if e = os.MkdirAll(filepath.Dir(dest), 0700); e != nil {
		return e
	}
	in, e := os.Open(source)
	if e != nil {
		return e
	}
	defer in.Close()
	out, e := os.CreateTemp(filepath.Dir(dest), ".restore-*")
	if e != nil {
		return e
	}
	tmp := out.Name()
	defer os.Remove(tmp)
	if _, e = io.Copy(out, in); e != nil {
		out.Close()
		return e
	}
	if e = out.Sync(); e != nil {
		out.Close()
		return e
	}
	if e = out.Close(); e != nil {
		return e
	}
	if os.Getuid() == 0 {
		if e = os.Chown(tmp, 10001, 10001); e != nil {
			return e
		}
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		if e = os.Remove(dest + suffix); e != nil && !os.IsNotExist(e) {
			return e
		}
	}
	if e = os.Rename(tmp, dest); e != nil {
		return e
	}
	d, e := os.Open(filepath.Dir(dest))
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}
