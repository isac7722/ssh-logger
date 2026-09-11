package main

import (
	"database/sql"
	"encoding/json"
	"path/filepath"
	"sshlogger/internal/model"
	"testing"
	"time"
)

func TestLegacyDatabaseMigrationAndBackupRestore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	s, err := openStore(path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.db.Exec(`ALTER TABLE events DROP COLUMN pid; ALTER TABLE events DROP COLUMN ppid; UPDATE schema_version SET version=1;
 INSERT INTO admins VALUES('existing-admin','existing-hash');
 INSERT INTO servers(id,name,token_hash,created) VALUES('s','legacy','hash',1);
 INSERT INTO events(server_id,id,time,received,kind,session_id,user,login_uid,effective_user,ip,program,args,command,outcome) VALUES('s','old',1,1,'exec','','alice','1000','alice','','/usr/bin/id','["id"]','id','yes');`)
	if err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(t.TempDir(), "v1.db")
	if _, err = s.db.Exec("VACUUM INTO ?", backup); err != nil {
		t.Fatal(err)
	}
	s.db.Close()
	for _, target := range []string{path, filepath.Join(t.TempDir(), "restored.db")} {
		if target != path {
			if err = restoreSnapshot(target, backup); err != nil {
				t.Fatal(err)
			}
		}
		migrated, err := openStore(target)
		if err != nil {
			t.Fatal(err)
		}
		var version, n int
		var pid, ppid sql.NullInt64
		var admin string
		if err = migrated.db.QueryRow("SELECT version FROM schema_version").Scan(&version); err != nil || version != currentSchemaVersion {
			t.Fatal(version, err)
		}
		if err = migrated.db.QueryRow("SELECT pid,ppid FROM events WHERE id='old'").Scan(&pid, &ppid); err != nil || pid.Valid || ppid.Valid {
			t.Fatal(pid, ppid, err)
		}
		migrated.db.QueryRow("SELECT COUNT(*) FROM events").Scan(&n)
		if n != 1 {
			t.Fatal(n)
		}
		migrated.db.QueryRow("SELECT username FROM admins").Scan(&admin)
		if admin != "existing-admin" {
			t.Fatal(admin)
		}
		if err = migrated.migrate(); err != nil {
			t.Fatal("migration not idempotent", err)
		}
		migrated.db.Close()
	}
}
func TestProcessIDsPersistAndOldAgentsRemainCompatible(t *testing.T) {
	a, h := fixture(t)
	cookie, csrf := admin(t, h)
	w := request(h, "POST", "/api/servers", map[string]string{"name": "processes"}, cookie, csrf, "")
	var server map[string]string
	json.Unmarshal(w.Body.Bytes(), &server)
	pid, ppid := 12345, 0
	ev := model.Event{ID: "new", Time: time.Now().UnixMilli(), Kind: "exec", Program: "/usr/bin/id", PID: &pid, PPID: &ppid}
	old := model.Event{ID: "old", Time: ev.Time, Kind: "exec", Program: "/usr/bin/id"}
	w = request(h, "POST", "/api/ingest", model.Batch{Events: []model.Event{ev, old}}, "", "", server["token"])
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	var gotPID, gotPPID sql.NullInt64
	a.store.db.QueryRow("SELECT pid,ppid FROM events WHERE id='new'").Scan(&gotPID, &gotPPID)
	if !gotPID.Valid || gotPID.Int64 != 12345 || !gotPPID.Valid || gotPPID.Int64 != 0 {
		t.Fatal(gotPID, gotPPID)
	}
	a.store.db.QueryRow("SELECT pid,ppid FROM events WHERE id='old'").Scan(&gotPID, &gotPPID)
	if gotPID.Valid || gotPPID.Valid {
		t.Fatal("old agent IDs should be null")
	}
	bad := -1
	ev.ID = "bad"
	ev.PPID = &bad
	w = request(h, "POST", "/api/ingest", model.Batch{Events: []model.Event{ev}}, "", "", server["token"])
	if w.Code != 400 {
		t.Fatal(w.Code)
	}
}

func TestVersionTwoMigrationInvalidatesUnownedSessions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v2.db")
	s, err := openStore(path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.db.Exec(`INSERT INTO admins VALUES('existing','hash');
 DROP TABLE auth_sessions;
 CREATE TABLE auth_sessions(token_hash TEXT PRIMARY KEY,csrf TEXT NOT NULL,expires INTEGER NOT NULL);
 INSERT INTO auth_sessions VALUES('old','csrf',9999999999999);
 UPDATE schema_version SET version=2;`)
	if err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(t.TempDir(), "v2-backup.db")
	if _, err = s.db.Exec("VACUUM INTO ?", backup); err != nil {
		t.Fatal(err)
	}
	s.db.Close()
	restored := filepath.Join(t.TempDir(), "restored.db")
	if err = restoreSnapshot(restored, backup); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{path, restored} {
		migrated, err := openStore(target)
		if err != nil {
			t.Fatal(err)
		}
		var count int
		if err = migrated.db.QueryRow("SELECT COUNT(*) FROM auth_sessions").Scan(&count); err != nil || count != 0 {
			t.Fatal("legacy sessions retained", count, err)
		}
		if _, err = migrated.db.Exec("INSERT INTO auth_sessions VALUES('new','csrf',9999999999999,'existing')"); err != nil {
			t.Fatal(err)
		}
		if err = migrated.migrate(); err != nil {
			t.Fatal(err)
		}
		if err = migrated.db.QueryRow("SELECT COUNT(*) FROM auth_sessions").Scan(&count); err != nil || count != 1 {
			t.Fatal("new session lost on repeated migration", count, err)
		}
		migrated.db.Close()
	}
}
