package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"sshlogger/internal/model"
	"strings"
	"testing"
	"time"
)

func TestRoutineClassificationIsNarrow(t *testing.T) {
	a, _ := fixture(t)
	cases := []struct {
		name, program string
		args          []string
		routine       bool
	}{
		{"bitness", "/usr/bin/getconf", []string{"getconf", "LONG_BIT"}, true},
		{"interpreter", "/usr/bin/dash", []string{"/bin/sh", "/usr/bin/lsb_release", "-a"}, true},
		{"getopt", "/usr/bin/getopt", []string{"getopt", "--name", "lsb_release", "-o", "hvidrcas", "-l", "help,version,id,description,release,codename,all,short", "--", "-a"}, true},
		{"case_conversion", "/usr/bin/tr", []string{"tr", "[:upper:]", "[:lower:]"}, true},
		{"cargo_tr", "/usr/lib/cargo/bin/coreutils/tr", []string{"tr", "[:upper:]", "[:lower:]"}, true},
		{"cargo_tr_other_args", "/usr/lib/cargo/bin/coreutils/tr", []string{"tr", "-d", "a-z"}, false},
		{"custom_tr", "/tmp/tr", []string{"tr", "[:upper:]", "[:lower:]"}, false},
		{"letter", "/usr/bin/cut", []string{"cut", "-c1"}, true},
		{"cargo_cut_first", "/usr/lib/cargo/bin/coreutils/cut", []string{"cut", "-c1"}, true},
		{"cargo_cut_rest", "/usr/lib/cargo/bin/coreutils/cut", []string{"cut", "-c2-"}, true},
		{"cargo_cut_file", "/usr/lib/cargo/bin/coreutils/cut", []string{"cut", "-c1", "/etc/shadow"}, false},
		{"custom_cut", "/tmp/cut", []string{"cut", "-c1"}, false},
		{"cargo_wc_stdin", "/usr/lib/cargo/bin/coreutils/wc", []string{"wc", "-l"}, true},
		{"cargo_wc_file", "/usr/lib/cargo/bin/coreutils/wc", []string{"wc", "-l", "/etc/shadow"}, false},
		{"count_stdin", "/usr/bin/wc", []string{"wc", "-l"}, true},
		{"blank_lines", "/usr/bin/sed", []string{"sed", "/^$/d"}, true},
		{"shell_options", "/usr/bin/awk", []string{"awk", `$2=="on"{print $1}`}, true},
		{"locale", "/usr/bin/locale", []string{"locale"}, true},
		{"profile_listing", "/usr/bin/run-parts", []string{"run-parts", "--list", "--regex", `^[a-zA-Z0-9_][a-zA-Z0-9._-]*\.sh$`, "/etc/profile.d"}, true},
		{"cat", "/usr/bin/cat", []string{"cat", "/etc/shadow"}, false},
		{"cat_stdin", "/usr/bin/cat", []string{"cat"}, false},
		{"find_delete", "/usr/bin/find", []string{"find", "/tmp", "-delete"}, false},
		{"sed_edit", "/usr/bin/sed", []string{"sed", "-i", "s/foo/bar/", "/etc/ssh/sshd_config"}, false},
		{"wc_file", "/usr/bin/wc", []string{"wc", "-l", "/etc/shadow"}, false},
		{"cut_file", "/usr/bin/cut", []string{"cut", "-c1", "/etc/shadow"}, false},
		{"custom_getconf", "/tmp/getconf", []string{"getconf", "LONG_BIT"}, false},
		{"different_tr", "/usr/bin/tr", []string{"tr", "-d", "a-z"}, false},
		{"shell", "/bin/bash", []string{"bash", "-lc", "lsb_release -a; rm /tmp/example"}, false},
		{"script_named_probe", "/usr/bin/dash", []string{"sh", "/tmp/lsb_release", "-a"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, _ := json.Marshal(tc.args)
			var reason string
			q := "SELECT " + routineReasonSQL + " FROM (SELECT 'exec' AS kind,'yes' AS outcome,'alice' AS user,'alice' AS effective_user,? AS program,? AS args) e"
			if err := a.store.db.QueryRow(q, tc.program, string(raw)).Scan(&reason); err != nil {
				t.Fatal(err)
			}
			if (reason != "") != tc.routine {
				t.Fatalf("routine=%v reason=%q", tc.routine, reason)
			}
		})
	}
	for _, tc := range []struct{ kind, outcome, user, effective string }{
		{"exec", "no", "alice", "alice"}, {"exec", "", "alice", "alice"}, {"exec", "yes", "alice", "root"},
		{"exec", "yes", "", "alice"}, {"exec", "yes", "alice", ""}, {"login_failure", "yes", "alice", "alice"},
	} {
		var reason string
		q := "SELECT " + routineReasonSQL + " FROM (SELECT ? AS kind,? AS outcome,? AS user,? AS effective_user,'/usr/bin/getconf' AS program,'[\"getconf\",\"LONG_BIT\"]' AS args) e"
		if err := a.store.db.QueryRow(q, tc.kind, tc.outcome, tc.user, tc.effective).Scan(&reason); err != nil {
			t.Fatal(err)
		}
		if reason != "" {
			t.Fatalf("protected activity was hidden: %#v %s", tc, reason)
		}
	}
}
func TestActivityFilterBeforePaginationAndHistoricalRecords(t *testing.T) {
	a, h := fixture(t)
	cookie, csrf := admin(t, h)
	w := request(h, "POST", "/api/servers", map[string]string{"name": "activity"}, cookie, csrf, "")
	var server map[string]string
	json.Unmarshal(w.Body.Bytes(), &server)
	now := time.Now().UnixMilli()
	// Direct inserts represent records written before display classification existed.
	err := a.store.transaction(context.Background(), func(tx *sql.Tx) error {
		for n := 0; n < 180; n++ {
			program := "/usr/bin/cat"
			args := []string{"cat", fmt.Sprintf("file-%d", n)}
			if n >= 60 {
				program = "/usr/bin/getconf"
				args = []string{"getconf", "LONG_BIT"}
			}
			raw, _ := json.Marshal(args)
			_, err := tx.Exec(`INSERT INTO events(server_id,id,time,received,kind,session_id,user,login_uid,effective_user,ip,program,args,command,outcome) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, server["id"], fmt.Sprint(n), now-int64(180-n), now, "exec", "fixture:1", "alice", "1000", "alice", "203.0.113.1", program, string(raw), strings.Join(args, " "), "yes")
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	base := "/api/events?server_id=" + server["id"] + "&user=alice&ip=203.0.113.1&session_id=fixture:1"
	get := func(params string) ([]map[string]any, map[string]any) {
		t.Helper()
		res := request(h, "GET", base+params, nil, cookie, "", "")
		if res.Code != 200 {
			t.Fatal(res.Code, res.Body.String())
		}
		var v map[string]json.RawMessage
		if err := json.Unmarshal(res.Body.Bytes(), &v); err != nil {
			t.Fatal(err)
		}
		var rows []map[string]any
		json.Unmarshal(v["items"], &rows)
		var meta map[string]any
		json.Unmarshal(res.Body.Bytes(), &meta)
		return rows, meta
	}
	rows, meta := get("&activity=important&summary=1")
	if len(rows) != 51 || meta["total_count"] != float64(180) || meta["routine_count"] != float64(120) || meta["visible_count"] != float64(60) {
		t.Fatal(len(rows), meta)
	}
	for _, row := range rows {
		if row["program"] != "/usr/bin/cat" {
			t.Fatal("routine record leaked into important view")
		}
	}
	next, _ := get("&activity=important&summary=1&page=1")
	if len(next) != 10 {
		t.Fatal(len(next))
	}
	if next[0]["seq"] == rows[49]["seq"] {
		t.Fatal("pagination duplicated boundary")
	}
	routine, _ := get("&activity=routine&summary=1")
	if len(routine) != 51 || routine[0]["routine_reason"] == "" {
		t.Fatal(routine)
	}
	_, filtered := get("&activity=important&summary=1&q=LONG_BIT")
	if filtered["total_count"] != float64(120) || filtered["visible_count"] != float64(0) {
		t.Fatal(filtered)
	}
	res := request(h, "GET", base, nil, cookie, "", "")
	var all []map[string]any
	if err := json.Unmarshal(res.Body.Bytes(), &all); err != nil || len(all) != 51 {
		t.Fatal("default API compatibility", err)
	}
	if res = request(h, "GET", base+"&activity=typo", nil, cookie, "", ""); res.Code != 400 {
		t.Fatal(res.Code)
	}
	var n int
	a.store.db.QueryRow("SELECT COUNT(*) FROM events").Scan(&n)
	if n != 180 {
		t.Fatal("display filter mutated records")
	}
}
func TestIngestDoesNotDiscardRoutineEvents(t *testing.T) {
	a, h := fixture(t)
	cookie, csrf := admin(t, h)
	w := request(h, "POST", "/api/servers", map[string]string{"name": "kept"}, cookie, csrf, "")
	var server map[string]string
	json.Unmarshal(w.Body.Bytes(), &server)
	ev := model.Event{ID: "routine", Time: time.Now().UnixMilli(), Kind: "exec", User: "alice", EffectiveUser: "alice", Program: "/usr/bin/getconf", Args: []string{"getconf", "LONG_BIT"}, Outcome: "yes"}
	for i := 0; i < 2; i++ {
		w = request(h, "POST", "/api/ingest", model.Batch{Events: []model.Event{ev}, Health: "ok"}, "", "", server["token"])
		if w.Code != http.StatusOK {
			t.Fatal(w.Body.String())
		}
	}
	var n int
	a.store.db.QueryRow("SELECT COUNT(*) FROM events").Scan(&n)
	if n != 1 {
		t.Fatal(n)
	}
}
